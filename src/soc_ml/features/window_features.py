"""Streaming per-entity window features for web use cases.

Turns an (approximately time-ordered) event stream into one FeatureVector per
``(entity, 5-minute window)``. This is the entity-level aggregation that makes
two-level gating (FR-24) structural: nothing downstream ever scores a single
event.

Phase-1 note (journaled as D-017): windows are **tumbling**, not sliding — the
spec's sliding windows matter for live latency, where an attack should not wait
for a bucket boundary to be visible; for offline training and backtest the
tumbling approximation produces the same vector distribution at a fraction of
the cost. The feature *definitions* are identical either way, so models trained
here remain valid when the live sliding path arrives.

Memory is bounded everywhere: per-window sets/lists are capped, closed windows
are evicted by watermark, and a hard cap on simultaneously-open windows guards
against a pathological unsorted feed (NFR-09: the guard counts what it drops).

Feature names follow docs/NAMING.md: ``<group>.<feature>``, window carried by
the vector, not the name.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from soc_ml.baseline.profile import EnvironmentProfile, _extension
from soc_ml.core.contracts import EntityKey, Event, FeatureVector
from soc_ml.features.bot_features import (
    BotWindowState,
    EntityMemory,
    claimed_crawler_family,
    declared_bot,
    verified_crawler,
)

__all__ = ["WindowFeatureBuilder", "WindowResult", "WEB_RECON_FEATURES"]

#: The features this builder emits (what use cases can `require`).
WEB_RECON_FEATURES: tuple[str, ...] = (
    "web.ratio_404",
    "web.status_2xx_ratio",
    "web.status_3xx_ratio",
    "web.status_4xx_ratio",
    "web.status_5xx_ratio",
    "web.mean_path_idf",
    "web.path_token_entropy",
    "web.uniq_paths_per_min",
    "web.unknown_ext_ratio",
    "web.referrer_absent_ratio",
    "ua.len",
    "ua.rarity",
    "timing.interarrival_cv",
)

_WINDOW_S = 300  # 5 minutes — the spec's primary short window for UC-02/04
_GRACE_S = 120  # how far the watermark trails before a window closes
_MAX_DISTINCT_PATHS = 4096  # per-window cap; beyond this "many" is the signal
_MAX_GAPS = 2048
_MAX_EVIDENCE_LINES = 10  # spec: alerts carry 3-10 verbatim lines
_MAX_OPEN_WINDOWS = 250_000  # hard guard against a badly unsorted feed
_MAX_TRACKED_ENTITIES = 200_000  # cross-window entity-memory cap
_SWEEP_EVERY = 1000  # events between watermark sweeps


@dataclass(slots=True)
class _OpenWindow:
    entity: EntityKey
    start: datetime
    count: int = 0
    n404: int = 0
    n2xx: int = 0
    n3xx: int = 0
    n4xx: int = 0
    n5xx: int = 0
    referrer_absent: int = 0
    unknown_ext: int = 0
    idf_sum: float = 0.0
    paths: set = field(default_factory=set)
    paths_capped: bool = False
    tokens: Counter = field(default_factory=Counter)
    last_ts: datetime | None = None
    gaps: list = field(default_factory=list)
    raw_lines: deque = field(default_factory=lambda: deque(maxlen=_MAX_EVIDENCE_LINES))
    ua: str | None = None
    bot: BotWindowState = field(default_factory=BotWindowState)


@dataclass(slots=True)
class WindowResult:
    """One closed window: the model input plus the evidence around it."""

    vector: FeatureVector
    evidence: dict[str, Any]


class WindowFeatureBuilder:
    """Streams events in, yields closed WindowResults out.

    Usage::

        builder = WindowFeatureBuilder(profile)
        for event in source.read():
            yield from builder.add(event)
        yield from builder.flush()
    """

    def __init__(self, profile: EnvironmentProfile, window_s: int = _WINDOW_S) -> None:
        self.profile = profile
        self.window_s = window_s
        self._open: dict[tuple[EntityKey, int], _OpenWindow] = {}
        # Cross-window per-entity memory (activity hours, robots.txt) — the
        # inputs that make no sense inside a single five-minute slice. Bounded
        # LRU: past the cap the least-recently-seen entity is evicted (its
        # history restarts if it returns), and evictions are counted, never
        # silent (NFR-09).
        self._memory: dict[EntityKey, EntityMemory] = {}
        # (server, crawler family) pairs where a *verified* member of the
        # family fetched /robots.txt. Politeness is an operator property, not
        # an entity one: Googlebot fetches robots.txt from one address of its
        # pool and crawls from dozens, so a per-entity flag misses the pool
        # (D-023 — found on production traffic). Naturally tiny: verified
        # families × servers.
        self._family_robots: set[tuple[str, str]] = set()
        self._watermark: datetime | None = None
        self._since_sweep = 0
        self.stats = {
            "events": 0,
            "windows_closed": 0,
            "out_of_order": 0,
            "dropped_open_cap": 0,
            "entity_memory_capped": 0,
        }

    # ------------------------------------------------------------------ #

    def add(self, event: Event) -> Iterator[WindowResult]:
        self.stats["events"] += 1
        ts = event.timestamp
        if ts.tzinfo is None:  # defensive: contract requires UTC-aware
            ts = ts.replace(tzinfo=timezone.utc)

        if self._watermark is None or ts > self._watermark:
            self._watermark = ts
        elif ts < self._watermark - timedelta(seconds=_GRACE_S):
            self.stats["out_of_order"] += 1  # folded in, visibly counted

        bucket = int(ts.timestamp()) // self.window_s
        key = (event.entity, bucket)
        window = self._open.get(key)
        if window is None:
            if len(self._open) >= _MAX_OPEN_WINDOWS:
                # A feed this unsorted is broken input; count, don't crash.
                self.stats["dropped_open_cap"] += 1
                return
            window = _OpenWindow(
                entity=event.entity,
                start=datetime.fromtimestamp(bucket * self.window_s, tz=timezone.utc),
            )
            self._open[key] = window
        self._fold(window, event, ts)

        self._since_sweep += 1
        if self._since_sweep >= _SWEEP_EVERY:
            self._since_sweep = 0
            yield from self._sweep()

    def flush(self) -> Iterator[WindowResult]:
        """Close everything — end of an offline pass."""
        for key in sorted(self._open, key=lambda k: self._open[k].start):
            yield self._close(self._open[key])
        self._open.clear()

    @property
    def open_count(self) -> int:
        """Windows currently open (awaiting close) — a health/backpressure signal."""
        return len(self._open)

    # ------------------------------------------------------------------ #

    def _memory_for(self, entity: EntityKey) -> EntityMemory:
        memory = self._memory.pop(entity, None)
        if memory is None:
            if len(self._memory) >= _MAX_TRACKED_ENTITIES:
                # Evict the least-recently-seen entity (dicts keep insertion
                # order and every access below re-inserts, so the first key
                # is the coldest).
                del self._memory[next(iter(self._memory))]
                self.stats["entity_memory_capped"] += 1
            memory = EntityMemory()
        self._memory[entity] = memory
        return memory

    def _fold(self, w: _OpenWindow, event: Event, ts: datetime) -> None:
        server = event.entity.server
        w.count += 1
        w.ua = event.user_agent
        self._memory_for(w.entity).remember(event)
        w.bot.fold(event, ts, w.start)
        if event.url_path == "/robots.txt":
            family = claimed_crawler_family(event.user_agent)
            if family and verified_crawler(event.source_ip, event.user_agent):
                self._family_robots.add((server, family))

        status = event.status_code or 0
        if status == 404:
            w.n404 += 1
        if 200 <= status < 300:
            w.n2xx += 1
        elif 300 <= status < 400:
            w.n3xx += 1
        elif 400 <= status < 500:
            w.n4xx += 1
        elif status >= 500:
            w.n5xx += 1

        if event.http_referrer is None:
            w.referrer_absent += 1

        path = event.url_path
        if path:
            if len(w.paths) < _MAX_DISTINCT_PATHS:
                w.paths.add(path)
            elif path not in w.paths:
                w.paths_capped = True
            w.idf_sum += self.profile.path_idf(server, path)
            for token in path.split("/"):
                if token:
                    w.tokens[token] += 1
            ext = _extension(path)
            if ext and ext not in self.profile.served_extensions(server):
                w.unknown_ext += 1

        if w.last_ts is not None:
            gap = (ts - w.last_ts).total_seconds()
            if gap >= 0 and len(w.gaps) < _MAX_GAPS:
                w.gaps.append(gap)
        if w.last_ts is None or ts >= w.last_ts:
            w.last_ts = ts

        if event.original:
            w.raw_lines.append(event.original)

    def _sweep(self) -> Iterator[WindowResult]:
        if self._watermark is None:
            return
        horizon = self._watermark - timedelta(seconds=_GRACE_S)
        due = [
            key
            for key, w in self._open.items()
            if w.start + timedelta(seconds=self.window_s) < horizon
        ]
        for key in sorted(due, key=lambda k: self._open[k].start):
            yield self._close(self._open.pop(key))

    def _close(self, w: _OpenWindow) -> WindowResult:
        self.stats["windows_closed"] += 1
        server = w.entity.server
        n = w.count
        minutes = self.window_s / 60.0

        values = {
            "web.ratio_404": w.n404 / n,
            "web.status_2xx_ratio": w.n2xx / n,
            "web.status_3xx_ratio": w.n3xx / n,
            "web.status_4xx_ratio": w.n4xx / n,
            "web.status_5xx_ratio": w.n5xx / n,
            "web.mean_path_idf": w.idf_sum / n,
            "web.path_token_entropy": _token_entropy(w.tokens),
            "web.uniq_paths_per_min": len(w.paths) / minutes,
            "web.unknown_ext_ratio": w.unknown_ext / n,
            "web.referrer_absent_ratio": w.referrer_absent / n,
            "ua.len": float(len(w.ua or "")),
            "ua.rarity": self.profile.ua_rarity(server, w.ua),
            "timing.interarrival_cv": _cv(w.gaps),
        }
        values.update(
            w.bot.finalize(
                event_count=n,
                distinct_paths=len(w.paths),
                window_s=self.window_s,
                ua=w.ua,
                memory=self._memory_for(w.entity),
            )
        )
        vector = FeatureVector(
            entity=w.entity,
            window="5m",
            computed_at=w.start + timedelta(seconds=self.window_s),
            values=values,
        )
        family = claimed_crawler_family(w.ua)
        evidence = {
            "window_start": w.start.isoformat(),
            "window_end": (w.start + timedelta(seconds=self.window_s)).isoformat(),
            "entity": str(w.entity),
            "event_count": n,
            "distinct_paths": len(w.paths),
            "distinct_paths_capped": w.paths_capped,
            "n404": w.n404,
            "user_agent": w.ua,
            # Identity context for UC-04's gate and the crawler export —
            # evidence, deliberately never model input (models learn behavior,
            # not IP ranges).
            "declared_bot": declared_bot(w.ua),
            "crawler_family": family,
            "verified_crawler": verified_crawler(w.entity.ip, w.ua),
            # Operator-level politeness: some verified member of this family
            # fetched robots.txt on this server (D-023).
            "family_robots_txt": bool(family)
            and (server, family) in self._family_robots,
            "raw_lines": list(w.raw_lines),
        }
        return WindowResult(vector=vector, evidence=evidence)


# ---------------------------------------------------------------------- #
# Feature maths — small, exact, unit-tested
# ---------------------------------------------------------------------- #


def _token_entropy(tokens: Counter) -> float:
    """Shannon entropy of the path-segment distribution, normalized to [0, 1].

    Human browsing revisits the same segments (low entropy); wordlist scanning
    spreads mass across hundreds of one-shot segments (high entropy).
    """
    total = sum(tokens.values())
    if total <= 1 or len(tokens) <= 1:
        return 0.0
    h = -sum((c / total) * math.log2(c / total) for c in tokens.values())
    return h / math.log2(len(tokens))


def _cv(gaps: list[float]) -> float:
    """Coefficient of variation of inter-arrival gaps; 0 when undefined."""
    if len(gaps) < 2:
        return 0.0
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return 0.0
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return math.sqrt(var) / mean
