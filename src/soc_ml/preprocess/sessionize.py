"""Sessionization — reconstructing visits from a stream of events (FR-07).

The input contract has no cookies and no usernames, so a "visit" has to be
rebuilt from behaviour (SPEC_DIGEST §3):

    SESSION KEY = (observer.server, source.ip, sha(user_agent))
    consecutive same-key events form one session until an idle gap > 30 minutes

The 30-minute gap is a **grouping** default, not a detection threshold — it
decides where one visit ends, never whether anything is suspicious. That is why
it may live in config without violating FR-62.

Sessions are what UC-06 (scraping), UC-10 (status sequences), and UC-11 (session
abuse) are built on, so the shape here constrains those use cases later.
"""

from __future__ import annotations

import math
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from soc_ml.core.contracts import EntityKey, Event, Session

__all__ = ["Sessionizer", "session_features", "SessionizerStats"]

#: Cap on per-session sequence retention. A harvesting session can run to
#: hundreds of thousands of requests; an uncapped list is an out-of-memory bug
#: waiting for the first real scraper.
DEFAULT_MAX_SEQUENCE = 10_000


@dataclass(slots=True)
class SessionizerStats:
    opened: int = 0
    closed_by_gap: int = 0
    closed_by_flush: int = 0
    out_of_order: int = 0
    truncated: int = 0


class Sessionizer:
    """Groups events into sessions by entity and idle gap.

    Usage is push-based: feed events in, take closed sessions out.

        >>> sz = Sessionizer(idle_gap_s=1800)
        >>> for event in source.read():
        ...     for finished in sz.add(event):
        ...         handle(finished)
        >>> for finished in sz.flush():
        ...     handle(finished)

    Real log streams are only *approximately* ordered — a multi-worker parser
    interleaves output. An event older than the session's last-seen time is
    still folded in, but contributes no negative inter-arrival, and is counted
    in ``stats.out_of_order`` so a badly-ordered feed is visible rather than
    quietly skewing timing features.
    """

    def __init__(
        self,
        idle_gap_s: int = 1800,
        *,
        max_sequence: int = DEFAULT_MAX_SEQUENCE,
    ) -> None:
        self.idle_gap = timedelta(seconds=idle_gap_s)
        self.max_sequence = max_sequence
        self._open: dict[EntityKey, Session] = {}
        self.stats = SessionizerStats()

    # -- ingestion --------------------------------------------------------- #

    def add(self, event: Event) -> list[Session]:
        """Fold one event in. Returns any session this event caused to close."""
        entity = event.entity
        closed: list[Session] = []
        session = self._open.get(entity)

        if session is not None:
            gap = event.timestamp - session.last_seen_at
            if gap > self.idle_gap:
                session.closed = True
                self.stats.closed_by_gap += 1
                closed.append(session)
                session = None

        if session is None:
            session = self._start(entity, event)

        self._append(session, event)
        return closed

    def _start(self, entity: EntityKey, event: Event) -> Session:
        session = Session(
            entity=entity,
            started_at=event.timestamp,
            last_seen_at=event.timestamp,
            entry_path=event.url_path,
        )
        self._open[entity] = session
        self.stats.opened += 1
        return session

    def _append(self, session: Session, event: Event) -> None:
        delta = (event.timestamp - session.last_seen_at).total_seconds()
        if delta < 0:
            # Out-of-order arrival: fold it in, but do not invent a negative gap
            # and do not move the clock backwards.
            self.stats.out_of_order += 1
        else:
            if session.event_count:
                self._push(session.inter_arrivals, delta, session)
            session.last_seen_at = event.timestamp

        session.event_count += 1
        session.bytes_total += event.body_bytes or 0
        if event.http_referrer is not None:
            session.referrer_present += 1

        if event.url_path is not None:
            session.exit_path = event.url_path
            if len(session.unique_paths) < self.max_sequence:
                session.unique_paths.add(event.url_path)
            self._push(session.paths, event.url_path, session)
        if event.status_code is not None:
            self._push(session.status_codes, event.status_code, session)
        if event.http_method is not None:
            self._push(session.methods, event.http_method, session)

    def _push(self, seq: list, value, session: Session | None = None) -> None:
        if len(seq) >= self.max_sequence:
            if session is not None and not session.truncated:
                session.truncated = True
                self.stats.truncated += 1
            return
        seq.append(value)

    # -- closing ----------------------------------------------------------- #

    def expire(self, now: datetime) -> list[Session]:
        """Close sessions idle beyond the gap as of ``now``.

        A live pipeline calls this on a timer; without it, a session whose entity
        never returns stays open forever and is never scored.
        """
        due = [
            entity
            for entity, session in self._open.items()
            if now - session.last_seen_at > self.idle_gap
        ]
        out = []
        for entity in due:
            session = self._open.pop(entity)
            session.closed = True
            self.stats.closed_by_gap += 1
            out.append(session)
        return out

    def flush(self) -> list[Session]:
        """Close every open session — end of an offline run."""
        out = []
        for session in self._open.values():
            session.closed = True
            self.stats.closed_by_flush += 1
            out.append(session)
        self._open.clear()
        return out

    def run(self, events: Iterator[Event]) -> Iterator[Session]:
        """Convenience: stream events in, closed sessions out, flushing at end."""
        for event in events:
            yield from self.add(event)
        yield from self.flush()

    @property
    def open_count(self) -> int:
        return len(self._open)


# --------------------------------------------------------------------------- #
# Session features (SPEC_DIGEST §3)
# --------------------------------------------------------------------------- #


def session_features(session: Session) -> dict[str, float]:
    """The spec's session feature set.

    Computed at session end and, in a live pipeline, every 60 s while the
    session is open.

    Note what is *not* here: no judgement. These are descriptive numbers. The
    decision about whether any of them is abnormal belongs to a use case scoring
    them against the learned Environment Profile — never to a constant in this
    file (FR-62).
    """
    n = session.event_count
    duration = session.duration_s
    gaps = session.inter_arrivals

    mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
    if len(gaps) > 1 and mean_gap > 0:
        variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
        cv_gap = math.sqrt(variance) / mean_gap
    else:
        cv_gap = 0.0

    status_hist = _class_histogram(session.status_codes)
    method_hist = _method_histogram(session.methods)

    depths = [p.count("/") for p in session.paths] if session.paths else []

    return {
        "session.duration_s": duration,
        "session.event_count": float(n),
        "session.unique_paths": float(len(session.unique_paths)),
        "session.paths_per_minute": (n / (duration / 60.0)) if duration > 0 else 0.0,
        "session.bytes_total": float(session.bytes_total),
        "session.bytes_per_request": (session.bytes_total / n) if n else 0.0,
        "session.mean_inter_arrival": mean_gap,
        "session.cv_inter_arrival": cv_gap,
        "session.referrer_present_ratio": (session.referrer_present / n) if n else 0.0,
        "session.path_depth_mean": (sum(depths) / len(depths)) if depths else 0.0,
        "session.repeat_path_ratio": (
            1.0 - len(session.unique_paths) / n if n else 0.0
        ),
        **status_hist,
        **method_hist,
    }


def _class_histogram(codes: list[int]) -> dict[str, float]:
    """Status-class shares. Ratios, not counts — they ride seasonal tides.

    The 4xx split into auth (401/403) and not-found (404) mirrors the 5-symbol
    alphabet UC-10 decodes, so the same distinction is available to both.
    """
    total = len(codes)
    buckets = {"2xx": 0, "3xx": 0, "4xx_auth": 0, "4xx_notfound": 0, "4xx_other": 0, "5xx": 0}
    for code in codes:
        if 200 <= code < 300:
            buckets["2xx"] += 1
        elif 300 <= code < 400:
            buckets["3xx"] += 1
        elif code in (401, 403):
            buckets["4xx_auth"] += 1
        elif code == 404:
            buckets["4xx_notfound"] += 1
        elif 400 <= code < 500:
            buckets["4xx_other"] += 1
        elif code >= 500:
            buckets["5xx"] += 1
    return {
        f"session.status_{name}_ratio": (count / total if total else 0.0)
        for name, count in buckets.items()
    }


def _method_histogram(methods: list[str]) -> dict[str, float]:
    total = len(methods)
    tracked = ("GET", "POST", "HEAD")
    counts = {m: 0 for m in tracked}
    other = 0
    for method in methods:
        upper = method.upper()
        if upper in counts:
            counts[upper] += 1
        else:
            other += 1
    out = {
        f"session.method_{m.lower()}_ratio": (c / total if total else 0.0)
        for m, c in counts.items()
    }
    out["session.method_other_ratio"] = other / total if total else 0.0
    return out
