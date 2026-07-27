"""Bot / crawler behavioral features and labels (UC-04, JOURNAL D-019).

Three kinds of things live here, and keeping them distinct is the whole design:

1. **Behavioral features** (``bot.*``, ``timing.fano_factor``) — model inputs,
   computed per (entity, 5m) window like every other feature. They describe
   *how* a client behaves: whether it fetches page assets, how bursty it is,
   whether its referrers chain like navigation, when it is awake.
2. **The self-supervised label** (``bot.declared_bot``) — derived from the UA
   string. It rides in the feature vector but is the GBM's *target*, never a
   behavioral input: the classifier predicts "would this client declare itself
   a bot?" from behavior alone, so a browser-declared client that scores high
   is a spoofer, and the calibrated probability is the human-likeness signal
   other use cases consume.
3. **The verified-crawler identity check** — Googlebot/Bingbot confirmed by
   their published address ranges. This is an allowlist of *identity* (who the
   operator is), not a detection threshold, so FR-62 is untouched. It makes
   downstream suppression certain instead of probabilistic — the spec's "free
   precision" layer. It is evidence/annotation input, deliberately **not** a
   model feature: models must learn behavior, not memorize IP ranges.

Two features need memory *across* windows for one entity (activity-hour
entropy needs hours, robots.txt is fetched once per crawl session, not per
five minutes). :class:`EntityMemory` carries that state; the window builder
owns a bounded table of them.
"""

from __future__ import annotations

import ipaddress
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from soc_ml.baseline.profile import _extension
from soc_ml.core.contracts import Event

__all__ = [
    "BOT_DETECTION_FEATURES",
    "BotWindowState",
    "EntityMemory",
    "claimed_crawler_family",
    "declared_bot",
    "verified_crawler",
]

#: What bot_detection consumes (plus reused web.*/ua.*/timing.* — see the
#: use case's ``requires``). Names per docs/NAMING.md: <group>.<name>.
BOT_DETECTION_FEATURES: tuple[str, ...] = (
    "bot.asset_fetch_ratio",
    "bot.activity_hour_entropy",
    "bot.referrer_chain_depth",
    "bot.path_repeat_ratio",
    "bot.method_get_ratio",
    "bot.bytes_per_req_p50",
    "bot.robots_txt_fetched",
    "bot.declared_bot",
    "timing.fano_factor",
)

#: Sub-resources a real browser fetches implicitly when rendering a page.
#: Scripts and scrapers request content and skip these — that asymmetry is
#: one of the strongest rate-independent bot signals in the spec.
ASSET_EXTENSIONS = frozenset({
    "css", "js", "mjs", "map",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
    "woff", "woff2", "ttf", "otf", "eot",
})

# The declared-bot label matcher. Precision-first: explicit automation tool
# names plus the generic bot/crawler/spider terms. Substring "bot" alone would
# mislabel real devices (the CUBOT phone family is the classic trap), so the
# generic terms require a non-letter or end-of-string after the match. Minor
# residual label noise is acceptable — the GBM is calibrated, not thresholded
# on single rows.
_DECLARED_BOT_RE = re.compile(
    r"(?:bot|crawler|spider|scraper|slurp)(?:[^a-z]|$)"
    r"|curl/|wget/|python-requests|python-urllib|scrapy|go-http-client"
    r"|java/|libwww|okhttp|httpx/|aiohttp|phantomjs|headlesschrome"
    r"|facebookexternalhit|feedfetcher|monitoring|pingdom|uptimerobot|nagios"
)
_CUBOT_RE = re.compile(r"cubot[ _-]")  # device brand, not a robot

#: Published crawl ranges for the crawler families we verify. This is operator
#: identity published by the operators themselves (Google's and Microsoft's
#: verification docs), not learned data — update it like any other code when
#: they publish changes. Verification demands BOTH the UA claim and a source
#: address inside the claimed family's ranges; a claim from outside the range
#: is spoofing evidence, never a pass.
CRAWLER_RANGES: dict[str, tuple[str, ...]] = {
    "googlebot": ("66.249.64.0/19",),
    "bingbot": (
        "157.55.39.0/24",
        "207.46.13.0/24",
        "40.77.167.0/24",
        "13.66.139.0/24",
        "52.167.144.0/24",
    ),
}
_CRAWLER_NETWORKS = {
    family: tuple(ipaddress.ip_network(r) for r in ranges)
    for family, ranges in CRAWLER_RANGES.items()
}
_FAMILY_MARKERS = (
    ("googlebot", "googlebot"),
    ("bingbot", "bingbot"),
    ("msnbot", "bingbot"),
)

_MAX_BYTES_SAMPLES = 2048  # per-window cap, same idiom as _MAX_GAPS
_MAX_CHAIN_PATHS = 4096  # referrer-chain table cap per window
_FANO_BIN_S = 30  # 10 sub-bins per 5-minute window


# --------------------------------------------------------------------------- #
# Labels and identity
# --------------------------------------------------------------------------- #


def declared_bot(ua: str | None) -> bool:
    """Does this client *declare* automation in its user-agent string?

    This is the free self-supervised label (D-019): cheap, present on every
    event, and honest clients set it. It is never used as a behavioral model
    input — it is what the behavioral model is trained to predict.
    """
    if not ua:
        # No UA at all is overwhelmingly scripts/monitors, and a browser
        # without a UA is not a thing real users produce.
        return True
    lowered = ua.lower()
    if _CUBOT_RE.search(lowered):
        return False
    return bool(_DECLARED_BOT_RE.search(lowered))


def claimed_crawler_family(ua: str | None) -> str | None:
    """Which verifiable crawler family (if any) this UA claims to be."""
    if not ua:
        return None
    lowered = ua.lower()
    for marker, family in _FAMILY_MARKERS:
        if marker in lowered:
            return family
    return None


def verified_crawler(ip: str | None, ua: str | None) -> bool:
    """True when the UA claims a known crawler AND the source address sits in
    that family's published ranges. Identity allowlist — not a threshold."""
    family = claimed_crawler_family(ua)
    if family is None or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CRAWLER_NETWORKS[family])


# --------------------------------------------------------------------------- #
# Cross-window entity memory
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class EntityMemory:
    """What one entity's history contributes beyond a single window.

    Rebuilt from the stream (training: the whole corpus; live: since process
    start), never persisted — so a freshly restarted runtime under-reads hour
    entropy for a while rather than trusting stale state. That bias is shared
    by training and live identically, which is what calibration requires.
    """

    hour_counts: Counter = field(default_factory=Counter)  # hour-of-day -> events
    robots_txt_fetched: bool = False

    def remember(self, event: Event) -> None:
        self.hour_counts[event.timestamp.hour] += 1
        if event.url_path == "/robots.txt":
            self.robots_txt_fetched = True

    @property
    def activity_hour_entropy(self) -> float:
        """Shannon entropy of the 24-bin activity histogram, normalized [0, 1].

        Humans sleep: their mass concentrates in waking hours (low entropy).
        Machines don't: flat around-the-clock activity approaches 1.0.
        """
        total = sum(self.hour_counts.values())
        if total <= 1 or len(self.hour_counts) <= 1:
            return 0.0
        h = -sum(
            (c / total) * math.log2(c / total) for c in self.hour_counts.values()
        )
        return h / math.log2(24)


# --------------------------------------------------------------------------- #
# Per-window accumulator
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class BotWindowState:
    """Bot-feature accumulation for one open (entity, window)."""

    asset_hits: int = 0
    get_hits: int = 0
    method_seen: int = 0
    bytes_samples: list = field(default_factory=list)
    #: path -> navigation depth (1 = entry; depth(referrer)+1 when the
    #: referrer was itself requested in this window). Browsers build chains;
    #: scripts with absent or constant referrers stay at depth <= 1.
    chain_depth: dict = field(default_factory=dict)
    max_chain_depth: int = 0
    #: 30-second sub-bin -> event count, for the Fano factor.
    sub_bins: Counter = field(default_factory=Counter)

    def fold(self, event: Event, ts: datetime, window_start: datetime) -> None:
        path = event.url_path
        if path:
            ext = _extension(path)
            if ext and ext in ASSET_EXTENSIONS:
                self.asset_hits += 1

        if event.http_method:
            self.method_seen += 1
            if event.http_method.upper() == "GET":
                self.get_hits += 1

        if event.body_bytes is not None and len(self.bytes_samples) < _MAX_BYTES_SAMPLES:
            self.bytes_samples.append(event.body_bytes)

        if path and len(self.chain_depth) < _MAX_CHAIN_PATHS:
            referrer_path = _referrer_path(event.http_referrer)
            depth = self.chain_depth.get(referrer_path, 0) + 1 if referrer_path else 1
            # A path keeps its deepest observed position in the chain.
            if depth > self.chain_depth.get(path, 0):
                self.chain_depth[path] = depth
            if depth > self.max_chain_depth:
                self.max_chain_depth = depth

        self.sub_bins[int((ts - window_start).total_seconds() // _FANO_BIN_S)] += 1

    def finalize(
        self,
        *,
        event_count: int,
        distinct_paths: int,
        window_s: int,
        ua: str | None,
        memory: EntityMemory,
    ) -> dict[str, float]:
        n = max(event_count, 1)
        return {
            "bot.asset_fetch_ratio": self.asset_hits / n,
            "bot.activity_hour_entropy": memory.activity_hour_entropy,
            "bot.referrer_chain_depth": float(self.max_chain_depth),
            "bot.path_repeat_ratio": (
                (event_count - distinct_paths) / n if event_count else 0.0
            ),
            "bot.method_get_ratio": (
                self.get_hits / self.method_seen if self.method_seen else 0.0
            ),
            "bot.bytes_per_req_p50": (
                float(statistics.median(self.bytes_samples))
                if self.bytes_samples
                else 0.0
            ),
            "bot.robots_txt_fetched": 1.0 if memory.robots_txt_fetched else 0.0,
            "bot.declared_bot": 1.0 if declared_bot(ua) else 0.0,
            "timing.fano_factor": _fano(self.sub_bins, window_s // _FANO_BIN_S),
        }


def _referrer_path(referrer: str | None) -> str | None:
    """The path component of a referrer, or None.

    Referrers arrive both as absolute URLs and bare paths; queries and
    fragments never take part in chain matching.
    """
    if not referrer:
        return None
    if "://" in referrer:
        rest = referrer.split("://", 1)[1]
        slash = rest.find("/")
        referrer = rest[slash:] if slash >= 0 else "/"
    return referrer.split("?", 1)[0].split("#", 1)[0] or None


def _fano(sub_bins: Counter, n_bins: int) -> float:
    """Fano factor (variance/mean) of per-sub-bin event counts.

    ~1 for Poisson-like human arrivals; well below 1 for metronomic
    automation; well above 1 for burst-and-sleep crawling. Empty sub-bins
    count — a burst is only a burst relative to the silence around it.
    """
    if n_bins <= 1:
        return 0.0
    counts = [sub_bins.get(i, 0) for i in range(n_bins)]
    mean = sum(counts) / n_bins
    if mean <= 0:
        return 0.0
    var = sum((c - mean) ** 2 for c in counts) / n_bins
    return var / mean
