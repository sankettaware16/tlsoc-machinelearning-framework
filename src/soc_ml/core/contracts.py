"""The data contracts every part of the framework agrees on.

These types are the framework's spine. `Event` in particular is *frozen* — it
mirrors the ECS JSON that the log parser emits (SPEC_DIGEST §3) and is the only
hard dependency between this framework and the outside world. Anything that can
produce this shape can drive the framework.

Two rules that are enforced elsewhere but originate here:

* ``Event.original`` is evidence for a human. It is **never** a model input.
* ``observer.*`` fields are namespace/partitioning keys. They are **never**
  features — otherwise a model learns "server X is suspicious" instead of
  learning what suspicious behaviour looks like.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

__all__ = [
    "Event",
    "Observer",
    "EntityKey",
    "Session",
    "FeatureVector",
    "Score",
    "Alert",
    "Insight",
    "Severity",
    "Verdict",
    "RunMode",
    "Profile",
]


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class RunMode(str, Enum):
    """What a use case is permitted to do (ARCHITECTURE §4).

    Orthogonal to :class:`Profile` and settable *per use case*, which is how the
    staged cold-start is expressed: Tier-1 ``LIVE`` while Tier-2 still
    ``SHADOW``.
    """

    OFFLINE = "offline"  # historical input, results to a report only
    SHADOW = "shadow"  # live input, scored and recorded, never delivered
    LIVE = "live"  # scored and delivered to sinks


class Profile(str, Enum):
    """How much infrastructure is available (ARCHITECTURE §3)."""

    STANDALONE = "standalone"  # no infra: files + SQLite + local registry
    CLUSTER = "cluster"  # Kafka + Redis
    ENTERPRISE = "enterprise"  # + MLflow, Elasticsearch, Flink


class Severity(str, Enum):
    """Alert severity bands, cut from ``severity_score`` (SPEC_DIGEST §7)."""

    LOW = "low"  # < 45
    MEDIUM = "medium"  # 45-69
    HIGH = "high"  # 70-89
    CRITICAL = "critical"  # >= 90

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 45:
            return cls.MEDIUM
        return cls.LOW


class Verdict(str, Enum):
    """Analyst feedback (SPEC_DIGEST §7).

    ``BENIGN_TRUE_POSITIVE`` is deliberately distinct from ``FALSE``: the model
    was *correct* that the behaviour was anomalous, but the activity was
    authorised. Counting it as a false positive would punish the model for being
    right and corrupt the precision metric.
    """

    REAL = "real"
    FALSE = "false"
    BENIGN_TRUE_POSITIVE = "benign-true-positive"
    NEEDS_INFO = "needs-info"


# --------------------------------------------------------------------------- #
# Input contract
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Observer:
    """Deployment identity. Namespace keys only — never features (FR-06)."""

    org: str | None = None
    dept: str | None = None
    env: str | None = None
    server: str | None = None
    source_host: str | None = None
    source_program: str | None = None

    @property
    def namespace(self) -> str:
        """Model/profile partition key: ``org/env/server``."""
        return "/".join(p or "_" for p in (self.org, self.env, self.server))


@dataclass(frozen=True, slots=True)
class Event:
    """One normalized web-traffic event — the framework's input contract.

    Mirrors the parser's ECS JSON (SPEC_DIGEST §3). Optional fields are genuinely
    optional in the wild; a feature that needs one must handle its absence rather
    than assume it.
    """

    timestamp: datetime
    observer: Observer

    source_ip: str | None = None
    # Absence of geo *is* the internal/external flag — internal RFC1918 addresses
    # never resolve. Do not treat missing geo as a data-quality problem.
    geo_country_iso: str | None = None
    geo_country_name: str | None = None
    geo_city: str | None = None
    geo_lat: float | None = None
    geo_lon: float | None = None

    http_method: str | None = None
    http_referrer: str | None = None  # literally "-" when absent, not null
    status_code: int | None = None
    body_bytes: int | None = None

    url_path: str | None = None
    url_query: str | None = None

    user_agent: str | None = None

    #: ECS ``event.category`` / ``event.type``. Kept because a web log carries
    #: more than requests: nginx writes its *error* channel to the same stream,
    #: and an error record is not a request even though it names a URL.
    event_category: str | None = None
    event_type: str | None = None

    module: str | None = None
    #: Raw log line. Evidence for humans only — NEVER a model input (FR-05).
    original: str | None = None

    #: Anything the parser carried that the contract does not name.
    extra: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def ua_hash(self) -> str:
        """Stable short hash of the user agent, used in the entity key."""
        ua = self.user_agent or ""
        return hashlib.sha256(ua.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def entity(self) -> "EntityKey":
        """The reconstructed actor (SPEC_DIGEST §3).

        Logs carry no usernames, so identity is ``(server, ip, ua_hash)``. This
        is *approximate* and fragments under CGNAT and shared proxies — a stated
        limitation, not a bug to be worked around silently.
        """
        return EntityKey(
            server=self.observer.server or "_",
            ip=self.source_ip or "_",
            ua_hash=self.ua_hash,
        )

    @property
    def is_internal(self) -> bool:
        """True when the source has no resolved geo, i.e. a private address."""
        return self.source_ip is not None and self.geo_country_iso is None

    @classmethod
    def from_ecs(cls, doc: dict[str, Any]) -> "Event":
        """Build an Event from one parsed ECS JSON document.

        This is the single place the wire format is interpreted, so quirks live
        here rather than being rediscovered in every feature:

        * ``http.request.referrer`` is the literal string ``"-"`` when absent —
          normalized to ``None`` so features don't have to special-case it.
        * ``url.query`` may be ``null`` or absent; both mean "no query string".
        * Missing ``source.geo`` is meaningful, not a defect: it identifies an
          internal address.

        Raises :class:`ValueError` when a required field is missing or
        unparseable, so bad input dead-letters loudly instead of becoming a
        silently degraded event (NFR-09).
        """
        ts_raw = doc.get("@timestamp")
        if not ts_raw:
            raise ValueError("missing @timestamp")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"unparseable @timestamp {ts_raw!r}") from exc

        obs = doc.get("observer") or {}
        src = doc.get("source") or {}
        geo = src.get("geo") or {}
        loc = geo.get("location") or {}
        http = doc.get("http") or {}
        req = http.get("request") or {}
        resp = http.get("response") or {}
        body = resp.get("body") or {}
        url = doc.get("url") or {}
        evt = doc.get("event") or {}

        referrer = req.get("referrer")
        if referrer == "-":
            referrer = None

        return cls(
            timestamp=ts,
            observer=Observer(
                org=obs.get("org"),
                dept=obs.get("dept"),
                env=obs.get("env"),
                server=obs.get("server"),
                source_host=obs.get("source_host"),
                source_program=obs.get("source_program"),
            ),
            source_ip=src.get("ip"),
            geo_country_iso=geo.get("country_iso_code"),
            geo_country_name=geo.get("country_name"),
            geo_city=geo.get("city_name"),
            geo_lat=loc.get("lat"),
            geo_lon=loc.get("lon"),
            http_method=req.get("method"),
            http_referrer=referrer,
            status_code=resp.get("status_code"),
            body_bytes=body.get("bytes"),
            url_path=url.get("path"),
            url_query=url.get("query"),
            user_agent=(doc.get("user_agent") or {}).get("original"),
            event_category=evt.get("category"),
            event_type=evt.get("type"),
            module=evt.get("module"),
            original=evt.get("original"),
        )

    @property
    def is_request(self) -> bool:
        """Does this record describe a request a client actually made?

        A web log stream is not all requests. nginx's error channel lands in
        the same file and the parser labels it ``event.type: error`` — those
        records name a URL but carry no status, no bytes and no user-agent, so
        folding them into request features invents an entity that made
        "requests" no browser made.

        Only a *positive* non-access label excludes a record. A shipper that
        sets no ``event.type`` (Filebeat, Vector, a hand-rolled producer) still
        gets its events processed — the contract asks for access logs, and
        assuming the worst about a silent producer would drop real traffic.
        """
        return self.event_type is None or self.event_type == "access"


@dataclass(frozen=True, slots=True)
class EntityKey:
    """The unit of behavioural analysis."""

    server: str
    ip: str
    ua_hash: str

    def __str__(self) -> str:
        return f"{self.server}|{self.ip}|{self.ua_hash}"


@dataclass(slots=True)
class Session:
    """A reconstructed visit: consecutive same-entity events until an idle gap.

    The gap (default 30 min) is a *grouping* default, not a detection threshold —
    it may live in config without violating FR-62.

    Sequence fields (``paths``, ``status_codes``, ``methods``,
    ``inter_arrivals``) are **capped** by the sessionizer. A scraping session can
    run to hundreds of thousands of requests, and an uncapped per-session list is
    how a streaming detector runs a box out of memory. ``truncated`` records that
    it happened, because a silently shortened sequence would quietly corrupt any
    sequence-based feature.
    """

    entity: EntityKey
    started_at: datetime
    last_seen_at: datetime
    event_count: int = 0
    bytes_total: int = 0
    #: Distinct paths seen. Unbounded uniques are capped alongside the sequences.
    unique_paths: set[str] = field(default_factory=set)
    #: Ordered request sequence (capped).
    paths: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    inter_arrivals: list[float] = field(default_factory=list)
    referrer_present: int = 0
    entry_path: str | None = None
    exit_path: str | None = None
    truncated: bool = False
    closed: bool = False

    @property
    def duration_s(self) -> float:
        return (self.last_seen_at - self.started_at).total_seconds()


# --------------------------------------------------------------------------- #
# Pipeline types
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FeatureVector:
    """Named features for one entity over one window.

    Feature names are namespaced by group (``path.idf_mean``, ``timing.cv``) so
    that two groups cannot silently collide.
    """

    entity: EntityKey
    window: str  # "1m" | "5m" | "30m" | "24h" | "7d" | "168h"
    computed_at: datetime
    values: dict[str, float] = field(default_factory=dict)

    def subset(self, names: list[str]) -> dict[str, float]:
        """Features a use case declared, missing ones omitted rather than zeroed.

        Zero-filling is wrong here: for most of these features zero is a
        meaningful value, so a missing feature must stay missing and let the
        model or gate decide.
        """
        return {n: self.values[n] for n in names if n in self.values}


@dataclass(slots=True)
class Score:
    """One use case's opinion about one entity.

    ``raw`` is model-specific and meaningless across servers. ``percentile`` is
    the calibrated 0-1 value, and it is the **only** one that may be compared or
    gated (FR-22).
    """

    usecase: str  # "UC-02"
    entity: EntityKey
    window: str
    computed_at: datetime
    raw: float
    percentile: float | None = None
    features: dict[str, float] = field(default_factory=dict)
    model_version: str | None = None
    #: Set when the gate's evidence floor was met (FR-23).
    elevated: bool = False

    def require_calibrated(self) -> float:
        if self.percentile is None:
            raise ValueError(
                f"{self.usecase}: raw scores must be percentile-calibrated "
                "before comparison or gating (FR-22)"
            )
        return self.percentile


@dataclass(slots=True)
class Alert:
    """A delivered detection, ECS-aligned (SPEC_DIGEST §7).

    Every suppression, fold, and budget decision must remain visible in this
    document — silence is the one unacceptable failure (NFR-09).
    """

    id: str
    timestamp: datetime
    usecase: str
    entity: EntityKey
    severity: Severity
    severity_score: int  # 0-100
    confidence: float  # 0-1, fused
    scores: dict[str, float] = field(default_factory=dict)
    #: Per-feature attributions with population context (FR-40/41).
    top_features: list[dict[str, Any]] = field(default_factory=list)
    narrative: str | None = None
    #: 3-10 verbatim raw log lines (FR-42).
    evidence: list[str] = field(default_factory=list)
    model_versions: dict[str, str] = field(default_factory=dict)
    links: dict[str, Any] = field(default_factory=dict)
    suppressed_by: str | None = None
    delivered: bool = True
    feedback: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Insight:
    """An analytics finding (AU-nn). Informational — never an alarm."""

    id: str
    timestamp: datetime
    analytics_case: str  # "AU-01"
    namespace: str
    title: str
    body: str
    metrics: dict[str, Any] = field(default_factory=dict)
    links: dict[str, Any] = field(default_factory=dict)
