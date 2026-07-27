"""bot_detection (UC-04) — Bot & Abnormal Crawler Detection.

The unusual detector (JOURNAL D-019): its *primary* product is the per-entity
crawler signal it exports for other use cases — ``crawler.human_likeness``,
``crawler.is_known``, ``crawler.is_verified`` — which suppresses the
search-engine false positives that dominate ``web_recon`` in production. Its
*own* alert is the narrower catch: **UA spoofing**, a client that declares a
browser but behaves like a machine.

The self-supervised trick (spec §5, UC-04): ``bot.declared_bot`` — derived
from the UA string — is a free label. The GBM predicts it from behavior only,
the GMM reads association with the population's bot-shaped modes, and HDBSCAN
(optional) clusters undeclared automation with the declared kind. All three
are calibrated to percentiles per server (FR-22).

Gate (spec): a **browser-declared** entity whose fused P(bot | behavior)
percentile holds at or above p99.5 for **six consecutive 5-minute windows**
(>= 30 min sustained) fires a UA-spoofing alert. Declared bots never
self-alert here — they are the training signal and flow to the export instead.
The clustering model's percentile is deliberately excluded from the gate
fusion: sitting in a crawler cluster is association evidence for the export,
not spoofing evidence (a verified Googlebot lives there legitimately).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import FeatureVector, RunMode
from soc_ml.core.plugins import UseCase
from soc_ml.features.bot_features import BOT_DETECTION_FEATURES

__all__ = ["BotDetection"]

_MAX_TRACKED_STREAKS = 100_000  # entities with an active over-gate streak


class BotDetection(UseCase):
    # Naming triple — docs/NAMING.md. The slug is the canonical name everywhere.
    name = "bot_detection"
    usecase_id = "UC-04"
    title = "Bot & Abnormal Crawler Detection"
    description = (
        "Separates bots from humans by behavior; alerts on UA spoofing, exports "
        "the crawler signal that suppresses other detectors' false positives"
    )

    tier = 1
    requires = BOT_DETECTION_FEATURES + (
        "timing.interarrival_cv",
        "ua.rarity",
        "ua.len",
        "web.referrer_absent_ratio",
        "web.status_2xx_ratio",
        "web.status_3xx_ratio",
        "web.status_4xx_ratio",
        "web.status_5xx_ratio",
    )
    models = ("gbm_bot", "gmm", "hdbscan_cluster")
    default_mode = RunMode.SHADOW
    daily_alert_budget = 50

    # Spec constants (SPEC_DIGEST §5, UC-04). They live in code because they
    # ARE the specification — config carries policy only (FR-62).
    GATE_PERCENTILE = 0.995
    #: 6 consecutive 5-minute windows = the spec's "sustained >= 30 min".
    SUSTAINED_WINDOWS = 6
    #: Only these models vote on the spoofing gate; the cluster model feeds
    #: the export, not the alert.
    GATE_MODELS = ("gbm_bot", "gmm")
    # Conservative evidence floor (spec leaves UC-04's floor implicit; same
    # reading as D-017): too few requests is noise, not a bot judgment.
    MIN_EVENTS = 5

    def __init__(self, profile: EnvironmentProfile) -> None:
        self.profile = profile
        # entity -> (consecutive over-gate windows, end of the last one).
        # Event-time based, so backtest and live behave identically.
        self._streaks: dict[str, tuple[int, datetime]] = {}

    @classmethod
    def canary(cls, server, start):
        """Browser-declared, machine-behaving traffic — the spoofing check."""
        from soc_ml.evaluation.canary import spoofer_canary_events

        return spoofer_canary_events(server, start)

    # ------------------------------------------------------------------ #

    def vector(self, fv: FeatureVector) -> dict[str, float] | None:
        """Model input: bot behavior features plus reused timing/ua/web ones.

        ``bot.declared_bot`` rides along as the GBM/GMM label; the model
        wrappers themselves exclude it (and every ``ua.*`` feature) from
        behavioral inputs — leakage protection is structural, not etiquette.
        """
        if fv.window != "5m":
            return None
        x = fv.subset(list(self.requires))
        if len(x) < len(self.requires):
            return None  # incomplete vector — refuse rather than zero-fill
        return x

    def fuse(self, calibrated: dict[str, float]) -> float:
        """Max over the gate models only (cluster membership never gates)."""
        gating = [v for k, v in calibrated.items() if k in self.GATE_MODELS]
        return max(gating) if gating else max(calibrated.values())

    def calibration_rows(
        self, model_slug: str, rows: list[dict[str, float]]
    ) -> list[dict[str, float]]:
        """Gate models calibrate against **browser-declared** windows.

        The spoofing question is "more bot-like than 99.5% of the *browsers*
        here" — calibrating against all traffic would let real crawler volume
        raise the bar until no spoofer could ever clear it. The cluster model
        keeps the full population (association is population-wide).
        """
        if model_slug in self.GATE_MODELS:
            return [r for r in rows if r.get("bot.declared_bot", 0.0) < 0.5]
        return rows

    def gate(self, fused_percentile: float, evidence: dict[str, Any]) -> bool:
        """Browser-declared + over p99.5 + sustained 30 min (FR-22/23/24).

        Declared bots return False unconditionally — they are the training
        signal, and their handling is the crawler export, not an alert.
        """
        entity = evidence.get("entity", "?")
        window_end = _parse_ts(evidence.get("window_end"))

        over = (
            fused_percentile >= self.GATE_PERCENTILE
            and not evidence.get("declared_bot", False)
            and evidence.get("event_count", 0) >= self.MIN_EVENTS
            and window_end is not None
        )
        if not over:
            self._streaks.pop(entity, None)
            return False

        streak, last_end = self._streaks.get(entity, (0, None))
        # Consecutive means adjacent 5-minute windows; a silent window in
        # between breaks the "sustained" claim and restarts the count.
        if last_end is not None and window_end - last_end > timedelta(minutes=5):
            streak = 0
        streak += 1
        if len(self._streaks) >= _MAX_TRACKED_STREAKS and entity not in self._streaks:
            self._prune(window_end)
        self._streaks[entity] = (streak, window_end)
        return streak >= self.SUSTAINED_WINDOWS

    def _prune(self, now: datetime) -> None:
        """Drop streaks whose last window is stale — they are broken anyway."""
        cutoff = now - timedelta(minutes=10)
        for entity in [e for e, (_, end) in self._streaks.items() if end < cutoff]:
            del self._streaks[entity]


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None
