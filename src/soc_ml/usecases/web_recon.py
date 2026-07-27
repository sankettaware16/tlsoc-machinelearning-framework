"""web_recon (UC-02) — Web Reconnaissance & Directory Enumeration.

Detects wordlist/path scanning (gobuster, ffuf, dirsearch and their quieter
cousins) by *shape*, not rate: a scanner's window is heavy on 404s, requests
paths this server has never served (high IDF), spreads path tokens thin (high
entropy), asks for extensions the app doesn't serve (.env/.sql/.bak), and skips
referrers. All of that survives slowing the scan down — the spec chose this as
the rate-independent Tier-1 detection.

Models (spec §5, UC-02): Isolation Forest (global outliers) + LOF in novelty
mode (odd-in-local-neighborhood, which matters on small servers). **Fusion is
max of the two after percentile conversion** — a vector only needs to look
anomalous through one lens.

Gate (spec): fused percentile >= 99.7, plus an evidence floor. The spec gives
UC-02 no explicit floor number (unlike UC-06/09/15), so per the ambiguity rule
we take the conservative reading — journaled in D-017: at least 5 requests and
3 distinct paths in the window before we are willing to judge at all.

Crawler suppression (Phase 3.5, JOURNAL D-019): this use case consumes
bot_detection's exported crawler annotation. The gate itself is untouched —
detection still fires and is still recorded — but a fired alert on a
**verified, polite** crawler (published-range identity + robots.txt fetched)
is suppressed at the delivery layer, and a known/borderline automation entity
is down-weighted one severity band. Every such decision is written onto the
alert document (``suppressed_by`` / ``links``) — never silent (NFR-09). When
bot_detection is not deployed, the annotation is absent and behaviour is
exactly as before: the missing signal means "unknown", not "human".

Not yet wired (arrives with later phases, by design):
* progressive alerting (first candidate "low", upgraded over a 10-min window);
* the fleet-simultaneity / campaign-folding fusion stages.
"""

from __future__ import annotations

from typing import Any

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import FeatureVector, RunMode
from soc_ml.core.plugins import UseCase
from soc_ml.features.window_features import WEB_RECON_FEATURES

__all__ = ["WebRecon"]


class WebRecon(UseCase):
    # Naming triple — docs/NAMING.md. The slug is the canonical name everywhere.
    name = "web_recon"
    usecase_id = "UC-02"
    title = "Web Reconnaissance & Directory Enumeration"
    description = "Detects directory/path enumeration by behavioural shape, rate-independent"

    tier = 1
    requires = WEB_RECON_FEATURES
    models = ("isolation_forest", "lof_novelty")
    default_mode = RunMode.SHADOW
    daily_alert_budget = 50
    #: bot_detection scores first each window so its crawler annotation
    #: exists by the time this gate's alert is considered for delivery.
    depends_on = ("bot_detection",)

    # Spec constants (SPEC_DIGEST §5, UC-02). These live in code because they
    # ARE the specification — config carries policy only (FR-62).
    GATE_PERCENTILE = 0.997
    # Conservative evidence floor (spec leaves UC-02's floor implicit; D-017).
    MIN_EVENTS = 5
    MIN_DISTINCT_PATHS = 3

    def __init__(self, profile: EnvironmentProfile) -> None:
        self.profile = profile

    @classmethod
    def canary(cls, server, start):
        """A deterministic enumeration burst — the backtest's detection check."""
        from soc_ml.evaluation.canary import canary_events

        return canary_events(server, start)

    # ------------------------------------------------------------------ #

    def vector(self, fv: FeatureVector) -> dict[str, float] | None:
        """Model input: the required features plus the population-delta feature.

        The spec's first UC-02 feature is "ratio_404 minus population median" —
        the delta is derived here (profile-backed), so the raw builder stays
        judgement-free.
        """
        if fv.window != "5m":
            return None
        x = fv.subset(list(self.requires))
        if len(x) < len(self.requires):
            return None  # incomplete vector — refuse rather than zero-fill

        pop = self.profile.population(self.name, "web.ratio_404")
        median_404 = pop.get("p50", 0.0)
        x["web.ratio_404_delta"] = x["web.ratio_404"] - median_404
        return x

    # fuse(): inherited default max() — exactly the spec's rule for UC-02.

    def gate(self, fused_percentile: float, evidence: dict[str, Any]) -> bool:
        """Fire only above the spec percentile AND the evidence floor (FR-23/24)."""
        if evidence.get("event_count", 0) < self.MIN_EVENTS:
            return False
        if evidence.get("distinct_paths", 0) < self.MIN_DISTINCT_PATHS:
            return False
        return fused_percentile >= self.GATE_PERCENTILE

    # Borderline automation: the exported human-likeness below an even-odds
    # read. A probability midpoint, not a tunable — it lives in code like the
    # spec's percentile gates (FR-62 concerns config, and this is not there).
    BORDERLINE_HUMAN_LIKENESS = 0.5

    def suppression(self, evidence: dict[str, Any]) -> tuple[str, str] | None:
        """Consume the crawler annotation: suppress certain, down-weight borderline.

        The gate has already fired when this runs — nothing here re-judges the
        anomaly or adds a detection threshold; it reads an upstream *identity
        and behavior* signal. No annotation means bot_detection is not
        deployed or has not seen this entity: deliver normally.
        """
        ann = evidence.get("entity_annotations")
        if not ann or ann.get("source") != "bot_detection":
            return None
        likeness = ann.get("crawler.human_likeness")
        if ann.get("crawler.is_verified"):
            if ann.get("crawler.robots_txt"):
                return (
                    "suppress",
                    "bot_detection: verified search-engine crawler "
                    f"(robots.txt respected, human_likeness {likeness})",
                )
            # Verified identity but impolite behavior — keep the alert, softer.
            return (
                "downweight",
                "bot_detection: verified crawler ignoring robots.txt "
                f"(human_likeness {likeness})",
            )
        if ann.get("crawler.is_known") or (
            likeness is not None and likeness < self.BORDERLINE_HUMAN_LIKENESS
        ):
            return (
                "downweight",
                f"bot_detection: known/borderline automation (human_likeness {likeness})",
            )
        return None
