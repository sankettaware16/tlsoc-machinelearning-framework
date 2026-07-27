"""Scorer — the one scoring path, shared by backtest and live runtime.

Given a trained :class:`ModelBundle`, it turns a closed feature window into a
verdict: the per-model calibrated percentiles, the fused confidence, whether the
gate fired, and — if it did — a fully-explained :class:`Alert`.

Nothing here knows about *delivery*. Whether an alert is written, suppressed by
mode, or deduplicated is the runtime's decision (SPEC: gates and budgets control
delivery, never detection). The scorer's job is to decide, explain, and record.

Because backtest and live both call this, a backtest exercises the exact code
that will serve production traffic (FR-72).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from soc_ml.core.contracts import Alert, EntityKey, Severity
from soc_ml.core.plugins import UseCase
from soc_ml.detection.annotations import EntityAnnotations
from soc_ml.explain.context import narrative, top_features
from soc_ml.features.window_features import WindowResult
from soc_ml.fusion.severity import severity_score
from soc_ml.registry.store import ModelBundle

__all__ = ["Scorer", "ScoreResult"]

#: Severity reduction for a down-weighted alert — one band (the bands are
#: 25-point wide, SPEC_DIGEST §7). A fusion constant, in code like the gates.
_DOWNWEIGHT_POINTS = 25


@dataclass(slots=True)
class ScoreResult:
    """The outcome of scoring one window."""

    entity: EntityKey
    window_end: str
    fused_percentile: float
    per_model: dict[str, float]
    fired: bool
    evidence: dict[str, Any]
    #: The finalized model-input features — used by drift monitoring.
    features: dict[str, float] = field(default_factory=dict)
    #: Raw (uncalibrated) per-model scores. Gates never touch these (FR-22);
    #: they exist for exports whose semantics *are* the raw value — the GBM's
    #: isotonic P(bot|behavior) is itself the human-likeness signal.
    per_model_raw: dict[str, float] = field(default_factory=dict)
    alert: Alert | None = None

    def record(self) -> dict[str, Any]:
        """The always-written audit line (every score, alert or not)."""
        row = {
            "window_end": self.window_end,
            "entity": str(self.entity),
            "fused_pct": round(self.fused_percentile, 5),
            "fired": self.fired,
            "event_count": self.evidence.get("event_count"),
        }
        row.update({f"{m}_pct": round(p, 5) for m, p in self.per_model.items()})
        if self.alert is not None and self.alert.suppressed_by:
            # The before/after measurement lives here: fired stays true,
            # the suppression is its own visible fact (NFR-09).
            row["suppressed_by"] = self.alert.suppressed_by
        return row


class Scorer:
    """Scores windows for one use case using one trained bundle.

    ``annotations`` is the shared cross-use-case store: before gating, the
    entity's current annotations are injected into the window evidence (so a
    consumer's gate can read what an upstream use case exported); after
    scoring, whatever this use case's :meth:`UseCase.annotate` returns is
    written back for the use cases that run after it.
    """

    def __init__(
        self,
        usecase_cls: type[UseCase],
        bundle: ModelBundle,
        annotations: EntityAnnotations | None = None,
    ) -> None:
        self.bundle = bundle
        self.usecase_cls = usecase_cls
        self.usecase = usecase_cls(bundle.profile)
        self.slug = usecase_cls.name
        self.annotations = annotations

    def score(self, result: WindowResult, *, synthetic: bool = False) -> ScoreResult | None:
        """Score one window. Returns None when the window is not applicable."""
        x = self.usecase.vector(result.vector)
        if x is None:
            return None

        entity_str = str(result.vector.entity)
        if self.annotations is not None:
            # What upstream use cases currently know about this entity (None
            # is meaningful: "no signal" must stay distinguishable, NFR-09).
            result.evidence["entity_annotations"] = self.annotations.get(entity_str)

        per_model_raw = {
            mslug: model.score(x) for mslug, model in self.bundle.models.items()
        }
        per_model = {
            mslug: self.bundle.calibrators[mslug].percentile(raw)
            for mslug, raw in per_model_raw.items()
        }
        fused = self.usecase.fuse(per_model)
        fired = self.usecase.gate(fused, result.evidence)

        out = ScoreResult(
            entity=result.vector.entity,
            window_end=result.vector.computed_at.isoformat(),
            fused_percentile=fused,
            per_model=per_model,
            fired=fired,
            evidence=result.evidence,
            features=x,
            per_model_raw=per_model_raw,
        )
        if fired:
            out.alert = self._build_alert(x, result, per_model, fused, synthetic)
            self._apply_suppression(out)

        if self.annotations is not None:
            exported = self.usecase.annotate(out)
            if exported:
                self.annotations.annotate(
                    entity_str, exported, at=out.window_end, source=self.slug
                )
        return out

    # ------------------------------------------------------------------ #

    def _apply_suppression(self, out: ScoreResult) -> None:
        """The fusion 'suppress' stage: after detection, before delivery.

        Detection is already decided (``fired`` never changes here). A
        suppression withholds delivery; a down-weight lowers severity one
        band. Both leave their reason on the alert document (NFR-09).
        """
        decision = self.usecase.suppression(out.evidence)
        if decision is None:
            return
        kind, reason = decision
        alert = out.alert
        if kind == "suppress":
            alert.suppressed_by = reason
            alert.delivered = False
        else:
            alert.severity_score = max(alert.severity_score - _DOWNWEIGHT_POINTS, 0)
            alert.severity = Severity.from_score(alert.severity_score)
            alert.links["downweighted_by"] = reason

    def _build_alert(
        self,
        x: dict[str, float],
        result: WindowResult,
        per_model: dict[str, float],
        fused: float,
        synthetic: bool,
    ) -> Alert:
        score_0_100, band = severity_score(fused)
        top = top_features(x, self.bundle.profile, self.slug)
        entity = result.vector.entity
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=result.vector.computed_at,
            usecase=self.slug,
            entity=entity,
            severity=band,
            severity_score=score_0_100,
            confidence=fused,
            scores={"fused_pct": fused, **per_model},
            top_features=top,
            narrative=narrative(
                self.usecase_cls.title, entity.ip, entity.server, result.evidence, top
            ),
            evidence=result.evidence.get("raw_lines", [])[:10],
            model_versions=dict.fromkeys(self.bundle.models, self.bundle.version),
            links={
                "rule_id": self.usecase_cls.usecase_id,
                "rule_name": self.usecase_cls.title,
                "synthetic": synthetic,
                # The upstream annotation snapshot the delivery decision saw —
                # audit context for suppress/downweight (NFR-09).
                **(
                    {"entity_annotations": result.evidence["entity_annotations"]}
                    if result.evidence.get("entity_annotations")
                    else {}
                ),
            },
        )
