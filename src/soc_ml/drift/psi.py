"""Drift detection — Population Stability Index (PSI).

The promise "the model never becomes outdated" needs a way to *notice* when the
world has moved. PSI compares the distribution of a feature now against the
distribution the model was trained on, per feature. It is the standard,
interpretable drift measure and needs no labels — which suits an unsupervised
detector.

    PSI = sum over bins of  (now% - train%) * ln(now% / train%)

Conventional reading (adopted by the spec, §8/§15):
    PSI < 0.10   stable
    0.10-0.25    moderate drift — watch
    > 0.25       significant drift — retrain (the spec's weekly trigger)

The live runtime accumulates recent feature values in a bounded reservoir and
periodically computes PSI against the bundle's training reference. A feature
crossing 0.25 raises a health event and flags the bundle for retraining — drift
is a retrain *trigger*, never a silent model swap.
"""

from __future__ import annotations

import math

__all__ = ["population_stability_index", "DriftReport", "drift_band"]

_EPS = 1e-6  # keeps ln() finite when a bin is empty on one side


def population_stability_index(
    reference: list[float], current: list[float], bins: int = 10
) -> float:
    """PSI of ``current`` against ``reference`` using reference deciles.

    Bin edges come from the reference quantiles, so each reference bin holds ~the
    same mass and PSI reflects how differently the current sample distributes
    across the model's own training regions. Returns 0.0 when either side is too
    small to be meaningful (the caller treats that as "insufficient data").
    """
    if len(reference) < bins or len(current) < bins:
        return 0.0

    import numpy as np

    ref = np.asarray(reference, dtype=float)
    cur = np.asarray(current, dtype=float)

    # Quantile edges from the reference; dedupe so constant features don't crash.
    qs = np.linspace(0.0, 1.0, bins + 1)
    edges = np.unique(np.quantile(ref, qs))
    if len(edges) < 3:
        return 0.0  # near-constant feature — PSI is not meaningful
    edges[0], edges[-1] = -np.inf, np.inf

    ref_pct = np.histogram(ref, bins=edges)[0] / len(ref)
    cur_pct = np.histogram(cur, bins=edges)[0] / len(cur)

    psi = 0.0
    for r, c in zip(ref_pct, cur_pct):
        r_, c_ = max(r, _EPS), max(c, _EPS)
        psi += (c_ - r_) * math.log(c_ / r_)
    return float(psi)


def drift_band(psi: float) -> str:
    if psi > 0.25:
        return "significant"
    if psi >= 0.10:
        return "moderate"
    return "stable"


class DriftReport:
    """Per-feature PSI plus an overall verdict."""

    def __init__(self, per_feature: dict[str, float]) -> None:
        self.per_feature = per_feature

    @property
    def max_psi(self) -> float:
        return max(self.per_feature.values(), default=0.0)

    @property
    def band(self) -> str:
        return drift_band(self.max_psi)

    @property
    def drifted_features(self) -> list[str]:
        return sorted(
            (f for f, v in self.per_feature.items() if v > 0.25),
            key=lambda f: self.per_feature[f],
            reverse=True,
        )

    def should_retrain(self, min_features: int = 2) -> bool:
        """Spec weekly trigger: PSI > 0.25 on >= 2 features (§8)."""
        return len(self.drifted_features) >= min_features

    def to_dict(self) -> dict:
        return {
            "max_psi": round(self.max_psi, 4),
            "band": self.band,
            "drifted_features": self.drifted_features,
            "should_retrain": self.should_retrain(),
            "per_feature": {f: round(v, 4) for f, v in self.per_feature.items()},
        }
