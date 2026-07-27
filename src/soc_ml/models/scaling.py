"""Per-feature standardization for distance/density models.

GMM and clustering operate in feature space directly, where
``bot.bytes_per_req_p50`` (thousands) would drown ``bot.asset_fetch_ratio``
(0-1) without scaling. Tree models don't care and don't use this. The scaler is
part of the fitted artifact — the exact transform that trained the model scores
with it (NFR-10).
"""

from __future__ import annotations

__all__ = ["FeatureScaler"]

_EPS = 1e-9


class FeatureScaler:
    """z-score per feature over a fixed, sorted feature list."""

    def __init__(self) -> None:
        self.features: list[str] = []
        self._mean: list[float] = []
        self._std: list[float] = []

    def fit(self, rows: list[dict[str, float]]) -> "FeatureScaler":
        import numpy as np

        if not rows:
            raise ValueError("scaler: cannot fit on zero rows")
        self.features = sorted(rows[0].keys())
        matrix = np.array(
            [[row.get(f, 0.0) for f in self.features] for row in rows], dtype=float
        )
        self._mean = [float(v) for v in matrix.mean(axis=0)]
        self._std = [float(v) for v in matrix.std(axis=0)]
        return self

    def transform(self, rows: list[dict[str, float]]):
        import numpy as np

        matrix = np.array(
            [[row.get(f, 0.0) for f in self.features] for row in rows], dtype=float
        )
        mean = np.array(self._mean)
        std = np.array(self._std)
        return (matrix - mean) / (std + _EPS)

    # -- persistence -------------------------------------------------------- #

    def to_dict(self) -> dict:
        return {"features": self.features, "mean": self._mean, "std": self._std}

    @classmethod
    def from_dict(cls, doc: dict) -> "FeatureScaler":
        scaler = cls()
        scaler.features = list(doc["features"])
        scaler._mean = [float(v) for v in doc["mean"]]
        scaler._std = [float(v) for v in doc["std"]]
        return scaler
