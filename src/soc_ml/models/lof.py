"""Local Outlier Factor (novelty mode) — the local-neighborhood complement.

The spec pairs LOF with Isolation Forest for web_recon (UC-02): IForest finds
globally isolated vectors; LOF catches odd-in-local-neighborhood behaviour that
survives global statistics, which matters on small/quiet servers. Fusion is max
of the two after percentile conversion — done by the use case, not here.

LOF is distance-based, so features are standardized inside the wrapper (the
scaler is part of the artifact — a model without its scaler is a different
model).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from soc_ml.core.plugins import Model

__all__ = ["LOFNoveltyModel"]


class LOFNoveltyModel(Model):
    name = "lof_novelty"
    description = "Local Outlier Factor (novelty mode) over entity-window vectors"
    incremental = False

    N_NEIGHBORS = 20

    def __init__(self) -> None:
        self._pipeline = None
        self._features: list[str] = []

    def fit(self, X: Iterable[dict[str, float]]) -> None:
        import numpy as np
        from sklearn.neighbors import LocalOutlierFactor
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        rows = list(X)
        if not rows:
            raise ValueError("lof_novelty: empty training corpus")
        self._features = sorted(rows[0].keys())
        matrix = np.array(
            [[row.get(f, 0.0) for f in self._features] for row in rows], dtype=float
        )
        n_neighbors = min(self.N_NEIGHBORS, max(2, len(rows) - 1))
        self._pipeline = Pipeline(
            [
                ("scale", StandardScaler()),
                ("lof", LocalOutlierFactor(n_neighbors=n_neighbors, novelty=True)),
            ]
        ).fit(matrix)

    def score(self, x: dict[str, float]) -> float:
        import numpy as np

        if self._pipeline is None:
            raise RuntimeError("lof_novelty: score() before fit()/load()")
        row = np.array([[x.get(f, 0.0) for f in self._features]], dtype=float)
        return float(-self._pipeline.score_samples(row)[0])

    def save(self, path: Path) -> None:
        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": self._pipeline, "features": self._features}, path)

    def load(self, path: Path) -> None:
        import joblib

        blob = joblib.load(path)
        self._pipeline = blob["pipeline"]
        self._features = blob["features"]

    @property
    def feature_names(self) -> list[str]:
        return list(self._features)
