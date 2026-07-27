"""Isolation Forest wrapper — the workhorse for entity-window anomaly vectors.

Raw scores are ``-score_samples`` (higher = more anomalous) and are meaningless
across servers until percentile-calibrated (FR-22). Callers own corpus hygiene
(FR-56) — this class fits what it is given.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from soc_ml.core.plugins import Model

__all__ = ["IsolationForestModel"]


class IsolationForestModel(Model):
    name = "isolation_forest"
    description = "Isolation Forest over entity-window feature vectors"
    incremental = False

    N_ESTIMATORS = 200
    RANDOM_STATE = 7  # determinism: same corpus -> same model (NFR-10)

    def __init__(self) -> None:
        self._model = None
        self._features: list[str] = []

    def fit(self, X: Iterable[dict[str, float]]) -> None:
        import numpy as np
        from sklearn.ensemble import IsolationForest

        rows = list(X)
        if not rows:
            raise ValueError("isolation_forest: empty training corpus")
        self._features = sorted(rows[0].keys())
        matrix = np.array(
            [[row.get(f, 0.0) for f in self._features] for row in rows], dtype=float
        )
        self._model = IsolationForest(
            n_estimators=self.N_ESTIMATORS,
            random_state=self.RANDOM_STATE,
            n_jobs=-1,
        ).fit(matrix)

    def score(self, x: dict[str, float]) -> float:
        import numpy as np

        if self._model is None:
            raise RuntimeError("isolation_forest: score() before fit()/load()")
        row = np.array([[x.get(f, 0.0) for f in self._features]], dtype=float)
        return float(-self._model.score_samples(row)[0])

    def score_batch(self, rows: list[dict[str, float]]) -> list[float]:
        """Score many rows in ONE sklearn call — vectorized, not a per-row loop.

        Training scores tens of thousands of windows twice (hygiene ranking +
        calibration); doing that one row at a time makes training minutes-to-hours
        slower than it needs to be.
        """
        import numpy as np

        if self._model is None:
            raise RuntimeError("isolation_forest: score_batch() before fit()/load()")
        if not rows:
            return []
        matrix = np.array(
            [[x.get(f, 0.0) for f in self._features] for x in rows], dtype=float
        )
        return [float(v) for v in -self._model.score_samples(matrix)]

    def save(self, path: Path) -> None:
        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "features": self._features}, path)

    def load(self, path: Path) -> None:
        import joblib

        blob = joblib.load(path)
        self._model = blob["model"]
        self._features = blob["features"]

    @property
    def feature_names(self) -> list[str]:
        return list(self._features)
