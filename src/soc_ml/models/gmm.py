"""Human-likeness GMM (UC-04) — bot-likeness by population association.

A BIC-selected Gaussian mixture is fitted over the standardized behavior
vectors of *everything* (humans and bots — the training stream is unlabeled
traffic, FR-58 forbids synthetic labels). The free ``bot.declared_bot`` label
then annotates each fitted component with its declared-bot fraction, and

    score(x) = sum_k P(component k | x) * bot_fraction_k

— a smooth [0, 1] "how much does this behavior sit in bot territory". It is
the GBM's complement: the GBM draws a discriminative boundary, the GMM reads
association with the population's bot-shaped modes, and an entity can look
bot-like through either lens. ``1 - score`` is the human-likeness reading the
crawler export uses.

Like the GBM, UA-derived features are excluded from inputs — the label comes
from the UA, and association must be earned by behavior.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from soc_ml.core.plugins import Model
from soc_ml.models.scaling import FeatureScaler

__all__ = ["GMMModel"]


class GMMModel(Model):
    name = "gmm"
    description = "BIC-selected GMM: bot-likeness by component association (UC-04)"
    incremental = False

    LABEL_KEY = "bot.declared_bot"
    EXCLUDED_PREFIXES = ("ua.",)
    RANDOM_STATE = 7  # determinism (NFR-10)
    MAX_COMPONENTS = 8

    def __init__(self) -> None:
        self._model = None
        self._scaler: FeatureScaler | None = None
        self._bot_fraction: list[float] = []
        self.n_components = 0

    # ------------------------------------------------------------------ #

    def fit(self, X: Iterable[dict[str, float]]) -> None:
        import numpy as np
        from sklearn.mixture import GaussianMixture

        rows = list(X)
        if not rows:
            raise ValueError("gmm: empty training corpus")
        labels = np.array([row.get(self.LABEL_KEY, 0.0) >= 0.5 for row in rows])
        behavior = [
            {
                f: v
                for f, v in row.items()
                if f != self.LABEL_KEY and not f.startswith(self.EXCLUDED_PREFIXES)
            }
            for row in rows
        ]
        self._scaler = FeatureScaler().fit(behavior)
        matrix = self._scaler.transform(behavior)

        # BIC selection: smallest k whose model the data doesn't punish.
        best = None
        best_bic = None
        upper = min(self.MAX_COMPONENTS, max(1, len(rows) // 10))
        for k in range(1, upper + 1):
            candidate = GaussianMixture(
                n_components=k,
                covariance_type="diag",  # robust at small n, cheap at large n
                random_state=self.RANDOM_STATE,
                reg_covar=1e-4,
            ).fit(matrix)
            bic = candidate.bic(matrix)
            if best_bic is None or bic < best_bic:
                best, best_bic = candidate, bic
        self._model = best
        self.n_components = best.n_components

        # Annotate each component with its declared-bot share: soft
        # responsibilities, so a point between modes votes proportionally.
        resp = best.predict_proba(matrix)  # (n_rows, k)
        weights = resp.sum(axis=0)  # total mass per component
        bot_mass = resp[labels].sum(axis=0) if labels.any() else np.zeros_like(weights)
        self._bot_fraction = [
            float(b / w) if w > 0 else 0.0 for b, w in zip(bot_mass, weights)
        ]

    def score(self, x: dict[str, float]) -> float:
        return self.score_batch([x])[0]

    def score_batch(self, rows: list[dict[str, float]]) -> list[float]:
        import numpy as np

        if self._model is None:
            raise RuntimeError("gmm: score before fit()/load()")
        if not rows:
            return []
        behavior = [
            {
                f: v
                for f, v in row.items()
                if f != self.LABEL_KEY and not f.startswith(self.EXCLUDED_PREFIXES)
            }
            for row in rows
        ]
        resp = self._model.predict_proba(self._scaler.transform(behavior))
        fractions = np.array(self._bot_fraction)
        return [float(v) for v in resp @ fractions]

    # ------------------------------------------------------------------ #

    def save(self, path: Path) -> None:
        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "scaler": self._scaler.to_dict(),
                "bot_fraction": self._bot_fraction,
            },
            path,
        )

    def load(self, path: Path) -> None:
        import joblib

        blob = joblib.load(path)
        self._model = blob["model"]
        self._scaler = FeatureScaler.from_dict(blob["scaler"])
        self._bot_fraction = blob["bot_fraction"]
        self.n_components = self._model.n_components
