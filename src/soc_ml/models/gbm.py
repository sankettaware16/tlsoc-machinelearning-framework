"""Gradient-boosted P(bot | behavior) classifier — UC-04's core model.

The clearest case of free labels in the spec (D-019): ``bot.declared_bot``
(derived from the UA string) is the *target*, and the model predicts it from
**behavioral features only**. The UA must never leak into the inputs — a model
that predicts "does the UA say bot" from the UA has learned nothing — so this
wrapper strips the label key and every ``ua.*`` feature itself, structurally,
rather than trusting every caller to remember.

``score`` returns the isotonic-calibrated P(bot | behavior) in [0, 1]:
* on a **browser-declared** entity, a high value means "declares a browser,
  behaves like a bot" — the UA-spoofing signal (gated on percentile, FR-22);
* ``1 - P(bot)`` is the human-likeness signal exported for other use cases.

Calibration ladder, degrading loudly rather than crashing (NFR-08): isotonic
(cv) when both classes have enough rows; the raw classifier's probabilities
when the minority class is too thin for cross-validated isotonic; a constant
class-prevalence probability when training saw a single class only.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from soc_ml.core.plugins import Model

__all__ = ["GBMBotClassifier"]


class GBMBotClassifier(Model):
    name = "gbm_bot"
    description = "Gradient-boosted P(bot|behavior), isotonic-calibrated (UC-04)"
    incremental = False

    LABEL_KEY = "bot.declared_bot"
    #: UA-derived features are excluded from inputs — the label comes from the
    #: UA, so admitting them is target leakage, not signal.
    EXCLUDED_PREFIXES = ("ua.",)
    RANDOM_STATE = 7  # determinism: same corpus -> same model (NFR-10)
    #: Minimum minority-class rows for cross-validated isotonic calibration
    #: (below this, isotonic overfits its handful of points).
    MIN_CALIBRATION_ROWS = 15
    _CV_FOLDS = 3

    def __init__(self) -> None:
        self._model = None  # fitted classifier, or None when constant
        self._constant: float | None = None  # single-class fallback
        self._features: list[str] = []
        self.calibrated = False

    # ------------------------------------------------------------------ #

    def _input_features(self, row: dict[str, float]) -> list[str]:
        return sorted(
            f
            for f in row
            if f != self.LABEL_KEY and not f.startswith(self.EXCLUDED_PREFIXES)
        )

    def fit(self, X: Iterable[dict[str, float]]) -> None:
        import numpy as np
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.ensemble import HistGradientBoostingClassifier

        rows = list(X)
        if not rows:
            raise ValueError("gbm_bot: empty training corpus")
        if self.LABEL_KEY not in rows[0]:
            raise ValueError(
                f"gbm_bot: training rows carry no {self.LABEL_KEY!r} label — "
                "the use case's vector() must include it"
            )
        self._features = self._input_features(rows[0])
        matrix = np.array(
            [[row.get(f, 0.0) for f in self._features] for row in rows], dtype=float
        )
        y = np.array([row.get(self.LABEL_KEY, 0.0) >= 0.5 for row in rows])

        minority = int(min(y.sum(), (~y).sum()))
        if minority == 0:
            # One class only (an environment with no declared bots at all, or
            # nothing but them). A classifier fit here would be fiction; a
            # constant prevalence probability is honest.
            self._constant = float(y.mean())
            self._model = None
            self.calibrated = False
            return

        base = HistGradientBoostingClassifier(random_state=self.RANDOM_STATE)
        if minority >= self.MIN_CALIBRATION_ROWS:
            self._model = CalibratedClassifierCV(
                base, method="isotonic", cv=self._CV_FOLDS
            ).fit(matrix, y)
            self.calibrated = True
        else:
            self._model = base.fit(matrix, y)
            self.calibrated = False
        self._constant = None

    def score(self, x: dict[str, float]) -> float:
        return self.score_batch([x])[0]

    def score_batch(self, rows: list[dict[str, float]]) -> list[float]:
        import numpy as np

        if self._model is None and self._constant is None:
            raise RuntimeError("gbm_bot: score before fit()/load()")
        if not rows:
            return []
        if self._model is None:
            return [self._constant] * len(rows)
        matrix = np.array(
            [[x.get(f, 0.0) for f in self._features] for x in rows], dtype=float
        )
        return [float(p) for p in self._model.predict_proba(matrix)[:, 1]]

    # ------------------------------------------------------------------ #

    def save(self, path: Path) -> None:
        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "constant": self._constant,
                "features": self._features,
                "calibrated": self.calibrated,
            },
            path,
        )

    def load(self, path: Path) -> None:
        import joblib

        blob = joblib.load(path)
        self._model = blob["model"]
        self._constant = blob["constant"]
        self._features = blob["features"]
        self.calibrated = blob["calibrated"]

    @property
    def feature_names(self) -> list[str]:
        return list(self._features)
