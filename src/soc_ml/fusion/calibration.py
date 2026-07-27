"""Percentile calibration — the only lens raw scores are ever seen through.

A raw anomaly score is model- and server-specific noise: 0.61 from an Isolation
Forest on server A is not comparable to 0.61 on server B, or to anything from
LOF. Calibration maps every raw score onto "what fraction of this server's
recent scores does it exceed" — a 0-1 percentile that is comparable across
models, servers, and time, and is what every gate consumes (FR-22).

Implementation: a 1001-point quantile grid fitted on training scores.
Interpolation between grid points keeps the artifact tiny (8 KB) regardless of
corpus size, and lookup is O(log n).
"""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["PercentileCalibrator"]

_GRID_POINTS = 1001  # quantiles at 0.001 resolution — matches the spec's
# finest gate (p99.9) with one grid step to spare


class PercentileCalibrator:
    """Maps raw scores to [0, 1] percentiles of a fitted reference distribution."""

    def __init__(self) -> None:
        self._grid: list[float] | None = None

    def fit(self, scores: list[float]) -> "PercentileCalibrator":
        import numpy as np

        if not scores:
            raise ValueError("calibrator: cannot fit on zero scores")
        qs = np.linspace(0.0, 1.0, _GRID_POINTS)
        self._grid = [float(v) for v in np.quantile(np.array(scores, dtype=float), qs)]
        return self

    def percentile(self, raw: float) -> float:
        """Fraction of the reference distribution this score exceeds."""
        import numpy as np

        if self._grid is None:
            raise RuntimeError("calibrator: percentile() before fit()/load()")
        # searchsorted over the grid: index/1000 IS the percentile, because the
        # grid was built at uniform quantile spacing.
        idx = int(np.searchsorted(np.array(self._grid), raw, side="right"))
        return min(idx / (_GRID_POINTS - 1), 1.0)

    # -- persistence -------------------------------------------------------- #

    def to_dict(self) -> dict:
        if self._grid is None:
            raise RuntimeError("calibrator: to_dict() before fit()")
        return {"grid": self._grid}

    @classmethod
    def from_dict(cls, doc: dict) -> "PercentileCalibrator":
        cal = cls()
        cal._grid = [float(v) for v in doc["grid"]]
        return cal

    @staticmethod
    def save_many(calibrators: dict[str, "PercentileCalibrator"], path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({k: c.to_dict() for k, c in calibrators.items()}),
            encoding="utf-8",
        )

    @staticmethod
    def load_many(path: Path) -> dict[str, "PercentileCalibrator"]:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return {k: PercentileCalibrator.from_dict(v) for k, v in doc.items()}
