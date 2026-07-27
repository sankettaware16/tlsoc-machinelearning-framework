"""Tests for percentile calibration and the severity formula."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_ml.core.contracts import Severity
from soc_ml.fusion import PercentileCalibrator, severity_score


def test_calibrator_maps_scores_to_percentiles() -> None:
    cal = PercentileCalibrator().fit([float(i) for i in range(1000)])

    assert cal.percentile(-5.0) == 0.0, "below the reference floor"
    assert cal.percentile(2000.0) == 1.0, "above the reference ceiling"
    assert abs(cal.percentile(499.5) - 0.5) < 0.01
    assert abs(cal.percentile(990.0) - 0.99) < 0.005


def test_calibrator_is_monotonic() -> None:
    cal = PercentileCalibrator().fit([float(i * i) for i in range(500)])
    values = [cal.percentile(x) for x in [0, 10, 100, 1000, 10000, 100000]]
    assert values == sorted(values)


def test_calibrator_survives_constant_scores() -> None:
    """A degenerate reference (all equal) must not divide by zero."""
    cal = PercentileCalibrator().fit([3.14] * 100)
    assert cal.percentile(3.13) == 0.0
    assert cal.percentile(3.15) == 1.0


def test_calibrator_roundtrip(tmp_path: Path) -> None:
    cals = {
        "isolation_forest": PercentileCalibrator().fit([1.0, 2.0, 3.0, 4.0]),
        "lof_novelty": PercentileCalibrator().fit([10.0, 20.0, 30.0]),
    }
    path = tmp_path / "calibration.json"
    PercentileCalibrator.save_many(cals, path)
    loaded = PercentileCalibrator.load_many(path)

    assert set(loaded) == set(cals)
    for score in (0.5, 2.5, 3.9, 25.0):
        assert loaded["isolation_forest"].percentile(score) == pytest.approx(
            cals["isolation_forest"].percentile(score)
        )


def test_calibrator_refuses_empty_fit() -> None:
    with pytest.raises(ValueError):
        PercentileCalibrator().fit([])


# ----------------------------------------------------------------------- #


def test_severity_formula_and_bands() -> None:
    assert severity_score(1.0) == (100, Severity.CRITICAL)
    assert severity_score(0.75) == (75, Severity.HIGH)
    assert severity_score(0.50) == (50, Severity.MEDIUM)
    assert severity_score(0.20) == (20, Severity.LOW)


def test_severity_bands_add_and_clamp() -> None:
    score, band = severity_score(0.70, corroboration_band=10, context_band=10)
    assert (score, band) == (90, Severity.CRITICAL)
    score, _ = severity_score(1.0, breadth_band=15, corroboration_band=10)
    assert score == 100, "must clamp at 100"


def test_severity_asset_weight_scales() -> None:
    score, band = severity_score(1.0, asset_weight=0.6)
    assert (score, band) == (60, Severity.MEDIUM)


def test_severity_rejects_uncalibrated_input() -> None:
    with pytest.raises(ValueError):
        severity_score(3.7)  # raw scores must never reach severity (FR-22)
