"""End-to-end backtest test — the whole Phase-1 slice on real fixture data.

This is the release gate for the vertical slice: real parsed logs stream through
the real profile/feature/model/calibration/gate/explain path, the canary must be
detected, and every artifact the audit trail depends on must exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_ml.evaluation.backtest import run_backtest

FIXTURE = Path(__file__).resolve().parents[2] / "log_samples" / "nginx_sample.json"


@pytest.fixture(scope="module")
def report(tmp_path_factory) -> dict:
    if not FIXTURE.exists():
        pytest.skip("nginx fixture not present")
    out = tmp_path_factory.mktemp("backtest")
    return run_backtest(FIXTURE, out_dir=out, inject_canary=True)


def test_pipeline_completes_and_detects_the_canary(report: dict) -> None:
    assert report["usecase"] == "web_recon"
    assert report["rule_id"] == "UC-02"
    assert report["train"]["windows"] >= 20
    assert report["score"]["windows"] > 0
    assert report["canary"]["injected"] is True
    assert report["canary"]["detected"] is True, (
        "a textbook enumeration burst must be caught — if this fails, the "
        "detection path is broken end to end"
    )


def test_false_positive_budget_holds_on_real_traffic(report: dict) -> None:
    """Real (non-canary) delivered alert volume must respect the spec budget.

    The fixture is benign university traffic; a slice that alerts above budget
    on it would be a false-positive machine in production. This is the *deduped*
    delivered rate — the number a SOC analyst actually sees.
    """
    assert report["score"]["delivered_per_day_per_server"] <= 3


def test_artifacts_are_complete_and_versioned(report: dict) -> None:
    bundle_dir = Path(report["artifacts"]["bundle"])
    for artifact in (
        "profile.json",
        "isolation_forest.joblib",
        "lof_novelty.joblib",
        "calibration.json",
        "feature_stats.json",
        "metadata.json",
    ):
        assert (bundle_dir / artifact).exists(), f"missing {artifact} (FR-53)"

    meta = json.loads((bundle_dir / "metadata.json").read_text())
    assert meta["usecase"] == "web_recon"
    assert meta["feature_code_sha256"], "reproducibility anchor (NFR-10)"
    assert meta["gate"]["percentile"] == 0.997
    assert meta["hygiene"]["clip_quantile"] == 0.999


def test_every_score_is_recorded_not_only_alerts(report: dict) -> None:
    """Spec: gates control delivery, never detection — all scores on record."""
    scores_path = Path(report["artifacts"]["scores"])
    lines = scores_path.read_text().splitlines()
    assert len(lines) == report["score"]["windows"] + report["canary"]["windows_seen"] or (
        len(lines) >= report["score"]["windows"]
    )
    row = json.loads(lines[0])
    assert {"fused_pct", "entity", "fired", "canary"} <= set(row)


def test_alert_documents_carry_the_naming_triple_and_explanation(report: dict) -> None:
    alerts_path = Path(report["artifacts"]["alerts"])
    lines = alerts_path.read_text().splitlines()
    assert lines, "canary detection implies at least one alert document"
    doc = json.loads(lines[0])

    assert doc["usecase"] == "web_recon"
    assert doc["rule"] == {
        "id": "UC-02",
        "name": "Web Reconnaissance & Directory Enumeration",
    }
    assert doc["alert"]["severity"] in ("low", "medium", "high", "critical")
    exp = doc["explanation"]
    assert exp["top_features"], "attributions are mandatory (FR-40)"
    assert {"feature", "value", "population_p50", "population_p99"} <= set(
        exp["top_features"][0]
    ), "population context is mandatory (FR-41)"
    assert exp["narrative"]
    assert 1 <= len(exp["evidence_events"]) <= 10, "verbatim evidence (FR-42)"


def test_canary_never_contaminates_training(report: dict) -> None:
    """FR-58: synthetic data is evaluation-only. The canary is injected after
    the train/score cutoff by construction — verify no canary event was scored
    before the cutoff (which would imply it could have reached training)."""
    scores_path = Path(report["artifacts"]["scores"])
    cutoff = report["cutoff"]
    canary_windows = [
        json.loads(line)
        for line in scores_path.read_text().splitlines()
        if json.loads(line)["canary"]
    ]
    assert canary_windows, "the canary must have been scored"
    assert all(w["window_end"] >= cutoff for w in canary_windows), (
        "a canary window scored before the cutoff would violate FR-58"
    )
