"""Tests for the model registry — versioning, promotion, rollback, pruning."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.fusion.calibration import PercentileCalibrator
from soc_ml.models.isolation_forest import IsolationForestModel
from soc_ml.registry.store import ModelBundle, ModelRegistry

FACTORIES = {"isolation_forest": IsolationForestModel}


def make_bundle(version: str) -> ModelBundle:
    profile = EnvironmentProfile()
    for i in range(60):
        from datetime import datetime, timezone

        from soc_ml.core.contracts import Event, Observer

        profile.observe(
            Event(
                timestamp=datetime(2026, 7, 9, tzinfo=timezone.utc),
                observer=Observer(server="web01"),
                source_ip="10.0.0.1",
                url_path=f"/p{i % 5}",
                user_agent="UA",
                status_code=200,
            )
        )
    rows = [{"a": float(i), "b": float(i % 3)} for i in range(50)]
    model = IsolationForestModel()
    model.fit(rows)
    cal = PercentileCalibrator().fit([model.score(r) for r in rows])
    return ModelBundle(
        usecase="web_recon",
        version=version,
        profile=profile,
        models={"isolation_forest": model},
        calibrators={"isolation_forest": cal},
        metadata={"usecase": "web_recon", "version": version, "rule_id": "UC-02"},
        reference_sample={"a": [float(i) for i in range(50)]},
    )


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    b = make_bundle("v1")
    reg.save_bundle(b)
    reg.promote("web_recon", "v1")

    loaded = reg.load_current("web_recon", FACTORIES)
    assert loaded is not None
    assert loaded.version == "v1"
    assert loaded.reference_sample["a"][:3] == [0.0, 1.0, 2.0]
    # scoring must survive the roundtrip identically
    row = {"a": 5.0, "b": 2.0}
    assert loaded.models["isolation_forest"].score(row) == b.models[
        "isolation_forest"
    ].score(row)


def test_no_current_before_promotion(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    reg.save_bundle(make_bundle("v1"))
    assert reg.current_version("web_recon") is None
    assert reg.load_current("web_recon", FACTORIES) is None


def test_candidate_then_promote(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    reg.save_bundle(make_bundle("v1"))
    reg.set_candidate("web_recon", "v1")
    assert reg.candidate_version("web_recon") == "v1"

    reg.promote("web_recon")  # promotes the candidate
    assert reg.current_version("web_recon") == "v1"
    assert reg.candidate_version("web_recon") is None, "candidate cleared on promote"


def test_promote_is_atomic_swap_not_mutation(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    for v in ("v1", "v2"):
        reg.save_bundle(make_bundle(v))
    reg.promote("web_recon", "v1")
    assert reg.current_version("web_recon") == "v1"
    reg.promote("web_recon", "v2")
    assert reg.current_version("web_recon") == "v2"
    # v1 bundle still on disk and loadable — promotion never edits bundles
    assert reg.load("web_recon", "v1", FACTORIES).version == "v1"


def test_rollback(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    for v in ("v1", "v2", "v3"):
        reg.save_bundle(make_bundle(v))
        reg.promote("web_recon", v)
    assert reg.current_version("web_recon") == "v3"
    target = reg.rollback("web_recon")
    assert target == "v2"
    assert reg.current_version("web_recon") == "v2"


def test_prune_keeps_hot_versions_and_never_current(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    versions = [f"v{i:02d}" for i in range(8)]
    for v in versions:
        reg.save_bundle(make_bundle(v))
    reg.promote("web_recon", "v00")  # pin an OLD version as current
    reg.promote("web_recon", "v07")  # promote newest -> triggers prune
    remaining = reg.versions("web_recon")
    # keeps 3 hot + protects current; the pinned-then-superseded v00 may prune,
    # but the serving version must always survive.
    assert "v07" in remaining
    assert len(remaining) <= 4
    assert reg.load_current("web_recon", FACTORIES) is not None


def test_stale_pointer_to_pruned_version_is_ignored(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    reg.save_bundle(make_bundle("v1"))
    reg._write_pointer("web_recon", "current", "v-does-not-exist")
    assert reg.current_version("web_recon") is None


def test_promote_unknown_version_errors(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    with pytest.raises(ValueError):
        reg.promote("web_recon", "nope")
