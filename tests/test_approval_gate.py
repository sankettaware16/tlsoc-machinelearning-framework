"""The approval gate end to end: check_candidate records a verdict, the registry
demands it (FR-55, D-035). Runs the real script against real bundles."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from soc_ml.core.plugins import usecase_model_factories
from soc_ml.registry.store import ModelRegistry
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases import WebRecon
from tests.test_detection_lifecycle import _write_events
from tests.test_progressive import _benign, _sustained_scanner

ROOT = Path(__file__).resolve().parents[1]


def test_check_candidate_records_a_verdict_the_registry_accepts(tmp_path: Path) -> None:
    reg = ModelRegistry(tmp_path)
    for version in ("v20260101T000000", "v20260102T000000"):
        bundle = train_bundle(WebRecon, usecase_model_factories(WebRecon),
                              lambda: iter(_benign()), source_desc="benign")
        bundle.version = version
        reg.save_bundle(bundle)
    reg.promote("web_recon", "v20260101T000000")
    reg.set_candidate("web_recon", "v20260102T000000")
    assert reg.metadata("web_recon", "v20260101T000000")["code_commit"] is not None

    replay = tmp_path / "replay.json"
    _write_events(replay, sorted(_benign() + _sustained_scanner("203.0.113.70", 40),
                                 key=lambda e: e.timestamp))
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_candidate.py"), "--uc", "web_recon",
         "--input", str(replay), "--limit", "0", "--out", str(tmp_path)],
        capture_output=True, text=True, timeout=600)
    assert run.returncode == 0, run.stdout + run.stderr

    report = reg.approval("web_recon", "v20260102T000000")
    assert report["verdict"] in ("PASS", "WARN")
    assert report["serving"] == "v20260101T000000"
    assert report["input"]["events"] > 1000 and len(report["input"]["sha256_events"]) == 64
    assert report["canary"]["candidate"]["fired"] > 0
    assert "recorded:" in run.stdout

    reg.promote("web_recon")
    promo = reg.metadata("web_recon", "v20260102T000000")["promotion"]
    assert promo["gate"] == "approval_check" and promo["displaced"] == "v20260101T000000"
    json.dumps(report)  # the report is plain JSON
