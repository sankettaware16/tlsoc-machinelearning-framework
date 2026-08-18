"""Operator dashboard: state reads, API routes, and the promotion gate.

The dashboard is the human gate FR-55 asks for, so the tests that matter most
are the ones about *not* promoting: a read-only server must refuse, and a
token-protected server must refuse an unauthenticated caller.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_ml.web.server import build_server, serve_in_thread
from soc_ml.web.state import DashboardState

NOW = datetime.now(timezone.utc)


# ------------------------------- fixtures ------------------------------- #


def _deployment(root: Path, *, health_age_s: float = 3.0, candidate: bool = True) -> Path:
    """A data root shaped exactly like a live runtime's."""
    state = root / "state"
    alerts = root / "alerts"
    state.mkdir(parents=True, exist_ok=True)
    alerts.mkdir(parents=True, exist_ok=True)

    stamp = (NOW - timedelta(seconds=health_age_s)).isoformat()
    (state / "web_recon_health.json").write_text(json.dumps({
        "timestamp": stamp, "usecase": "web_recon", "mode": "live",
        "bundle_version": "v20260806T124821", "uptime_s": 90000.0, "eps": 12.3,
        "events": 1_100_000, "windows": 80_000, "open_windows": 40,
        "ingest_failed": 0, "entity_annotations": 20_000,
        "alerts_delivered": 3, "alerts_folded": 20, "alerts_digested": 200,
        "alerts_suppressed": 7,
    }))
    (state / "web_recon_drift.json").write_text(json.dumps({
        "max_psi": 1.27, "band": "significant", "should_retrain": True,
        "drifted_features": ["ua.rarity", "web.status_2xx_ratio"],
    }))
    (state / "web_recon_scores.ndjson").write_text("".join(
        json.dumps({"window_end": stamp, "entity": f"srv|10.0.0.{i}|h",
                    "fused_pct": 0.998, "fired": True, "event_count": 40,
                    "disposition": "delivered" if i % 2 else "digested"}) + "\n"
        for i in range(30)))
    (alerts / "web_recon.ndjson").write_text(json.dumps({
        "@timestamp": stamp, "usecase": "web_recon",
        "entity": {"server": "srv", "ip": "10.0.0.9", "ua_hash": "h"},
        "alert": {"id": "1", "severity": "high", "severity_score": 80},
    }) + "\n")

    models = root / "models" / "web_recon"
    for version in ("v20260101T000000", "v20260806T124821", "v20260818T090000"):
        d = models / version
        d.mkdir(parents=True, exist_ok=True)
        # Exactly the keys ModelBundle.save writes — an invented shape here
        # would let a field-name mistake in the reader pass its own test.
        (d / "metadata.json").write_text(json.dumps({
            "usecase": "web_recon", "rule_id": "UC-02", "tier": 1,
            "version": version,
            "created_at": f"{version[1:5]}-01-01T00:00:00+00:00",
            "source": "/var/log/soc_output/nginx.json",
            "train_events": 641721, "train_windows": 12643,
            "hygiene": {"windows_dropped": 33},
            "models": {"isolation_forest": "IsolationForestModel",
                       "lof_novelty": "LOFNoveltyModel"},
            "models_skipped": [],
            "gate": {"percentile": 0.997, "min_events": 5, "min_distinct_paths": 3},
            "feature_code_sha256": "3e069beacfefcadf",
        }))
    (models / "current").write_text("v20260806T124821")
    if candidate:
        (models / "candidate").write_text("v20260818T090000")
    return root


# --------------------------------- state -------------------------------- #


def test_overview_reports_live_and_derives_fires(tmp_path: Path) -> None:
    st = DashboardState(_deployment(tmp_path))
    ov = st.overview()
    assert ov["runtime"]["live"] is True
    assert ov["runtime"]["mode"] == "live"

    uc = next(u for u in ov["usecases"] if u["slug"] == "web_recon")
    # Every fire lands in exactly one bucket, so the four must sum to fires.
    assert uc["fired"] == 3 + 20 + 200 + 7
    assert uc["serving"] == "v20260806T124821"
    assert uc["candidate"] == "v20260818T090000"
    assert uc["drift"]["should_retrain"] is True


def test_a_stopped_runtime_is_not_reported_as_live(tmp_path: Path) -> None:
    """Health older than the write interval means the detector is gone."""
    st = DashboardState(_deployment(tmp_path, health_age_s=3600))
    assert st.overview()["runtime"]["live"] is False


def test_models_marks_approval_status(tmp_path: Path) -> None:
    st = DashboardState(_deployment(tmp_path))
    uc = st.models()["usecases"][0]
    by_status = {v["version"]: v["status"] for v in uc["versions"]}
    assert by_status["v20260806T124821"] == "approved"
    assert by_status["v20260818T090000"] == "pending"
    assert by_status["v20260101T000000"] == "retained"
    assert uc["can_rollback"] is True


def test_version_provenance_is_read_from_real_metadata_keys(tmp_path: Path) -> None:
    """Regression: the reader looked for `trained_at`/`feature_sha256`.

    The bundle writes `created_at` and `feature_code_sha256`, so every version
    rendered "trained: None" against a real registry while the tests passed.
    """
    st = DashboardState(_deployment(tmp_path))
    v = st.models()["usecases"][0]["versions"][0]
    assert v["trained_at"], "provenance must survive the read"
    assert v["feature_code_sha256"] == "3e069beacfefcadf"
    assert v["train_events"] == 641721
    assert v["windows_dropped"] == 33
    assert v["models"] == ["isolation_forest", "lof_novelty"]
    assert v["gate"]["min_distinct_paths"] == 3


def test_promote_moves_the_serving_pointer(tmp_path: Path) -> None:
    st = DashboardState(_deployment(tmp_path))
    assert st.promote("web_recon", "v20260818T090000")["promoted"] == "v20260818T090000"
    uc = st.models()["usecases"][0]
    assert uc["serving"] == "v20260818T090000"
    assert uc["candidate"] is None, "approving clears the pending candidate"


def test_records_are_newest_first_and_bounded(tmp_path: Path) -> None:
    st = DashboardState(_deployment(tmp_path))
    got = st.records("scores", "web_recon", limit=5)
    assert len(got["rows"]) == 5
    assert got["rows"][0]["entity"].endswith("10.0.0.29|h"), "newest first"


def test_catalog_lists_planned_use_cases_not_only_built_ones(tmp_path: Path) -> None:
    st = DashboardState(_deployment(tmp_path))
    rows = st.catalog()
    slugs = {r["slug"]: r for r in rows}
    assert len(rows) >= 15, "the whole UC-01..UC-15 catalog, not just what is built"
    assert slugs["web_recon"]["implemented"] is True
    assert slugs["web_recon"]["deployed"] is True
    assert slugs["credential_stuffing"]["implemented"] is False


# ---------------------------------- http -------------------------------- #


@pytest.fixture()
def server(tmp_path: Path):
    made = {}

    def start(**kw):
        st = DashboardState(_deployment(tmp_path))
        httpd = build_server(st, host="127.0.0.1", port=0, **kw)
        serve_in_thread(httpd)
        made["httpd"] = httpd
        return f"http://127.0.0.1:{httpd.server_address[1]}", st

    yield start
    if "httpd" in made:
        made["httpd"].shutdown()
        made["httpd"].server_close()


def _get(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, json.loads(r.read())


def _post(url, payload, token=None):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_dashboard_page_and_api_are_served(server) -> None:
    base, _ = server()
    with urllib.request.urlopen(base + "/", timeout=5) as r:
        body = r.read().decode()
    assert r.status == 200 and "soc-ml operator console" in body

    status, ov = _get(base + "/api/overview")
    assert status == 200 and ov["runtime"]["live"] is True
    assert _get(base + "/api/models")[1]["usecases"]
    assert _get(base + "/api/catalog")[1]["usecases"]
    assert "samples" in _get(base + "/api/timeseries")[1]


def test_unknown_route_is_404_not_a_traceback(server) -> None:
    base, _ = server()
    try:
        _get(base + "/api/nope")
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404
        assert "Traceback" not in e.read().decode()


def test_read_only_server_refuses_to_promote(server) -> None:
    base, st = server(read_only=True)
    code, body = _post(base + "/api/models/promote",
                       {"slug": "web_recon", "version": "v20260818T090000"})
    assert code == 403 and "read-only" in body["error"]
    assert st.registry.current_version("web_recon") == "v20260806T124821", "unchanged"


def test_promotion_requires_the_token_when_one_is_set(server) -> None:
    base, st = server(token="s3cret")

    code, body = _post(base + "/api/models/promote", {"slug": "web_recon"})
    assert code == 401
    assert st.registry.current_version("web_recon") == "v20260806T124821"

    code, body = _post(base + "/api/models/promote", {"slug": "web_recon"}, token="wrong")
    assert code == 401
    assert st.registry.current_version("web_recon") == "v20260806T124821"

    code, body = _post(base + "/api/models/promote", {"slug": "web_recon"}, token="s3cret")
    assert code == 200 and body["promoted"] == "v20260818T090000"
    assert st.registry.current_version("web_recon") == "v20260818T090000"


def test_promote_without_a_candidate_is_a_clean_conflict(server) -> None:
    base, st = server()
    st.registry.promote("web_recon", "v20260818T090000")  # consumes the candidate
    code, body = _post(base + "/api/models/promote", {"slug": "web_recon"})
    assert code == 409 and "candidate" in body["error"]
