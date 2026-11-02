"""Operator dashboard: state reads, API routes, and the promotion gate.

The dashboard is the human gate FR-55 asks for, so the tests that matter most
are the ones about *not* promoting: a read-only server must refuse, and a
token-protected server must refuse an unauthenticated caller.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soc_ml.registry.store import PromotionRefused
from soc_ml.web.server import build_server, serve_in_thread
from soc_ml.web.state import DashboardState

# ------------------------------- fixtures ------------------------------- #


def _deployment(root: Path, *, health_age_s: float = 3.0, candidate: bool = True,
                input_age_s: float | None = 3.0) -> Path:
    """A data root shaped exactly like a live runtime's."""
    state = root / "state"
    alerts = root / "alerts"
    state.mkdir(parents=True, exist_ok=True)
    alerts.mkdir(parents=True, exist_ok=True)

    # Health age must be relative to *this call*, not module import: on a
    # loaded machine the suite can take longer than the 60s liveness window.
    stamp = (datetime.now(UTC) - timedelta(seconds=health_age_s)).isoformat()
    last_event = (None if input_age_s is None else
                  (datetime.now(UTC) - timedelta(seconds=input_age_s)).isoformat())
    (state / "web_recon_health.json").write_text(json.dumps({
        "timestamp": stamp, "last_event_at": last_event,
        "usecase": "web_recon", "mode": "live",
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
        # What scripts/check_candidate.py records; without it promotion is refused.
        (models / "v20260818T090000" / "approval_check.json").write_text(json.dumps({
            "verdict": "PASS", "serving": "v20260806T124821",
            "generated_at": "2026-08-18T10:00:00+00:00", "notes": []}))
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


def test_a_running_runtime_with_no_input_is_live_but_idle(tmp_path: Path) -> None:
    """Fresh health with an old last event: the feed stopped, not the detector."""
    rt = DashboardState(_deployment(tmp_path, input_age_s=1800)).overview()["runtime"]
    assert rt["live"] is True
    assert rt["input_idle"] is True
    assert rt["input_age_s"] >= 1800


def test_input_idle_needs_evidence(tmp_path: Path) -> None:
    """Flowing input is not idle; health from before the field existed is unknown."""
    flowing = DashboardState(_deployment(tmp_path / "a")).overview()["runtime"]
    assert flowing["input_idle"] is False
    legacy = DashboardState(_deployment(tmp_path / "b", input_age_s=None)).overview()["runtime"]
    assert legacy["input_idle"] is False and legacy["input_age_s"] is None


def test_models_marks_approval_status(tmp_path: Path) -> None:
    st = DashboardState(_deployment(tmp_path))
    uc = st.models()["usecases"][0]
    by_status = {v["version"]: v["status"] for v in uc["versions"]}
    assert by_status["v20260806T124821"] == "approved"
    assert by_status["v20260818T090000"] == "pending"
    assert by_status["v20260101T000000"] == "retained"
    # No version here carries a record of having served (bundles from before
    # promotions were recorded), so there is nowhere safe to roll back to.
    assert uc["can_rollback"] is False and uc["rollback_target"] is None


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


def test_versions_are_flagged_when_their_feature_code_is_not_current(
        tmp_path: Path) -> None:
    """Nothing verifies the feature-code hash at load, so the console must.

    A bundle fitted against different feature code scores current features
    through a model built for a different feature set — wrong numbers rather
    than an error, which is the worst failure mode available.
    """
    root = _deployment(tmp_path)
    stale = root / "models" / "web_recon" / "v20260101T000000" / "metadata.json"
    meta = json.loads(stale.read_text())
    meta["feature_code_sha256"] = "0000000000000000deadbeef"
    stale.write_text(json.dumps(meta))

    st = DashboardState(root)
    by_version = {v["version"]: v for v in st.models()["usecases"][0]["versions"]}
    assert by_version["v20260101T000000"]["feature_code_current"] is False
    # The fixture's other bundles carry a hash that is not this build's either,
    # so they must be flagged too rather than silently passing.
    assert by_version["v20260818T090000"]["feature_code_current"] is False


def test_unknown_feature_code_is_not_reported_as_matching(tmp_path: Path) -> None:
    """"We cannot tell" must stay distinct from "it matches" (NFR-09)."""
    root = _deployment(tmp_path)
    path = root / "models" / "web_recon" / "v20260101T000000" / "metadata.json"
    meta = json.loads(path.read_text())
    del meta["feature_code_sha256"]
    path.write_text(json.dumps(meta))

    st = DashboardState(root)
    by_version = {v["version"]: v for v in st.models()["usecases"][0]["versions"]}
    assert by_version["v20260101T000000"]["feature_code_current"] is None


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



def test_the_console_shows_the_verdict_and_refuses_without_one(tmp_path: Path) -> None:
    root = _deployment(tmp_path)
    (root / "models" / "web_recon" / "v20260818T090000" / "approval_check.json").unlink()
    st = DashboardState(root)
    by_version = {v["version"]: v for v in st.models()["usecases"][0]["versions"]}
    assert by_version["v20260818T090000"]["approval"] is None
    assert by_version["v20260818T090000"]["promotable"] is False
    with pytest.raises(PromotionRefused):
        st.promote("web_recon", "v20260818T090000")
    assert st.registry.current_version("web_recon") == "v20260806T124821"


def test_a_passing_verdict_is_shown_and_promotable(tmp_path: Path) -> None:
    st = DashboardState(_deployment(tmp_path))
    v = {v["version"]: v for v in st.models()["usecases"][0]["versions"]}["v20260818T090000"]
    assert v["approval"]["verdict"] == "PASS" and v["promotable"] is True


# ------------------------------ analyst view ------------------------------ #
# The console's job for an analyst: what happened, is it real, who, what else,
# what to do — and a recorded verdict. Fixtures are written by the real
# alert_document(), so a renamed field in the sink fails here, not in prod.

_KEY = "www.example.edu|/.git/"


def _exposure_alert(alert_id: str, ip: str, minutes: int = 0):
    from soc_ml.alerting.file_sink import alert_document
    from soc_ml.core.contracts import Alert, EntityKey, Severity
    from soc_ml.features.exposure import KINDS

    kind = KINDS["vcs"]
    ts = datetime(2026, 10, 22, 15, 20, tzinfo=UTC) + timedelta(minutes=minutes)
    exposure = {
        "key": _KEY, "kind": "vcs", "root": "/.git/", "domain": "www.example.edu",
        "first_seen": ts.isoformat(), "last_seen": ts.isoformat(), "files_count": 3,
        "bytes_total": 912, "files": [{"path": "/.git/config", "status": 200, "bytes": 311}],
        "title": kind.title, "impact": kind.impact, "actions": list(kind.actions),
        "alertable": True,
    }
    return alert_document(Alert(
        id=alert_id, timestamp=ts, usecase="web_recon",
        entity=EntityKey(server="logserver", ip=ip, ua_hash="h"),
        severity=Severity.CRITICAL, severity_score=95, confidence=0.99,
        narrative=f"{ip} downloaded 3 files of a repository.",
        evidence=[f"... access: www.example.edu {ip} GET /.git/config 200"],
        links={"rule_id": "UC-02", "rule_name": "web recon: exposure",
               "category": "exposure", "exposures": [exposure],
               "context": {"window_start": (ts - timedelta(minutes=5)).isoformat(),
                           "window_end": ts.isoformat(), "user_agent": "git/2.40",
                           "events": 40, "distinct_paths": 38, "n404": 2,
                           "status_counts": {"2xx": 38, "3xx": 0, "4xx": 2, "5xx": 0},
                           "domains": [["www.example.edu", 40]],
                           "geo": {"country_iso_code": "ZZ", "country_name": "Testland"},
                           "network": {"number": 64500, "organization": "Example Hosting"}}},
    ))


def _analyst(root: Path, **kw) -> DashboardState:
    _deployment(root)
    alerts = root / "alerts" / "web_recon.ndjson"
    with alerts.open("a") as fh:   # the fixture's legacy alert "1" stays first
        fh.write(json.dumps(_exposure_alert("exp-1", "203.0.113.38")) + "\n")
        fh.write(json.dumps(_exposure_alert("exp-2", "203.0.113.77", minutes=30)) + "\n")
    with (root / "state" / "web_recon_exposures.ndjson").open("w") as fh:
        for ip, aid in (("203.0.113.38", "exp-1"), ("203.0.113.77", "exp-2"),
                        ("198.51.100.4", "exp-1")):
            fh.write(json.dumps({"@timestamp": "2026-10-22T15:20:00+00:00", "key": _KEY,
                                 "client": ip, "network": {"organization": "Net"},
                                 "files_count": 3, "bytes_total": 912,
                                 "alert_id": aid}) + "\n")
        fh.write(json.dumps({"key": "other.example.edu|/.env", "client": "203.0.113.9",
                             "alert_id": "zzz"}) + "\n")
    return DashboardState(root, **kw)


def test_the_queue_joins_verification_and_triage(tmp_path: Path) -> None:
    st = _analyst(tmp_path)
    (tmp_path / "state" / "web_recon_verifications.ndjson").write_text(json.dumps({
        "alert_id": "exp-1", "key": _KEY, "verdict": "confirmed",
        "summary": "Confirmed", "signature": "git HEAD",
        "checked_at": "2026-10-22T15:21:00+00:00"}) + "\n")
    st.alerts.triage("exp-1", {"verdict": "false_positive", "status": "open"})
    st.alerts.triage("exp-1", {"verdict": "true_positive", "status": "resolved"})

    got = st.alerts.list("incidents")
    assert [r["id"] for r in got["rows"]] == ["exp-2", "exp-1"], "newest first"
    exp1 = got["rows"][1]
    assert exp1["title"].startswith("Source-code repository") and \
        "https://www.example.edu/.git/" in exp1["title"]
    assert exp1["network"] == "Example Hosting" and exp1["country"] == "Testland"
    assert exp1["verification"]["verdict"] == "confirmed"
    assert exp1["triage"]["verdict"] == "true_positive", "the latest verdict wins"
    # Verification is about the exposure, so the other alert of the same key shows it.
    assert got["rows"][0]["verification"]["verdict"] == "confirmed"
    tally = got["tally"]["exposure"]
    assert tally == {"total": 2, "true_positive": 1, "false_positive": 0, "benign": 0,
                     "untriaged": 1, "precision": 1.0}


def test_a_pre_schema_alert_still_renders(tmp_path: Path) -> None:
    st = _analyst(tmp_path)
    old = next(r for r in st.alerts.list("all")["rows"] if r["id"] == "1")
    assert old["category"] == "scanner" and old["ip"] == "10.0.0.9"
    assert old["title"].startswith("Scanner — 10.0.0.9")
    detail = st.alerts.detail("1")
    assert detail["exposures"] == [] and detail["other_clients"] == []
    assert "10.0.0.9" in detail["investigate"]["esql"]


def test_detail_answers_who_else_and_how_to_check(tmp_path: Path) -> None:
    st = _analyst(tmp_path)
    d = st.alerts.detail("exp-1")
    assert {c["client"] for c in d["other_clients"]} == {
        "203.0.113.38", "203.0.113.77", "198.51.100.4"}, "same key only"
    assert d["distinct_clients"] == 3
    assert sum(c["this_alert"] for c in d["other_clients"]) == 2
    ex = d["exposures"][0]
    assert ex["curl"] == "curl -sk -r 0-300 'https://www.example.edu/.git/HEAD'"
    assert "every path" in ex["how_to_read"]
    inv = d["investigate"]
    assert 'source.ip == "203.0.113.38"' in inv["esql"]
    assert 'url.domain == "www.example.edu"' in inv["esql"]
    assert inv["kibana_url"] is None, "no link without siem.kibana_url"
    assert st.alerts.detail("nope") is None and st.alerts.detail("../../etc") is None


def test_the_kibana_link_needs_an_http_base_and_quotes_its_values(tmp_path: Path) -> None:
    st = _analyst(tmp_path, kibana_url="https://kibana.example.edu:5601/")
    link = st.alerts.detail("exp-1")["investigate"]["kibana_url"]
    assert link.startswith("https://kibana.example.edu:5601/app/discover#/?_g=")
    assert "203.0.113.38" in link and " " not in link
    bad = _analyst(tmp_path / "b", kibana_url="javascript:alert(1)")
    assert bad.alerts.detail("exp-1")["investigate"]["kibana_url"] is None


def test_a_forged_host_never_reaches_the_query_text(tmp_path: Path) -> None:
    st = _analyst(tmp_path)
    doc = _exposure_alert("exp-x", "203.0.113.5")
    doc["url"]["domain"] = 'evil" OR 1==1 | DROP'
    doc["exposure"][0]["domain"] = "evil'; rm -rf /"
    with (tmp_path / "alerts" / "web_recon.ndjson").open("a") as fh:
        fh.write(json.dumps(doc) + "\n")
    d = st.alerts.detail("exp-x")
    assert "evil" not in d["investigate"]["esql"]
    assert d["exposures"][0]["curl"] is None, "no command is built for an invalid site"


def test_triage_validates_and_records(tmp_path: Path) -> None:
    st = _analyst(tmp_path)
    with pytest.raises(ValueError):
        st.alerts.triage("exp-1", {"verdict": "maybe"})
    with pytest.raises(ValueError):
        st.alerts.triage("exp-1", {"status": "closed-forever"})
    with pytest.raises(LookupError):
        st.alerts.triage("no-such", {"verdict": "benign"})
    row = st.alerts.triage("exp-1", {"verdict": "benign", "status": "investigating",
                                     "note": "our own pentest", "checklist": [1, 0, 1]})
    assert row["checklist"] == [True, False, True] and row["by"] == "operator"
    lines = (tmp_path / "state" / "triage.ndjson").read_text().splitlines()
    assert json.loads(lines[-1])["note"] == "our own pentest"


def _fake_verify(calls):
    def verify(domain, root, kind, *, allowed_domains):
        calls.append((domain, root, kind, allowed_domains))
        return {"verdict": "not_reproducible", "summary": "catch-all page",
                "checked_at": "2026-10-22T16:00:00+00:00", "domain": domain, "root": root}
    return verify


def test_the_background_check_verifies_each_exposure_once(tmp_path: Path) -> None:
    calls: list = []
    st = _analyst(tmp_path, verify_fn=_fake_verify(calls), allowed_domains=("example.edu",))
    assert st.alerts.verify_pending() == 1, "two alerts, one exposure key"
    assert calls == [("www.example.edu", "/.git/", "vcs", ("example.edu",))]
    assert st.alerts.verify_pending() == 0, "already checked"
    row = st.alerts.list("incidents")["rows"][0]
    assert row["verification"]["verdict"] == "not_reproducible"


def test_without_verify_domains_the_real_check_refuses_offline(tmp_path: Path) -> None:
    st = _analyst(tmp_path)          # real verify(), empty allow-list: no network
    st.alerts.verify_pending()
    rec = st.alerts.list("incidents")["rows"][0]["verification"]
    assert rec["verdict"] == "refused"


@pytest.fixture()
def analyst_server(tmp_path: Path):
    made = {}

    def start(calls, **kw):
        st = _analyst(tmp_path, verify_fn=_fake_verify(calls),
                      allowed_domains=("example.edu",))
        httpd = build_server(st, host="127.0.0.1", port=0, **kw)
        serve_in_thread(httpd)
        made["httpd"] = httpd
        return f"http://127.0.0.1:{httpd.server_address[1]}", st

    yield start
    if "httpd" in made:
        made["httpd"].shutdown()
        made["httpd"].server_close()


def test_alert_routes_serve_the_queue_and_detail(analyst_server) -> None:
    base, _ = analyst_server([])
    code, body = _get(base + "/api/alerts?category=incidents")
    assert code == 200 and [r["id"] for r in body["rows"]] == ["exp-2", "exp-1"]
    code, body = _get(base + "/api/alerts/exp-1")
    assert code == 200 and body["summary"]["id"] == "exp-1"
    try:
        _get(base + "/api/alerts/missing")
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_triage_and_verify_need_the_token(analyst_server) -> None:
    calls: list = []
    base, _ = analyst_server(calls, token="s3cret")
    code, _ = _post(base + "/api/alerts/exp-1/triage", {"verdict": "true_positive"})
    assert code == 401
    code, _ = _post(base + "/api/alerts/exp-1/verify", {})
    assert code == 401 and calls == []

    code, row = _post(base + "/api/alerts/exp-1/triage",
                      {"verdict": "true_positive", "status": "resolved"}, token="s3cret")
    assert code == 200 and row["verdict"] == "true_positive"
    code, _ = _post(base + "/api/alerts/exp-1/triage", {"verdict": "nah"}, token="s3cret")
    assert code == 400

    code, body = _post(base + "/api/alerts/exp-1/verify", {}, token="s3cret")
    assert code == 200 and body["results"][0]["verdict"] == "not_reproducible"
    code, body = _post(base + "/api/alerts/exp-1/verify", {}, token="s3cret")
    assert body["results"][0]["rate_limited"] is True, "one check per minute per exposure"
    assert len(calls) == 1


def test_a_read_only_console_refuses_triage(analyst_server) -> None:
    base, _ = analyst_server([], read_only=True)
    code, _ = _post(base + "/api/alerts/exp-1/triage", {"verdict": "benign"})
    assert code == 403
