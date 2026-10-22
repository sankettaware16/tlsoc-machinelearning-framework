"""A scan that *finds* something is not a weak signal (D-034).

Progressive alerting keeps one-burst scanners low (D-033) — right for the
thousands a day that find nothing, wrong for the one that gets a config file
back. On elkcc, 2026-10-12, six of nine captured scanners received HTTP 200 for
``/web.config`` from www.iitb.ac.in. A *finding* is a success on a file type
the server never serves, at a path it was never seen serving — both learned
from the profile, no threshold. A fired window with a finding is queued at
once, at the spec's "transition-to-success" context band, with no ceiling.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from soc_ml.baseline.profile import EnvironmentProfile, file_type
from soc_ml.core.contracts import Event, Observer, Severity
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.fusion.progressive import Progression
from tests.test_detection_lifecycle import T0
from tests.test_progressive import _benign, _fire, _rows, _run


def _ev(path: str, status: int = 200, ip: str = "203.0.113.9", ua: str = "probe/1.0",
        seconds: float = 0) -> Event:
    return Event(timestamp=T0 + timedelta(hours=2, seconds=seconds),
                 observer=Observer(server="web01"), source_ip=ip, geo_country_iso="ZZ",
                 url_path=path, status_code=status, http_referrer=None,
                 user_agent=ua, body_bytes=4039, original=f"GET {path} {status}")


def _profile(extra: list[Event] = ()) -> EnvironmentProfile:
    p = EnvironmentProfile()
    for e in _benign() + list(extra):
        p.observe(e)
    return p


def _evidence(profile: EnvironmentProfile, events: list[Event]) -> list[dict]:
    b = WindowFeatureBuilder(profile)
    out = []
    for e in events:
        out.extend(b.add(e))
    out.extend(b.flush())
    return [r.evidence for r in out]


# ------------------------------- profile -------------------------------- #


def test_file_type_covers_hidden_paths() -> None:
    assert file_type("/.env") == ".env"
    assert file_type("/.git/config") == ".git"
    assert file_type("/web.config") == "config"
    assert file_type("/admin/") is None


def test_profile_learns_served_hidden_segments_and_round_trips(tmp_path: Path) -> None:
    known = [_ev(f"/.well-known/acme-{i}", seconds=i) for i in range(3)]
    p = _profile(known)
    assert ".well-known" in p.served_types("web01")
    assert "html" in p.served_types("web01") and ".env" not in p.served_types("web01")
    assert p.path_seen("web01", "/page0.html") and not p.path_seen("web01", "/.env")
    p.save(tmp_path / "p.json")
    assert ".well-known" in EnvironmentProfile.load(tmp_path / "p.json").served_types("web01")

    legacy = json.loads((tmp_path / "p.json").read_text())
    legacy.pop("hidden_2xx")
    (tmp_path / "old.json").write_text(json.dumps(legacy))
    old = EnvironmentProfile.load(tmp_path / "old.json")
    assert ".well-known" not in old.served_types("web01"), "older profiles know none"


# ------------------------------- builder -------------------------------- #


def test_a_success_on_a_never_served_file_type_is_a_finding() -> None:
    ev = _evidence(_profile(), [_ev("/x.html", 404), _ev("/web.config", 200, seconds=1),
                                _ev("/.env", 404, seconds=2), _ev("/page1.html", 200, seconds=3)])
    assert ev[0]["source_findings"] == [{"path": "/web.config", "status": 200, "bytes": 4039}]


def test_failures_served_types_and_known_paths_are_not_findings() -> None:
    p = _profile([_ev("/legacy.cfg", 200, ip="10.0.0.1", seconds=s) for s in range(1)]
                 + [_ev(f"/.well-known/k{i}", 200, ip="10.0.0.1", seconds=i) for i in range(3)])
    ev = _evidence(p, [
        _ev("/.env", 404),                         # probed, not found
        _ev("/index.html", 200, seconds=1),        # a type this site serves
        _ev("/.well-known/security.txt", 200, seconds=2),  # a served hidden segment
        _ev("/legacy.cfg", 200, seconds=3),        # unserved type, but a known path
    ])
    assert ev[0]["source_findings"] == []


def test_a_rotating_scanner_cannot_split_the_finding_away() -> None:
    ev = _evidence(_profile(), [
        _ev(f"/probe{i}.php", 404, ua="ua-a", seconds=i) for i in range(5)
    ] + [_ev("/backup.sql", 200, ua="ua-b", seconds=10)])
    assert len(ev) == 2
    assert all(e["source_findings"][0]["path"] == "/backup.sql" for e in ev), (
        "the user-agent that found nothing carries its address's finding too"
    )


# ----------------------------- progression ------------------------------ #


def test_a_finding_is_queued_at_once_without_a_ceiling() -> None:
    p = Progression()
    a = _fire(score=100)
    a.links["findings"] = [{"path": "/web.config", "status": 200, "bytes": 4039}]
    step = p.decide(a)
    assert step.action == "deliver" and step.escalated
    assert a.severity is Severity.CRITICAL and a.severity_score == 100
    assert a.links["progressive"]["escalated_by"] == "finding"
    again = _fire(minutes=5, score=100)
    again.links["findings"] = a.links["findings"]
    assert p.decide(again).action == "fold", "once per address per day still holds"


# ------------------------------- runtime -------------------------------- #


def _burst(found: bool) -> list[Event]:
    events = [_ev(f"/secret/dump_{i}.php", 404, ip="203.0.113.60", seconds=2 * i)
              for i in range(40)]
    if found:
        events.append(_ev("/backup.sql", 200, ip="203.0.113.60", seconds=81))
    return events


def test_a_one_burst_scan_that_finds_something_reaches_the_queue(tmp_path: Path) -> None:
    rt = _run(tmp_path, _burst(found=True))
    assert rt.stats["alerts_delivered"] == 1
    doc = _rows(tmp_path / "alerts" / "web_recon.ndjson")[0]
    assert doc["alert"]["severity"] == "critical"
    assert doc["links"]["findings"][0]["path"] == "/backup.sql"
    assert "never serves: /backup.sql (200" in doc["explanation"]["narrative"]
    rows = [r for r in _rows(tmp_path / "state" / "web_recon_scores.ndjson")
            if "203.0.113.60" in r["entity"]]
    assert rows[0]["escalated_by"] == "finding"


def test_the_same_burst_finding_nothing_stays_a_candidate(tmp_path: Path) -> None:
    rt = _run(tmp_path, _burst(found=False))
    assert rt.stats["alerts_delivered"] == 0


def test_the_narrative_names_what_was_found() -> None:
    from soc_ml.explain.context import narrative
    text = narrative("T", "1.2.3.4", "web01", {
        "event_count": 9, "distinct_paths": 9, "n404": 8,
        "source_findings": [{"path": "/web.config", "status": 200, "bytes": 4039}]}, [])
    assert "a file type this site never serves: /web.config (200, 4,039 bytes)." in text
