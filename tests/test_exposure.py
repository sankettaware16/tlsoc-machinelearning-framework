"""Sensitive-file exposure (D-040): the alert an analyst can act on.

The cases come from prod, 22 Oct - 2 Nov, with names replaced: a repository
downloaded object by object; scanners handed a site's real ``.htaccess``; an
SPA that answers ``/dashboard/.env`` with its own shell; Anubis and ONLYOFFICE
assets that the old "never-served file type" rule escalated as critical.
"""

from __future__ import annotations

import io
import json
import urllib.error
from datetime import timedelta
from email.message import Message
from pathlib import Path

from soc_ml.core.contracts import Event, Observer
from soc_ml.features.exposure import ExposureTracker, classify, verify
from tests.test_detection_lifecycle import T0
from tests.test_findings import _evidence, _profile
from tests.test_progressive import _rows, _run

SITE = "club.example.edu"


def _ev(path: str, status: int = 200, *, ip: str = "203.0.113.38", size: int = 311,
        seconds: float = 0, site: str = SITE, ua: str = "python-requests/2.31") -> Event:
    return Event(timestamp=T0 + timedelta(hours=2, seconds=seconds),
                 observer=Observer(server="web01"), source_ip=ip, geo_country_iso="ZZ",
                 source_asn=14061, source_as_org="EXAMPLE-HOSTING",
                 url_path=path, url_domain=site, status_code=status, user_agent=ua,
                 body_bytes=size, original=f"{site} GET {path} {status} {size}")


# ------------------------------ classification ------------------------------ #


def test_sensitive_kinds_and_roots() -> None:
    assert classify("/~groupa/.git/objects/ab/cdef")[1] == "/~groupa/.git/"
    assert classify("/.git/config")[0].slug == "vcs"
    assert classify("/search/.env")[0].slug == "secrets"
    assert classify("/db.sql.gz")[0].slug == "dump"
    assert classify("/wp-config.php.bak")[0].slug == "secrets"
    assert classify("/index.php~")[0].slug == "source"
    assert classify("/.git.tar.gz")[0].slug == "backup"
    assert classify("/.htaccess")[0].slug == "server_config"
    assert classify("/phpinfo.php")[0].slug == "debug"
    assert classify("/.DS_Store")[0].alert is False, "metadata is recorded, not alerted"


def test_what_the_old_rule_escalated_is_not_sensitive() -> None:
    """30 of 39 escalations, 22 Oct - 2 Nov: new legitimate services."""
    for path in ("/.within.website/x/cmd/anubis/static/js/main.mjs",
                 "/8.1.3-4/sdkjs/common/libfont/engine/fonts.wasm",
                 "/cache/files/data/1/Editor.bin/Editor.bin",
                 "/dana-cached/hc/HostCheckerInstaller.osx",
                 "/themes/custom/x/webfonts/fa-brands-400.eot",
                 "/wp-content/themes/t/static/bundle/main.js@ver=2.1.21",
                 "/.well-known/security.txt", "/sites/default/files/foot.dwg",
                 "/.gitignore", "/course-notes.zip", "/README.md"):
        hit = classify(path)
        assert hit is None or not hit[0].alert, path


# ------------------------------- the builder -------------------------------- #


def test_a_repository_download_is_one_exposure_with_every_object() -> None:
    events = [_ev("/~groupa/.git/HEAD", size=23)] + [
        _ev(f"/~groupa/.git/objects/{i:02x}/{i:038x}", size=200 + i, seconds=i + 1)
        for i in range(30)]
    ev = _evidence(_profile(), events)
    exposures = [e for w in ev for e in w["exposures"]]
    assert len(exposures) == 1
    exp = exposures[0]
    assert exp["key"] == f"{SITE}|/~groupa/.git/" and exp["kind"] == "vcs"
    assert exp["files_count"] == 31 and exp["bytes_total"] == 23 + sum(200 + i for i in range(30))


def test_the_sites_catch_all_page_is_not_an_exposure() -> None:
    """An SPA answered /dashboard/.env with the same 110,059-byte shell it
    returns for /dashboard and every other route."""
    shell = [_ev(p, ip=f"198.51.100.{i}", size=110_059, seconds=i)
             for i, p in enumerate(("/dashboard", "/dashboard/login", "/dashboard/x"))]
    ev = _evidence(_profile(), shell + [_ev("/dashboard/.env", size=110_059, seconds=9)])
    assert not [e for w in ev for e in w["exposures"]]


def test_a_real_file_that_shares_its_size_with_one_page_is_still_an_exposure() -> None:
    """The main site's real .htaccess was 8,024 bytes — so was one ordinary
    page. One coincidence is not a catch-all."""
    ev = _evidence(_profile(), [_ev("/en/node.html", ip="198.51.100.1", size=8024),
                                _ev("/.htaccess", size=8024, seconds=5)])
    assert [e["root"] for w in ev for e in w["exposures"]] == ["/.htaccess"]


def test_empty_bodies_and_failures_are_not_exposures() -> None:
    ev = _evidence(_profile(), [_ev("/.env", 404), _ev("/.git/HEAD", 200, size=0, seconds=1),
                                _ev("/.env", 403, seconds=2)])
    assert not [e for w in ev for e in w["exposures"]]


def test_a_rotating_scanner_reports_its_exposure_once() -> None:
    ev = _evidence(_profile(), [_ev("/.env", size=913, ua=f"ua-{i}", seconds=i)
                                for i in range(5)])
    assert len(ev) == 5
    assert sum(len(w["exposures"]) for w in ev) == 1


# ------------------------------- delivery --------------------------------- #


def test_a_single_targeted_download_is_alerted_though_the_models_do_not_fire(
        tmp_path: Path) -> None:
    """One request never reaches the evidence floor (5 events, 3 paths); the
    old code could not alert on it at all."""
    rt = _run(tmp_path, [_ev("/.env", size=913)])
    alerts = _rows(tmp_path / "alerts" / "web_recon.ndjson")
    assert len(alerts) == 1 and rt.stats["alerts_delivered"] == 1
    doc = alerts[0]
    assert doc["alert"]["category"] == "exposure" and doc["alert"]["severity"] == "critical"
    assert doc["url"]["full"] == f"https://{SITE}/.env"
    assert doc["source"]["as"]["organization"]["name"] == "EXAMPLE-HOSTING"
    assert "did not look like a scan" in doc["explanation"]["narrative"]
    rows = _rows(tmp_path / "state" / "web_recon_exposures.ndjson")
    assert rows[0]["client"] == "203.0.113.38" and rows[0]["new"] is True


def test_later_downloaders_fold_into_the_first_alert_and_are_all_recorded(
        tmp_path: Path) -> None:
    downloads = [_ev("/.htaccess", ip=f"203.0.113.{10 + i}", size=8024, seconds=600 * i)
                 for i in range(5)]
    _run(tmp_path, downloads)
    alerts = _rows(tmp_path / "alerts" / "web_recon.ndjson")
    assert len(alerts) == 1, "five scanners, one misconfiguration"
    rows = _rows(tmp_path / "state" / "web_recon_exposures.ndjson")
    assert len(rows) == 5 and {r["alert_id"] for r in rows} == {alerts[0]["alert"]["id"]}


def test_an_allowed_exposure_is_not_alerted(tmp_path: Path) -> None:
    _run(tmp_path, [_ev("/.htaccess", size=8024)], exposure_allow=(f"{SITE}|/.htaccess",))
    assert _rows(tmp_path / "alerts" / "web_recon.ndjson") == []


def test_the_tracker_survives_a_restart() -> None:
    t = ExposureTracker()
    assert t.decide("s|/.env", "a1", T0, "1.1.1.1") == ("deliver", "a1")
    u = ExposureTracker()
    u.restore_state(json.loads(json.dumps(t.export_state())))
    assert u.decide("s|/.env", "a2", T0 + timedelta(hours=3), "2.2.2.2") == ("fold", "a1")
    assert u.decide("s|/.env", "a3", T0 + timedelta(days=8), "3.3.3.3")[0] == "deliver", (
        "still being downloaded a week later: raised again")


# ------------------------------ verification ------------------------------ #


class _Resp(io.BytesIO):
    def __init__(self, body: bytes, status: int = 206, ctype: str = "application/octet-stream"):
        super().__init__(body)
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = ctype

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, result):
        self.result = result
        self.urls: list[str] = []

    def open(self, req, timeout):
        self.urls.append(req.full_url)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _verify(kind: str, root: str, result) -> tuple[dict, list[str]]:
    opener = _Opener(result)
    out = verify(SITE, root, kind, allowed_domains=("example.edu",), opener=opener)
    return out, opener.urls


def test_verification_confirms_by_content_signature() -> None:
    out, urls = _verify("vcs", "/~groupa/.git/", _Resp(b"ref: refs/heads/main\n"))
    assert urls == [f"https://{SITE}/~groupa/.git/HEAD"]
    assert out["verdict"] == "confirmed" and out["signature"] == "git HEAD"
    out, _ = _verify("server_config", "/web.config",
                     _Resp(b'<?xml version="1.0"?>\n<configuration>\n'))
    assert out["verdict"] == "confirmed"
    out, _ = _verify("secrets", "/.env", _Resp(b"APP_KEY=base64:abc\nDB_PASSWORD=x\n"))
    assert out["verdict"] == "confirmed" and "content" not in out and "body" not in out


def test_an_html_answer_is_not_reproducible() -> None:
    out, _ = _verify("secrets", "/dashboard/.env",
                     _Resp(b"<!DOCTYPE html><html><head>", ctype="text/html"))
    assert out["verdict"] == "not_reproducible"


def test_a_refusal_now_is_reported_as_blocked() -> None:
    hdrs = Message()
    out, _ = _verify("secrets", "/.env",
                     urllib.error.HTTPError(f"https://{SITE}/.env", 403, "Forbidden", hdrs, None))
    assert out["verdict"] == "blocked_now" and out["status"] == 403


def test_a_forged_host_is_never_contacted() -> None:
    """The domain is the client's Host header: verify only the institute's sites."""
    for host in ("internal-admin.local", "169.254.169.254", "example.edu.attacker.net"):
        opener = _Opener(_Resp(b"x"))
        out = verify(host, "/.env", "secrets", allowed_domains=("example.edu",), opener=opener)
        assert out["verdict"] == "refused" and opener.urls == [], host
