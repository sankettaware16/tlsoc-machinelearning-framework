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
from soc_ml.core.plugins import usecase_model_factories
from soc_ml.features.exposure import ExposureTracker, classify, verify
from soc_ml.registry.store import ModelRegistry
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases import BotDetection
from tests.test_detection_lifecycle import T0
from tests.test_findings import _evidence, _profile
from tests.test_progressive import _benign, _rows, _run

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


def test_a_page_that_echoes_the_path_is_not_an_exposure() -> None:
    """prod, 6 Nov: a soft-404 printing the path 5 times answered /x/.env with
    125,629 bytes and /x/.htaccess, /x/trace.axd with 125,654 — no size three
    times, so the exact-size rule delivered all three."""
    d = "/tabs/nojs/tab_a"
    ev = _evidence(_profile(), [_ev(f"{d}/.env", size=125_629),
                                _ev(f"{d}/.htaccess", size=125_654, seconds=1),
                                _ev(f"{d}/trace.axd", size=125_654, seconds=2)])
    assert not [e for w in ev for e in w["exposures"]]


def test_a_routed_parent_page_is_not_an_exposure() -> None:
    """prod, 6 Nov: /project/13/<anything> served the project page; the
    scanner's own random probes got 20,791 and 20,790 bytes, trace.axd 20,781."""
    ev = _evidence(_profile(), [_ev("/project/13/2085030971309886763", size=20_791),
                                _ev("/project/13/967931374307874472", size=20_790, seconds=1),
                                _ev("/project/13/trace.axd", size=20_781, seconds=2)])
    assert not [e for w in ev for e in w["exposures"]]


def test_the_probes_count_though_the_directory_is_busy() -> None:
    """prod, 6 Nov: two random probes of /division/ (17,313 bytes), then the
    scanner crawled the directory's pages, then trace.axd (17,303)."""
    probes = [_ev(f"/division/{n}", size=17_313, seconds=i)
              for i, n in enumerate(("4425020930872022362", "6674209890008715192"))]
    crawl = [_ev(f"/division/page-{i:02d}", ip="198.51.100.4", size=9_000 + 37 * i,
                 seconds=2 + i * 0.1) for i in range(20)]
    ev = _evidence(_profile(), probes + crawl + [_ev("/division/trace.axd", size=17_303,
                                                     seconds=5)])
    assert not [e for w in ev for e in w["exposures"]]


def test_real_files_beside_pages_and_each_other_are_still_exposures() -> None:
    """Sizes that differ, or follow no common echo count, are files. Two
    copies of one .env (913 and 914 bytes) are both real."""
    ev = _evidence(_profile(), [
        _ev("/about", ip="198.51.100.1", size=24_310),
        _ev("/contact", ip="198.51.100.2", size=19_877, seconds=1),
        _ev("/.env", size=913, seconds=2), _ev("/.env.bak", size=914, seconds=3),
        _ev("/sites/default/files/.htaccess", size=486, seconds=4),
        _ev("/sites/default/files/2024-05/report.pdf", ip="198.51.100.3", size=512_004,
            seconds=5)])
    assert sorted(e["root"] for w in ev for e in w["exposures"]) == [
        "/.env", "/.env.bak", "/sites/default/files/.htaccess"]


def test_one_echo_coincidence_is_not_a_catch_all() -> None:
    """Two siblings are needed, and with the same echo count."""
    ev = _evidence(_profile(), [_ev("/app/x", ip="198.51.100.1", size=1_000),
                                _ev("/app/longer-name", ip="198.51.100.2", size=1_100),
                                _ev("/app/.env", size=1_001, seconds=2)])
    assert [e["root"] for w in ev for e in w["exposures"]] == ["/app/.env"]


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


def test_an_exposure_is_alerted_by_one_use_case_only(tmp_path: Path) -> None:
    """prod replay, 2 Nov: bot_detection queued the same web.config and
    .htaccess web_recon did."""
    bundle = train_bundle(BotDetection, usecase_model_factories(BotDetection),
                          lambda: iter(_benign()), source_desc="benign only")
    ModelRegistry(tmp_path).save_bundle(bundle)
    ModelRegistry(tmp_path).promote("bot_detection", bundle.version)
    rt = _run(tmp_path, [_ev("/.env", size=913)], usecases=("bot_detection", "web_recon"))
    assert [r.slug for r in rt.runners] == ["bot_detection", "web_recon"]
    assert len(_rows(tmp_path / "alerts" / "web_recon.ndjson")) == 1
    bot = tmp_path / "alerts" / "bot_detection.ndjson"
    assert not [d for d in (_rows(bot) if bot.exists() else [])
                if d["alert"]["category"] == "exposure" or "exposure" in d]
    assert not (tmp_path / "state" / "bot_detection_exposures.ndjson").exists()


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


def test_a_status_page_is_confirmed_although_it_is_html() -> None:
    """prod, 31 Oct: a library catalogue served Apache's /server-status; the
    first verifier rejected it as "an ordinary web page"."""
    out, _ = _verify("debug", "/server-status", _Resp(
        b"<!DOCTYPE HTML PUBLIC><html><head><title>Apache Status</title></head><body>"
        b"<h1>Apache Server Status for lib.example.edu</h1><dl><dt>Server Version: ",
        status=200, ctype="text/html"))
    assert out["verdict"] == "confirmed" and out["signature"] == "server status"


def test_a_php_error_log_is_confirmed() -> None:
    """prod, 6 Nov: a public /error_log of PHP warnings was only "likely"."""
    out, _ = _verify("debug", "/error_log", _Resp(
        b"[04-Apr-2025 09:25:09 UTC] PHP Warning:  Constant X already defined in "
        b"/home/site/config.php on line 17\n", status=200, ctype=""))
    assert out["verdict"] == "confirmed" and out["signature"] == "log file"
    out, _ = _verify("debug", "/logs/error.log", _Resp(
        b"[Wed Nov 06 01:23:45.123456 2026] [php:error] [pid 1] PHP Fatal error\n"))
    assert out["verdict"] == "confirmed"


def test_trace_viewers_are_confirmed_although_html_and_a_page_is_not() -> None:
    out, _ = _verify("debug", "/trace.axd", _Resp(
        b"<html><head><style>span.tracecontent b { color:white }</style>", status=200,
        ctype="text/html"))
    assert out["verdict"] == "confirmed" and out["signature"] == "ASP.NET trace"
    out, _ = _verify("debug", "/elmah.axd", _Resp(
        b"<!DOCTYPE html><html><head><title>Error log for / on WEB01 (Page #1)</title>"
        b"<meta name=\"generator\" content=\"ELMAH\">", status=200, ctype="text/html"))
    assert out["signature"] == "ELMAH error log"
    # prod, 6 Nov: /project/13/trace.axd answered by the project's own page.
    out, _ = _verify("debug", "/project/13/trace.axd", _Resp(
        b"<!DOCTYPE html><html><head><title>Project 13</title>", status=200,
        ctype="text/html"))
    assert out["verdict"] == "not_reproducible"


def test_the_download_line_leads_the_evidence(tmp_path: Path) -> None:
    scan = [_ev(f"/probe{i}", 404, size=150 + i, seconds=i) for i in range(12)]
    _run(tmp_path, scan[:3] + [_ev("/.env", size=913, seconds=3.5)] + scan[3:])
    doc = _rows(tmp_path / "alerts" / "web_recon.ndjson")[0]
    assert doc["explanation"]["evidence_events"][0] == f"{SITE} GET /.env 200 913"
    assert doc["exposure"][0]["files"][0]["line"] == f"{SITE} GET /.env 200 913"
