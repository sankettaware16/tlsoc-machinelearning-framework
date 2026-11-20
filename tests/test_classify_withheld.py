"""H5's classifier reads the raw log for every withheld exposure and names its class.

The cases are M-003c's: a catch-all served for ``/`` and ``/.env`` alike, a
search route that prints the term (16 Nov, the second of M-003b's two false
alerts), and prod 18-19 Nov, one scanner handed exactly 2,102 B with 200 for
``/.env.production`` and ``/.env.save`` while a browser and the SOC's check got
404 (D-044); and the review of 21 Nov: a script copy the suffix guess called
ordinary, another path's 206, a 304, the SOC's own verifier read back as
"another client", and tables that grew per client. Sites and addresses are
placeholders.
"""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

spec = importlib.util.spec_from_file_location(
    "classify_withheld", Path(__file__).resolve().parents[1] / "scripts" / "classify_withheld.py")
m = sys.modules["classify_withheld"] = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)  # registered first: its dataclasses look the module up by name

IST = ZoneInfo("Asia/Kolkata")
START = datetime(2026, 11, 17, tzinfo=IST)
END = datetime(2026, 11, 24, tzinfo=IST)
T = datetime(2026, 11, 18, 16, 58, 18, tzinfo=IST)
SITE = "portal.example.edu"
SCANNER = "203.0.113.7"
BROWSER = "198.51.100.23"
SOC = "192.0.2.10"
VERIFIER_UA = "tlsoc-ml-exposure-verifier/1.0"


def _line(path: str, status: int, size: int, *, site: str = SITE, ip: str = SCANNER,
          when: datetime = T, ua: str = "python-requests/2.31",
          prog: str = "vhnginx_access") -> str:
    local = when.astimezone(IST).strftime("%d/%b/%Y:%H:%M:%S %z")
    return (f'{when.astimezone(UTC).isoformat()} 10.0.0.4 {prog}: {site} {ip} ":" 56323 - - '
            f'[{local}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}" "-"')


def _record(path: str, size: int, *, status: int = 200, kind: str = "secrets", site: str = SITE,
            when: datetime = T, client: str = SCANNER, verdict: str | None = "not_reproducible",
            new: bool = False) -> dict:
    row = {"@timestamp": when.isoformat(), "key": f"{site}|{path}", "kind": kind,
           "domain": site, "root": path, "client": client, "files_count": 1,
           "bytes_total": size, "alert_id": "a1", "new": new,
           "files": [{"path": path, "status": status, "bytes": size,
                      "line": _line(path, status, size, site=site, ip=client, when=when)}]}
    if verdict:
        row["verdict"] = verdict
    return row


def _check(path: str, verdict: str, status: int, *, site: str = SITE) -> dict:
    return {"alert_id": None, "key": f"{site}|{path}", "verdict": verdict, "status": status,
            "content_type": "text/html", "checked_at": (T + timedelta(minutes=4)).isoformat(),
            "by": "runtime"}


def _run(tmp_path: Path, records: list[dict], lines: list[str], *, checks: list[dict] = (),
         gz: bool = False) -> tuple[list[dict], str]:
    state = tmp_path / "data" / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "web_recon_exposures.ndjson").write_text(
        "".join(json.dumps(r) + "\n" for r in records))
    (state / "web_recon_verifications.ndjson").write_text(
        "".join(json.dumps(c) + "\n" for c in checks))
    text = "".join(ln + "\n" for ln in lines)
    log = tmp_path / ("nginx.log.gz" if gz else "nginx.log")
    if gz:
        with gzip.open(log, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        log.write_text(text)
    out = io.StringIO()
    rows = m.report(tmp_path / "data", [str(log)], START, END, IST, out=out)
    return rows, out.getvalue()


@pytest.mark.parametrize("gz", [False, True])
def test_a_the_catch_all_size_names_the_other_path(tmp_path: Path, gz: bool) -> None:
    rows, text = _run(tmp_path, [_record("/.env", 9860)], [
        _line("/", 200, 9860, ip=BROWSER, when=T - timedelta(hours=3)),
        _line("/.env", 200, 9860),
    ], gz=gz)
    (row,) = rows
    assert row["class"] == "a"
    assert row["reason"].startswith("9860 B also for / (")
    assert "(a)" in text and "per class: (a) a size the site returned for another path: 1" in text


def test_a_does_not_count_the_keys_own_path_or_the_day_before_the_context(tmp_path: Path) -> None:
    """Two downloads of the same file are not 'another path'; two days back is not read."""
    rows, _ = _run(tmp_path, [_record("/.env", 9860)], [
        _line("/", 200, 9860, ip=BROWSER, when=START - timedelta(days=2)),
        _line("/.env", 200, 9860),
        _line("/.env", 200, 9860, ip=BROWSER, when=T + timedelta(minutes=1)),
    ])
    assert rows[0]["class"] == "d"


def test_b_a_slice_is_a_slice_whatever_size_it_shares(tmp_path: Path) -> None:
    rows, _ = _run(tmp_path, [_record("/backup.zip", 1024, status=206, kind="backup")], [
        _line("/", 200, 1024, ip=BROWSER),
        _line("/backup.zip", 206, 1024),
    ])
    assert rows[0]["class"] == "b" and "/backup.zip" in rows[0]["reason"]


def test_c_a_sibling_within_one_percent_is_the_echo_page(tmp_path: Path) -> None:
    rows, _ = _run(tmp_path, [_record("/search/.env", 34149)], [
        _line("/search/zzz", 200, 34200, ip=BROWSER, when=T - timedelta(minutes=30)),
        _line("/search/.env", 200, 34149),
    ])
    (row,) = rows
    assert row["class"] == "c"
    assert row["reason"].startswith("/search/zzz 34200 B is 0.15% from 34149 B (directory /search/")


def test_c_is_not_a_sibling_five_percent_away(tmp_path: Path) -> None:
    rows, _ = _run(tmp_path, [_record("/search/.env", 34149)], [
        _line("/search/zzz", 200, 35900, ip=BROWSER, when=T - timedelta(minutes=30)),
        _line("/search/.env", 200, 34149),
    ])
    assert rows[0]["class"] == "d"


def test_c_falls_back_to_the_route_only_when_the_directory_is_silent(tmp_path: Path) -> None:
    rows, _ = _run(tmp_path, [_record("/beta/app/.env", 20790)], [
        _line("/beta/index", 200, 20791, ip=BROWSER),
        _line("/beta/app/.env", 200, 20790),
    ])
    assert rows[0]["class"] == "c" and "(route /beta/" in rows[0]["reason"]
    rows, _ = _run(tmp_path, [_record("/beta/app/.env", 20790)], [
        _line("/beta/index", 200, 20791, ip=BROWSER),
        _line("/beta/app/other", 200, 5000, ip=BROWSER),  # the directory answers: no fallback
        _line("/beta/app/.env", 200, 20790),
    ])
    assert rows[0]["class"] == "d"


def test_d_a_lone_size_is_fetched_at_the_verdict(tmp_path: Path) -> None:
    rows, text = _run(tmp_path, [_record("/.env", 9860)], [
        _line("/", 200, 970, ip=BROWSER),
        _line("/.env", 200, 9860),
    ], checks=[_check("/.env", "not_reproducible", 200)])
    (row,) = rows
    assert row["class"] == "d" and row["reason"] == m.FETCH == row["action"]
    assert "FETCH AT THE VERDICT (up to 64 KB) and read" in text
    assert row["check"] == {"verdict": "not_reproducible", "status": 200,
                            "content_type": "text/html",
                            "checked_at": (T + timedelta(minutes=4)).isoformat(), "by": "runtime"}


def test_e_another_client_got_404_for_the_path(tmp_path: Path) -> None:
    """Prod, 18 Nov: the scanner's 200, a browser's 404, the check's 404 (D-044)."""
    lines = [
        _line("/.env.production", 200, 2102),
        _line("/.env.production", 404, 153, ip=BROWSER, when=T + timedelta(minutes=2)),
    ]
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102, verdict="blocked_now")], lines,
                   checks=[_check("/.env.production", "blocked_now", 404)])
    (row,) = rows
    assert row["class"] == "e"
    assert row["reason"].startswith(f"another client {BROWSER} got 404 for /.env.production")
    assert row["check"]["status"] == 404
    # The same log under a page verdict is not (e): the check saw the page itself.
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102)], lines)
    assert rows[0]["class"] == "d"


def test_e_needs_the_other_clients_404_inside_the_window(tmp_path: Path) -> None:
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102, verdict="blocked_now")], [
        _line("/.env.production", 404, 153, ip=BROWSER, when=START - timedelta(hours=1)),
        _line("/.env.production", 200, 2102),
    ])
    assert rows[0]["class"] == "d"


def test_e_the_same_client_got_the_same_size_for_another_sensitive_path(tmp_path: Path) -> None:
    """Prod, 19 Nov: 2,102 B for /.env.production and /.env.save, 970 B for the rest.

    Two sensitive-looking paths of one size from one client are (e)'s
    evidence; (a) counts ordinary paths only, or this could never be reached.
    """
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102, verdict="redirected")], [
        _line("/", 200, 970, ip=BROWSER),
        _line("/wp-login.php", 200, 970),
        _line("/.env.save", 200, 2102, when=T + timedelta(seconds=3)),
        _line("/.env.production", 200, 2102),
    ])
    (row,) = rows
    assert row["class"] == "e"
    assert row["reason"].startswith(f"same client {SCANNER} got 2102 B for /.env.save too")
    assert row["evidence"]["same_client"] == [SCANNER, 2102, ["/.env.save"]]


def test_the_window_and_the_withheld_definition(tmp_path: Path) -> None:
    rows, text = _run(tmp_path, [
        _record("/.env", 9860, when=START - timedelta(minutes=1)),   # before the window
        _record("/.env", 9860, when=END),                             # at its end
        _record("/web.config", 512, kind="server_config", new=True,
                verdict="confirmed"),                                 # delivered
        _record("/.htaccess", 300, kind="server_config", verdict=None),  # never checked
    ], [_line("/.env", 200, 9860)])
    assert rows == [] and "no withheld exposures in the window" in text


def test_downloads_are_grouped_by_key_with_every_client_and_size(tmp_path: Path) -> None:
    rows, _ = _run(tmp_path, [
        _record("/.env", 9860),
        _record("/.env", 9860, client=BROWSER, when=T + timedelta(hours=1)),
        _record("/search/.env", 34149, when=T + timedelta(hours=2)),
    ], [_line("/", 200, 9860, ip=BROWSER), _line("/.env", 200, 9860)])
    assert [r["key"] for r in rows] == [f"{SITE}|/.env", f"{SITE}|/search/.env"]
    assert rows[0]["downloads"] == 2 and rows[0]["clients"] == sorted([SCANNER, BROWSER])
    assert rows[0]["class"] == "a" and rows[1]["class"] == "d"


def test_error_lines_and_other_sites_are_skipped_without_a_crash(tmp_path: Path) -> None:
    rows, text = _run(tmp_path, [_record("/.env", 9860)], [
        "2026-11-18T11:28:18+00:00 10.0.0.4 vhnginx_error: 2026/11/18 16:58:18 [error] 12#12: "
        '*7 open() "/var/www/.env" failed (2: No such file or directory), client: 203.0.113.7',
        _line("/", 200, 9860, ip=BROWSER, site="www.example.edu"),  # another site's page
        "not a log line at all",
        _line("/.env", 200, 9860),
        # An access-shaped line on the error channel is not a request either.
        _line("/", 200, 9860, ip=BROWSER, prog="vhnginx_error"),
    ])
    assert rows[0]["class"] == "d"
    assert "3 non-access lines skipped" in text


def test_the_cli_writes_the_table_and_the_json(tmp_path: Path, capsys) -> None:
    state = tmp_path / "data" / "state"
    state.mkdir(parents=True)
    (state / "web_recon_exposures.ndjson").write_text(json.dumps(_record("/.env", 9860)) + "\n")
    log = tmp_path / "nginx.log"
    log.write_text("".join(ln + "\n" for ln in (
        _line("/", 200, 9860, ip=BROWSER), _line("/.env", 200, 9860))))
    out = tmp_path / "withheld.ndjson"
    assert m.main(["--live", str(tmp_path / "data"), "--start", START.isoformat(),
                   "--end", END.isoformat(), "--json", str(out), str(log)]) == 0
    text = capsys.readouterr().out
    assert "raw log counted from 2026-11-16T00:00:00+05:30 (the day before the window" in text
    assert f"{SITE}|/.env" in text and "18 Nov 16:58" in text
    (row,) = [json.loads(ln) for ln in out.read_text().splitlines()]
    assert row["class"] == "a" and row["sizes"] == [9860] and row["raw"]["path_status"] == {
        "/.env": {"2xx": 1}}


@pytest.mark.parametrize("other", [
    "/.env.save", "/wp-config.php.save", "/config.php~", "/id_rsa", "/web.config", "/phpinfo.php",
])
def test_e_the_second_sensitive_name_is_whatever_the_detector_calls_sensitive(
        tmp_path: Path, other: str) -> None:
    """Prod, 19 Nov, with the scanner's other 2,102 B hit any of the detector's kinds.

    A suffix guess called ``/wp-config.php.save`` ordinary: the key was (a) "also
    for /wp-config.php.save" and (e)'s second clause never saw it. Sensitive is
    what ``exposure.classify`` says it is, plus any dotfile.
    """
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102, verdict="redirected")], [
        _line("/", 200, 970, ip=BROWSER),
        _line(other, 200, 2102, when=T + timedelta(seconds=3)),
        _line("/.env.production", 200, 2102),
    ])
    (row,) = rows
    assert row["class"] == "e"
    assert row["reason"].startswith(f"same client {SCANNER} got 2102 B for {other} too")
    assert row["evidence"]["same_client"] == [SCANNER, 2102, [other]]


@pytest.mark.parametrize("key,copy", [
    ("/.env", "/.env.bak"), ("/wp-config.php.bak", "/wp-config.php.save"),
    ("/id_rsa", "/id_rsa.bak"),
])
def test_a_never_counts_a_second_copy_of_the_file(tmp_path: Path, key: str, copy: str) -> None:
    """Two real copies of one file, one size, one client: the catch-all's opposite."""
    rows, _ = _run(tmp_path, [_record(key, 3141)], [
        _line("/", 200, 970, ip=BROWSER),
        _line(copy, 200, 3141, when=T + timedelta(seconds=3)),
        _line(key, 200, 3141),
    ])
    assert rows[0]["class"] == "d"
    rows, _ = _run(tmp_path, [_record(key, 3141, verdict="blocked_now")], [
        _line(copy, 200, 3141, when=T + timedelta(seconds=3)),
        _line(key, 200, 3141),
    ])
    assert rows[0]["class"] == "e" and copy in rows[0]["reason"]


def test_another_paths_206_is_not_a_body_of_that_size(tmp_path: Path) -> None:
    """A slice's length is the range asked for; it is no path's size for (a) or (c)."""
    rows, _ = _run(tmp_path, [_record("/.env", 9860)], [
        _line("/video/lecture.mp4", 206, 9860, ip=BROWSER),
        _line("/.env", 200, 9860),
    ])
    assert rows[0]["class"] == "d"
    rows, _ = _run(tmp_path, [_record("/search/.env", 34149)], [
        _line("/search/clip.mp4", 206, 34200, ip=BROWSER, when=T - timedelta(minutes=30)),
        _line("/search/.env", 200, 34149),
    ])
    assert rows[0]["class"] == "d"


def test_e_does_not_take_a_304_for_a_refusal(tmp_path: Path) -> None:
    """304 says that client already holds a copy: the opposite of a 404."""
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102, verdict="blocked_now")], [
        _line("/.env.production", 200, 2102),
        _line("/.env.production", 304, 0, ip=BROWSER, when=T + timedelta(minutes=2)),
    ], checks=[_check("/.env.production", "blocked_now", 404)])
    (row,) = rows
    assert row["class"] == "d"
    assert row["raw"]["path_status"] == {"/.env.production": {"2xx": 1, "3xx": 1}}


def test_e_never_takes_the_socs_own_verifier_for_another_client(tmp_path: Path) -> None:
    """The check's 404 is the verdict's own evidence; read back from the log it is not a second."""
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102, verdict="blocked_now")], [
        _line("/.env.production", 200, 2102),
        _line("/.env.production", 404, 153, ip=SOC, ua=VERIFIER_UA, when=T + timedelta(minutes=4)),
    ], checks=[_check("/.env.production", "blocked_now", 404)])
    (row,) = rows
    assert row["class"] == "d"
    assert row["raw"]["path_status"] == {"/.env.production": {"2xx": 1}}


def test_the_verifier_ua_is_the_one_verify_sends() -> None:
    """The constant here must track ``exposure.verify()``, or the skip is silently void."""
    from soc_ml.features.exposure import verify

    sent = []

    class _Resp:
        status, headers = 404, {"Content-Type": "text/html"}

        def read(self, n: int = -1) -> bytes:
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> bool:
            return False

    class _Opener:
        def open(self, req, timeout=None):
            sent.append(req.get_header("User-agent"))
            return _Resp()

    verify(SITE, "/.env", "secrets", allowed_domains=(SITE,), opener=_Opener())
    assert sent and all(ua.startswith(m._VERIFIER_UA) for ua in sent)


def test_the_per_client_tables_keep_their_first_entries_only(tmp_path: Path, monkeypatch) -> None:
    """A withheld path probed from thousands of addresses must not grow the state with them."""
    monkeypatch.setattr(m, "PATHS_PER_SIZE", 2)
    site = m._Site(sizes={2102}, dirs={"/"}, segments={"/"}, paths={"/.env.production"},
                   clients={SCANNER})
    for i in range(5):
        when = T + timedelta(seconds=i)
        site.see("/.env.production", 404, 153, f"198.51.100.{i}", when, True)
        site.see("/.env.production", 206, 100, f"198.51.100.{i}", when, True)
        site.see(f"/.env.{i}", 200, 2102, SCANNER, when, True)
    site.see("/.env.production", 206, 100, SCANNER, T, True)
    st = site.path_stats["/.env.production"]
    assert list(st.non2xx) == ["198.51.100.0", "198.51.100.1"]
    assert list(site.client_size[(SCANNER, 2102)]) == ["/.env.0", "/.env.1"]
    assert st.partial == {SCANNER}  # (b) asks only about the withheld clients
    # The reason still names the first other client seen.
    rows, _ = _run(tmp_path, [_record("/.env.production", 2102, verdict="blocked_now")], [
        _line("/.env.production", 200, 2102),
        *(_line("/.env.production", 404, 153, ip=f"198.51.100.{i}", when=T + timedelta(minutes=i))
          for i in range(1, 5)),
    ])
    assert rows[0]["class"] == "e" and "another client 198.51.100.1 got 404" in rows[0]["reason"]

