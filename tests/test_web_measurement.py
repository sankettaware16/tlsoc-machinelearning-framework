"""The console's measurement view: a pre-registered doc, scored as it runs.

The view is only worth having if it counts the way the verdict will, so these
pin the doc's own rules — the verdict of record, the per-day budget, what a
withheld exposure is, what H4 counts — on a deployment shaped like prod's.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc_ml.web.server import build_server, serve_in_thread
from soc_ml.web.state import DashboardState

# The doc's prose breaks strict YAML on purpose ("authorised: the detection").
_DOC = """# M-009 — Exposure alerts, 3 days on a test box

*Written before the window opened.*

```yaml
id: M-009
question: >
  Are the exposure alerts real: and few?
window:
  start: 2026-12-01T00:00:00+05:30   # if the build runs by 30 Nov 23:00 IST
  end:   2026-12-04T00:00:00+05:30
definitions:
  exposure alert: a delivered web_recon alert with alert.category "exposure"
  verdict of record: the analyst's latest verdict; if an alert has none by
    2026-12-06 00:00 IST, the verifier's latest per exposure key stands in —
    benign (real but authorised: the detection was right)
hypotheses:
  H1: of exposure alerts with a verdict of record, >= 80% are correct, and
      at most 2 of the week's exposure alerts are untriaged
  H2: exposure alerts <= 3 per day on at least 5 of the 7 days
  H4: zero watchdog restarts and zero tracebacks inside the window
  H5: nothing real is held back
consequence:
  H1 fails: read the false positives
```

---

## Verdict

*(appended after the window closes)*
"""

_OTHER = """# M-008 — Something else

```yaml
id: M-008
window:
  start: 2026-11-01T00:00:00+05:30
  end:   2026-11-02T00:00:00+05:30
hypotheses:
  H1: a thing
```

## Verdict

H1 PASS.
"""

# 1 Dec IST, as UTC instants.
D1 = "2026-11-30T20:00:00+00:00"   # 1 Dec 01:30 IST
D2 = "2026-12-01T20:00:00+00:00"   # 2 Dec 01:30 IST
BEFORE = "2026-11-30T17:00:00+00:00"  # 30 Nov 22:30 IST, outside


def _alert(alert_id: str, ts: str, keys: list[str], category: str = "exposure") -> dict:
    return {"@timestamp": ts, "usecase": "web_recon",
            "entity": {"server": "srv", "ip": "203.0.113.7"},
            "alert": {"id": alert_id, "category": category, "severity": "high",
                      "severity_score": 85},
            "exposure": [{"key": k, "kind": "secrets", "domain": k.split("|")[0],
                          "root": k.split("|")[1]} for k in keys]}


def _check(key: str, verdict: str, at: str, by: str = "console") -> dict:
    return {"alert_id": None, "key": key, "checked_at": at, "verdict": verdict,
            "kind": "secrets", "url": "https://" + key.replace("|", ""), "by": by}


def _download(key: str, ts: str, *, new: bool, verdict: str | None = None,
              client: str = "203.0.113.9") -> dict:
    row = {"@timestamp": ts, "key": key, "kind": "secrets", "client": client, "new": new,
           "files": [{"path": key.split("|")[1], "status": 200, "bytes": 4103}]}
    return row | ({"verdict": verdict} if verdict else {})


def _box(tmp_path: Path) -> tuple[Path, Path]:
    repo, data = tmp_path / "repo", tmp_path / "data"
    (repo / "docs" / "measurements").mkdir(parents=True)
    (repo / "docs" / "measurements" / "M-009-test.md").write_text(_DOC)
    (repo / "docs" / "measurements" / "M-008-other.md").write_text(_OTHER)
    (data / "state").mkdir(parents=True)
    (data / "alerts").mkdir(parents=True)
    a, b, c, d = ("a.example.edu|/.env", "b.example.edu|/web.config",
                  "c.example.edu|/beta/.env", "d.example.edu|/x.bak")
    alerts = [
        _alert("analyst-fp", D1, [a]),      # verifier says confirmed, analyst says no
        _alert("confirmed", D1, [b]),
        _alert("page", D1, [c]),
        _alert("mixed", D1, [d, b]),        # d unreachable, b confirmed: any confirmed wins
        _alert("before", BEFORE, [a]),      # outside the window
        _alert("scanner", D1, [], category="scanner"),
    ] + [_alert(f"d2-{i}", D2, [d]) for i in range(4)]  # 4 on day 2: over budget
    (data / "alerts" / "web_recon.ndjson").write_text(
        "".join(json.dumps(x) + "\n" for x in alerts))
    (data / "state" / "web_recon_verifications.ndjson").write_text("".join(
        json.dumps(x) + "\n" for x in (
            _check(a, "confirmed", D1), _check(b, "confirmed", D1),
            _check(c, "not_reproducible", D1, by="runtime"),
            _check(d, "unreachable", D1, by="runtime"),
            # after the deadline: must not change the verdict of record
            _check(b, "blocked_now", "2026-12-07T00:00:00+00:00"),
        )))
    (data / "state" / "triage.ndjson").write_text(json.dumps(
        {"alert_id": "analyst-fp", "at": D2, "verdict": "false_positive"}) + "\n")
    (data / "state" / "web_recon_exposures.ndjson").write_text("".join(
        json.dumps(x) + "\n" for x in (
            _download("e.example.edu|/search/.env", D1, new=False, verdict="not_reproducible"),
            _download("e.example.edu|/search/.env", D2, new=False, verdict="not_reproducible",
                      client="203.0.113.10"),
            _download(c, D1, new=True, verdict="not_reproducible"),  # delivered, not withheld
            _download(b, D1, new=True, verdict="confirmed"),
            # D-044: a 404 to the SOC withholds too; the verdict says which
            _download("f.example.edu|/.env.save", D2, new=False, verdict="blocked_now"),
        )))
    (data / "state" / "runtime.log").write_text(
        "[watchdog] 2026-11-30T23:00:01+05:30 runtime not running; restarting\n"
        "2026-12-01T10:00:00+00:00 [runtime] resumed from checkpoint\n"
        "Traceback (most recent call last):\n"
        "  File \"x.py\", line 1\n")
    return repo, data


def _book(tmp_path: Path):
    repo, data = _box(tmp_path)
    return DashboardState(data, repo_root=repo).measurements


def test_the_doc_is_read_although_its_prose_is_not_strict_yaml(tmp_path: Path) -> None:
    listing = _book(tmp_path).list(now=datetime(2026, 12, 2, tzinfo=UTC))
    rows = {r["id"]: r for r in listing["measurements"]}
    assert rows["M-009"]["status"] == "open" and rows["M-009"]["scored"] is True
    # A verdict below the line makes a doc judged; not an exposure doc: not scored.
    assert rows["M-008"]["status"] == "judged" and rows["M-008"]["scored"] is False
    assert listing["current"] == "M-009"


def test_the_verdict_of_record_follows_the_docs_rule(tmp_path: Path) -> None:
    card = _book(tmp_path).scorecard("M-009", now=datetime(2026, 12, 10, tzinfo=UTC))
    record = {a["id"]: (a["of_record"], a["filled_in"]) for a in card["alerts"]}
    assert record == {
        "analyst-fp": ("false_positive", False),   # the analyst outranks the verifier
        "confirmed": ("true_positive", True),
        "page": ("false_positive", True),
        "mixed": ("true_positive", True),          # any exposure confirmed
        "d2-0": (None, False), "d2-1": (None, False),  # unreachable: untriaged
        "d2-2": (None, False), "d2-3": (None, False),
    }
    h1 = card["results"]["H1"]
    assert (h1["correct"], h1["judged"], h1["untriaged"]) == (2, 4, 4)
    assert h1["state"] == "fail" and h1["by_analyst"] == 1 and h1["filled_in"] == 3


def test_days_are_local_and_over_three_counts_against_h2(tmp_path: Path) -> None:
    card = _book(tmp_path).scorecard("M-009", now=datetime(2026, 12, 2, 12, tzinfo=UTC))
    assert [d["exposure_alerts"] for d in card["per_day"]] == [4, 4, None]
    assert card["results"]["H2"]["days_over"] == ["2026-12-01", "2026-12-02"]
    assert card["results"]["H2"]["state"] == "on_track"  # 7 - 5 = 2 days may go over


def test_a_withheld_exposure_is_a_checked_download_that_opened_no_alert(tmp_path: Path) -> None:
    card = _book(tmp_path).scorecard("M-009", now=datetime(2026, 12, 5, tzinfo=UTC))
    held = card["withheld"]
    # A page (D-042) and a 404 to the SOC (D-044) are both withheld; a checked
    # download that was delivered (new) is not.
    assert [w["key"] for w in held] == ["e.example.edu|/search/.env", "f.example.edu|/.env.save"]
    assert held[0]["downloads"] == 2 and held[0]["clients"] == 2
    assert held[1]["check"]["verdict"] is None, "no check record for it in this box"
    assert card["results"]["H5"]["state"] == "pending" and card["results"]["H5"]["withheld"] == 2
    assert [d["withheld"] for d in card["per_day"]] == [1, 1, 0]
    assert card["pre_checks"] == {"not_reproducible": 1, "unreachable": 1}


def test_h4_counts_only_what_the_log_puts_inside_the_window(tmp_path: Path) -> None:
    h4 = _book(tmp_path).scorecard("M-009", now=datetime(2026, 12, 5, tzinfo=UTC))["results"]["H4"]
    # The restart at 30 Nov 23:00 IST is before the window; the traceback after
    # a 1 Dec stamp is inside it.
    assert h4["restarts"] == [] and h4["tracebacks"] == 1 and h4["state"] == "fail"
    assert "H3" not in _book(tmp_path / "again").scorecard("M-009")["results"]  # not in the doc


def test_still_exposed_means_the_latest_check_found_it(tmp_path: Path) -> None:
    card = _book(tmp_path).scorecard("M-009", now=datetime(2026, 12, 5, tzinfo=UTC))
    keys = {o["key"] for o in card["open_exposures"]}
    # b's latest check is blocked_now; c is a page; d unreachable.
    assert keys == {"a.example.edu|/.env"}


def test_without_a_stand_in_h1_needs_every_alert_judged(tmp_path: Path) -> None:
    """M-003d: from D-044 on every delivered exposure is one the verifier
    passed, so the verifier cannot stand in for the analyst; an alert without
    an analyst verdict at the deadline makes H1 not testable, never a pass."""
    repo, data = _box(tmp_path)
    doc = _DOC.replace("the verifier's latest per exposure key stands in —",
                       "nothing stands in for it; an alert without one is unjudged —")
    (repo / "docs" / "measurements" / "M-009-test.md").write_text(doc)
    book = DashboardState(data, repo_root=repo).measurements
    before = book.scorecard("M-009", now=datetime(2026, 12, 2, tzinfo=UTC))["results"]["H1"]
    assert before["filled_in"] == 0 and before["judged"] == 1, "the analyst's one verdict only"
    assert before["state"] == "off_track" and before["stand_in"] is False  # 0/1 correct
    after = book.scorecard("M-009", now=datetime(2026, 12, 10, tzinfo=UTC))["results"]["H1"]
    assert after["state"] == "not_testable" and after["untriaged"] == 7
    assert "analyst's verdict by the deadline" in after["figure"]
    # The same box under M-003c's rule fills in from the verifier and fails.
    assert _book(tmp_path / "standin").scorecard(
        "M-009", now=datetime(2026, 12, 10, tzinfo=UTC))["results"]["H1"]["state"] == "fail"


def test_the_routes_serve_the_scorecard(tmp_path: Path) -> None:
    repo, data = _box(tmp_path)
    httpd = build_server(DashboardState(data, repo_root=repo), host="127.0.0.1", port=0)
    serve_in_thread(httpd)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/api/measurements/M-009", timeout=5) as r:
            card = json.loads(r.read())
        assert card["id"] == "M-009" and card["deadline"].startswith("2026-12-06")
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(base + "/api/measurements/M-404", timeout=5)
        assert err.value.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()
