"""M-001's metric must measure what its hypotheses name (advisory review, P1).

With --daily-budget 3 the *delivered* count is capped at 3 by construction, so
"delivered <= 3" would pass every day whatever happened. H1 counts what reached
the queue before the cap: delivered, or digested for budget.
"""

from __future__ import annotations

import importlib.util
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

spec = importlib.util.spec_from_file_location(
    "measure_m001", Path(__file__).resolve().parents[1] / "scripts" / "measure_m001.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
IST = ZoneInfo("Asia/Kolkata")
START = datetime(2026, 10, 23, tzinfo=IST)
END = datetime(2026, 10, 30, tzinfo=IST)


def _row(when: str, disposition: str, **kw) -> dict:
    return {"window_end": when, "entity": "logserver|1.2.3.4|h", "disposition": disposition, **kw}


def test_over_budget_digests_count_as_queued_and_candidates_do_not() -> None:
    day = "2026-10-24T06:00:00+00:00"
    scores = ([_row(day, "delivered", episode_windows=6, stage="high")] * 3
              + [_row(day, "digested", digest_reason="budget", episode_windows=6)] * 2
              + [_row(day, "digested", digest_reason="candidate", episode_windows=1,
                      stage="low")] * 50)
    r = m.evaluate(scores, "", START, END, IST)
    oct24 = next(p for p in r["per_day"] if p["day"] == "2026-10-24")
    assert oct24 == {"day": "2026-10-24", "server": "logserver",
                     "fires": 55, "queued": 5, "delivered": 3}
    assert r["H1"]["days_ok"] == 6, "the capped day is over the queue cap"
    assert r["H1"]["verdict"] == "PASS"
    assert r["H3"]["verdict"] == "PASS"


def test_days_are_local_and_the_window_is_seven_full_days() -> None:
    late = "2026-10-23T19:00:00+00:00"   # 00:30 IST on the 24th
    r = m.evaluate([_row(late, "delivered")], "", START, END, IST)
    assert [p["day"] for p in r["per_day"]][:2] == ["2026-10-23", "2026-10-24"]
    assert len(r["per_day"]) == 7
    assert next(p for p in r["per_day"] if p["day"] == "2026-10-24")["queued"] == 1


def test_an_escalation_that_did_not_reach_the_queue_fails_h2() -> None:
    r = m.evaluate([_row("2026-10-24T06:00:00+00:00", "digested", digest_reason="candidate",
                         escalated_by="finding")], "", START, END, IST)
    assert r["H2"]["verdict"] == "FAIL"


def test_a_watchdog_restart_inside_the_window_fails_h4() -> None:
    log = "[watchdog] 2026-10-25T03:00:00+05:30 runtime not running; restarting\n"
    assert m.evaluate([], log, START, END, IST)["H4"]["verdict"] == "FAIL"
    before = "[watchdog] 2026-10-20T03:00:00+05:30 runtime not running; restarting\n"
    assert m.evaluate([], before, START, END, IST)["H4"]["verdict"] == "PASS"
