"""M-001's metric must measure what its hypotheses name, and every hypothesis
must be able to fail (advisory review P1; adversarial review 2026-10-22 C3,
C12, C13, C16)."""

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
AFTER = datetime(2026, 10, 31, tzinfo=IST)
ENTITY = "logserver|1.2.3.4|h"


def _row(when: str, disposition: str, **kw) -> dict:
    return {"window_end": when, "entity": ENTITY, "disposition": disposition, **kw}


def _every_day(extra: list[dict] = ()) -> list[dict]:
    """One harmless candidate per day, so no day is missing from the log."""
    rows = [_row(f"2026-10-{d}T06:00:00+00:00", "digested", digest_reason="candidate",
                 episode_windows=1, stage="low") for d in range(23, 30)]
    return rows + list(extra)


def _digest_for(rows: list[dict]) -> list[dict]:
    return [{"entity": r["entity"], "@timestamp": r["window_end"],
             "reason": "progressive candidate (low, 1 window(s)) — below the queue"}
            for r in rows if r.get("digest_reason") == "candidate"]


def _eval(rows, digest=None, log="", now=AFTER):
    return m.evaluate(rows, _digest_for(rows) if digest is None else digest, log,
                      START, END, IST, now=now)


def test_over_budget_digests_count_as_queued_and_candidates_do_not() -> None:
    day = "2026-10-24T06:00:00+00:00"
    rows = _every_day([_row(day, "delivered", episode_windows=6, stage="high")] * 3
                      + [_row(day, "digested", digest_reason="budget", episode_windows=6)] * 2)
    r = _eval(rows)
    oct24 = next(p for p in r["per_day"] if p["day"] == "2026-10-24")
    assert oct24["queued"] == 5 and oct24["delivered"] == 3
    assert r["H1"]["days_ok"] == 6 and r["H1"]["verdict"] == "PASS"


def test_h1_is_not_testable_before_the_window_closes_or_with_a_missing_day() -> None:
    assert _eval(_every_day(), now=datetime(2026, 10, 26, tzinfo=IST))["H1"]["verdict"] \
        .startswith("not testable: the window")
    gap = [r for r in _every_day() if not r["window_end"].startswith("2026-10-25")]
    assert "2026-10-25" in _eval(gap)["H1"]["verdict"], "an empty day is not a passing day"


def test_h1_fails_when_the_queue_runs_over_on_three_days() -> None:
    over = [_row(f"2026-10-{d}T06:00:00+00:00", "delivered", episode_windows=6)
            for d in (24, 25, 26) for _ in range(4)]
    assert _eval(_every_day(over))["H1"]["verdict"] == "FAIL"


def test_h2_fails_for_a_finding_that_did_not_reach_the_queue() -> None:
    folded_away = _row("2026-10-24T14:45:00+00:00", "folded", findings=1,
                       folded_by="episode", into_finding=False)
    assert _eval(_every_day([folded_away]))["H2"]["verdict"] == "FAIL"
    kept = _row("2026-10-24T14:50:00+00:00", "folded", findings=1,
                folded_by="episode", into_finding=True)
    queued = _row("2026-10-24T14:45:00+00:00", "delivered", findings=1)
    assert _eval(_every_day([queued, kept]))["H2"]["verdict"] == "PASS"
    assert _eval(_every_day())["H2"]["verdict"].startswith("not testable")


def test_h3_cross_checks_the_digest_file() -> None:
    rows = _every_day()
    assert _eval(rows)["H3"]["verdict"] == "PASS"
    assert _eval(rows, digest=[])["H3"]["verdict"] == "FAIL", "candidates absent from the digest"


def test_h4_counts_only_restarts_and_tracebacks_inside_the_window() -> None:
    before = ("2026-10-20T10:00:00+00:00 [runtime] stopped\nTraceback (most recent call last):\n"
              "[watchdog] 2026-10-20T03:00:00+05:30 runtime not running; restarting\n")
    assert _eval(_every_day(), log=before)["H4"]["verdict"] == "PASS"
    inside = before + ("2026-10-25T10:00:00+00:00 [runtime] resumed\n"
                       "Traceback (most recent call last):\n")
    assert _eval(_every_day(), log=inside)["H4"]["tracebacks"] == 1
    crash = before + "[watchdog] 2026-10-25T03:00:00+05:30 runtime not running; restarting\n"
    assert _eval(_every_day(), log=crash)["H4"]["verdict"] == "FAIL"
