#!/usr/bin/env python3
"""Compute M-001's numbers (docs/measurements/M-001-progressive-7d.md).

Committed before the window opened; the rules live in the measurement doc and
this file implements them to the letter. Read-only. Every hypothesis must be
able to fail: an adversarial review on 2026-10-22 found the first version could
not (missing days counted as passes, H2/H3 tested fields only the branch under
test writes, tracebacks outside the window counted). Those were fixed before
the window opened.

    python3 scripts/measure_m001.py --data data \\
        --start 2026-10-23T00:00:00+05:30 --end 2026-10-30T00:00:00+05:30 \\
        --tz Asia/Kolkata
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

QUEUE_CAP = 3  # H1: the spec's FP budget, alerts per server per day
_STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s")
_WATCHDOG = re.compile(r"^\[watchdog\] (\S+) ")


def rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def queued(row: dict) -> bool:
    """Reached the queue before the budget cap: delivered, or digested *for budget*."""
    return row.get("disposition") == "delivered" or (
        row.get("disposition") == "digested" and row.get("digest_reason") == "budget")


def _ts(text: str) -> datetime:
    t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def log_events(runtime_log: str, start: datetime, end: datetime) -> tuple[int, int]:
    """(watchdog runtime restarts, tracebacks) whose time falls in [start, end).

    A traceback carries no timestamp; it is placed at the last timestamped
    line before it (runtime lines are stamped since this measurement). One that
    precedes every timestamp cannot be placed and is not counted.
    """
    restarts = tracebacks = 0
    now: datetime | None = None
    for line in runtime_log.splitlines():
        m = _STAMP.match(line) or _WATCHDOG.match(line)
        if m:
            with contextlib.suppress(ValueError):
                now = _ts(m.group(1))
        inside = now is not None and start <= now < end
        if inside and line.startswith("[watchdog]") and "runtime not running" in line:
            restarts += 1
        if inside and line.startswith("Traceback (most recent call last)"):
            tracebacks += 1
    return restarts, tracebacks


def evaluate(scores: list[dict], digest: list[dict], runtime_log: str, start: datetime,
             end: datetime, tz: ZoneInfo, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    window = [r for r in scores if start <= _ts(r["window_end"]) < end]

    # ---- H1: queue volume per local day, before the cap ------------------ #
    days: dict[tuple[str, str], Counter] = defaultdict(Counter)
    rows_per_day: Counter = Counter()
    for r in window:
        day = _ts(r["window_end"]).astimezone(tz).date().isoformat()
        server = r["entity"].split("|")[0]
        rows_per_day[day] += 1
        days[(day, server)]["fires"] += 1
        days[(day, server)]["queued"] += int(queued(r))
        days[(day, server)]["delivered"] += int(r.get("disposition") == "delivered")
    all_days, d = [], start.astimezone(tz).date()
    while datetime.combine(d, datetime.min.time(), tz) < end:
        all_days.append(d.isoformat())
        d += timedelta(days=1)
    servers = sorted({s for _, s in days}) or ["logserver"]
    per_day = [{"day": day, "server": srv, **{k: days[(day, srv)][k]
                                               for k in ("fires", "queued", "delivered")}}
               for day in all_days for srv in servers]
    missing = [day for day in all_days if rows_per_day[day] == 0]
    h1_days_ok = sum(1 for p in per_day if p["queued"] <= QUEUE_CAP)
    if now < end:
        h1_verdict = "not testable: the window has not closed"
    elif missing:
        h1_verdict = f"not testable: score log has no rows on {', '.join(missing)}"
    else:
        h1_verdict = "PASS" if h1_days_ok >= 5 else "FAIL"

    # ---- H2: every fire that carried a finding reached the queue ----------- #
    # The population is chosen by the score row's own `findings` count, which
    # is recorded before and whatever delivery decides.
    with_findings = [r for r in window if (r.get("findings") or 0) > 0]
    lost = [r for r in with_findings
            if not (queued(r) or (r.get("disposition") == "folded" and r.get("into_finding")))]

    # ---- H3: every one-window candidate is in the digest with its stage ----- #
    # Checked against the digest file itself, not against the field the
    # runtime writes for the same decision.
    in_digest = {(d["entity"], d["@timestamp"]) for d in digest
                 if "progressive candidate (" in (d.get("reason") or "")}
    singles = [r for r in window if r.get("episode_windows") == 1
               and not (r.get("findings") or 0) and r.get("disposition") != "folded"
               and r.get("disposition") != "suppressed"]
    h3_missing = [r for r in singles
                  if r.get("disposition") != "digested" or not r.get("stage")
                  or (r["entity"], r["window_end"]) not in in_digest]

    restarts, tracebacks = log_events(runtime_log, start, end)
    return {
        "window": [start.isoformat(), end.isoformat()],
        "fires": len(window),
        "per_day": per_day,
        "H1": {"rule": f"queued <= {QUEUE_CAP}/day/server on >= 5 of {len(all_days)} days",
               "days_ok": h1_days_ok, "verdict": h1_verdict},
        "H2": {"rule": "every fire whose score row records findings was queued, or folded "
                       "into an alert that itself carried a finding",
               "with_findings": len(with_findings), "lost": len(lost),
               "verdict": ("not testable: no fire carried a finding" if not with_findings
                           else "PASS" if not lost else "FAIL")},
        "H3": {"rule": "every one-window fire without a finding is a digested candidate with "
                       "its stage, and is in the digest file",
               "one_window_fires": len(singles), "missing": len(h3_missing),
               "verdict": ("not testable: no one-window fire" if not singles
                           else "PASS" if not h3_missing else "FAIL")},
        "H4": {"rule": "0 watchdog restarts and 0 tracebacks inside the window",
               "watchdog_restarts": restarts, "tracebacks": tracebacks,
               "verdict": ("not testable: the window has not closed" if now < end
                           else "PASS" if not restarts and not tracebacks else "FAIL")},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--tz", default="Asia/Kolkata")
    args = ap.parse_args()
    data = Path(args.data)
    log_path = data / "state" / "runtime.log"
    result = evaluate(
        rows(data / "state" / "web_recon_scores.ndjson"),
        rows(data / "state" / "web_recon_digest.ndjson"),
        log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else "",
        _ts(args.start), _ts(args.end), ZoneInfo(args.tz))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
