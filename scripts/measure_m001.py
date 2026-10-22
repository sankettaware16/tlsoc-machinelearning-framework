#!/usr/bin/env python3
"""Compute M-001's numbers (docs/measurements/M-001-progressive-7d.md).

Committed before the window opened; the rules live in the measurement doc and
this file implements them to the letter. Read-only.

    python3 scripts/measure_m001.py --data data \
        --start 2026-10-23T00:00:00+05:30 --end 2026-10-30T00:00:00+05:30 \
        --tz Asia/Kolkata
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

QUEUE_CAP = 3  # H1: the spec's FP budget, alerts per server per day


def rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def queued(row: dict) -> bool:
    """Reached the queue before the budget cap: delivered, or digested *for budget*."""
    return row.get("disposition") == "delivered" or (
        row.get("disposition") == "digested" and row.get("digest_reason") == "budget")


def evaluate(scores: list[dict], runtime_log: str, start: datetime, end: datetime,
             tz: ZoneInfo) -> dict:
    window = [r for r in scores
              if start <= datetime.fromisoformat(r["window_end"]) < end]
    days: dict[str, Counter] = defaultdict(Counter)
    for r in window:
        day = datetime.fromisoformat(r["window_end"]).astimezone(tz).date().isoformat()
        server = r["entity"].split("|")[0]
        days[(day, server)]["fires"] += 1
        days[(day, server)]["queued"] += int(queued(r))
        days[(day, server)]["delivered"] += int(r.get("disposition") == "delivered")
    all_days = []
    d = start.astimezone(tz).date()
    while datetime.combine(d, datetime.min.time(), tz) < end:
        all_days.append(d.isoformat())
        d += timedelta(days=1)
    servers = sorted({s for _, s in days}) or ["logserver"]
    per_day = [{"day": day, "server": srv, **{k: days[(day, srv)][k]
                                               for k in ("fires", "queued", "delivered")}}
               for day in all_days for srv in servers]
    h1_days_ok = sum(1 for p in per_day if p["queued"] <= QUEUE_CAP)

    escalated = [r for r in window if r.get("escalated_by") == "finding"]
    h2_ok = all(queued(r) for r in escalated)

    bursts = [r for r in window if r.get("episode_windows") == 1
              and r.get("disposition") == "digested" and r.get("digest_reason") == "candidate"]
    singles = [r for r in window if r.get("episode_windows") == 1
               and not r.get("escalated_by") and r.get("disposition") != "folded"]
    h3_ok = all(r.get("stage") for r in bursts) and len(bursts) == len(singles)

    crashes = [line for line in runtime_log.splitlines()
               if line.startswith("[watchdog]") and "runtime not running" in line
               and start <= datetime.fromisoformat(line.split()[1]) < end]
    tracebacks = runtime_log.count("Traceback (most recent call last)")

    return {
        "window": [start.isoformat(), end.isoformat()],
        "fires": len(window),
        "per_day": per_day,
        "H1": {"rule": f"queued <= {QUEUE_CAP}/day/server on >= 5 of {len(per_day)} days",
               "days_ok": h1_days_ok,
               "verdict": ("not testable" if len(per_day) < 7
                           else "PASS" if h1_days_ok >= 5 else "FAIL")},
        "H2": {"rule": "every fire escalated by a finding reached the queue",
               "escalated": len(escalated),
               "verdict": "not testable" if not escalated else ("PASS" if h2_ok else "FAIL")},
        "H3": {"rule": "every one-window fire is a digested candidate with its stage",
               "one_window_fires": len(singles), "digested_candidates": len(bursts),
               "verdict": "not testable" if not singles else ("PASS" if h3_ok else "FAIL")},
        "H4": {"rule": "0 restarts not caused by the operator, 0 tracebacks",
               "watchdog_restarts": len(crashes), "tracebacks": tracebacks,
               "verdict": "PASS" if not crashes and not tracebacks else "FAIL"},
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
        log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else "",
        datetime.fromisoformat(args.start), datetime.fromisoformat(args.end), ZoneInfo(args.tz))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
