#!/usr/bin/env python3
"""Replay recorded web_recon fires through the delivery layer's Progression.

Every live fire is in ``<data>/state/<slug>_scores.ndjson`` with its entity,
window end, and finding count. Progression's decisions depend on nothing else
(severity only caps), so replaying those rows in file order — the order the
runtime handled them — through ``Progression`` reproduces what reached the
queue, and lets a change to Progression be measured on real traffic without
deploying it.

The replay must first prove itself: run against the *serving* code, its queued
counts must equal the ones the score log recorded (``--check``). A replay that
cannot reproduce the past is not evidence about the future.

    python scripts/replay_progression.py --data data \\
        --start 2026-10-23T00:00:00+05:30 --end 2026-10-30T00:00:00+05:30 --check
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_ml.core.contracts import Alert, EntityKey, Severity  # noqa: E402
from soc_ml.fusion.progressive import Progression  # noqa: E402

#: Episodes end after 10 quiet minutes and "once per day" needs the day's
#: earlier queue, so state is warmed from the day before the range.
WARMUP = timedelta(days=1)


def _recorded_queued(row: dict) -> bool:
    return row.get("disposition") == "delivered" or (
        row.get("disposition") == "digested" and row.get("digest_reason") == "budget")


def replay(scores: Path, start: datetime, end: datetime, tz: ZoneInfo) -> dict:
    prog = Progression(tz=tz)
    per_day: dict[str, Counter] = defaultdict(Counter)
    folds: list[dict] = []
    with scores.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not row.get("fired") or "window_end" not in row:
                continue
            ts = datetime.fromisoformat(row["window_end"])
            if ts < start - WARMUP or ts >= end:
                continue
            # Suppressed alerts never reach Progression in the runtime.
            if row.get("disposition") == "suppressed":
                continue
            server, ip, ua = row["entity"].split("|")
            alert = Alert(
                id=f"r{n}", timestamp=ts, usecase="web_recon",
                entity=EntityKey(server=server, ip=ip, ua_hash=ua),
                severity=Severity.HIGH, severity_score=80, confidence=1.0,
                links={"findings": [{}] * int(row.get("findings") or 0)},
            )
            step = prog.decide(alert)
            if ts < start:
                continue
            day = ts.astimezone(tz).date().isoformat()
            c = per_day[day]
            c["fires"] += 1
            c["queued"] += step.action == "deliver"
            c["recorded_queued"] += _recorded_queued(row)
            if step.action == "fold":
                c[f"folded_by_{step.folded_by}"] += 1
                if step.folded_by == "campaign":
                    folds.append({"window_end": row["window_end"], "entity": row["entity"],
                                  "into": step.folded_into})
    return {"per_day": {d: dict(c) for d, c in sorted(per_day.items())},
            "campaign_folds": len(folds)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", default="data")
    ap.add_argument("--slug", default="web_recon")
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--tz", default="Asia/Kolkata")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 unless replayed queued == recorded queued on every day")
    args = ap.parse_args()

    out = replay(Path(args.data) / "state" / f"{args.slug}_scores.ndjson",
                 datetime.fromisoformat(args.start), datetime.fromisoformat(args.end),
                 ZoneInfo(args.tz))
    print(json.dumps(out, indent=2))
    if args.check:
        bad = {d: c for d, c in out["per_day"].items()
               if c.get("queued", 0) != c.get("recorded_queued", 0)}
        if bad:
            print(f"CHECK FAILED: replay does not reproduce the recorded queue on {sorted(bad)}",
                  file=sys.stderr)
            return 1
        print("check: replay reproduces the recorded queue on every day", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
