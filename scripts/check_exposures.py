#!/usr/bin/env python3
"""Re-run the exposure rule offline and compare it with what was delivered live.

The exposure alert (D-040) depends on no model: a 2xx with a body to a
sensitive kind, minus the site's catch-all pages, folded per (site, root).
So the whole decision can be replayed from the log lines alone, through the
same ``WindowFeatureBuilder`` and ``ExposureTracker`` the runtime uses, and
every exposure it finds checked against the live records. This is M-003's
H3 (completeness), and it measures a rule change on real traffic before it is
deployed: run it once per checkout.

Input is either the parser's ECS JSON or the log server's raw nginx lines
(``<ts> <host> vhnginx_access: <site> <ip> ...``), gzipped or not: the raw
files outlive Elasticsearch, which keeps about five days.

    python scripts/check_exposures.py --bundle data/models/web_recon/<version> \\
        --live data --start 2026-11-03T00:00:00+05:30 --end 2026-11-10T00:00:00+05:30 \\
        data/corpus/m003/nginx.log-*.gz
"""

from __future__ import annotations

import argparse
import builtins
import functools
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc_ml.baseline.profile import EnvironmentProfile  # noqa: E402
from soc_ml.core.contracts import Event, Observer  # noqa: E402
from soc_ml.features.exposure import KINDS, ExposureTracker  # noqa: E402
from soc_ml.features.window_features import WindowFeatureBuilder  # noqa: E402

print = functools.partial(builtins.print, flush=True)  # noqa: A001

#: The log server's raw access line, as the parser reads it.
_RAW = re.compile(
    r'^\S+ \S+ (?P<prog>\S+): (?P<site>\S+) (?P<ip>\S+) "[^"]*" \S+ \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')
#: Every event reports under one server on prod (see the deployment notes).
_SERVER = "logserver"


def _raw_event(line: str) -> Event | None:
    m = _RAW.match(line)
    if m is None or not m["prog"].endswith("_access"):
        return None
    parts = m["req"].split(" ")
    if len(parts) < 2:
        return None
    target = parts[1]
    if target.startswith(("http://", "https://")):
        u = urlsplit(target)
        path, query = u.path or "/", u.query or None
    else:
        path, _, query = target.partition("?")
        query = query or None
    ref = m["ref"]
    return Event(
        timestamp=datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z"),
        observer=Observer(server=_SERVER), source_ip=m["ip"],
        http_method=parts[0], http_referrer=None if ref == "-" else ref,
        status_code=int(m["status"]),
        body_bytes=None if m["bytes"] == "-" else int(m["bytes"]),
        url_path=path, url_query=query, url_domain=m["site"].lower(),
        user_agent=m["ua"], event_type="access", original=line.rstrip("\n"))


def events(paths: list[str]):
    for p in paths:
        opener = gzip.open if p.endswith(".gz") else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("{"):
                    try:
                        ev = Event.from_ecs(json.loads(line))
                    except (ValueError, TypeError):
                        continue
                    if not ev.is_request:
                        continue
                else:
                    ev = _raw_event(line)
                    if ev is None:
                        continue
                yield ev


def replay(paths: list[str], profile: EnvironmentProfile, allow: tuple[str, ...]):
    """Yield (window end, client, exposure, decision, alert id) as the runtime would."""
    builder = WindowFeatureBuilder(profile)
    tracker = ExposureTracker()
    n = 0

    def handle(results):
        for r in results:
            for exp in r.evidence.get("exposures") or []:
                if any(fnmatchcase(exp["key"], pat) for pat in allow):
                    continue
                kind = KINDS.get(exp["kind"])
                if kind is None or not kind.alert:
                    continue
                at = r.vector.computed_at
                ip = r.vector.entity.ip
                action, alert_id = tracker.decide(exp["key"], f"{exp['key']}@{at}", at, ip)
                yield at, ip, exp, action, alert_id

    for ev in events(paths):
        n += 1
        if n % 5_000_000 == 0:
            print(f"  ... {n:,} events, at {ev.timestamp.isoformat()}", file=sys.stderr)
        yield from handle(builder.add(ev))
    yield from handle(builder.flush())
    print(f"  {n:,} events replayed", file=sys.stderr)


def _live(data: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    """Live exposure records by key, and live exposure alerts by id."""
    by_key: dict[str, list[dict]] = defaultdict(list)
    p = data / "state" / "web_recon_exposures.ndjson"
    if p.exists():
        for line in p.open(encoding="utf-8"):
            if line.strip():
                row = json.loads(line)
                by_key[row["key"]].append(row)
    alerts = {}
    p = data / "alerts" / "web_recon.ndjson"
    if p.exists():
        for line in p.open(encoding="utf-8"):
            if line.strip():
                doc = json.loads(line)
                if doc["alert"].get("category") == "exposure":
                    alerts[doc["alert"]["id"]] = doc
    return by_key, alerts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", help="raw nginx lines or ECS JSON, .gz or plain, in time order")
    ap.add_argument("--bundle", required=True, help="web_recon bundle dir (for its profile)")
    ap.add_argument("--live", help="data root of the live run, to compare against")
    ap.add_argument("--start", required=True, help="ISO time, counted from (replay warms up before)")
    ap.add_argument("--end", required=True)
    ap.add_argument("--allow", action="append", default=[], help="exposure.allow pattern")
    ap.add_argument("--tz", default="Asia/Kolkata", help="day boundaries for per-day counts")
    ap.add_argument("--json", help="write every offline alert here")
    args = ap.parse_args()

    start, end = datetime.fromisoformat(args.start), datetime.fromisoformat(args.end)
    tz = ZoneInfo(args.tz)
    profile = EnvironmentProfile.load(Path(args.bundle) / "profile.json")

    offline: list[dict] = []
    folded: Counter = Counter()
    for at, ip, exp, action, _ in replay(args.files, profile, tuple(args.allow)):
        if not start <= at < end:
            continue
        if action == "deliver":
            offline.append({"at": at.isoformat(), "day": at.astimezone(tz).date().isoformat(),
                            "client": ip, "key": exp["key"], "kind": exp["kind"],
                            "files": [(f["path"], f["status"], f["bytes"]) for f in exp["files"]]})
        else:
            folded[exp["key"]] += 1

    per_day = Counter(o["day"] for o in offline)
    print(f"offline: {len(offline)} exposure deliveries, {sum(folded.values())} folded downloads")
    for day in sorted(per_day):
        print(f"  {day}: {per_day[day]}")
    for o in offline:
        print(f"  {o['at'][:16]} {o['kind']:<13} {o['key']}  ({o['client']}, "
              f"{len(o['files'])} file(s), first {o['files'][0][2]} B)")

    if args.live:
        by_key, alerts = _live(Path(args.live))
        # Development metadata is recorded live but never alerted: not compared.
        in_window = {k: [r for r in rows if start <= datetime.fromisoformat(r["@timestamp"]) < end
                         and getattr(KINDS.get(r["kind"]), "alert", False)]
                     for k, rows in by_key.items()}
        live_keys = {k for k, rows in in_window.items() if rows}
        missing = [o for o in offline if o["key"] not in by_key]
        print(f"\nlive: {len(live_keys)} exposure keys recorded in the window, "
              f"{len({i for rows in in_window.values() for r in rows for i in [r['alert_id']]} & set(alerts))} "
              "exposure alerts")
        print(f"H3 — offline exposures never recorded live: {len(missing)}")
        for o in missing:
            print(f"  MISSING {o['at'][:16]} {o['key']}")
        extra = sorted(live_keys - {o["key"] for o in offline} - set(folded))
        print(f"live exposure keys the offline rule does not find: {len(extra)}")
        for k in extra:
            print(f"  LIVE-ONLY {k}")

    if args.json:
        Path(args.json).write_text("\n".join(json.dumps(o) for o in offline) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
