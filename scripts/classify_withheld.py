#!/usr/bin/env python3
"""Put every withheld exposure of a window in one class, with its evidence from the raw log.

H5 of M-003c ("nothing real is held back"): a download the runtime checked and
did not alert must be a page, and the verdict has to say why for each one. A
withheld exposure is a download record with a verdict and ``new`` false: an
ordinary web page at the URL (D-042), a 4xx or a redirect now (D-044). The
verdict's own evidence is one fetch minutes later; this reads what the site
did in the log around the download, and writes it down per key so the verdict
is a matter of reading the table, not of re-reading 20M lines.

The classes, in the order checked (first match wins):

* (a) a size the site returned for another, ordinary path — the catch-all;
* (b) a 206 slice;
* (c) a page whose size moves with the path: another path in the directory
  (or, when the directory has no other answers, under the same first segment)
  within 1% of the withheld size and not equal to it;
* (e) for blocked_now / redirected only: another client got a non-2xx (not a
  304: that client holds a copy) for the path inside the window, or the same
  client got the same size for another sensitive path — prod, 18 Nov: one
  scanner got exactly 2,102 B with 200 for ``/.env.production`` and
  ``/.env.save``, a browser 404, the SOC's check 404 four minutes later. Two
  sensitive paths of one size from one client are this class's evidence, not
  (a)'s, which is why (a) counts ordinary paths only. Sensitive is what the
  detector's kinds say (``exposure.classify``), plus any dotfile; the SOC's
  own verifier is never "another client", its answer is the verdict itself;
* (d) none of these: fetch at the verdict, in full up to 64 KB, and read.

Raw lines only (the log server's ``<ts> <host> vhnginx_access: <site> <ip> ...``,
gzipped or not, in time order); error-channel lines are not requests and are
skipped. Lines from the day before the window count too, as context. The
corpus is streamed once, with state only for the withheld sites and only for
what the classes ask about (the withheld sizes, directories, paths and
clients); every table that fills per other path or per other client keeps its
first PATHS_PER_SIZE entries, which is all a reason ever quotes, so the state
is bounded by the withheld set, not by the corpus.

    python scripts/classify_withheld.py --live data \\
        --start 2026-11-17T00:00:00+05:30 --end 2026-11-24T00:00:00+05:30 \\
        --tz Asia/Kolkata --json data/reports/m003c-withheld.ndjson \\
        data/corpus/m003c/nginx.log-*.gz
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from check_exposures import _RAW  # noqa: E402 — the parser's raw access line

from soc_ml.features.exposure import classify as exposure_kind  # noqa: E402

CONTEXT = timedelta(days=1)
PATHS_PER_SIZE = 64
NEAR = 0.01
FETCH = "FETCH AT THE VERDICT (up to 64 KB) and read"
#: What ``exposure.verify()`` sends: the SOC's own check, never (e)'s "another client".
_VERIFIER_UA = "tlsoc-ml-exposure-verifier"
_CLIENT_VERDICTS = ("blocked_now", "redirected")
CLASSES = {
    "a": "a size the site returned for another path",
    "b": "a 206 slice",
    "c": "a page whose size moves with the path",
    "e": "answered per client (D-044)",
    "d": "none of these",
}


def _sensitive(path: str) -> bool:
    """The detector's kinds are the specification of sensitive; any dotfile counts too."""
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return last.startswith(".") or exposure_kind(path) is not None


def _directory(path: str) -> str:
    """``/search/.env`` -> ``/search/``; ``/.env`` -> ``/``."""
    return path[: path.rstrip("/").rfind("/") + 1] or "/"


def _segment(path: str) -> str:
    """``/beta/app/.env`` -> ``/beta/``: the route, when the directory says nothing."""
    first = path.lstrip("/").split("/", 1)[0]
    return f"/{first}/" if first else "/"


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _when(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


# -- step 1: the withheld set -------------------------------------------------

@dataclass
class Withheld:
    key: str
    site: str
    root: str
    kind: str
    domain: str | None
    first: datetime
    last: datetime
    downloads: int = 0
    clients: set[str] = field(default_factory=set)
    #: (path, status, bytes) of the recorded files, in first-seen order.
    files: dict[tuple[str, int, int | None], None] = field(default_factory=dict)
    verdicts: Counter = field(default_factory=Counter)
    check: dict | None = None

    @property
    def verdict(self) -> str:
        return "/".join(sorted(self.verdicts))

    @property
    def paths(self) -> set[str]:
        return {f[0] for f in self.files if f[0]} | ({self.root} if self.root else set())

    @property
    def sizes(self) -> set[int]:
        """Full 2xx bodies; a 206 slice's length says nothing about the file."""
        return {f[2] for f in self.files if f[2] and 200 <= f[1] < 300 and f[1] != 206}

    def own(self, path: str) -> bool:
        """The key's own path: the root, a recorded file, or anything under a directory root."""
        return path in self.paths or bool(self.root and self.root.endswith("/")
                                          and path.startswith(self.root))


def withheld(data: Path, start: datetime, end: datetime) -> list[Withheld]:
    """Download records in the window with a verdict and ``new`` false, by key."""
    groups: dict[str, Withheld] = {}
    for row in _rows(data / "state" / "web_recon_exposures.ndjson"):
        if "verdict" not in row or row.get("new") or not row.get("key"):
            continue
        at = _when(row.get("@timestamp"))
        if at is None or not start <= at < end:
            continue
        w = groups.get(row["key"])
        if w is None:
            site, _, root = row["key"].partition("|")
            w = groups[row["key"]] = Withheld(
                row["key"], site.lower(), row.get("root") or root, row.get("kind", "?"),
                row.get("domain"), at, at)
        w.first, w.last = min(w.first, at), max(w.last, at)
        w.downloads += 1
        w.clients.add(str(row.get("client")))
        w.verdicts[str(row["verdict"])] += 1
        for f in row.get("files") or []:
            w.files.setdefault((f.get("path"), int(f.get("status") or 0), f.get("bytes")))
    checks: dict[str, list[dict]] = defaultdict(list)
    for c in _rows(data / "state" / "web_recon_verifications.ndjson"):
        if c.get("key") in groups:
            checks[c["key"]].append(c)
    for w in groups.values():
        same = [c for c in checks[w.key] if c.get("verdict") in w.verdicts] or checks[w.key]
        if same:
            c = max(same, key=lambda c: str(c.get("checked_at")))
            w.check = {k: c.get(k) for k in ("verdict", "status", "content_type", "checked_at")}
            w.check["by"] = c.get("by") or "console"
    return sorted(groups.values(), key=lambda w: w.first)


# -- step 2: one pass over the raw log ----------------------------------------

@dataclass
class _PathStats:
    classes: Counter = field(default_factory=Counter)
    #: client -> (status, time) of its first non-2xx inside the window; a 304 is not
    #: one (that client holds a copy). PATHS_PER_SIZE clients kept.
    non2xx: dict[str, tuple[int, datetime]] = field(default_factory=dict)
    partial: set[str] = field(default_factory=set)  # withheld clients that got a 206


@dataclass
class _Site:
    """What the classes ask of one site; everything keyed by what is withheld there."""
    sizes: set[int]
    dirs: set[str]
    segments: set[str]
    paths: set[str]
    clients: set[str]
    #: size -> path -> (time, count): every 2xx of a withheld size (PATHS_PER_SIZE paths kept).
    same_size: dict[int, dict[str, tuple[datetime, int]]] = field(
        default_factory=lambda: defaultdict(dict))
    same_size_n: Counter = field(default_factory=Counter)
    #: (directory, withheld size) -> path -> (size, time): 2xx within NEAR of it.
    near_dir: dict[tuple[str, int], dict[str, tuple[int, datetime]]] = field(
        default_factory=lambda: defaultdict(dict))
    near_seg: dict[tuple[str, int], dict[str, tuple[int, datetime]]] = field(
        default_factory=lambda: defaultdict(dict))
    dir_answers: Counter = field(default_factory=Counter)  # 2xx per withheld directory
    path_stats: dict[str, _PathStats] = field(default_factory=lambda: defaultdict(_PathStats))
    #: (client, size) -> sensitive path -> time, for the withheld clients and sizes
    #: (PATHS_PER_SIZE paths kept).
    client_size: dict[tuple[str, int], dict[str, datetime]] = field(
        default_factory=lambda: defaultdict(dict))

    @classmethod
    def for_keys(cls, keys: list[Withheld]) -> _Site:
        paths = {p for w in keys for p in w.paths}
        return cls(sizes={s for w in keys for s in w.sizes},
                   dirs={_directory(p) for p in paths},
                   segments={_segment(p) for p in paths},
                   paths=paths, clients={c for w in keys for c in w.clients})

    def see(self, path: str, status: int, size: int | None, client: str, at: datetime,
            in_window: bool) -> None:
        cls = f"{status // 100}xx"
        if path in self.paths:
            st = self.path_stats[path]
            st.classes[cls] += 1
            if status == 206 and client in self.clients:
                st.partial.add(client)
            if cls != "2xx" and status != 304 and in_window and len(st.non2xx) < PATHS_PER_SIZE:
                st.non2xx.setdefault(client, (status, at))
        # A slice's length is the range asked for, not a body: (b) has what it needs above.
        if cls != "2xx" or status == 206 or not size:
            return
        if size in self.sizes:
            bucket = self.same_size[size]
            self.same_size_n[size] += 1
            if path in bucket:
                bucket[path] = (bucket[path][0], bucket[path][1] + 1)
            elif len(bucket) < PATHS_PER_SIZE:
                bucket[path] = (at, 1)
            if client in self.clients and _sensitive(path):
                seen = self.client_size[(client, size)]
                if len(seen) < PATHS_PER_SIZE:
                    seen.setdefault(path, at)
        d = _directory(path)
        if d in self.dirs:
            self.dir_answers[d] += 1
            for want in self.sizes:
                if abs(size - want) <= want * NEAR:
                    near = self.near_dir[(d, want)]
                    if path not in near and len(near) < PATHS_PER_SIZE:
                        near[path] = (size, at)
        s = _segment(path)
        if s in self.segments:
            for want in self.sizes:
                if abs(size - want) <= want * NEAR:
                    near = self.near_seg[(s, want)]
                    if path not in near and len(near) < PATHS_PER_SIZE:
                        near[path] = (size, at)


def stream(files: list[str], sites: dict[str, _Site], start: datetime,
           end: datetime) -> dict[str, int]:
    """One pass; only lines of the withheld sites inside [start - 1 day, end) are parsed."""
    lower = start - CONTEXT
    n = Counter()
    for p in files:
        opener = gzip.open if p.endswith(".gz") else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                n["lines"] += 1
                head = line.split(" ", 4)
                if len(head) < 5 or not head[2].endswith("_access:"):
                    n["not_access"] += 1
                    continue
                site = sites.get(head[3].lower())
                if site is None:
                    continue
                m = _RAW.match(line)
                if m is None:
                    n["unparsed"] += 1
                    continue
                parts = m["req"].split(" ")
                if len(parts) < 2:
                    n["unparsed"] += 1
                    continue
                at = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
                if not lower <= at < end:
                    continue
                if m["ua"].startswith(_VERIFIER_UA):
                    continue  # the SOC's own check: its answer is the verdict, not the site's
                n["counted"] += 1
                target = parts[1]
                if target.startswith(("http://", "https://")):
                    target = "/" + target.split("/", 3)[-1] if target.count("/") >= 3 else "/"
                path = target.partition("?")[0].partition("#")[0] or "/"
                site.see(path, int(m["status"]), None if m["bytes"] == "-" else int(m["bytes"]),
                         m["ip"], at, at >= start)
    return dict(n)


# -- step 3: the classes ------------------------------------------------------

def _fmt(at: datetime, tz: ZoneInfo) -> str:
    return at.astimezone(tz).strftime("%d %b %H:%M")


def classify(w: Withheld, site: _Site, tz: ZoneInfo) -> tuple[str, str, dict]:
    """(class, reason, evidence) for one withheld key, first match wins."""
    sizes = sorted(w.sizes)
    # (a) the same size for an ordinary path — any client, context day included.
    hits = {}
    for size in sizes:
        others = [(p, t, c) for p, (t, c) in site.same_size.get(size, {}).items()
                  if not w.own(p) and not _sensitive(p)]
        if not others:
            break
        hits[size] = sorted(others, key=lambda x: x[1])
    if sizes and len(hits) == len(sizes):
        parts = []
        for size, others in hits.items():
            p, t, c = others[0]
            more = len(others) - 1
            parts.append(f"{size} B also for {p} ({_fmt(t, tz)}, {c}x"
                         + (f"; {more} other path(s)" if more else "")
                         + f"; {site.same_size_n[size]} answers of this size)")
        return "a", "; ".join(parts), {"same_size": {
            str(s): [p for p, _, _ in o[:8]] for s, o in hits.items()}}
    # (b) a slice.
    sliced = [f[0] for f in w.files if f[1] == 206]
    sliced += [p for p in sorted(w.paths) if p not in sliced and p in site.path_stats
               and site.path_stats[p].partial & w.clients]
    if sliced:
        return "b", f"206 for {', '.join(sorted(sliced))}", {"partial": sorted(sliced)}
    # (c) a sibling within 1%: the directory first, the route when it is empty.
    near = {}
    for size in sizes:
        found = None
        for p in w.paths:
            d = _directory(p)
            own_2xx = sum(site.path_stats[q].classes["2xx"] for q in w.paths
                          if _directory(q) == d and q in site.path_stats)
            pool = site.near_dir.get((d, size), {})
            where = f"directory {d}"
            if site.dir_answers[d] - own_2xx <= 0:  # no other answers there: the route
                pool = site.near_seg.get((_segment(p), size), {})
                where = f"route {_segment(p)}"
            # An equal size does not move with the path: that is (a)'s question, and
            # (a) has already said the path was not ordinary (prod, 19 Nov: /.env.save).
            cands = [(q, s, t) for q, (s, t) in pool.items() if not w.own(q) and s != size]
            if cands:
                q, s, t = min(cands, key=lambda x: (_sensitive(x[0]), abs(x[1] - size)))
                found = (q, s, t, where, len(cands))
                break
        if found is None:
            break
        near[size] = found
    if sizes and len(near) == len(sizes):
        parts = [f"{q} {s} B is {abs(s - size) / size:.2%} from {size} B "
                 f"({where}, {_fmt(t, tz)}" + (f", {n - 1} more within 1%" if n > 1 else "") + ")"
                 for size, (q, s, t, where, n) in near.items()]
        return "c", "; ".join(parts), {
            "near": {str(s): [v[0], v[1], v[3]] for s, v in near.items()}}
    # (e) answered per client: only when the check itself got a 4xx or 3xx.
    if any(v in _CLIENT_VERDICTS for v in w.verdicts):
        for p in sorted(w.paths):
            st = site.path_stats.get(p)
            if st is None:
                continue
            for client, (status, t) in sorted(st.non2xx.items(), key=lambda x: x[1][1]):
                if client not in w.clients:
                    return ("e", f"another client {client} got {status} for {p} at {_fmt(t, tz)} "
                                 f"inside the window", {"other_client": [client, status, p]})
        for client in sorted(w.clients):
            for size in sizes:
                others = {p: t for p, t in site.client_size.get((client, size), {}).items()
                          if not w.own(p)}
                if others:
                    p, t = min(others.items(), key=lambda x: x[1])
                    return ("e", f"same client {client} got {size} B for {p} too ({_fmt(t, tz)})",
                            {"same_client": [client, size, sorted(others)]})
    return "d", FETCH, {}


# -- the report ---------------------------------------------------------------

def report(data: Path, files: list[str], start: datetime, end: datetime,
           tz: ZoneInfo, out=None) -> list[dict]:
    out = out or sys.stdout
    keys = withheld(data, start, end)
    print(f"withheld exposures in [{start.isoformat()}, {end.isoformat()}): {len(keys)}", file=out)
    if not keys:
        print("no withheld exposures in the window", file=out)
        return []
    sites: dict[str, _Site] = {}
    by_site: dict[str, list[Withheld]] = defaultdict(list)
    for w in keys:
        by_site[w.site].append(w)
    for site, ws in by_site.items():
        sites[site] = _Site.for_keys(ws)
    lower = start - CONTEXT
    print(f"raw log counted from {lower.isoformat()} (the day before the window, for context) "
          f"to {end.isoformat()}, {len(sites)} site(s)", file=out)
    n = stream(files, sites, start, end)
    print(f"  {n.get('lines', 0):,} lines read, {n.get('counted', 0):,} counted for those sites, "
          f"{n.get('not_access', 0):,} non-access lines skipped, "
          f"{n.get('unparsed', 0):,} unparsed", file=out)

    rows = []
    print(f"\n{'key':<48} {'kind':<13} {'verdict':<16} {'first':<12} {'dl':>3} {'cl':>3}  "
          f"size(s)      cls", file=out)
    for w in keys:
        cls, reason, evidence = classify(w, sites[w.site], tz)
        sizes = "/".join(str(s) for s in sorted(w.sizes)) or "-"
        print(f"{w.key:<48} {w.kind:<13} {w.verdict:<16} {_fmt(w.first, tz):<12} "
              f"{w.downloads:>3} {len(w.clients):>3}  {sizes:<12} ({cls})", file=out)
        print(f"    {reason}", file=out)
        if w.check:
            c = w.check
            print(f"    check: {c.get('verdict')} HTTP {c.get('status')} "
                  f"{c.get('content_type') or '-'} at {c.get('checked_at')} ({c.get('by')})",
                  file=out)
        stats = sites[w.site].path_stats
        rows.append({
            "key": w.key, "site": w.site, "root": w.root, "kind": w.kind, "domain": w.domain,
            "verdict": w.verdict, "verdicts": dict(w.verdicts), "check": w.check,
            "first": w.first.isoformat(), "last": w.last.isoformat(),
            "downloads": w.downloads, "clients": sorted(w.clients),
            "files": [{"path": p, "status": s, "bytes": b} for p, s, b in w.files],
            "sizes": sorted(w.sizes), "class": cls, "class_name": CLASSES[cls],
            "reason": reason, "evidence": evidence,
            **({"action": FETCH} if cls == "d" else {}),
            "raw": {"counted_from": lower.isoformat(), "counted_to": end.isoformat(),
                    "path_status": {p: dict(stats[p].classes) for p in sorted(w.paths)
                                    if p in stats}},
        })
    totals = Counter(r["class"] for r in rows)
    print("\nper class: " + ", ".join(f"({c}) {CLASSES[c]}: {totals.get(c, 0)}" for c in "abced"),
          file=out)
    for r in rows:
        if r["class"] == "d":
            print(f"  (d) {r['key']}: {FETCH}", file=out)
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", help="raw nginx lines, .gz or plain, in time order")
    ap.add_argument("--live", required=True, help="data root of the live run")
    ap.add_argument("--start", required=True, help="ISO time, the window opens")
    ap.add_argument("--end", required=True, help="ISO time, the window closes")
    ap.add_argument("--tz", default="Asia/Kolkata", help="local time in the table")
    ap.add_argument("--json", help="write one object per withheld key here (ndjson)")
    args = ap.parse_args(argv)
    tz = ZoneInfo(args.tz)
    start, end = datetime.fromisoformat(args.start), datetime.fromisoformat(args.end)
    start = start if start.tzinfo else start.replace(tzinfo=tz)
    end = end if end.tzinfo else end.replace(tzinfo=tz)
    rows = report(Path(args.live), args.files, start, end, tz)
    if args.json:
        Path(args.json).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
