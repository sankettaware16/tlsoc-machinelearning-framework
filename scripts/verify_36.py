#!/usr/bin/env python3
"""Read-only Phase 3.6 verification for a live soc-ml deployment.

Run from the repo root on the server:

    python3 verify_36.py                 # assumes ./data
    python3 verify_36.py --out /path/data

Answers the three ROADMAP 3.6 exit criteria:
  1. web_recon fire rate before/after crawler suppression
  2. did bot_detection flag a UA spoofer
  3. is the combined *delivered* rate within budget

Touches nothing: opens every file read-only and streams line by line, so it is
safe against multi-GB shadow logs.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

SLUGS = ("bot_detection", "web_recon")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def hr(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def sub(title: str) -> None:
    print(f"\n--- {title} ---")


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024.0
    return f"{n}"


def mtime(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")
    except OSError:
        return "?"


#: Above this, streaming takes long enough that silence reads as a hang.
_PROGRESS_BYTES = 200 * 1024 * 1024
_PROGRESS_EVERY = 250_000


def stream(path: Path):
    """Yield parsed JSON objects from an ndjson file, skipping bad lines.

    Streamed line by line and never held in memory: on a server that has been
    running for weeks these files are measured in GB.
    """
    noisy = path.stat().st_size > _PROGRESS_BYTES
    if noisy:
        print(f"  (streaming {human_size(path.stat().st_size)} — this takes a moment)",
              flush=True)
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            n += 1
            if noisy and n % _PROGRESS_EVERY == 0:
                print(f"    ... {n:,} lines", flush=True)
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def span_days(first: str | None, last: str | None) -> float | None:
    if not first or not last:
        return None
    try:
        a = datetime.fromisoformat(first.replace("Z", "+00:00"))
        b = datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return None
    secs = (b - a).total_seconds()
    return secs / 86400.0 if secs > 0 else None


def per_day(count: int, days: float | None) -> str:
    if not days or days <= 0:
        return "n/a (span too short)"
    return f"{count / days:.1f}/day"


# --------------------------------------------------------------------------- #
# crawler identity — reuse the project's own published ranges when importable
# --------------------------------------------------------------------------- #

def load_crawler_nets():
    try:
        sys.path.insert(0, str(Path.cwd() / "src"))
        from soc_ml.features.bot_features import CRAWLER_RANGES  # type: ignore
        nets = {}
        for family, cidrs in CRAWLER_RANGES.items():
            nets[family] = [ipaddress.ip_network(c) for c in cidrs]
        return nets, "project CRAWLER_RANGES"
    except Exception:
        # Fallback: the two families that dominated the elkcc false positives.
        return {
            "googlebot": [ipaddress.ip_network("66.249.64.0/19")],
            "bingbot": [ipaddress.ip_network("157.55.0.0/16"),
                        ipaddress.ip_network("207.46.0.0/16")],
        }, "built-in fallback (soc_ml not importable)"


def crawler_family(ip: str, nets) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for family, networks in nets.items():
        if any(addr in n for n in networks):
            return family
    return None


# --------------------------------------------------------------------------- #
# sections
# --------------------------------------------------------------------------- #

def section_process() -> None:
    hr("1. IS IT STILL RUNNING?")
    try:
        out = subprocess.run(
            ["ps", "-eo", "pid,etime,rss,stat,cmd"],
            capture_output=True, text=True, timeout=15,
        ).stdout
        hits = [ln for ln in out.splitlines() if "soc-ml" in ln or "soc_ml" in ln]
        hits = [ln for ln in hits if "verify_36" not in ln and "grep" not in ln]
        if hits:
            print("RUNNING:")
            print("  PID   ELAPSED     RSS STAT CMD")
            for ln in hits:
                print("  " + ln.strip())
        else:
            print("NOT RUNNING — no soc-ml process found.")
            print("(If you launched it in a plain SSH shell, closing the terminal")
            print(" sends SIGHUP, which the runtime does NOT handle — it dies")
            print(" without the clean drain. Check the health timestamp below")
            print(" to see exactly when it stopped.)")
    except Exception as exc:
        print(f"could not run ps: {exc}")

    try:
        out = subprocess.run(
            ["systemctl", "is-active", "foss-soc-ml"],
            capture_output=True, text=True, timeout=10,
        )
        print(f"\nsystemd unit foss-soc-ml: {out.stdout.strip() or out.stderr.strip()}")
    except Exception:
        print("\nsystemd unit foss-soc-ml: (systemctl unavailable)")


def section_health(state: Path) -> dict:
    hr("2. HEALTH — WHAT THE RUNTIME LAST REPORTED")
    healths = {}
    for slug in SLUGS:
        p = state / f"{slug}_health.json"
        sub(f"{slug}")
        if not p.exists():
            print(f"  MISSING {p} — this use case never wrote health.")
            continue
        try:
            doc = json.loads(p.read_text())
        except Exception as exc:
            print(f"  unreadable: {exc}")
            continue
        healths[slug] = doc
        print(f"  file mtime        : {mtime(p)}   (health is written every 10s,")
        print("                      so this is when the process was last alive)")
        for key in ("timestamp", "mode", "bundle_version", "uptime_s", "eps",
                    "events", "open_windows", "ingest_failed", "entity_annotations",
                    "alerts_delivered", "alerts_folded", "alerts_digested",
                    "alerts_suppressed"):
            if key in doc:
                val = doc[key]
                if key == "uptime_s" and isinstance(val, (int, float)):
                    val = f"{val:,.0f}s  ({val / 3600:.1f}h)"
                elif isinstance(val, int):
                    val = f"{val:,}"
                print(f"  {key:<18}: {val}")
    return healths


def section_checkpoint(state: Path) -> None:
    hr("3. CHECKPOINT — READ POSITION AND POLITENESS MEMORY")
    found = list(state.glob("*_checkpoint.json"))
    if not found:
        print(f"  No checkpoint in {state} — the runtime never persisted a cursor.")
        return
    for p in found:
        sub(p.name)
        print(f"  mtime: {mtime(p)}   size: {human_size(p.stat().st_size)}")
        try:
            doc = json.loads(p.read_text())
        except Exception as exc:
            print(f"  UNREADABLE ({exc}) — a restart would silently start from scratch.")
            continue
        fam = doc.get("family_robots") or []
        print(f"  family_robots (verified polite (server,family) pairs): {len(fam)}")
        for pair in fam[:15]:
            print(f"    {pair}")
        if len(fam) > 15:
            print(f"    ... and {len(fam) - 15} more")
        if not fam:
            print("    NONE — no verified crawler was seen fetching robots.txt.")
            print("    Consequence (D-023): verified crawlers get down-weighted,")
            print("    not suppressed, so web_recon keeps delivering Googlebot.")
        for key, val in doc.items():
            if key == "family_robots":
                continue
            shown = val if not isinstance(val, (dict, list)) else f"<{type(val).__name__}>"
            print(f"  {key}: {shown}")


def section_registry(data: Path) -> None:
    hr("4. MODEL REGISTRY — WHAT WAS ACTUALLY SERVING")
    models = data / "models"
    if not models.is_dir():
        print(f"  No {models} — nothing was ever trained here.")
        return
    for slug in SLUGS:
        d = models / slug
        sub(slug)
        if not d.is_dir():
            print(f"  MISSING {d} — no model for this use case.")
            print("  In --mode live that is a loud refusal at startup.")
            continue
        versions = sorted(p.name for p in d.iterdir() if p.is_dir())
        print(f"  versions on disk: {', '.join(versions) if versions else '(none)'}")
        for pointer in ("current", "candidate"):
            pp = d / pointer
            if pp.exists():
                try:
                    target = pp.read_text().strip() if pp.is_file() else os.readlink(pp)
                except Exception:
                    target = "?"
                print(f"  {pointer:<9} -> {target}")
        meta = d / "current" / "metadata.json"
        if meta.is_file():
            try:
                m = json.loads(meta.read_text())
                for k in ("trained_at", "train_windows", "feature_sha256", "version"):
                    if k in m:
                        print(f"  {k}: {m[k]}")
            except Exception:
                pass


def section_shadow(state: Path, nets) -> dict:
    hr("5. THE BEFORE/AFTER MEASUREMENT  (exit criterion 1)")
    print("Every score is recorded in the shadow log whether or not it fired,")
    print("and a suppressed alert keeps fired=true with suppressed_by set (D-022).")
    print("So the shadow log alone gives the fire rate before AND after suppression.")
    summary = {}
    for slug in SLUGS:
        p = state / f"{slug}_shadow.ndjson"
        sub(f"{slug}_shadow.ndjson")
        if not p.exists():
            print("  MISSING — no scores were ever recorded for this use case.")
            continue
        print(f"  size: {human_size(p.stat().st_size)}   mtime: {mtime(p)}")
        rows = fired = suppressed = downweighted = 0
        first = last = None
        supp_reasons = Counter()
        down_reasons = Counter()
        fired_entities = Counter()
        delivered_entities = Counter()
        supp_entities = Counter()
        for row in stream(p):
            rows += 1
            we = row.get("window_end")
            if we:
                if first is None:
                    first = we
                last = we
            if not row.get("fired"):
                continue
            fired += 1
            ent = row.get("entity", "?")
            fired_entities[ent] += 1
            s = row.get("suppressed_by")
            d = row.get("downweighted_by")
            if s:
                suppressed += 1
                supp_reasons[s] += 1
                supp_entities[ent] += 1
            else:
                delivered_entities[ent] += 1
            if d:
                downweighted += 1
                down_reasons[d] += 1
        days = span_days(first, last)
        after = fired - suppressed
        print(f"  scored windows       : {rows:,}")
        print(f"  span                 : {first}  ->  {last}"
              + (f"   ({days:.2f} days)" if days else ""))
        print(f"  FIRED (before suppr.): {fired:,}   {per_day(fired, days)}")
        print(f"  suppressed           : {suppressed:,}   {per_day(suppressed, days)}")
        print(f"  DELIVERED (after)    : {after:,}   {per_day(after, days)}")
        if fired:
            print(f"  suppression rate     : {100.0 * suppressed / fired:.1f}% of fires")
        print(f"  down-weighted        : {downweighted:,}")
        if supp_reasons:
            print("  suppression reasons:")
            for reason, n in supp_reasons.most_common(10):
                print(f"    {n:>7,}  {reason}")
        if down_reasons:
            print("  down-weight reasons:")
            for reason, n in down_reasons.most_common(10):
                print(f"    {n:>7,}  {reason}")
        if supp_entities:
            print("  top suppressed entities:")
            for ent, n in supp_entities.most_common(8):
                print(f"    {n:>7,}  {ent}")
        if delivered_entities:
            print("  top STILL-DELIVERED entities (these are your remaining noise):")
            for ent, n in delivered_entities.most_common(12):
                fam = None
                for tok in str(ent).replace("|", " ").replace(",", " ").split():
                    fam = crawler_family(tok.strip("()'\" "), nets)
                    if fam:
                        break
                flag = f"   <-- {fam.upper()} IN PUBLISHED RANGE, STILL FIRING" if fam else ""
                print(f"    {n:>7,}  {ent}{flag}")
        summary[slug] = {
            "fired": fired, "suppressed": suppressed, "after": after, "days": days,
        }
    return summary


def section_alerts(data: Path, nets) -> dict:
    hr("6. DELIVERED ALERTS  (exit criteria 2 and 3)")
    alerts_dir = data / "alerts"
    out = {}
    if not alerts_dir.is_dir():
        print(f"  No {alerts_dir} — nothing was ever delivered.")
        print("  Expected if the run was shadow/observe, NOT expected for --mode live.")
        return out
    for slug in SLUGS:
        p = alerts_dir / f"{slug}.ndjson"
        sub(f"alerts/{slug}.ndjson")
        if not p.exists():
            print("  MISSING — this use case delivered nothing.")
            continue
        print(f"  size: {human_size(p.stat().st_size)}   mtime: {mtime(p)}")
        n = 0
        first = last = None
        sev = Counter()
        ents = Counter()
        crawler_hits = Counter()
        samples = []
        for doc in stream(p):
            n += 1
            ts = doc.get("@timestamp")
            if ts:
                if first is None:
                    first = ts
                last = ts
            sev[(doc.get("alert") or {}).get("severity", "?")] += 1
            ent = doc.get("entity") or {}
            ip = ent.get("ip", "?")
            key = f"{ip} @ {ent.get('server', '?')}"
            ents[key] += 1
            fam = crawler_family(ip, nets)
            if fam:
                crawler_hits[f"{ip} ({fam})"] += 1
            if len(samples) < 3:
                samples.append(doc)
        days = span_days(first, last)
        print(f"  delivered alerts : {n:,}")
        print(f"  span             : {first}  ->  {last}"
              + (f"   ({days:.2f} days)" if days else ""))
        print(f"  rate             : {per_day(n, days)}   (target: <=3/day/server)")
        print(f"  severity         : {dict(sev)}")
        if ents:
            print("  top entities:")
            for ent, c in ents.most_common(10):
                print(f"    {c:>6,}  {ent}")
        if crawler_hits:
            print("\n  *** VERIFIED-CRAWLER ADDRESSES STILL BEING DELIVERED ***")
            print("  This is exactly the false positive Phase 3 exists to remove.")
            for ent, c in crawler_hits.most_common(10):
                print(f"    {c:>6,}  {ent}")
        else:
            print("\n  No published-range crawler addresses in delivered alerts. GOOD.")
        if slug == "bot_detection" and samples:
            print("\n  bot_detection fires = UA-spoofing candidates. Sample narratives:")
            for doc in samples:
                nar = ((doc.get("explanation") or {}).get("narrative") or "")[:260]
                print(f"    - {(doc.get('entity') or {}).get('ip')}: {nar}")
        out[slug] = {"delivered": n, "days": days, "crawlers": sum(crawler_hits.values())}
    return out


def section_side_files(state: Path) -> None:
    hr("7. SUPPRESSED / DIGEST / DLQ / DRIFT")
    for slug in SLUGS:
        for kind in ("suppressed", "digest"):
            p = state / f"{slug}_{kind}.ndjson"
            if p.exists():
                n = sum(1 for _ in p.open("r", encoding="utf-8", errors="replace"))
                note = ""
                if kind == "digest" and n:
                    note = "   <-- OVER DAILY BUDGET (overflow, not dropped)"
                print(f"  {slug}_{kind}.ndjson: {n:,} lines   ({human_size(p.stat().st_size)}){note}")
            else:
                print(f"  {slug}_{kind}.ndjson: (absent)")
        p = state / f"{slug}_drift.json"
        if p.exists():
            try:
                doc = json.loads(p.read_text())
                drifted = doc.get("drifted") or doc.get("features_over_threshold") or []
                print(f"  {slug}_drift.json: {mtime(p)}  drifted={drifted if drifted else 'none'}")
            except Exception:
                print(f"  {slug}_drift.json: unreadable")
        else:
            print(f"  {slug}_drift.json: (absent — drift never evaluated)")

    for p in state.glob("*_dlq.ndjson"):
        n = sum(1 for _ in p.open("r", encoding="utf-8", errors="replace"))
        flag = "   <-- PARSE FAILURES, input contract may be off" if n else ""
        print(f"  {p.name}: {n:,} lines{flag}")


def section_verdict(shadow: dict, alerts: dict, healths: dict) -> None:
    hr("8. VERDICT AGAINST THE 3.6 EXIT CRITERIA")
    wr = shadow.get("web_recon") or {}
    ok1 = None
    if wr.get("fired"):
        supp = wr["suppressed"]
        ok1 = supp > 0
        print(f"  [1] web_recon before/after : {wr['fired']:,} fired -> "
              f"{wr['after']:,} delivered ({supp:,} suppressed)")
        print(f"      {'PASS' if ok1 else 'FAIL'} — "
              + ("suppression is doing work" if ok1
                 else "NOTHING was suppressed; the crawler export is not reaching the gate"))
    else:
        print("  [1] web_recon before/after : no fires recorded — cannot measure.")

    bd = alerts.get("bot_detection") or {}
    if bd:
        print(f"  [2] bot_detection spoofers : {bd['delivered']:,} alerts delivered")
        print("      " + ("candidates exist — review the narratives above"
                          if bd["delivered"] else
                          "none fired; either no spoofer present or the gate never triggers"))
    else:
        print("  [2] bot_detection spoofers : no alert file — nothing delivered.")

    total = sum(v.get("delivered", 0) for v in alerts.values())
    days = max((v.get("days") or 0) for v in alerts.values()) if alerts else 0
    if days:
        rate = total / days
        print(f"  [3] combined delivered rate: {total:,} over {days:.2f}d = {rate:.1f}/day")
        print(f"      {'WITHIN' if rate <= 3 else 'ABOVE'} the <=3/day/server target"
              + ("" if rate <= 3 else " — do not widen scope yet"))
    else:
        print("  [3] combined delivered rate: span too short to judge.")

    stale = [s for s, h in healths.items() if h.get("mode") != "live"]
    if stale:
        print(f"\n  NOTE: health reports mode="
              f"{ {s: healths[s].get('mode') for s in stale} } — not 'live'.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data", help="registry/data root (default: data)")
    args = ap.parse_args()

    data = Path(args.out).expanduser().resolve()
    state = data / "state"

    print(f"soc-ml Phase 3.6 verification")
    print(f"host: {os.uname().nodename}   cwd: {Path.cwd()}")
    print(f"data root: {data}   exists: {data.is_dir()}")
    if not data.is_dir():
        print("\nNo data root. Either you ran from a different directory, or the")
        print("runtime never started. Try:  python3 verify_36.py --out /path/to/data")
        return 1

    nets, src = load_crawler_nets()
    print(f"crawler ranges: {src} ({len(nets)} families)")

    section_process()
    healths = section_health(state)
    section_checkpoint(state)
    section_registry(data)
    shadow = section_shadow(state, nets)
    alerts = section_alerts(data, nets)
    section_side_files(state)
    section_verdict(shadow, alerts, healths)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
