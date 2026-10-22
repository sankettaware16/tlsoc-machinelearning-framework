#!/usr/bin/env python3
"""Score real traffic through the serving and candidate bundles, side by side.

Answers the two questions that should be asked before clicking Approve:

1. **Does it fix the volume?** Percentile calibration is fitted on the training
   corpus, so a drifted model fires on far more than its design fraction. This
   replays the same windows through both bundles and reports what share of
   windows each one gates open on.

2. **Can it still see an attack?** A model retrained on traffic that already
   contains background scanning can learn that scanning is normal. Each use
   case ships a deterministic known-bad burst (``UseCase.canary``); this
   injects it and reports whether each bundle catches it. A candidate that
   lowers the fire rate but misses the canary must not be approved.

3. **Can it still see the attacks we have actually had?** A synthetic canary
   is one shape. Every captured real attack under
   ``data/incidents/<use case>/*.ndjson`` (raw parser output, never
   committed) is replayed through both bundles, plus any ``--incident FILE``;
   a candidate that goes blind to an attack the serving model catches must
   not be approved. Incidents are filed per use case on purpose: a headless
   botnet is bot_detection's evidence, and web_recon *not* firing on it is
   precision, not blindness. On elkcc, 2026-10-12, a retrained
   bot_detection passed its canary and fired on none of 756 windows of a
   live headless-browser botnet the serving model caught (D-032).

It writes one file: the verdict, as ``approval_check.json`` in the candidate's
bundle directory — the registry refuses to promote without a PASS or WARN
checked against the bundle serving now (D-035). Nothing else is written, and
the running detector is untouched. The replay is held in memory: bound it with
``--limit`` on a busy box.

    python3 scripts/check_candidate.py --uc web_recon \
        --input /var/log/soc_output/nginx.json --limit 200000
"""

from __future__ import annotations

import argparse
import builtins
import functools
import hashlib
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Same tiny-matrix workload as the CLI, same pin (JOURNAL.md D-026) — this
# script bypasses cli/main.py, so it must set the defaults itself, before
# numpy/sklearn load. The standard library above loads neither.
for _var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_var, "1")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import soc_ml.models  # noqa: F401,E402
import soc_ml.usecases  # noqa: F401,E402
from soc_ml.core.plugins import registry as plugin_registry  # noqa: E402
from soc_ml.core.plugins import usecase_model_factories  # noqa: E402
from soc_ml.core.provenance import code_commit  # noqa: E402
from soc_ml.detection.annotations import EntityAnnotations  # noqa: E402
from soc_ml.detection.scorer import Scorer  # noqa: E402
from soc_ml.evaluation.canary import is_canary_ip  # noqa: E402
from soc_ml.features.window_features import WindowFeatureBuilder  # noqa: E402
from soc_ml.ingest.file import FileSource  # noqa: E402
from soc_ml.registry.store import ModelRegistry  # noqa: E402

#: This is slow enough to be run redirected to a file, where Python buffers
#: stdout and the run looks hung for minutes.
print = functools.partial(builtins.print, flush=True)  # noqa: A001


def events(path: str, limit: int):
    src = FileSource(path)
    for n, event in enumerate(src.read(), 1):
        yield event
        if limit and n >= limit:
            break


def score_through(uc_cls, bundle, stream, canary_events) -> dict:
    """Replay one event stream through one bundle. Returns gate statistics."""
    scorer = Scorer(uc_cls, bundle, EntityAnnotations())
    builder = WindowFeatureBuilder(bundle.profile)

    windows = fired = canary_windows = canary_fired = 0
    top: list[tuple[float, str, int]] = []
    fired_ips: set[str] = set()

    def handle(results: list) -> None:
        nonlocal windows, fired, canary_windows, canary_fired
        flags = [is_canary_ip(r.vector.entity.ip) for r in results]
        outcomes = scorer.score_many(results, synthetic=flags)
        for outcome, synthetic in zip(outcomes, flags, strict=True):
            if outcome is None:
                continue
            windows += 1
            canary_windows += int(synthetic)
            if outcome.fired:
                fired += 1
                canary_fired += int(synthetic)
                fired_ips.add(outcome.entity.ip)
                if not synthetic:
                    top.append((outcome.fused_percentile, str(outcome.entity),
                                outcome.evidence.get("event_count", 0)))

    merged = sorted(list(stream) + list(canary_events), key=lambda e: e.timestamp)
    for event in merged:
        closed = list(builder.add(event))
        if closed:
            handle(closed)

    # Everything above closed because a later event arrived — the same way
    # windows close in the live runtime. The final flush is different: it
    # closes every still-open window at once, including the one-request tail
    # that live scoring would never have counted yet. Counting those inflates
    # the denominator and reports a fire rate several times lower than the
    # deployment actually runs at, which is exactly the wrong direction for a
    # go/no-go check.
    natural_windows, natural_fired = windows, fired
    handle(list(builder.flush()))

    top.sort(reverse=True)
    return {
        "windows": natural_windows,
        "fired": natural_fired,
        # Including the final flush: right for a finite incident replay,
        # where every window is part of the attack.
        "windows_all": windows,
        "fired_all": fired,
        "fired_ips": fired_ips,
        "rate_pct": (100.0 * natural_fired / natural_windows) if natural_windows else 0.0,
        "flushed_windows": windows - natural_windows,
        "canary_windows": canary_windows,
        "canary_fired": canary_fired,
        "top": top[:5],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uc", default="web_recon")
    ap.add_argument("--input", required=True)
    ap.add_argument("--limit", type=int, default=200_000,
                    help="events to replay (0 = all; bound it on a busy box)")
    ap.add_argument("--out", default="data")
    ap.add_argument("--incident", action="append", default=[], metavar="FILE",
                    help="captured real attack (parser output) the candidate must "
                         "still catch; repeatable")
    args = ap.parse_args()

    slug = args.uc.replace("-", "_")
    uc_cls = plugin_registry.get("usecase", slug)
    factories = usecase_model_factories(uc_cls)
    reg = ModelRegistry(args.out)

    serving = reg.current_version(slug)
    candidate = reg.candidate_version(slug)
    print(f"use case  : {slug} ({uc_cls.usecase_id} — {uc_cls.title})")
    print(f"serving   : {serving}")
    print(f"candidate : {candidate or '(none)'}")
    if not candidate:
        print("\nNothing to compare — no candidate is registered.")
        return 1

    print(f"\nreplaying up to {args.limit:,} events from {args.input} ...")
    stream = list(events(args.input, args.limit))
    if not stream:
        print("no events read")
        return 1
    span_h = (stream[-1].timestamp - stream[0].timestamp).total_seconds() / 3600.0
    print(f"read {len(stream):,} events spanning {span_h:.2f}h\n")

    results = {}
    bundles = {}
    for label, version in (("serving", serving), ("candidate", candidate)):
        bundle = bundles[label] = reg.load(slug, version, factories)
        server = bundle.profile.dominant_server() or "_"
        canary = uc_cls.canary(server, stream[0].timestamp + timedelta(minutes=30))
        results[label] = score_through(uc_cls, bundle, stream, canary)
        results[label]["version"] = version

    gate = getattr(uc_cls, "GATE_PERCENTILE", None)
    design = round(100.0 * (1.0 - gate), 3) if gate else None
    print(f"{'':<11}{'version':<22}{'windows':>9}{'fired':>8}{'rate':>9}{'canary':>10}")
    print("-" * 69)
    for label in ("serving", "candidate"):
        r = results[label]
        canary_txt = (f"{r['canary_fired']}/{r['canary_windows']}"
                      if r["canary_windows"] else "n/a")
        print(f"{label:<11}{r['version']:<22}{r['windows']:>9,}{r['fired']:>8,}"
              f"{r['rate_pct']:>8.3f}%{canary_txt:>10}")
    if design is not None:
        print(f"\ndesign fire rate for this gate: {design}% of windows "
              f"(p{gate * 100:g} percentile)")
    print(f"windows counted: closed by a later event, as in the live runtime. "
          f"{results['serving'].get('flushed_windows', 0):,} still-open windows "
          f"were flushed at the end and excluded.")

    filed = sorted((Path(args.out) / "incidents" / slug).glob("*.ndjson"))
    incidents = [str(p) for p in filed] + list(args.incident)
    blind_to: list[str] = []
    weaker_on: list[str] = []
    incident_rows: list[dict] = []
    if incidents:
        # Addresses decide the verdict: since D-031 one address is one alert,
        # however many user-agent fragments of it fire. Windows are context.
        print(f"\n{'incident':<44}{'serving':>16}{'candidate':>16}")
        print(f"{'':<44}{'addrs (windows)':>16}{'addrs (windows)':>16}")
        print("-" * 76)
    for path in incidents:
        stream_i = list(events(path, 0))
        if not stream_i:
            print(f"{Path(path).name:<44}  (no request events read)")
            continue
        addresses = {e.source_ip for e in stream_i if e.is_request}
        caught = {}
        for label in ("serving", "candidate"):
            r = score_through(uc_cls, bundles[label], stream_i, [])
            caught[label] = (r["fired_ips"], r["fired_all"], r["windows_all"])
        (s_ips, sf, sw), (c_ips, cf, cw) = caught["serving"], caught["candidate"]
        n = len(addresses)
        print(f"{Path(path).name:<44}"
              f"{f'{len(s_ips)}/{n} ({sf}/{sw})':>16}{f'{len(c_ips)}/{n} ({cf}/{cw})':>16}")
        incident_rows.append({
            "file": Path(path).name,
            "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            "addresses": n,
            "serving_caught": len(s_ips), "candidate_caught": len(c_ips),
            "serving_windows": [sf, sw], "candidate_windows": [cf, cw],
            "missed_by_candidate": sorted(s_ips - c_ips)[:20],
        })
        if s_ips and not c_ips:
            blind_to.append(Path(path).name)
        elif s_ips - c_ips:
            weaker_on.append(f"{Path(path).name} — misses {len(s_ips - c_ips)} "
                             f"address(es) serving catches")

    s, c = results["serving"], results["candidate"]
    notes: list[str] = []
    verdict = "PASS"
    if c["canary_windows"] and not c["canary_fired"]:
        verdict = "DO_NOT_APPROVE"
        notes.append("the candidate misses its own known-bad burst — lower volume "
                     "with no detection is a worse model, not a better one")
    if blind_to:
        verdict = "DO_NOT_APPROVE"
        notes.append("the candidate is blind to a real attack the serving model "
                     f"catches: {', '.join(blind_to)}")
    if verdict == "PASS":
        for note in weaker_on:
            verdict = "WARN"
            notes.append(note)
        if not c["canary_windows"]:
            verdict = "WARN"
            notes.append("no canary windows produced — detection is unverified here")
        if c["rate_pct"] > s["rate_pct"]:
            verdict = "WARN"
            notes.append(f"candidate fires MORE ({c['rate_pct']:.3f}% vs "
                         f"{s['rate_pct']:.3f}%) — investigate before approving")
    info: list[str] = []
    if c["canary_windows"] and c["canary_fired"]:
        info.append("canary caught by the candidate — it can still see a textbook attack")
    if s["rate_pct"] and c["rate_pct"] < s["rate_pct"]:
        factor = s["rate_pct"] / max(c["rate_pct"], 1e-9)
        info.append(f"fire rate {s['rate_pct']:.3f}% -> {c['rate_pct']:.3f}% "
                    f"({factor:.1f}x fewer)")
    if design is not None and c["rate_pct"] > design * 3:
        info.append(f"still {c['rate_pct'] / design:.1f}x the design rate — "
                    "calibration alone will not reach the alert budget")

    print("\nverdict")
    label = {"PASS": "PASS", "WARN": "WARN — approvable, read the notes",
             "DO_NOT_APPROVE": "DO NOT APPROVE"}[verdict]
    print(f"  {label}")
    for note in notes:
        print(f"  - {note}")
    for line in info:
        print(f"  {line}")

    # The recorded verdict the registry demands before promotion (FR-55, D-035).
    digest = hashlib.sha256()
    for e in stream:
        digest.update(f"{e.timestamp.isoformat()}|{e.source_ip}|{e.url_path}|"
                      f"{e.status_code}\n".encode())
    report = {
        "verdict": verdict,
        "generated_at": datetime.now(UTC).isoformat(),
        "code_commit": code_commit(),
        "usecase": slug,
        "serving": serving,
        "candidate": candidate,
        "input": {
            "path": str(args.input), "limit": args.limit, "events": len(stream),
            "first": stream[0].timestamp.isoformat(),
            "last": stream[-1].timestamp.isoformat(),
            "sha256_events": digest.hexdigest(),
        },
        "fire_rate": {k: {"windows": results[k]["windows"], "fired": results[k]["fired"],
                          "rate_pct": round(results[k]["rate_pct"], 4)}
                      for k in ("serving", "candidate")},
        "design_rate_pct": design,
        "canary": {k: {"windows": results[k]["canary_windows"],
                       "fired": results[k]["canary_fired"]}
                   for k in ("serving", "candidate")},
        "incidents": incident_rows,
        "notes": notes,
        "info": info,
    }
    path = reg.write_approval(slug, candidate, report)
    print(f"\nrecorded: {path}")
    return 2 if verdict == "DO_NOT_APPROVE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
