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

Read-only with respect to the registry and the running detector: it loads
bundles, scores in memory, and writes nothing.

    python3 scripts/check_candidate.py --uc web_recon \
        --input /var/log/soc_output/nginx.json --limit 200000
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import soc_ml.models  # noqa: F401,E402
import soc_ml.usecases  # noqa: F401,E402
from soc_ml.core.plugins import registry as plugin_registry  # noqa: E402
from soc_ml.core.plugins import usecase_model_factories  # noqa: E402
from soc_ml.detection.annotations import EntityAnnotations  # noqa: E402
from soc_ml.detection.scorer import Scorer  # noqa: E402
from soc_ml.evaluation.canary import is_canary_ip  # noqa: E402
from soc_ml.features.window_features import WindowFeatureBuilder  # noqa: E402
from soc_ml.ingest.file import FileSource  # noqa: E402
from soc_ml.registry.store import ModelRegistry  # noqa: E402


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

    def handle(result) -> None:
        nonlocal windows, fired, canary_windows, canary_fired
        synthetic = is_canary_ip(result.vector.entity.ip)
        outcome = scorer.score(result, synthetic=synthetic)
        if outcome is None:
            return
        windows += 1
        canary_windows += int(synthetic)
        if outcome.fired:
            fired += 1
            canary_fired += int(synthetic)
            if not synthetic:
                top.append((outcome.fused_percentile, str(outcome.entity),
                            outcome.evidence.get("event_count", 0)))

    merged = sorted(list(stream) + list(canary_events), key=lambda e: e.timestamp)
    for event in merged:
        for result in builder.add(event):
            handle(result)
    for result in builder.flush():
        handle(result)

    top.sort(reverse=True)
    return {
        "windows": windows,
        "fired": fired,
        "rate_pct": (100.0 * fired / windows) if windows else 0.0,
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
    for label, version in (("serving", serving), ("candidate", candidate)):
        bundle = reg.load(slug, version, factories)
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

    s, c = results["serving"], results["candidate"]
    print("\nverdict")
    if c["canary_windows"] and not c["canary_fired"]:
        print("  DO NOT APPROVE — the candidate misses its own known-bad burst.")
        print("  Lower volume with no detection is a worse model, not a better one.")
        return 2
    if c["canary_windows"]:
        print("  canary caught by the candidate — it can still see a textbook attack")
    else:
        print("  no canary windows produced — detection is UNVERIFIED here")
    if s["rate_pct"] and c["rate_pct"] < s["rate_pct"]:
        factor = s["rate_pct"] / max(c["rate_pct"], 1e-9)
        print(f"  fire rate {s['rate_pct']:.3f}% -> {c['rate_pct']:.3f}% "
              f"({factor:.1f}x fewer)")
    elif c["rate_pct"] > s["rate_pct"]:
        print(f"  WARNING: candidate fires MORE ({c['rate_pct']:.3f}% vs "
              f"{s['rate_pct']:.3f}%) — investigate before approving")
    if design is not None and c["rate_pct"] > design * 3:
        print(f"  note: still {c['rate_pct'] / design:.1f}x the design rate — "
              "calibration alone will not reach the alert budget")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
