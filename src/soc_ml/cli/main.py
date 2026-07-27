"""``soc-ml`` command line entry point.

Commands that work today (Phase 0): ``validate``, ``lint-config``, ``plugins``,
``version``. The pipeline commands (``backtest``, ``run``, ``train``,
``promote``) are declared so the interface is settled, and each fails with a
clear "not implemented yet, see ROADMAP" rather than a stack trace.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

__all__ = ["main"]

_NOT_YET = "not implemented yet (Phase 0 scaffold) — see docs/ROADMAP.md"

# Cap on distinct-value tracking so `validate` stays memory-bounded on
# multi-GB inputs. Exact counts (parsed/failed/coverage) are unaffected; only
# cardinality estimates (distinct entities/servers/timestamps) stop growing
# past this many keys. See the large-data note in docs/DEVELOPING.md.
_TRACK_CAP = 2_000_000


# --------------------------------------------------------------------------- #
# validate — does this input satisfy the event contract?
# --------------------------------------------------------------------------- #


def cmd_validate(args: argparse.Namespace) -> int:
    """Check that a directory of parser output satisfies the input contract."""
    from soc_ml.core import Event

    root = Path(args.input).expanduser()
    if not root.exists():
        print(f"[ERROR] input not found: {root}", file=sys.stderr)
        return 2

    files = sorted(root.rglob("*.json")) if root.is_dir() else [root]
    if not files:
        print(f"[ERROR] no .json files under {root}", file=sys.stderr)
        return 2

    total = bad = has_original_time = 0
    reasons: Counter[str] = Counter()
    coverage: Counter[str] = Counter()
    stamps: Counter = Counter()
    ts_sources: Counter[str] = Counter()
    servers: set[str] = set()
    entities: set[str] = set()
    earliest = latest = None

    tracked = {
        "source_ip": lambda e: e.source_ip,
        "url_path": lambda e: e.url_path,
        "status_code": lambda e: e.status_code,
        "http_method": lambda e: e.http_method,
        "user_agent": lambda e: e.user_agent,
        "body_bytes": lambda e: e.body_bytes,
        "referrer": lambda e: e.http_referrer,
        "geo": lambda e: e.geo_country_iso,
    }

    for path in files:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                if args.limit and total >= args.limit:
                    break
                total += 1
                try:
                    doc = json.loads(line)
                    event = Event.from_ecs(doc)
                except Exception as exc:
                    bad += 1
                    reasons[type(exc).__name__ + ": " + str(exc)[:60]] += 1
                    continue
                # Bound the cardinality-sized structures. On a multi-GB file with
                # microsecond timestamps, `stamps` would otherwise grow to one key
                # per event and OOM. Existing keys still increment (so collision
                # counting stays correct); new keys stop being added past the cap.
                if event.timestamp in stamps or len(stamps) < _TRACK_CAP:
                    stamps[event.timestamp] += 1
                ev_block = doc.get("event") or {}
                if ev_block.get("original_time"):
                    has_original_time += 1
                if ev_block.get("timestamp_source"):
                    ts_sources[ev_block["timestamp_source"]] += 1
                for name, get in tracked.items():
                    if get(event) is not None:
                        coverage[name] += 1
                if event.observer.server and len(servers) < _TRACK_CAP:
                    servers.add(event.observer.server)
                if len(entities) < _TRACK_CAP:
                    entities.add(str(event.entity))
                ts = event.timestamp
                earliest = ts if earliest is None or ts < earliest else earliest
                latest = ts if latest is None or ts > latest else latest

    good = total - bad
    print(f"files      : {len(files)}")
    print(f"events     : {total}  ({good} parsed, {bad} failed)")
    if earliest and latest:
        span = (latest - earliest).total_seconds()
        print(f"time span  : {earliest.isoformat()} -> {latest.isoformat()}  ({span/3600:.1f}h)")
        # Long-window use cases cannot be exercised by a short sample, and that
        # is the single most common reason a backtest looks broken.
        for window, hours in (("24h", 24), ("7d", 168)):
            if span < hours * 3600:
                print(f"[WARN] span is shorter than the {window} window — "
                      f"features over {window} cannot be exercised by this input")
    capped = " (capped — distinct-count sampling limit reached)" if len(entities) >= _TRACK_CAP else ""
    print(f"servers    : {len(servers)}")
    print(f"entities   : {len(entities)}{capped}", end="")
    if good and not capped:
        print(f"  ({good/max(len(entities),1):.1f} events per entity)")
    else:
        print()

    print("\nfield coverage (of parsed events):")
    for name in tracked:
        pct = 100.0 * coverage[name] / good if good else 0.0
        flag = "" if pct >= 90 or name == "geo" else "   <-- low"
        print(f"  {name:<12} {pct:6.1f}%{flag}")
    if coverage["geo"] < good:
        internal = good - coverage["geo"]
        print(f"  (note: {internal} events have no geo = internal addresses, expected)")

    if ts_sources:
        attested = ", ".join(f"{k}={v}" for k, v in ts_sources.most_common())
        print(f"\nevent time : {attested}  (parser-attested)")

    warnings = _check_timestamp_quality(stamps, good, has_original_time, ts_sources)

    if bad:
        print("\nfailures:")
        for reason, count in reasons.most_common(5):
            print(f"  {count:>6}  {reason}")

    if good and len(entities) >= good:
        warnings.append(
            "almost every event is its own entity — per-entity windowed "
            "features will have nothing to aggregate"
        )

    if warnings:
        print()
        for warning in warnings:
            print(f"[WARN] {warning}")

    ok = bad == 0 and good > 0
    if not ok:
        print(f"\nRESULT: FAIL — {bad} unparseable event(s)")
        return 1
    if warnings and args.strict:
        print("\nRESULT: FAIL — contract satisfied but data quality warnings (--strict)")
        return 1
    suffix = f" ({len(warnings)} warning(s))" if warnings else ""
    print(f"\nRESULT: PASS — input satisfies the contract{suffix}")
    return 0


def _check_timestamp_quality(
    stamps: Counter,
    good: int,
    has_original_time: int,
    ts_sources: Counter | None = None,
) -> list[str]:
    """Detect @timestamp carrying ingest time instead of event time.

    This defect is invisible in field-coverage terms: @timestamp is present,
    well-formed, and 100% populated — it is simply the wrong clock. And it is
    worse than data loss: a flushed batch sharing one instant yields an
    inter-arrival CV of ~0, which is exactly the "machine-regular" signature
    UC-01 and UC-04 treat as strong bot evidence, so it manufactures confident
    false positives.

    Two-level check:

    1. **Trust the parser's own attestation when present.**
       `event.timestamp_source` is authoritative: `log` / `log_assumed_utc`
       mean the time was parsed from the line; `ingest_fallback` means it was
       stamped at parse time (and the parser said so honestly).
    2. **Heuristic only for feeds without the attestation** (older engine
       versions, foreign shippers): real event times at *sub-second* precision
       essentially never collide in bulk, so a large group of events sharing
       one microsecond-precision instant is an ingest stamp. Second-resolution
       collisions (classic CLF at high request rates — hundreds of events per
       second on a busy server) are expected and must NOT be flagged; a plain
       distinct/total ratio gets that wrong.
    """
    problems: list[str] = []
    if not good or not stamps:
        return problems
    ts_sources = ts_sources or Counter()

    # -- 1. attested by the parser ----------------------------------------- #
    fallback = ts_sources.get("ingest_fallback", 0)
    if fallback / good > 0.05:
        problems.append(
            f"{fallback} events ({fallback / good:.0%}) carry "
            "event.timestamp_source=ingest_fallback — the parser could not read "
            "the event's real time and stamped parse time instead. Timing "
            "features on these events measure the pipeline, not the client; "
            "near-zero inter-arrival CV then reads as 'machine-like' and "
            "manufactures false positives. Fix the rule's `timestamp:` block "
            "(foss-soc-engine WRITING_RULES.md §5)."
        )
    if ts_sources.get("log", 0) or ts_sources.get("log_assumed_utc", 0):
        # Event times are parser-attested; any remaining collisions are just
        # clock resolution (CLF is 1-second), which is normal at high rates.
        return problems

    # -- 2. heuristic for unattested feeds ---------------------------------- #
    subsecond = {t: c for t, c in stamps.items() if getattr(t, "microsecond", 0)}
    if subsecond:
        largest = max(subsecond.values())
        if largest >= 10 and largest / good > 0.01:
            problems.append(
                f"@timestamp looks like INGEST time, not event time: {largest} "
                f"events share a single microsecond-precision instant "
                f"(real event times do not collide like that). Timing features "
                "(inter-arrival CV, beaconing periodicity, activity calendars) "
                "would measure the parser's flush schedule, not client "
                "behaviour — and near-zero inter-arrival CV reads as "
                "'machine-like', so this manufactures false positives rather "
                "than just losing signal."
            )
            if has_original_time:
                problems.append(
                    f"remediation: {has_original_time} events carry "
                    "'event.original_time' with the true event time — this looks "
                    "like output from an old parser version; re-parse with a "
                    "current engine whose rule has a `timestamp:` block "
                    "(foss-soc-engine WRITING_RULES.md §5)"
                )
    return problems


# --------------------------------------------------------------------------- #
# lint-config / plugins
# --------------------------------------------------------------------------- #


def cmd_sessions(args: argparse.Namespace) -> int:
    """Sessionize input and report the visit shape of this environment.

    Useful before building anything: it shows whether the data can support
    per-session features at all, which is the usual reason a backtest of UC-06
    or UC-10 comes back empty.

    MEMORY-BOUNDED BY DESIGN. This is a diagnostic, and diagnostics get pointed
    at whatever is lying around — including the multi-gigabyte real-traffic
    dumps. It therefore reads at most ``--limit`` events (a *prefix* of the
    input) and retains only closed-session objects for that prefix, never the
    events. It must never attempt to load a whole file. See the large-data
    note in docs/DEVELOPING.md.
    """
    import statistics

    from soc_ml.ingest import FileSource
    from soc_ml.preprocess import Sessionizer, session_features

    limit = args.limit if args.limit else 1_000_000

    # Read a bounded prefix. We buffer only up to `limit` events so that a
    # 26 GB file costs the same memory as a 26 MB one; the reader is lazy, so
    # the rest of the file is never touched.
    src = FileSource(args.input)
    events = []
    for event in src.read():
        events.append(event)
        if len(events) >= limit:
            break
    truncated = len(events) >= limit

    if not events:
        print(f"[ERROR] no events read from {args.input}", file=sys.stderr)
        return 2

    # Sessionization assumes approximate time order; a multi-worker parser
    # interleaves output, so sort the prefix before grouping rather than
    # counting every file boundary as out-of-order.
    events.sort(key=lambda e: e.timestamp)

    sz = Sessionizer(idle_gap_s=args.idle_gap)
    sessions = list(sz.run(iter(events)))
    if not sessions:
        print("[ERROR] no sessions produced", file=sys.stderr)
        return 1

    counts = [s.event_count for s in sessions]
    durations = [s.duration_s for s in sessions]
    uniques = [len(s.unique_paths) for s in sessions]
    feats = [session_features(s) for s in sessions]
    cvs = [f["session.cv_inter_arrival"] for f in feats if f["session.event_count"] > 2]

    def pct(values: list[float], p: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        idx = min(int(p / 100 * len(ordered)), len(ordered) - 1)
        return ordered[idx]

    if truncated:
        print(f"[NOTE] sampled the first {len(events):,} events (--limit); "
              "this is a prefix, not the whole file")
    print(f"events            : {len(events):,}  ({src.stats.failed} unparseable)")
    print(f"sessions          : {len(sessions):,}")
    print(f"entities          : {len({str(s.entity) for s in sessions}):,}")
    print(f"idle gap          : {args.idle_gap}s")
    print()
    print(f"events/session    : median {statistics.median(counts):.0f}   "
          f"p95 {pct(counts, 95):.0f}   max {max(counts)}")
    print(f"duration (s)      : median {statistics.median(durations):.0f}   "
          f"p95 {pct(durations, 95):.0f}   max {max(durations):.0f}")
    print(f"unique paths      : median {statistics.median(uniques):.0f}   "
          f"p95 {pct(uniques, 95):.0f}   max {max(uniques)}")
    if cvs:
        print(f"inter-arrival CV  : median {statistics.median(cvs):.2f}   "
              f"p05 {pct(cvs, 5):.2f}  (low = machine-regular)")
    print()
    print(f"out-of-order      : {sz.stats.out_of_order}")
    print(f"truncated (seq)   : {sz.stats.truncated}")

    single = sum(1 for c in counts if c == 1)
    share = single / len(sessions)
    print(f"single-event      : {single} ({share:.0%})")
    if share > 0.8:
        print("\n[WARN] most sessions hold a single event — per-session features "
              "(UC-06, UC-10, UC-11) have nothing to aggregate on this input")
    if len(cvs) < 10:
        print("[WARN] very few multi-event sessions — timing features will be noisy")
    return 0


def cmd_lint_config(args: argparse.Namespace) -> int:
    """Enforce that config carries policy only, never detection thresholds."""
    from soc_ml.core import ConfigError, load_config

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"profile      : {cfg.profile.value}")
    print(f"default mode : {cfg.default_mode.value}")
    print(f"source/state : {cfg.source} / {cfg.state}")
    enabled = [uc for uc in cfg.usecases if cfg.is_enabled(uc)]
    print(f"use cases on : {', '.join(sorted(enabled)) or 'none'}")
    for problem in cfg.check_runtime():
        print(f"[WARN] {problem}")
    print("\nRESULT: PASS — policy only, no detection thresholds (FR-62)")
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    """List every discovered plugin."""
    from soc_ml.core import registry

    registry.discover(Path(args.plugin_dir) if args.plugin_dir else None)
    kinds = registry.kinds()
    if not kinds:
        print("no plugins registered yet (Phase 0 scaffold)")
        return 0
    for kind in kinds:
        print(f"\n{kind}:")
        for name, cls in sorted(registry.all(kind).items()):
            print(f"  {name:<20} {cls.description or cls.__name__}")
    return 0


def _resolve_usecase(slug: str):
    """Resolve a use-case slug via the plugin registry (built-ins + drop-ins).

    Returns the class, or None after printing an error that lists what exists —
    the same discovery path for every pipeline command, so a drop-in use case
    under ``plugins/`` works in train/backtest/run without core edits (NFR-12).
    """
    from soc_ml.core import registry

    registry.discover(Path("plugins"))
    try:
        return registry.get("usecase", slug)
    except LookupError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return None


def cmd_backtest(args: argparse.Namespace) -> int:
    """Run the offline backtest for one use case (streaming; FR-71/72)."""
    from soc_ml.evaluation.backtest import run_backtest

    slug = args.uc.replace("-", "_")
    if _resolve_usecase(slug) is None:
        return 3

    try:
        report = run_backtest(
            args.input,
            usecase=slug,
            limit=args.limit,
            train_frac=args.train_frac,
            out_dir=args.out,
            inject_canary=not args.no_canary,
            top_n=args.top,
        )
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    t, s, c = report["train"], report["score"], report["canary"]
    print(f"usecase       : {report['usecase']}  ({report['rule_id']} — {report['title']})")
    print(f"version       : {report['version']}")
    print(f"events        : {report['events_total']:,} over {report['span_hours']}h")
    print(f"train         : {t['events']:,} events -> {t['windows']:,} windows "
          f"(hygiene dropped {t['hygiene_dropped']})")
    print(f"score         : {s['windows']:,} windows over {s['days']} days")
    print(f"alerts        : {s['alerts_delivered']} delivered "
          f"({s['delivered_per_day_per_server']}/day/server, budget "
          f"{s['fp_budget_per_day_per_server']}); {s['alerts_raw']} raw, "
          f"{s['folded']} folded by dedup")
    if c["injected"]:
        verdict = "DETECTED" if c["detected"] else "MISSED"
        print(f"canary        : {verdict}  "
              f"({c['fired']} firing window(s) of {c['windows_seen']} canary window(s))")
    if report["top_alerts"]:
        print("\ntop alerts:")
        for entry in report["top_alerts"]:
            print(f"  [{entry['severity']}] {entry['narrative']}")
    print(f"\nartifacts     : {report['artifacts']['bundle']}")
    print(f"report        : {report['artifacts']['alerts']}")

    if c["injected"] and not c["detected"]:
        print("\nRESULT: FAIL — the pipeline missed the synthetic canary", file=sys.stderr)
        return 1
    print("\nRESULT: PASS")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    """Train a model bundle from historical logs and register it (FR-53)."""
    from datetime import datetime

    from soc_ml.core.plugins import usecase_model_factories
    from soc_ml.ingest.file import FileSource
    from soc_ml.registry.store import ModelRegistry
    from soc_ml.training.trainer import TrainingError, train_bundle
    import soc_ml.models  # noqa: F401

    slug = args.uc.replace("-", "_")
    uc_cls = _resolve_usecase(slug)
    if uc_cls is None:
        return 3
    factories = usecase_model_factories(uc_cls)

    def stream():
        src = FileSource(args.input)
        n = 0
        for event in src.read():
            yield event
            n += 1
            if args.limit and n >= args.limit:
                break

    print(f"training {slug} from {args.input}"
          + (f" (first {args.limit:,} events)" if args.limit else " (all events)"))
    print("note: this reads the input twice (profile, then features) — progress below\n")

    def progress(msg: str) -> None:
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

    try:
        bundle = train_bundle(
            uc_cls, factories, stream, source_desc=str(args.input), log=progress
        )
    except TrainingError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    print()

    registry = ModelRegistry(args.out)
    registry.save_bundle(bundle)
    meta = bundle.metadata
    print(f"version       : {bundle.version}")
    print(f"train events  : {meta['train_events']:,} -> {meta['train_windows']:,} windows")
    print(f"hygiene       : dropped {meta['hygiene']['windows_dropped']} anomalous windows")
    print(f"servers       : {len(bundle.profile.servers())}")
    print(f"bundle        : {registry.bundle_dir(slug, bundle.version)}")

    if args.promote:
        registry.promote(slug, bundle.version)
        print(f"\npromoted {bundle.version} to CURRENT (serving)")
    else:
        registry.set_candidate(slug, bundle.version)
        current = registry.current_version(slug)
        print(f"\nregistered as CANDIDATE (current serving: {current or 'none'})")
        print(f"promote with: soc-ml promote --uc {slug}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run the live detection pipeline (streaming, restart-safe)."""
    from soc_ml.core import load_config, registry
    from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig

    registry.discover(Path("plugins"))  # drop-in use cases work in run too
    slugs = tuple(
        s.strip().replace("-", "_") for s in args.uc.split(",") if s.strip()
    )
    input_dir = args.input
    if input_dir is None:
        try:
            cfg = load_config(args.config)
            input_dir = str(cfg.input_dir) if cfg.input_dir else None
        except Exception:
            input_dir = None
    if not input_dir:
        print("[ERROR] no input: pass --input <dir> or set input_dir in config",
              file=sys.stderr)
        return 2

    rc = RuntimeConfig(
        usecases=slugs,
        input_dir=input_dir,
        data_dir=args.out,
        mode=args.mode,
        follow=not args.once,
        allow_cold_start=args.allow_cold_start,
        warmup_events=args.warmup_events,
    )
    try:
        return DetectionRuntime(rc).run()
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


def cmd_promote(args: argparse.Namespace) -> int:
    """Promote a candidate (or a named version) to serving (FR-55 gate = human)."""
    from soc_ml.registry.store import ModelRegistry

    slug = args.uc.replace("-", "_")
    registry = ModelRegistry(args.out)
    try:
        if args.rollback:
            target = registry.rollback(slug)
            print(f"rolled back {slug} -> {target}")
        else:
            target = registry.promote(slug, args.version)
            print(f"promoted {slug} -> {target} (now serving)")
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show registry state and the latest live health for a use case."""
    import json as _json

    from soc_ml.registry.store import ModelRegistry

    slug = args.uc.replace("-", "_")
    registry = ModelRegistry(args.out)
    desc = registry.describe(slug)
    print(f"usecase   : {slug}")
    print(f"serving   : {desc['current'] or '(none — not deployed)'}")
    print(f"candidate : {desc['candidate'] or '(none)'}")
    print(f"versions  : {', '.join(desc['versions']) or '(none)'}")

    health_path = Path(args.out) / "state" / f"{slug}_health.json"
    if health_path.exists():
        h = _json.loads(health_path.read_text())
        print("\nlive health:")
        print(f"  as of      : {h.get('timestamp')}")
        print(f"  mode       : {h.get('mode')}   bundle {h.get('bundle_version')}")
        print(f"  uptime     : {h.get('uptime_s')}s   eps {h.get('eps')}")
        print(f"  events     : {h.get('events'):,}   windows {h.get('windows'):,}")
        print(f"  delivered  : {h.get('alerts_delivered')}   folded {h.get('alerts_folded')}")
        print(f"  drift      : {h.get('last_drift_band')}")
    else:
        print("\n(no live health yet — runtime has not run)")
    return 0


def cmd_not_implemented(args: argparse.Namespace) -> int:
    print(f"[ERROR] '{args.command}' {_NOT_YET}", file=sys.stderr)
    return 3


# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soc-ml",
        description="Self-learning behavioral analytics for web traffic.",
    )
    p.add_argument("--config", default="config/default.yaml", help="config file")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="check input against the event contract")
    v.add_argument("--input", required=True, help="parser output file or directory")
    v.add_argument("--limit", type=int, default=0, help="stop after N events (0 = all)")
    v.add_argument("--strict", action="store_true",
                   help="treat data-quality warnings as failure (for CI gating)")
    v.set_defaults(func=cmd_validate)

    s = sub.add_parser("sessions", help="sessionize input and report visit shape")
    s.add_argument("--input", required=True, help="parser output file or directory")
    s.add_argument("--idle-gap", type=int, default=1800, dest="idle_gap",
                   help="seconds of inactivity that end a session (default 1800)")
    s.add_argument("--limit", type=int, default=0,
                   help="max events to sample (0 = default cap 1,000,000). "
                        "A prefix — keeps memory bounded on multi-GB files.")
    s.set_defaults(func=cmd_sessions)

    lc = sub.add_parser("lint-config", help="verify config carries policy only")
    lc.set_defaults(func=cmd_lint_config)

    pl = sub.add_parser("plugins", help="list discovered plugins")
    pl.add_argument("--plugin-dir", default="plugins")
    pl.set_defaults(func=cmd_plugins)

    b = sub.add_parser("backtest", help="run offline over historical logs and report metrics")
    b.add_argument("--input", required=True, help="parser output file or directory")
    b.add_argument("--uc", default="web_recon",
                   help="use case slug (see docs/NAMING.md; accepts - or _)")
    b.add_argument("--limit", type=int, default=0,
                   help="max events to read per pass (0 = all; USE THIS on multi-GB files)")
    b.add_argument("--train-frac", type=float, default=0.6, dest="train_frac",
                   help="chronological fraction used for training (default 0.6)")
    b.add_argument("--out", default="data", help="artifact/report output root")
    b.add_argument("--no-canary", action="store_true",
                   help="skip the synthetic detection canary")
    b.add_argument("--top", type=int, default=5, help="top alerts to show")
    b.set_defaults(func=cmd_backtest)

    tr = sub.add_parser("train", help="train a model bundle from historical logs and register it")
    tr.add_argument("--input", required=True, help="historical parser output file or dir")
    tr.add_argument("--uc", default="web_recon", help="use case slug")
    tr.add_argument("--limit", type=int, default=0, help="max events (0 = all; USE on multi-GB files)")
    tr.add_argument("--out", default="data", help="registry/data root")
    tr.add_argument("--promote", action="store_true",
                    help="promote immediately to serving (else registered as candidate)")
    tr.set_defaults(func=cmd_train)

    rn = sub.add_parser("run", help="run the live detection pipeline (streaming)")
    rn.add_argument("--input", help="parser output dir to tail (default: config input_dir)")
    rn.add_argument("--uc", default="web_recon",
                    help="use case slug(s), comma-separated; scored per window "
                         "in dependency order (e.g. bot_detection,web_recon)")
    rn.add_argument("--mode", default="shadow", choices=["observe", "shadow", "live"],
                    help="observe/shadow = record only; live = deliver alerts")
    rn.add_argument("--out", default="data", help="registry/data root")
    rn.add_argument("--once", action="store_true",
                    help="process current data then exit (don't follow)")
    rn.add_argument("--allow-cold-start", action="store_true", dest="allow_cold_start",
                    help="if no model exists, learn one from live traffic first")
    rn.add_argument("--warmup-events", type=int, default=200_000, dest="warmup_events",
                    help="cold-start warmup size (default 200,000)")
    rn.set_defaults(func=cmd_run)

    pr = sub.add_parser("promote", help="promote a candidate model to serving (or rollback)")
    pr.add_argument("--uc", default="web_recon", help="use case slug")
    pr.add_argument("--version", help="specific version (default: the current candidate)")
    pr.add_argument("--rollback", action="store_true", help="roll back to the previous version")
    pr.add_argument("--out", default="data", help="registry/data root")
    pr.set_defaults(func=cmd_promote)

    st = sub.add_parser("status", help="show registry state and live health")
    st.add_argument("--uc", default="web_recon", help="use case slug")
    st.add_argument("--out", default="data", help="registry/data root")
    st.set_defaults(func=cmd_status)

    sub.add_parser("version", help="show version").set_defaults(
        func=lambda a: (print(_version()), 0)[1]
    )
    return p


def _version() -> str:
    try:
        from importlib.metadata import version

        return f"foss-soc-ml {version('foss-soc-ml')}"
    except Exception:
        return "foss-soc-ml 0.1.0.dev0 (not installed)"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
