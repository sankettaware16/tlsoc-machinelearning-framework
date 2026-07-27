"""Backtest harness — evaluation over the SAME code that serves production.

It trains a bundle (via ``training.trainer``), then scores held-out traffic (via
``detection.scorer``) — the exact modules the live runtime uses. There is no
separate evaluation reimplementation, so a green backtest means the production
path works (FR-72).

Chronological, streaming, zero-infra:

    pass 0  scan     -> time span -> train/score cutoff
    train            -> trainer.train_bundle over the training slice
    save             -> registry (versioned bundle)
    score            -> scorer over the held-out slice + the injected canary
                        -> dedup -> alerts + full score log + report
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc_ml.alerting.file_sink import FileSink
from soc_ml.core.plugins import registry as plugin_registry
from soc_ml.core.contracts import Event
from soc_ml.detection.dedup import AlertDeduplicator
from soc_ml.detection.scorer import Scorer
from soc_ml.evaluation.canary import CANARY_IP, canary_events
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.ingest.file import FileSource
from soc_ml.registry.store import ModelRegistry
from soc_ml.training.trainer import TrainingError, train_bundle
from soc_ml.usecases.web_recon import WebRecon

# ensure model plugins are registered
import soc_ml.models  # noqa: F401  isort: skip

__all__ = ["run_backtest"]

_USECASES = {"web_recon": WebRecon}


def _events(input_path: str | Path, limit: int) -> Iterator[Event]:
    source = FileSource(input_path)
    read = 0
    for event in source.read():
        yield event
        read += 1
        if limit and read >= limit:
            break


def _merge_by_time(main: Iterator[Event], extras: list[Event]) -> Iterator[Event]:
    queue = sorted(extras, key=lambda e: e.timestamp)
    idx = 0
    for event in main:
        while idx < len(queue) and queue[idx].timestamp <= event.timestamp:
            yield queue[idx]
            idx += 1
        yield event
    while idx < len(queue):
        yield queue[idx]
        idx += 1


def run_backtest(
    input_path: str | Path,
    *,
    usecase: str = "web_recon",
    limit: int = 0,
    train_frac: float = 0.6,
    out_dir: str | Path = "data",
    inject_canary: bool = True,
    top_n: int = 5,
) -> dict[str, Any]:
    uc_cls = _USECASES.get(usecase)
    if uc_cls is None:
        raise ValueError(f"unknown use case {usecase!r}")
    factories = {m: plugin_registry.get("model", m) for m in uc_cls.models}
    out_dir = Path(out_dir)

    # ---- pass 0: span -> cutoff ---------------------------------------- #
    t_min = t_max = None
    total = 0
    for event in _events(input_path, limit):
        total += 1
        ts = event.timestamp
        t_min = ts if t_min is None or ts < t_min else t_min
        t_max = ts if t_max is None or ts > t_max else t_max
    if not total or t_min is None or t_max is None:
        raise ValueError(f"no events readable from {input_path}")
    span = (t_max - t_min).total_seconds()
    if span <= 0:
        raise ValueError(
            "input has no usable time span — every event shares one timestamp. "
            "Run `soc-ml validate` (this is usually ingest-time data)."
        )
    cutoff = t_min + timedelta(seconds=span * train_frac)

    # ---- train --------------------------------------------------------- #
    def train_stream() -> Iterator[Event]:
        for event in _events(input_path, limit):
            if event.timestamp < cutoff:
                yield event

    try:
        bundle = train_bundle(
            uc_cls, factories, train_stream, source_desc=f"backtest:{input_path}"
        )
    except TrainingError as exc:
        raise ValueError(str(exc)) from exc

    registry = ModelRegistry(out_dir)
    bundle_dir = registry.save_bundle(bundle)

    # ---- score held-out + canary --------------------------------------- #
    scorer = Scorer(uc_cls, bundle)
    builder = WindowFeatureBuilder(bundle.profile)
    dedup = AlertDeduplicator()

    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{bundle.usecase}_{bundle.version}"
    alert_sink = FileSink(reports_dir / f"alerts_{tag}.ndjson")
    scores_fh = (reports_dir / f"scores_{tag}.ndjson").open("w", encoding="utf-8")

    canary: list[Event] = []
    if inject_canary:
        server = bundle.profile.dominant_server() or "_"
        canary = canary_events(server, cutoff + timedelta(seconds=60))

    scored = alerts_delivered = alerts_raw = 0
    canary_windows = canary_fired = 0
    top_alerts: list[tuple[float, dict[str, Any]]] = []

    def handle(result) -> None:
        nonlocal scored, alerts_delivered, alerts_raw, canary_windows, canary_fired
        is_canary = result.vector.entity.ip == CANARY_IP
        outcome = scorer.score(result, synthetic=is_canary)
        if outcome is None:
            return
        scored += 1
        canary_windows += int(is_canary)
        scores_fh.write(json.dumps({**outcome.record(), "canary": is_canary}) + "\n")
        if not outcome.fired:
            return
        alerts_raw += 1
        canary_fired += int(is_canary)
        decision = dedup.decide(outcome.alert)
        if decision.deliver:
            alerts_delivered += 1
            alert_sink.emit_alert(outcome.alert)
            if not is_canary:
                top_alerts.append(
                    (outcome.fused_percentile,
                     {"narrative": outcome.alert.narrative,
                      "severity": outcome.alert.severity.value})
                )

    scoring = (e for e in _events(input_path, limit) if e.timestamp >= cutoff)
    for event in _merge_by_time(scoring, canary):
        for result in builder.add(event):
            handle(result)
    for result in builder.flush():
        handle(result)

    alert_sink.flush()
    alert_sink.close()
    scores_fh.close()

    # ---- report -------------------------------------------------------- #
    score_days = max((t_max - cutoff).total_seconds() / 86400.0, 1e-9)
    n_servers = max(len(bundle.profile.servers()), 1)
    top_alerts.sort(key=lambda p: p[0], reverse=True)
    report = {
        "usecase": bundle.usecase,
        "rule_id": bundle.metadata["rule_id"],
        "title": bundle.metadata["title"],
        "version": bundle.version,
        "input": str(input_path),
        "events_total": total,
        "span_hours": round(span / 3600.0, 2),
        "cutoff": cutoff.isoformat(),
        "train": {
            "events": bundle.metadata["train_events"],
            "windows": bundle.metadata["train_windows"],
            "hygiene_dropped": bundle.metadata["hygiene"]["windows_dropped"],
        },
        "score": {
            "windows": scored,
            "days": round(score_days, 3),
            "alerts_raw": alerts_raw,
            "alerts_delivered": alerts_delivered,
            "folded": dedup.stats["folded"],
            "delivered_per_day_per_server": round(
                (alerts_delivered - canary_delivered(dedup, canary_fired))
                / score_days / n_servers, 2
            ),
            "fp_budget_per_day_per_server": 3,
        },
        "canary": {
            "injected": bool(canary),
            "windows_seen": canary_windows,
            "fired": canary_fired,
            "detected": canary_fired > 0,
        },
        "top_alerts": [e for _, e in top_alerts[:top_n]],
        "artifacts": {
            "bundle": str(bundle_dir),
            "alerts": str(alert_sink.path),
            "scores": str(reports_dir / f"scores_{tag}.ndjson"),
        },
    }
    (reports_dir / f"report_{tag}.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def canary_delivered(dedup: AlertDeduplicator, canary_fired: int) -> int:
    """At most one delivered alert belongs to the canary entity."""
    return 1 if canary_fired else 0
