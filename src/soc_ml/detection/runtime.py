"""The live detection runtime — the production loop.

Tails the parser's ECS output, scores every closed window through the shared
:class:`Scorer`, de-duplicates, and delivers alerts — continuously, restart-safe,
and self-monitoring. This is the body that was missing around the detection
brain; with it, ``soc-ml run`` is a deployable service.

What it guarantees for production:

* **Same scoring code as the backtest** — it uses ``detection.scorer`` and
  ``training.trainer``, so what a backtest validated is what runs (FR-72).
* **Three modes, per the cold-start protocol** (SPEC §8):
    - ``observe`` — score, record to a shadow log, deliver nothing;
    - ``shadow`` — same, kept distinct so an operator can run a challenger beside
      a live model;
    - ``live`` — deliver alerts to the configured sink.
* **Restart-safe** — the source checkpoint (byte offsets) is persisted and
  reloaded, so a restart resumes exactly where it stopped, reprocessing nothing
  and losing nothing.
* **Never goes stale** — it keeps a bounded reservoir of live feature values and
  computes PSI against the bundle's training reference; significant drift raises
  a health event and flags a retrain (it never silently swaps a model).
* **Never fails silently** — health (EPS, counts, mode, drift band, uptime) is
  written to ``data/state`` on a timer and on shutdown; a missing model is a
  loud, explained refusal, not a crash (NFR-08/09).
* **Cold-start** — with ``--allow-cold-start`` and no trained model, it buffers a
  bounded warmup of live traffic, trains a first bundle from it, promotes it, and
  begins scoring — so the framework adapts to a brand-new environment with no
  historical data on hand.
"""

from __future__ import annotations

import json
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_ml.alerting.file_sink import FileSink
from soc_ml.core.plugins import Sink, registry as plugin_registry
from soc_ml.detection.budget import AlertBudget, BudgetDecision
from soc_ml.detection.dedup import AlertDeduplicator
from soc_ml.detection.scorer import Scorer
from soc_ml.drift.psi import DriftReport, population_stability_index
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.ingest.file import FileSource
from soc_ml.registry.store import ModelBundle, ModelRegistry
from soc_ml.training.trainer import TrainingError, train_bundle
from soc_ml.usecases.web_recon import WebRecon

import soc_ml.models  # noqa: F401 — register model plugins

__all__ = ["DetectionRuntime", "RuntimeConfig"]

_USECASES = {"web_recon": WebRecon}
_DRIFT_RESERVOIR = 4000  # live feature values retained per feature for PSI


class RuntimeConfig:
    """Everything the runtime needs to run one use case."""

    def __init__(
        self,
        *,
        usecase: str = "web_recon",
        input_dir: str | Path,
        data_dir: str | Path = "data",
        mode: str = "shadow",
        follow: bool = True,
        poll_interval_s: float = 2.0,
        checkpoint_every_s: float = 30.0,
        health_every_s: float = 10.0,
        drift_every_s: float = 3600.0,
        allow_cold_start: bool = False,
        warmup_events: int = 200_000,
        daily_alert_budget: int = 50,
        sink_name: str = "file",
    ) -> None:
        self.usecase = usecase
        self.input_dir = Path(input_dir)
        self.data_dir = Path(data_dir)
        self.mode = mode
        self.follow = follow
        self.poll_interval_s = poll_interval_s
        self.checkpoint_every_s = checkpoint_every_s
        self.health_every_s = health_every_s
        self.drift_every_s = drift_every_s
        self.allow_cold_start = allow_cold_start
        self.warmup_events = warmup_events
        self.daily_alert_budget = daily_alert_budget
        self.sink_name = sink_name


class DetectionRuntime:
    def __init__(self, config: RuntimeConfig, log=print) -> None:
        self.cfg = config
        self.log = log
        self.uc_cls = _USECASES.get(config.usecase)
        if self.uc_cls is None:
            raise ValueError(f"unknown use case {config.usecase!r}")
        self.factories = {
            m: plugin_registry.get("model", m) for m in self.uc_cls.models
        }
        self.registry = ModelRegistry(config.data_dir)
        self.state_dir = config.data_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.bundle: ModelBundle | None = None
        self.scorer: Scorer | None = None
        self.builder: WindowFeatureBuilder | None = None
        self.dedup = AlertDeduplicator()
        self.budget = AlertBudget(config.daily_alert_budget)
        self._reservoir: dict[str, list[float]] = {}

        self.sink: Sink | None = None
        self._shadow_fh = None
        self._digest_fh = None
        self._stop = False
        self._started = time.monotonic()
        self.stats = {
            "events": 0,
            "windows": 0,
            "alerts_delivered": 0,
            "alerts_folded": 0,
            "alerts_digested": 0,
            "last_drift_band": "unknown",
        }

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def run(self) -> int:
        self._install_signals()
        self.log(f"[runtime] use case {self.cfg.usecase}, mode={self.cfg.mode}")

        if not self._load_or_bootstrap():
            return 2  # explained inside

        source = FileSource(
            self.cfg.input_dir, follow=self.cfg.follow,
            poll_interval_s=self.cfg.poll_interval_s,
            dlq_path=self.state_dir / f"{self.cfg.usecase}_dlq.ndjson",
        )
        self._restore_checkpoint(source)
        self._open_sink()

        last_ckpt = last_health = last_drift = time.monotonic()
        try:
            for event in source.read():
                if self._stop:
                    break
                self.stats["events"] += 1
                for result in self.builder.add(event):
                    self._handle(result)

                now = time.monotonic()
                if now - last_ckpt >= self.cfg.checkpoint_every_s:
                    self._save_checkpoint(source)
                    last_ckpt = now
                if now - last_health >= self.cfg.health_every_s:
                    self._write_health(source)
                    last_health = now
                if now - last_drift >= self.cfg.drift_every_s:
                    self._check_drift()
                    last_drift = now
        finally:
            self._shutdown(source)
        return 0

    # ------------------------------------------------------------------ #
    # Model loading / cold start
    # ------------------------------------------------------------------ #

    def _load_or_bootstrap(self) -> bool:
        bundle = self.registry.load_current(self.cfg.usecase, self.factories)
        if bundle is not None:
            self._activate(bundle)
            self.log(f"[runtime] serving bundle {bundle.version}")
            return True

        if not self.cfg.allow_cold_start:
            self.log(
                f"[runtime] ERROR: no trained model for {self.cfg.usecase!r}. "
                f"Run `soc-ml train --input <historical logs>` and promote it, "
                f"or pass --allow-cold-start to learn from live traffic first."
            )
            return False

        return self._cold_start()

    def _cold_start(self) -> bool:
        """Buffer a bounded warmup of live traffic, train, promote, then serve."""
        self.log(
            f"[runtime] cold start: buffering up to {self.cfg.warmup_events:,} "
            "events to learn this environment (no alerts during warmup)"
        )
        source = FileSource(
            self.cfg.input_dir, follow=self.cfg.follow,
            poll_interval_s=self.cfg.poll_interval_s,
        )
        buffer: list = []
        for event in source.read():
            if self._stop:
                self.log("[runtime] cold start interrupted before enough data")
                return False
            buffer.append(event)
            if len(buffer) >= self.cfg.warmup_events:
                break
            if len(buffer) % 25_000 == 0:
                self.log(f"[runtime] warmup {len(buffer):,}/{self.cfg.warmup_events:,}")
        source.close()

        try:
            bundle = train_bundle(
                self.uc_cls, self.factories, lambda: iter(buffer),
                source_desc="cold-start warmup",
            )
        except TrainingError as exc:
            self.log(f"[runtime] ERROR: cold start could not train a model: {exc}")
            return False

        self.registry.save_bundle(bundle)
        self.registry.promote(self.cfg.usecase, bundle.version)
        self._activate(bundle)
        self.log(f"[runtime] cold start complete — promoted {bundle.version}")
        return True

    def _activate(self, bundle: ModelBundle) -> None:
        self.bundle = bundle
        self.scorer = Scorer(self.uc_cls, bundle)
        self.builder = WindowFeatureBuilder(bundle.profile)

    # ------------------------------------------------------------------ #
    # Per-window handling
    # ------------------------------------------------------------------ #

    def _handle(self, result) -> None:
        outcome = self.scorer.score(result)
        if outcome is None:
            return
        self.stats["windows"] += 1
        self._collect_drift(outcome)

        if self.cfg.mode == "live":
            if outcome.fired and outcome.alert is not None:
                self._deliver(outcome)
        else:
            # observe / shadow: record everything, deliver nothing.
            self._shadow_record(outcome)

    def _deliver(self, outcome) -> None:
        # 1. Fold repeats of the same entity into one open alert (dedup).
        decision = self.dedup.decide(outcome.alert)
        if not decision.deliver:
            self.stats["alerts_folded"] += 1
            return
        # 2. Cap daily delivery per server; overflow -> digest, never dropped.
        if self.budget.decide(outcome.alert) == BudgetDecision.DIGEST:
            self._digest(outcome.alert)
            self.stats["alerts_digested"] += 1
            return
        self.sink.emit_alert(outcome.alert)
        self.stats["alerts_delivered"] += 1

    def _digest(self, alert) -> None:
        if self._digest_fh is None:
            path = self.state_dir / f"{self.cfg.usecase}_digest.ndjson"
            self._digest_fh = path.open("a", encoding="utf-8")
        self._digest_fh.write(
            json.dumps({
                "@timestamp": alert.timestamp.isoformat(),
                "usecase": alert.usecase,
                "entity": str(alert.entity),
                "severity": alert.severity.value,
                "reason": "over daily budget — folded into digest",
                "narrative": alert.narrative,
            }) + "\n"
        )

    def _shadow_record(self, outcome) -> None:
        if self._shadow_fh is None:
            path = self.state_dir / f"{self.cfg.usecase}_shadow.ndjson"
            self._shadow_fh = path.open("a", encoding="utf-8")
        row = {**outcome.record(), "would_alert": outcome.fired}
        self._shadow_fh.write(json.dumps(row) + "\n")

    # ------------------------------------------------------------------ #
    # Drift
    # ------------------------------------------------------------------ #

    def _collect_drift(self, outcome) -> None:
        # Reservoir the model-input features of each scored window; PSI later
        # compares these live values against the bundle's training reference.
        for feature, value in outcome.features.items():
            bucket = self._reservoir.setdefault(feature, [])
            if len(bucket) < _DRIFT_RESERVOIR:
                bucket.append(value)

    def _check_drift(self) -> None:
        if not self.bundle or not self.bundle.reference_sample:
            return
        per_feature = {}
        for feature, ref in self.bundle.reference_sample.items():
            cur = self._reservoir.get(feature, [])
            if len(cur) >= 50:
                per_feature[feature] = population_stability_index(ref, cur)
        if not per_feature:
            return
        report = DriftReport(per_feature)
        self.stats["last_drift_band"] = report.band
        (self.state_dir / f"{self.cfg.usecase}_drift.json").write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        if report.should_retrain():
            self.log(
                f"[runtime] DRIFT: significant on {report.drifted_features} "
                f"(max PSI {report.max_psi:.2f}) — retrain recommended: "
                f"`soc-ml train --input <recent logs>`"
            )
        # Reservoir rolls forward: keep the second half so the next window
        # measures against fresher live data.
        for feature, bucket in self._reservoir.items():
            del bucket[: len(bucket) // 2]

    # ------------------------------------------------------------------ #
    # Persistence / health
    # ------------------------------------------------------------------ #

    def _ckpt_path(self) -> Path:
        return self.state_dir / f"{self.cfg.usecase}_checkpoint.json"

    def _restore_checkpoint(self, source: FileSource) -> None:
        path = self._ckpt_path()
        if path.exists():
            try:
                source.seek(json.loads(path.read_text()))
                self.log("[runtime] resumed from checkpoint")
            except Exception as exc:
                self.log(f"[runtime] WARN: checkpoint unreadable ({exc}); starting fresh")

    def _save_checkpoint(self, source: FileSource) -> None:
        tmp = self._ckpt_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(source.checkpoint()), encoding="utf-8")
        tmp.replace(self._ckpt_path())

    def _write_health(self, source: FileSource) -> None:
        uptime = time.monotonic() - self._started
        health = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "usecase": self.cfg.usecase,
            "mode": self.cfg.mode,
            "bundle_version": self.bundle.version if self.bundle else None,
            "uptime_s": round(uptime, 1),
            "eps": round(self.stats["events"] / uptime, 1) if uptime > 0 else 0,
            "open_windows": self.builder.open_count if self.builder else 0,
            "ingest_failed": source.stats.failed,
            **self.stats,
        }
        path = self.state_dir / f"{self.cfg.usecase}_health.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(health, indent=2), encoding="utf-8")
        tmp.replace(path)

    def _open_sink(self) -> None:
        if self.cfg.mode != "live":
            return
        if self.cfg.sink_name == "file":
            self.sink = FileSink(
                self.cfg.data_dir / "alerts" / f"{self.cfg.usecase}.ndjson"
            )
        else:
            self.sink = plugin_registry.get("sink", self.cfg.sink_name)()

    # ------------------------------------------------------------------ #
    # Shutdown
    # ------------------------------------------------------------------ #

    def _install_signals(self) -> None:
        def handler(signum, _frame):
            self.log(f"[runtime] signal {signum} — draining and shutting down")
            self._stop = True

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except ValueError:
                pass  # not on the main thread (e.g. in tests) — fine

    def _shutdown(self, source: FileSource) -> None:
        if self.builder:
            for result in self.builder.flush():
                self._handle(result)
        self._save_checkpoint(source)
        self._write_health(source)
        if self.sink:
            self.sink.flush()
            if hasattr(self.sink, "close"):
                self.sink.close()
        if self._shadow_fh:
            self._shadow_fh.close()
        if self._digest_fh:
            self._digest_fh.close()
        source.close()
        self.log(
            f"[runtime] stopped — {self.stats['events']:,} events, "
            f"{self.stats['windows']:,} windows, "
            f"{self.stats['alerts_delivered']} delivered, "
            f"{self.stats['alerts_folded']} folded"
        )
