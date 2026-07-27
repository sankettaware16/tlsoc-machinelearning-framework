"""The live detection runtime — the production loop.

Tails the parser's ECS output, scores every closed window through the shared
:class:`Scorer`, de-duplicates, and delivers alerts — continuously, restart-safe,
and self-monitoring. This is the body that was missing around the detection
brain; with it, ``soc-ml run`` is a deployable service.

What it guarantees for production:

* **Same scoring code as the backtest** — it uses ``detection.scorer`` and
  ``training.trainer``, so what a backtest validated is what runs (FR-72).
* **N use cases per window, in dependency order** — one runtime scores every
  configured use case on the same event stream. A use case that exports a
  per-entity signal (bot_detection) is scored before its consumers (web_recon),
  per ``UseCase.depends_on``. Each use case keeps its own bundle, dedup,
  budget, drift reservoir, and per-slug health/shadow/alert files — one
  detector's noise can never spend another's budget.
* **Three modes, per the cold-start protocol** (SPEC §8):
    - ``observe`` — score, record to a shadow log, deliver nothing;
    - ``shadow`` — same, kept distinct so an operator can run a challenger beside
      a live model;
    - ``live`` — deliver alerts to the configured sink.
* **Restart-safe** — the source checkpoint (byte offsets) is persisted and
  reloaded, so a restart resumes exactly where it stopped, reprocessing nothing
  and losing nothing. The checkpoint is keyed by the *set* of use cases this
  runtime serves; changing the set starts a fresh read (never a corrupt resume).
* **Never goes stale** — it keeps a bounded reservoir of live feature values per
  use case and computes PSI against each bundle's training reference;
  significant drift raises a health event and flags a retrain (it never silently
  swaps a model).
* **Never fails silently** — per-use-case health (EPS, counts, mode, drift band,
  uptime) is written to ``data/state`` on a timer and on shutdown; a missing
  model is a loud, explained refusal, not a crash (NFR-08/09).
* **Cold-start** — with ``--allow-cold-start`` and missing trained models, it
  buffers a bounded warmup of live traffic once, trains a first bundle for every
  use case that lacks one, promotes them, and begins scoring — so the framework
  adapts to a brand-new environment with no historical data on hand.
"""

from __future__ import annotations

import json
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from soc_ml.alerting.file_sink import FileSink
from soc_ml.core.plugins import Sink, UseCase, registry as plugin_registry
from soc_ml.detection.budget import AlertBudget, BudgetDecision
from soc_ml.detection.dedup import AlertDeduplicator
from soc_ml.detection.scorer import Scorer
from soc_ml.drift.psi import DriftReport, population_stability_index
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.ingest.file import FileSource
from soc_ml.registry.store import ModelBundle, ModelRegistry
from soc_ml.training.trainer import TrainingError, train_bundle
from soc_ml.usecases import dependency_order

import soc_ml.models  # noqa: F401 — register model plugins
import soc_ml.usecases  # noqa: F401 — register use-case plugins

__all__ = ["DetectionRuntime", "RuntimeConfig"]

_DRIFT_RESERVOIR = 4000  # live feature values retained per feature for PSI


class RuntimeConfig:
    """Everything the runtime needs to run one set of use cases."""

    def __init__(
        self,
        *,
        usecases: str | tuple[str, ...] = ("web_recon",),
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
        daily_alert_budget: int | None = None,
        sink_name: str = "file",
    ) -> None:
        self.usecases = (usecases,) if isinstance(usecases, str) else tuple(usecases)
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
        #: None = each use case's own class default (delivery policy, FR-34).
        self.daily_alert_budget = daily_alert_budget
        self.sink_name = sink_name

    @property
    def set_key(self) -> str:
        """Stable name for this runtime's use-case set — keys shared state files.

        Sorted, so ``--uc a,b`` and ``--uc b,a`` resume the same checkpoint. A
        single-use-case runtime keeps its historical key (``web_recon_...``),
        so existing deployments resume seamlessly after upgrade.
        """
        return "+".join(sorted(self.usecases))


class _UseCaseRunner:
    """One use case's private state inside the shared runtime loop.

    Isolation is the point: bundle, feature builder, dedup, budget, drift
    reservoir, and output files are all per use case, so detectors never
    contend for each other's cooldowns or budgets and every artifact on disk
    is keyed by slug.
    """

    def __init__(self, uc_cls: type[UseCase], daily_budget_override: int | None) -> None:
        self.uc_cls = uc_cls
        self.slug = uc_cls.name
        self.factories = {m: plugin_registry.get("model", m) for m in uc_cls.models}
        self.bundle: ModelBundle | None = None
        self.scorer: Scorer | None = None
        self.builder: WindowFeatureBuilder | None = None
        self.dedup = AlertDeduplicator()
        self.budget = AlertBudget(
            daily_budget_override
            if daily_budget_override is not None
            else uc_cls.daily_alert_budget
        )
        self.reservoir: dict[str, list[float]] = {}
        self.sink: Sink | None = None
        self.shadow_fh = None
        self.digest_fh = None
        self.stats = {
            "windows": 0,
            "alerts_delivered": 0,
            "alerts_folded": 0,
            "alerts_digested": 0,
            "last_drift_band": "unknown",
        }

    def activate(self, bundle: ModelBundle) -> None:
        self.bundle = bundle
        self.scorer = Scorer(self.uc_cls, bundle)
        self.builder = WindowFeatureBuilder(bundle.profile)


class DetectionRuntime:
    def __init__(self, config: RuntimeConfig, log=print) -> None:
        self.cfg = config
        self.log = log
        classes = []
        for slug in config.usecases:
            cls = plugin_registry.all("usecase").get(slug)
            if cls is None:
                available = ", ".join(sorted(plugin_registry.all("usecase"))) or "none"
                raise ValueError(
                    f"unknown use case {slug!r}; available: {available}"
                )
            classes.append(cls)
        # Scoring order is the dependency order: exporters before consumers.
        self.runners = [
            _UseCaseRunner(cls, config.daily_alert_budget)
            for cls in dependency_order(classes)
        ]
        self.registry = ModelRegistry(config.data_dir)
        self.state_dir = config.data_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self._stop = False
        self._started = time.monotonic()
        self.stats = {
            "events": 0,
            "windows": 0,
            "alerts_delivered": 0,
            "alerts_folded": 0,
            "alerts_digested": 0,
        }

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def run(self) -> int:
        self._install_signals()
        order = ", ".join(r.slug for r in self.runners)
        self.log(f"[runtime] use cases {order} (dependency order), mode={self.cfg.mode}")

        if not self._load_or_bootstrap():
            return 2  # explained inside

        source = FileSource(
            self.cfg.input_dir, follow=self.cfg.follow,
            poll_interval_s=self.cfg.poll_interval_s,
            dlq_path=self.state_dir / f"{self.cfg.set_key}_dlq.ndjson",
        )
        self._restore_checkpoint(source)
        if self.cfg.mode == "live":
            for runner in self.runners:
                self._open_sink(runner)

        last_ckpt = last_health = last_drift = time.monotonic()
        try:
            for event in source.read():
                if self._stop:
                    break
                self.stats["events"] += 1
                # Every runner sees every event; closed windows are handled
                # immediately per runner, so an exporter's window for a bucket
                # is scored before any consumer's window for that same bucket.
                for runner in self.runners:
                    for result in runner.builder.add(event):
                        self._handle(runner, result)

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
        missing: list[_UseCaseRunner] = []
        for runner in self.runners:
            bundle = self.registry.load_current(runner.slug, runner.factories)
            if bundle is not None:
                runner.activate(bundle)
                self.log(f"[runtime] {runner.slug}: serving bundle {bundle.version}")
            else:
                missing.append(runner)
        if not missing:
            return True

        slugs = ", ".join(r.slug for r in missing)
        if not self.cfg.allow_cold_start:
            self.log(
                f"[runtime] ERROR: no trained model for {slugs}. "
                f"Run `soc-ml train --uc <slug> --input <historical logs>` and "
                f"promote it, or pass --allow-cold-start to learn from live "
                f"traffic first."
            )
            return False

        return self._cold_start(missing)

    def _cold_start(self, missing: list[_UseCaseRunner]) -> bool:
        """Buffer one bounded warmup of live traffic, then train every missing
        use case from it, promote, and serve."""
        self.log(
            f"[runtime] cold start ({', '.join(r.slug for r in missing)}): "
            f"buffering up to {self.cfg.warmup_events:,} events to learn this "
            "environment (no alerts during warmup)"
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

        for runner in missing:
            try:
                bundle = train_bundle(
                    runner.uc_cls, runner.factories, lambda: iter(buffer),
                    source_desc="cold-start warmup",
                )
            except TrainingError as exc:
                self.log(
                    f"[runtime] ERROR: cold start could not train "
                    f"{runner.slug}: {exc}"
                )
                return False
            self.registry.save_bundle(bundle)
            self.registry.promote(runner.slug, bundle.version)
            runner.activate(bundle)
            self.log(f"[runtime] cold start: promoted {runner.slug} {bundle.version}")
        return True

    # ------------------------------------------------------------------ #
    # Per-window handling
    # ------------------------------------------------------------------ #

    def _handle(self, runner: _UseCaseRunner, result) -> None:
        outcome = runner.scorer.score(result)
        if outcome is None:
            return
        runner.stats["windows"] += 1
        self.stats["windows"] += 1
        self._collect_drift(runner, outcome)

        if self.cfg.mode == "live":
            if outcome.fired and outcome.alert is not None:
                self._deliver(runner, outcome)
        else:
            # observe / shadow: record everything, deliver nothing.
            self._shadow_record(runner, outcome)

    def _deliver(self, runner: _UseCaseRunner, outcome) -> None:
        # 1. Fold repeats of the same entity into one open alert (dedup).
        decision = runner.dedup.decide(outcome.alert)
        if not decision.deliver:
            runner.stats["alerts_folded"] += 1
            self.stats["alerts_folded"] += 1
            return
        # 2. Cap daily delivery per server; overflow -> digest, never dropped.
        if runner.budget.decide(outcome.alert) == BudgetDecision.DIGEST:
            self._digest(runner, outcome.alert)
            runner.stats["alerts_digested"] += 1
            self.stats["alerts_digested"] += 1
            return
        runner.sink.emit_alert(outcome.alert)
        runner.stats["alerts_delivered"] += 1
        self.stats["alerts_delivered"] += 1

    def _digest(self, runner: _UseCaseRunner, alert) -> None:
        if runner.digest_fh is None:
            path = self.state_dir / f"{runner.slug}_digest.ndjson"
            runner.digest_fh = path.open("a", encoding="utf-8")
        runner.digest_fh.write(
            json.dumps({
                "@timestamp": alert.timestamp.isoformat(),
                "usecase": alert.usecase,
                "entity": str(alert.entity),
                "severity": alert.severity.value,
                "reason": "over daily budget — folded into digest",
                "narrative": alert.narrative,
            }) + "\n"
        )

    def _shadow_record(self, runner: _UseCaseRunner, outcome) -> None:
        if runner.shadow_fh is None:
            path = self.state_dir / f"{runner.slug}_shadow.ndjson"
            runner.shadow_fh = path.open("a", encoding="utf-8")
        row = {**outcome.record(), "would_alert": outcome.fired}
        runner.shadow_fh.write(json.dumps(row) + "\n")

    # ------------------------------------------------------------------ #
    # Drift
    # ------------------------------------------------------------------ #

    def _collect_drift(self, runner: _UseCaseRunner, outcome) -> None:
        # Reservoir the model-input features of each scored window; PSI later
        # compares these live values against the bundle's training reference.
        for feature, value in outcome.features.items():
            bucket = runner.reservoir.setdefault(feature, [])
            if len(bucket) < _DRIFT_RESERVOIR:
                bucket.append(value)

    def _check_drift(self) -> None:
        for runner in self.runners:
            if not runner.bundle or not runner.bundle.reference_sample:
                continue
            per_feature = {}
            for feature, ref in runner.bundle.reference_sample.items():
                cur = runner.reservoir.get(feature, [])
                if len(cur) >= 50:
                    per_feature[feature] = population_stability_index(ref, cur)
            if not per_feature:
                continue
            report = DriftReport(per_feature)
            runner.stats["last_drift_band"] = report.band
            (self.state_dir / f"{runner.slug}_drift.json").write_text(
                json.dumps(report.to_dict(), indent=2), encoding="utf-8"
            )
            if report.should_retrain():
                self.log(
                    f"[runtime] DRIFT ({runner.slug}): significant on "
                    f"{report.drifted_features} (max PSI {report.max_psi:.2f}) "
                    f"— retrain recommended: `soc-ml train --uc {runner.slug} "
                    f"--input <recent logs>`"
                )
            # Reservoir rolls forward: keep the second half so the next window
            # measures against fresher live data.
            for feature, bucket in runner.reservoir.items():
                del bucket[: len(bucket) // 2]

    # ------------------------------------------------------------------ #
    # Persistence / health
    # ------------------------------------------------------------------ #

    def _ckpt_path(self) -> Path:
        return self.state_dir / f"{self.cfg.set_key}_checkpoint.json"

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
        for runner in self.runners:
            health = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "usecase": runner.slug,
                "mode": self.cfg.mode,
                "bundle_version": runner.bundle.version if runner.bundle else None,
                "uptime_s": round(uptime, 1),
                "eps": round(self.stats["events"] / uptime, 1) if uptime > 0 else 0,
                "events": self.stats["events"],
                "open_windows": runner.builder.open_count if runner.builder else 0,
                "ingest_failed": source.stats.failed,
                **runner.stats,
            }
            path = self.state_dir / f"{runner.slug}_health.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(health, indent=2), encoding="utf-8")
            tmp.replace(path)

    def _open_sink(self, runner: _UseCaseRunner) -> None:
        if self.cfg.sink_name == "file":
            runner.sink = FileSink(
                self.cfg.data_dir / "alerts" / f"{runner.slug}.ndjson"
            )
        else:
            runner.sink = plugin_registry.get("sink", self.cfg.sink_name)()

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
        # Drain in dependency order for the same reason the loop scores in it.
        for runner in self.runners:
            if runner.builder:
                for result in runner.builder.flush():
                    self._handle(runner, result)
        self._save_checkpoint(source)
        self._write_health(source)
        for runner in self.runners:
            if runner.sink:
                runner.sink.flush()
                if hasattr(runner.sink, "close"):
                    runner.sink.close()
            if runner.shadow_fh:
                runner.shadow_fh.close()
            if runner.digest_fh:
                runner.digest_fh.close()
        source.close()
        self.log(
            f"[runtime] stopped — {self.stats['events']:,} events, "
            f"{self.stats['windows']:,} windows, "
            f"{self.stats['alerts_delivered']} delivered, "
            f"{self.stats['alerts_folded']} folded"
        )
