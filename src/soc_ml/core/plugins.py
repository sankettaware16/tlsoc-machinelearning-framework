"""The six extension points, and how they are discovered.

Everything a user adds to this framework is one of six things: a ``Source``, a
``FeatureGroup``, a ``UseCase``, a ``Model``, a ``StateStore``, or a ``Sink``.
There is one discovery mechanism for all of them, so there is one thing to learn.

Discovery, in order:

1. **Directory drop-in** — anything under ``plugins/<kind>/`` is imported at
   startup. No packaging, no registration file. This is the "copy a file and it
   works" path.
2. **Entry points** — ``soc_ml.usecases``, ``soc_ml.features``, ... for
   pip-installable third-party packages.

Adding a use case must require **zero edits to this package** (NFR-12). If you
find yourself editing ``core/`` to add one, the interface is wrong — fix the
interface rather than working around it.
"""

from __future__ import annotations

import abc
import importlib
import importlib.metadata
import importlib.util
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, TypeVar

from .contracts import (
    Alert,
    EntityKey,
    Event,
    FeatureVector,
    Insight,
    RunMode,
)

log = logging.getLogger(__name__)

__all__ = [
    "Plugin",
    "Source",
    "FeatureGroup",
    "UseCase",
    "Model",
    "StateStore",
    "Sink",
    "PluginRegistry",
    "registry",
    "usecase_model_factories",
]


# --------------------------------------------------------------------------- #
# Base
# --------------------------------------------------------------------------- #


class Plugin(abc.ABC):
    """Common base. Subclasses of the six kinds below self-register."""

    #: Unique identifier — the join key across spec, code, config, tests, alerts.
    name: ClassVar[str] = ""
    #: One line, shown by ``soc-ml plugins``.
    description: ClassVar[str] = ""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Abstract intermediates (Source, UseCase, ...) declare no name and are
        # not registered; concrete plugins declare one and are.
        if getattr(cls, "name", ""):
            registry.register(cls)


# --------------------------------------------------------------------------- #
# 1. Source — where events come from
# --------------------------------------------------------------------------- #


class Source(Plugin):
    """Yields :class:`Event` objects from somewhere.

    Implementations must support **replay** (FR-04): cold-start warmup,
    backtests, and SAIF all work by rewinding, so a source that can only move
    forward is only half a source.
    """

    @abc.abstractmethod
    def read(self) -> Iterator[Event]:
        """Yield events until exhausted (offline) or forever (live)."""

    def checkpoint(self) -> dict[str, Any]:
        """Restart-safe position. Default: no durable position."""
        return {}

    def seek(self, checkpoint: dict[str, Any]) -> None:
        """Resume from a previous checkpoint. Override to support replay."""
        raise NotImplementedError(f"{self.name} does not support replay")

    def close(self) -> None:
        return None


# --------------------------------------------------------------------------- #
# 2. FeatureGroup — derived numbers
# --------------------------------------------------------------------------- #


class FeatureGroup(Plugin):
    """Computes a related set of features for an entity over a window.

    Features are computed **once** and shared by every subscribing use case
    (FR-11). Never recompute something another group already provides; declare a
    dependency on it instead.

    Two hard rules (FR-05/06), enforced by CI lint:

    * never read ``Event.original``
    * never use ``observer.*`` as a feature value
    """

    #: Windows this group can be computed over.
    windows: ClassVar[tuple[str, ...]] = ("1m", "5m", "30m", "24h")
    #: Feature names produced, namespaced by group (e.g. ``path.idf_mean``).
    produces: ClassVar[tuple[str, ...]] = ()
    #: Other feature groups this one needs.
    depends_on: ClassVar[tuple[str, ...]] = ()

    @abc.abstractmethod
    def update(self, event: Event, state: "StateStore") -> None:
        """Fold one event into the running state."""

    @abc.abstractmethod
    def compute(
        self, entity: EntityKey, window: str, state: "StateStore"
    ) -> dict[str, float]:
        """Produce this group's features for an entity/window."""


# --------------------------------------------------------------------------- #
# 3. Model — the algorithms
# --------------------------------------------------------------------------- #


class Model(Plugin):
    """A uniform wrapper around one algorithm family.

    Use cases must not inline algorithms; they select a model. That keeps the
    algorithm reusable and, more importantly, keeps versioning and explanation in
    one place.
    """

    #: True for online/incremental models (Half-Space Trees, BOCPD, EWMA) that
    #: learn per-event and need no batch corpus.
    incremental: ClassVar[bool] = False

    @classmethod
    def available(cls) -> bool:
        """Can this model run here? Override for optional-dependency models.

        A model backed by an extra (``hdbscan``, ``torch``, ...) returns False
        when its import is missing; callers then skip it — a documented
        degradation, never a crash (NFR-08).
        """
        return True

    @abc.abstractmethod
    def fit(self, X: Iterable[dict[str, float]]) -> None:
        """Train on a corpus.

        The caller is responsible for corpus hygiene (FR-56) — top 0.1%
        anomalous windows excluded, p99.9 clipping, confirmed-incident windows
        quarantined. Never fit on synthetic/SAIF data (FR-58).
        """

    @abc.abstractmethod
    def score(self, x: dict[str, float]) -> float:
        """Raw anomaly score. Meaningless across servers until calibrated."""

    def score_batch(self, rows: list[dict[str, float]]) -> list[float]:
        """Score many rows at once. Override to vectorize.

        Training scores every window twice (hygiene ranking + calibration), so a
        per-row default is O(n) framework/sklearn-call overhead — models with a
        vectorized path (trees, distance models) should override this. The
        default keeps simple models correct.
        """
        return [self.score(x) for x in rows]

    @abc.abstractmethod
    def save(self, path: Path) -> None: ...

    @abc.abstractmethod
    def load(self, path: Path) -> None: ...

    def explain(self, x: dict[str, float]) -> list[tuple[str, float]]:
        """Per-feature attributions, strongest first (FR-40).

        The right method depends on the family: TreeSHAP for trees, per-feature
        reconstruction error for autoencoders, per-dimension distance for
        GMM/Mahalanobis, decoded state path for HMMs, nearest-cluster contrast
        for clustering.
        """
        return []


# --------------------------------------------------------------------------- #
# 4. UseCase — a detection
# --------------------------------------------------------------------------- #


class UseCase(Plugin):
    """One detection (UC-nn) or analytics (AU-nn) case.

    Declare features, models, and gate; write code only for genuinely novel
    maths.

    **Naming (docs/NAMING.md):** every use case carries a triple identity —
    ``name`` (the snake_case slug, e.g. ``web_recon``; canonical everywhere:
    module, config key, CLI, alert ``usecase`` field), ``usecase_id`` (the spec
    cross-reference, e.g. ``UC-02``, emitted as ``rule.id``), and ``title``
    (the human name, emitted as ``rule.name``). Slugs are immutable after first
    release.

    The gate is where accuracy is won or lost. Two rules are mandatory:

    * **Two-level gating** (FR-24) — a single event never alerts on its own;
      scoring operates on entity-level aggregates, never single events.
    * **Evidence floors** (FR-23) — the spec's minimum volume per use case
      (UC-06 needs >= 50 content requests, UC-09 >= 10 grammar-breaking URLs,
      UC-15 >= 200 calls). Small-sample anomalies are noise, not detections.

    And the invariant that defines this project: **no literal detection
    threshold may come from config** (FR-62). Every number compared against data
    comes from the learned Environment Profile. (Evidence floors and percentile
    gates fixed by the spec live in the use case *class*, which is code, not
    config.)
    """

    #: Spec ID — "UC-02". Cross-reference to SPEC_DIGEST; emitted as rule.id.
    usecase_id: ClassVar[str] = ""
    #: Human name — emitted as rule.name, shown on dashboards.
    title: ClassVar[str] = ""
    #: 1, 2, or 3 — build order and backpressure priority (shed 3 before 1).
    tier: ClassVar[int] = 3
    #: Feature names consumed, namespaced per NAMING.md (e.g. "web.ratio_404").
    requires: ClassVar[tuple[str, ...]] = ()
    #: Model plugin names. Several models means the use case fuses them.
    models: ClassVar[tuple[str, ...]] = ()
    #: Default mode; overridable per deployment for staged cold-start.
    default_mode: ClassVar[RunMode] = RunMode.SHADOW
    #: Daily delivery budget. Delivery only — every score is still recorded.
    daily_alert_budget: ClassVar[int] = 50
    #: Slugs of use cases whose exported per-entity signals this one consumes.
    #: The runtime scores dependencies first within each window, so their
    #: annotations exist by the time this use case's gate runs. A dependency
    #: that is not deployed is skipped, never fatal — the consumer must treat
    #: the missing signal as "unknown", visibly (NFR-09).
    depends_on: ClassVar[tuple[str, ...]] = ()

    @classmethod
    def canary(cls, server: str, start: datetime) -> list[Event]:
        """Synthetic known-bad events for this use case's backtest canary.

        Injected into the **scoring stream only**, never training (FR-58).
        Empty (the default) means this use case ships no canary yet and the
        backtest skips the detection check rather than failing it. Canary
        sources must use RFC 5737 TEST-NET-2 addresses (198.51.100.0/24) so
        they are recognizable and can never collide with real traffic.
        """
        return []

    @abc.abstractmethod
    def vector(self, fv: FeatureVector) -> dict[str, float] | None:
        """Select and finalize this use case's model input from a FeatureVector.

        Return None when the vector is not applicable (wrong window, missing
        required features). This is selection/derivation only — no judgement.
        """

    def fuse(self, calibrated: dict[str, float]) -> float:
        """Combine per-model calibrated percentiles into one confidence.

        Default is max — the spec's rule for UC-02 (IForest/LOF) and the safe
        default elsewhere. Override for use cases with a different fusion rule.
        Inputs are percentiles (0-1), never raw scores (FR-22).
        """
        return max(calibrated.values())

    def suppression(self, evidence: dict[str, Any]) -> tuple[str, str] | None:
        """Should a fired alert be suppressed or down-weighted, and why?

        Called only after the gate fired — detection is never touched, which
        is what keeps "no new thresholds" true: this consumes an upstream
        signal (``evidence["entity_annotations"]``), it does not re-judge the
        anomaly. Return ``("suppress", reason)`` to withhold delivery,
        ``("downweight", reason)`` to lower severity one band, or None for
        normal delivery. Whatever is returned is recorded on the alert
        document — a suppression that leaves no trace is forbidden (NFR-09).
        """
        return None

    def annotate(self, outcome: Any) -> dict[str, Any] | None:
        """Per-entity signals this use case exports after scoring a window.

        ``outcome`` is the scorer's ScoreResult (typed loosely here — core
        cannot depend on the detection layer). Return a dict of namespaced
        annotation values (``crawler.human_likeness``, ...) to publish to the
        shared entity-annotation store for use cases that score later in the
        window (see ``depends_on``), or None to publish nothing. Default:
        nothing — most use cases only consume.
        """
        return None

    def calibration_rows(
        self, model_slug: str, rows: list[dict[str, float]]
    ) -> list[dict[str, float]]:
        """The sub-population whose scores define a model's percentile reference.

        Default: every training row. Override when "unusual" must be judged
        against a specific population — bot_detection calibrates P(bot)
        against *browser-declared* windows, because "more bot-like than 99.5%
        of a population that is one-fifth actual Googlebot" is a bar no
        spoofer can clear; the spoofing question is "more bot-like than the
        browsers here". Still learned, still per server: FR-22 intact.
        The trainer falls back to all rows when the subset is too small.
        """
        return rows

    @abc.abstractmethod
    def gate(self, fused_percentile: float, evidence: dict[str, Any]) -> bool:
        """Decide whether this calibrated, fused score is alert-worthy.

        ``fused_percentile`` is 0-1, already calibrated per server (FR-22).
        ``evidence`` carries window-level counts (event_count, distinct paths,
        ...) — enforce the spec's evidence floor here (FR-23)."""


# --------------------------------------------------------------------------- #
# 5. StateStore — the learned memory
# --------------------------------------------------------------------------- #


class StateStore(Plugin):
    """Windowed counters, approximate uniques, and learned frequency tables.

    Backends: ``memory`` and ``sqlite`` (standalone), ``redis`` (cluster+). The
    interface is deliberately narrow so a new backend is a small job.
    """

    @abc.abstractmethod
    def incr(self, key: str, field: str, amount: float = 1.0, ttl_s: int | None = None) -> None: ...

    @abc.abstractmethod
    def get(self, key: str, field: str) -> float | None: ...

    @abc.abstractmethod
    def add_unique(self, key: str, value: str, ttl_s: int | None = None) -> None:
        """Record a value in an approximate-unique structure (HyperLogLog)."""

    @abc.abstractmethod
    def count_unique(self, key: str) -> int: ...

    @abc.abstractmethod
    def expire(self, now_ts: float) -> int:
        """Drop expired keys; return how many. Called on a timer."""


# --------------------------------------------------------------------------- #
# 6. Sink — where results go
# --------------------------------------------------------------------------- #


class Sink(Plugin):
    """Delivers alerts and insights somewhere.

    A sink that drops something must say so (NFR-09). Failing silently is worse
    than failing loudly.
    """

    @abc.abstractmethod
    def emit_alert(self, alert: Alert) -> None: ...

    def emit_insight(self, insight: Insight) -> None:
        return None

    def flush(self) -> None:
        return None


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_KINDS: dict[str, type[Plugin]] = {}
P = TypeVar("P", bound=Plugin)


class PluginRegistry:
    """Holds every discovered plugin, indexed by kind and name."""

    def __init__(self) -> None:
        self._by_kind: dict[str, dict[str, type[Plugin]]] = {}

    # -- registration ------------------------------------------------------ #

    def register(self, cls: type[Plugin]) -> None:
        kind = self._kind_of(cls)
        if kind is None:
            return
        bucket = self._by_kind.setdefault(kind, {})
        existing = bucket.get(cls.name)
        if existing is not None and existing is not cls:
            # A drop-in plugin shadowing a built-in is a legitimate override, but
            # it must never be silent — that way lies a very confusing afternoon.
            log.warning(
                "plugin %r (%s) overrides existing %s.%s",
                cls.name, kind, existing.__module__, existing.__qualname__,
            )
        bucket[cls.name] = cls

    @staticmethod
    def _kind_of(cls: type[Plugin]) -> str | None:
        for kind, base in _KINDS.items():
            if issubclass(cls, base) and cls is not base:
                return kind
        return None

    # -- lookup ------------------------------------------------------------ #

    def get(self, kind: str, name: str) -> type[Plugin]:
        try:
            return self._by_kind[kind][name]
        except KeyError:
            available = ", ".join(sorted(self._by_kind.get(kind, {}))) or "none"
            raise LookupError(
                f"no {kind} plugin named {name!r}; available: {available}"
            ) from None

    def all(self, kind: str) -> dict[str, type[Plugin]]:
        return dict(self._by_kind.get(kind, {}))

    def kinds(self) -> list[str]:
        return sorted(self._by_kind)

    # -- discovery --------------------------------------------------------- #

    def load_builtins(self) -> None:
        """Import the packaged plugin modules so they self-register."""
        for module in (
            "soc_ml.ingest",
            "soc_ml.state",
            "soc_ml.features",
            "soc_ml.models",
            "soc_ml.usecases",
            "soc_ml.analytics",
            "soc_ml.alerting",
        ):
            try:
                importlib.import_module(module)
            except ImportError as exc:  # pragma: no cover - scaffold phase
                log.debug("builtin package %s not importable yet: %s", module, exc)

    def load_directory(self, root: Path) -> int:
        """Import every ``.py`` under ``plugins/<kind>/`` — the drop-in path.

        A broken plugin logs and is skipped. One bad third-party file must not
        stop the engine from starting (NFR-08).
        """
        loaded = 0
        if not root.is_dir():
            return 0
        for path in sorted(root.rglob("*.py")):
            if path.name.startswith("_"):
                continue
            mod_name = f"soc_ml_plugins.{path.relative_to(root).with_suffix('').as_posix().replace('/', '.')}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                loaded += 1
            except Exception:
                log.exception("failed to load plugin %s — skipping", path)
        return loaded

    def load_entrypoints(self) -> int:
        """Import plugins published by installed packages."""
        loaded = 0
        for kind in _KINDS:
            group = f"soc_ml.{kind}s"
            try:
                entries = importlib.metadata.entry_points(group=group)
            except Exception:  # pragma: no cover
                continue
            for entry in entries:
                try:
                    entry.load()
                    loaded += 1
                except Exception:
                    log.exception("failed to load entry point %s — skipping", entry.name)
        return loaded

    def discover(self, plugin_dir: Path | None = None) -> None:
        self.load_builtins()
        if plugin_dir is not None:
            self.load_directory(plugin_dir)
        self.load_entrypoints()


registry = PluginRegistry()


def usecase_model_factories(uc_cls: type[UseCase]) -> dict[str, type[Model]]:
    """Model classes a use case declares, minus unavailable optional ones.

    The one place train/backtest/run build their factory maps, so an optional
    model whose extra is not installed degrades identically everywhere: it is
    skipped with a warning (visible degradation, NFR-08) at fit *and* at load —
    a bundle trained with the extra still serves without it, just without that
    model's contribution. No model available at all is the caller's error to
    raise loudly.
    """
    factories: dict[str, type[Model]] = {}
    for mslug in uc_cls.models:
        cls = registry.get("model", mslug)
        if not cls.available():
            log.warning(
                "%s: model %r unavailable (optional dependency missing) — "
                "continuing without it (NFR-08)",
                uc_cls.name, mslug,
            )
            continue
        factories[mslug] = cls
    return factories

_KINDS.update(
    {
        "source": Source,
        "feature": FeatureGroup,
        "model": Model,
        "usecase": UseCase,
        "state": StateStore,
        "sink": Sink,
    }
)
