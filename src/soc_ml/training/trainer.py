"""Trainer — turns an event stream into a servable ModelBundle.

This is the single place models are fitted. Both ``soc-ml train`` (production)
and ``soc-ml backtest`` (evaluation) call it, so a backtest necessarily trains
the same way production does (FR-72). Corpus hygiene (FR-56) lives here and is
not optional — a trainer that skips it fails review.

The trainer takes a **stream factory** (a callable returning a fresh event
iterator) rather than a materialized list, so it can make its passes over
multi-GB inputs without holding the events in memory. Memory is bounded by the
number of *windows* (far fewer than events), which sklearn needs in memory to
fit anyway.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import Event
from soc_ml.core.plugins import UseCase
from soc_ml.features import window_features as _wf
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.fusion.calibration import PercentileCalibrator
from soc_ml.registry.store import ModelBundle

__all__ = ["train_bundle", "TrainingError"]

_HYGIENE_CLIP_Q = 0.999  # clip features at p99.9 before fitting (FR-56)
_HYGIENE_DROP_FRACTION = 0.001  # drop top 0.1% most-anomalous windows (FR-56)
_MIN_TRAIN_WINDOWS = 20  # below this a fit is not meaningful
_DRIFT_REFERENCE_CAP = 5000  # per-feature reference sample size for PSI


class TrainingError(ValueError):
    """Training could not proceed (too little data, empty stream, ...)."""


def train_bundle(
    usecase_cls: type[UseCase],
    model_factories: dict[str, type],
    events: Callable[[], Iterator[Event]],
    *,
    version: str | None = None,
    source_desc: str = "",
    now: datetime | None = None,
) -> ModelBundle:
    """Fit a full bundle for ``usecase_cls`` over the events the factory yields."""
    now = now or datetime.now(timezone.utc)
    version = version or ("v" + now.strftime("%Y%m%dT%H%M%S"))
    slug = usecase_cls.name

    # -- pass 1: Environment Profile ------------------------------------- #
    profile = EnvironmentProfile()
    observed = 0
    for event in events():
        profile.observe(event)
        observed += 1
    if observed == 0:
        raise TrainingError(f"{slug}: empty training stream")

    # -- pass 2: window feature vectors ---------------------------------- #
    builder = WindowFeatureBuilder(profile)
    results = []
    for event in events():
        results.extend(builder.add(event))
    results.extend(builder.flush())
    if len(results) < _MIN_TRAIN_WINDOWS:
        raise TrainingError(
            f"{slug}: only {len(results)} training windows "
            f"(need >= {_MIN_TRAIN_WINDOWS}) — provide more history or events"
        )

    # Population stats first: the use case's vector() and the explainer read them.
    stats = _feature_stats([r.vector.values for r in results])
    profile.set_feature_stats(slug, stats)

    usecase = usecase_cls(profile)
    model_inputs = [x for r in results if (x := usecase.vector(r.vector)) is not None]
    if len(model_inputs) < _MIN_TRAIN_WINDOWS:
        raise TrainingError(f"{slug}: too few usable feature vectors after selection")

    # -- corpus hygiene (FR-56) ------------------------------------------ #
    clip = _quantile_per_feature(model_inputs, _HYGIENE_CLIP_Q)
    clipped = [_clip(x, clip) for x in model_inputs]
    cleaned, dropped = _drop_most_anomalous(clipped, model_factories)

    # -- fit models + calibrators ---------------------------------------- #
    models: dict[str, Any] = {}
    calibrators: dict[str, PercentileCalibrator] = {}
    for mslug in usecase_cls.models:
        model = model_factories[mslug]()
        model.fit(cleaned)
        models[mslug] = model
        calibrators[mslug] = PercentileCalibrator().fit([model.score(x) for x in cleaned])

    metadata = {
        "usecase": slug,
        "rule_id": usecase_cls.usecase_id,
        "title": usecase_cls.title,
        "tier": usecase_cls.tier,
        "version": version,
        "created_at": now.isoformat(),
        "source": source_desc,
        "train_events": observed,
        "train_windows": len(results),
        "usable_vectors": len(model_inputs),
        "hygiene": {
            "clip_quantile": _HYGIENE_CLIP_Q,
            "drop_fraction": _HYGIENE_DROP_FRACTION,
            "windows_dropped": dropped,
        },
        "models": {m: type(models[m]).__name__ for m in models},
        "gate": {
            "percentile": getattr(usecase_cls, "GATE_PERCENTILE", None),
            "min_events": getattr(usecase_cls, "MIN_EVENTS", None),
            "min_distinct_paths": getattr(usecase_cls, "MIN_DISTINCT_PATHS", None),
        },
        # Reproducibility anchor: which feature code produced these vectors.
        "feature_code_sha256": hashlib.sha256(
            Path(_wf.__file__).read_bytes()
        ).hexdigest(),
    }

    # Bounded per-feature reference for PSI drift detection (from the cleaned,
    # in-distribution corpus — the "normal" the live stream is compared to).
    reference_sample = _reference_sample(cleaned, cap=_DRIFT_REFERENCE_CAP)

    return ModelBundle(
        usecase=slug,
        version=version,
        profile=profile,
        models=models,
        calibrators=calibrators,
        metadata=metadata,
        reference_sample=reference_sample,
    )


# ---------------------------------------------------------------------- #
# hygiene + stats helpers
# ---------------------------------------------------------------------- #


def _drop_most_anomalous(
    rows: list[dict[str, float]], model_factories: dict[str, type]
) -> tuple[list[dict[str, float]], int]:
    """Drop the top 0.1% most-anomalous windows so an attacker in the training
    window cannot teach the model that they are normal (FR-56)."""
    if len(rows) <= 100:
        return rows, 0
    from soc_ml.models.isolation_forest import IsolationForestModel

    factory = model_factories.get("isolation_forest", IsolationForestModel)
    prelim = factory()
    prelim.fit(rows)
    ranked = sorted(rows, key=prelim.score)
    n_drop = max(1, int(len(ranked) * _HYGIENE_DROP_FRACTION))
    return ranked[: len(ranked) - n_drop], n_drop


def _feature_stats(vectors: list[dict[str, float]]) -> dict[str, dict[str, float]]:
    import numpy as np

    if not vectors:
        return {}
    stats: dict[str, dict[str, float]] = {}
    for feature in vectors[0]:
        col = np.array([v.get(feature, 0.0) for v in vectors], dtype=float)
        stats[feature] = {
            "p50": float(np.quantile(col, 0.50)),
            "p99": float(np.quantile(col, 0.99)),
        }
    return stats


def _quantile_per_feature(vectors: list[dict[str, float]], q: float) -> dict[str, float]:
    import numpy as np

    if not vectors:
        return {}
    return {
        f: float(np.quantile(np.array([v.get(f, 0.0) for v in vectors]), q))
        for f in vectors[0]
    }


def _clip(x: dict[str, float], clip: dict[str, float]) -> dict[str, float]:
    return {k: min(v, clip.get(k, v)) for k, v in x.items()}


def _reference_sample(
    rows: list[dict[str, float]], cap: int
) -> dict[str, list[float]]:
    """Deterministic evenly-spaced sample of each feature (no RNG — replayable)."""
    if not rows:
        return {}
    step = max(1, len(rows) // cap)
    sampled = rows[::step][:cap]
    return {
        feature: [r.get(feature, 0.0) for r in sampled] for feature in rows[0]
    }
