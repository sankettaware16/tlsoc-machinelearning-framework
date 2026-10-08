"""Batched scoring must be the per-window path, only faster.

A bucket's windows all close on one watermark sweep; on elkcc, scoring a
3,500-window bucket one row at a time took 3+ minutes of sklearn per-call
overhead, during which the runtime read no events and wrote no health (looked
dead on the console). ``Scorer.score_many`` asks each model once per batch.
Everything stateful stays per window, so the outcomes must be identical to
scoring the same windows one at a time — including the gate streak that
bot_detection keeps across windows and the annotations web_recon reads.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from soc_ml.core.contracts import Event, Observer
from soc_ml.core.plugins import usecase_model_factories
from soc_ml.detection.annotations import EntityAnnotations
from soc_ml.detection.scorer import Scorer
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases import WebRecon

T0 = datetime(2026, 7, 21, 8, 0, 0, tzinfo=timezone.utc)


def _traffic() -> list[Event]:
    benign = [
        Event(
            timestamp=T0 + timedelta(seconds=i * 2),
            observer=Observer(server="web01"),
            source_ip=f"10.0.{i % 5}.{i % 20}",
            url_path=f"/page{i % 4}.html", status_code=200,
            http_referrer="/home", user_agent="Mozilla/5.0", body_bytes=1000,
        )
        for i in range(1500)
    ]
    start = T0 + timedelta(hours=2)
    scan = [
        Event(
            timestamp=start + timedelta(seconds=i * 2),
            observer=Observer(server="web01"),
            source_ip="203.0.113.50", geo_country_iso="ZZ",
            url_path=f"/old/backup_{i}.sql", status_code=404,
            http_referrer=None, user_agent="scan/1.0", body_bytes=100,
            original=f"GET /old/backup_{i}.sql 404",
        )
        for i in range(60)
    ]
    return benign + scan


def _closed_windows(bundle, events):
    builder = WindowFeatureBuilder(bundle.profile)
    results = []
    for e in events:
        results.extend(builder.add(e))
    results.extend(builder.flush())
    return results


def test_score_many_matches_scoring_one_window_at_a_time() -> None:
    events = _traffic()
    bundle = train_bundle(
        WebRecon, usecase_model_factories(WebRecon),
        lambda: iter(events[:1500]), source_desc="test",
    )
    windows = _closed_windows(bundle, events)
    assert len(windows) > 50

    one_by_one = [Scorer(WebRecon, bundle, EntityAnnotations()).score(w)
                  for w in _closed_windows(bundle, events)]
    batched = Scorer(WebRecon, bundle, EntityAnnotations()).score_many(windows)

    assert len(batched) == len(one_by_one)
    assert any(o is not None and o.fired for o in batched), "the scan must fire"
    for single, many in zip(one_by_one, batched, strict=True):
        if single is None:
            assert many is None
            continue
        assert many.entity == single.entity and many.window_end == single.window_end
        assert many.fired == single.fired
        assert many.fused_percentile == single.fused_percentile
        assert many.per_model == single.per_model
        for mslug, raw in single.per_model_raw.items():
            assert abs(many.per_model_raw[mslug] - raw) < 1e-9
        if single.fired:
            assert many.alert.severity == single.alert.severity
            assert many.alert.delivered == single.alert.delivered


def test_score_many_keeps_positions_of_inapplicable_windows() -> None:
    events = _traffic()
    bundle = train_bundle(
        WebRecon, usecase_model_factories(WebRecon),
        lambda: iter(events[:1500]), source_desc="test",
    )
    windows = _closed_windows(bundle, events)
    scorer = Scorer(WebRecon, bundle, EntityAnnotations())
    out = scorer.score_many(windows, synthetic=[False] * len(windows))
    assert len(out) == len(windows)
    assert scorer.score_many([]) == []
