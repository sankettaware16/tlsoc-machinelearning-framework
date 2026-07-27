"""Tests for the streaming window feature builder — hand-computed expectations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import Event, Observer
from soc_ml.features.window_features import (
    WEB_RECON_FEATURES,
    WindowFeatureBuilder,
    _cv,
    _token_entropy,
)

# Aligned to a 5-minute boundary so one burst = exactly one window.
T0 = datetime(2026, 7, 9, 8, 0, 0, tzinfo=timezone.utc)


def ev(offset_s: float = 0, path: str = "/", status: int = 200,
       referrer: str | None = None, ua: str = "Mozilla/5.0",
       server: str = "web01", ip: str = "10.0.0.1") -> Event:
    return Event(
        timestamp=T0 + timedelta(seconds=offset_s),
        observer=Observer(server=server),
        source_ip=ip,
        url_path=path,
        status_code=status,
        http_referrer=referrer,
        user_agent=ua,
        original=f"raw {path}",
    )


def trained_profile() -> EnvironmentProfile:
    """A server that serves /index.html and .pdf files, nothing else."""
    profile = EnvironmentProfile()
    for i in range(50):
        profile.observe(ev(path="/index.html"))
        profile.observe(ev(path=f"/docs/report{i % 3}.pdf"))
    return profile


def collect(builder: WindowFeatureBuilder, events: list[Event]):
    results = []
    for event in events:
        results.extend(builder.add(event))
    results.extend(builder.flush())
    return results


# --------------------------------------------------------------------- #


def test_scanner_window_features_hand_computed() -> None:
    profile = trained_profile()
    builder = WindowFeatureBuilder(profile)

    # 10 requests, 10s apart: 8 hit unseen paths w/ unserved extensions (404),
    # 2 hit the known page (200). No referrers.
    events = [
        ev(offset_s=i * 10, path=f"/backup_{i}.sql", status=404) for i in range(8)
    ] + [
        ev(offset_s=80, path="/index.html", status=200),
        ev(offset_s=90, path="/index.html", status=200),
    ]
    (result,) = collect(builder, events)
    v = result.vector.values

    assert result.vector.window == "5m"
    assert v["web.ratio_404"] == 0.8
    assert v["web.status_2xx_ratio"] == 0.2
    assert v["web.status_4xx_ratio"] == 0.8
    assert v["web.uniq_paths_per_min"] == 9 / 5  # 8 sql paths + index.html
    assert v["web.unknown_ext_ratio"] == 0.8  # .sql never served; .html? also!
    assert v["web.referrer_absent_ratio"] == 1.0
    assert v["ua.len"] == float(len("Mozilla/5.0"))
    assert v["timing.interarrival_cv"] == 0.0  # metronome-regular
    # 8 never-seen paths (idf 1.0) + 2 common ones -> mean well above common
    assert v["web.mean_path_idf"] > 0.8

    e = result.evidence
    assert e["event_count"] == 10
    assert e["distinct_paths"] == 9
    assert e["n404"] == 8
    assert 3 <= len(e["raw_lines"]) <= 10


def test_html_counts_as_unknown_only_if_never_served() -> None:
    """Profile knowledge, not a hardcoded list, decides 'unknown extension'."""
    profile = trained_profile()  # serves .html and .pdf
    builder = WindowFeatureBuilder(profile)
    (result,) = collect(builder, [ev(path="/index.html", status=200)])
    assert result.vector.values["web.unknown_ext_ratio"] == 0.0

    (result2,) = collect(WindowFeatureBuilder(profile), [ev(path="/dump.sql", status=404)])
    assert result2.vector.values["web.unknown_ext_ratio"] == 1.0


def test_all_declared_features_are_always_present() -> None:
    from soc_ml.features import BOT_DETECTION_FEATURES

    builder = WindowFeatureBuilder(trained_profile())
    (result,) = collect(builder, [ev()])
    assert set(result.vector.values) == set(WEB_RECON_FEATURES) | set(
        BOT_DETECTION_FEATURES
    )


def test_windows_split_by_entity_and_bucket() -> None:
    builder = WindowFeatureBuilder(trained_profile())
    events = [
        ev(offset_s=0, ip="10.0.0.1"),
        ev(offset_s=0, ip="10.0.0.2"),  # second entity
        ev(offset_s=400, ip="10.0.0.1"),  # next 5m bucket
    ]
    results = collect(builder, events)
    assert len(results) == 3
    assert builder.stats["windows_closed"] == 3


def test_watermark_closes_windows_without_flush() -> None:
    """A live stream must emit closed windows as time advances (sweep path)."""
    builder = WindowFeatureBuilder(trained_profile())
    emitted = []
    emitted.extend(builder.add(ev(offset_s=0)))
    # Sweep runs every 1000 events; push the watermark far past the bucket.
    for i in range(1100):
        emitted.extend(builder.add(ev(offset_s=1000 + i, ip="10.9.9.9")))
    assert any(r.vector.entity.ip == "10.0.0.1" for r in emitted), (
        "the first entity's window must close via watermark, not only at flush"
    )


def test_out_of_order_is_counted_not_crashed() -> None:
    builder = WindowFeatureBuilder(trained_profile())
    list(builder.add(ev(offset_s=600)))
    list(builder.add(ev(offset_s=0)))  # 10 min late
    assert builder.stats["out_of_order"] == 1


def test_token_entropy_bounds() -> None:
    from collections import Counter

    assert _token_entropy(Counter()) == 0.0
    assert _token_entropy(Counter({"a": 10})) == 0.0  # one token, no spread
    uniform = Counter({f"t{i}": 1 for i in range(64)})
    assert _token_entropy(uniform) == 1.0  # maximal spread
    skewed = Counter({"common": 100, **{f"t{i}": 1 for i in range(10)}})
    assert 0.0 < _token_entropy(skewed) < 1.0


def test_cv_edges() -> None:
    assert _cv([]) == 0.0
    assert _cv([5.0]) == 0.0
    assert _cv([10.0, 10.0, 10.0]) == 0.0
    assert _cv([1.0, 100.0]) > 0.9
