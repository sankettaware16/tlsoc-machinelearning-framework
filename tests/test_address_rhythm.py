"""Address rhythm for bot_detection (D-036, advisory review P1).

The headless botnet's only tells were temporal; the GBM's label cannot teach
"headless browser" (D-032). The address — not (address, user-agent) — is the
stable actor, its memory must survive restarts, and a cold memory must read
"unknown" rather than "human".
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from soc_ml.core.contracts import Event, Observer
from soc_ml.core.plugins import usecase_model_factories
from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig
from soc_ml.features.bot_features import AddressMemory
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.models.rhythm import RHYTHM_INPUTS, RhythmIsolationForest
from soc_ml.registry.store import ModelBundle, ModelRegistry
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases import BotDetection
from tests.test_detection_lifecycle import _normal_and_scan, _write_events
from tests.test_window_features import trained_profile

T0 = datetime(2026, 7, 21, 0, 0, 0, tzinfo=UTC)


# ------------------------------- memory --------------------------------- #


def test_hour_entropy_separates_around_the_clock_from_waking_hours() -> None:
    clock, human = AddressMemory(), AddressMemory()
    for h in range(24):
        clock.remember(T0 + timedelta(hours=h))
    for h in (9, 10, 10, 11, 14):
        human.remember(T0 + timedelta(hours=h))
    assert clock.hour_entropy() > 0.99 > 0.6 > human.hour_entropy()


def test_active_ratio_and_rate_cv() -> None:
    bot, person = AddressMemory(), AddressMemory()
    for b in range(100, 112):
        bot.close_bucket(b, 7)
    for b, n in ((100, 40), (101, 3), (107, 25)):
        person.close_bucket(b, n)
    assert bot.active_ratio(111) == 1.0 and bot.rate_cv() == 0.0
    assert person.active_ratio(111) == 3 / 12 and person.rate_cv() > 0.5


def test_too_little_history_reads_neutral_not_regular() -> None:
    m = AddressMemory()
    m.close_bucket(1, 5)
    assert m.rate_cv() == 1.0, "one bucket is not 'perfectly regular'"


def test_memory_round_trips() -> None:
    m = AddressMemory()
    for d in range(10):
        m.remember(T0 + timedelta(days=d, hours=d))
    m.close_bucket(5, 9)
    back = AddressMemory.from_row(json.loads(json.dumps(m.to_row())))
    assert back.hour_counts == m.hour_counts and back.recent == [[5, 9]]
    assert len(back.days) == 8, "bounded"


# ------------------------------- builder -------------------------------- #


def _ev(ip: str, ua: str, minute: float, path: str = "/core/misc/drupal.js") -> Event:
    return Event(timestamp=T0 + timedelta(minutes=minute), observer=Observer(server="web01"),
                 source_ip=ip, url_path=path, status_code=200, http_referrer="https://x/",
                 user_agent=ua, body_bytes=900)


def _windows(builder, events):
    out = []
    for e in sorted(events, key=lambda e: e.timestamp):
        out.extend(builder.add(e))
    out.extend(builder.flush())
    return out


def test_address_features_are_shared_across_user_agents() -> None:
    b = WindowFeatureBuilder(trained_profile())
    events = [_ev("198.51.100.9", f"ua{k % 3}", minute=k * 1.0) for k in range(60)]
    last = [w for w in _windows(b, events) if w.evidence["window_start"].endswith("00:55:00+00:00")]
    assert len(last) == 3, "three user-agents, three entity windows"
    ratios = {w.vector.values["bot.addr_active_ratio"] for w in last}
    assert ratios == {1.0}, "every user-agent window sees the address present all hour"
    assert all(w.evidence["addr_memory_hours"] > 0.9 for w in last)


def test_restored_memory_is_warm_from_the_first_window() -> None:
    first = WindowFeatureBuilder(trained_profile())
    _windows(first, [_ev("198.51.100.9", "ua", minute=k * 5.0) for k in range(24 * 12)])
    snapshot = json.loads(json.dumps(first.export_address_memory()))

    warm = WindowFeatureBuilder(trained_profile())
    warm.restore_address_memory(snapshot)
    cold = WindowFeatureBuilder(trained_profile())
    later = [_ev("198.51.100.9", "ua", minute=24 * 60 + k) for k in range(3)]
    (w_warm,) = _windows(warm, later)
    (w_cold,) = _windows(cold, later)
    assert w_warm.vector.values["bot.addr_hour_entropy"] > 0.95
    assert w_cold.vector.values["bot.addr_hour_entropy"] == 0.0
    assert w_warm.evidence["addr_memory_hours"] >= 24
    assert w_cold.evidence["addr_memory_hours"] < 1, "cold reads as cold, visibly"


# --------------------------- model + use case --------------------------- #


def test_the_rhythm_model_reads_only_its_inputs() -> None:
    m = RhythmIsolationForest()
    rows = [{**{f: float(i % 7) for f in RHYTHM_INPUTS}, "bot.declared_bot": 1.0,
             "ua.rarity": 0.9} for i in range(300)]
    m.fit(rows)
    assert m._features == sorted(RHYTHM_INPUTS), "no label, no user-agent field"


def test_the_rhythm_model_is_fitted_on_browsers_only() -> None:
    uc = BotDetection.__new__(BotDetection)
    rows = [{"bot.declared_bot": 1.0}, {"bot.declared_bot": 0.0}]
    assert uc.training_rows("rhythm_iforest", rows) == [{"bot.declared_bot": 0.0}]
    assert uc.training_rows("gbm_bot", rows) == rows


def test_a_bundle_trained_before_the_rhythm_model_still_serves(tmp_path: Path) -> None:
    factories = usecase_model_factories(BotDetection)
    older = {k: v for k, v in factories.items() if k != "rhythm_iforest"}
    events = _normal_and_scan()
    bundle = train_bundle(BotDetection, older, lambda: iter(events), source_desc="old")
    reg = ModelRegistry(tmp_path)
    reg.save_bundle(bundle)
    loaded = ModelBundle.load(reg.bundle_dir("bot_detection", bundle.version), factories)
    assert "rhythm_iforest" not in loaded.models and "gbm_bot" in loaded.models


def test_the_runtime_keeps_address_memory_across_a_restart(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan())
    cfg = dict(input_dir=incoming, data_dir=tmp_path, mode="shadow", follow=False)
    DetectionRuntime(RuntimeConfig(**cfg, allow_cold_start=True), log=lambda *_: None).run()
    path = tmp_path / "state" / "web_recon_address_memory.json"
    assert len(json.loads(path.read_text())["addresses"]) > 10
    logs: list[str] = []
    DetectionRuntime(RuntimeConfig(**cfg), log=logs.append).run()
    assert any("address memory restored" in line for line in logs)


# ----------------- review 2026-10-22: C7, C10/C15, S1 ------------------ #


def test_a_bucket_cut_short_by_shutdown_is_completed_after_restart() -> None:
    m = AddressMemory()
    for b in range(1, 6):
        m.close_bucket(b, 7)
    m.close_bucket(6, 3, partial=True)            # shutdown mid-bucket
    assert m.rate_cv() == 0.0, "a partial bucket is not a cadence sample"
    assert m.active_ratio(6) == 6 / 12, "but it is activity"
    m.close_bucket(6, 4)                           # the rest of bucket 6 after restart
    assert m.recent[-1] == [6, 7] and m.rate_cv() == 0.0


def test_flush_marks_its_buckets_partial() -> None:
    b = WindowFeatureBuilder(trained_profile())
    _windows(b, [_ev("198.51.100.9", "ua", minute=k * 0.5) for k in range(4)])
    (memory,) = [m for (s, ip), m in b._addresses.items() if ip == "198.51.100.9"]
    assert memory.recent[-1][2] == 1


def test_a_snapshot_covering_the_replay_is_not_counted_twice() -> None:
    live = WindowFeatureBuilder(trained_profile())
    events = [_ev("198.51.100.9", "ua", minute=k * 5.0) for k in range(24)]
    _windows(live, events)
    snapshot = json.loads(json.dumps(live.export_address_memory()))
    before = list(live._addresses[("web01", "198.51.100.9")].hour_counts)

    replay = WindowFeatureBuilder(trained_profile())
    replay.restore_address_memory(snapshot, history_only=True)
    _windows(replay, events + [_ev("198.51.100.77", "ua", minute=1.0)])
    frozen = replay._addresses[("web01", "198.51.100.9")]
    assert frozen.hour_counts == before, "replayed events are already in the snapshot"
    assert all(r[0] <= events[-1].timestamp.timestamp() // 300 for r in frozen.recent), \
        "no bucket from after the replay"
    assert sum(replay._addresses[("web01", "198.51.100.77")].hour_counts) == 1, \
        "an address the snapshot never saw accumulates normally"


def test_address_features_feed_only_the_rhythm_model() -> None:
    from soc_ml.models.gbm import GBMBotClassifier
    from soc_ml.models.gmm import GMMModel
    rows = [{"bot.addr_hour_entropy": float(i % 3), "bot.asset_fetch_ratio": i / 100,
             "timing.interarrival_cv": (i % 7) / 3, "bot.declared_bot": float(i % 2),
             "ua.rarity": 0.5} for i in range(200)]
    gbm = GBMBotClassifier()
    gbm.fit(rows)
    assert not any(f.startswith("bot.addr_") for f in gbm._features)
    gmm = GMMModel()
    gmm.fit(rows)
    assert not any(f.startswith("bot.addr_") for f in gmm._scaler.features)
