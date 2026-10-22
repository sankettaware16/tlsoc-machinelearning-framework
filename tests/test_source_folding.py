"""One address, many user-agents: seen together, folded together (D-031).

The entity key is (server, ip, ua_hash). On elkcc a single scanner rotating
34 user-agents became 36 entities and 36 fires in one window, spent the day's
delivery budget by itself, and could have slipped under the evidence floor
entirely with a little more rotation. Three things change here:

* every closed window carries what its *address* did in the bucket across all
  user-agents (``source_*`` evidence);
* a fire from an address with an open alert folds into it whatever the
  user-agent, and the fold says so;
* the delivered alert shows the rotation.

The evidence floor itself is unchanged, and the last test pins the gap that
leaves — fragments under the floor are not detected — so closing it has to be
a deliberate act (compare D-024).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import Event, Observer
from soc_ml.core.plugins import usecase_model_factories
from soc_ml.detection.annotations import EntityAnnotations
from soc_ml.detection.dedup import AlertDeduplicator
from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig
from soc_ml.detection.scorer import Scorer
from soc_ml.explain.context import narrative
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases import WebRecon
from tests.test_detection_lifecycle import _normal_and_scan, _write_events, alert

T0 = datetime(2026, 7, 21, 8, 0, 0, tzinfo=UTC)


def _rotating_scanner(ip: str, start: datetime, uas: int, per_ua: int,
                      server: str = "web01") -> list[Event]:
    """One address, ``uas`` user-agents, ``per_ua`` never-seen 404s each."""
    events = []
    for u in range(uas):
        for i in range(per_ua):
            k = u * per_ua + i
            events.append(Event(
                timestamp=start + timedelta(seconds=k * 2),
                observer=Observer(server=server),
                source_ip=ip, geo_country_iso="ZZ",
                url_path=f"/secret/dump_{k}.sql", status_code=404,
                http_referrer=None, user_agent=f"probe/{u}.0", body_bytes=100,
                original=f"GET /secret/dump_{k}.sql 404",
            ))
    return events


# ------------------------------ builder --------------------------------- #


def test_every_window_carries_what_its_address_did_across_user_agents() -> None:
    builder = WindowFeatureBuilder(EnvironmentProfile())
    results = []
    for e in _rotating_scanner("203.0.113.9", T0, uas=3, per_ua=4):
        results.extend(builder.add(e))
    results.extend(builder.flush())

    assert len(results) == 3, "three user-agents -> three entity windows"
    for r in results:
        assert r.evidence["event_count"] == 4
        assert r.evidence["source_event_count"] == 12
        assert r.evidence["source_ua_count"] == 3
        assert r.evidence["source_distinct_paths"] == 12
    assert not builder._sources, "released once the bucket's windows closed"


def test_source_aggregate_is_per_bucket_and_per_address() -> None:
    builder = WindowFeatureBuilder(EnvironmentProfile())
    events = _rotating_scanner("203.0.113.9", T0, uas=2, per_ua=3)
    events += _rotating_scanner("203.0.113.10", T0, uas=1, per_ua=5)
    events += _rotating_scanner("203.0.113.9", T0 + timedelta(minutes=10), uas=1, per_ua=2)
    events.sort(key=lambda e: e.timestamp)
    results = []
    for e in events:
        results.extend(builder.add(e))
    results.extend(builder.flush())
    by = {(r.vector.entity.ip, r.evidence["window_start"]): r.evidence for r in results}
    first = by[("203.0.113.9", T0.isoformat())]
    assert (first["source_ua_count"], first["source_event_count"]) == (2, 6)
    other = by[("203.0.113.10", T0.isoformat())]
    assert (other["source_ua_count"], other["source_event_count"]) == (1, 5)
    later = by[("203.0.113.9", (T0 + timedelta(minutes=10)).isoformat())]
    assert (later["source_ua_count"], later["source_event_count"]) == (1, 2)


# ------------------------------- dedup ---------------------------------- #


def _ua_alert(ip: str, ua_hash: str, offset_s: float = 0):
    a = alert(ip=ip, offset_s=offset_s)
    a.entity = type(a.entity)(server="web01", ip=ip, ua_hash=ua_hash)
    return a


def test_same_address_other_user_agent_folds_with_a_reason() -> None:
    d = AlertDeduplicator(cooldown_s=1800)
    first = d.decide(_ua_alert("1.1.1.1", "ua-a", 0))
    assert first.deliver is True
    second = d.decide(_ua_alert("1.1.1.1", "ua-b", 60))
    assert second.deliver is False and second.folded_by == "source"
    assert second.folded_into == first.folded_into or second.folded_into is not None
    third = d.decide(_ua_alert("1.1.1.1", "ua-b", 120))
    assert third.folded_by == "source", "folded fragments never open an alert of their own"
    assert d.decide(_ua_alert("2.2.2.2", "ua-a", 60)).deliver is True, "other address"
    assert d.rotation(_ua_alert("1.1.1.1", "ua-a").entity) == 2
    assert d.stats["folded_by_source"] == 2


def test_address_fold_expires_with_the_cooldown() -> None:
    d = AlertDeduplicator(cooldown_s=600)
    d.decide(_ua_alert("1.1.1.1", "ua-a", 0))
    assert d.decide(_ua_alert("1.1.1.1", "ua-b", 2000)).deliver is True


def test_address_fold_state_survives_restart_and_legacy_checkpoints() -> None:
    d = AlertDeduplicator(cooldown_s=1800)
    d.decide(_ua_alert("1.1.1.1", "ua-a", 0))
    d.decide(_ua_alert("1.1.1.1", "ua-b", 60))
    doc = json.loads(json.dumps(d.export_state()))
    restored = AlertDeduplicator(cooldown_s=1800)
    restored.restore_state(doc)
    assert restored.decide(_ua_alert("1.1.1.1", "ua-c", 120)).folded_by == "source"
    assert restored.rotation(_ua_alert("1.1.1.1", "ua-a").entity) == 3

    legacy = {"open": doc["open"]}  # written before address folding existed
    old = AlertDeduplicator(cooldown_s=1800)
    old.restore_state(legacy)
    assert old.decide(_ua_alert("1.1.1.1", "ua-c", 120)).folded_by == "source", (
        "entities already open imply an open address"
    )


# ---------------------------- alert document ---------------------------- #


def test_alert_shows_the_rotation() -> None:
    events = _normal_and_scan()[:1500] + _rotating_scanner(
        "203.0.113.9", T0 + timedelta(hours=2), uas=4, per_ua=8)
    bundle = train_bundle(WebRecon, usecase_model_factories(WebRecon),
                          lambda: iter(events[:1500]), source_desc="test")
    builder = WindowFeatureBuilder(bundle.profile)
    results = []
    for e in events:
        results.extend(builder.add(e))
    results.extend(builder.flush())
    fired = [o for o in Scorer(WebRecon, bundle, EntityAnnotations()).score_many(results)
             if o is not None and o.fired]
    assert len(fired) == 4, "every fragment is above the floor and fires"
    for o in fired:
        assert o.alert.links["source"] == {"events": 32, "user_agents": 4, "distinct_paths": 32}
        assert "4 different user-agents" in o.alert.narrative


def test_narrative_is_silent_about_rotation_when_there_is_none() -> None:
    text = narrative("T", "1.2.3.4", "web01",
                     {"event_count": 5, "distinct_paths": 3, "n404": 2, "source_ua_count": 1}, [])
    assert "user-agents" not in text


# ------------------------------ runtime --------------------------------- #


def test_rotating_scanner_is_one_delivered_alert(tmp_path: Path, monkeypatch) -> None:
    """elkcc 2026-10-08: 36 fires, 3 delivered + 33 digested, budget gone in
    one window. Now: one alert, the rest folded into it with the reason.

    The address-level dedup path, as non-progressive detectors use it;
    web_recon's progressive path folds the same way (test_progressive)."""
    monkeypatch.setattr(WebRecon, "progressive", False)
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    events = _normal_and_scan()[:1500] + _rotating_scanner(
        "203.0.113.9", T0 + timedelta(hours=2), uas=6, per_ua=8)
    _write_events(incoming / "logs.json", events)
    rt = DetectionRuntime(
        RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="live",
                      follow=False, allow_cold_start=True, daily_alert_budget=3),
        log=lambda *_: None,
    )
    rt.run()
    rows = [json.loads(line) for line in (tmp_path / "state" / "web_recon_scores.ndjson")
            .read_text().splitlines()]
    assert len(rows) == 6, "six fragments, six fires — detection is unchanged"
    assert sum(r["disposition"] == "delivered" for r in rows) == 1
    assert sum(r.get("folded_by") == "source" for r in rows) == 5
    assert rt.stats["alerts_digested"] == 0, "the budget is no longer spent on fragments"
    delivered = [json.loads(line) for line in (tmp_path / "alerts" / "web_recon.ndjson")
                 .read_text().splitlines()]
    assert delivered[0]["links"]["source"]["user_agents"] == 6


def test_known_gap_fragments_under_the_floor_are_not_detected(tmp_path: Path) -> None:
    """Pinned, not fixed: with enough rotation every fragment falls under the
    5-request floor and the scan is invisible. The address aggregate is now
    on every window, so a floor that reads it is a one-line change — but it
    would also admit every tiny fragment behind a busy NAT, so that call is
    deliberate (D-031)."""
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    events = _normal_and_scan()[:1500] + _rotating_scanner(
        "203.0.113.9", T0 + timedelta(hours=2), uas=10, per_ua=3)
    _write_events(incoming / "logs.json", events)
    rt = DetectionRuntime(
        RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="live",
                      follow=False, allow_cold_start=True, daily_alert_budget=3),
        log=lambda *_: None,
    )
    rt.run()
    assert rt.stats["alerts_delivered"] + rt.stats["alerts_folded"] \
        + rt.stats["alerts_digested"] == 0
