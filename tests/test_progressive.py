"""Progressive alerting: lone weak signals stay low; sustained ones reach the queue.

elkcc, 2026-10-13..20: web_recon fired on ~3,000 distinct addresses a day and
91% of them fired once and never again. The spec's UC-02 answer is progressive
alerting — first candidate low, upgraded as evidence accumulates — and on the
week's real fires, queueing only 30-minute sustained episodes (once per address
per day) gives 3.9 alerts/day (D-033). These tests pin the stage rules, the
durability across restarts, and the end-to-end path with a model trained on
benign traffic only (a model trained on the scanner learns it as normal, D-032).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from soc_ml.core.contracts import EntityKey, Event, Observer, Severity
from soc_ml.core.plugins import usecase_model_factories
from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig
from soc_ml.fusion.progressive import Progression
from soc_ml.registry.store import ModelRegistry
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases import WebRecon
from tests.test_detection_lifecycle import T0, _normal_and_scan, _write_events, alert


def _fire(ip: str = "1.1.1.1", minutes: float = 0, ua: str = "h", score: int = 100):
    a = alert(ip=ip, offset_s=minutes * 60)
    a.entity = EntityKey(server="web01", ip=ip, ua_hash=ua)
    a.id = f"{ip}-{ua}-{minutes}"
    a.severity_score = score
    a.severity = Severity.from_score(score)
    a.narrative = "n"
    return a


# ------------------------------- stages --------------------------------- #


def test_a_lone_window_is_a_low_candidate() -> None:
    p = Progression()
    a = _fire()
    step = p.decide(a)
    assert step.action == "candidate" and step.stage is Severity.LOW
    assert a.severity is Severity.LOW and a.severity_score == 44
    assert a.links["progressive"]["episode_windows"] == 1


def test_severity_rises_with_persistence_and_queues_once_sustained() -> None:
    p = Progression()
    steps = [p.decide(_fire(minutes=5 * k)) for k in range(8)]
    assert [s.stage for s in steps[:6]] == [Severity.LOW] + [Severity.MEDIUM] * 4 + [Severity.HIGH]
    assert [s.action for s in steps[:5]] == ["candidate"] * 5
    assert steps[5].action == "deliver", "the 6th consecutive window (30 min) reaches the queue"
    assert steps[6].action == steps[7].action == "fold"
    assert steps[6].folded_by == "episode" and steps[6].folded_into == "1.1.1.1-h-25"


def test_the_ceiling_never_raises_a_severity() -> None:
    p = Progression()
    for k in range(5):
        p.decide(_fire(minutes=5 * k))
    weak = _fire(minutes=25, score=40)
    p.decide(weak)
    assert weak.severity_score == 40 and weak.severity is Severity.LOW


def test_one_quiet_window_does_not_end_an_episode_but_a_longer_gap_does() -> None:
    p = Progression()
    assert p.decide(_fire(minutes=0)).episode_windows == 1
    assert p.decide(_fire(minutes=10)).episode_windows == 2, "gap of one window keeps it"
    assert p.decide(_fire(minutes=25)).episode_windows == 1, "15 min of silence ends it"


def test_other_user_agents_in_the_same_window_fold_and_do_not_count() -> None:
    p = Progression()
    first = p.decide(_fire(ua="a"))
    second = p.decide(_fire(ua="b"))
    assert first.action == "candidate"
    assert second.action == "fold" and second.folded_by == "source"
    assert second.folded_into == "1.1.1.1-a-0" and second.episode_windows == 1


def test_queued_once_per_address_per_day() -> None:
    p = Progression()
    for k in range(6):
        p.decide(_fire(minutes=5 * k))
    later = [p.decide(_fire(minutes=120 + 5 * k)) for k in range(6)]
    assert all(s.action in ("candidate", "fold") for s in later)
    assert later[-1].action == "fold", "already queued today"
    tomorrow = [p.decide(_fire(minutes=24 * 60 + 5 * k)) for k in range(6)]
    assert tomorrow[-1].action == "deliver"


def test_progression_survives_a_restart_mid_episode() -> None:
    p = Progression()
    for k in range(3):
        p.decide(_fire(minutes=5 * k))
    doc = json.loads(json.dumps(p.export_state()))
    restored = Progression()
    restored.restore_state(doc)
    steps = [restored.decide(_fire(minutes=15 + 5 * k)) for k in range(3)]
    assert steps[-1].action == "deliver", "the episode resumed at window 4, not 1"

    legacy = {"episodes": [row[:5] for row in doc["episodes"]]}  # pre-window_alert rows
    old = Progression()
    old.restore_state(legacy)
    assert old.decide(_fire(minutes=15)).episode_windows == 4


# ------------------------------ runtime --------------------------------- #


def _benign() -> list[Event]:
    return [e for e in _normal_and_scan() if e.source_ip != "203.0.113.7"]


def _sustained_scanner(ip: str, minutes: int, uas: int = 1) -> list[Event]:
    """One never-seen 404 path every 30 s per user-agent, from T0+60 min."""
    base = T0 + timedelta(minutes=60)
    events = []
    for k in range(minutes * 2):
        for u in range(uas):
            events.append(Event(
                timestamp=base + timedelta(seconds=30 * k + u),
                observer=Observer(server="web01"),
                source_ip=ip, geo_country_iso="ZZ",
                url_path=f"/secret/{u}/dump_{k}.sql", status_code=404,
                http_referrer=None, user_agent=f"scan/{u}.0", body_bytes=100,
                original=f"GET /secret/{u}/dump_{k}.sql 404",
            ))
    return events


def _run(tmp_path: Path, attack: list[Event]) -> DetectionRuntime:
    bundle = train_bundle(WebRecon, usecase_model_factories(WebRecon),
                          lambda: iter(_benign()), source_desc="benign only")
    registry = ModelRegistry(tmp_path)
    registry.save_bundle(bundle)
    registry.promote("web_recon", bundle.version)
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", sorted(_benign() + attack, key=lambda e: e.timestamp))
    rt = DetectionRuntime(RuntimeConfig(input_dir=incoming, data_dir=tmp_path,
                                        mode="live", follow=False), log=lambda *_: None)
    assert rt.run() == 0
    return rt


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_a_sustained_scanner_reaches_the_queue_once(tmp_path: Path) -> None:
    _run(tmp_path, _sustained_scanner("203.0.113.50", minutes=50))
    scores = [r for r in _rows(tmp_path / "state" / "web_recon_scores.ndjson")
              if "203.0.113.50" in r["entity"]]
    assert len(scores) >= 8, "detection is unchanged: every scanner window fires"
    delivered = [r for r in scores if r["disposition"] == "delivered"]
    assert len(delivered) == 1 and delivered[0]["stage"] == "high"
    assert delivered[0]["episode_windows"] == 6
    before = scores[:scores.index(delivered[0])]
    assert {r["disposition"] for r in before} == {"digested"}
    assert all(r["digest_reason"] == "candidate" for r in before)
    after = scores[scores.index(delivered[0]) + 1:]
    assert after and all(r["disposition"] == "folded" and r["folded_by"] == "episode"
                         for r in after)

    alert_doc = _rows(tmp_path / "alerts" / "web_recon.ndjson")[0]
    assert alert_doc["alert"]["severity"] == "high", "one detector alone never claims critical"
    assert alert_doc["links"]["progressive"]["stage"] == "high"
    assert "Sustained" in alert_doc["explanation"]["narrative"]
    digest = _rows(tmp_path / "state" / "web_recon_digest.ndjson")
    assert all("progressive candidate" in d["reason"] for d in digest)
    health = json.loads((tmp_path / "state" / "web_recon_health.json").read_text())
    assert health["alerts_candidates"] == len(before) == health["alerts_digested"]


def test_a_sustained_rotating_scanner_is_one_alert_showing_the_rotation(tmp_path: Path) -> None:
    _run(tmp_path, _sustained_scanner("203.0.113.51", minutes=40, uas=4))
    scores = [r for r in _rows(tmp_path / "state" / "web_recon_scores.ndjson")
              if "203.0.113.51" in r["entity"]]
    assert sum(r["disposition"] == "delivered" for r in scores) == 1
    assert any(r.get("folded_by") == "source" for r in scores), "same-window fragments fold"
    doc = _rows(tmp_path / "alerts" / "web_recon.ndjson")[0]
    assert doc["links"]["source"]["user_agents"] == 4


def test_a_lone_burst_stays_a_visible_candidate(tmp_path: Path) -> None:
    burst = _sustained_scanner("203.0.113.52", minutes=4)
    rt = _run(tmp_path, burst)
    assert rt.stats["alerts_delivered"] == 0
    digest = _rows(tmp_path / "state" / "web_recon_digest.ndjson")
    mine = [d for d in digest if "203.0.113.52" in d["entity"]]
    assert mine and all(d["severity"] == "low" for d in mine)
    assert all("progressive candidate (low, 1 window(s))" in d["reason"] for d in mine)


# ------------- review 2026-10-22: C1 (findings never folded away), C2 ------------ #


def _with_finding(a):
    a.links["findings"] = [{"path": "/.git/config", "status": 200, "bytes": 311}]
    return a


def test_a_finding_is_not_folded_into_a_queued_alert_that_had_none() -> None:
    from zoneinfo import ZoneInfo
    p = Progression(tz=ZoneInfo("Asia/Kolkata"))
    for k in range(6):                       # morning: a plain sustained scanner
        p.decide(_fire(minutes=5 * k))
    evening = _with_finding(_fire(minutes=12 * 60))
    step = p.decide(evening)
    assert step.action == "deliver" and step.escalated, "the success reaches the queue"
    again = _with_finding(_fire(minutes=12 * 60 + 5))
    later = p.decide(again)
    assert later.action == "fold" and later.into_finding, "folds only into an alert with one"


def test_a_finding_from_another_user_agent_in_the_same_window_is_not_lost() -> None:
    p = Progression()
    assert p.decide(_fire(ua="a")).action == "candidate"
    step = p.decide(_with_finding(_fire(ua="b")))
    assert step.action == "deliver" and step.escalated


def test_an_episode_running_across_midnight_is_not_queued_twice() -> None:
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    p = Progression(tz=ist)
    # _fire's clock starts at 08:00 UTC = 13:30 IST; +600 min is 23:30 IST.
    fires = [_fire(minutes=600 + 5 * k) for k in range(16)]
    days = {f.timestamp.astimezone(ist).date() for f in fires}
    assert len(days) == 2, "the episode really crosses the local midnight"
    steps = [p.decide(f) for f in fires]
    delivered = [s for s in steps if s.action == "deliver"]
    assert len(delivered) == 1, "one alert for one continuous scanner, midnight or not"


def test_a_finding_bypasses_the_daily_cap(tmp_path: Path) -> None:
    from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig
    from tests.test_findings import _burst
    rt = _run_with_budget(tmp_path, _burst(found=True), budget=0)
    rows = [r for r in _rows(tmp_path / "state" / "web_recon_scores.ndjson")
            if "203.0.113.60" in r["entity"]]
    assert rows[0]["disposition"] == "delivered" and rows[0]["budget"] == "bypassed: finding"
    assert rows[0]["findings"] == 1
    _ = (DetectionRuntime, RuntimeConfig, rt)


def _run_with_budget(tmp_path: Path, attack: list[Event], budget: int):
    bundle = train_bundle(WebRecon, usecase_model_factories(WebRecon),
                          lambda: iter(_benign()), source_desc="benign only")
    registry = ModelRegistry(tmp_path)
    registry.save_bundle(bundle)
    registry.promote("web_recon", bundle.version)
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", sorted(_benign() + attack, key=lambda e: e.timestamp))
    rt = DetectionRuntime(RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="live",
                                        follow=False, daily_alert_budget=budget),
                          log=lambda *_: None)
    assert rt.run() == 0
    return rt


# ------------- campaign folding (M-001, 23/26 Oct: one botnet, 30 alerts) ------------- #


def _campaign_window(p: Progression, minutes: float, ips: list[str], ua: str = "bot",
                     finding: set[str] = frozenset()) -> dict[str, object]:
    """One five-minute window in which every address fires, as the runtime
    hands a bucket's closed windows over: one after another."""
    out = {}
    for ip in ips:
        a = _fire(ip=ip, minutes=minutes, ua=ua)
        out[ip] = p.decide(_with_finding(a) if ip in finding else a)
    return out


def _sustain(p: Progression, ips: list[str], ua: str = "bot", start: float = 0,
             finding: set[str] = frozenset()) -> dict[str, object]:
    """Six windows: every address reaches the queue stage on the last one."""
    for k in range(5):
        _campaign_window(p, start + 5 * k, ips, ua)
    return _campaign_window(p, start + 25, ips, ua, finding)


def test_one_user_agent_across_many_addresses_at_once_is_one_alert() -> None:
    p = Progression()
    ips = [f"47.82.11.{i}" for i in range(30)]
    last = _sustain(p, ips)
    delivered = [ip for ip, s in last.items() if s.action == "deliver"]
    assert delivered == [ips[0]], "the first member carries the campaign"
    folded = [s for s in last.values() if s.action == "fold"]
    assert len(folded) == 29
    assert {s.folded_by for s in folded} == {"campaign"}
    assert {s.folded_into for s in folded} == {f"{ips[0]}-bot-25"}


def test_a_shared_user_agent_without_co_arrival_is_not_a_campaign() -> None:
    """A common browser string is not an actor: two addresses reaching the
    queue an hour apart stay two alerts."""
    p = Progression()
    first = _sustain(p, ["10.0.0.1"], ua="chrome")
    second = _sustain(p, ["10.0.0.2"], ua="chrome", start=60)
    assert first["10.0.0.1"].action == "deliver"
    assert second["10.0.0.2"].action == "deliver"


def test_different_user_agents_at_once_are_different_campaigns() -> None:
    p = Progression()
    _sustain(p, ["10.0.0.1", "10.0.0.2"], ua="a")
    last = _sustain(p, ["10.0.0.3"], ua="b")
    assert last["10.0.0.3"].action == "deliver"


def test_a_finding_never_folds_into_a_campaign_that_had_none() -> None:
    p = Progression()
    last = _sustain(p, ["10.0.0.1", "10.0.0.2"], finding={"10.0.0.2"})
    assert last["10.0.0.1"].action == "deliver"
    assert last["10.0.0.2"].action == "deliver" and last["10.0.0.2"].escalated


def test_findings_of_one_user_agent_at_once_fold_into_a_finding() -> None:
    """25 Oct: six addresses of one user-agent, each with a finding, in ten minutes."""
    p = Progression()
    steps = _campaign_window(p, 0, ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                             finding={"10.0.0.1", "10.0.0.2", "10.0.0.3"})
    assert steps["10.0.0.1"].action == "deliver" and steps["10.0.0.1"].escalated
    for ip in ("10.0.0.2", "10.0.0.3"):
        assert steps[ip].action == "fold" and steps[ip].folded_by == "campaign"
        assert steps[ip].into_finding, "a finding folds only into an alert with one"


def test_a_campaign_member_later_that_day_folds_into_the_campaign_alert() -> None:
    p = Progression()
    _sustain(p, ["10.0.0.1", "10.0.0.2"])
    later = p.decide(_fire(ip="10.0.0.2", minutes=120, ua="bot"))
    assert later.action == "fold" and later.folded_by == "episode"
    assert later.folded_into == "10.0.0.1-bot-25"


def test_a_campaign_survives_a_restart() -> None:
    p = Progression()
    _sustain(p, ["10.0.0.1"])
    q = Progression()
    q.restore_state(json.loads(json.dumps(p.export_state())))
    last = _sustain(q, ["10.0.0.2"], start=5)      # reaches the queue five minutes later
    assert last["10.0.0.2"].action == "fold"
    assert last["10.0.0.2"].folded_by == "campaign"
