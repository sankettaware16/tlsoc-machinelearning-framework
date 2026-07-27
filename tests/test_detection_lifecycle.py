"""Tests for dedup, budget, drift, and the live runtime."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_ml.core.contracts import Alert, EntityKey, Event, Observer, Severity
from soc_ml.detection.budget import AlertBudget, BudgetDecision
from soc_ml.detection.dedup import AlertDeduplicator
from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig
from soc_ml.drift.psi import DriftReport, population_stability_index

T0 = datetime(2026, 7, 9, 8, 0, 0, tzinfo=timezone.utc)


def alert(ip: str = "1.1.1.1", offset_s: float = 0, server: str = "web01",
          confidence: float = 0.99) -> Alert:
    return Alert(
        id=f"{ip}-{offset_s}",
        timestamp=T0 + timedelta(seconds=offset_s),
        usecase="web_recon",
        entity=EntityKey(server=server, ip=ip, ua_hash="h"),
        severity=Severity.HIGH,
        severity_score=80,
        confidence=confidence,
        narrative="n",
    )


# ------------------------------- dedup --------------------------------- #


def test_dedup_folds_repeat_firings_of_one_entity() -> None:
    d = AlertDeduplicator(cooldown_s=1800)
    assert d.decide(alert(offset_s=0)).deliver is True
    assert d.decide(alert(offset_s=300)).deliver is False, "within cooldown -> fold"
    assert d.decide(alert(offset_s=600)).deliver is False
    assert d.stats == {"delivered": 1, "folded": 2}


def test_dedup_redelivers_after_cooldown() -> None:
    d = AlertDeduplicator(cooldown_s=1800)
    d.decide(alert(offset_s=0))
    assert d.decide(alert(offset_s=2000)).deliver is True, "past cooldown -> new alert"


def test_dedup_is_per_entity() -> None:
    d = AlertDeduplicator()
    assert d.decide(alert(ip="1.1.1.1")).deliver is True
    assert d.decide(alert(ip="2.2.2.2")).deliver is True, "different entity"


# ------------------------------- budget -------------------------------- #


def test_budget_caps_delivery_and_digests_overflow() -> None:
    b = AlertBudget(daily_budget=3)
    decisions = [b.decide(alert(offset_s=i)) for i in range(5)]
    assert decisions[:3] == [BudgetDecision.DELIVER] * 3
    assert decisions[3:] == [BudgetDecision.DIGEST] * 2
    assert b.stats == {"delivered": 3, "digested": 2}


def test_budget_is_per_server_per_day() -> None:
    b = AlertBudget(daily_budget=1)
    assert b.decide(alert(server="a")) == BudgetDecision.DELIVER
    assert b.decide(alert(server="b")) == BudgetDecision.DELIVER, "other server"
    assert b.decide(alert(server="a")) == BudgetDecision.DIGEST, "server a exhausted"
    # next day resets
    assert b.decide(alert(server="a", offset_s=86400)) == BudgetDecision.DELIVER


# -------------------------------- drift -------------------------------- #


def test_psi_zero_for_identical_distributions() -> None:
    ref = [float(i) for i in range(1000)]
    assert population_stability_index(ref, list(ref)) < 0.001


def test_psi_high_for_shifted_distribution() -> None:
    ref = [float(i) for i in range(1000)]
    shifted = [float(i) + 2000 for i in range(1000)]
    assert population_stability_index(ref, shifted) > 0.25


def test_psi_handles_small_and_constant_input() -> None:
    assert population_stability_index([1.0], [1.0]) == 0.0
    assert population_stability_index([5.0] * 100, [5.0] * 100) == 0.0


def test_drift_report_retrain_trigger() -> None:
    calm = DriftReport({"a": 0.05, "b": 0.08})
    assert calm.band == "stable"
    assert calm.should_retrain() is False

    storm = DriftReport({"a": 0.4, "b": 0.3, "c": 0.02})
    assert storm.band == "significant"
    assert storm.drifted_features == ["a", "b"]
    assert storm.should_retrain() is True  # >= 2 features over 0.25


# ------------------------------- runtime ------------------------------- #


def _write_events(path: Path, events: list[Event]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps({
                "@timestamp": e.timestamp.isoformat(),
                "observer": {"server": e.observer.server},
                "source": {"ip": e.source_ip,
                           **({"geo": {"country_iso_code": "US"}} if not e.is_internal else {})},
                "http": {"request": {"method": "GET",
                                     **({"referrer": e.http_referrer} if e.http_referrer else {})},
                         "response": {"status_code": e.status_code}},
                "url": {"path": e.url_path},
                "user_agent": {"original": e.user_agent},
                "event": {"original": e.original or "raw"},
            }) + "\n")


def _normal_and_scan(server: str = "web01") -> list[Event]:
    """Benign browsing + one clear enumeration burst."""
    events = []
    # benign: repeated visits to a few known pages, 200s, with referrers
    for i in range(1500):
        events.append(Event(
            timestamp=T0 + timedelta(seconds=i * 2),
            observer=Observer(server=server),
            source_ip=f"10.0.{i % 5}.{i % 20}", geo_country_iso=None,
            url_path=f"/page{i % 4}.html", status_code=200,
            http_referrer="/home", user_agent="Mozilla/5.0", body_bytes=1000,
            original="benign",
        ))
    # scanner: many never-seen paths, 404s, no referrer, one entity
    base = T0 + timedelta(seconds=4000)
    for i in range(60):
        events.append(Event(
            timestamp=base + timedelta(seconds=i * 2),
            observer=Observer(server=server),
            source_ip="203.0.113.7", geo_country_iso="ZZ",
            url_path=f"/secret/backup_{i}.sql", status_code=404,
            http_referrer=None, user_agent="scan/1.0", body_bytes=100,
            original=f"GET /secret/backup_{i}.sql 404",
        ))
    events.sort(key=lambda e: e.timestamp)
    return events


def test_runtime_cold_start_trains_then_detects(tmp_path: Path) -> None:
    """Turnkey path: no model, learn from traffic, then catch the scanner."""
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan())

    cfg = RuntimeConfig(
        input_dir=incoming, data_dir=tmp_path, mode="live", follow=False,
        allow_cold_start=True, warmup_events=100_000,
    )
    logs: list[str] = []
    rc = DetectionRuntime(cfg, log=logs.append).run()
    assert rc == 0

    # a model was trained and promoted during cold start
    from soc_ml.registry.store import ModelRegistry
    assert ModelRegistry(tmp_path).current_version("web_recon") is not None

    # the scanner was delivered as an alert
    alerts_file = tmp_path / "alerts" / "web_recon.ndjson"
    assert alerts_file.exists()
    ips = {json.loads(l)["entity"]["ip"] for l in alerts_file.read_text().splitlines()}
    assert "203.0.113.7" in ips, "the enumeration scanner must be caught"

    # health was written
    assert (tmp_path / "state" / "web_recon_health.json").exists()


def test_runtime_refuses_without_model_or_cold_start(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan()[:100])
    cfg = RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="live", follow=False)
    logs: list[str] = []
    assert DetectionRuntime(cfg, log=logs.append).run() == 2
    assert any("no trained model" in m for m in logs)


def test_runtime_checkpoint_resumes_without_reprocessing(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan())

    # first run: cold-start + process everything
    cfg = RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="shadow",
                        follow=False, allow_cold_start=True)
    DetectionRuntime(cfg, log=lambda *_: None).run()
    ckpt = tmp_path / "state" / "web_recon_checkpoint.json"
    assert ckpt.exists()

    # second run over the SAME file: checkpoint means nothing new to read
    cfg2 = RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="shadow", follow=False)
    rt = DetectionRuntime(cfg2, log=lambda *_: None)
    rt.run()
    assert rt.stats["events"] == 0, "resumed run must not reprocess consumed events"


def test_runtime_shadow_mode_delivers_nothing(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan())
    cfg = RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="shadow",
                        follow=False, allow_cold_start=True)
    rt = DetectionRuntime(cfg, log=lambda *_: None)
    rt.run()
    assert rt.stats["alerts_delivered"] == 0, "shadow must not deliver"
    assert not (tmp_path / "alerts").exists()
    assert (tmp_path / "state" / "web_recon_shadow.ndjson").exists(), "but must record"
