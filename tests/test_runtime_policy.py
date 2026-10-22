"""Runtime policy the advisory review found wrong (2026-10-22).

* the day: budgets and once-per-day folds counted the UTC date, so an IST SOC's
  daily promise reset at 05:30 local — on 2026-10-21 the three deliveries were
  spent by the first window after 00:00 UTC and a real git dump went to the
  digest (D-034);
* per-use-case run modes (FR-70) were in config but the runtime used one mode;
* the drift sample kept the first ~2,000 windows after each hourly check —
  under two minutes of traffic on elkcc — instead of the hour.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from soc_ml.core.contracts import EntityKey
from soc_ml.detection.budget import AlertBudget, BudgetDecision
from soc_ml.detection.runtime import _DRIFT_RESERVOIR, DetectionRuntime, RuntimeConfig
from soc_ml.fusion.progressive import Progression
from tests.test_detection_lifecycle import _normal_and_scan, _write_events, alert

IST = ZoneInfo("Asia/Kolkata")


def _at(utc: str):
    a = alert()
    a.timestamp = datetime.fromisoformat(utc).replace(tzinfo=UTC)
    return a


def test_the_budget_counts_the_deployments_day() -> None:
    b = AlertBudget(daily_budget=1, tz=IST)
    # 23:00 UTC on the 20th is 04:30 IST on the 21st; 00:05 UTC is 05:35 IST.
    assert b.decide(_at("2026-10-20T23:00:00")) == BudgetDecision.DELIVER
    assert b.decide(_at("2026-10-21T00:05:00")) == BudgetDecision.DIGEST, (
        "same IST day: the UTC midnight is not the SOC's midnight"
    )
    utc = AlertBudget(daily_budget=1)
    utc.decide(_at("2026-10-20T23:00:00"))
    assert utc.decide(_at("2026-10-21T00:05:00")) == BudgetDecision.DELIVER


def test_once_per_address_per_day_uses_the_deployments_day() -> None:
    def fire(utc: str):
        a = _at(utc)
        a.entity = EntityKey(server="web01", ip="9.9.9.9", ua_hash="h")
        a.id = utc
        a.links["findings"] = [{"path": "/.env", "status": 200, "bytes": 9}]
        return a
    p = Progression(tz=IST)
    assert p.decide(fire("2026-10-20T23:00:00")).action == "deliver"
    assert p.decide(fire("2026-10-21T01:00:00")).action == "fold", "still the same IST day"


def test_timezone_names_resolve() -> None:
    assert RuntimeConfig(input_dir=".", timezone_name="Asia/Kolkata").tz == IST
    assert RuntimeConfig(input_dir=".").tz == ZoneInfo("UTC")
    assert RuntimeConfig(input_dir=".", timezone_name="local").tz is not None


def test_each_use_case_runs_in_its_own_mode(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan())
    rt = DetectionRuntime(RuntimeConfig(
        input_dir=incoming, data_dir=tmp_path, mode="live", follow=False,
        allow_cold_start=True, modes={"web_recon": "shadow"}), log=lambda *_: None)
    assert [r.mode for r in rt.runners] == ["shadow"]
    rt.run()
    assert (tmp_path / "state" / "web_recon_shadow.ndjson").exists()
    assert not (tmp_path / "alerts").exists(), "a shadowing use case delivers nothing"
    health = json.loads((tmp_path / "state" / "web_recon_health.json").read_text())
    assert health["mode"] == "shadow"


def test_the_drift_sample_covers_the_whole_period() -> None:
    rt = DetectionRuntime(RuntimeConfig(input_dir=".", follow=False), log=lambda *_: None)
    runner = rt.runners[0]
    n = _DRIFT_RESERVOIR * 10
    for i in range(n):
        rt._collect_drift(runner, SimpleNamespace(features={"f": float(i)}))
    sample = runner.reservoir["f"]
    assert len(sample) == _DRIFT_RESERVOIR
    late = sum(1 for v in sample if v >= n / 2)
    assert 0.4 < late / len(sample) < 0.6, (
        "a uniform sample: about half of it from the second half of the period"
    )
    rt._check_drift()
    assert runner.reservoir == {} and runner.reservoir_seen == 0


def test_the_checkpoint_is_written_through(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan()[:200])
    DetectionRuntime(RuntimeConfig(input_dir=incoming, data_dir=tmp_path, mode="shadow",
                                   follow=False, allow_cold_start=True,
                                   warmup_events=150), log=lambda *_: None).run()
    ckpt = tmp_path / "state" / "web_recon_checkpoint.json"
    assert json.loads(ckpt.read_text())["offsets"]
    assert not ckpt.with_suffix(".tmp").exists()



def test_health_reports_the_gate_fire_share_per_local_hour(tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _normal_and_scan())
    DetectionRuntime(RuntimeConfig(
        input_dir=incoming, data_dir=tmp_path, mode="shadow", follow=False,
        allow_cold_start=True, timezone_name="Asia/Kolkata"), log=lambda *_: None).run()
    health = json.loads((tmp_path / "state" / "web_recon_health.json").read_text())
    assert health["design_share_pct"] == 0.3
    rows = health["fire_share_by_hour"]
    assert rows and all(r["hour"].startswith("2026-07-09T") for r in rows)
    assert rows[0]["hour"].endswith("T13"), "08:00 UTC is 13:30 IST"
    assert sum(r["windows"] for r in rows) == health["windows"]
    assert all(r["vs_design"] == round(r["share_pct"] / 0.3, 2) for r in rows)
