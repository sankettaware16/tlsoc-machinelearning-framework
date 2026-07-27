"""Multi-use-case plumbing (ROADMAP 3.0).

One runtime scores N use cases per window in dependency order, each with its
own bundle, dedup, budget, and per-slug state files; train/backtest/run resolve
any registered slug through the plugin registry instead of a hardcoded map.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_ml.cli.main import main
from soc_ml.core import registry
from soc_ml.core.contracts import Event, Observer
from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig
from soc_ml.usecases import WebRecon, dependency_order

T0 = datetime(2026, 7, 9, 8, 0, 0, tzinfo=timezone.utc)


# ------------------------- dependency ordering ------------------------- #
# Plain classes (not UseCase subclasses) so nothing registers globally.


def _uc(slug: str, deps: tuple[str, ...] = ()) -> type:
    return type(f"Fake_{slug}", (), {"name": slug, "depends_on": deps})


def test_dependency_order_schedules_exporters_before_consumers() -> None:
    consumer = _uc("web_recon", deps=("bot_detection",))
    exporter = _uc("bot_detection")
    ordered = dependency_order([consumer, exporter])
    assert [c.name for c in ordered] == ["bot_detection", "web_recon"]


def test_dependency_order_is_deterministic_for_independent_cases() -> None:
    a, b, c = _uc("charlie"), _uc("alpha"), _uc("bravo")
    assert [x.name for x in dependency_order([a, b, c])] == ["alpha", "bravo", "charlie"]
    assert [x.name for x in dependency_order([c, b, a])] == ["alpha", "bravo", "charlie"]


def test_dependency_order_ignores_deps_outside_the_set() -> None:
    # web_recon depends on bot_detection, but only web_recon is deployed:
    # it must still schedule (the missing signal is the consumer's problem).
    only = _uc("web_recon", deps=("bot_detection",))
    assert [c.name for c in dependency_order([only])] == ["web_recon"]


def test_dependency_order_rejects_cycles() -> None:
    a = _uc("a_case", deps=("b_case",))
    b = _uc("b_case", deps=("a_case",))
    with pytest.raises(ValueError, match="cycle"):
        dependency_order([a, b])


# ------------------------- CLI slug resolution ------------------------- #


def test_train_unknown_usecase_lists_available(tmp_path: Path, capsys) -> None:
    log = tmp_path / "x.json"
    log.write_text("", encoding="utf-8")
    rc = main(["train", "--input", str(log), "--uc", "no_such_case"])
    assert rc == 3
    err = capsys.readouterr().err
    assert "no_such_case" in err and "web_recon" in err, (
        "the error must name what was asked for and list what exists"
    )


def test_backtest_unknown_usecase_lists_available(tmp_path: Path, capsys) -> None:
    log = tmp_path / "x.json"
    log.write_text("", encoding="utf-8")
    rc = main(["backtest", "--input", str(log), "--uc", "no_such_case"])
    assert rc == 3
    assert "web_recon" in capsys.readouterr().err


# --------------------- runtime with N use cases ------------------------ #


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


def _traffic(server: str = "web01") -> list[Event]:
    events = []
    for i in range(1500):
        events.append(Event(
            timestamp=T0 + timedelta(seconds=i * 2),
            observer=Observer(server=server),
            source_ip=f"10.0.{i % 5}.{i % 20}", geo_country_iso=None,
            url_path=f"/page{i % 4}.html", status_code=200,
            http_referrer="/home", user_agent="Mozilla/5.0", body_bytes=1000,
            original="benign",
        ))
    return events


@pytest.fixture()
def second_usecase():
    """Register a second use case for the duration of one test.

    It reuses web_recon's features/models (this is plumbing under test, not
    detection) and declares web_recon as its dependency, then is removed from
    the registry so the naming-standard tests never see it.
    """

    class EchoRecon(WebRecon):
        name = "echo_recon"
        usecase_id = "UC-99"
        title = "Echo (test double)"
        depends_on = ("web_recon",)

    try:
        yield EchoRecon
    finally:
        registry._by_kind["usecase"].pop("echo_recon", None)


def test_runtime_scores_n_usecases_with_isolated_state(
    tmp_path: Path, second_usecase
) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", _traffic())

    cfg = RuntimeConfig(
        usecases=("echo_recon", "web_recon"),  # deliberately consumer-first
        input_dir=incoming, data_dir=tmp_path, mode="shadow",
        follow=False, allow_cold_start=True,
    )
    rt = DetectionRuntime(cfg, log=lambda *_: None)

    # dependency order corrected the CLI-supplied order
    assert [r.slug for r in rt.runners] == ["web_recon", "echo_recon"]

    assert rt.run() == 0
    assert rt.stats["events"] == 1500

    # each use case trained, promoted, and kept fully separate state
    from soc_ml.registry.store import ModelRegistry
    reg = ModelRegistry(tmp_path)
    for slug in ("web_recon", "echo_recon"):
        assert reg.current_version(slug) is not None, f"{slug} must be promoted"
        assert (tmp_path / "state" / f"{slug}_shadow.ndjson").exists()
        health = json.loads((tmp_path / "state" / f"{slug}_health.json").read_text())
        assert health["usecase"] == slug
        assert health["windows"] > 0

    # the shared ingest checkpoint is keyed by the sorted use-case set
    assert (tmp_path / "state" / "echo_recon+web_recon_checkpoint.json").exists()


def test_runtime_budgets_default_per_usecase(tmp_path: Path) -> None:
    cfg = RuntimeConfig(usecases=("web_recon",), input_dir="unused", data_dir=tmp_path)
    rt = DetectionRuntime(cfg, log=lambda *_: None)
    assert rt.runners[0].budget.daily_budget == WebRecon.daily_alert_budget

    override = RuntimeConfig(
        usecases=("web_recon",), input_dir="unused", data_dir=tmp_path,
        daily_alert_budget=7,
    )
    rt2 = DetectionRuntime(override, log=lambda *_: None)
    assert rt2.runners[0].budget.daily_budget == 7


def test_runtime_rejects_unknown_usecase(tmp_path: Path) -> None:
    cfg = RuntimeConfig(usecases=("nope",), input_dir="unused", data_dir=tmp_path)
    with pytest.raises(ValueError, match="available"):
        DetectionRuntime(cfg, log=lambda *_: None)
