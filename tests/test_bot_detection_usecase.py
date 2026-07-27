"""bot_detection (UC-04) use case + UA-spoofing gate (ROADMAP 3.3).

Unit tests for vector/fuse/gate semantics, plus one end-to-end backtest over a
synthetic corpus with humans and declared bots — asserting the pipeline
catches the browser-declared, machine-behaving spoofer canary.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import EntityKey, FeatureVector
from soc_ml.evaluation.canary import (
    SPOOFER_CANARY_IP,
    SPOOFER_CANARY_UA,
    is_canary_ip,
    spoofer_canary_events,
)
from soc_ml.features.bot_features import declared_bot
from soc_ml.usecases.bot_detection import BotDetection

T0 = datetime(2026, 7, 20, 8, 0, 0, tzinfo=timezone.utc)


def _uc() -> BotDetection:
    return BotDetection(EnvironmentProfile())


def _evidence(i: int, *, declared: bool = False, count: int = 20) -> dict:
    """Evidence for the i-th consecutive 5-minute window of one entity."""
    return {
        "entity": "web01|203.0.113.7|h",
        "window_end": (T0 + timedelta(minutes=5 * (i + 1))).isoformat(),
        "declared_bot": declared,
        "event_count": count,
    }


# ------------------------------- gate ---------------------------------- #


def test_gate_fires_only_after_six_sustained_windows() -> None:
    uc = _uc()
    fired = [uc.gate(0.999, _evidence(i)) for i in range(6)]
    assert fired == [False] * 5 + [True], "30 minutes = six 5-minute windows"


def test_gate_never_fires_for_declared_bots() -> None:
    uc = _uc()
    assert not any(
        uc.gate(1.0, _evidence(i, declared=True)) for i in range(12)
    ), "declared bots are the training signal, not the alert target"


def test_gate_streak_resets_on_quiet_window_gap() -> None:
    uc = _uc()
    for i in range(5):
        uc.gate(0.999, _evidence(i))
    # entity goes quiet for one bucket, then returns
    assert uc.gate(0.999, _evidence(6)) is False, "gap broke the sustained claim"
    for i in range(7, 12):
        result = uc.gate(0.999, _evidence(i))
    assert result is True, "six new consecutive windows fire again"


def test_gate_streak_resets_below_percentile() -> None:
    uc = _uc()
    for i in range(5):
        uc.gate(0.999, _evidence(i))
    uc.gate(0.5, _evidence(5))  # dips under the gate
    assert uc.gate(0.999, _evidence(6)) is False


def test_gate_enforces_evidence_floor() -> None:
    uc = _uc()
    assert not any(
        uc.gate(0.999, _evidence(i, count=BotDetection.MIN_EVENTS - 1))
        for i in range(12)
    ), "tiny windows are noise, not bot judgments (FR-23)"


# --------------------------- fuse / vector ----------------------------- #


def test_fuse_ignores_cluster_membership() -> None:
    uc = _uc()
    fused = uc.fuse({"gbm_bot": 0.6, "gmm": 0.4, "hdbscan_cluster": 1.0})
    assert fused == 0.6, "sitting in a crawler cluster is not spoofing evidence"


def test_calibration_reference_is_browser_declared_for_gate_models() -> None:
    uc = _uc()
    rows = [{"bot.declared_bot": 0.0, "x.y": 1.0}] * 3 + [
        {"bot.declared_bot": 1.0, "x.y": 9.0}
    ] * 2
    assert len(uc.calibration_rows("gbm_bot", rows)) == 3
    assert len(uc.calibration_rows("gmm", rows)) == 3
    assert len(uc.calibration_rows("hdbscan_cluster", rows)) == 5


def test_vector_requires_completeness_and_5m_window() -> None:
    uc = _uc()
    entity = EntityKey(server="web01", ip="203.0.113.7", ua_hash="h")
    full = dict.fromkeys(uc.requires, 0.5)
    fv = FeatureVector(entity=entity, window="5m", computed_at=T0, values=full)
    x = uc.vector(fv)
    assert x is not None and "bot.declared_bot" in x, "the label rides along"

    assert uc.vector(
        FeatureVector(entity=entity, window="24h", computed_at=T0, values=full)
    ) is None
    partial = dict(full)
    partial.pop("bot.asset_fetch_ratio")
    assert uc.vector(
        FeatureVector(entity=entity, window="5m", computed_at=T0, values=partial)
    ) is None, "refuse rather than zero-fill"


# ------------------------------ canary --------------------------------- #


def test_spoofer_canary_is_browser_declared_machine_traffic() -> None:
    events = spoofer_canary_events("web01", T0)
    assert is_canary_ip(SPOOFER_CANARY_IP)
    assert declared_bot(SPOOFER_CANARY_UA) is False, "must claim a browser"
    span = events[-1].timestamp - events[0].timestamp
    assert span >= timedelta(minutes=30), "must be able to satisfy 'sustained'"
    assert events == spoofer_canary_events("web01", T0), "deterministic (NFR-10)"


# ----------------------------- end to end ------------------------------ #


def _synthetic_mixed_corpus(path: Path, hours: int = 8) -> None:
    """Humans (assets, referrers, ragged timing) + declared bots (machines)."""
    rows = []
    pages = ["/", "/courses", "/about", "/news", "/contact"]
    assets = ["/static/app.css", "/static/app.js", "/img/logo.png"]
    human_ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"
    for i in range(hours * 240):  # a human page-load every 15s across entities
        ts = T0 + timedelta(seconds=i * 15 + (i * 7) % 11)
        ip = f"203.0.113.{i % 30}"
        page = pages[i % len(pages)]
        rows.append((ts, ip, page, human_ua, "/", 200, 2000 + (i % 5) * 300))
        for j, asset in enumerate(assets):
            rows.append(
                (ts + timedelta(seconds=j + 1), ip, asset, human_ua, page, 200, 500)
            )
    for b in range(3):  # three declared bots, metronomic, no assets
        bot_ua = ["curl/8.5.0", "python-requests/2.31",
                  "Mozilla/5.0 (compatible; SeekBot/1.4; +crawler)"][b]
        for i in range(hours * 360):  # every 10s
            ts = T0 + timedelta(seconds=i * 10 + b)
            rows.append(
                (ts, f"198.18.0.{b + 1}", f"/page/{i % 400}", bot_ua, None, 200, 512)
            )
    rows.sort(key=lambda r: r[0])
    with path.open("w", encoding="utf-8") as fh:
        for ts, ip, url, ua, ref, status, size in rows:
            fh.write(json.dumps({
                "@timestamp": ts.isoformat(),
                "observer": {"server": "web01"},
                "source": {"ip": ip, "geo": {"country_iso_code": "US"}},
                "http": {"request": {"method": "GET",
                                     **({"referrer": ref} if ref else {})},
                         "response": {"status_code": status, "body": {"bytes": size}}},
                "url": {"path": url},
                "user_agent": {"original": ua},
                "event": {"original": "synthetic"},
            }) + "\n")


def test_backtest_catches_the_ua_spoofer_canary(tmp_path: Path) -> None:
    from soc_ml.evaluation.backtest import run_backtest

    corpus = tmp_path / "mixed.json"
    _synthetic_mixed_corpus(corpus)
    report = run_backtest(
        corpus, usecase="bot_detection", out_dir=tmp_path / "data"
    )
    assert report["usecase"] == "bot_detection"
    assert report["canary"]["injected"] is True
    assert report["canary"]["detected"] is True, (
        "a browser-declared entity behaving like a machine for 45 minutes "
        "must trip the sustained UA-spoofing gate"
    )
    # declared bots must not be alerted on by this use case
    for entry in report["top_alerts"]:
        assert "curl" not in (entry["narrative"] or "")
