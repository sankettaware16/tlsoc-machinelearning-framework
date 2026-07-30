"""web_recon consumes bot_detection's crawler export (ROADMAP 3.5).

The production false-positive fix: web_recon's gate is untouched — detection
still fires and is recorded — but delivery of a fired alert on a verified,
polite crawler is suppressed, and known/borderline automation is down-weighted
one severity band. Every decision lands on the alert document. The end-to-end
test is the phase's exit criterion: both detectors in one runtime, the
Googlebot-shaped false positive stops being delivered, a real scanner still is.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import Event, Observer, Severity
from soc_ml.core.plugins import usecase_model_factories
from soc_ml.detection.annotations import EntityAnnotations
from soc_ml.detection.runtime import DetectionRuntime, RuntimeConfig
from soc_ml.detection.scorer import Scorer
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases import BotDetection, WebRecon, dependency_order

T0 = datetime(2026, 7, 21, 8, 0, 0, tzinfo=timezone.utc)

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GOOGLEBOT_IP = "66.249.66.1"  # inside Google's published crawl range
# A different pool member fetches robots.txt — the production reality (D-023):
# politeness lives at the operator, not the (ip, ua) entity.
GOOGLEBOT_ROBOTS_IP = "66.249.64.5"


# --------------------------- dependency wiring -------------------------- #


def test_web_recon_depends_on_bot_detection() -> None:
    assert "bot_detection" in WebRecon.depends_on
    ordered = dependency_order([WebRecon, BotDetection])
    assert [c.name for c in ordered] == ["bot_detection", "web_recon"]


# --------------------------- suppression policy ------------------------- #


def _ann(**over) -> dict:
    base = {
        "crawler.human_likeness": 0.1,
        "crawler.is_known": True,
        "crawler.is_verified": True,
        "crawler.robots_txt": True,
        "source": "bot_detection",
        "at": T0.isoformat(),
    }
    base.update(over)
    return base


def test_verified_polite_crawler_is_suppressed() -> None:
    uc = WebRecon(EnvironmentProfile())
    kind, reason = uc.suppression({"entity_annotations": _ann()})
    assert kind == "suppress"
    assert "verified" in reason and "bot_detection" in reason


def test_verified_but_impolite_crawler_is_only_downweighted() -> None:
    uc = WebRecon(EnvironmentProfile())
    kind, reason = uc.suppression(
        {"entity_annotations": _ann(**{"crawler.robots_txt": False})}
    )
    assert kind == "downweight"
    assert "robots.txt" in reason


def test_borderline_automation_is_downweighted() -> None:
    uc = WebRecon(EnvironmentProfile())
    kind, _ = uc.suppression({"entity_annotations": _ann(
        **{"crawler.is_verified": False, "crawler.is_known": False,
           "crawler.human_likeness": 0.3}
    )})
    assert kind == "downweight"


def test_human_or_missing_annotation_delivers_normally() -> None:
    uc = WebRecon(EnvironmentProfile())
    human = _ann(**{"crawler.is_verified": False, "crawler.is_known": False,
                    "crawler.human_likeness": 0.95})
    assert uc.suppression({"entity_annotations": human}) is None
    assert uc.suppression({"entity_annotations": None}) is None
    assert uc.suppression({}) is None, "no signal means unknown, not crawler"


# ----------------------------- scorer level ----------------------------- #


def _benign(n: int = 1500) -> list[Event]:
    return [
        Event(
            timestamp=T0 + timedelta(seconds=i * 2),
            observer=Observer(server="web01"),
            source_ip=f"10.0.{i % 5}.{i % 20}",
            url_path=f"/page{i % 4}.html", status_code=200,
            http_referrer="/home", user_agent="Mozilla/5.0", body_bytes=1000,
        )
        for i in range(n)
    ]


def _scan_burst(ip: str, ua: str, start: datetime, n: int = 60) -> list[Event]:
    return [
        Event(
            timestamp=start + timedelta(seconds=i * 2),
            observer=Observer(server="web01"),
            source_ip=ip, geo_country_iso="ZZ",
            url_path=f"/old/backup_{i}.sql", status_code=404,
            http_referrer=None, user_agent=ua, body_bytes=100,
            original=f"GET /old/backup_{i}.sql 404",
        )
        for i in range(n)
    ]


def _fired_outcomes(scorer: Scorer, bundle, events: list[Event]):
    builder = WindowFeatureBuilder(bundle.profile)
    results = []
    for e in events:
        results.extend(builder.add(e))
    results.extend(builder.flush())
    outcomes = [scorer.score(r) for r in results]
    return [o for o in outcomes if o is not None and o.fired]


def test_scorer_suppresses_and_downweights_fired_alerts(tmp_path: Path) -> None:
    bundle = train_bundle(
        WebRecon, usecase_model_factories(WebRecon),
        lambda: iter(_benign()), source_desc="test",
    )
    burst = _scan_burst("203.0.113.50", "scan/1.0", T0 + timedelta(hours=2))
    entity = str(burst[0].entity)

    # no annotation: fired and delivered, untouched
    plain = _fired_outcomes(Scorer(WebRecon, bundle, EntityAnnotations()), bundle, burst)
    assert plain and all(o.alert.delivered for o in plain)

    # verified + polite annotation: fired, but delivery withheld with a reason
    store = EntityAnnotations()
    store.annotate(entity, {k: v for k, v in _ann().items() if k.startswith("crawler.")},
                   at=T0.isoformat(), source="bot_detection")
    suppressed = _fired_outcomes(Scorer(WebRecon, bundle, store), bundle, burst)
    assert suppressed, "detection itself must be unchanged"
    assert all(not o.alert.delivered for o in suppressed)
    assert all("verified" in o.alert.suppressed_by for o in suppressed)
    assert all(o.record()["suppressed_by"] for o in suppressed), (
        "the shadow/score log must carry the suppression"
    )
    assert all(
        o.alert.links["entity_annotations"]["crawler.is_verified"]
        for o in suppressed
    ), "the alert document carries the annotation snapshot it acted on"

    # borderline annotation: delivered, one severity band lower, reason on doc
    store2 = EntityAnnotations()
    borderline = {"crawler.human_likeness": 0.2, "crawler.is_known": False,
                  "crawler.is_verified": False, "crawler.robots_txt": False}
    store2.annotate(entity, borderline, at=T0.isoformat(), source="bot_detection")
    weighted = _fired_outcomes(Scorer(WebRecon, bundle, store2), bundle, burst)
    assert weighted and all(o.alert.delivered for o in weighted)
    assert all("downweighted_by" in o.alert.links for o in weighted)
    assert all(o.record()["downweighted_by"] for o in weighted), (
        "down-weights must be measurable in the shadow/score log (D-023)"
    )
    plain_score = plain[0].alert.severity_score
    assert weighted[0].alert.severity_score == max(plain_score - 25, 0)
    assert weighted[0].alert.severity == Severity.from_score(
        weighted[0].alert.severity_score
    )


# ------------------------------ end to end ------------------------------ #


def _write_events(path: Path, events: list[Event]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps({
                "@timestamp": e.timestamp.isoformat(),
                "observer": {"server": e.observer.server},
                "source": {"ip": e.source_ip,
                           **({"geo": {"country_iso_code": "ZZ"}}
                              if not e.is_internal else {})},
                "http": {"request": {"method": "GET",
                                     **({"referrer": e.http_referrer}
                                        if e.http_referrer else {})},
                         "response": {"status_code": e.status_code,
                                      "body": {"bytes": e.body_bytes or 0}}},
                "url": {"path": e.url_path},
                "user_agent": {"original": e.user_agent},
                "event": {"original": e.original or "raw"},
            }) + "\n")


def test_runtime_suppresses_googlebot_but_delivers_the_scanner(tmp_path: Path) -> None:
    """Phase 3 exit criterion, offline: the crawler FP stops, detection doesn't."""
    events = _benign(2000)
    # Googlebot's normal presence during the training window: polite crawl,
    # robots.txt first — fetched by a DIFFERENT address of the verified pool
    # than the one that later recrawls (the rotating-pool production shape).
    # This also gives the GBM its declared-bot class.
    events.append(Event(
        timestamp=T0, observer=Observer(server="web01"),
        source_ip=GOOGLEBOT_ROBOTS_IP, geo_country_iso="ZZ",
        url_path="/robots.txt", status_code=200, http_referrer=None,
        user_agent=GOOGLEBOT_UA, body_bytes=200,
    ))
    events += [
        Event(
            timestamp=T0 + timedelta(seconds=20 + i * 20),
            observer=Observer(server="web01"),
            source_ip=GOOGLEBOT_IP, geo_country_iso="ZZ",
            url_path=f"/page{i % 6}.html", status_code=200,
            http_referrer=None, user_agent=GOOGLEBOT_UA, body_bytes=900,
        )
        for i in range(180)
    ]
    # After training: Googlebot recrawls dead links (the production FP shape)
    # and a genuine browser-declared scanner enumerates.
    events += _scan_burst(GOOGLEBOT_IP, GOOGLEBOT_UA, T0 + timedelta(seconds=5000))
    events += _scan_burst("203.0.113.77", "scan/1.0", T0 + timedelta(seconds=5200))
    events.sort(key=lambda e: e.timestamp)

    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _write_events(incoming / "logs.json", events)

    cfg = RuntimeConfig(
        usecases=("web_recon", "bot_detection"),
        input_dir=incoming, data_dir=tmp_path, mode="live", follow=False,
        allow_cold_start=True, warmup_events=4200,
    )
    rt = DetectionRuntime(cfg, log=lambda *_: None)
    assert rt.run() == 0

    alerts_file = tmp_path / "alerts" / "web_recon.ndjson"
    assert alerts_file.exists(), "the scanner must still be delivered"
    delivered_ips = {
        json.loads(line)["entity"]["ip"]
        for line in alerts_file.read_text().splitlines()
    }
    assert "203.0.113.77" in delivered_ips, "real recon still alerts"
    assert GOOGLEBOT_IP not in delivered_ips, (
        "the verified crawler must not reach the queue"
    )

    suppressed_file = tmp_path / "state" / "web_recon_suppressed.ndjson"
    assert suppressed_file.exists(), "suppression must leave a visible record"
    rows = [json.loads(line) for line in suppressed_file.read_text().splitlines()]
    assert any(
        GOOGLEBOT_IP in r["entity"] and "verified" in r["suppressed_by"]
        for r in rows
    )
    assert rt.stats["alerts_suppressed"] >= 1
    health = json.loads((tmp_path / "state" / "web_recon_health.json").read_text())
    assert health["alerts_suppressed"] >= 1
