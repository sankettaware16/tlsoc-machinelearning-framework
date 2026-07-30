"""Cross-use-case annotation export (ROADMAP 3.4, JOURNAL D-019).

The store itself, bot_detection's crawler export, and the scorer chain:
bot_detection scores a window -> crawler.* lands in the shared store ->
the next scorer's evidence carries it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import EntityKey, Event, Observer
from soc_ml.detection.annotations import EntityAnnotations
from soc_ml.detection.scorer import ScoreResult, Scorer
from soc_ml.features.window_features import WindowFeatureBuilder
from soc_ml.training.trainer import train_bundle
from soc_ml.usecases.bot_detection import BotDetection

from soc_ml.core.plugins import usecase_model_factories

T0 = datetime(2026, 7, 20, 8, 0, 0, tzinfo=timezone.utc)

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


# ------------------------------- store --------------------------------- #


def test_store_roundtrip_and_overwrite() -> None:
    store = EntityAnnotations()
    store.annotate("e1", {"crawler.human_likeness": 0.9}, at="t1", source="bot_detection")
    got = store.get("e1")
    assert got["crawler.human_likeness"] == 0.9
    assert got["at"] == "t1" and got["source"] == "bot_detection"

    store.annotate("e1", {"crawler.human_likeness": 0.1}, at="t2", source="bot_detection")
    assert store.get("e1")["crawler.human_likeness"] == 0.1, "refresh replaces"
    assert store.get("missing") is None


def test_store_is_bounded_lru() -> None:
    store = EntityAnnotations(max_entities=3)
    for i in range(3):
        store.annotate(f"e{i}", {"v": i}, at="t", source="s")
    store.get("e0")  # touch: e0 becomes warm, e1 is now coldest
    store.annotate("e3", {"v": 3}, at="t", source="s")
    assert store.get("e1") is None, "coldest entity evicted"
    assert store.get("e0") is not None
    assert store.stats["evicted"] == 1


# --------------------------- annotate hook ------------------------------ #


def _outcome(*, gbm: float, declared: bool, verified: bool,
             cluster: float = 0.0, family_robots: bool = False) -> ScoreResult:
    return ScoreResult(
        entity=EntityKey(server="web01", ip="203.0.113.9", ua_hash="h"),
        window_end=T0.isoformat(),
        fused_percentile=0.5,
        per_model={},
        fired=False,
        evidence={"declared_bot": declared, "verified_crawler": verified,
                  "family_robots_txt": family_robots},
        per_model_raw={"gbm_bot": gbm, "gmm": 0.5, "hdbscan_cluster": cluster},
    )


def test_annotate_exports_the_crawler_signal() -> None:
    uc = BotDetection(EnvironmentProfile())
    out = uc.annotate(_outcome(gbm=0.97, declared=True, verified=True))
    assert out["crawler.human_likeness"] == 0.03
    assert out["crawler.is_known"] is True
    assert out["crawler.is_verified"] is True


def test_annotate_marks_undeclared_automation_by_association() -> None:
    uc = BotDetection(EnvironmentProfile())
    out = uc.annotate(_outcome(gbm=0.8, declared=False, verified=False, cluster=0.9))
    assert out["crawler.is_known"] is True, "clustered with the declared bots"
    assert out["crawler.is_verified"] is False


def test_annotate_takes_politeness_from_the_family_scope_too() -> None:
    uc = BotDetection(EnvironmentProfile())
    # this entity never fetched robots.txt itself, but its verified pool did
    out = uc.annotate(_outcome(gbm=0.97, declared=True, verified=True,
                               family_robots=True))
    assert out["crawler.robots_txt"] is True


def test_annotate_on_a_human_reads_human() -> None:
    uc = BotDetection(EnvironmentProfile())
    out = uc.annotate(_outcome(gbm=0.02, declared=False, verified=False))
    assert out["crawler.human_likeness"] == 0.98
    assert out["crawler.is_known"] is False


# --------------------------- scorer chain ------------------------------- #


def _training_events() -> list[Event]:
    """Humans with assets+referrers, declared bots metronomic — both classes."""
    events = []
    for i in range(2200):
        ts = T0 + timedelta(seconds=i * 4 + (i * 7) % 5)
        ip = f"203.0.113.{i % 20}"
        events.append(Event(
            timestamp=ts, observer=Observer(server="web01"), source_ip=ip,
            http_method="GET", http_referrer="/" if i % 3 else None,
            status_code=200, body_bytes=1500 + (i % 7) * 100,
            url_path=["/", "/a", "/b", "/static/app.js", "/static/app.css"][i % 5],
            user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
        ))
    for i in range(1200):
        ts = T0 + timedelta(seconds=i * 8)
        events.append(Event(
            timestamp=ts, observer=Observer(server="web01"), source_ip="198.18.0.9",
            http_method="GET", http_referrer=None, status_code=200, body_bytes=512,
            url_path=f"/page/{i % 300}", user_agent="curl/8.5.0",
        ))
    events.sort(key=lambda e: e.timestamp)
    return events


def test_scoring_a_crawler_window_writes_the_store(tmp_path) -> None:
    events = _training_events()
    bundle = train_bundle(
        BotDetection, usecase_model_factories(BotDetection),
        lambda: iter(events), source_desc="test",
    )
    store = EntityAnnotations()
    scorer = Scorer(BotDetection, bundle, store)
    builder = WindowFeatureBuilder(bundle.profile)

    # fresh scoring traffic: a declared, published-range Googlebot
    scoring = [
        Event(
            timestamp=T0 + timedelta(hours=6, seconds=i * 6),
            observer=Observer(server="web01"), source_ip="66.249.66.1",
            http_method="GET", http_referrer=None, status_code=200,
            body_bytes=600, url_path=f"/page/{i % 50}", user_agent=GOOGLEBOT_UA,
        )
        for i in range(100)
    ]
    results = []
    for e in scoring:
        results.extend(builder.add(e))
    results.extend(builder.flush())
    outcomes = [scorer.score(r) for r in results]
    outcomes = [o for o in outcomes if o is not None]
    assert outcomes, "crawler windows must be scorable"

    entity = str(outcomes[0].entity)
    record = store.get(entity)
    assert record is not None, "bot_detection must export per scored window"
    assert record["source"] == "bot_detection"
    assert record["crawler.is_verified"] is True, "Googlebot from 66.249.64.0/19"
    assert record["crawler.is_known"] is True
    assert record["crawler.human_likeness"] < 0.5, "a crawler must not read human"
    assert not any(o.fired for o in outcomes), "declared bots never self-alert"

    # the next scorer for the same entity sees the annotation in evidence
    builder2 = WindowFeatureBuilder(bundle.profile)
    more = [
        Event(
            timestamp=T0 + timedelta(hours=7, seconds=i * 6),
            observer=Observer(server="web01"), source_ip="66.249.66.1",
            http_method="GET", http_referrer=None, status_code=200,
            body_bytes=600, url_path=f"/page/{i % 50}", user_agent=GOOGLEBOT_UA,
        )
        for i in range(60)
    ]
    results2 = []
    for e in more:
        results2.extend(builder2.add(e))
    results2.extend(builder2.flush())
    scorer.score(results2[0])
    assert (
        results2[0].evidence["entity_annotations"]["crawler.is_verified"] is True
    ), "consumers read what the exporter wrote"
