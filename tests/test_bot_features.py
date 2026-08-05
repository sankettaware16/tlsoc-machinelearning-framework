"""bot_detection features + labels (ROADMAP 3.1, JOURNAL D-019).

The behavioral features, the self-supervised declared_bot label, and the
verified-crawler identity check. Synthetic fixtures only; addresses are
RFC 5737 documentation IPs or the crawlers' own published ranges.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import Event, Observer
from soc_ml.features.bot_features import (
    BOT_DETECTION_FEATURES,
    claimed_crawler_family,
    declared_bot,
    verified_crawler,
)
from soc_ml.features.window_features import WindowFeatureBuilder

T0 = datetime(2026, 7, 9, 8, 0, 0, tzinfo=timezone.utc)

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def _event(
    ts: datetime,
    ip: str = "203.0.113.10",
    path: str = "/index.html",
    ua: str = BROWSER_UA,
    referrer: str | None = None,
    method: str = "GET",
    status: int = 200,
    body_bytes: int | None = 1000,
) -> Event:
    return Event(
        timestamp=ts,
        observer=Observer(server="web01"),
        source_ip=ip,
        http_method=method,
        http_referrer=referrer,
        status_code=status,
        body_bytes=body_bytes,
        url_path=path,
        user_agent=ua,
    )


def _windows(events: list[Event]):
    builder = WindowFeatureBuilder(EnvironmentProfile())
    results = []
    for e in events:
        results.extend(builder.add(e))
    results.extend(builder.flush())
    return results


# ------------------------------ labels --------------------------------- #


def test_declared_bot_label() -> None:
    assert declared_bot(GOOGLEBOT_UA) is True
    assert declared_bot("curl/8.5.0") is True
    assert declared_bot("python-requests/2.31") is True
    assert declared_bot(None) is True, "no UA at all is script traffic"
    assert declared_bot(BROWSER_UA) is False
    # the production mislabel: honest automation that says monitor/probe,
    # just not with any of the classic bot keywords
    assert declared_bot("netprobe/1.0 (latency monitor)") is True


def test_declared_bot_does_not_mislabel_cubot_phones() -> None:
    ua = "Mozilla/5.0 (Linux; Android 10; CUBOT X30) AppleWebKit/537.36"
    assert declared_bot(ua) is False


def test_claimed_crawler_family() -> None:
    assert claimed_crawler_family(GOOGLEBOT_UA) == "googlebot"
    assert claimed_crawler_family("Mozilla/5.0 (compatible; bingbot/2.0)") == "bingbot"
    assert claimed_crawler_family(BROWSER_UA) is None


def test_verified_crawler_needs_claim_and_published_range() -> None:
    assert verified_crawler("66.249.66.1", GOOGLEBOT_UA) is True
    # claims Googlebot from outside Google's ranges -> spoofing, not verified
    assert verified_crawler("203.0.113.5", GOOGLEBOT_UA) is False
    # right range, no claim -> not verified (identity requires both)
    assert verified_crawler("66.249.66.1", BROWSER_UA) is False
    assert verified_crawler(None, GOOGLEBOT_UA) is False
    assert verified_crawler("not-an-ip", GOOGLEBOT_UA) is False


# --------------------------- window features --------------------------- #


def test_every_bot_feature_is_emitted_per_window() -> None:
    results = _windows([_event(T0 + timedelta(seconds=i)) for i in range(10)])
    assert results
    for name in BOT_DETECTION_FEATURES:
        assert name in results[0].vector.values, f"missing {name}"


def test_asset_fetch_ratio_separates_browsers_from_scripts() -> None:
    # a browser page-load: one document plus its sub-resources
    browser = [
        _event(T0, path="/index.html"),
        _event(T0 + timedelta(seconds=1), path="/static/app.css"),
        _event(T0 + timedelta(seconds=2), path="/static/app.js"),
        _event(T0 + timedelta(seconds=3), path="/img/logo.png"),
    ]
    # a scraper: documents only, from another entity
    scraper = [
        _event(T0 + timedelta(seconds=10 + i), ip="203.0.113.99",
               ua="scrapy/2.11", path=f"/article/{i}")
        for i in range(4)
    ]
    by_ip = {
        r.vector.entity.ip: r.vector.values["bot.asset_fetch_ratio"]
        for r in _windows(browser + scraper)
    }
    assert by_ip["203.0.113.10"] == 0.75
    assert by_ip["203.0.113.99"] == 0.0


def test_path_repeat_and_method_get_ratios() -> None:
    events = [
        _event(T0, path="/poll", method="GET"),
        _event(T0 + timedelta(seconds=1), path="/poll", method="GET"),
        _event(T0 + timedelta(seconds=2), path="/poll", method="GET"),
        _event(T0 + timedelta(seconds=3), path="/submit", method="POST"),
    ]
    values = _windows(events)[0].vector.values
    assert values["bot.path_repeat_ratio"] == 0.5  # 4 events, 2 distinct
    assert values["bot.method_get_ratio"] == 0.75


def test_bytes_per_req_p50_is_the_median() -> None:
    events = [
        _event(T0 + timedelta(seconds=i), body_bytes=b)
        for i, b in enumerate([100, 200, 100_000])
    ]
    assert _windows(events)[0].vector.values["bot.bytes_per_req_p50"] == 200.0


def test_referrer_chains_run_deeper_for_navigation_than_scripts() -> None:
    nav = [
        _event(T0, path="/"),
        _event(T0 + timedelta(seconds=5), path="/courses", referrer="/"),
        _event(T0 + timedelta(seconds=9), path="/courses/ml",
               referrer="https://web01.example/courses"),
        _event(T0 + timedelta(seconds=15), path="/courses/ml/syllabus",
               referrer="/courses/ml?tab=1"),
    ]
    script = [
        _event(T0 + timedelta(seconds=20 + i), ip="203.0.113.99",
               ua="curl/8.5.0", path=f"/api/{i}", referrer=None)
        for i in range(4)
    ]
    by_ip = {
        r.vector.entity.ip: r.vector.values["bot.referrer_chain_depth"]
        for r in _windows(nav + script)
    }
    assert by_ip["203.0.113.10"] == 4.0
    assert by_ip["203.0.113.99"] == 1.0


def test_fano_factor_flags_burst_and_sleep() -> None:
    # steady: one request every 10s across the whole window
    steady = [_event(T0 + timedelta(seconds=i * 10)) for i in range(30)]
    # bursty, same volume: all 30 requests inside the first 30s sub-bin
    bursty = [
        _event(T0 + timedelta(seconds=i), ip="203.0.113.99", path=f"/x/{i}")
        for i in range(30)
    ]
    by_ip = {
        r.vector.entity.ip: r.vector.values["timing.fano_factor"]
        for r in _windows(steady + bursty)
    }
    assert by_ip["203.0.113.10"] < 1.0, "metronomic traffic is sub-Poisson"
    assert by_ip["203.0.113.99"] > 5.0, "burst-and-sleep is super-Poisson"


def test_activity_hour_entropy_grows_with_around_the_clock_activity() -> None:
    # one entity active in a single hour, another active across 12 hours
    single = [_event(T0 + timedelta(seconds=i * 10)) for i in range(20)]
    around = [
        _event(T0 + timedelta(hours=h), ip="203.0.113.99", path=f"/p{h}")
        for h in range(12)
    ]
    results = _windows(single + around)
    single_e = max(
        r.vector.values["bot.activity_hour_entropy"]
        for r in results if r.vector.entity.ip == "203.0.113.10"
    )
    around_e = max(
        r.vector.values["bot.activity_hour_entropy"]
        for r in results if r.vector.entity.ip == "203.0.113.99"
    )
    assert single_e == 0.0
    assert around_e > 0.5


def test_robots_txt_memory_persists_across_windows() -> None:
    events = [_event(T0, path="/robots.txt")] + [
        _event(T0 + timedelta(minutes=20, seconds=i), path=f"/page/{i}")
        for i in range(5)
    ]
    results = _windows(events)
    assert len(results) == 2
    later = results[-1].vector.values
    assert later["bot.robots_txt_fetched"] == 1.0, (
        "the robots.txt fetch happened in an earlier window but is a property "
        "of the entity, not the window"
    )


def test_family_robots_txt_spans_the_crawler_pool() -> None:
    """The production lesson (D-023): Googlebot fetches robots.txt from one
    address of its pool and crawls from others — politeness is per operator."""
    fetcher = _event(T0, ip="66.249.64.5", ua=GOOGLEBOT_UA, path="/robots.txt")
    crawler = [
        _event(T0 + timedelta(seconds=10 + i), ip="66.249.66.1",
               ua=GOOGLEBOT_UA, path=f"/p{i}")
        for i in range(3)
    ]
    results = _windows([fetcher] + crawler)
    by_ip = {r.vector.entity.ip: r.evidence for r in results}
    assert by_ip["66.249.66.1"]["family_robots_txt"] is True, (
        "another verified pool member fetched robots.txt on this server"
    )
    assert by_ip["66.249.66.1"]["verified_crawler"] is True


def test_family_robots_memory_survives_export_restore() -> None:
    """Restart-safety (D-023): a resumed runtime must not forget a verified
    crawler already proved polite — history is skipped on resume."""
    from soc_ml.baseline.profile import EnvironmentProfile

    first = WindowFeatureBuilder(EnvironmentProfile())
    for _ in first.add(_event(T0, ip="66.249.64.5", ua=GOOGLEBOT_UA, path="/robots.txt")):
        pass
    state = first.export_state()
    assert ["logserver", "googlebot"] not in state["family_robots"]  # server is web01
    assert ["web01", "googlebot"] in state["family_robots"]

    resumed = WindowFeatureBuilder(EnvironmentProfile())
    resumed.restore_state(state)
    results = []
    for i in range(3):
        results.extend(resumed.add(
            _event(T0 + timedelta(hours=1, seconds=i), ip="66.249.66.1",
                   ua=GOOGLEBOT_UA, path=f"/p{i}")
        ))
    results.extend(resumed.flush())
    assert results[0].evidence["family_robots_txt"] is True


def test_family_robots_txt_ignores_unverified_claimants() -> None:
    # claims Googlebot from outside the published ranges: its robots.txt
    # fetch must not whitelist the family
    fake = _event(T0, ip="203.0.113.66", ua=GOOGLEBOT_UA, path="/robots.txt")
    real = [
        _event(T0 + timedelta(seconds=10 + i), ip="66.249.66.1",
               ua=GOOGLEBOT_UA, path=f"/p{i}")
        for i in range(3)
    ]
    results = _windows([fake] + real)
    by_ip = {r.vector.entity.ip: r.evidence for r in results}
    assert by_ip["66.249.66.1"]["family_robots_txt"] is False
    assert by_ip["203.0.113.66"]["family_robots_txt"] is False


def test_evidence_carries_identity_context() -> None:
    events = [
        _event(T0 + timedelta(seconds=i), ip="66.249.66.1", ua=GOOGLEBOT_UA,
               path=f"/p{i}")
        for i in range(3)
    ]
    evidence = _windows(events)[0].evidence
    assert evidence["declared_bot"] is True
    assert evidence["crawler_family"] == "googlebot"
    assert evidence["verified_crawler"] is True


def test_declared_bot_rides_in_the_vector_as_the_label() -> None:
    bot = [_event(T0 + timedelta(seconds=i), ua="curl/8.5.0") for i in range(3)]
    human = [_event(T0 + timedelta(seconds=30 + i), ip="203.0.113.99") for i in range(3)]
    by_ip = {
        r.vector.entity.ip: r.vector.values["bot.declared_bot"]
        for r in _windows(bot + human)
    }
    assert by_ip["203.0.113.10"] == 1.0
    assert by_ip["203.0.113.99"] == 0.0
