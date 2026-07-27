"""Tests for sessionization and session features (FR-07)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from soc_ml.core.contracts import Event, Observer
from soc_ml.preprocess import Sessionizer, session_features

T0 = datetime(2026, 7, 9, 8, 0, 0, tzinfo=timezone.utc)


def ev(
    *,
    offset_s: float = 0,
    ip: str = "10.0.0.1",
    ua: str = "Mozilla/5.0",
    path: str = "/",
    status: int = 200,
    method: str = "GET",
    referrer: str | None = None,
    body_bytes: int = 100,
    server: str = "web01",
) -> Event:
    return Event(
        timestamp=T0 + timedelta(seconds=offset_s),
        observer=Observer(server=server),
        source_ip=ip,
        user_agent=ua,
        url_path=path,
        status_code=status,
        http_method=method,
        http_referrer=referrer,
        body_bytes=body_bytes,
    )


# --------------------------------------------------------------------------- #
# Grouping
# --------------------------------------------------------------------------- #


def test_events_within_the_gap_form_one_session() -> None:
    sz = Sessionizer(idle_gap_s=1800)
    for i in range(5):
        assert sz.add(ev(offset_s=i * 60)) == []
    assert sz.open_count == 1

    (session,) = sz.flush()
    assert session.event_count == 5
    assert session.closed is True


def test_exceeding_the_gap_starts_a_new_session() -> None:
    sz = Sessionizer(idle_gap_s=1800)
    sz.add(ev(offset_s=0, path="/a"))
    closed = sz.add(ev(offset_s=1801, path="/b"))

    assert len(closed) == 1
    assert closed[0].event_count == 1
    assert closed[0].entry_path == "/a"
    assert sz.open_count == 1
    assert sz.stats.closed_by_gap == 1


def test_gap_boundary_is_exclusive() -> None:
    """Exactly the gap must not split; the rule is 'greater than'."""
    sz = Sessionizer(idle_gap_s=1800)
    sz.add(ev(offset_s=0))
    assert sz.add(ev(offset_s=1800)) == [], "exactly 1800s must stay in-session"
    assert sz.add(ev(offset_s=3601)) != [], "1801s past last-seen must split"


def test_different_entities_get_different_sessions() -> None:
    sz = Sessionizer()
    sz.add(ev(ip="10.0.0.1"))
    sz.add(ev(ip="10.0.0.2"))
    sz.add(ev(ip="10.0.0.1", ua="curl/8.0"))  # same IP, different UA = different entity
    sz.add(ev(ip="10.0.0.1", server="web02"))  # same IP+UA, different server
    assert sz.open_count == 4


def test_expire_closes_idle_sessions() -> None:
    """Without this a departed entity's session is never scored."""
    sz = Sessionizer(idle_gap_s=1800)
    sz.add(ev(offset_s=0, ip="10.0.0.1"))
    sz.add(ev(offset_s=0, ip="10.0.0.2"))

    assert sz.expire(T0 + timedelta(seconds=600)) == []
    expired = sz.expire(T0 + timedelta(seconds=1801))
    assert len(expired) == 2
    assert sz.open_count == 0


def test_out_of_order_events_do_not_corrupt_timing() -> None:
    """Real multi-worker parser output is only approximately ordered."""
    sz = Sessionizer()
    sz.add(ev(offset_s=100))
    sz.add(ev(offset_s=90))  # arrives late

    (session,) = sz.flush()
    assert sz.stats.out_of_order == 1
    assert session.event_count == 2
    assert all(g >= 0 for g in session.inter_arrivals), "no negative inter-arrivals"
    assert session.last_seen_at == T0 + timedelta(seconds=100), "clock must not go back"


def test_sequences_are_capped_and_truncation_is_recorded() -> None:
    """An uncapped per-session list is how a scraper exhausts memory."""
    sz = Sessionizer(max_sequence=10)
    for i in range(50):
        sz.add(ev(offset_s=i, path=f"/p{i}"))

    (session,) = sz.flush()
    assert session.event_count == 50, "every event still counted"
    assert len(session.paths) == 10, "sequence capped"
    assert session.truncated is True, "truncation must be visible, not silent"
    assert sz.stats.truncated == 1


def test_entry_and_exit_paths_are_tracked() -> None:
    sz = Sessionizer()
    for i, p in enumerate(["/start", "/middle", "/end"]):
        sz.add(ev(offset_s=i, path=p))
    (session,) = sz.flush()
    assert session.entry_path == "/start"
    assert session.exit_path == "/end"


def test_run_streams_events_to_closed_sessions() -> None:
    sz = Sessionizer(idle_gap_s=1800)
    events = [ev(offset_s=0), ev(offset_s=1801), ev(offset_s=1802)]
    sessions = list(sz.run(iter(events)))
    assert len(sessions) == 2
    assert [s.event_count for s in sessions] == [1, 2]


# --------------------------------------------------------------------------- #
# Features
# --------------------------------------------------------------------------- #


def test_session_features_are_computed_correctly() -> None:
    sz = Sessionizer()
    # 4 requests, 10s apart, 2 unique paths, one 404, one with a referrer.
    sz.add(ev(offset_s=0, path="/a", status=200, body_bytes=100, referrer="/x"))
    sz.add(ev(offset_s=10, path="/b", status=404, body_bytes=200))
    sz.add(ev(offset_s=20, path="/a", status=200, body_bytes=300))
    sz.add(ev(offset_s=30, path="/a", status=200, body_bytes=400, method="POST"))
    (session,) = sz.flush()

    f = session_features(session)

    assert f["session.event_count"] == 4
    assert f["session.duration_s"] == 30
    assert f["session.unique_paths"] == 2
    assert f["session.bytes_total"] == 1000
    assert f["session.bytes_per_request"] == 250
    assert f["session.mean_inter_arrival"] == 10
    assert f["session.cv_inter_arrival"] == 0.0, "perfectly regular timing"
    assert f["session.referrer_present_ratio"] == 0.25
    assert f["session.status_2xx_ratio"] == 0.75
    assert f["session.status_4xx_notfound_ratio"] == 0.25
    assert f["session.method_get_ratio"] == 0.75
    assert f["session.method_post_ratio"] == 0.25
    assert f["session.repeat_path_ratio"] == 0.5
    assert f["session.paths_per_minute"] == 8.0


def test_regular_timing_scores_lower_cv_than_irregular() -> None:
    """CV of inter-arrival is the bot-vs-human signal UC-01/04 depend on."""
    bot = Sessionizer()
    for i in range(10):
        bot.add(ev(offset_s=i * 10))
    (bot_session,) = bot.flush()

    human = Sessionizer()
    for i, t in enumerate([0, 3, 40, 45, 120, 121, 300, 480, 481, 900]):
        human.add(ev(offset_s=t))
    (human_session,) = human.flush()

    assert session_features(bot_session)["session.cv_inter_arrival"] < (
        session_features(human_session)["session.cv_inter_arrival"]
    )


def test_auth_failures_are_distinct_from_not_found() -> None:
    """UC-10 decodes a 5-symbol alphabet; 401/403 must not be lumped with 404."""
    sz = Sessionizer()
    sz.add(ev(offset_s=0, status=401))
    sz.add(ev(offset_s=1, status=403))
    sz.add(ev(offset_s=2, status=404))
    sz.add(ev(offset_s=3, status=418))
    (session,) = sz.flush()

    f = session_features(session)
    assert f["session.status_4xx_auth_ratio"] == 0.5
    assert f["session.status_4xx_notfound_ratio"] == 0.25
    assert f["session.status_4xx_other_ratio"] == 0.25


def test_single_event_session_has_no_degenerate_values() -> None:
    """A one-request session must not divide by zero or invent timing."""
    sz = Sessionizer()
    sz.add(ev())
    (session,) = sz.flush()

    f = session_features(session)
    assert f["session.duration_s"] == 0
    assert f["session.mean_inter_arrival"] == 0
    assert f["session.cv_inter_arrival"] == 0
    assert f["session.paths_per_minute"] == 0
    assert f["session.bytes_per_request"] == 100


# --------------------------------------------------------------------------- #
# Against real data
# --------------------------------------------------------------------------- #


def test_sessionizes_real_sample_logs() -> None:
    import json
    from pathlib import Path

    import pytest

    path = Path(__file__).resolve().parents[2] / "log_samples" / "nginx_sample.json"
    if not path.exists():
        pytest.skip("sample not present")

    events = [
        Event.from_ecs(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    events.sort(key=lambda e: e.timestamp)

    sz = Sessionizer(idle_gap_s=1800)
    sessions = list(sz.run(iter(events)))

    assert sessions, "real traffic must produce sessions"
    assert sum(s.event_count for s in sessions) == len(events), "no events lost"
    for s in sessions:
        assert s.closed
        assert s.event_count > 0
        assert s.duration_s >= 0
        session_features(s)  # must not raise on any real session
