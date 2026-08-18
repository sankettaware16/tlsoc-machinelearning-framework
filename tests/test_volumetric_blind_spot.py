"""The deployed gates cannot see a short single-path flood (JOURNAL D-024).

On 17 August 2026 www.iitb.ac.in absorbed 5,955,459 requests across two bursts
of roughly two minutes, 99.99% of them GET "/" from ~3,868 addresses. The live
runtime ingested every one of those events and emitted no alert.

That was not a model failure. Both deployed gates reject the shape before a
score is ever consulted:

* ``web_recon`` requires ``MIN_DISTINCT_PATHS`` distinct paths. A flood aimed
  at one path can never clear it.
* ``bot_detection`` requires ``SUSTAINED_WINDOWS`` *consecutive* five-minute
  windows. A two-minute burst produces one.

These tests pin that reasoning in place. They are expected to pass while the
blind spot exists: they assert what the current gates do, so that whoever
closes the gap has to come here and say so deliberately.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from soc_ml.usecases import BotDetection, WebRecon

T0 = datetime(2026, 8, 16, 22, 44, 0, tzinfo=timezone.utc)  # burst 1, in UTC


def _flood_evidence(entity: str, window_end: datetime) -> dict:
    """One attacker's five-minute window during the burst.

    Per-source numbers are the report's: 4,750,701 requests over 3,868
    addresses is ~1,228 each, all to "/", answered 429 (a 4xx), no referrer.
    """
    return {
        "entity": entity,
        "window_end": window_end.isoformat(),
        "event_count": 1228,
        "distinct_paths": 1,
        "declared_bot": False,  # the flood declares a desktop Chrome UA
    }


def test_web_recon_cannot_fire_on_a_single_path_flood() -> None:
    uc = WebRecon(profile=None)
    evidence = _flood_evidence("logserver|218.59.117.197|chrome", T0)

    # Even at a percentile far above the gate, the path floor rejects it.
    assert uc.gate(1.0, evidence) is False
    assert evidence["distinct_paths"] < WebRecon.MIN_DISTINCT_PATHS

    # The floor is doing exactly its job — the same entity enumerating paths
    # is caught at the same percentile.
    assert uc.gate(1.0, {**evidence, "distinct_paths": 40}) is True


def test_bot_detection_cannot_fire_on_a_two_minute_burst() -> None:
    uc = BotDetection(profile=None)
    entity = "logserver|218.59.117.197|chrome"

    # The burst lasted ~125 seconds: one window, or two if it straddles a
    # boundary. Neither reaches the sustained requirement.
    assert uc.gate(1.0, _flood_evidence(entity, T0)) is False
    assert uc.gate(1.0, _flood_evidence(entity, T0 + timedelta(minutes=5))) is False
    assert BotDetection.SUSTAINED_WINDOWS == 6

    # Sustained automation of the same shape *is* caught, which is why the
    # requirement is not simply wrong: it is scoped to a different phenomenon.
    # Two windows are already on the streak; the sixth is the one that fires.
    for i in range(2, BotDetection.SUSTAINED_WINDOWS - 1):
        assert uc.gate(1.0, _flood_evidence(entity, T0 + timedelta(minutes=5 * i))) is False
    fired = uc.gate(
        1.0,
        _flood_evidence(entity, T0 + timedelta(minutes=5 * (BotDetection.SUSTAINED_WINDOWS - 1))),
    )
    assert fired is True, "six consecutive windows must fire — the gate is intact"


def test_no_deployed_use_case_is_scoped_to_a_server() -> None:
    """The structural reason, stated once.

    Every gate reasons about one entity's window. A flood's signal is that
    3,868 entities arrived at once, and no entity-scoped gate can express
    that — the aggregate is not any entity's property.
    """
    # Both gates take one window's evidence and nothing about the rest of the
    # server's traffic in that window, so neither can reference a peer view.
    for uc_cls in (WebRecon, BotDetection):
        assert "server_window" not in uc_cls.gate.__code__.co_names
        assert "peer_entities" not in uc_cls.gate.__code__.co_names
