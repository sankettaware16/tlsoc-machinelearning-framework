"""Per-entity alert de-duplication (cooldown).

A scanner active for twenty minutes produces a firing window every five minutes.
Delivering all four as separate alerts is how a SOC queue becomes unreadable —
the same failure static rules have. Until the full campaign-folding fusion stage
exists (Phase 3), a cooldown gives production-grade behaviour: **the first
firing window for an entity is delivered; subsequent firings within the cooldown
are folded into that open alert instead of delivered anew.**

This controls *delivery only*. Every score is still recorded upstream — the
folded count is carried on the alert so nothing is hidden (NFR-09).

The cooldown is keyed on the entity, uses event time (not wall-clock) so it
behaves identically in backtest and live, and is memory-bounded by eviction of
entities whose cooldown has fully elapsed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from soc_ml.core.contracts import Alert, EntityKey

__all__ = ["AlertDeduplicator", "DedupDecision"]

_DEFAULT_COOLDOWN_S = 1800  # 30 min — matches the session idle gap


@dataclass(slots=True)
class DedupDecision:
    """What to do with a fired alert."""

    deliver: bool
    #: When folded, the id of the open alert it was folded into.
    folded_into: str | None = None


class AlertDeduplicator:
    def __init__(self, cooldown_s: int = _DEFAULT_COOLDOWN_S) -> None:
        self.cooldown = timedelta(seconds=cooldown_s)
        # entity -> (open_alert_id, last_event_time, folded_count, peak_confidence)
        self._open: dict[EntityKey, _OpenAlert] = {}
        self.stats = {"delivered": 0, "folded": 0}

    def decide(self, alert: Alert) -> DedupDecision:
        now = alert.timestamp
        self._evict(now)
        state = self._open.get(alert.entity)

        if state is None:
            self._open[alert.entity] = _OpenAlert(
                alert_id=alert.id, last=now, folded=0, peak=alert.confidence
            )
            self.stats["delivered"] += 1
            return DedupDecision(deliver=True)

        # Within cooldown of an open alert -> fold.
        state.last = now
        state.folded += 1
        state.peak = max(state.peak, alert.confidence)
        self.stats["folded"] += 1
        return DedupDecision(deliver=False, folded_into=state.alert_id)

    def _evict(self, now: datetime) -> None:
        stale = [e for e, s in self._open.items() if now - s.last > self.cooldown]
        for entity in stale:
            del self._open[entity]

    def open_count(self) -> int:
        return len(self._open)


@dataclass(slots=True)
class _OpenAlert:
    alert_id: str
    last: datetime
    folded: int
    peak: float
