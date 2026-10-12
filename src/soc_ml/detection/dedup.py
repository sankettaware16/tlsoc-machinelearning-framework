"""Per-entity and per-address alert de-duplication (cooldown).

A scanner active for twenty minutes produces a firing window every five minutes.
Delivering all four as separate alerts is how a SOC queue becomes unreadable —
the same failure static rules have. Until the full campaign-folding fusion stage
exists (Phase 3), a cooldown gives production-grade behaviour: **the first
firing window for an entity is delivered; subsequent firings within the cooldown
are folded into that open alert instead of delivered anew.**

The second level is the address. The entity key is (server, ip, ua_hash), so a
scanner that rotates its user-agent is many entities to the detector — on
elkcc one address became 36 alerts in a single window and spent the day's
budget by itself (D-027). A fire from an address that already has an open
alert, whatever the user-agent, folds into it; the fold reason says so, and
the rotation count is kept on the open alert.

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
_MAX_SOURCE_UAS = 256  # rotation counted up to here; beyond is "many"


@dataclass(slots=True)
class DedupDecision:
    """What to do with a fired alert."""

    deliver: bool
    #: When folded, the id of the open alert it was folded into.
    folded_into: str | None = None
    #: Why it folded: "entity" (same entity inside its cooldown) or "source"
    #: (same server+address, a different user-agent).
    folded_by: str | None = None


class AlertDeduplicator:
    def __init__(self, cooldown_s: int = _DEFAULT_COOLDOWN_S) -> None:
        self.cooldown = timedelta(seconds=cooldown_s)
        # entity -> (open_alert_id, last_event_time, folded_count, peak_confidence)
        self._open: dict[EntityKey, _OpenAlert] = {}
        # (server, ip) -> the open alert for that address, across user-agents
        self._open_sources: dict[tuple[str, str], _OpenSource] = {}
        self.stats = {"delivered": 0, "folded": 0, "folded_by_source": 0}

    def decide(self, alert: Alert) -> DedupDecision:
        now = alert.timestamp
        self._evict(now)
        entity = alert.entity
        source_key = (entity.server, entity.ip)
        state = self._open.get(entity)

        if state is not None:
            # Within cooldown of this entity's open alert -> fold.
            state.last = now
            state.folded += 1
            state.peak = max(state.peak, alert.confidence)
            self._touch_source(source_key, entity, now, alert.confidence)
            self.stats["folded"] += 1
            return DedupDecision(deliver=False, folded_into=state.alert_id,
                                 folded_by="entity")

        source = self._open_sources.get(source_key)
        if source is not None:
            # Same address, another user-agent, inside the open alert's
            # cooldown: one scanner, not a new one.
            self._touch_source(source_key, entity, now, alert.confidence)
            self.stats["folded"] += 1
            self.stats["folded_by_source"] += 1
            return DedupDecision(deliver=False, folded_into=source.alert_id,
                                 folded_by="source")

        self._open[entity] = _OpenAlert(
            alert_id=alert.id, last=now, folded=0, peak=alert.confidence
        )
        self._open_sources[source_key] = _OpenSource(
            alert_id=alert.id, last=now, folded=0, peak=alert.confidence,
            ua_hashes={entity.ua_hash},
        )
        self.stats["delivered"] += 1
        return DedupDecision(deliver=True)

    def _touch_source(self, key: tuple[str, str], entity: EntityKey,
                      now: datetime, confidence: float) -> None:
        source = self._open_sources.get(key)
        if source is None:
            return
        source.last = now
        source.folded += 1
        source.peak = max(source.peak, confidence)
        if len(source.ua_hashes) < _MAX_SOURCE_UAS:
            source.ua_hashes.add(entity.ua_hash)

    def rotation(self, entity: EntityKey) -> int:
        """Distinct user-agents folded into the address's open alert so far."""
        source = self._open_sources.get((entity.server, entity.ip))
        return len(source.ua_hashes) if source else 0

    def _evict(self, now: datetime) -> None:
        stale = [e for e, s in self._open.items() if now - s.last > self.cooldown]
        for entity in stale:
            del self._open[entity]
        stale_sources = [k for k, s in self._open_sources.items()
                         if now - s.last > self.cooldown]
        for key in stale_sources:
            del self._open_sources[key]

    def open_count(self) -> int:
        return len(self._open)

    # -- durable state ----------------------------------------------------- #
    # Lost on restart, an open alert's cooldown re-delivers the same entity
    # as a brand-new alert. Carried in the runtime checkpoint; entries past
    # their cooldown are evicted on the first decision after restore.

    def export_state(self) -> dict:
        return {
            "open": [
                [e.server, e.ip, e.ua_hash, s.alert_id, s.last.isoformat(),
                 s.folded, s.peak]
                for e, s in self._open.items()
            ],
            "open_sources": [
                [server, ip, s.alert_id, s.last.isoformat(), s.folded, s.peak,
                 sorted(s.ua_hashes)]
                for (server, ip), s in self._open_sources.items()
            ],
        }

    def restore_state(self, doc: dict) -> None:
        self._open = {}
        for server, ip, ua_hash, alert_id, last, folded, peak in doc.get("open") or []:
            self._open[EntityKey(server=server, ip=ip, ua_hash=ua_hash)] = _OpenAlert(
                alert_id=str(alert_id), last=datetime.fromisoformat(last),
                folded=int(folded), peak=float(peak),
            )
        self._open_sources = {}
        for server, ip, alert_id, last, folded, peak, uas in doc.get("open_sources") or []:
            self._open_sources[(str(server), str(ip))] = _OpenSource(
                alert_id=str(alert_id), last=datetime.fromisoformat(last),
                folded=int(folded), peak=float(peak), ua_hashes=set(uas),
            )
        # A checkpoint from before address-level folding knows entities only;
        # rebuild the address view from them so the restart does not re-deliver.
        if not self._open_sources:
            for e, s in self._open.items():
                key = (e.server, e.ip)
                src = self._open_sources.get(key)
                if src is None:
                    self._open_sources[key] = _OpenSource(
                        alert_id=s.alert_id, last=s.last, folded=s.folded,
                        peak=s.peak, ua_hashes={e.ua_hash},
                    )
                else:
                    src.last = max(src.last, s.last)
                    src.ua_hashes.add(e.ua_hash)


@dataclass(slots=True)
class _OpenAlert:
    alert_id: str
    last: datetime
    folded: int
    peak: float


@dataclass(slots=True)
class _OpenSource:
    alert_id: str
    last: datetime
    folded: int
    peak: float
    ua_hashes: set
