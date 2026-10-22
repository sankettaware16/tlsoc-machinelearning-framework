"""Progressive alerting (SPEC_DIGEST §5 UC-02, §7): lone weak signals stay low.

A percentile gate fires on a fixed share of windows by construction, so on a
busy edge it fires thousands of times a day; on elkcc (2026-10-13..20) web_recon
fired on ~3,000 distinct addresses a day and 91% of them fired once and never
again. The spec's answer for UC-02 is progressive alerting — "first candidate
low, upgraded as evidence accumulates over 10 min" — and "lone weak signals stay
low" (§7). This stage implements it at the delivery layer, per address:

* An **episode** is a run of firing windows from one (server, address) with no
  gap longer than ``EPISODE_GAP`` (10 min — the spec's accumulation horizon, so
  one quiet window does not end it). Several user-agents of one address in the
  same window count once, and fold into that window's alert (D-031).
* The alert's severity is **capped by the episode's stage**: one window → low;
  persisting over 10 min → medium; sustained 30 min → high (the spec's
  "sustained", as UC-04 defines it). Critical is left to the additive bands
  (corroboration, context) — one detector's lone view never claims it.
* Only a **high** episode reaches the queue, once per address per event-time
  day; later fires of that address that day fold into it. Everything below
  high goes to the digest as a candidate, with its stage — recorded, visible,
  never dropped (NFR-09). Detection is untouched: every fire still fires.

Measured on the week's real fires: 3,009 addresses/day firing → 3.9 queued
alerts/day (range 1-6), all of them 30-minute sustained scanners. The price,
stated: a scanner that finishes inside one burst and finds nothing never
reaches the queue (it is a low candidate in the digest), and a sustained one
reaches the queue 30 minutes after it began. A scan that *finds* something —
a success on a file type the site never serves, at a path it was never seen
serving — is queued at once with no ceiling: the spec's "transition-to-
success" context band (D-034).

These constants are the specification's time horizons and severity bands, not
data thresholds (FR-62): nothing here is compared against a learned quantity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from soc_ml.core.contracts import Alert, Severity

__all__ = ["Progression", "ProgressionStep", "EPISODE_GAP"]

EPISODE_GAP = timedelta(minutes=10)
#: (windows reached, stage, severity_score ceiling) — ceilings are the top of
#: each spec band: low < 45, medium 45-69, high 70-89.
_STAGES = ((6, Severity.HIGH, 89), (2, Severity.MEDIUM, 69), (1, Severity.LOW, 44))
QUEUE_STAGE = Severity.HIGH


@dataclass(slots=True)
class ProgressionStep:
    """What the delivery layer should do with one fired alert."""

    #: "deliver" (episode just reached the queue), "fold", or "candidate"
    #: (below the queue: digest it).
    action: str
    stage: Severity
    episode_windows: int
    episode_started: datetime
    folded_into: str | None = None
    #: "episode" (address already queued today) or "source" (another
    #: user-agent of an address already represented in this window).
    folded_by: str | None = None
    #: Queued at once because the scan *found* something (D-034).
    escalated: bool = False


@dataclass(slots=True)
class _Episode:
    started: datetime
    last: datetime
    windows: int
    #: The alert that represents the episode's current window, if any.
    window_alert: str | None = None


class Progression:
    def __init__(self) -> None:
        self._episodes: dict[tuple[str, str], _Episode] = {}
        # (server, ip) -> (event-time day, delivered alert id)
        self._queued: dict[tuple[str, str], tuple[str, str]] = {}
        self.stats = {"delivered": 0, "folded": 0, "candidates": 0, "escalated": 0}

    def decide(self, alert: Alert) -> ProgressionStep:
        """Advance the address's episode, cap the alert's severity, choose an action.

        Mutates ``alert``: ``severity``/``severity_score`` are capped by the
        stage and ``links["progressive"]`` records why (FR-36).
        """
        now = alert.timestamp
        day = now.date().isoformat()
        self._evict(now, day)
        key = (alert.entity.server, alert.entity.ip)

        episode = self._episodes.get(key)
        if episode is None or now - episode.last > EPISODE_GAP:
            episode = self._episodes[key] = _Episode(started=now, last=now, windows=1)
        elif now > episode.last:
            episode.windows += 1
            episode.last = now
            episode.window_alert = None

        stage, ceiling = _stage(episode.windows)
        # A scan that got a never-served file type back is not a weak signal,
        # however short: no ceiling, straight to the queue (D-034).
        found = bool(alert.links.get("findings"))
        if found:
            stage, ceiling = Severity.from_score(alert.severity_score), 100
        if alert.severity_score > ceiling:
            alert.severity_score = ceiling
            alert.severity = Severity.from_score(ceiling)
        minutes = round((episode.last - episode.started).total_seconds() / 60) + 5
        alert.links["progressive"] = {
            "stage": stage.value,
            "episode_windows": episode.windows,
            "episode_started": episode.started.isoformat(),
            "episode_minutes": minutes,
            **({"escalated_by": "finding"} if found else {}),
        }

        queued = self._queued.get(key)
        if queued is not None and queued[0] == day:
            self.stats["folded"] += 1
            return ProgressionStep("fold", stage, episode.windows, episode.started,
                                   folded_into=queued[1], folded_by="episode")
        if episode.window_alert is not None:
            self.stats["folded"] += 1
            return ProgressionStep("fold", stage, episode.windows, episode.started,
                                   folded_into=episode.window_alert, folded_by="source")
        episode.window_alert = alert.id
        if found:
            self._queued[key] = (day, alert.id)
            self.stats["delivered"] += 1
            self.stats["escalated"] += 1
            return ProgressionStep("deliver", stage, episode.windows, episode.started,
                                   escalated=True)
        if stage is QUEUE_STAGE:
            self._queued[key] = (day, alert.id)
            if alert.narrative:
                alert.narrative += (
                    f" Sustained: the address kept firing for about {minutes} minutes "
                    f"({episode.windows} windows) before this alert was queued."
                )
            self.stats["delivered"] += 1
            return ProgressionStep("deliver", stage, episode.windows, episode.started)
        self.stats["candidates"] += 1
        return ProgressionStep("candidate", stage, episode.windows, episode.started)

    def _evict(self, now: datetime, day: str) -> None:
        stale = [k for k, e in self._episodes.items() if now - e.last > EPISODE_GAP]
        for k in stale:
            del self._episodes[k]
        old = [k for k, (d, _) in self._queued.items() if d < day]
        for k in old:
            del self._queued[k]

    # -- durable state ----------------------------------------------------- #
    # Same reasoning as the budget and cooldowns (D-029): a restart must not
    # reset an episode halfway to the queue, nor re-queue an address today.

    def export_state(self) -> dict:
        return {
            "episodes": [[s, ip, e.started.isoformat(), e.last.isoformat(), e.windows,
                          e.window_alert]
                         for (s, ip), e in self._episodes.items()],
            "queued": [[s, ip, d, aid] for (s, ip), (d, aid) in self._queued.items()],
        }

    def restore_state(self, doc: dict) -> None:
        self._episodes = {
            (str(row[0]), str(row[1])): _Episode(
                started=datetime.fromisoformat(row[2]), last=datetime.fromisoformat(row[3]),
                windows=int(row[4]), window_alert=row[5] if len(row) > 5 else None)
            for row in doc.get("episodes") or []
        }
        self._queued = {(str(s), str(ip)): (str(d), str(aid))
                        for s, ip, d, aid in doc.get("queued") or []}


def _stage(windows: int) -> tuple[Severity, int]:
    for reached, stage, ceiling in _STAGES:
        if windows >= reached:
            return stage, ceiling
    return Severity.LOW, 44
