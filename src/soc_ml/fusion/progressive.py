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
from datetime import datetime, timedelta, tzinfo

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
    #: "episode" (the address's queued alert — this episode's, or today's) or
    #: "source" (another user-agent of an address already represented in this
    #: window).
    folded_by: str | None = None
    #: Queued at once because the scan *found* something (D-034).
    escalated: bool = False
    #: Whether the alert this fire folded into itself carried a finding — the
    #: measurable fact that no finding was folded into an alert without one.
    into_finding: bool = False


@dataclass(slots=True)
class _Episode:
    started: datetime
    last: datetime
    windows: int
    #: The alert that represents the episode's current window, and whether it
    #: carried a finding.
    window_alert: str | None = None
    window_found: bool = False
    #: The alert this episode put in the queue, if any, and whether it carried
    #: a finding. Survives midnight: an episode still running at 00:00 is the
    #: same scanner, not a new alert (review 2026-10-22, C2).
    queued_alert: str | None = None
    queued_found: bool = False


class Progression:
    def __init__(self, tz: tzinfo | None = None) -> None:
        #: "Once per address per day" uses the deployment's day (see AlertBudget).
        self.tz = tz
        self._episodes: dict[tuple[str, str], _Episode] = {}
        # (server, ip) -> (local day, queued alert id, that alert carried a finding)
        self._queued: dict[tuple[str, str], tuple[str, str, bool]] = {}
        self.stats = {"delivered": 0, "folded": 0, "candidates": 0, "escalated": 0}

    def decide(self, alert: Alert) -> ProgressionStep:
        """Advance the address's episode, cap the alert's severity, choose an action.

        Mutates ``alert``: ``severity``/``severity_score`` are capped by the
        stage and ``links["progressive"]`` records why (FR-36).

        Folding never hides a finding: a fire that carries one folds only into
        an alert that carried one too; otherwise it is queued as its own
        escalation (review 2026-10-22, C1 — a morning "sustained scanner"
        alert used to swallow the same address's evening ``/.git`` success).
        """
        now = alert.timestamp
        day = (now.astimezone(self.tz) if self.tz else now).date().isoformat()
        self._evict(now, day)
        key = (alert.entity.server, alert.entity.ip)

        episode = self._episodes.get(key)
        if episode is None or now - episode.last > EPISODE_GAP:
            episode = self._episodes[key] = _Episode(started=now, last=now, windows=1)
        elif now > episode.last:
            episode.windows += 1
            episode.last = now
            episode.window_alert = None
            episode.window_found = False

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

        def fold(into: str, by: str, into_found: bool) -> ProgressionStep:
            self.stats["folded"] += 1
            return ProgressionStep("fold", stage, episode.windows, episode.started,
                                   folded_into=into, folded_by=by, into_finding=into_found)

        # 1. This episode already has a queued alert (even from before midnight).
        if episode.queued_alert is not None and (episode.queued_found or not found):
            return fold(episode.queued_alert, "episode", episode.queued_found)
        # 2. The address was queued earlier today, in another episode.
        queued = self._queued.get(key)
        if queued is not None and queued[0] == day and (queued[2] or not found):
            return fold(queued[1], "episode", queued[2])
        # 3. Another user-agent of this address is already this window's alert.
        if episode.window_alert is not None and (episode.window_found or not found):
            return fold(episode.window_alert, "source", episode.window_found)

        episode.window_alert, episode.window_found = alert.id, found
        if found or stage is QUEUE_STAGE:
            self._queued[key] = (day, alert.id, found)
            episode.queued_alert, episode.queued_found = alert.id, found
            self.stats["delivered"] += 1
            if found:
                self.stats["escalated"] += 1
                return ProgressionStep("deliver", stage, episode.windows, episode.started,
                                       escalated=True)
            if alert.narrative:
                alert.narrative += (
                    f" Sustained: the address kept firing for about {minutes} minutes "
                    f"({episode.windows} windows) before this alert was queued."
                )
            return ProgressionStep("deliver", stage, episode.windows, episode.started)
        self.stats["candidates"] += 1
        return ProgressionStep("candidate", stage, episode.windows, episode.started)

    def _evict(self, now: datetime, day: str) -> None:
        stale = [k for k, e in self._episodes.items() if now - e.last > EPISODE_GAP]
        for k in stale:
            del self._episodes[k]
        old = [k for k, q in self._queued.items() if q[0] < day]
        for k in old:
            del self._queued[k]

    # -- durable state ----------------------------------------------------- #
    # Same reasoning as the budget and cooldowns (D-029): a restart must not
    # reset an episode halfway to the queue, nor re-queue an address today.

    def export_state(self) -> dict:
        return {
            "episodes": [[s, ip, e.started.isoformat(), e.last.isoformat(), e.windows,
                          e.window_alert, e.window_found, e.queued_alert, e.queued_found]
                         for (s, ip), e in self._episodes.items()],
            "queued": [[s, ip, d, aid, found]
                       for (s, ip), (d, aid, found) in self._queued.items()],
        }

    def restore_state(self, doc: dict) -> None:
        def opt(row: list, i: int, default):
            return row[i] if len(row) > i else default
        self._episodes = {
            (str(row[0]), str(row[1])): _Episode(
                started=datetime.fromisoformat(row[2]), last=datetime.fromisoformat(row[3]),
                windows=int(row[4]), window_alert=opt(row, 5, None),
                window_found=bool(opt(row, 6, False)), queued_alert=opt(row, 7, None),
                queued_found=bool(opt(row, 8, False)))
            for row in doc.get("episodes") or []
        }
        # Rows from before findings were tracked carry no flag: read "no finding".
        self._queued = {(str(row[0]), str(row[1])): (str(row[2]), str(row[3]),
                                                     bool(opt(row, 4, False)))
                        for row in doc.get("queued") or []}


def _stage(windows: int) -> tuple[Severity, int]:
    for reached, stage, ceiling in _STAGES:
        if windows >= reached:
            return stage, ceiling
    return Severity.LOW, 44
