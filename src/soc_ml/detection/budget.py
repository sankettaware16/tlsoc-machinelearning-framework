"""Daily alert-rate governance (FR-34, SPEC §7 step 5).

A single use case gating at the 99.7th percentile fires on ~0.3% of windows by
construction. Cross-entity campaign folding and crawler suppression (Phase 3)
bring the *quality* up, but until then — and as a permanent safety net — the
framework must never flood a SOC queue no matter what the models do.

The budget caps **delivery**, never detection: every score is still recorded and
every fired alert past the budget is written to a **digest** instead of the live
queue, with a visible reason. An operator sees "42 more web_recon alerts today,
see digest" rather than 42 pages. The budget is per use case, per server, per day
(the natural unit an analyst reasons about), and resets on the event-time date so
it behaves identically in backtest and live.
"""

from __future__ import annotations

from soc_ml.core.contracts import Alert

__all__ = ["AlertBudget", "BudgetDecision"]


class BudgetDecision:
    DELIVER = "deliver"
    DIGEST = "digest"  # over budget — route to the daily digest


class AlertBudget:
    """Per-(server, date) delivery cap. Overflow is digested, not dropped."""

    def __init__(self, daily_budget: int) -> None:
        self.daily_budget = daily_budget
        self._counts: dict[tuple[str, str], int] = {}
        self.stats = {"delivered": 0, "digested": 0}

    def decide(self, alert: Alert) -> str:
        day = alert.timestamp.date().isoformat()
        key = (alert.entity.server, day)
        # Bound memory: once a new day appears, older day-keys are dead weight.
        if len(self._counts) > 4096:
            self._counts = {k: v for k, v in self._counts.items() if k[1] >= day}
        used = self._counts.get(key, 0)
        if used >= self.daily_budget:
            self.stats["digested"] += 1
            return BudgetDecision.DIGEST
        self._counts[key] = used + 1
        self.stats["delivered"] += 1
        return BudgetDecision.DELIVER
