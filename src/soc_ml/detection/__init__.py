"""Detection runtime — the shared scorer, dedup, and the live loop."""

from .budget import AlertBudget, BudgetDecision
from .dedup import AlertDeduplicator, DedupDecision
from .scorer import Scorer, ScoreResult

__all__ = ["Scorer", "ScoreResult", "AlertDeduplicator", "DedupDecision",
           "AlertBudget", "BudgetDecision"]
from .runtime import DetectionRuntime, RuntimeConfig  # noqa: E402

__all__ += ["DetectionRuntime", "RuntimeConfig"]
