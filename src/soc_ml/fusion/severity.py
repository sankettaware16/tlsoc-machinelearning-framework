"""The single severity formula (SPEC_DIGEST §7) — one formula for all use cases.

    severity_score = round( 100 * fused_confidence * asset_weight
                            + breadth_band + corroboration_band + context_band )

    bands: critical >= 90 | high 70-89 | medium 45-69 | low < 45

Phase-1 honesty note: ``asset_weight`` is specified as *learned* endpoint
sensitivity (0.6-1.0, from response-size profiles, client diversity, role
membership, POST share) and the additive bands come from fusion stages
(campaign breadth, cross-use-case corroboration, context). None of those
producers exist yet — they arrive with UC-04/UC-12 and the full fusion layer —
so callers currently pass the neutral defaults below. The formula is wired now
so alert documents carry the final shape from day one and nothing downstream
needs a schema change later.
"""

from __future__ import annotations

from soc_ml.core.contracts import Severity

__all__ = ["severity_score", "Severity"]

NEUTRAL_ASSET_WEIGHT = 1.0  # replaced by the learned weight (FR-33/FR-61)


def severity_score(
    fused_confidence: float,
    *,
    asset_weight: float = NEUTRAL_ASSET_WEIGHT,
    breadth_band: int = 0,
    corroboration_band: int = 0,
    context_band: int = 0,
) -> tuple[int, Severity]:
    """Compute (0-100 score, band) from a calibrated 0-1 confidence."""
    if not 0.0 <= fused_confidence <= 1.0:
        raise ValueError(f"fused_confidence must be 0-1, got {fused_confidence}")
    score = round(
        100.0 * fused_confidence * asset_weight
        + breadth_band
        + corroboration_band
        + context_band
    )
    score = max(0, min(100, score))
    return score, Severity.from_score(score)
