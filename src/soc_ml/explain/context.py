"""Alert explanation — population context, top features, deterministic narrative.

Every alert must let an analyst see *why* in one glance (FR-40/41/42): which
features drove the score, what this server's normal looks like for each
(``value`` vs ``population_p50``/``p99``), and the verbatim log lines behind it.

Attribution here is population-deviation based — how many "normal ranges" the
value sits above its server median — which is model-agnostic and reads
directly ("47 unique paths/min; normal here is 1, p99 is 3"). Model-specific
attribution (TreeSHAP for forests, per-feature reconstruction error for AEs)
slots in per model family later without changing the alert schema.

Narratives are deterministic templates, never generated prose — an alert that
must stand up in an incident review cannot have non-reproducible wording.
"""

from __future__ import annotations

from typing import Any

from soc_ml.baseline.profile import EnvironmentProfile

__all__ = ["top_features", "narrative"]

_EPS = 1e-9

# How each feature reads in a narrative, in analyst language.
_FEATURE_PHRASES = {
    "web.ratio_404": "share of requests hitting 404",
    "web.ratio_404_delta": "404-share above this server's normal",
    "web.mean_path_idf": "rarity of requested paths on this server",
    "web.path_token_entropy": "spread of path segments (wordlist-like)",
    "web.uniq_paths_per_min": "unique paths per minute",
    "web.unknown_ext_ratio": "requests for file types this app does not serve",
    "web.referrer_absent_ratio": "requests arriving with no referrer",
    "ua.rarity": "rarity of the client user-agent here",
    "ua.len": "user-agent string length",
    "timing.interarrival_cv": "irregularity of request timing",
    "web.status_2xx_ratio": "share of successful responses",
    "web.status_3xx_ratio": "share of redirects",
    "web.status_4xx_ratio": "share of client errors",
    "web.status_5xx_ratio": "share of server errors",
}


def top_features(
    x: dict[str, float],
    profile: EnvironmentProfile,
    usecase: str,
    n: int = 5,
) -> list[dict[str, Any]]:
    """The n features most above their population norm, with that norm attached.

    Deviation = (value - p50) / (p99 - p50): "how far past the median toward
    (and beyond) this server's own extreme is this value". Features without
    population stats (no training coverage) are skipped rather than guessed.
    """
    scored: list[tuple[float, dict[str, Any]]] = []
    for feature, value in x.items():
        pop = profile.population(usecase, feature)
        if not pop:
            continue
        p50, p99 = pop.get("p50", 0.0), pop.get("p99", 0.0)
        # Degenerate population (p99 == p50, e.g. "nobody EVER does this here"):
        # any exceedance is off the chart — cap it so it reads as such instead
        # of an absurd division-by-epsilon number.
        deviation = min((value - p50) / (p99 - p50 + _EPS), 999.0)
        scored.append(
            (
                deviation,
                {
                    "feature": feature,
                    "value": round(value, 4),
                    "population_p50": round(p50, 4),
                    "population_p99": round(p99, 4),
                    "deviation": round(deviation, 2),
                },
            )
        )
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [entry for _, entry in scored[:n]]


def narrative(
    usecase_title: str,
    entity_ip: str,
    server: str,
    evidence: dict[str, Any],
    top: list[dict[str, Any]],
) -> str:
    """One deterministic sentence an analyst can read at 3 a.m."""
    parts = [
        f"{usecase_title}: {entity_ip} on {server} made "
        f"{evidence.get('event_count', '?')} requests "
        f"({evidence.get('distinct_paths', '?')} distinct paths, "
        f"{evidence.get('n404', '?')} were 404) in 5 minutes."
    ]
    for entry in top[:3]:
        phrase = _FEATURE_PHRASES.get(entry["feature"], entry["feature"])
        parts.append(
            f"{phrase}: {entry['value']} vs server median {entry['population_p50']}"
            f" (p99 {entry['population_p99']})."
        )
    return " ".join(parts)
