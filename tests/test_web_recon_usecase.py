"""Tests for the web_recon (UC-02) use case — gate, floor, fusion, vector."""

from __future__ import annotations

from datetime import datetime, timezone

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.core.contracts import EntityKey, FeatureVector
from soc_ml.features.window_features import WEB_RECON_FEATURES
from soc_ml.usecases.web_recon import WebRecon

T0 = datetime(2026, 7, 9, 8, 5, 0, tzinfo=timezone.utc)
ENTITY = EntityKey(server="web01", ip="10.0.0.1", ua_hash="deadbeefdeadbeef")


def profile_with_stats() -> EnvironmentProfile:
    profile = EnvironmentProfile()
    profile.set_feature_stats(
        "web_recon", {"web.ratio_404": {"p50": 0.05, "p99": 0.4}}
    )
    return profile


def full_vector(ratio_404: float = 0.9) -> FeatureVector:
    values = {name: 0.1 for name in WEB_RECON_FEATURES}
    values["web.ratio_404"] = ratio_404
    return FeatureVector(entity=ENTITY, window="5m", computed_at=T0, values=values)


def evidence(events: int = 50, paths: int = 40) -> dict:
    return {"event_count": events, "distinct_paths": paths}


# --------------------------------------------------------------------- #


def test_vector_adds_population_delta_feature() -> None:
    uc = WebRecon(profile_with_stats())
    x = uc.vector(full_vector(ratio_404=0.9))
    assert x is not None
    assert x["web.ratio_404_delta"] == 0.9 - 0.05, (
        "the spec's 'ratio_404 minus population median' feature"
    )


def test_vector_refuses_wrong_window_and_missing_features() -> None:
    uc = WebRecon(profile_with_stats())

    wrong_window = full_vector()
    wrong_window.window = "24h"
    assert uc.vector(wrong_window) is None

    incomplete = full_vector()
    del incomplete.values["ua.rarity"]
    assert uc.vector(incomplete) is None, "refuse rather than zero-fill (FR-24)"


def test_gate_fires_only_at_spec_percentile() -> None:
    uc = WebRecon(profile_with_stats())
    assert uc.gate(0.997, evidence()) is True
    assert uc.gate(0.9969, evidence()) is False
    assert uc.gate(1.0, evidence()) is True


def test_gate_holds_below_evidence_floor() -> None:
    """A perfect score with thin evidence must NOT alert (FR-23/24)."""
    uc = WebRecon(profile_with_stats())
    assert uc.gate(1.0, evidence(events=4, paths=40)) is False, "below MIN_EVENTS"
    assert uc.gate(1.0, evidence(events=50, paths=2)) is False, "below MIN_DISTINCT_PATHS"
    assert uc.gate(1.0, evidence(events=5, paths=3)) is True, "exactly at the floor"


def test_fusion_is_max_of_calibrated_scores() -> None:
    """Spec UC-02: fusion = max of IForest/LOF after percentile conversion."""
    uc = WebRecon(profile_with_stats())
    assert uc.fuse({"isolation_forest": 0.4, "lof_novelty": 0.998}) == 0.998
    assert uc.fuse({"isolation_forest": 0.999, "lof_novelty": 0.2}) == 0.999


def test_naming_triple_is_exact() -> None:
    assert WebRecon.name == "web_recon"
    assert WebRecon.usecase_id == "UC-02"
    assert WebRecon.title == "Web Reconnaissance & Directory Enumeration"
    assert WebRecon.tier == 1
    assert WebRecon.models == ("isolation_forest", "lof_novelty")
