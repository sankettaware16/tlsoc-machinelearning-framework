"""bot_detection model wrappers (ROADMAP 3.2): GBM, GMM, HDBSCAN.

All fixtures are synthetic and deterministic (arithmetic jitter, no RNG).
The recurring assertions: UA-derived features and the label never become
model inputs (target leakage), scores are [0, 1] and rank bot-like above
human-like, save/load round-trips exactly, and the optional hdbscan model
degrades to absence, never to a crash (NFR-08).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_ml.core.plugins import usecase_model_factories
from soc_ml.models.gbm import GBMBotClassifier
from soc_ml.models.gmm import GMMModel
from soc_ml.models.hdbscan_cluster import HDBSCANClusterModel


def _human_row(i: int) -> dict[str, float]:
    return {
        "bot.asset_fetch_ratio": 0.5 + (i % 7) / 70,
        "bot.activity_hour_entropy": 0.2 + (i % 5) / 100,
        "timing.fano_factor": 1.0 + (i % 9) / 30,
        "bot.method_get_ratio": 0.8 + (i % 3) / 100,
        "ua.len": 118.0,  # leak bait — must never be an input
        "bot.declared_bot": 0.0,
    }


def _bot_row(i: int) -> dict[str, float]:
    return {
        "bot.asset_fetch_ratio": 0.0 + (i % 5) / 200,
        "bot.activity_hour_entropy": 0.9 + (i % 4) / 100,
        "timing.fano_factor": 0.1 + (i % 6) / 100,
        "bot.method_get_ratio": 1.0,
        "ua.len": 15.0,
        "bot.declared_bot": 1.0,
    }


def _corpus(n_human: int = 150, n_bot: int = 150) -> list[dict[str, float]]:
    return [_human_row(i) for i in range(n_human)] + [_bot_row(i) for i in range(n_bot)]


# -------------------------------- GBM ---------------------------------- #


def test_gbm_predicts_bot_from_behavior_only() -> None:
    model = GBMBotClassifier()
    model.fit(_corpus())
    assert model.calibrated is True
    assert "bot.declared_bot" not in model.feature_names, "label is not an input"
    assert not any(f.startswith("ua.") for f in model.feature_names), (
        "UA-derived features are target leakage"
    )
    bot_p = model.score(_bot_row(999))
    human_p = model.score(_human_row(999))
    assert 0.0 <= human_p < 0.5 < bot_p <= 1.0


def test_gbm_score_batch_matches_score() -> None:
    model = GBMBotClassifier()
    model.fit(_corpus())
    rows = [_human_row(1), _bot_row(1), _human_row(2)]
    assert model.score_batch(rows) == [model.score(r) for r in rows]


def test_gbm_single_class_degrades_to_prevalence() -> None:
    model = GBMBotClassifier()
    model.fit([_human_row(i) for i in range(50)])
    assert model.calibrated is False
    assert model.score(_bot_row(0)) == 0.0, "no bots seen -> prevalence 0"


def test_gbm_thin_minority_skips_isotonic_but_still_ranks() -> None:
    model = GBMBotClassifier()
    model.fit([_human_row(i) for i in range(150)] + [_bot_row(i) for i in range(8)])
    assert model.calibrated is False
    assert model.score(_bot_row(999)) > model.score(_human_row(999))


def test_gbm_save_load_roundtrip(tmp_path: Path) -> None:
    model = GBMBotClassifier()
    model.fit(_corpus())
    model.save(tmp_path / "gbm.joblib")
    loaded = GBMBotClassifier()
    loaded.load(tmp_path / "gbm.joblib")
    rows = [_human_row(3), _bot_row(3)]
    assert loaded.score_batch(rows) == model.score_batch(rows)
    assert loaded.calibrated == model.calibrated


def test_gbm_is_deterministic() -> None:
    a, b = GBMBotClassifier(), GBMBotClassifier()
    a.fit(_corpus())
    b.fit(_corpus())
    assert a.score(_bot_row(42)) == b.score(_bot_row(42))


def test_gbm_refuses_rows_without_label() -> None:
    rows = [{k: v for k, v in _human_row(i).items() if k != "bot.declared_bot"}
            for i in range(30)]
    with pytest.raises(ValueError, match="declared_bot"):
        GBMBotClassifier().fit(rows)


# -------------------------------- GMM ---------------------------------- #


def test_gmm_reads_bot_likeness_from_component_association() -> None:
    model = GMMModel()
    model.fit(_corpus())
    assert model.n_components >= 2, "bimodal corpus must not collapse to one mode"
    bot_s = model.score(_bot_row(999))
    human_s = model.score(_human_row(999))
    assert 0.0 <= human_s < 0.3
    assert 0.7 < bot_s <= 1.0


def test_gmm_save_load_roundtrip(tmp_path: Path) -> None:
    model = GMMModel()
    model.fit(_corpus())
    model.save(tmp_path / "gmm.joblib")
    loaded = GMMModel()
    loaded.load(tmp_path / "gmm.joblib")
    rows = [_human_row(5), _bot_row(5)]
    assert loaded.score_batch(rows) == model.score_batch(rows)


def test_gmm_without_declared_bots_scores_zero() -> None:
    model = GMMModel()
    model.fit([_human_row(i) for i in range(60)])
    assert model.score(_human_row(0)) == 0.0, "no bot mass anywhere"


# ------------------------------ HDBSCAN -------------------------------- #


def test_hdbscan_availability_reflects_import() -> None:
    import importlib.util

    expected = importlib.util.find_spec("hdbscan") is not None
    assert HDBSCANClusterModel.available() is expected


def test_factories_skip_unavailable_optional_models(monkeypatch) -> None:
    class FakeUC:
        name = "fake_uc"
        models = ("isolation_forest", "hdbscan_cluster")

    monkeypatch.setattr(HDBSCANClusterModel, "available", classmethod(lambda cls: False))
    factories = usecase_model_factories(FakeUC)
    assert "isolation_forest" in factories
    assert "hdbscan_cluster" not in factories, "unavailable -> skipped, not crashed"


def test_hdbscan_flags_membership_in_bot_majority_cluster() -> None:
    pytest.importorskip("hdbscan")
    model = HDBSCANClusterModel()
    model.fit(_corpus())
    assert model.score(_bot_row(999)) > 0.5
    assert model.score(_human_row(999)) == 0.0
