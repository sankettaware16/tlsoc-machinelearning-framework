"""Naming-standard enforcement (docs/NAMING.md).

The standard says naming compliance is CI-tested — this is that test. A use
case with a malformed slug, a missing title, or a module that doesn't match its
slug fails here, not in a code review three weeks later.
"""

from __future__ import annotations

import re
from pathlib import Path

import soc_ml.alerting  # noqa: F401 — populate the registry
import soc_ml.models  # noqa: F401
import soc_ml.usecases  # noqa: F401
from soc_ml.core import registry

SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{2,30}$")
SPEC_ID_RE = re.compile(r"^(UC|AU)-\d{2}$")
NAMING_MD = Path(__file__).resolve().parents[1] / "docs" / "NAMING.md"


def test_every_usecase_carries_a_valid_naming_triple() -> None:
    usecases = registry.all("usecase")
    assert usecases, "no use cases registered"
    for slug, cls in usecases.items():
        assert SLUG_RE.match(slug), f"{slug!r} is not a valid slug"
        assert cls.name == slug, "registry key must equal Plugin.name"
        assert SPEC_ID_RE.match(cls.usecase_id), (
            f"{slug}: usecase_id {cls.usecase_id!r} must look like UC-nn/AU-nn"
        )
        assert cls.title.strip(), f"{slug}: title is required (rule.name in alerts)"
        assert cls.tier in (1, 2, 3), f"{slug}: tier must be 1..3"


def test_usecase_module_name_matches_slug() -> None:
    for slug, cls in registry.all("usecase").items():
        module_base = cls.__module__.rsplit(".", 1)[-1]
        assert module_base == slug, (
            f"{slug}: lives in module {module_base!r} — module name must equal "
            "the slug (docs/NAMING.md §1)"
        )


def test_slugs_come_from_the_catalog() -> None:
    """Every slug must be pre-registered in NAMING.md — no improvised names."""
    catalog = NAMING_MD.read_text(encoding="utf-8")
    for slug, cls in registry.all("usecase").items():
        assert f"`{slug}`" in catalog, (
            f"{slug}: not in the NAMING.md catalog — add it there (with spec ID "
            "and title) before registering the use case"
        )


def test_model_and_sink_names_are_slugs() -> None:
    for kind in ("model", "sink"):
        for slug in registry.all(kind):
            assert SLUG_RE.match(slug), f"{kind} {slug!r} is not a valid slug"


def test_feature_names_are_namespaced() -> None:
    from soc_ml.features import BOT_DETECTION_FEATURES, WEB_RECON_FEATURES

    pattern = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    for feature in WEB_RECON_FEATURES + BOT_DETECTION_FEATURES:
        assert pattern.match(feature), (
            f"feature {feature!r} must be <group>.<name> snake_case"
        )
