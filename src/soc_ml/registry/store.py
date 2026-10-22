"""Model registry — versioned, on-disk, zero-infra (the standalone default).

A **bundle** is everything needed to score one use case: the Environment
Profile, the fitted models, their calibrators, feature stats, and metadata. It
is the unit that is versioned, promoted, loaded, and rolled back — "nothing
unversioned may serve" (FR-53).

Layout on disk::

    data/models/<usecase>/
        <version>/                     one immutable bundle
            profile.json
            <model>.joblib             one per model in the bundle
            calibration.json
            feature_stats.json
            metadata.json
        current      -> text file naming the promoted version (what serves)
        candidate    -> text file naming a challenger awaiting promotion

Design choices that matter in production:

* **Immutable versions.** A version directory is written once. Promotion never
  edits a bundle, it repoints ``current``. Rollback is repointing back.
* **Atomic pointer swap.** ``current`` is updated via write-temp-then-rename, so
  a crash mid-promote never leaves a half-written pointer — a reader sees either
  the old version or the new one, never garbage (NFR-09).
* **Keep N hot.** Old versions are pruned but the last N are retained for
  instant rollback (spec: 3 hot). Pruning never touches ``current``/``candidate``.
* **MLflow later.** This is the ``standalone`` implementation of the same
  interface; an MLflow-backed store swaps in at the ``enterprise`` profile
  without touching callers.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soc_ml.baseline.profile import EnvironmentProfile
from soc_ml.fusion.calibration import PercentileCalibrator

__all__ = ["ModelBundle", "ModelRegistry", "PromotionRefused", "APPROVAL_FILE"]

log = logging.getLogger(__name__)

_HOT_VERSIONS = 3  # keep this many old versions for rollback (spec §14)

#: Written by scripts/check_candidate.py into the candidate's bundle directory.
APPROVAL_FILE = "approval_check.json"
_APPROVING = ("PASS", "WARN")


class PromotionRefused(ValueError):
    """A version may not serve without a recorded verdict (FR-55, D-035)."""


@dataclass
class ModelBundle:
    """Everything required to score one use case at one version.

    ``models`` holds already-fitted Model instances keyed by slug. ``metadata``
    is the audit record (training window, row counts, feature-code SHA, gate,
    hygiene, and — once evaluated — canary/volume results).
    """

    usecase: str
    version: str
    profile: EnvironmentProfile
    models: dict[str, Any]
    calibrators: dict[str, PercentileCalibrator]
    metadata: dict[str, Any] = field(default_factory=dict)
    #: Bounded per-feature sample of the training distribution — the reference
    #: PSI drift detection compares live traffic against (feature -> values).
    reference_sample: dict[str, list[float]] = field(default_factory=dict)

    # -- persistence ------------------------------------------------------- #

    def save(self, bundle_dir: Path) -> None:
        bundle_dir.mkdir(parents=True, exist_ok=True)
        self.profile.save(bundle_dir / "profile.json")
        for slug, model in self.models.items():
            model.save(bundle_dir / f"{slug}.joblib")
        PercentileCalibrator.save_many(self.calibrators, bundle_dir / "calibration.json")
        (bundle_dir / "feature_stats.json").write_text(
            json.dumps(self.profile.feature_stats), encoding="utf-8"
        )
        (bundle_dir / "drift_reference.json").write_text(
            json.dumps(self.reference_sample), encoding="utf-8"
        )
        (bundle_dir / "metadata.json").write_text(
            json.dumps(self.metadata, indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, bundle_dir: Path, model_factories: dict[str, type]) -> ModelBundle:
        """Load a bundle. ``model_factories`` maps slug -> Model class."""
        metadata = json.loads((bundle_dir / "metadata.json").read_text())
        profile = EnvironmentProfile.load(bundle_dir / "profile.json")
        calibrators = PercentileCalibrator.load_many(bundle_dir / "calibration.json")
        ref_path = bundle_dir / "drift_reference.json"
        reference = json.loads(ref_path.read_text()) if ref_path.exists() else {}
        models: dict[str, Any] = {}
        for slug, factory in model_factories.items():
            path = bundle_dir / f"{slug}.joblib"
            if not path.exists() or slug not in calibrators:
                # A model declared after this bundle was trained (D-036): the
                # bundle serves as trained, without it — the same visible
                # degradation as a missing optional dependency (NFR-08).
                log.warning("%s %s: no %s in this bundle — serving without it",
                            metadata.get("usecase"), bundle_dir.name, slug)
                continue
            model = factory()
            model.load(path)
            models[slug] = model
        return cls(
            usecase=metadata.get("usecase", bundle_dir.parent.name),
            version=metadata.get("version", bundle_dir.name),
            profile=profile,
            models=models,
            calibrators=calibrators,
            metadata=metadata,
            reference_sample=reference,
        )


class ModelRegistry:
    """On-disk registry rooted at ``<root>/models``."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root) / "models"

    # -- paths ------------------------------------------------------------- #

    def _uc_dir(self, usecase: str) -> Path:
        return self.root / usecase

    def bundle_dir(self, usecase: str, version: str) -> Path:
        return self._uc_dir(usecase) / version

    # -- writing ----------------------------------------------------------- #

    @staticmethod
    def new_version(now: datetime | None = None) -> str:
        now = now or datetime.now(UTC)
        return "v" + now.strftime("%Y%m%dT%H%M%S")

    def save_bundle(self, bundle: ModelBundle) -> Path:
        path = self.bundle_dir(bundle.usecase, bundle.version)
        bundle.save(path)
        return path

    # -- pointers ---------------------------------------------------------- #

    def _pointer(self, usecase: str, name: str) -> Path:
        return self._uc_dir(usecase) / name

    def _read_pointer(self, usecase: str, name: str) -> str | None:
        p = self._pointer(usecase, name)
        if not p.exists():
            return None
        version = p.read_text(encoding="utf-8").strip()
        # A pointer to a version that was pruned is stale, not authoritative.
        return version if (version and self.bundle_dir(usecase, version).is_dir()) else None

    def _write_pointer(self, usecase: str, name: str, version: str) -> None:
        p = self._pointer(usecase, name)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(version, encoding="utf-8")
        os.replace(tmp, p)  # atomic on POSIX — no half-written pointer

    def current_version(self, usecase: str) -> str | None:
        return self._read_pointer(usecase, "current")

    def candidate_version(self, usecase: str) -> str | None:
        return self._read_pointer(usecase, "candidate")

    def versions(self, usecase: str) -> list[str]:
        d = self._uc_dir(usecase)
        if not d.is_dir():
            return []
        return sorted(
            p.name for p in d.iterdir() if p.is_dir() and p.name.startswith("v")
        )

    # -- lifecycle transitions -------------------------------------------- #

    def set_candidate(self, usecase: str, version: str) -> None:
        self._require(usecase, version)
        self._write_pointer(usecase, "candidate", version)

    def promote(self, usecase: str, version: str | None = None, *,
                force_reason: str | None = None) -> str:
        """Make ``version`` (or the current candidate) the serving bundle.

        Refused (``PromotionRefused``) unless the version carries an approval
        report with a PASS or WARN verdict *checked against the bundle serving
        now* — a candidate that passed its canary was once blind to a live
        botnet, and only a replay that someone happened to run caught it
        (D-032). Exceptions, both recorded in the bundle's metadata: nothing is
        serving yet (bootstrap — nothing to compare against), or an operator
        ``force_reason``. Records the displaced version as ``rollback_target``.
        Clears the candidate pointer; prunes old versions but always keeps
        ``current``, the candidate and the rollback target.
        """
        version = version or self.candidate_version(usecase)
        if not version:
            raise ValueError(f"{usecase}: no version given and no candidate to promote")
        self._require(usecase, version)
        current = self.current_version(usecase)
        if version != current:
            gate = self._promotion_gate(usecase, version, current, force_reason)
            self.update_metadata(usecase, version, promotion={
                **gate, "at": datetime.now(UTC).isoformat(), "displaced": current,
            }, rollback_target=current)
        self._write_pointer(usecase, "current", version)
        cand = self._pointer(usecase, "candidate")
        if cand.exists():
            cand.unlink()
        self._prune(usecase)
        return version

    def _promotion_gate(self, usecase: str, version: str, current: str | None,
                        force_reason: str | None) -> dict[str, Any]:
        if current is None:
            return {"gate": "bootstrap"}
        report = self.approval(usecase, version) or {}
        verdict = report.get("verdict")
        if verdict in _APPROVING and report.get("serving") == current:
            return {"gate": "approval_check", "verdict": verdict,
                    "checked_at": report.get("generated_at")}
        if force_reason and force_reason.strip():
            return {"gate": "forced", "reason": force_reason.strip(), "verdict": verdict}
        if not report:
            why = "it has no approval report — run scripts/check_candidate.py"
        elif verdict not in _APPROVING:
            why = f"its approval check says {verdict}"
        else:
            why = (f"its approval check compared it with {report.get('serving')}, "
                   f"but {current} is serving now — re-run scripts/check_candidate.py")
        raise PromotionRefused(
            f"{usecase}: refusing to promote {version}: {why} "
            f"(an operator may override with --force --reason)")

    def rollback_target(self, usecase: str) -> str | None:
        """Where ``rollback`` would go, or None: only a version that has served.

        First the version the serving bundle displaced (recorded at promotion);
        otherwise the most recently promoted other version. Never the pending
        candidate and never a version without a promotion record — rollback is
        not a way around the approval gate (review 2026-10-22, C6/C17: the old
        "newest other version" fallback could serve a DO_NOT_APPROVE candidate).
        """
        current = self.current_version(usecase)
        if current is None:
            return None
        target = (self.metadata(usecase, current) or {}).get("rollback_target")
        if target and target != current and self.bundle_dir(usecase, target).is_dir():
            return target
        candidate = self.candidate_version(usecase)
        served = []
        for version in self.versions(usecase):
            if version in (current, candidate):
                continue
            promo = (self.metadata(usecase, version) or {}).get("promotion")
            if promo:
                served.append((str(promo.get("at") or ""), version))
        return max(served)[1] if served else None

    def rollback(self, usecase: str) -> str:
        """Repoint ``current`` to a version that has served before (see rollback_target)."""
        current = self.current_version(usecase)
        target = self.rollback_target(usecase)
        if target is None:
            raise ValueError(
                f"{usecase}: no recorded earlier serving version to roll back to — "
                f"promote one explicitly (it needs an approval check, or --force --reason)")
        self.update_metadata(usecase, target, rolled_back_to={
            "at": datetime.now(UTC).isoformat(), "from": current})
        self._write_pointer(usecase, "current", target)
        return target

    # -- approval + metadata ---------------------------------------------- #

    def approval(self, usecase: str, version: str) -> dict[str, Any] | None:
        path = self.bundle_dir(usecase, version) / APPROVAL_FILE
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def write_approval(self, usecase: str, version: str, report: dict[str, Any]) -> Path:
        self._require(usecase, version)
        path = self.bundle_dir(usecase, version) / APPROVAL_FILE
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
        os.replace(tmp, path)
        return path

    def metadata(self, usecase: str, version: str) -> dict[str, Any] | None:
        try:
            return json.loads((self.bundle_dir(usecase, version) / "metadata.json")
                              .read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def update_metadata(self, usecase: str, version: str, **fields: Any) -> None:
        """Record lifecycle facts (promotion, rollback target) beside the bundle."""
        path = self.bundle_dir(usecase, version) / "metadata.json"
        meta = self.metadata(usecase, version) or {}
        meta.update(fields)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    # -- loading ----------------------------------------------------------- #

    def load_current(
        self, usecase: str, model_factories: dict[str, type]
    ) -> ModelBundle | None:
        version = self.current_version(usecase)
        if version is None:
            return None
        return ModelBundle.load(self.bundle_dir(usecase, version), model_factories)

    def load(
        self, usecase: str, version: str, model_factories: dict[str, type]
    ) -> ModelBundle:
        self._require(usecase, version)
        return ModelBundle.load(self.bundle_dir(usecase, version), model_factories)

    # -- helpers ----------------------------------------------------------- #

    def _require(self, usecase: str, version: str) -> None:
        if not self.bundle_dir(usecase, version).is_dir():
            raise ValueError(f"{usecase}: no such version {version!r}")

    def _prune(self, usecase: str, keep: int = _HOT_VERSIONS) -> None:
        current = self.current_version(usecase)
        protected = {current, self.candidate_version(usecase)}
        if current:
            protected.add((self.metadata(usecase, current) or {}).get("rollback_target"))
        protected.discard(None)
        prunable = [v for v in self.versions(usecase) if v not in protected]
        for version in prunable[: max(0, len(prunable) - keep)]:
            shutil.rmtree(self.bundle_dir(usecase, version), ignore_errors=True)

    def describe(self, usecase: str) -> dict[str, Any]:
        return {
            "usecase": usecase,
            "current": self.current_version(usecase),
            "candidate": self.candidate_version(usecase),
            "versions": self.versions(usecase),
        }
