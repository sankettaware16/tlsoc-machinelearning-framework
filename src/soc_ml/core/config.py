"""Configuration loading.

Config in this framework carries **policy, never data thresholds** (FR-62). That
distinction is the whole reason the project exists, so it is worth being precise
about:

* **Policy** (allowed here) — which profile, what mode each use case runs in,
  daily alert budgets, retraining cadences, feature toggles, connection details,
  paths, the sessionization idle gap.
* **Data thresholds** (never here) — any number compared against observed
  traffic. "Alert above 50 requests/minute", "flag paths deeper than 6",
  "suspicious if more than 20 404s". Every one of those comes from the learned
  Environment Profile instead.

The distinction is not always obvious at the boundary, so the test is: *would
this number need to change if the framework were deployed at a different
organisation?* If yes, it must be learned, not configured.

``soc-ml lint-config`` enforces this in CI.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .contracts import Profile, RunMode

__all__ = ["Config", "load_config", "ConfigError"]


class ConfigError(Exception):
    """Raised for a malformed or self-contradictory configuration."""


# Keys that look like data thresholds. The config lint rejects any of these
# appearing under a use case block. Extend as new smells are found.
_THRESHOLD_SMELLS = (
    "threshold",
    "max_",
    "min_",
    "_limit",
    "cutoff",
    "per_minute",
    "per_second",
    "suspicious_",
)

# Budgets and cadences legitimately contain numbers; they are delivery policy,
# not detection thresholds.
_THRESHOLD_ALLOWLIST = (
    "daily_alert_budget",
    "min_shadow_hours",
    "max_evidence_lines",
)


@dataclass(slots=True)
class UseCaseConfig:
    """Per-use-case policy. Deliberately small."""

    enabled: bool = True
    mode: RunMode | None = None  # None = inherit the global default
    daily_alert_budget: int | None = None  # None = the use case's own default


@dataclass(slots=True)
class Config:
    """Resolved runtime configuration."""

    profile: Profile = Profile.STANDALONE
    default_mode: RunMode = RunMode.SHADOW

    # Paths
    root: Path = field(default_factory=Path.cwd)
    input_dir: Path | None = None
    data_dir: Path = field(default_factory=lambda: Path("data"))
    plugin_dir: Path = field(default_factory=lambda: Path("plugins"))

    # Plugin selection per profile
    source: str = "file"
    state: str = "sqlite"
    sinks: tuple[str, ...] = ("file",)

    # Grouping defaults (not detection thresholds — see module docstring)
    session_idle_gap_s: int = 1800  # 30 minutes
    windows: tuple[str, ...] = ("1m", "5m", "30m", "24h")

    # Per-use-case policy, keyed by spec ID ("UC-02")
    usecases: dict[str, UseCaseConfig] = field(default_factory=dict)

    # Retraining cadence policy
    cadence: dict[str, str] = field(default_factory=dict)

    # Backend connection details, only used by non-standalone profiles
    backends: dict[str, Any] = field(default_factory=dict)

    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    # -- resolution -------------------------------------------------------- #

    def mode_for(self, usecase_id: str) -> RunMode:
        """Effective run mode for a use case (ARCHITECTURE §4)."""
        uc = self.usecases.get(usecase_id)
        if uc is not None and uc.mode is not None:
            return uc.mode
        return self.default_mode

    def is_enabled(self, usecase_id: str) -> bool:
        uc = self.usecases.get(usecase_id)
        return True if uc is None else uc.enabled

    def budget_for(self, usecase_id: str, default: int) -> int:
        uc = self.usecases.get(usecase_id)
        if uc is not None and uc.daily_alert_budget is not None:
            return uc.daily_alert_budget
        return default

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(self.data_dir, *parts)

    # -- validation -------------------------------------------------------- #

    def validate(self) -> list[str]:
        """Return structural problems, worst first. Empty means valid.

        Structural only — this must not depend on the state of the filesystem.
        A config is not invalid because a log directory has not been mounted
        yet, otherwise the shipped defaults fail to load on a fresh install.
        Path existence is a *runtime* concern; see :meth:`check_runtime`.
        """
        problems: list[str] = []

        if self.profile is Profile.STANDALONE:
            # NFR-07: the zero-infra default must stay zero-infra.
            for backend in ("kafka", "redis", "mlflow", "elasticsearch"):
                if backend in self.backends:
                    problems.append(
                        f"profile 'standalone' must not require {backend}; "
                        f"use profile 'cluster' or 'enterprise' (NFR-07)"
                    )
            if self.source not in ("file", "replay"):
                problems.append(
                    f"profile 'standalone' cannot use source {self.source!r}"
                )

        problems.extend(self.lint_thresholds())
        return problems

    def check_runtime(self) -> list[str]:
        """Problems that only matter once we actually try to run.

        Called by the CLI before starting a pipeline, not at load time.
        """
        problems: list[str] = []
        if self.input_dir is None:
            problems.append(
                "no input_dir configured; set it in config or pass --input"
            )
        elif not self.input_dir.exists():
            problems.append(f"input_dir does not exist: {self.input_dir}")
        return problems

    def lint_thresholds(self) -> list[str]:
        """Reject data thresholds smuggled into config (FR-62)."""
        problems: list[str] = []
        blocks = self.raw.get("usecases") or {}
        if not isinstance(blocks, dict):
            return problems
        for uc_id, block in blocks.items():
            if not isinstance(block, dict):
                continue
            for key in block:
                if key in _THRESHOLD_ALLOWLIST:
                    continue
                lowered = key.lower()
                if any(smell in lowered for smell in _THRESHOLD_SMELLS):
                    problems.append(
                        f"{uc_id}.{key}: detection thresholds must be learned "
                        f"from the Environment Profile, not configured (FR-62)"
                    )
        return problems


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_PROFILE_DEFAULTS: dict[Profile, dict[str, Any]] = {
    Profile.STANDALONE: {"source": "file", "state": "sqlite", "sinks": ("file",)},
    Profile.CLUSTER: {"source": "kafka", "state": "redis", "sinks": ("elasticsearch",)},
    Profile.ENTERPRISE: {
        "source": "kafka",
        "state": "redis",
        "sinks": ("elasticsearch", "kafka"),
    },
}


def load_config(path: str | Path | None = None) -> Config:
    """Load YAML config, applying profile defaults then explicit overrides.

    Environment variables ``SOC_ML_*`` override the file, which is what makes a
    container deployment reasonable.
    """
    import yaml  # imported lazily so `--help` works without dependencies

    path = Path(path) if path else Path("config/default.yaml")
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")

    profile = Profile(os.getenv("SOC_ML_PROFILE") or raw.get("profile", "standalone"))
    defaults = _PROFILE_DEFAULTS[profile]

    cfg = Config(
        profile=profile,
        default_mode=RunMode(
            os.getenv("SOC_ML_MODE") or (raw.get("modes") or {}).get("default", "shadow")
        ),
        root=path.resolve().parent.parent,
        source=raw.get("source", defaults["source"]),
        state=raw.get("state", defaults["state"]),
        sinks=tuple(raw.get("sinks", defaults["sinks"])),
        session_idle_gap_s=int(raw.get("session_idle_gap_s", 1800)),
        windows=tuple(raw.get("windows", ("1m", "5m", "30m", "24h"))),
        cadence=dict(raw.get("cadence") or {}),
        backends=dict(raw.get("backends") or {}),
        raw=raw,
    )

    if (input_dir := os.getenv("SOC_ML_INPUT") or raw.get("input_dir")) is not None:
        cfg.input_dir = Path(input_dir).expanduser()
    if (data_dir := raw.get("data_dir")) is not None:
        cfg.data_dir = Path(data_dir)
    if (plugin_dir := raw.get("plugin_dir")) is not None:
        cfg.plugin_dir = Path(plugin_dir)

    # Per-use-case policy, plus the global mode overrides block.
    overrides = (raw.get("modes") or {}).get("overrides") or {}
    for uc_id, block in (raw.get("usecases") or {}).items():
        block = block or {}
        cfg.usecases[uc_id] = UseCaseConfig(
            enabled=bool(block.get("enabled", True)),
            mode=RunMode(block["mode"]) if "mode" in block else None,
            daily_alert_budget=block.get("daily_alert_budget"),
        )
    for uc_id, mode in overrides.items():
        uc = cfg.usecases.setdefault(uc_id, UseCaseConfig())
        uc.mode = RunMode(mode)

    if problems := cfg.validate():
        raise ConfigError(
            f"invalid configuration in {path}:\n  - " + "\n  - ".join(problems)
        )
    return cfg
