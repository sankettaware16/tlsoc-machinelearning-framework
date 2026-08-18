"""Reads a deployment's on-disk state and shapes it for the dashboard.

Every value here comes from a file the runtime or the registry already writes.
Nothing is computed twice and nothing is cached longer than ``_TTL_S``, so a
dashboard tab left open overnight cannot pin a stale picture.

Sizes matter: ``*_scores.ndjson`` and ``*_digest.ndjson`` grow without bound on
a long-running server, so every read here is either a whole small JSON file or
a bounded tail — never a full scan.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_ml.registry.store import ModelRegistry

__all__ = ["DashboardState"]

#: Health is written every 10s; beyond this the runtime is treated as gone.
_LIVE_WINDOW_S = 60.0
#: Cache window for disk reads. Short enough to feel live, long enough that a
#: 2-second poll from several tabs does not turn into a disk hammer.
_TTL_S = 2.0
#: Rolling samples for the live rate chart (5s apart -> ~30 min of history).
_SAMPLES = 360
_SAMPLE_EVERY_S = 5.0

_CATALOG_ROW = re.compile(r"^\|\s*(UC-\d+)\s*\|\s*`([a-z0-9_]+)`\s*\|\s*([^|]+?)\s*\|")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _tail_lines(path: Path, limit: int, max_bytes: int = 1_500_000) -> list[str]:
    """Last ``limit`` non-empty lines, reading at most ``max_bytes`` from the end."""
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()  # discard the partial line we landed in
            chunk = fh.read()
    except OSError:
        return []
    lines = [ln for ln in chunk.decode("utf-8", "replace").splitlines() if ln.strip()]
    return lines[-limit:]


def _tail_json(path: Path, limit: int) -> list[dict[str, Any]]:
    out = []
    for line in _tail_lines(path, limit):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _count_lines(path: Path) -> int:
    try:
        with path.open("rb") as fh:
            return sum(1 for ln in fh if ln.strip())
    except OSError:
        return 0


def _age_s(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds()


class DashboardState:
    """All dashboard reads go through here."""

    def __init__(self, data_root: str | Path, repo_root: Path | None = None) -> None:
        self.data_root = Path(data_root)
        self.state_dir = self.data_root / "state"
        self.alerts_dir = self.data_root / "alerts"
        self.registry = ModelRegistry(self.data_root)
        self.repo_root = repo_root or Path(__file__).resolve().parents[3]
        self._cache: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self._samples: deque[dict[str, Any]] = deque(maxlen=_SAMPLES)
        self._sampler: threading.Thread | None = None
        self._stop = threading.Event()

    # ----------------------------------------------------------------- #
    # caching
    # ----------------------------------------------------------------- #

    def _cached(self, key: str, produce):
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < _TTL_S:
                return hit[1]
        value = produce()
        with self._lock:
            self._cache[key] = (now, value)
        return value

    # ----------------------------------------------------------------- #
    # catalog
    # ----------------------------------------------------------------- #

    def catalog(self) -> list[dict[str, Any]]:
        """The full UC-01..UC-15 catalog, marked with what is implemented.

        Parsed from docs/NAMING.md rather than duplicated: that table is the
        CI-enforced source of truth for slugs (D-016), and a second copy here
        would be the first thing to drift.
        """
        return self._cached("catalog", self._catalog)

    def _catalog(self) -> list[dict[str, Any]]:
        implemented = self._implemented()
        rows: list[dict[str, Any]] = []
        naming = self.repo_root / "docs" / "NAMING.md"
        try:
            text = naming.read_text(encoding="utf-8")
        except OSError:
            text = ""
        for line in text.splitlines():
            m = _CATALOG_ROW.match(line.strip())
            if not m:
                continue
            uc_id, slug, title = m.group(1), m.group(2), m.group(3).strip()
            cls = implemented.get(slug)
            rows.append({
                "id": uc_id,
                "slug": slug,
                "title": title,
                "implemented": cls is not None,
                "models": list(getattr(cls, "models", ())) if cls else [],
                "features": len(getattr(cls, "requires", ())) if cls else 0,
                "depends_on": list(getattr(cls, "depends_on", ())) if cls else [],
                "daily_alert_budget": getattr(cls, "daily_alert_budget", None) if cls else None,
                "deployed": bool(self.registry.current_version(slug)),
            })
        return rows

    @staticmethod
    def _implemented() -> dict[str, type]:
        from soc_ml import usecases as uc_mod

        out = {}
        for name in getattr(uc_mod, "__all__", []):
            cls = getattr(uc_mod, name, None)
            if isinstance(cls, type) and getattr(cls, "name", ""):
                out[cls.name] = cls
        return out

    # ----------------------------------------------------------------- #
    # overview
    # ----------------------------------------------------------------- #

    def deployed_slugs(self) -> list[str]:
        """Slugs with either a model or a health file — what this box runs."""
        slugs = set()
        models_dir = self.data_root / "models"
        if models_dir.is_dir():
            slugs.update(p.name for p in models_dir.iterdir() if p.is_dir())
        if self.state_dir.is_dir():
            for p in self.state_dir.glob("*_health.json"):
                slugs.add(p.name[: -len("_health.json")])
        return sorted(slugs)

    def overview(self) -> dict[str, Any]:
        return self._cached("overview", self._overview)

    def _overview(self) -> dict[str, Any]:
        slugs = self.deployed_slugs()
        usecases = []
        newest_age: float | None = None
        mode = None
        for slug in slugs:
            health = _read_json(self.state_dir / f"{slug}_health.json") or {}
            drift = _read_json(self.state_dir / f"{slug}_drift.json") or {}
            age = _age_s(health.get("timestamp"))
            if age is not None and (newest_age is None or age < newest_age):
                newest_age = age
            mode = mode or health.get("mode")
            usecases.append({
                "slug": slug,
                "mode": health.get("mode"),
                "serving": self.registry.current_version(slug),
                "candidate": self.registry.candidate_version(slug),
                "bundle_version": health.get("bundle_version"),
                "health_age_s": round(age, 1) if age is not None else None,
                "live": age is not None and age < _LIVE_WINDOW_S,
                "uptime_s": health.get("uptime_s"),
                "eps": health.get("eps"),
                "events": health.get("events"),
                "windows": health.get("windows"),
                "open_windows": health.get("open_windows"),
                "ingest_failed": health.get("ingest_failed"),
                "entity_annotations": health.get("entity_annotations"),
                "delivered": health.get("alerts_delivered", 0),
                "folded": health.get("alerts_folded", 0),
                "digested": health.get("alerts_digested", 0),
                "suppressed": health.get("alerts_suppressed", 0),
                "drift": {
                    "band": drift.get("band"),
                    "max_psi": drift.get("max_psi"),
                    "should_retrain": bool(drift.get("should_retrain")),
                    "drifted_features": drift.get("drifted_features") or [],
                },
                "files": self._file_sizes(slug),
            })

        for uc in usecases:
            fired = uc["delivered"] + uc["folded"] + uc["digested"] + uc["suppressed"]
            uc["fired"] = fired
            days = (uc.get("uptime_s") or 0) / 86400.0
            uc["fired_per_day"] = round(fired / days, 1) if days > 0.01 else None
            uc["delivered_per_day"] = (
                round(uc["delivered"] / days, 1) if days > 0.01 else None
            )
            uc["windows"] = uc.get("windows") or 0
            uc["fire_rate_pct"] = (
                round(100.0 * fired / uc["windows"], 4) if uc["windows"] else None
            )

        live = newest_age is not None and newest_age < _LIVE_WINDOW_S
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_root": str(self.data_root.resolve()),
            "runtime": {
                "live": live,
                "mode": mode,
                "last_seen_age_s": round(newest_age, 1) if newest_age is not None else None,
                "eps": max((u.get("eps") or 0) for u in usecases) if usecases else 0,
                "events": max((u.get("events") or 0) for u in usecases) if usecases else 0,
                "uptime_s": max((u.get("uptime_s") or 0) for u in usecases) if usecases else 0,
                "ingest_failed": max(
                    (u.get("ingest_failed") or 0) for u in usecases) if usecases else 0,
                "dlq": self._dlq_count(),
            },
            "usecases": usecases,
        }

    def _file_sizes(self, slug: str) -> dict[str, int]:
        out = {}
        for kind, path in (
            ("alerts", self.alerts_dir / f"{slug}.ndjson"),
            ("scores", self.state_dir / f"{slug}_scores.ndjson"),
            ("shadow", self.state_dir / f"{slug}_shadow.ndjson"),
            ("digest", self.state_dir / f"{slug}_digest.ndjson"),
            ("suppressed", self.state_dir / f"{slug}_suppressed.ndjson"),
        ):
            try:
                out[kind] = path.stat().st_size
            except OSError:
                out[kind] = 0
        return out

    def _dlq_count(self) -> int:
        if not self.state_dir.is_dir():
            return 0
        return sum(_count_lines(p) for p in self.state_dir.glob("*_dlq.ndjson"))

    # ----------------------------------------------------------------- #
    # models / approval
    # ----------------------------------------------------------------- #

    def models(self) -> dict[str, Any]:
        return self._cached("models", self._models)

    def _models(self) -> dict[str, Any]:
        out = []
        for slug in self.deployed_slugs():
            current = self.registry.current_version(slug)
            candidate = self.registry.candidate_version(slug)
            versions = []
            for version in reversed(self.registry.versions(slug)):
                meta = _read_json(
                    self.registry.bundle_dir(slug, version) / "metadata.json") or {}
                if version == current:
                    status = "approved"
                elif version == candidate:
                    status = "pending"
                else:
                    status = "retained"
                versions.append({
                    "version": version,
                    "status": status,
                    "trained_at": meta.get("trained_at"),
                    "train_windows": meta.get("train_windows"),
                    "feature_sha256": meta.get("feature_sha256"),
                    "models": list((meta.get("models") or {}).keys()) or meta.get("models"),
                    "source": meta.get("source_desc") or meta.get("source"),
                })
            out.append({
                "slug": slug,
                "serving": current,
                "candidate": candidate,
                "can_rollback": len([v for v in self.registry.versions(slug)
                                     if v != current]) > 0,
                "versions": versions,
            })
        return {"usecases": out}

    def promote(self, slug: str, version: str | None) -> dict[str, Any]:
        promoted = self.registry.promote(slug, version)
        self._invalidate()
        return {"slug": slug, "promoted": promoted}

    def rollback(self, slug: str) -> dict[str, Any]:
        target = self.registry.rollback(slug)
        self._invalidate()
        return {"slug": slug, "rolled_back_to": target}

    def _invalidate(self) -> None:
        with self._lock:
            self._cache.clear()

    # ----------------------------------------------------------------- #
    # records
    # ----------------------------------------------------------------- #

    def records(self, kind: str, slug: str, limit: int = 100) -> dict[str, Any]:
        paths = {
            "alerts": self.alerts_dir / f"{slug}.ndjson",
            "scores": self.state_dir / f"{slug}_scores.ndjson",
            "shadow": self.state_dir / f"{slug}_shadow.ndjson",
            "digest": self.state_dir / f"{slug}_digest.ndjson",
            "suppressed": self.state_dir / f"{slug}_suppressed.ndjson",
        }
        path = paths.get(kind)
        if path is None:
            raise KeyError(kind)
        rows = _tail_json(path, max(1, min(limit, 500)))
        rows.reverse()  # newest first
        return {
            "kind": kind, "slug": slug, "rows": rows,
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
        }

    # ----------------------------------------------------------------- #
    # live rate sampling
    # ----------------------------------------------------------------- #

    def start_sampler(self) -> None:
        if self._sampler is not None:
            return
        self._sampler = threading.Thread(
            target=self._sample_loop, name="soc-ml-ui-sampler", daemon=True)
        self._sampler.start()

    def stop_sampler(self) -> None:
        self._stop.set()

    def _sample_loop(self) -> None:
        prev: dict[str, Any] | None = None
        while not self._stop.wait(_SAMPLE_EVERY_S):
            try:
                ov = self._overview()
            except Exception:  # a sampler must never take the server down
                continue
            now = time.time()
            rt = ov["runtime"]
            sample = {"t": now, "events": rt.get("events") or 0, "eps": 0.0,
                      "live": rt.get("live", False), "fires": {}}
            for uc in ov["usecases"]:
                sample["fires"][uc["slug"]] = uc["fired"]
            if prev is not None:
                dt = now - prev["t"]
                if dt > 0:
                    # Measured rate, not the runtime's lifetime average: a
                    # cumulative mean cannot show a burst, which is the whole
                    # point of a live chart.
                    sample["eps"] = max(0.0, (sample["events"] - prev["events"]) / dt)
                    sample["fire_delta"] = {
                        s: max(0, n - prev["fires"].get(s, n))
                        for s, n in sample["fires"].items()
                    }
            prev = sample
            self._samples.append(sample)

    def timeseries(self) -> dict[str, Any]:
        return {"samples": list(self._samples), "interval_s": _SAMPLE_EVERY_S}
