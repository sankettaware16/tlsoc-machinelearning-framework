"""File sink — NDJSON alerts, ECS-aligned, the standalone-profile default."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from soc_ml.core.contracts import Alert, Insight
from soc_ml.core.plugins import Sink

__all__ = ["FileSink"]


class FileSink(Sink):
    name = "file"
    description = "append alerts/insights as NDJSON to a local file"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self.written = 0

    def emit_alert(self, alert: Alert) -> None:
        doc = {
            "@timestamp": alert.timestamp.isoformat(),
            "event": {"kind": "alert"},
            # Naming triple (docs/NAMING.md): slug in `usecase`, spec ID and
            # human title under ECS rule.* so SIEM dashboards read instantly.
            "usecase": alert.usecase,
            "rule": {"id": alert.links.get("rule_id"), "name": alert.links.get("rule_name")},
            "entity": {
                "server": alert.entity.server,
                "ip": alert.entity.ip,
                "ua_hash": alert.entity.ua_hash,
            },
            "alert": {
                "id": alert.id,
                "severity": alert.severity.value,
                "severity_score": alert.severity_score,
                "confidence": round(alert.confidence, 4),
            },
            "scores": {k: round(v, 4) for k, v in alert.scores.items()},
            "explanation": {
                "top_features": alert.top_features,
                "narrative": alert.narrative,
                "evidence_events": alert.evidence,
            },
            "model_versions": alert.model_versions,
            "links": {
                k: v for k, v in alert.links.items() if k not in ("rule_id", "rule_name")
            },
        }
        self._fh.write(json.dumps(doc) + "\n")
        self.written += 1

    def emit_insight(self, insight: Insight) -> None:
        self._fh.write(json.dumps(asdict(insight), default=str) + "\n")

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
