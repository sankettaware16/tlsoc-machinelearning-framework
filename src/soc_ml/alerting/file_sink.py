"""File sink — NDJSON alerts, ECS-aligned, the standalone-profile default."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from soc_ml.core.contracts import Alert, Insight
from soc_ml.core.plugins import Sink

__all__ = ["FileSink", "alert_document"]


class FileSink(Sink):
    name = "file"
    description = "append alerts/insights as NDJSON to a local file"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self.written = 0

    def emit_alert(self, alert: Alert) -> None:
        self._fh.write(json.dumps(alert_document(alert)) + "\n")
        self.written += 1

    def emit_insight(self, insight: Insight) -> None:
        self._fh.write(json.dumps(asdict(insight), default=str) + "\n")

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


#: Keys of ``Alert.links`` lifted to their own ECS fields in the document.
_LIFTED = ("rule_id", "rule_name", "context", "exposures", "category")


def alert_document(alert: Alert) -> dict:
    """The alert as one ECS-aligned document — the file line and the SIEM doc.

    ``source.*``, ``url.domain`` and ``user_agent.original`` are where a SIEM
    analyst searches, so the alert carries them in ECS's own places; the
    detection-specific detail lives under ``exposure``, ``activity`` and
    ``explanation``.
    """
    ctx = alert.links.get("context") or {}
    domains = ctx.get("domains") or []
    exposures = alert.links.get("exposures") or []
    geo = ctx.get("geo") or {}
    net = ctx.get("network") or {}
    return {
        "@timestamp": alert.timestamp.isoformat(),
        "event": {"kind": "alert", "category": ["web"], "module": "tlsoc-ml",
                  "dataset": f"tlsoc_ml.{alert.usecase}",
                  "severity": alert.severity_score},
        # Naming triple (docs/NAMING.md): slug in `usecase`, spec ID and
        # human title under ECS rule.* so SIEM dashboards read instantly.
        "usecase": alert.usecase,
        "rule": {"id": alert.links.get("rule_id"), "name": alert.links.get("rule_name")},
        "entity": {
            "server": alert.entity.server,
            "ip": alert.entity.ip,
            "ua_hash": alert.entity.ua_hash,
        },
        "source": {
            "ip": alert.entity.ip,
            **({"geo": {k: v for k, v in geo.items() if v}} if geo else {}),
            **({"as": {"number": net.get("number"),
                       "organization": {"name": net.get("organization")}}}
               if net else {}),
        },
        **({"url": {"domain": (exposures[0]["domain"] if exposures else domains[0][0]),
                    **({"path": exposures[0]["root"],
                        "full": f"https://{exposures[0]['domain']}{exposures[0]['root']}"}
                       if exposures else {})}}
           if exposures or domains else {}),
        **({"user_agent": {"original": ctx["user_agent"]}} if ctx.get("user_agent") else {}),
        "alert": {
            "id": alert.id,
            "category": alert.links.get("category") or alert.usecase,
            "severity": alert.severity.value,
            "severity_score": alert.severity_score,
            "confidence": round(alert.confidence, 4),
        },
        **({"exposure": exposures} if exposures else {}),
        **({"activity": {k: v for k, v in ctx.items()
                         if k not in ("geo", "network", "user_agent")}}
           if ctx else {}),
        "scores": {k: round(v, 4) for k, v in alert.scores.items()},
        "explanation": {
            "top_features": alert.top_features,
            "narrative": alert.narrative,
            "evidence_events": alert.evidence,
        },
        "model_versions": alert.model_versions,
        "links": {
            k: v for k, v in alert.links.items() if k not in _LIFTED
        },
    }
