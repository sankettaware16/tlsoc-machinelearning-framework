"""Ship alerts to the SIEM (Elasticsearch) — a separate process from detection.

The alert files under ``data/alerts`` stay the source of truth; this process
tails them and indexes each alert into ``<index>`` with ``_id = alert.id``, so
a resend after a crash or an outage overwrites rather than duplicates. Later
facts about an alert — the verifier's verdict, the analyst's triage — are
applied as partial updates under ``tlsoc.verification`` / ``tlsoc.triage``.
Every exposure download goes to ``<index>-downloads``.

Why a separate process: an Elasticsearch outage must never slow or stop
detection (NFR-13 says the same about analytics). Offsets advance only after
Elasticsearch acknowledged every document of a batch, so nothing is lost
between the two.
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

__all__ = ["SiemShipper", "ALERT_MAPPINGS"]

_BATCH = 500
_ORPHAN_TRIES = 6  # rounds an update waits for its alert to be indexed
_MAX_LINE = 2_000_000

#: Explicit types for what analysts search and aggregate on; the free-form
#: parts (feature attributions, links) are stored but not indexed, so a new
#: key in them can never break the mapping.
ALERT_MAPPINGS: dict[str, Any] = {
    "dynamic": True,
    "properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"kind": {"type": "keyword"}, "category": {"type": "keyword"},
                                 "module": {"type": "keyword"}, "dataset": {"type": "keyword"},
                                 "severity": {"type": "long"}}},
        "usecase": {"type": "keyword"},
        "rule": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
        "source": {"properties": {
            "ip": {"type": "ip"},
            "geo": {"properties": {"country_iso_code": {"type": "keyword"},
                                   "country_name": {"type": "keyword"},
                                   "city_name": {"type": "keyword"}}},
            "as": {"properties": {"number": {"type": "long"},
                                  "organization": {"properties": {"name": {"type": "keyword"}}}}},
        }},
        "url": {"properties": {"domain": {"type": "keyword"}, "path": {"type": "keyword"},
                               "full": {"type": "keyword"}}},
        "user_agent": {"properties": {"original": {"type": "keyword", "ignore_above": 1024}}},
        "alert": {"properties": {"id": {"type": "keyword"}, "category": {"type": "keyword"},
                                 "severity": {"type": "keyword"},
                                 "severity_score": {"type": "long"},
                                 "confidence": {"type": "float"}}},
        "exposure": {"properties": {"key": {"type": "keyword"}, "kind": {"type": "keyword"},
                                    "title": {"type": "keyword"}, "domain": {"type": "keyword"},
                                    "root": {"type": "keyword"}, "files_count": {"type": "long"},
                                    "bytes_total": {"type": "long"},
                                    "first_seen": {"type": "date"}, "last_seen": {"type": "date"},
                                    "files": {"type": "object", "enabled": False},
                                    "actions": {"type": "text"}, "impact": {"type": "text"}}},
        "activity": {"type": "object", "enabled": False},
        "explanation": {"properties": {"narrative": {"type": "text"},
                                       "evidence_events": {"type": "text"},
                                       "top_features": {"type": "object", "enabled": False}}},
        "scores": {"type": "object", "enabled": False},
        "model_versions": {"type": "object", "enabled": False},
        "links": {"type": "object", "enabled": False},
        "tlsoc": {"properties": {
            "verification": {"properties": {"verdict": {"type": "keyword"},
                                            "summary": {"type": "text"},
                                            "checked_at": {"type": "date"},
                                            "status": {"type": "long"},
                                            "signature": {"type": "keyword"}}},
            "triage": {"properties": {"verdict": {"type": "keyword"},
                                      "status": {"type": "keyword"},
                                      "note": {"type": "text"}, "at": {"type": "date"}}},
        }},
    },
}

_DOWNLOAD_MAPPINGS: dict[str, Any] = {
    "properties": {
        "@timestamp": {"type": "date"}, "key": {"type": "keyword"},
        "kind": {"type": "keyword"}, "domain": {"type": "keyword"},
        "root": {"type": "keyword"}, "client": {"type": "ip"},
        "alert_id": {"type": "keyword"}, "files": {"type": "object", "enabled": False},
    },
}


class SiemShipper:
    """Tail the alert, verification, triage and download files into Elasticsearch."""

    def __init__(self, data_dir: str | Path, *, url: str, api_key: str,
                 index: str = "tlsoc-ml-alerts", verify_tls: bool = True,
                 log: Callable[[str], None] = print, opener=None) -> None:
        self.data = Path(data_dir)
        self.url = url.rstrip("/")
        self.index = index
        self.log = log
        self._auth = "ApiKey " + (api_key if ":" not in api_key
                                  else base64.b64encode(api_key.encode()).decode())
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = opener or urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx))
        self._ckpt = self.data / "state" / "siem_checkpoint.json"
        self._offsets: dict[str, int] = {}
        if self._ckpt.exists():
            try:
                self._offsets = json.loads(self._ckpt.read_text()).get("offsets", {})
            except (OSError, ValueError):
                self._offsets = {}
        self._ready = False
        self._orphans: dict[str, int] = {}
        self.stats = {"alerts": 0, "updates": 0, "downloads": 0, "errors": 0}

    # -- HTTP ------------------------------------------------------------- #

    def _request(self, method: str, path: str, body: bytes | None = None,
                 ctype: str = "application/json") -> tuple[int, dict]:
        req = urllib.request.Request(self.url + path, data=body, method=method, headers={
            "Authorization": self._auth, "Content-Type": ctype})
        try:
            with self._opener.open(req, timeout=60) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            try:
                return exc.code, json.loads(raw) if raw else {}
            except ValueError:
                return exc.code, {"error": raw[:200].decode("utf-8", "replace")}

    def ensure_indices(self) -> None:
        for name, mappings in ((self.index, ALERT_MAPPINGS),
                               (f"{self.index}-downloads", _DOWNLOAD_MAPPINGS)):
            status, _ = self._request("HEAD", f"/{name}")
            if status == 404:
                status, doc = self._request("PUT", f"/{name}", json.dumps(
                    {"mappings": mappings}).encode())
                if status >= 300 and "resource_already_exists" not in json.dumps(doc):
                    raise RuntimeError(f"cannot create index {name}: {status} {doc}")
                self.log(f"[siem] created index {name}")
            elif status >= 300:
                raise RuntimeError(f"cannot reach index {name}: HTTP {status}")
        self._ready = True

    # -- files ------------------------------------------------------------ #

    def _sources(self) -> list[tuple[str, Path]]:
        state = self.data / "state"
        out = [("alert", p) for p in sorted((self.data / "alerts").glob("*.ndjson"))]
        out += [("verification", p) for p in sorted(state.glob("*_verifications.ndjson"))]
        out += [("triage", state / "triage.ndjson")]
        out += [("download", p) for p in sorted(state.glob("*_exposures.ndjson"))]
        return [(kind, p) for kind, p in out if p.exists()]

    def _read_new(self, path: Path) -> tuple[list[dict], int]:
        key = str(path)
        start = self._offsets.get(key, 0)
        size = path.stat().st_size
        if size < start:  # truncated or replaced: read it again from the top
            start = 0
        rows, end = [], start
        with path.open("rb") as fh:
            fh.seek(start)
            while len(rows) < _BATCH:
                line = fh.readline(_MAX_LINE)
                if not line or not line.endswith(b"\n"):
                    break  # nothing more, or a line still being written
                end = fh.tell()
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    self.stats["errors"] += 1
        return rows, end

    def _actions(self, kind: str, rows: list[dict]) -> list[str]:
        lines: list[str] = []
        for row in rows:
            if kind == "alert":
                aid = (row.get("alert") or {}).get("id")
                if not aid:
                    continue
                lines += [json.dumps({"index": {"_index": self.index, "_id": aid}}),
                          json.dumps(row)]
            elif kind in ("verification", "triage") and row.get("alert_id"):
                part = {k: v for k, v in row.items() if k != "alert_id"}
                lines += [json.dumps({"update": {"_index": self.index, "_id": row["alert_id"],
                                                 "retry_on_conflict": 3}}),
                          json.dumps({"doc": {"tlsoc": {kind: part}}})]
            elif kind == "download":
                lines += [json.dumps({"index": {"_index": f"{self.index}-downloads"}}),
                          json.dumps(row)]
        return lines

    def ship_once(self) -> int:
        """Send what is new in every file; returns documents acknowledged."""
        if not self._ready:
            self.ensure_indices()
        sent = 0
        for kind, path in self._sources():
            while True:
                rows, end = self._read_new(path)
                if not rows:
                    if end != self._offsets.get(str(path), 0):
                        self._offsets[str(path)] = end
                    break
                lines = self._actions(kind, rows)
                if lines:
                    status, doc = self._request("POST", "/_bulk",
                                                ("\n".join(lines) + "\n").encode(),
                                                "application/x-ndjson")
                    if status >= 300:
                        raise RuntimeError(f"bulk failed: HTTP {status} {str(doc)[:300]}")
                    failed = [item for item in doc.get("items", [])
                              for res in item.values() if res.get("status", 200) >= 300]
                    if failed:
                        # An update that arrives before its alert is indexed
                        # (404) is retried next round; anything else is loud.
                        first = next(iter(failed[0].values()))
                        if not all(next(iter(f.values())).get("status") == 404 for f in failed):
                            self.stats["errors"] += len(failed)
                            raise RuntimeError(f"bulk item failed: {json.dumps(first)[:300]}")
                        tries = self._orphans.get(str(path), 0) + 1
                        if tries < _ORPHAN_TRIES:
                            self._orphans[str(path)] = tries
                            self._save()
                            return sent
                        # The alert never arrived (deleted, or from before the
                        # SIEM existed): give the update up, visibly.
                        self.stats["orphan_updates"] = (
                            self.stats.get("orphan_updates", 0) + len(failed))
                    self._orphans.pop(str(path), None)
                    sent += len(rows)
                    self.stats[{"alert": "alerts", "download": "downloads"}.get(
                        kind, "updates")] += len(rows)
                self._offsets[str(path)] = end
                self._save()
        return sent

    def _save(self) -> None:
        self._ckpt.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._ckpt.with_suffix(".tmp")
        tmp.write_text(json.dumps({"offsets": self._offsets, "stats": self.stats}))
        tmp.replace(self._ckpt)

    def run(self, every_s: float = 10.0, once: bool = False) -> int:
        backoff = every_s
        while True:
            try:
                n = self.ship_once()
                if n:
                    self.log(f"[siem] shipped {n} ({self.stats})")
                backoff = every_s
            except (RuntimeError, OSError, urllib.error.URLError) as exc:
                self.log(f"[siem] WARN: {exc}; retrying in {backoff:.0f}s")
                if once:
                    return 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 300.0)
                continue
            if once:
                return 0
            time.sleep(every_s)
