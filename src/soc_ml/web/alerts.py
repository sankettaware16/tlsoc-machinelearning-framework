"""The analyst's side of the console: alert queue, detail, triage, verification.

The operations panels answer "is the detector healthy". This answers what the
person holding an alert needs: what happened, is it real, who did it, what else
they did, and what to do now — and it records their verdict, because the
share of delivered alerts an analyst confirms is the number that decides
whether a use case is production-ready.

Everything is read from files the runtime already writes:

* ``alerts/<slug>.ndjson`` — delivered alerts (``alerting.file_sink``);
* ``state/web_recon_exposures.ndjson`` — every download of every exposure;
* ``state/web_recon_verifications.ndjson`` — written here: the result of
  fetching an exposed file once from the SOC side (``features.exposure.verify``);
* ``state/triage.ndjson`` — written here: the analyst's verdict, newest wins.

Every string in an alert came from a request someone else chose (path,
user-agent, Host header). Nothing here interprets it; the page renders it as
text only.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

__all__ = ["AlertBook", "VERDICTS", "STATUSES"]

VERDICTS = ("true_positive", "false_positive", "benign")
STATUSES = ("open", "investigating", "resolved")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}$")
#: Bounded reads: alert files are small, the exposure log grows with downloads.
_ALERT_TAIL_BYTES = 16_000_000
_STATE_TAIL_BYTES = 8_000_000
#: One verification per exposure per minute, however often the button is hit.
_VERIFY_MIN_INTERVAL_S = 60.0
_LOGS_INDEX = "fosstlsoc-logs-*"
#: A raw nginx line as the logserver relays it: "... vhnginx_access: <site> <ip> ..."
_RAW_SITE = re.compile(r"access: (\S+) (\S+) ")

#: What the responder should see when they run the curl command themselves.
_EXPECT = {
    "vcs": "a line like 'ref: refs/heads/main' (HEAD of a git repository)",
    "secrets": "KEY=value lines, a private key block, or credentials",
    "dump": "SQL statements (CREATE TABLE, INSERT INTO) or archive bytes",
    "backup": "binary archive bytes (zip/gzip/tar), not a web page",
    "source": "server-side source code such as '<?php'",
    "debug": "phpinfo output, server status, or log lines",
    "server_config": "Apache directives (RewriteRule, <IfModule>) or "
                     "<configuration> XML",
    "metadata": "tool metadata (binary .DS_Store, JSON, lock-file text)",
}


def _tail(path: Path, max_bytes: int) -> list[dict[str, Any]]:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()
            chunk = fh.read()
    except OSError:
        return []
    out = []
    for line in chunk.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _parse_ts(stamp: Any) -> datetime | None:
    if not isinstance(stamp, str) or not stamp:
        return None
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _safe_domain(value: Any) -> str | None:
    if isinstance(value, str) and _DOMAIN.match(value) and len(value) <= 253:
        return value.lower()
    return None


def _safe_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _shell_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def _rison(text: str) -> str:
    return "'" + text.replace("!", "!!").replace("'", "!'") + "'"


class AlertBook:
    """Reads alerts and writes triage/verification for one data root."""

    def __init__(self, data_root: Path, *, verify_fn: Callable[..., dict] | None = None,
                 allowed_domains: tuple[str, ...] = (), kibana_url: str | None = None,
                 timezone: str = "Asia/Kolkata") -> None:
        self.data_root = Path(data_root)
        self.alerts_dir = self.data_root / "alerts"
        self.state_dir = self.data_root / "state"
        self.triage_path = self.state_dir / "triage.ndjson"
        self.verify_path = self.state_dir / "web_recon_verifications.ndjson"
        self.exposures_path = self.state_dir / "web_recon_exposures.ndjson"
        if verify_fn is None:
            from soc_ml.features.exposure import verify as verify_fn
        self.verify_fn = verify_fn
        self.allowed_domains = tuple(allowed_domains)
        base = (kibana_url or "").rstrip("/")
        self.kibana_url = base if re.match(r"^https?://[^\s'\"<>]+$", base) else None
        self.timezone = timezone
        self._write_lock = threading.Lock()
        self._last_verify: dict[str, float] = {}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ----------------------------------------------------------------- #
    # reading
    # ----------------------------------------------------------------- #

    def _docs(self) -> list[dict[str, Any]]:
        """Every alert on disk (bounded tail per file), newest first."""
        docs = []
        if self.alerts_dir.is_dir():
            for path in sorted(self.alerts_dir.glob("*.ndjson")):
                for doc in _tail(path, _ALERT_TAIL_BYTES):
                    if (doc.get("alert") or {}).get("id"):
                        doc.setdefault("usecase", path.stem)
                        docs.append(doc)
        docs.sort(key=lambda d: str(d.get("@timestamp") or ""), reverse=True)
        return docs

    def _latest_triage(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for row in _tail(self.triage_path, _STATE_TAIL_BYTES):
            if row.get("alert_id"):
                latest[str(row["alert_id"])] = row
        return latest

    def _verifications(self) -> dict[str, list[dict]]:
        """Verification records by exposure key, oldest first."""
        by_key: dict[str, list[dict]] = {}
        for row in _tail(self.verify_path, _STATE_TAIL_BYTES):
            if row.get("key"):
                by_key.setdefault(str(row["key"]), []).append(row)
        return by_key

    @staticmethod
    def category(doc: dict) -> str:
        cat = (doc.get("alert") or {}).get("category")
        if cat:
            return "bot" if cat == "bot_detection" else str(cat)
        if doc.get("exposure"):
            return "exposure"
        # Written before alerts carried a category (D-040, 2026-11-02): their
        # "findings" were judged by a rule since replaced, so they are shown
        # apart and kept out of the triage tally that M-003 reads.
        return "legacy"

    @staticmethod
    def _site(doc: dict) -> str | None:
        """The site an alert is about: ECS url.domain, else the first raw line."""
        dom = (doc.get("url") or {}).get("domain")
        if dom:
            return str(dom)
        for line in (doc.get("explanation") or {}).get("evidence_events") or []:
            m = _RAW_SITE.search(str(line))
            if m:
                return m.group(1)
        return None

    def summary(self, doc: dict, triage: dict | None, verif: dict[str, list]) -> dict:
        entity = doc.get("entity") or {}
        source = doc.get("source") or {}
        alert = doc.get("alert") or {}
        exposures = doc.get("exposure") or []
        cat = self.category(doc)
        ip = source.get("ip") or entity.get("ip")
        site = self._site(doc)
        if cat == "exposure" and exposures:
            first = exposures[0]
            url = (doc.get("url") or {}).get("full") or \
                f"https://{first.get('domain')}{first.get('root')}"
            title = f"{first.get('title') or 'Sensitive file'} exposed — {url}"
            if len(exposures) > 1:
                title += f" (+{len(exposures) - 1} more)"
        elif cat == "bot":
            title = f"Automated client — {ip} on {site or entity.get('server') or '?'}"
        else:
            title = f"Scanner — {ip} on {site or entity.get('server') or '?'}"
        latest = None
        if exposures:
            records = verif.get(str(exposures[0].get("key")), [])
            latest = records[-1] if records else None
        return {
            "id": alert.get("id"),
            "timestamp": doc.get("@timestamp"),
            "usecase": doc.get("usecase"),
            "category": cat,
            "severity": alert.get("severity"),
            "severity_score": alert.get("severity_score"),
            "title": title,
            "ip": ip,
            "network": ((source.get("as") or {}).get("organization") or {}).get("name"),
            "asn": (source.get("as") or {}).get("number"),
            "country": (source.get("geo") or {}).get("country_name")
                       or (source.get("geo") or {}).get("country_iso_code"),
            "site": site,
            "kind": exposures[0].get("kind") if exposures else None,
            "verification": ({k: latest.get(k) for k in
                              ("verdict", "summary", "checked_at", "signature", "status")}
                             if latest else None),
            "triage": ({k: triage.get(k) for k in ("verdict", "status", "at")}
                       if triage else None),
        }

    def list(self, category: str = "all", limit: int = 200) -> dict[str, Any]:
        docs = self._docs()
        triage = self._latest_triage()
        verif = self._verifications()
        rows = [self.summary(d, triage.get(str(d["alert"]["id"])), verif) for d in docs]
        tally: dict[str, dict[str, int]] = {}
        for r in rows:
            t = tally.setdefault(r["category"], {"total": 0, "true_positive": 0,
                                                 "false_positive": 0, "benign": 0,
                                                 "untriaged": 0})
            t["total"] += 1
            verdict = (r["triage"] or {}).get("verdict")
            t[verdict if verdict in VERDICTS else "untriaged"] += 1
        for t in tally.values():
            # M-003's "correct": benign (real but authorised) means the
            # detection was right.
            right = t["true_positive"] + t["benign"]
            judged = right + t["false_positive"]
            t["precision"] = round(right / judged, 3) if judged else None
        want = {"incidents": "exposure", "exposure": "exposure", "scanner": "scanner",
                "scanners": "scanner", "bot": "bot", "bots": "bot",
                "legacy": "legacy"}.get(category)
        if want:
            rows = [r for r in rows if r["category"] == want]
        return {"rows": rows[: max(1, min(int(limit), 1000))], "total": len(rows),
                "tally": tally, "timezone": self.timezone}

    def _find(self, alert_id: str) -> dict | None:
        if not _ID.match(alert_id or ""):
            return None
        return next((d for d in self._docs() if str(d["alert"]["id"]) == alert_id), None)

    def detail(self, alert_id: str) -> dict[str, Any] | None:
        doc = self._find(alert_id)
        if doc is None:
            return None
        docs = self._docs()
        triage_all = self._latest_triage()
        verif = self._verifications()
        summary = self.summary(doc, triage_all.get(alert_id), verif)
        ip = summary["ip"]
        same_ip = [self.summary(d, triage_all.get(str(d["alert"]["id"])), verif)
                   for d in docs
                   if str(d["alert"]["id"]) != alert_id
                   and ((d.get("source") or {}).get("ip")
                        or (d.get("entity") or {}).get("ip")) == ip][:50]
        exposures = doc.get("exposure") or []
        keys = {str(e.get("key")) for e in exposures if e.get("key")}
        clients = []
        if keys:
            for row in _tail(self.exposures_path, _STATE_TAIL_BYTES):
                if str(row.get("key")) in keys:
                    clients.append({
                        "timestamp": row.get("@timestamp"), "key": row.get("key"),
                        "client": row.get("client"),
                        "network": (row.get("network") or {}).get("organization"),
                        "asn": (row.get("network") or {}).get("number"),
                        "country": (row.get("geo") or {}).get("country_name"),
                        "user_agent": row.get("user_agent"),
                        "files_count": row.get("files_count"),
                        "bytes_total": row.get("bytes_total"),
                        "alert_id": row.get("alert_id"),
                        "this_alert": row.get("alert_id") == alert_id,
                    })
            clients.sort(key=lambda c: str(c.get("timestamp") or ""), reverse=True)
        return {
            "summary": summary,
            "alert": doc,
            "exposures": [self._exposure_view(e, verif) for e in exposures],
            "same_ip": same_ip,
            "other_clients": clients[:500],
            "distinct_clients": len({c["client"] for c in clients}),
            "triage": triage_all.get(alert_id),
            "triage_history": self._triage_history(alert_id),
            "investigate": self._investigate(doc, summary),
            "timezone": self.timezone,
        }

    def _triage_history(self, alert_id: str) -> list[dict]:
        return [r for r in _tail(self.triage_path, _STATE_TAIL_BYTES)
                if str(r.get("alert_id")) == alert_id][-20:]

    def _exposure_view(self, exp: dict, verif: dict[str, list]) -> dict:
        domain = _safe_domain(exp.get("domain"))
        root = str(exp.get("root") or "/")
        kind = str(exp.get("kind") or "")
        probe = root + ("HEAD" if kind == "vcs" and root.endswith("/") else "")
        url = f"https://{domain}{quote(probe, safe='/~._-!$&()*+,;=:@%')}" if domain else None
        records = verif.get(str(exp.get("key")), [])
        return {
            **exp,
            "verify_url": url,
            "curl": f"curl -sk -r 0-300 {_shell_quote(url)}" if url else None,
            "how_to_read": (
                "Run it from outside the web server. If the output is an ordinary web "
                "page (it starts with <!DOCTYPE html> or <html>), the site answers every "
                "path with a page and the alert is probably a false positive. If you see "
                f"{_EXPECT.get(kind, 'the file content')}, the file is really public: "
                "follow the response checklist."),
            "verification": records[-1] if records else None,
            "verification_history": records[-10:],
        }

    def _investigate(self, doc: dict, summary: dict) -> dict:
        """The same question asked of the raw logs: Kibana link and ES|QL text."""
        activity = doc.get("activity") or {}
        ts = _parse_ts(doc.get("@timestamp")) or datetime.now(UTC)
        start = _parse_ts(activity.get("window_start")) or ts - timedelta(minutes=5)
        end = _parse_ts(activity.get("window_end")) or ts
        frm = (start - timedelta(minutes=30)).astimezone(UTC).isoformat(timespec="seconds")
        to = (end + timedelta(minutes=30)).astimezone(UTC).isoformat(timespec="seconds")
        frm, to = frm.replace("+00:00", "Z"), to.replace("+00:00", "Z")
        ip = _safe_ip(summary.get("ip"))
        site = _safe_domain(summary.get("site"))
        conds = [f'@timestamp >= "{frm}"', f'@timestamp <= "{to}"']
        kql = []
        if ip:
            conds.append(f'source.ip == "{ip}"')
            kql.append(f'source.ip : "{ip}"')
        if site:
            conds.append(f'url.domain == "{site}"')
            kql.append(f'url.domain : "{site}"')
        esql = (f"FROM {_LOGS_INDEX}\n| WHERE " + " AND ".join(conds) + "\n"
                "| KEEP @timestamp, source.ip, url.domain, http.request.method, url.path,"
                " http.response.status_code, http.response.body.bytes,"
                " user_agent.original\n| SORT @timestamp\n| LIMIT 1000")
        link = None
        if self.kibana_url and kql:
            g = f"(time:(from:{_rison(frm)},to:{_rison(to)}))"
            a = f"(query:(language:kuery,query:{_rison(' and '.join(kql))}))"
            link = (f"{self.kibana_url}/app/discover#/?_g={quote(g, safe='():,!')}"
                    f"&_a={quote(a, safe='():,!')}")
        return {"from": frm, "to": to, "esql": esql, "kql": " and ".join(kql),
                "kibana_url": link, "index": _LOGS_INDEX}

    # ----------------------------------------------------------------- #
    # writing
    # ----------------------------------------------------------------- #

    def _append(self, path: Path, row: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._write_lock, path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

    def triage(self, alert_id: str, body: dict) -> dict:
        if self._find(alert_id) is None:
            raise LookupError(f"no alert {alert_id!r}")
        verdict = body.get("verdict")
        status = body.get("status") or "open"
        if verdict not in (None, "", *VERDICTS):
            raise ValueError(f"verdict must be one of {', '.join(VERDICTS)}")
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        note = str(body.get("note") or "")[:4000]
        checklist = body.get("checklist") or []
        if not isinstance(checklist, list) or len(checklist) > 50:
            raise ValueError("checklist must be a list of booleans")
        row = {"alert_id": alert_id, "at": datetime.now(UTC).isoformat(timespec="seconds"),
               "verdict": verdict or None, "status": status, "note": note,
               "checklist": [bool(x) for x in checklist], "by": "operator"}
        self._append(self.triage_path, row)
        return row

    def verify_alert(self, alert_id: str, *, force: bool = True) -> list[dict]:
        """Verify every exposure of one alert; rate-limited per exposure."""
        doc = self._find(alert_id)
        if doc is None:
            raise LookupError(f"no alert {alert_id!r}")
        out = []
        for exp in doc.get("exposure") or []:
            rec = self._verify_one(alert_id, exp, force=force)
            if rec is not None:
                out.append(rec)
        return out

    def _verify_one(self, alert_id: str, exp: dict, *, force: bool) -> dict | None:
        key = str(exp.get("key") or "")
        if not key:
            return None
        now = time.monotonic()
        last = self._last_verify.get(key)
        if last is not None and now - last < _VERIFY_MIN_INTERVAL_S:
            records = self._verifications().get(key) or []
            if records:
                return {**records[-1], "rate_limited": True}
            if not force:
                return None
        self._last_verify[key] = now
        try:
            result = self.verify_fn(exp.get("domain"), str(exp.get("root") or "/"),
                                    str(exp.get("kind") or ""),
                                    allowed_domains=self.allowed_domains)
        except Exception as exc:  # a broken check must not take the console down
            result = {"verdict": "unreachable", "detail": f"{type(exc).__name__}: {exc}",
                      "summary": f"Check failed: {type(exc).__name__}"}
        row = {"alert_id": alert_id, "key": key, **result}
        row.setdefault("checked_at", datetime.now(UTC).isoformat(timespec="seconds"))
        self._append(self.verify_path, row)
        return row

    def verify_pending(self) -> int:
        """Check every exposure that has never been checked. Returns how many."""
        verif = self._verifications()
        done = 0
        for doc in self._docs():
            for exp in doc.get("exposure") or []:
                key = str(exp.get("key") or "")
                if key and key not in verif:
                    if self._verify_one(str(doc["alert"]["id"]), exp, force=False):
                        verif[key] = [{}]
                        done += 1
        return done

    def start_verifier(self, every_s: float = 60.0) -> None:
        if self._thread is not None:
            return

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.verify_pending()
                except Exception:
                    pass  # never take the console down; the next pass retries
                self._stop.wait(every_s)

        self._thread = threading.Thread(target=loop, name="soc-ml-ui-verifier", daemon=True)
        self._thread.start()

    def stop_verifier(self) -> None:
        self._stop.set()
