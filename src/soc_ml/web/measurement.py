"""The measurement view: a pre-registered measurement, scored as it runs.

A measurement is decided by the letter of its doc (``docs/measurements/M-*.md``),
so the window, the hypotheses and the verdict deadline are read from that doc's
YAML block, never restated here. What this adds is the live count each
hypothesis will be judged on, from the files the runtime and the console
already write — the same rules the verdict applies, so the operator can watch
a hypothesis go off track while there is still time to triage.

Only exposure-alert measurements (M-003 onwards: their definitions name an
"exposure alert") are scored; any other doc is listed with its window and
hypotheses only. H3 (completeness) needs the log server's raw files and an
offline replay, so it is shown as pending until the verdict, never guessed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from soc_ml.web.alerts import AlertBook, _parse_ts, _tail

__all__ = ["MeasurementBook"]

_STATE_TAIL_BYTES = 8_000_000
_LOG_TAIL_BYTES = 16_000_000
_YAML_BLOCK = re.compile(r"^```yaml\n(.*?)^```", re.S | re.M)
_KEY = re.compile(r"^( {0,2})([A-Za-z0-9_][A-Za-z0-9_ .-]*):(?:\s+(.*))?$")
_COMMENT = re.compile(r"\s+#\s.*$")
_DEADLINE = re.compile(r"by\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})\s+IST")
_LOG_TS = re.compile(r"^(?:\[watchdog\] )?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})")
_AT_LEAST = re.compile(r"(\d+)\s+per day on at least\s+(\d+)\s+of the\s+(\d+)\s+days")
_PLACEHOLDER = "*(appended after the window closes)*"
#: Verifier verdicts that mean the file is out there now.
_EXPOSED = ("confirmed", "likely")
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _loose_yaml(block: str) -> dict[str, Any]:
    """The two levels of key: value a measurement doc uses.

    The docs' blocks are YAML in shape but prose in content ("benign (benign =
    real but authorised: the detection was right)"), which a strict parser
    rejects. A key is a line at indent 0 or 2; every deeper line continues the
    value above it, and a value opened with ``>`` takes its indent-2 lines as
    text, not keys.
    """
    out: dict[str, Any] = {}
    top: str | None = None
    sub: str | None = None
    folded = False
    for raw in block.splitlines():
        line = _COMMENT.sub("", raw.rstrip())
        if not line.strip():
            continue
        m = _KEY.match(line)
        indent = len(line) - len(line.lstrip())
        if m and indent == 0:
            top, sub = m.group(2), None
            value = (m.group(3) or "").strip()
            folded = value in (">", "|")
            out[top] = "" if folded else (value or {})
        elif m and indent == 2 and top is not None and not folded:
            if not isinstance(out[top], dict):
                out[top] = {}
            sub = m.group(2)
            out[top][sub] = (m.group(3) or "").strip()
        elif top is not None:
            text = line.strip()
            if sub is not None and isinstance(out[top], dict):
                out[top][sub] = f"{out[top][sub]} {text}".strip()
            elif isinstance(out[top], str):
                out[top] = f"{out[top]} {text}".strip()
    return out


def _when(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return _parse_ts(str(value)) if value else None


class MeasurementBook:
    """Lists the measurement docs and scores the exposure ones."""

    def __init__(self, data_root: Path, repo_root: Path, alerts: AlertBook,
                 timezone: str = "Asia/Kolkata") -> None:
        self.state_dir = Path(data_root) / "state"
        self.data_root = Path(data_root)
        self.docs_dir = Path(repo_root) / "docs" / "measurements"
        self.alerts = alerts
        self.tz = ZoneInfo(timezone)

    # ----------------------------------------------------------------- #
    # the docs
    # ----------------------------------------------------------------- #

    def _parse(self, path: Path) -> dict[str, Any] | None:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        m = _YAML_BLOCK.search(text)
        spec = _loose_yaml(m.group(1)) if m else {}
        if not spec.get("id"):
            return None
        window = spec.get("window") if isinstance(spec.get("window"), dict) else {}
        start, end = _when(window.get("start")), _when(window.get("end"))
        if start is None or end is None:
            return None
        definitions = spec.get("definitions") if isinstance(spec.get("definitions"), dict) else {}
        record = str(definitions.get("verdict of record") or "")
        due = _DEADLINE.search(record)
        deadline = (datetime.fromisoformat(f"{due.group(1)}T{due.group(2)}:00")
                    .replace(tzinfo=ZoneInfo("Asia/Kolkata")) if due else None)
        verdict = text.split("\n## Verdict", 1)[1] if "\n## Verdict" in text else ""
        verdict = verdict.replace(_PLACEHOLDER, "").strip()
        title = text.splitlines()[0].lstrip("# ").strip() if text else str(spec["id"])
        return {
            "id": str(spec["id"]),
            "title": title,
            "file": f"docs/measurements/{path.name}",
            "question": " ".join(str(spec.get("question") or "").split()),
            "start": start, "end": end, "deadline": deadline,
            "hypotheses": dict(spec["hypotheses"]) if isinstance(
                spec.get("hypotheses"), dict) else {},
            "consequence": dict(spec["consequence"]) if isinstance(
                spec.get("consequence"), dict) else {},
            "scored": "exposure alert" in definitions,
            # M-003d: "nothing stands in for" the analyst's verdict — the
            # verifier is the gate's own instrument from D-044 on.
            "stand_in": "nothing stands in" not in record,
            "verdict": verdict,
        }

    def _specs(self) -> list[dict[str, Any]]:
        specs = [s for p in sorted(self.docs_dir.glob("M-*.md"))
                 if (s := self._parse(p)) is not None]
        specs.sort(key=lambda s: s["start"])
        return specs

    @staticmethod
    def _status(spec: dict, now: datetime) -> str:
        if spec["verdict"]:
            return "judged"
        if now < spec["start"]:
            return "upcoming"
        return "open" if now < spec["end"] else "closed"

    def list(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        rows = [{"id": s["id"], "title": s["title"], "start": s["start"].isoformat(),
                 "end": s["end"].isoformat(), "status": self._status(s, now),
                 "scored": s["scored"]} for s in self._specs()]
        # The one to show first: running, else next, else awaiting a verdict.
        current = next((r["id"] for r in rows if r["status"] == "open"), None) \
            or next((r["id"] for r in rows if r["status"] == "upcoming"), None) \
            or next((r["id"] for r in reversed(rows) if r["status"] == "closed"), None) \
            or (rows[-1]["id"] if rows else None)
        return {"measurements": rows, "current": current}

    # ----------------------------------------------------------------- #
    # the scorecard
    # ----------------------------------------------------------------- #

    def scorecard(self, mid: str, now: datetime | None = None) -> dict[str, Any] | None:
        now = now or datetime.now(UTC)
        spec = next((s for s in self._specs() if s["id"] == mid), None)
        if spec is None:
            return None
        start, end = spec["start"], spec["end"]
        status = self._status(spec, now)
        out: dict[str, Any] = {
            "id": spec["id"], "title": spec["title"], "file": spec["file"],
            "question": spec["question"], "status": status,
            "start": start.isoformat(), "end": end.isoformat(),
            "deadline": spec["deadline"].isoformat() if spec["deadline"] else None,
            "now": now.isoformat(), "timezone": str(self.tz),
            "hypotheses": [{"id": k, "text": v} for k, v in spec["hypotheses"].items()],
            "consequence": spec["consequence"],
            "verdict": spec["verdict"][:6000],
            "scored": spec["scored"],
        }
        if spec["scored"]:
            out.update(self._score(spec, now))
            # Only what this doc hypothesises (M-003b has no H5).
            out["results"] = {k: v for k, v in out["results"].items()
                              if k in spec["hypotheses"]}
        return out

    def _days(self, start: datetime, end: datetime) -> list[datetime]:
        day = start.astimezone(self.tz)
        days = []
        while day < end:
            days.append(day)
            day += timedelta(days=1)  # wall-clock days in the window's zone
        return days

    def _score(self, spec: dict, now: datetime) -> dict[str, Any]:
        start, end, deadline = spec["start"], spec["end"], spec["deadline"]
        upto = min(now, end)
        inside = lambda ts: ts is not None and start <= ts < upto  # noqa: E731
        final = now >= end
        days = self._days(start, end)

        def day_of(ts: datetime) -> int:
            return (ts.astimezone(self.tz).date() - days[0].date()).days

        # Verifier rows by key, oldest first; after the deadline, only those
        # made by it (the verdict of record is fixed then).
        checks = self.alerts._verifications()
        cutoff = deadline if deadline and now >= deadline else None

        def latest(key: str) -> dict | None:
            rows = [r for r in checks.get(key, [])
                    if cutoff is None or (_when(r.get("checked_at")) or now) <= cutoff]
            return rows[-1] if rows else None

        triage = self.alerts._latest_triage()
        alerts = []
        for doc in self.alerts._docs():
            ts = _parse_ts(doc.get("@timestamp"))
            if AlertBook.category(doc) != "exposure" or not inside(ts):
                continue
            alert_id = str(doc["alert"]["id"])
            keys = [str(e.get("key")) for e in doc.get("exposure") or [] if e.get("key")]
            verdicts = {k: (latest(k) or {}).get("verdict") for k in keys}
            if not spec["stand_in"]:
                stand_in = None
            elif any(v == "confirmed" for v in verdicts.values()):
                stand_in = "true_positive"
            elif keys and all(v == "not_reproducible" for v in verdicts.values()):
                stand_in = "false_positive"
            else:
                stand_in = None
            t = triage.get(alert_id) or {}
            analyst = t.get("verdict") if (cutoff is None or (
                _when(t.get("at")) or now) <= cutoff) else None
            summary = self.alerts.summary(doc, t or None, checks)
            alerts.append({
                "id": alert_id, "timestamp": doc.get("@timestamp"), "day": day_of(ts),
                "title": summary["title"], "severity": summary["severity"],
                "severity_score": summary["severity_score"],
                "verifier": verdicts, "analyst": analyst, "stand_in": stand_in,
                "of_record": analyst or stand_in,
                "filled_in": analyst is None and stand_in is not None,
            })
        alerts.sort(key=lambda a: str(a["timestamp"]))

        downloads = [r for r in _tail(self.state_dir / "web_recon_exposures.ndjson",
                                      _STATE_TAIL_BYTES)
                     if inside(_parse_ts(r.get("@timestamp")))]
        withheld: dict[str, dict[str, Any]] = {}
        for r in downloads:
            # A checked download that opened no alert: a page (D-042), a 4xx or
            # a redirect (D-044) at its URL. The verdict says which.
            if not r.get("verdict") or r.get("new"):
                continue
            w = withheld.setdefault(str(r.get("key")), {
                "key": r.get("key"), "kind": r.get("kind"), "first": r.get("@timestamp"),
                "downloads": 0, "clients": set(), "sizes": set(), "day": day_of(
                    _parse_ts(r.get("@timestamp"))), "check": latest(str(r.get("key")))})
            w["downloads"] += 1
            w["clients"].add(r.get("client"))
            w["sizes"].update(f.get("bytes") for f in r.get("files") or [])
        pre_checks = [r for rows in checks.values() for r in rows
                      if r.get("by") == "runtime" and inside(_when(r.get("checked_at")))]

        per_day = []
        for i, d in enumerate(days):
            elapsed = d < upto
            per_day.append({
                "date": d.date().isoformat(), "elapsed": elapsed,
                "exposure_alerts": sum(a["day"] == i for a in alerts) if elapsed else None,
                "withheld": sum(w["day"] == i for w in withheld.values()) if elapsed else None,
                "downloads": sum(day_of(_parse_ts(r["@timestamp"])) == i
                                 for r in downloads) if elapsed else None,
                "checks": sum(day_of(_when(r["checked_at"])) == i
                              for r in pre_checks) if elapsed else None,
            })

        restarts, tracebacks = self._log_events(start, upto)
        return {
            "per_day": per_day,
            "alerts": alerts,
            "withheld": sorted(({**w, "clients": len(w["clients"]),
                                 "sizes": sorted(s for s in w["sizes"] if s is not None),
                                 "check": {k: (w["check"] or {}).get(k) for k in
                                           ("verdict", "status", "content_type", "summary",
                                            "checked_at")}}
                                for w in withheld.values()), key=lambda w: str(w["first"])),
            "pre_checks": {v: sum(r.get("verdict") == v for r in pre_checks)
                           for v in sorted({str(r.get("verdict")) for r in pre_checks})},
            "results": {
                "H1": self._h1(alerts, final and (deadline is None or now >= deadline),
                               stand_in=spec["stand_in"]),
                "H2": self._h2(per_day, final, spec["hypotheses"].get("H2", "")),
                "H3": self._h3(spec, final),
                "H4": {"state": ("fail" if restarts or tracebacks else
                                 "pass" if final else
                                 "waiting" if now < start else "on_track"),
                       "restarts": restarts, "tracebacks": tracebacks,
                       "figure": f"{len(restarts)} watchdog restarts, "
                                 f"{tracebacks} tracebacks"},
                "H5": self._h5(withheld, final),
            },
            "open_exposures": self._open_exposures(checks),
        }

    @staticmethod
    def _h1(alerts: list[dict], final: bool, *, stand_in: bool = True) -> dict[str, Any]:
        """M-003c's rule (the verifier stands in; at most 2 untriaged) or
        M-003d's (analyst verdicts only; one unjudged at the deadline makes
        H1 not testable, never a pass)."""
        judged = [a for a in alerts if a["of_record"]]
        right = sum(a["of_record"] in ("true_positive", "benign") for a in judged)
        untriaged = len(alerts) - len(judged)
        share = right / len(judged) if judged else None
        if stand_in:
            ok = share is not None and share >= 0.8 and untriaged <= 2
        else:
            # Until the deadline the analyst still has time: judge the share.
            ok = share is None or share >= 0.8
        if not alerts:
            state = "not_testable" if final else "waiting"
        elif final and not stand_in and untriaged:
            state = "not_testable"
        elif ok:
            state = "pass" if final else "on_track"
        else:
            state = "fail" if final else "off_track"
        if judged:
            figure = f"{right}/{len(judged)} correct ({share:.0%}), {untriaged} untriaged"
        else:
            figure = f"{len(alerts)} alerts, none with a verdict"
        if not stand_in and untriaged:
            figure += " — every alert needs the analyst's verdict by the deadline"
        return {
            "state": state, "alerts": len(alerts), "correct": right, "judged": len(judged),
            "untriaged": untriaged, "share": round(share, 3) if share is not None else None,
            "by_analyst": sum(not a["filled_in"] and a["of_record"] is not None
                              for a in alerts),
            "filled_in": sum(a["filled_in"] for a in alerts),
            "stand_in": stand_in,
            "figure": figure,
        }

    @staticmethod
    def _h2(per_day: list[dict], final: bool, rule: str) -> dict[str, Any]:
        """The doc's "<= N per day on at least K of the D days"."""
        m = _AT_LEAST.search(rule)
        cap, need, of = (int(g) for g in m.groups()) if m else (3, 5, 7)
        seen = [d for d in per_day if d["elapsed"]]
        over = [d["date"] for d in seen if d["exposure_alerts"] > cap]
        allowed = of - need
        state = ("fail" if len(over) > allowed else
                 "pass" if final else "waiting" if not seen else "on_track")
        return {"state": state, "days_over": over, "allowed_over": allowed, "cap": cap,
                "figure": f"{len(seen) - len(over)} of {len(seen)} days at {cap} or fewer"
                          f" (needs {need} of {of})"}

    def _h3(self, spec: dict, final: bool) -> dict[str, Any]:
        corpus = self.data_root / "corpus" / spec["id"].lower().replace("-", "")
        files = sorted(p.name for p in corpus.glob("*")) if corpus.is_dir() else []
        return {"state": "pending", "corpus": f"data/corpus/{corpus.name}/", "files": files,
                "figure": ("an offline replay of the log server's files, after the window"
                           if not final else
                           f"{len(files)} raw files copied" if files else
                           "raw files not copied yet — the log server keeps ~2.5 days each")}

    @staticmethod
    def _h5(withheld: dict, final: bool) -> dict[str, Any]:
        n = len(withheld)
        return {"state": ("not_testable" if final and not n else
                          "pending" if n else "waiting"),
                "withheld": n,
                "figure": (f"{n} withheld — each classified from the raw log at the verdict"
                           if n else "nothing withheld so far")}

    def _log_events(self, start: datetime, upto: datetime) -> tuple[list[str], int]:
        """Watchdog restarts and tracebacks the runtime log puts in the window."""
        restarts, tracebacks = [], 0
        stamp: datetime | None = None
        path = self.state_dir / "runtime.log"
        try:
            size = path.stat().st_size
            with path.open("rb") as fh:
                if size > _LOG_TAIL_BYTES:
                    fh.seek(size - _LOG_TAIL_BYTES)
                    fh.readline()
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            return [], 0
        for line in text.splitlines():
            m = _LOG_TS.match(line)
            if m:
                stamp = _parse_ts(m.group(1))
            inside = stamp is not None and start <= stamp < upto
            if inside and "runtime not running" in line:
                restarts.append(m.group(1) if m else "?")
            elif inside and line.startswith("Traceback"):
                tracebacks += 1
        return restarts, tracebacks

    def _open_exposures(self, checks: dict[str, list[dict]]) -> list[dict[str, Any]]:
        """Every exposure whose latest check found it served: work for a site owner."""
        from soc_ml.features.exposure import KINDS

        downloads: dict[str, dict[str, Any]] = {}
        for r in _tail(self.state_dir / "web_recon_exposures.ndjson", _STATE_TAIL_BYTES):
            d = downloads.setdefault(str(r.get("key")), {"clients": set(), "last": None,
                                                         "first_alert": None})
            d["clients"].add(r.get("client"))
            d["last"] = r.get("@timestamp")
            if r.get("new") and d["first_alert"] is None:
                d["first_alert"] = r.get("@timestamp")
        rows = []
        for key, history in checks.items():
            last = history[-1]
            if last.get("verdict") not in _EXPOSED:
                continue
            kind = KINDS.get(str(last.get("kind")))
            sev = getattr(getattr(kind, "severity", None), "value", None)
            d = downloads.get(key) or {"clients": set(), "last": None, "first_alert": None}
            rows.append({
                "key": key, "url": last.get("url"), "kind": last.get("kind"),
                "severity": sev, "verdict": last.get("verdict"),
                "signature": last.get("signature"), "checked_at": last.get("checked_at"),
                "first_alerted": d["first_alert"], "last_download": d["last"],
                "downloaders": len(d["clients"] - {None}),
            })
        rows.sort(key=lambda r: (_SEV_RANK.get(str(r["severity"]), 9), str(r["key"])))
        return rows
