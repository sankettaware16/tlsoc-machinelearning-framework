"""The SIEM shipper: idempotent, lossless across outages, never ahead of ES."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

from soc_ml.alerting.siem import SiemShipper


class _Resp(io.BytesIO):
    def __init__(self, status: int, doc: dict | None = None):
        super().__init__(json.dumps(doc or {}).encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeES:
    """Accepts index creation and bulk; can be told to fail."""

    def __init__(self) -> None:
        self.indices: set[str] = set()
        self.docs: dict[str, dict] = {}
        self.down = False
        self.bulks = 0

    def open(self, req, timeout):
        if self.down:
            raise urllib.error.URLError("connection refused")
        path = req.full_url.split("9200", 1)[1]
        assert req.headers["Authorization"].startswith("ApiKey ")
        if req.get_method() == "HEAD":
            if path.strip("/") in self.indices:
                return _Resp(200)
            raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, io.BytesIO(b""))
        if req.get_method() == "PUT":
            self.indices.add(path.strip("/"))
            return _Resp(200, {"acknowledged": True})
        self.bulks += 1
        lines = req.data.decode().strip().split("\n")
        items = []
        for action, body in zip(lines[::2], lines[1::2]):
            (op, meta), = json.loads(action).items()
            doc = json.loads(body)
            if op == "index":
                self.docs[meta.get("_id") or f"auto{len(self.docs)}"] = doc
                items.append({op: {"status": 201}})
            elif meta["_id"] in self.docs:
                self.docs[meta["_id"]].setdefault("tlsoc", {}).update(doc["doc"]["tlsoc"])
                items.append({op: {"status": 200}})
            else:
                items.append({op: {"status": 404}})
        return _Resp(200, {"errors": any(i[next(iter(i))]["status"] >= 300 for i in items),
                           "items": items})


def _alert(aid: str) -> dict:
    return {"@timestamp": "2026-11-02T03:50:00+00:00", "alert": {"id": aid},
            "source": {"ip": "203.0.113.9"}, "url": {"domain": "www.example.edu"}}


def _append(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _shipper(tmp_path: Path, es: _FakeES) -> SiemShipper:
    return SiemShipper(tmp_path, url="https://es:9200", api_key="id:secret",
                       log=lambda *_: None, opener=es)


def test_alerts_and_their_later_facts_reach_one_document(tmp_path: Path) -> None:
    es = _FakeES()
    _append(tmp_path / "alerts" / "web_recon.ndjson", [_alert("a1"), _alert("a2")])
    _append(tmp_path / "state" / "web_recon_verifications.ndjson",
            [{"alert_id": "a1", "verdict": "confirmed"}])
    _append(tmp_path / "state" / "triage.ndjson",
            [{"alert_id": "a1", "verdict": "true_positive", "status": "resolved"}])
    assert _shipper(tmp_path, es).ship_once() == 4
    assert {"tlsoc-ml-alerts", "tlsoc-ml-alerts-downloads"} <= es.indices
    assert es.docs["a1"]["tlsoc"] == {"verification": {"verdict": "confirmed"},
                                      "triage": {"verdict": "true_positive",
                                                 "status": "resolved"}}


def test_a_restart_resends_nothing_and_a_resend_never_duplicates(tmp_path: Path) -> None:
    es = _FakeES()
    _append(tmp_path / "alerts" / "web_recon.ndjson", [_alert("a1")])
    _shipper(tmp_path, es).ship_once()
    assert _shipper(tmp_path, es).ship_once() == 0, "offsets survive the process"
    (tmp_path / "state" / "siem_checkpoint.json").unlink()
    _shipper(tmp_path, es).ship_once()
    assert list(es.docs) == ["a1"], "the alert id is the document id"


def test_an_outage_loses_nothing(tmp_path: Path) -> None:
    es = _FakeES()
    s = _shipper(tmp_path, es)
    s.ship_once()
    es.down = True
    _append(tmp_path / "alerts" / "web_recon.ndjson", [_alert("a1")])
    assert s.run(once=True) == 1
    es.down = False
    assert s.ship_once() == 1 and "a1" in es.docs


def test_a_half_written_line_waits_for_its_end(tmp_path: Path) -> None:
    es = _FakeES()
    path = tmp_path / "alerts" / "web_recon.ndjson"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_alert("a1")) + "\n" + '{"alert": {"id": "a2"')
    s = _shipper(tmp_path, es)
    assert s.ship_once() == 1
    with path.open("a") as fh:
        fh.write("}}\n")
    assert s.ship_once() == 1 and "a2" in es.docs
