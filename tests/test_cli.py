"""CLI-level smoke tests — drive the real commands end to end.

Unit tests exercise the functions; these exercise the `soc-ml` command wrappers
themselves, which is where report-shape / print-formatting bugs hide (a renamed
report key crashes the CLI but not the function it wraps). Every command a user
runs must at least not crash on real output.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_ml.cli.main import main

T0 = datetime(2026, 7, 27, 8, 0, 0, tzinfo=timezone.utc)


def _synthetic_web_log(path: Path) -> None:
    """Benign browsing plus one clear directory-enumeration scanner."""
    rows = []
    pages = ["/", "/index.html", "/about", "/courses", "/static/app.js"]
    for i in range(4000):
        ts = T0 + timedelta(seconds=i * 3)
        rows.append({
            "@timestamp": ts.isoformat(),
            "observer": {"server": "web01"},
            "source": {"ip": f"203.0.113.{i % 40}", "geo": {"country_iso_code": "US"}},
            "http": {"request": {"method": "GET", "referrer": "/home"},
                     "response": {"status_code": 200 if i % 4 else 304, "body": {"bytes": 800}}},
            "url": {"path": pages[i % len(pages)]},
            "user_agent": {"original": "Mozilla/5.0"},
            "event": {"original": "benign"},
        })
    base = T0 + timedelta(seconds=7000)
    for i in range(120):
        ts = base + timedelta(seconds=i * 2)
        rows.append({
            "@timestamp": ts.isoformat(),
            "observer": {"server": "web01"},
            "source": {"ip": "198.51.100.66", "geo": {"country_iso_code": "ZZ"}},
            "http": {"request": {"method": "GET", "referrer": "-"},
                     "response": {"status_code": 404, "body": {"bytes": 150}}},
            "url": {"path": f"/hidden/backup_{i}.sql"},
            "user_agent": {"original": "scan/1.0"},
            "event": {"original": f"GET /hidden/backup_{i}.sql 404"},
        })
    rows.sort(key=lambda r: r["@timestamp"])
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


@pytest.fixture()
def logfile(tmp_path: Path) -> Path:
    p = tmp_path / "nginx.json"
    _synthetic_web_log(p)
    return p


def test_validate_command(logfile: Path, capsys) -> None:
    assert main(["validate", "--input", str(logfile)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_sessions_command(logfile: Path) -> None:
    assert main(["sessions", "--input", str(logfile)]) == 0


def test_backtest_command_runs_and_reports(logfile: Path, tmp_path: Path, capsys) -> None:
    """The regression guard: this crashed on a renamed report key (KeyError)."""
    rc = main(["backtest", "--input", str(logfile), "--out", str(tmp_path / "d")])
    out = capsys.readouterr().out
    assert rc == 0, out
    # the print block must render every field it references
    assert "alerts" in out and "delivered" in out
    assert "canary" in out and "DETECTED" in out
    assert "RESULT: PASS" in out


def test_train_promote_status_run_lifecycle(logfile: Path, tmp_path: Path, capsys) -> None:
    out_dir = str(tmp_path / "data")
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _synthetic_web_log(incoming / "nginx.json")

    assert main(["train", "--input", str(logfile), "--out", out_dir]) == 0
    assert "CANDIDATE" in capsys.readouterr().out

    assert main(["status", "--out", out_dir]) == 0
    assert "candidate" in capsys.readouterr().out.lower()

    assert main(["promote", "--out", out_dir]) == 0
    assert "serving" in capsys.readouterr().out.lower()

    # live run over a directory, one pass, deliver alerts, budget-capped
    rc = main(["run", "--input", str(incoming), "--out", out_dir,
               "--mode", "live", "--once", "--daily-budget", "5"])
    assert rc == 0
    assert main(["status", "--out", out_dir]) == 0
    assert "live health" in capsys.readouterr().out.lower()


def test_run_refuses_without_model(logfile: Path, tmp_path: Path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    _synthetic_web_log(incoming / "nginx.json")
    rc = main(["run", "--input", str(incoming), "--out", str(tmp_path / "empty"),
               "--mode", "live", "--once"])
    assert rc == 2  # no trained model, no cold-start
