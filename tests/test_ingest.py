"""Tests for file-tail ingestion (FR-02, FR-04, NFR-09)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_ml.ingest import FileSource

SAMPLES = Path(__file__).resolve().parents[2] / "log_samples"


def ecs(ip: str = "10.0.0.1", path: str = "/", ts: str = "2026-07-09T08:01:48Z") -> str:
    return json.dumps(
        {
            "@timestamp": ts,
            "observer": {"server": "web01", "org": "example", "env": "production"},
            "source": {"ip": ip},
            "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
            "url": {"path": path},
            "user_agent": {"original": "Mozilla/5.0"},
            "event": {"original": "raw line"},
        }
    )


def write(tmp: Path, name: str, lines: list[str], newline_at_end: bool = True) -> Path:
    body = "\n".join(lines) + ("\n" if newline_at_end and lines else "")
    p = tmp / name
    p.write_text(body, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #


def test_reads_all_events_from_a_directory(tmp_path: Path) -> None:
    write(tmp_path, "a.json", [ecs(path="/a"), ecs(path="/b")])
    write(tmp_path, "b.json", [ecs(path="/c")])

    src = FileSource(tmp_path)
    events = list(src.read())

    assert len(events) == 3
    assert src.stats.parsed == 3
    assert src.stats.failed == 0


def test_offline_read_stops_and_does_not_skip_backlog(tmp_path: Path) -> None:
    """A backtest must see existing data, never start at the end."""
    write(tmp_path, "a.json", [ecs(), ecs()])
    src = FileSource(tmp_path, follow=False, start_at_end=True)
    assert len(list(src.read())) == 2, "offline read must ignore start_at_end"


def test_read_order_is_deterministic(tmp_path: Path) -> None:
    """A backtest that reorders events between runs is not reproducible."""
    write(tmp_path, "b.json", [ecs(path="/b")])
    write(tmp_path, "a.json", [ecs(path="/a")])
    write(tmp_path, "c.json", [ecs(path="/c")])

    first = [e.url_path for e in FileSource(tmp_path).read()]
    second = [e.url_path for e in FileSource(tmp_path).read()]
    assert first == second == ["/a", "/b", "/c"]


def test_resumes_from_checkpoint_without_reprocessing(tmp_path: Path) -> None:
    write(tmp_path, "a.json", [ecs(path="/1"), ecs(path="/2")])

    src = FileSource(tmp_path)
    assert len(list(src.read())) == 2
    cp = src.checkpoint()

    # Appending new data; a resumed reader must see only the new lines.
    with (tmp_path / "a.json").open("a", encoding="utf-8") as fh:
        fh.write(ecs(path="/3") + "\n")

    resumed = FileSource(tmp_path)
    resumed.seek(cp)
    assert [e.url_path for e in resumed.read()] == ["/3"]


def test_rewind_replays_everything(tmp_path: Path) -> None:
    """Replay is load-bearing for cold start, backtest and SAIF (FR-04)."""
    write(tmp_path, "a.json", [ecs(path="/1"), ecs(path="/2")])
    src = FileSource(tmp_path)

    assert len(list(src.read())) == 2
    assert len(list(src.read())) == 0, "already consumed"
    src.rewind()
    assert len(list(src.read())) == 2, "rewind must replay"


def test_partial_line_is_not_consumed(tmp_path: Path) -> None:
    """The parser may be mid-write; a torn line must not become an event."""
    path = tmp_path / "a.json"
    path.write_text(ecs(path="/complete") + "\n" + ecs(path="/partial")[:40], encoding="utf-8")

    src = FileSource(tmp_path)
    first = [e.url_path for e in src.read()]
    assert first == ["/complete"]
    assert src.stats.failed == 0, "a partial line must not be dead-lettered"

    # Completing the line makes it readable, exactly once.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(ecs(path="/partial")[40:] + "\n")
    assert [e.url_path for e in src.read()] == ["/partial"]


def test_truncation_restarts_the_file(tmp_path: Path) -> None:
    """A rotated-in-place file must not be ignored forever."""
    path = tmp_path / "a.json"
    write(tmp_path, "a.json", [ecs(path="/old1"), ecs(path="/old2")])

    src = FileSource(tmp_path)
    assert len(list(src.read())) == 2

    path.write_text(ecs(path="/new") + "\n", encoding="utf-8")  # smaller than before
    assert [e.url_path for e in src.read()] == ["/new"]


def test_malformed_lines_are_dead_lettered_not_dropped(tmp_path: Path) -> None:
    """Silent discard is indistinguishable from working (NFR-09)."""
    dlq = tmp_path / "dlq" / "bad.json"
    write(
        tmp_path,
        "a.json",
        [ecs(path="/good"), "{not json", json.dumps({"no": "timestamp"}), ecs(path="/good2")],
    )

    src = FileSource(tmp_path, dlq_path=dlq)
    events = list(src.read())
    src.close()

    assert [e.url_path for e in events] == ["/good", "/good2"]
    assert src.stats.failed == 2
    assert src.stats.parsed == 2
    assert src.stats.reasons, "failure reasons must be recorded"

    records = [json.loads(line) for line in dlq.read_text().splitlines()]
    assert len(records) == 2
    assert all("reason" in r and "raw" in r for r in records)


def test_blank_lines_are_ignored_silently(tmp_path: Path) -> None:
    write(tmp_path, "a.json", [ecs(), "", "   ", ecs()])
    src = FileSource(tmp_path)
    assert len(list(src.read())) == 2
    assert src.stats.failed == 0


def test_missing_directory_yields_nothing_without_raising(tmp_path: Path) -> None:
    src = FileSource(tmp_path / "does-not-exist")
    assert list(src.read()) == []


def test_reads_the_real_sample_logs() -> None:
    path = SAMPLES / "nginx_sample.json"
    if not path.exists():
        pytest.skip("sample not present")
    src = FileSource(path)
    events = list(src.read())
    assert len(events) == 2000
    assert src.stats.failed == 0
    assert src.stats.failure_rate == 0.0
