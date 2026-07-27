"""Tests for input validation, especially timestamp-quality detection (FR-08).

A parser that stamps events at parse time produces @timestamp values that are
present, well-formed, 100% populated — and the wrong clock. Field-coverage
checks cannot see it, and it is worse than data loss: batched timestamps drive
inter-arrival CV to ~0, which is exactly the "machine-regular" signature UC-01
and UC-04 treat as bot evidence.

The check has two levels, and the distinction matters:

* `event.timestamp_source` is the parser's own attestation and is authoritative.
* The heuristic is a fallback for feeds without it. It keys on *sub-second*
  collisions, because real event times do not collide at microsecond precision,
  while second-resolution collisions (classic CLF on a busy server) are entirely
  normal and must never be flagged.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc_ml.cli.main import _check_timestamp_quality

T0 = datetime(2026, 7, 9, 8, 0, 0, tzinfo=timezone.utc)
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLES = Path(__file__).resolve().parents[2] / "log_samples"


def ingest_batched(batches: int, per_batch: int) -> Counter:
    """Whole flushes sharing one *microsecond-precision* instant."""
    return Counter(
        {T0 + timedelta(seconds=i * 60, microseconds=123456): per_batch
         for i in range(batches)}
    )


def clf_busy_server(seconds: int, per_second: int) -> Counter:
    """Real CLF event times: 1-second resolution, many events per second."""
    return Counter({T0 + timedelta(seconds=i): per_second for i in range(seconds)})


# --------------------------------------------------------------------------- #
# Parser attestation is authoritative
# --------------------------------------------------------------------------- #


def test_attested_log_time_is_trusted_despite_collisions() -> None:
    """A busy server yields many events per second — that is not a defect."""
    stamps = clf_busy_server(seconds=60, per_second=200)
    sources = Counter({"log": 12000})
    assert _check_timestamp_quality(stamps, 12000, 12000, sources) == []


def test_log_assumed_utc_is_also_trusted() -> None:
    stamps = clf_busy_server(seconds=30, per_second=100)
    sources = Counter({"log_assumed_utc": 3000})
    assert _check_timestamp_quality(stamps, 3000, 0, sources) == []


def test_ingest_fallback_is_reported_even_without_collisions() -> None:
    """The parser admitting it guessed is enough; no heuristic needed."""
    stamps = Counter({T0 + timedelta(seconds=i): 1 for i in range(1000)})
    sources = Counter({"ingest_fallback": 1000})
    problems = _check_timestamp_quality(stamps, 1000, 0, sources)

    assert problems, "ingest_fallback must always be surfaced"
    assert "ingest_fallback" in problems[0]
    assert "false positives" in problems[0]


def test_small_ingest_fallback_minority_is_tolerated() -> None:
    """A handful of unparseable lines is not a systemic failure."""
    stamps = Counter({T0 + timedelta(seconds=i): 1 for i in range(1000)})
    sources = Counter({"log": 980, "ingest_fallback": 20})
    assert _check_timestamp_quality(stamps, 1000, 0, sources) == []


# --------------------------------------------------------------------------- #
# Heuristic fallback, for feeds with no attestation
# --------------------------------------------------------------------------- #


def test_subsecond_batching_is_flagged_when_unattested() -> None:
    stamps = ingest_batched(batches=40, per_batch=50)
    problems = _check_timestamp_quality(stamps, 2000, 0, Counter())

    assert problems
    assert "INGEST time" in problems[0]
    assert "false positives" in problems[0]


def test_second_resolution_collisions_are_not_flagged() -> None:
    """The regression that matters: busy CLF traffic must stay clean."""
    stamps = clf_busy_server(seconds=100, per_second=50)
    assert _check_timestamp_quality(stamps, 5000, 5000, Counter()) == []


def test_healthy_distinct_timestamps_produce_no_warning() -> None:
    stamps = Counter(
        {T0 + timedelta(seconds=i, microseconds=i): 1 for i in range(1500)}
    )
    assert _check_timestamp_quality(stamps, 1500, 0, Counter()) == []


def test_remediation_points_at_reparsing_when_true_time_survives() -> None:
    problems = _check_timestamp_quality(ingest_batched(40, 50), 2000, 2000, Counter())
    assert len(problems) == 2
    assert "event.original_time" in problems[1]
    assert "re-parse" in problems[1]


def test_no_remediation_hint_when_true_time_is_unavailable() -> None:
    problems = _check_timestamp_quality(ingest_batched(40, 50), 2000, 0, Counter())
    assert len(problems) == 1, "do not suggest a fix the data cannot support"


def test_tiny_collisions_are_ignored() -> None:
    """Two events sharing an instant is coincidence, not a batch."""
    stamps = Counter({T0 + timedelta(microseconds=1): 2})
    stamps.update({T0 + timedelta(seconds=i, microseconds=7): 1 for i in range(1, 500)})
    assert _check_timestamp_quality(stamps, 501, 0, Counter()) == []


def test_empty_input_is_handled() -> None:
    assert _check_timestamp_quality(Counter(), 0, 0, Counter()) == []
    assert _check_timestamp_quality(Counter(), 100, 0, Counter()) == []


# --------------------------------------------------------------------------- #
# Against real files
# --------------------------------------------------------------------------- #


def _measure(path: Path) -> tuple[Counter, Counter, int, int]:
    stamps: Counter = Counter()
    sources: Counter = Counter()
    original_time = n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        doc = json.loads(line)
        n += 1
        stamps[datetime.fromisoformat(doc["@timestamp"].replace("Z", "+00:00"))] += 1
        ev = doc.get("event") or {}
        if ev.get("original_time"):
            original_time += 1
        if ev.get("timestamp_source"):
            sources[ev["timestamp_source"]] += 1
    return stamps, sources, original_time, n


@pytest.mark.parametrize(
    "name", ["nginx_sample.json", "moodleapplication_sample.json"]
)
def test_current_samples_have_trustworthy_event_time(name: str) -> None:
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"sample not present: {name}")
    stamps, sources, original_time, n = _measure(path)
    assert _check_timestamp_quality(stamps, n, original_time, sources) == [], (
        f"{name} should carry real event time"
    )


def test_stale_engine_output_is_still_detected() -> None:
    """Regression guard: output from the old engine must not slip through.

    This fixture is genuine output from a superseded parser version — the exact
    failure FR-08 exists to catch. It has no `timestamp_source` attestation, so
    it exercises the heuristic path.
    """
    path = FIXTURES / "nginx_stale_ingest_time.json"
    if not path.exists():
        pytest.skip("stale fixture not present")
    stamps, sources, original_time, n = _measure(path)

    assert not sources, "fixture predates event.timestamp_source"
    problems = _check_timestamp_quality(stamps, n, original_time, sources)
    assert problems, "stale ingest-time output must be flagged"
    assert "INGEST time" in problems[0]
    assert any("re-parse" in p for p in problems)
