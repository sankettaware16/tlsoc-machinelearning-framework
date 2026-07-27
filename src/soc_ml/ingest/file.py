"""File-tail ingestion — the default source (FR-02).

Reads the ECS JSON that the log parser writes to disk. This is the zero-infra
path: no Kafka, no broker, no network. It is also what makes replay cheap, and
replay is load-bearing — cold-start warmup, backtests, and SAIF all work by
rewinding (FR-04).

Three correctness details that matter more than they look:

* **Partial lines are never consumed.** The parser may be mid-write when we read.
  A line without a trailing newline is left unread and the offset is not
  advanced, so the next poll picks it up whole. Without this, tailing a live file
  silently corrupts roughly one event per flush.
* **Truncation and rotation are detected** by comparing file size against the
  stored offset. A rotated file restarts at 0 rather than being skipped forever.
* **Unparseable lines are dead-lettered, never dropped** (NFR-09). A source that
  quietly discards malformed input is indistinguishable from one that is working.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from soc_ml.core.contracts import Event
from soc_ml.core.plugins import Source

# orjson parses bytes 2-3x faster than stdlib json and is a core dependency;
# fall back gracefully if it is ever missing (NFR-08). Both accept bytes.
try:
    import orjson

    def _loads(raw: bytes):
        return orjson.loads(raw)
except ImportError:  # pragma: no cover - orjson is a core dependency
    def _loads(raw: bytes):
        return json.loads(raw)

log = logging.getLogger(__name__)

__all__ = ["FileSource", "IngestStats"]


@dataclass(slots=True)
class IngestStats:
    """Observable counters. Silence is not an acceptable failure mode."""

    files_seen: int = 0
    lines_read: int = 0
    parsed: int = 0
    failed: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def record_failure(self, exc: Exception) -> None:
        self.failed += 1
        key = f"{type(exc).__name__}: {str(exc)[:80]}"
        self.reasons[key] = self.reasons.get(key, 0) + 1

    @property
    def failure_rate(self) -> float:
        total = self.parsed + self.failed
        return self.failed / total if total else 0.0


class FileSource(Source):
    """Yield :class:`Event` objects from newline-delimited ECS JSON files.

    Args:
        path: file or directory of parser output.
        pattern: glob used when ``path`` is a directory.
        follow: keep polling for appended data and new files (live mode).
            ``False`` reads what exists and stops (offline/backtest).
        poll_interval_s: sleep between polls when following.
        dlq_path: where unparseable lines are written. ``None`` still counts
            them in :attr:`stats` but does not persist them.
        start_at_end: when following a live stream with no checkpoint, skip the
            existing backlog. Ignored for offline reads, which always start at
            the beginning.
    """

    name = "file"
    description = "tail ECS JSON files from the parser output directory"

    def __init__(
        self,
        path: str | Path,
        *,
        pattern: str = "*.json",
        follow: bool = False,
        poll_interval_s: float = 1.0,
        dlq_path: str | Path | None = None,
        start_at_end: bool = False,
    ) -> None:
        self.root = Path(path).expanduser()
        self.pattern = pattern
        self.follow = follow
        self.poll_interval_s = poll_interval_s
        self.dlq_path = Path(dlq_path).expanduser() if dlq_path else None
        self.start_at_end = start_at_end and follow

        self._offsets: dict[str, int] = {}
        self._dlq_fh: Any = None
        self.stats = IngestStats()
        self._stopped = False

    # -- discovery --------------------------------------------------------- #

    def _files(self) -> list[Path]:
        if self.root.is_file():
            return [self.root]
        if not self.root.is_dir():
            return []
        # Sorted so replay order is deterministic — a backtest that reorders
        # events between runs is not reproducible (NFR-10).
        return sorted(p for p in self.root.rglob(self.pattern) if p.is_file())

    def _key(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    # -- reading ----------------------------------------------------------- #

    def read(self) -> Iterator[Event]:
        """Yield events. Returns when exhausted unless ``follow`` is set."""
        first_pass = True
        while not self._stopped:
            files = self._files()
            self.stats.files_seen = len(files)
            for path in files:
                yield from self._read_file(path, first_pass=first_pass)
            if not self.follow:
                return
            first_pass = False
            time.sleep(self.poll_interval_s)

    def _read_file(self, path: Path, *, first_pass: bool) -> Iterator[Event]:
        key = self._key(path)
        try:
            size = path.stat().st_size
        except OSError as exc:  # disappeared between glob and stat
            log.debug("cannot stat %s: %s", path, exc)
            return

        offset = self._offsets.get(key)
        if offset is None:
            # A live tail with no checkpoint may skip the backlog; an offline
            # read never does, or a backtest would silently see nothing.
            offset = size if (self.start_at_end and first_pass) else 0
        elif size < offset:
            # Truncated or rotated in place — start over rather than never
            # reading this file again.
            log.info("file %s shrank (%d < %d); restarting from 0", key, size, offset)
            offset = 0

        if size == offset:
            self._offsets[key] = offset
            return

        try:
            fh = path.open("rb")
        except OSError as exc:
            log.warning("cannot open %s: %s", path, exc)
            return

        with fh:
            fh.seek(offset)
            while True:
                line = fh.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # Partial write in progress. Leave the offset before it so
                    # the next poll reads the complete line.
                    break
                offset += len(line)
                stripped = line.strip()
                if not stripped:
                    continue
                self.stats.lines_read += 1
                event = self._parse(stripped, key)
                if event is not None:
                    self.stats.parsed += 1
                    yield event

        self._offsets[key] = offset

    def _parse(self, raw: bytes, source_key: str) -> Event | None:
        try:
            return Event.from_ecs(_loads(raw))
        except Exception as exc:
            self.stats.record_failure(exc)
            self._dead_letter(raw, source_key, exc)
            return None

    def _dead_letter(self, raw: bytes, source_key: str, exc: Exception) -> None:
        if self.dlq_path is None:
            return
        try:
            if self._dlq_fh is None:
                self.dlq_path.parent.mkdir(parents=True, exist_ok=True)
                self._dlq_fh = self.dlq_path.open("a", encoding="utf-8")
            record = {
                "source": source_key,
                "reason": f"{type(exc).__name__}: {exc}",
                "raw": raw.decode("utf-8", "replace"),
            }
            self._dlq_fh.write(json.dumps(record) + "\n")
            self._dlq_fh.flush()
        except OSError as exc2:  # never let DLQ failure stop ingestion
            log.warning("cannot write DLQ %s: %s", self.dlq_path, exc2)

    # -- checkpoint / replay ----------------------------------------------- #

    def checkpoint(self) -> dict[str, Any]:
        """Restart-safe position: byte offset per file."""
        return {"offsets": dict(self._offsets)}

    def seek(self, checkpoint: dict[str, Any]) -> None:
        """Resume from a checkpoint. ``{}`` rewinds to the beginning (replay)."""
        self._offsets = dict(checkpoint.get("offsets") or {})

    def rewind(self) -> None:
        """Replay everything from the start (FR-04)."""
        self._offsets.clear()

    def stop(self) -> None:
        """Ask a following reader to finish after the current pass."""
        self._stopped = True

    def close(self) -> None:
        if self._dlq_fh is not None:
            self._dlq_fh.close()
            self._dlq_fh = None
