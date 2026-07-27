"""The shared per-entity annotation store — cross-use-case signal exchange.

The first real instance of the spec's cross-use-case feature sharing
(JOURNAL D-019): ``bot_detection`` writes ``crawler.human_likeness`` /
``crawler.is_known`` / ``crawler.is_verified`` per scored window, and the
scorer exposes the entity's current annotations to every use case that runs
*after* it in the window (dependency order guarantees the producer scored
first). ``web_recon``'s gate reads them to suppress verified crawlers —
visibly, never silently.

Deliberately dumb: a bounded LRU of ``entity -> {name: value, "at", "source"}``.
Staleness policy belongs to the *consumer* (a suppression decision knows how
fresh it needs its signal); the store just records when and by whom each
annotation was written. In-memory only — after a restart it refills within one
window cadence, which is cheaper and more honest than trusting stale state.
"""

from __future__ import annotations

from typing import Any

__all__ = ["EntityAnnotations"]

_MAX_ENTITIES = 200_000


class EntityAnnotations:
    """Bounded per-entity annotation table, shared across use cases."""

    def __init__(self, max_entities: int = _MAX_ENTITIES) -> None:
        self.max_entities = max_entities
        self._table: dict[str, dict[str, Any]] = {}
        self.stats = {"annotated": 0, "evicted": 0}

    def annotate(
        self, entity: str, values: dict[str, Any], *, at: str, source: str
    ) -> None:
        """Record (or refresh) one entity's annotations from one use case."""
        self._table.pop(entity, None)
        if len(self._table) >= self.max_entities:
            # LRU: insertion order + touch-on-read makes the first key coldest.
            del self._table[next(iter(self._table))]
            self.stats["evicted"] += 1
        self._table[entity] = {**values, "at": at, "source": source}
        self.stats["annotated"] += 1

    def get(self, entity: str) -> dict[str, Any] | None:
        """The entity's current annotations, or None when nothing is known."""
        record = self._table.pop(entity, None)
        if record is not None:
            self._table[entity] = record  # touch: reading keeps an entity warm
        return record

    @property
    def size(self) -> int:
        return len(self._table)
