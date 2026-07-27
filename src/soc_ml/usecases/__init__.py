"""Detection use cases. Naming per docs/NAMING.md: module = slug.

Importing this package registers every built-in use case with the registry.
"""

from __future__ import annotations

from .web_recon import WebRecon

__all__ = ["WebRecon", "dependency_order"]


def dependency_order(usecase_classes: list[type]) -> list[type]:
    """Order use-case classes so every declared dependency scores first.

    ``UseCase.depends_on`` names the slugs whose exported per-entity signals a
    use case consumes (bot_detection before web_recon — JOURNAL D-019). This is
    a deterministic topological sort: ties resolve by slug, so the same set
    always schedules identically (NFR-10). A dependency that is not in the
    given set is ignored here — the *consumer* is responsible for treating the
    missing signal as "unknown", visibly (NFR-09).

    Raises ``ValueError`` on a dependency cycle, naming the slugs involved.
    """
    by_slug = {cls.name: cls for cls in usecase_classes}
    remaining = dict(sorted(by_slug.items()))
    ordered: list[type] = []
    while remaining:
        ready = [
            slug
            for slug, cls in remaining.items()
            if not any(dep in remaining for dep in cls.depends_on)
        ]
        if not ready:
            raise ValueError(
                "use-case dependency cycle among: " + ", ".join(sorted(remaining))
            )
        for slug in ready:
            ordered.append(remaining.pop(slug))
    return ordered
