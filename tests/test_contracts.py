"""Contract tests against real parsed logs.

These run against `log_samples/` — genuine parser output from a live university
estate. If a change breaks these, the framework can no longer read the data it
exists to analyse, so they are release-blocking (FR-01).

The web sources (nginx, moodle/apache) are the primary detection domain. Squid
and postfix are out of the current detection scope but are kept here because
they prove the loader survives events that legitimately lack web fields, rather
than assuming every event is an HTTP request.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_ml.core import Event

SAMPLES = Path(__file__).resolve().parents[2] / "log_samples"
WEB_SAMPLES = ["nginx_sample.json", "moodleapplication_sample.json"]
ALL_SAMPLES = WEB_SAMPLES + ["squid_sample.json", "postfix_sample.json"]


def load(name: str, limit: int = 200) -> list[dict]:
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"sample not present: {path}")
    out = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
            if len(out) >= limit:
                break
    return out


@pytest.mark.parametrize("name", ALL_SAMPLES)
def test_every_line_parses(name: str) -> None:
    """No event in real parser output may fail to load."""
    docs = load(name)
    assert docs, f"{name} yielded no events"
    for doc in docs:
        Event.from_ecs(doc)


@pytest.mark.parametrize("name", WEB_SAMPLES)
def test_web_events_carry_the_fields_features_need(name: str) -> None:
    """The web contract must actually be populated, not merely parseable."""
    events = [Event.from_ecs(d) for d in load(name)]

    def coverage(pred) -> float:
        return sum(1 for e in events if pred(e)) / len(events)

    assert coverage(lambda e: e.source_ip is not None) > 0.95
    assert coverage(lambda e: e.url_path is not None) > 0.95
    assert coverage(lambda e: e.status_code is not None) > 0.95
    assert coverage(lambda e: e.user_agent is not None) > 0.90
    assert coverage(lambda e: e.http_method is not None) > 0.90
    assert coverage(lambda e: e.observer.server is not None) > 0.95


@pytest.mark.parametrize("name", WEB_SAMPLES)
def test_entity_key_is_stable_and_discriminating(name: str) -> None:
    """Entity identity must be reproducible and must not collapse to one actor."""
    docs = load(name)
    events = [Event.from_ecs(d) for d in docs]

    # Deterministic: parsing the same document twice yields the same entity.
    for doc in docs[:50]:
        assert Event.from_ecs(doc).entity == Event.from_ecs(doc).entity
        assert len(Event.from_ecs(doc).ua_hash) == 16

    # Discriminating: identical (server, ip, ua) must map to one entity, and
    # differing ones must not — otherwise per-entity features are meaningless.
    triples = {
        (e.observer.server, e.source_ip, e.user_agent) for e in events
    }
    entities = {str(e.entity) for e in events}
    assert len(entities) == len(triples), "entity key collides or over-splits"
    assert len(entities) > 1, "sample collapses to a single entity"


def test_missing_referrer_is_normalized() -> None:
    """The parser emits '-' for no referrer; features must not see that string."""
    doc = {
        "@timestamp": "2026-07-09T08:01:48.482587Z",
        "observer": {"server": "web01"},
        "http": {"request": {"method": "GET", "referrer": "-"}},
    }
    assert Event.from_ecs(doc).http_referrer is None


def test_absent_geo_marks_the_source_internal() -> None:
    """Missing source.geo IS the internal/external flag, not missing data."""
    internal = Event.from_ecs(
        {
            "@timestamp": "2026-07-09T08:01:48Z",
            "observer": {"server": "web01"},
            "source": {"ip": "10.99.1.82"},
        }
    )
    external = Event.from_ecs(
        {
            "@timestamp": "2026-07-09T08:01:48Z",
            "observer": {"server": "web01"},
            "source": {"ip": "203.0.113.65", "geo": {"country_iso_code": "US"}},
        }
    )
    assert internal.is_internal is True
    assert external.is_internal is False


def test_bad_input_fails_loudly() -> None:
    """Malformed events must raise, never yield a silently degraded Event."""
    with pytest.raises(ValueError):
        Event.from_ecs({"observer": {"server": "web01"}})  # no @timestamp
    with pytest.raises(ValueError):
        Event.from_ecs({"@timestamp": "not-a-time"})


def test_original_is_available_as_evidence_only() -> None:
    """event.original must survive for alert evidence (FR-42) but never be a feature."""
    docs = load("nginx_sample.json", limit=20)
    events = [Event.from_ecs(d) for d in docs]
    assert any(e.original for e in events), "no raw lines available for evidence"
