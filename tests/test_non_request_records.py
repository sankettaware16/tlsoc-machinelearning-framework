"""nginx's error channel is not a request stream (JOURNAL D-025).

On 18 August 2026 `web_recon` alerted on 157.51.4.183 — an iPhone loading the
IIT Bombay homepage. Nginx rate-limited the browser's asset burst and wrote
~50 `[error] limiting requests` lines. The parser labels those
``event.type: error``, but the framework did not look, so they became "requests"
with no user-agent, no status and no bytes.

Three consequences, all visible in the production alert:

* every firing entity carried ``ua_hash e3b0c44298fc1c14`` — SHA-256 of the
  empty string — because error records have no user-agent;
* error records log the whole request target, so ``url.path`` arrives with the
  query string attached and ``/x.js?v=9.3.22`` reads as the unknown extension
  ``js?v=9``. ``web.unknown_ext_ratio`` hit 0.6522 against a population median
  of 0.0 and became the top feature behind the alert;
* a third of every event on that stream was this, multiplied by every use case.
"""

from __future__ import annotations

from soc_ml.baseline.profile import _extension
from soc_ml.core.contracts import Event

ACCESS = {
    "@timestamp": "2026-08-18T07:48:14+00:00",
    "event": {"category": "web", "type": "access", "module": "nginx"},
    "observer": {"server": "logserver"},
    "source": {"ip": "157.51.4.183"},
    "http": {"request": {"method": "GET", "referrer": "https://www.iitb.ac.in/"},
             "response": {"status_code": 429, "body": {"bytes": 162}}},
    "url": {"path": "/core/misc/drupal.js"},
    "user_agent": {"original": "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6_0 like Mac OS X)"},
}

#: A real line from the production stream, trimmed.
ERROR = {
    "@timestamp": "2026-08-18T07:48:14+00:00",
    "event": {"category": "web", "type": "error", "module": "nginx",
              "action": "request_limit", "reason": "nginx_limit_req",
              "original": '... [error] 1209#1209: limiting requests, excess: 30.500 '
                          'by zone "perip", client: 157.51.4.183, request: '
                          '"GET /core/misc/drupal.js?v=9.3.22 HTTP/2.0"'},
    "observer": {"server": "logserver"},
    "source": {"ip": "157.51.4.183"},
    "log": {"level": "error"},
    "url": {"path": "/core/misc/drupal.js?v=9.3.22"},
}


def test_an_access_record_is_a_request() -> None:
    assert Event.from_ecs(ACCESS).is_request is True


def test_an_nginx_error_record_is_not_a_request() -> None:
    event = Event.from_ecs(ERROR)
    assert event.event_type == "error"
    assert event.is_request is False
    # The shape that made it look like a headless client in the first place.
    assert event.user_agent is None
    assert event.status_code is None


def test_a_producer_that_sets_no_event_type_is_still_processed() -> None:
    """Filebeat and Vector set no event.type; dropping their traffic is worse
    than processing an occasional non-request."""
    doc = {**ACCESS, "event": {"module": "nginx"}}
    assert Event.from_ecs(doc).is_request is True


def test_source_skips_non_requests_and_counts_them(tmp_path) -> None:
    import json

    from soc_ml.ingest.file import FileSource

    path = tmp_path / "nginx.json"
    path.write_text("".join(
        json.dumps(doc) + "\n" for doc in ([ACCESS] * 4 + [ERROR] * 6)))

    src = FileSource(path, follow=False)
    events = list(src.read())

    assert len(events) == 4, "only the access records reach the detector"
    assert src.stats.parsed == 10, "all ten parsed fine — this is not a failure"
    assert src.stats.skipped_non_request == 6, "and the skip is counted, not silent"
    assert src.stats.failed == 0


def test_extension_ignores_a_query_string() -> None:
    """The bug that drove the false positive.

    Unstripped, the extension of a versioned Drupal asset is `js?v=9`, which is
    not alphanumeric, so it reads as "a file type this app does not serve" —
    for roughly every asset a CMS serves.
    """
    assert _extension("/core/misc/drupal.js?v=9.3.22") == "js"
    assert _extension("/themes/custom/style.css?tjp91n") == "css"
    assert _extension("/core/assets/once.min.js?v=1.0.1") == "js"
    assert _extension("/core/misc/drupal.js") == "js"
    # Genuinely extension-less paths stay extension-less.
    assert _extension("/search") is None
    assert _extension("/search?q=x") is None
