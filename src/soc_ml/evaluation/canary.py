"""Deterministic detection canary — a tiny, known-bad enumeration burst.

Injected into the **scoring stream only** (never training — FR-58) so every
backtest ends with a built-in sanity check: "did the pipeline detect the one
attack we know is in there?" A backtest that scores quietly green while unable
to see a textbook wordlist scan is worse than no backtest.

Everything is deterministic (fixed IP, fixed path patterns, arithmetic jitter)
so replay produces identical results (NFR-10). The IP is from TEST-NET-2, which
cannot collide with real traffic.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from soc_ml.core.contracts import Event, Observer

__all__ = ["CANARY_IP", "CANARY_NET_PREFIX", "CANARY_UA", "canary_events", "is_canary_ip"]

CANARY_IP = "198.51.100.99"  # RFC 5737 TEST-NET-2 — never a real client
#: Every use case's canary must source from this /24 (TEST-NET-2), so canary
#: windows are recognizable regardless of which use case injected them.
CANARY_NET_PREFIX = "198.51.100."
CANARY_UA = "Mozilla/5.0 (compatible; SOC-ML-Canary/1.0)"


def is_canary_ip(ip: str | None) -> bool:
    """True when the address belongs to the reserved canary net (TEST-NET-2)."""
    return bool(ip) and ip.startswith(CANARY_NET_PREFIX)

_PATH_PATTERNS = (
    "/backup/site_{i:03d}.sql",
    "/old/config_{i:03d}.env",
    "/wp-admin/setup_{i:03d}.bak",
    "/admin/panel_{i:03d}.zip",
    "/.git/objects/{i:03d}",
    "/test/debug_{i:03d}.tar",
)


def canary_events(
    server: str,
    start: datetime,
    *,
    count: int = 150,
    org: str | None = None,
    env: str | None = None,
) -> list[Event]:
    """A 5-minute enumeration burst: rare paths, unserved extensions, ~90% 404."""
    observer = Observer(org=org, env=env, server=server, source_program="canary")
    events: list[Event] = []
    for i in range(count):
        # ~2s cadence with small arithmetic jitter — brisk but not volumetric;
        # the detection must come from shape, not from rate.
        ts = start + timedelta(seconds=i * 2 + (i * 7) % 3)
        path = _PATH_PATTERNS[i % len(_PATH_PATTERNS)].format(i=i)
        status = 404 if i % 10 else 403  # one non-404 per ten keeps it honest
        events.append(
            Event(
                timestamp=ts,
                observer=observer,
                source_ip=CANARY_IP,
                geo_country_iso="ZZ",  # external-looking; ZZ = unassigned
                http_method="GET",
                http_referrer=None,
                status_code=status,
                body_bytes=196,
                url_path=path,
                url_query=None,
                user_agent=CANARY_UA,
                original=(
                    f'{CANARY_IP} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                    f'"GET {path} HTTP/1.1" {status} 196 "-" "{CANARY_UA}" [canary]'
                ),
            )
        )
    return events
