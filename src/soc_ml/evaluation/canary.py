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

__all__ = [
    "CANARY_IP",
    "CANARY_NET_PREFIX",
    "CANARY_UA",
    "SPOOFER_CANARY_IP",
    "SPOOFER_CANARY_UA",
    "canary_events",
    "is_canary_ip",
    "spoofer_canary_events",
]

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

# UA-spoofer canary (UC-04): declares a stock desktop browser, behaves like a
# harvester — metronomic cadence, no referrers, no page assets, a tiny path
# rotation, fixed-size responses. Long enough to satisfy the spec's
# "sustained >= 30 min" gate with margin.
SPOOFER_CANARY_IP = "198.51.100.77"  # TEST-NET-2, distinct from CANARY_IP
SPOOFER_CANARY_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)
_SPOOFER_PATHS = ("/catalog/items", "/api/list", "/export/data")


def spoofer_canary_events(
    server: str,
    start: datetime,
    *,
    duration_min: int = 45,
    period_s: int = 2,
) -> list[Event]:
    """Browser-declared, bot-behaving traffic — UC-04's detection check."""
    observer = Observer(server=server, source_program="canary")
    events: list[Event] = []
    for i in range(duration_min * 60 // period_s):
        ts = start + timedelta(seconds=i * period_s)
        path = _SPOOFER_PATHS[i % len(_SPOOFER_PATHS)]
        events.append(
            Event(
                timestamp=ts,
                observer=observer,
                source_ip=SPOOFER_CANARY_IP,
                geo_country_iso="ZZ",
                http_method="GET",
                http_referrer=None,
                status_code=200,
                body_bytes=512,
                url_path=path,
                url_query=None,
                user_agent=SPOOFER_CANARY_UA,
                original=(
                    f'{SPOOFER_CANARY_IP} - - '
                    f'[{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                    f'"GET {path} HTTP/1.1" 200 512 "-" "{SPOOFER_CANARY_UA}" [canary]'
                ),
            )
        )
    return events


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
