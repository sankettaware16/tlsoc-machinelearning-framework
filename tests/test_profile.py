"""Tests for the Environment Profile — the learned tables everything reads."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from soc_ml.baseline.profile import EnvironmentProfile, _extension
from soc_ml.core.contracts import Event, Observer

T0 = datetime(2026, 7, 9, 8, 0, 0, tzinfo=timezone.utc)


def ev(path: str = "/", ua: str = "Mozilla/5.0", status: int = 200,
       server: str = "web01") -> Event:
    return Event(
        timestamp=T0,
        observer=Observer(server=server),
        source_ip="10.0.0.1",
        url_path=path,
        user_agent=ua,
        status_code=status,
    )


def build(events: list[Event]) -> EnvironmentProfile:
    profile = EnvironmentProfile()
    for event in events:
        profile.observe(event)
    return profile


# --------------------------------------------------------------------- #


def test_idf_orders_common_below_rare_below_unseen() -> None:
    profile = build([ev(path="/index.html")] * 90 + [ev(path="/rare.pdf")] * 2)

    common = profile.path_idf("web01", "/index.html")
    rare = profile.path_idf("web01", "/rare.pdf")
    unseen = profile.path_idf("web01", "/.env")

    assert common < rare < unseen
    assert unseen == 1.0, "never-seen-here must be maximum rarity"
    assert 0.0 <= common < 0.5


def test_idf_is_per_server() -> None:
    profile = build([ev(path="/a", server="web01")] * 50)
    assert profile.path_idf("web01", "/a") < 1.0
    assert profile.path_idf("web02", "/a") == 1.0, "another server never served it"


def test_empty_profile_returns_neutral_maximum_rarity() -> None:
    profile = EnvironmentProfile()
    assert profile.path_idf("web01", "/anything") == 1.0
    assert profile.ua_rarity("web01", "curl/8") == 1.0


def test_ua_rarity_orders_by_frequency() -> None:
    profile = build([ev(ua="Chrome")] * 95 + [ev(ua="weird-bot/0.1")] * 1)
    assert profile.ua_rarity("web01", "Chrome") < profile.ua_rarity("web01", "weird-bot/0.1")
    assert profile.ua_rarity("web01", "never-seen") == 1.0


def test_served_extensions_require_repeated_success() -> None:
    """One stray 200 must not whitelist an extension (min count = 3)."""
    events = (
        [ev(path=f"/f{i}.pdf", status=200) for i in range(5)]  # served
        + [ev(path="/oops.env", status=200)]  # single stray success
        + [ev(path="/x.sql", status=404)] * 10  # never succeeds
    )
    served = build(events).served_extensions("web01")
    assert "pdf" in served
    assert "env" not in served
    assert "sql" not in served


def test_save_load_roundtrip_preserves_lookups(tmp_path: Path) -> None:
    profile = build([ev(path="/common")] * 50 + [ev(path="/rare")])
    profile.set_feature_stats("web_recon", {"web.ratio_404": {"p50": 0.01, "p99": 0.4}})
    path = tmp_path / "profile.json"
    profile.save(path)

    loaded = EnvironmentProfile.load(path)
    assert loaded.path_idf("web01", "/common") == profile.path_idf("web01", "/common")
    assert loaded.path_idf("web01", "/unseen") == 1.0
    assert loaded.population("web_recon", "web.ratio_404")["p99"] == 0.4
    assert loaded.dominant_server() == "web01"


def test_extension_helper_edges() -> None:
    assert _extension("/a/b/report.pdf") == "pdf"
    assert _extension("/archive.tar.gz") == "gz"
    assert _extension("/no-extension") is None
    assert _extension("/.hidden") is None
    assert _extension("/x.veryLongExtension123") is None, "hashes are not extensions"
    assert _extension("/UPPER.PDF") == "pdf"
