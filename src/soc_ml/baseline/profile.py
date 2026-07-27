"""The Environment Profile — the deployment's learned self-portrait (FR-60).

Everything a detector compares data against comes from here, never from config
(FR-62). For the web_recon slice the profile carries, per server:

* **path document frequency** → IDF ("how rare is this path *here*?")
* **UA frequency** → UA rarity ("how unusual is this client string *here*?")
* **served extensions** → the set of file extensions this app actually serves
  with success, so requests for ``.env`` / ``.sql`` / ``.bak`` on an app that
  serves none stand out (``web.unknown_ext_ratio``)
* **feature stats** (median / p99 per feature) → population context for
  explanations ("value 47, this server's p50 is 1, p99 is 3") and the
  population-median deltas the spec's features call for

Built by a streaming pass over training events — bounded memory via capped
tables (the cap trims the *rarest* tail, which for IDF purposes collapses into
"max rarity" anyway). Persisted as JSON so a profile is a versionable,
replayable artifact (NFR-10).
"""

from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path

from soc_ml.core.contracts import Event

__all__ = ["EnvironmentProfile"]

# Table caps keep a profile bounded on unbounded path spaces (cache busters,
# per-user URLs). Overflowing keys are dropped from tracking; an unseen path at
# lookup time simply gets maximum rarity — which is exactly what "never seen
# here" should mean.
_MAX_PATHS_PER_SERVER = 500_000
_MAX_UAS_PER_SERVER = 100_000

# Extensions are "served" once seen this many times with a 2xx during training —
# one stray success (a misconfigured 200 on an error page) must not whitelist
# an extension forever.
_SERVED_MIN_COUNT = 3


class EnvironmentProfile:
    """Learned per-server tables + population feature statistics."""

    SCHEMA_VERSION = 1

    def __init__(self) -> None:
        # server -> Counter(path -> occurrences)
        self._path_df: dict[str, Counter] = {}
        self._path_total: dict[str, int] = {}
        # server -> Counter(ua -> occurrences)
        self._ua_freq: dict[str, Counter] = {}
        self._ua_total: dict[str, int] = {}
        # server -> Counter(ext -> 2xx occurrences)
        self._ext_2xx: dict[str, Counter] = {}
        # usecase -> feature -> {"p50": .., "p99": ..}
        self.feature_stats: dict[str, dict[str, dict[str, float]]] = {}
        self.meta: dict[str, object] = {"events_observed": 0}

    # ------------------------------------------------------------------ #
    # Building (streaming, one event at a time)
    # ------------------------------------------------------------------ #

    def observe(self, event: Event) -> None:
        server = event.observer.server or "_"
        self.meta["events_observed"] = int(self.meta.get("events_observed", 0)) + 1

        if event.url_path:
            table = self._path_df.setdefault(server, Counter())
            if event.url_path in table or len(table) < _MAX_PATHS_PER_SERVER:
                table[event.url_path] += 1
            self._path_total[server] = self._path_total.get(server, 0) + 1

            ext = _extension(event.url_path)
            if ext and event.status_code and 200 <= event.status_code < 300:
                self._ext_2xx.setdefault(server, Counter())[ext] += 1

        if event.user_agent:
            table = self._ua_freq.setdefault(server, Counter())
            if event.user_agent in table or len(table) < _MAX_UAS_PER_SERVER:
                table[event.user_agent] += 1
            self._ua_total[server] = self._ua_total.get(server, 0) + 1

    # ------------------------------------------------------------------ #
    # Lookups (what features and explanations consume)
    # ------------------------------------------------------------------ #

    def path_idf(self, server: str, path: str | None) -> float:
        """IDF of a path on this server, normalized to [0, 1].

        1.0 = never seen here (maximum rarity); ~0 = the most common paths.
        ``log((N+1)/(df+1)) / log(N+1)`` — the +1s make unseen paths finite and
        an empty profile return neutral 1.0 rather than dividing by zero.
        """
        if not path:
            return 0.0
        total = self._path_total.get(server, 0)
        if total == 0:
            return 1.0
        df = self._path_df.get(server, Counter()).get(path, 0)
        return math.log((total + 1) / (df + 1)) / math.log(total + 1)

    def ua_rarity(self, server: str, ua: str | None) -> float:
        """Rarity of a UA string on this server, normalized to [0, 1]."""
        if not ua:
            return 1.0
        total = self._ua_total.get(server, 0)
        if total == 0:
            return 1.0
        count = self._ua_freq.get(server, Counter()).get(ua, 0)
        return math.log((total + 1) / (count + 1)) / math.log(total + 1)

    def served_extensions(self, server: str) -> frozenset[str]:
        """Extensions this server actually serves (>= _SERVED_MIN_COUNT 2xx)."""
        table = self._ext_2xx.get(server, Counter())
        return frozenset(e for e, c in table.items() if c >= _SERVED_MIN_COUNT)

    def population(self, usecase: str, feature: str) -> dict[str, float]:
        """Population stats for one feature — p50/p99 context for explanations."""
        return self.feature_stats.get(usecase, {}).get(feature, {})

    def set_feature_stats(
        self, usecase: str, stats: dict[str, dict[str, float]]
    ) -> None:
        """Store per-feature population stats computed by the trainer."""
        self.feature_stats[usecase] = stats

    def servers(self) -> list[str]:
        return sorted(set(self._path_total) | set(self._ua_total))

    def dominant_server(self) -> str | None:
        """The server with the most observed traffic — richest baseline."""
        if not self._path_total:
            return None
        return max(self._path_total, key=lambda s: self._path_total[s])

    # ------------------------------------------------------------------ #
    # Persistence — a profile is an artifact, not process state
    # ------------------------------------------------------------------ #

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "schema_version": self.SCHEMA_VERSION,
            "meta": self.meta,
            "path_df": {s: dict(c) for s, c in self._path_df.items()},
            "path_total": self._path_total,
            "ua_freq": {s: dict(c) for s, c in self._ua_freq.items()},
            "ua_total": self._ua_total,
            "ext_2xx": {s: dict(c) for s, c in self._ext_2xx.items()},
            "feature_stats": self.feature_stats,
        }
        path.write_text(json.dumps(doc), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "EnvironmentProfile":
        doc = json.loads(path.read_text(encoding="utf-8"))
        profile = cls()
        profile.meta = doc.get("meta", {})
        profile._path_df = {s: Counter(c) for s, c in doc.get("path_df", {}).items()}
        profile._path_total = {s: int(v) for s, v in doc.get("path_total", {}).items()}
        profile._ua_freq = {s: Counter(c) for s, c in doc.get("ua_freq", {}).items()}
        profile._ua_total = {s: int(v) for s, v in doc.get("ua_total", {}).items()}
        profile._ext_2xx = {s: Counter(c) for s, c in doc.get("ext_2xx", {}).items()}
        profile.feature_stats = doc.get("feature_stats", {})
        return profile


def _extension(path: str) -> str | None:
    """File extension of a URL path, lowercased, or None.

    Only the last segment counts, and query strings never reach here (they are
    a separate field in the contract).
    """
    last = path.rsplit("/", 1)[-1]
    if "." not in last or last.startswith("."):
        return None
    ext = last.rsplit(".", 1)[-1].lower()
    # An "extension" of 10+ chars is almost always a version tag or a hash,
    # not a file type.
    return ext if 1 <= len(ext) <= 9 and ext.isalnum() else None
