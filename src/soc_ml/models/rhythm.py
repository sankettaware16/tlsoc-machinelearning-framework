"""Rhythm Isolation Forest — bot_detection's unsupervised spoofing component (D-036).

The GBM learns "behaves like something that admits to being a bot" from the
user-agent label, and a headless browser that fetches page assets and sends
referrers is outside what that label can teach: on elkcc a retrain scored the
live botnet P(bot) 0.22 and fired on none of its 756 windows (D-032). Its tells
were temporal. This model asks a different, label-free question over the
address's rhythm and its browser-likeness: how unusual is this window *among
browser-declared windows* (the use case fits and calibrates it on those)?

It reads only its own feature set, so no label and no user-agent field can
leak in.
"""

from __future__ import annotations

from collections.abc import Iterable

from soc_ml.models.isolation_forest import IsolationForestModel

__all__ = ["RhythmIsolationForest", "RHYTHM_INPUTS"]

RHYTHM_INPUTS: tuple[str, ...] = (
    "bot.addr_hour_entropy",     # around the clock vs waking hours
    "bot.addr_active_ratio",     # present in every 5-minute bucket of the hour
    "bot.addr_rate_cv",          # metronomic request rate across buckets
    "timing.interarrival_cv",
    "timing.fano_factor",
    "bot.asset_fetch_ratio",     # assets only, no page
    "bot.path_repeat_ratio",
    "web.referrer_absent_ratio",
)


class RhythmIsolationForest(IsolationForestModel):
    name = "rhythm_iforest"
    description = ("Isolation Forest over address rhythm among browser-declared "
                   "windows — the spoofing alert's label-free component")

    def fit(self, X: Iterable[dict[str, float]]) -> None:
        super().fit({f: row.get(f, 0.0) for f in RHYTHM_INPUTS} for row in X)
