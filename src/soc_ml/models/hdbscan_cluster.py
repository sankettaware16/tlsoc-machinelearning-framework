"""Known-crawler clustering (UC-04) — undeclared automation by association.

HDBSCAN groups standardized behavior vectors by density, with no distance
threshold to configure (the spec chose it over DBSCAN for exactly that
reason). Clusters where declared bots are the majority become **known-crawler
clusters**; scoring a new vector returns its membership strength in one of
them, so a client that never says "bot" but moves with the bot pack still
carries the association — the ``crawler.is_known`` input.

This model rides the optional ``cluster`` extra. When ``hdbscan`` is not
installed, :meth:`available` is False and the shared factory helper skips the
model with a warning — bot_detection degrades to GBM+GMM, documented, never a
crash (NFR-08). It contributes association evidence, not the alert gate, so
the degradation costs recall on undeclared crawlers, nothing else.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable
from pathlib import Path

from soc_ml.core.plugins import Model
from soc_ml.models.scaling import FeatureScaler

__all__ = ["HDBSCANClusterModel"]


class HDBSCANClusterModel(Model):
    name = "hdbscan_cluster"
    description = "HDBSCAN known-crawler clustering (optional 'cluster' extra, UC-04)"
    incremental = False

    LABEL_KEY = "bot.declared_bot"
    EXCLUDED_PREFIXES = ("ua.",)
    MIN_CLUSTER_SIZE = 10
    #: A cluster is "known-crawler" when declared bots are its majority.
    BOT_MAJORITY = 0.5

    def __init__(self) -> None:
        self._model = None
        self._scaler: FeatureScaler | None = None
        self._bot_clusters: set[int] = set()

    @classmethod
    def available(cls) -> bool:
        return importlib.util.find_spec("hdbscan") is not None

    # ------------------------------------------------------------------ #

    def _behavior(self, rows: list[dict[str, float]]) -> list[dict[str, float]]:
        return [
            {
                f: v
                for f, v in row.items()
                if f != self.LABEL_KEY and not f.startswith(self.EXCLUDED_PREFIXES)
            }
            for row in rows
        ]

    def fit(self, X: Iterable[dict[str, float]]) -> None:
        import hdbscan
        import numpy as np

        rows = list(X)
        if not rows:
            raise ValueError("hdbscan_cluster: empty training corpus")
        labels = np.array([row.get(self.LABEL_KEY, 0.0) >= 0.5 for row in rows])
        self._scaler = FeatureScaler().fit(self._behavior(rows))
        matrix = self._scaler.transform(self._behavior(rows))

        self._model = hdbscan.HDBSCAN(
            min_cluster_size=self.MIN_CLUSTER_SIZE,
            prediction_data=True,  # required for approximate_predict on new points
        ).fit(matrix)

        self._bot_clusters = set()
        for cluster_id in set(self._model.labels_):
            if cluster_id < 0:
                continue  # noise is not a cluster
            members = self._model.labels_ == cluster_id
            if labels[members].mean() > self.BOT_MAJORITY:
                self._bot_clusters.add(int(cluster_id))

    def score(self, x: dict[str, float]) -> float:
        return self.score_batch([x])[0]

    def score_batch(self, rows: list[dict[str, float]]) -> list[float]:
        from hdbscan import approximate_predict

        if self._model is None:
            raise RuntimeError("hdbscan_cluster: score before fit()/load()")
        if not rows:
            return []
        matrix = self._scaler.transform(self._behavior(rows))
        cluster_ids, strengths = approximate_predict(self._model, matrix)
        return [
            float(strength) if int(cid) in self._bot_clusters else 0.0
            for cid, strength in zip(cluster_ids, strengths)
        ]

    # ------------------------------------------------------------------ #

    def save(self, path: Path) -> None:
        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "scaler": self._scaler.to_dict(),
                "bot_clusters": sorted(self._bot_clusters),
            },
            path,
        )

    def load(self, path: Path) -> None:
        import joblib

        blob = joblib.load(path)
        self._model = blob["model"]
        self._scaler = FeatureScaler.from_dict(blob["scaler"])
        self._bot_clusters = set(blob["bot_clusters"])
