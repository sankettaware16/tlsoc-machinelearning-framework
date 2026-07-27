"""Model wrappers — uniform fit/score/save/load over algorithm families.

Importing this package registers the built-in models with the plugin registry.
Optional-dependency models (hdbscan) import their backend lazily, so
registration is always safe; ``Model.available()`` says whether they can run.
"""

from .gbm import GBMBotClassifier
from .gmm import GMMModel
from .hdbscan_cluster import HDBSCANClusterModel
from .isolation_forest import IsolationForestModel
from .lof import LOFNoveltyModel

__all__ = [
    "GBMBotClassifier",
    "GMMModel",
    "HDBSCANClusterModel",
    "IsolationForestModel",
    "LOFNoveltyModel",
]
