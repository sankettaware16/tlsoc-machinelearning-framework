"""Model wrappers — uniform fit/score/save/load over algorithm families.

Importing this package registers the built-in models with the plugin registry.
"""

from .isolation_forest import IsolationForestModel
from .lof import LOFNoveltyModel

__all__ = ["IsolationForestModel", "LOFNoveltyModel"]
