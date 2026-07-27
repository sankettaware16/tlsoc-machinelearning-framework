"""Training — fits servable ModelBundles with corpus hygiene."""

from .trainer import TrainingError, train_bundle

__all__ = ["train_bundle", "TrainingError"]
