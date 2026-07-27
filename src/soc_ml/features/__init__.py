"""Feature platform — derived numbers, computed once, shared by use cases."""

from .bot_features import BOT_DETECTION_FEATURES
from .window_features import WEB_RECON_FEATURES, WindowFeatureBuilder, WindowResult

__all__ = [
    "WindowFeatureBuilder",
    "WindowResult",
    "WEB_RECON_FEATURES",
    "BOT_DETECTION_FEATURES",
]
