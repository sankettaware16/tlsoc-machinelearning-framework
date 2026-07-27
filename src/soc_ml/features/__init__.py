"""Feature platform — derived numbers, computed once, shared by use cases."""

from .window_features import WEB_RECON_FEATURES, WindowFeatureBuilder, WindowResult

__all__ = ["WindowFeatureBuilder", "WindowResult", "WEB_RECON_FEATURES"]
