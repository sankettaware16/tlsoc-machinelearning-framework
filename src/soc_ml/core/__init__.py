"""Core contracts, configuration, and the plugin system.

Every other module depends on this one; this one depends on none of them. If you
find yourself importing a sibling module from here, the dependency is pointing
the wrong way.
"""

from .config import Config, ConfigError, load_config
from .contracts import (
    Alert,
    EntityKey,
    Event,
    FeatureVector,
    Insight,
    Observer,
    Profile,
    RunMode,
    Score,
    Session,
    Severity,
    Verdict,
)
from .plugins import (
    FeatureGroup,
    Model,
    Plugin,
    PluginRegistry,
    Sink,
    Source,
    StateStore,
    UseCase,
    registry,
)

__all__ = [
    # contracts
    "Event",
    "Observer",
    "EntityKey",
    "Session",
    "FeatureVector",
    "Score",
    "Alert",
    "Insight",
    "Severity",
    "Verdict",
    "RunMode",
    "Profile",
    # config
    "Config",
    "ConfigError",
    "load_config",
    # plugins
    "Plugin",
    "Source",
    "FeatureGroup",
    "Model",
    "UseCase",
    "StateStore",
    "Sink",
    "PluginRegistry",
    "registry",
]
