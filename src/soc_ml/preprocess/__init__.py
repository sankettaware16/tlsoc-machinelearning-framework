"""Preprocessing — validation, derived fields, and sessionization.

Sits between raw ingestion and the feature platform. Everything here is
deterministic and judgement-free: it reshapes events, it never decides whether
anything is suspicious.
"""

from .sessionize import Sessionizer, SessionizerStats, session_features

__all__ = ["Sessionizer", "SessionizerStats", "session_features"]
