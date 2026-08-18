"""Operator dashboard — a read-mostly view of a running deployment.

Deliberately a **separate process** that reads the artifacts the runtime
already writes (``data/state/*.json``, the per-slug NDJSON logs, the model
registry). It never imports the runtime, never holds a lock, and cannot slow
detection down: the worst a misbehaving dashboard can do is read stale files.

The one exception is model promotion, which writes registry pointers — that is
the human gate FR-55 requires, given a button instead of a shell.
"""

from soc_ml.web.server import serve
from soc_ml.web.state import DashboardState

__all__ = ["DashboardState", "serve"]
