"""Alert/Insight schema + Sink adapters.

Importing this package registers the built-in sinks with the plugin registry.
"""

from .file_sink import FileSink

__all__ = ["FileSink"]
