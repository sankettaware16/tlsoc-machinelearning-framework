"""Event sources — where events come from.

Importing this package registers the built-in sources with the plugin registry.
"""

from .file import FileSource, IngestStats

__all__ = ["FileSource", "IngestStats"]
