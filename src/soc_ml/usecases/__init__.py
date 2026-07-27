"""Detection use cases. Naming per docs/NAMING.md: module = slug.

Importing this package registers every built-in use case with the registry.
"""

from .web_recon import WebRecon

__all__ = ["WebRecon"]
