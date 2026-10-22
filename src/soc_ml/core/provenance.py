"""Which code produced an artifact (FR-53).

A bundle is reproducible only if both its feature code (``feature_code_sha256``)
and the code commit are known; an approval report is only meaningful next to
the commit that computed it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

__all__ = ["code_commit"]

_ROOT = Path(__file__).resolve().parents[3]


def code_commit() -> dict[str, object] | None:
    """``{"commit": sha, "dirty": bool}`` for the checkout this runs from, or None."""
    try:
        sha = subprocess.run(["git", "-C", str(_ROOT), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=5, check=True)
        status = subprocess.run(
            ["git", "-C", str(_ROOT), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, timeout=5, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return {"commit": sha.stdout.strip(), "dirty": bool(status.stdout.strip())}
