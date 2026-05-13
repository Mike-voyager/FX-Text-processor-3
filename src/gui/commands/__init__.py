"""Backward-compatible shim for src.gui.commands.

Deprecated: use src.gui.core.commands instead.
"""

import warnings

from src.gui.core.commands import *  # noqa: F401, F403
from src.gui.core.commands import __all__  # noqa: F401

warnings.warn(
    "src.gui.commands is deprecated; use src.gui.core.commands",
    DeprecationWarning,
    stacklevel=2,
)
