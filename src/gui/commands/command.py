"""Backward-compatible shim for src.gui.commands.command.

Deprecated: use src.gui.core.commands.command instead.
"""

import warnings

from src.gui.core.commands.command import *  # noqa: F401, F403

warnings.warn(
    "src.gui.commands.command is deprecated; use src.gui.core.commands.command",
    DeprecationWarning,
    stacklevel=2,
)
