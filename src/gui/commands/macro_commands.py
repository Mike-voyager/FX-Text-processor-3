"""Backward-compatible shim for src.gui.commands.macro_commands.

Deprecated: use src.gui.core.commands.macro_commands instead.
"""

import warnings

from src.gui.core.commands.macro_commands import *  # noqa: F401, F403

warnings.warn(
    "src.gui.commands.macro_commands is deprecated; use src.gui.core.commands.macro_commands",
    DeprecationWarning,
    stacklevel=2,
)
