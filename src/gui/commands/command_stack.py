"""Backward-compatible shim for src.gui.commands.command_stack.

Deprecated: use src.gui.core.commands.command_stack instead.
"""

import warnings

from src.gui.core.commands.command_stack import *  # noqa: F401, F403

warnings.warn(
    "src.gui.commands.command_stack is deprecated; use src.gui.core.commands.command_stack",
    DeprecationWarning,
    stacklevel=2,
)
