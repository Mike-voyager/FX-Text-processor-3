"""Backward-compatible shim for src.gui.commands.text_commands.

Deprecated: use src.gui.core.commands.text_commands instead.
"""

import warnings

from src.gui.core.commands.text_commands import *  # noqa: F401, F403

warnings.warn(
    "src.gui.commands.text_commands is deprecated; use src.gui.core.commands.text_commands",
    DeprecationWarning,
    stacklevel=2,
)
