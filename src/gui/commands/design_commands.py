"""Backward-compatible shim for src.gui.commands.design_commands.

Deprecated: use src.gui.core.commands.design_commands instead.
"""

import warnings

from src.gui.core.commands.design_commands import *  # noqa: F401, F403

warnings.warn(
    "src.gui.commands.design_commands is deprecated; use src.gui.core.commands.design_commands",
    DeprecationWarning,
    stacklevel=2,
)
