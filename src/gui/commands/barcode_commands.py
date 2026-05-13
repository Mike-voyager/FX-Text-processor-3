"""Backward-compatible shim for src.gui.commands.barcode_commands.

Deprecated: use src.gui.core.commands.barcode_commands instead.
"""

import warnings

from src.gui.core.commands.barcode_commands import *  # noqa: F401, F403

warnings.warn(
    "src.gui.commands.barcode_commands is deprecated; use src.gui.core.commands.barcode_commands",
    DeprecationWarning,
    stacklevel=2,
)
