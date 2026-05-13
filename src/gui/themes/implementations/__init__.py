"""Реализации встроенных тем для FX Text Processor 3.

Модуль содержит набор встроенных терминальных и доступных тем,
представленных через адаптеры ThemeProtocol.

Example:
    >>> from src.gui.themes.implementations import CLASSIC_GREEN_THEME
    >>> CLASSIC_GREEN_THEME.get_color("bg")
    '#000000'

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from src.gui.themes.implementations.amber import (
    AMBER_THEME,
)
from src.gui.themes.implementations.amber import (
    THEME as AMBER_THEME_RAW,
)
from src.gui.themes.implementations.classic_green import (
    CLASSIC_GREEN_THEME,
)
from src.gui.themes.implementations.classic_green import (
    THEME as CLASSIC_GREEN_THEME_RAW,
)
from src.gui.themes.implementations.high_contrast import (
    HIGH_CONTRAST_THEME,
)
from src.gui.themes.implementations.high_contrast import (
    THEME as HIGH_CONTRAST_THEME_RAW,
)
from src.gui.themes.implementations.phosphor_white import (
    PHOSPHOR_WHITE_THEME,
)
from src.gui.themes.implementations.phosphor_white import (
    THEME as PHOSPHOR_WHITE_THEME_RAW,
)
from src.gui.themes.implementations.retro_green import (
    RETRO_GREEN_THEME,
)
from src.gui.themes.implementations.retro_green import (
    THEME as RETRO_GREEN_THEME_RAW,
)

__all__ = [
    "AMBER_THEME",
    "AMBER_THEME_RAW",
    "CLASSIC_GREEN_THEME",
    "CLASSIC_GREEN_THEME_RAW",
    "HIGH_CONTRAST_THEME",
    "HIGH_CONTRAST_THEME_RAW",
    "PHOSPHOR_WHITE_THEME",
    "PHOSPHOR_WHITE_THEME_RAW",
    "RETRO_GREEN_THEME",
    "RETRO_GREEN_THEME_RAW",
]
