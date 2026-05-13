"""Константы layout для GUI.

Security: Все размеры вынесены в константы для предсказуемости UI.
"""

from __future__ import annotations

from typing import Final

# Window constraints
MIN_WINDOW_WIDTH: Final[int] = 1024
MIN_WINDOW_HEIGHT: Final[int] = 768
DEFAULT_WINDOW_WIDTH: Final[int] = 1280
DEFAULT_WINDOW_HEIGHT: Final[int] = 800

# Panel sizes
SIDEBAR_WIDTH: Final[int] = 250
SIDEBAR_COLLAPSED_WIDTH: Final[int] = 40
STATUSBAR_HEIGHT: Final[int] = 25
TABBAR_HEIGHT: Final[int] = 30
TOOLBAR_HEIGHT: Final[int] = 35

# Layout ratios
PANEL_RATIO_DEFAULT: Final[float] = 0.2  # 20% sidebar
PANEL_RATIO_MIN: Final[float] = 0.15
PANEL_RATIO_MAX: Final[float] = 0.4

# Canvas sizes
ESCP_COLS: Final[int] = 80
ESCP_ROWS: Final[int] = 66
ESCP_DOTS_PER_COL: Final[int] = 60
ESCP_DOTS_PER_ROW: Final[int] = 60

# Padding and margins
PADDING_SMALL: Final[int] = 2
PADDING_NORMAL: Final[int] = 5
PADDING_LARGE: Final[int] = 10

# Sash configuration
SASH_WIDTH: Final[int] = 4
SASH_RELIEF: Final[str] = "flat"

# Animation
COLLAPSE_ANIMATION_MS: Final[int] = 150
