"""Белый фосфор тема (P4 phosphor).

Theme в стиле белых фосфорных мониторов P4.
Нейтральная белая цветовая температура для точной
цветопередачи и работы с изображениями.

Colors:
    bg: #0A0A0A (почти чёрный)
    fg: #E8E8E8 (светло-серый)
    accent: #FFFFFF (белый)
    warning: #FFD700 (золотой)
    error: #FF4444 (красный)
    success: #44FF44 (зелёный)
    border: #333333 (серая граница)

Font:
    family: Courier New (моноширинный)
    size: 12pt

Example:
    >>> from src.gui.themes.implementations.phosphor_white import PHOSPHOR_WHITE_THEME
    >>> PHOSPHOR_WHITE_THEME.get_color("bg")
    '#0A0A0A'

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gui.themes import Theme as ThemeDataclass

from src.gui.themes.adapter import ThemeAdapter

# =============================================================================
# PHOSPHOR WHITE THEME
# =============================================================================

THEME: ThemeDataclass | None = None
PHOSPHOR_WHITE_THEME: ThemeAdapter | None = None


def _create_theme() -> None:
    """Создание темы и адаптера при первом импорте."""
    global THEME, PHOSPHOR_WHITE_THEME
    from src.gui.themes import Theme as T

    THEME = T(
        bg_color="#0A0A0A",
        fg_color="#E8E8E8",
        accent_color="#FFFFFF",
        warning_color="#FFD700",
        error_color="#FF4444",
        success_color="#44FF44",
        border_color="#333333",
        font_family="Courier New",
        font_size=12,
    )
    PHOSPHOR_WHITE_THEME = ThemeAdapter("phosphor_white", THEME)


_create_theme()

# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "THEME",
    "PHOSPHOR_WHITE_THEME",
]
