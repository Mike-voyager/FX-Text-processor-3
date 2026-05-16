"""Классическая зелёная тема VT100.

Theme в стиле классических терминалов VT100/VT220 с ярко-зелёным
фосфором на чёрном фоне. Оптимальная для длительной работы.

Colors:
    bg: #000000 (чёрный фон)
    fg: #00FF00 (ярко-зелёный текст)
    accent: #00AA00 (тёмно-зелёный акцент)
    warning: #FFA500 (оранжевый)
    error: #FF0000 (красный)
    success: #00FF00 (зелёный)
    border: #003300 (тёмно-зелёный)

Font:
    family: Courier New (моноширинный)
    size: 12pt

Example:
    >>> from src.gui.themes.implementations.classic_green import CLASSIC_GREEN_THEME
    >>> CLASSIC_GREEN_THEME.get_color("bg")
    '#000000'
    >>> CLASSIC_GREEN_THEME.get_font("default")
    ('Courier New', 12, 'normal')

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gui.themes import Theme as ThemeDataclass

# Отложенный импорт для избежания циклических зависимостей
from src.gui.themes.adapter import ThemeAdapter

# =============================================================================
# CLASSIC GREEN THEME
# =============================================================================

THEME: ThemeDataclass | None = None
CLASSIC_GREEN_THEME: ThemeAdapter | None = None


def _create_theme() -> None:
    """Создание темы и адаптера при первом импорте."""
    global THEME, CLASSIC_GREEN_THEME
    from src.gui.themes import Theme as T

    THEME = T(
        bg_color="#000000",
        fg_color="#00FF00",
        accent_color="#00AA00",
        warning_color="#FFA500",
        error_color="#FF0000",
        success_color="#00FF00",
        border_color="#003300",
        font_family="Courier New",
        font_size=12,
    )
    CLASSIC_GREEN_THEME = ThemeAdapter("classic_green", THEME)


_create_theme()

# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "THEME",
    "CLASSIC_GREEN_THEME",
]
