"""Янтарная тема CRT монитора.

Theme в стиле янтарных мониторов 1970-80-х годов.
Тёплый янтарный оттенок рекомендуется для работы в
условиях низкой освещённости (ночная смена).

Colors:
    bg: #1A1A1A (тёмно-серый фон)
    fg: #FFB000 (янтарный текст)
    accent: #FF8C00 (тёмно-янтарный акцент)
    warning: #FFD700 (золотой)
    error: #FF4500 (оранжево-красный)
    success: #FFA500 (оранжевый)
    border: #4D3300 (коричневая граница)

Font:
    family: Courier New (моноширинный)
    size: 12pt

Example:
    >>> from src.gui.themes.implementations.amber import AMBER_THEME
    >>> AMBER_THEME.get_color("bg")
    '#1A1A1A'

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gui.themes import Theme as ThemeDataclass

from src.gui.themes.adapter import ThemeAdapter

# =============================================================================
# AMBER THEME
# =============================================================================

THEME: ThemeDataclass | None = None
AMBER_THEME: ThemeAdapter | None = None


def _create_theme() -> None:
    """Создание темы и адаптера при первом импорте."""
    global THEME, AMBER_THEME
    from src.gui.themes import Theme as T

    THEME = T(
        bg_color="#1A1A1A",
        fg_color="#FFB000",
        accent_color="#FF8C00",
        warning_color="#FFD700",
        error_color="#FF4500",
        success_color="#FFA500",
        border_color="#4D3300",
        font_family="Courier New",
        font_size=12,
    )
    AMBER_THEME = ThemeAdapter("amber", THEME)


_create_theme()

# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "THEME",
    "AMBER_THEME",
]
