"""Ретро зелёный фосфор тема.

Тема в стиле старых мониторов с зелёным фосфором.
Более приглушённые цвета чем classic_green, имитирует
старение фосфорного покрытия и стекла монитора.

Colors:
    bg: #0D1B0D (тёмно-зелёный фон)
    fg: #33FF33 (приглушённый зелёный)
    accent: #66FF66 (светло-зелёный акцент)
    warning: #FFB366 (теплый оранжевый)
    error: #FF6666 (мягкий красный)
    success: #66FF66 (зелёный)
    border: #1A331A (граница)

Font:
    family: Courier New (моноширинный)
    size: 12pt

Example:
    >>> from src.gui.themes.implementations.retro_green import RETRO_GREEN_THEME
    >>> RETRO_GREEN_THEME.get_color("bg")
    '#0D1B0D'

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gui.themes import Theme as ThemeDataclass

from src.gui.themes.adapter import ThemeAdapter

# =============================================================================
# RETRO GREEN THEME
# =============================================================================

THEME: ThemeDataclass | None = None
RETRO_GREEN_THEME: ThemeAdapter | None = None


def _create_theme() -> None:
    """Создание темы и адаптера при первом импорте."""
    global THEME, RETRO_GREEN_THEME
    from src.gui.themes import Theme as T

    THEME = T(
        bg_color="#0D1B0D",
        fg_color="#33FF33",
        accent_color="#66FF66",
        warning_color="#FFB366",
        error_color="#FF6666",
        success_color="#66FF66",
        border_color="#1A331A",
        font_family="Courier New",
        font_size=12,
    )
    RETRO_GREEN_THEME = ThemeAdapter("retro_green", THEME)


_create_theme()

# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "THEME",
    "RETRO_GREEN_THEME",
]
