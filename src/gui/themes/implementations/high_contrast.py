"""Высококонтрастная доступная тема.

Theme с максимальным контрастом для пользователей с
нарушениями зрения. Соответствует стандартам WCAG 2.1
уровня AAA для контрастности.

Colors:
    bg: #000000 (чёрный фон)
    fg: #FFFFFF (белый текст)
    accent: #FFFF00 (жёлтый акцент - макс. контраст)
    warning: #FFA500 (оранжевый)
    error: #FF0000 (яркий красный)
    success: #00FF00 (яркий зелёный)
    border: #FFFFFF (белая граница)

Font:
    family: Courier New (моноширинный)
    size: 14pt (увеличенный для читаемости)

Accessibility:
    - WCAG 2.1 AAA contrast ratio: 21:1 (чёрный/белый)
    - Рекомендуется для пользователей с дальтонизмом
    - Увеличенный размер шрифта

Example:
    >>> from src.gui.themes.implementations.high_contrast import HIGH_CONTRAST_THEME
    >>> HIGH_CONTRAST_THEME.get_color("bg")
    '#000000'

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gui.themes import Theme as ThemeDataclass

from src.gui.themes.adapter import ThemeAdapter

# =============================================================================
# HIGH CONTRAST THEME
# =============================================================================

THEME: ThemeDataclass | None = None
HIGH_CONTRAST_THEME: ThemeAdapter | None = None


def _create_theme() -> None:
    """Создание темы и адаптера при первом импорте."""
    global THEME, HIGH_CONTRAST_THEME
    from src.gui.themes import Theme as T

    THEME = T(
        bg_color="#000000",
        fg_color="#FFFFFF",
        accent_color="#FFFF00",
        warning_color="#FFA500",
        error_color="#FF0000",
        success_color="#00FF00",
        border_color="#FFFFFF",
        font_family="Courier New",
        font_size=14,
    )
    HIGH_CONTRAST_THEME = ThemeAdapter("high_contrast", THEME)


_create_theme()

# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "THEME",
    "HIGH_CONTRAST_THEME",
]
