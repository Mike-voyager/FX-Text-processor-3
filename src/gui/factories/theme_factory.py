"""Фабрика theme-aware настроек GUI.

Предоставляет stateless функции и dataclass для получения цветов темы,
применения темы к виджетам и создания кнопок с вариантами стилей.

Example:
    >>> from src.gui.factories import get_theme_colors, create_themed_button
    >>> colors = get_theme_colors("classic_green")
    >>> btn = create_themed_button(parent, text="Start", variant="primary")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from typing import Any

from src.gui.themes import ThemeManager

__all__ = [
    "ThemeColors",
    "get_theme_colors",
    "apply_theme_to_widget",
    "create_themed_button",
]


@dataclass(frozen=True)
class ThemeColors:
    """Набор базовых цветов темы.

    Attributes:
        bg: Color фона.
        fg: Color текста.
        accent: Акцентный цвет.
        error: Color ошибки.
        warning: Color предупреждения.
        success: Color успеха.
    """

    bg: str
    fg: str
    accent: str
    error: str
    warning: str
    success: str


_VARIANT_MAP: dict[str, dict[str, str]] = {
    "primary": {"bg": "accent", "fg": "#FFFFFF"},
    "secondary": {"bg": "#555555", "fg": "#FFFFFF"},
    "danger": {"bg": "#CC0000", "fg": "#FFFFFF"},
    "success": {"bg": "#00AA00", "fg": "#FFFFFF"},
    "ghost": {"bg": "", "fg": ""},  # transparent / inherit
}


def get_theme_colors(theme_name: str = "default") -> ThemeColors:
    """Возвращает цветовую схему темы.

    Args:
        theme_name: Имя темы. Если "default", используется текущая тема.

    Returns:
        ThemeColors с цветами.

    Raises:
        ThemeNotFoundError: Если тема не найдена.
    """
    manager = ThemeManager()
    if theme_name == "default":
        theme = manager.get_current_theme()
    else:
        theme = manager.get_theme(theme_name)

    return ThemeColors(
        bg=theme.bg_color,
        fg=theme.fg_color,
        accent=theme.accent_color,
        error=theme.error_color,
        warning=theme.warning_color,
        success=theme.success_color,
    )


def apply_theme_to_widget(
    widget: tk.Widget,
    colors: ThemeColors,
) -> None:
    """Применяет цвета темы к виджету.

    Настраивает bg, fg и шрифт (если доступно).

    Args:
        widget: Целевой Tkinter виджет.
        colors: Colorовая схема.
    """
    if not hasattr(widget, "configure"):
        return

    try:
        widget.configure(bg=colors.bg)  # type: ignore[call-arg]
    except tk.TclError:
        pass

    try:
        widget.configure(fg=colors.fg)  # type: ignore[call-arg]
    except tk.TclError:
        pass

    # Шрифт берём из текущей темы, если configure поддерживает
    try:
        manager = ThemeManager()
        theme = manager.get_current_theme()
        widget.configure(font=(theme.font_family, theme.font_size))  # type: ignore[call-arg]
    except tk.TclError:
        pass


def create_themed_button(
    parent: tk.Widget,
    text: str,
    variant: str = "primary",
    **kwargs: Any,
) -> tk.Button:
    """Создаёт кнопку с вариантом стиля.

    Args:
        parent: Родительский виджет.
        text: Текст кнопки.
        variant: Вариант стиля
            (primary | secondary | danger | success | ghost).
        **kwargs: Дополнительные параметры (переопределяют тему).

    Returns:
        Созданный tk.Button.
    """
    colors = get_theme_colors("default")
    variant_config = _VARIANT_MAP.get(variant, _VARIANT_MAP["primary"])

    defaults: dict[str, Any] = {"text": text, "relief": tk.RAISED, "bd": 2}

    bg_setting = variant_config.get("bg", "")
    if bg_setting == "accent":
        defaults["bg"] = colors.accent
    elif bg_setting:
        defaults["bg"] = bg_setting

    fg_setting = variant_config.get("fg", "")
    if fg_setting:
        defaults["fg"] = fg_setting

    if variant == "ghost":
        defaults["bg"] = colors.bg
        defaults["fg"] = colors.fg
        defaults["relief"] = tk.FLAT
        defaults["bd"] = 0
        defaults["highlightthickness"] = 0

    defaults.update(kwargs)
    return tk.Button(parent, **defaults)
