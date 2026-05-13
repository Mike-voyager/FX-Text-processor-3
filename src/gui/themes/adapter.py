"""Базовый адаптер темы для FX Text Processor 3.

Преобразует существующие темы из формата Theme dataclass
в объект, реализующий ThemeProtocol.

Example:
    >>> from src.gui.themes.adapter import ThemeAdapter
    >>> theme = ThemeAdapter("classic_green", THEME)
    >>> theme.get_color("bg")
    '#000000'

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from src.gui.themes import Theme as ThemeDataclass


# Маппинг ключей старых тем на ключи нового протокола
_COLOR_KEY_MAP: dict[str, str] = {
    "bg": "bg_color",
    "fg": "fg_color",
    "accent": "accent_color",
    "warning": "warning_color",
    "error": "error_color",
    "success": "success_color",
    "border": "border_color",
    # Extended semantic keys for GUI components
    "button_primary": "accent_color",
    "tab_active_bg": "bg_color",
    "tab_active_fg": "fg_color",
    "tab_inactive_bg": "border_color",
    "tab_inactive_fg": "fg_color",
    "tab_border": "border_color",
    "close_hover": "error_color",
    "new_btn_bg": "success_color",
    "new_btn_fg": "bg_color",
    "new_btn_hover": "accent_color",
    "scroll_btn_bg": "border_color",
    "paper_preview_bg": "bg_color",
    "margin_color": "border_color",
    "perforation_color": "error_color",
    "text_primary": "fg_color",
    "text_secondary": "border_color",
    "info": "accent_color",
    "card_bg": "bg_color",
    "dialog_bg": "bg_color",
}


class ThemeAdapter:
    """Адаптер темы, реализующий ThemeProtocol.

    Оборачивает существующие Theme dataclass объекты,
    предоставляя интерфейс ThemeProtocol.

    Attributes:
        name: Уникальное имя темы.

    Example:
        >>> theme = ThemeAdapter("classic_green", THEME)
        >>> theme.get_color("bg")
        '#000000'
        >>> theme.get_font("default")
        ('Courier New', 12, 'normal')
    """

    def __init__(self, name: str, theme: "ThemeDataclass") -> None:
        """Инициализация адаптера.

        Args:
            name: Уникальное имя темы.
            theme: Исходная Theme dataclass.
        """
        self.name: str = name
        self._theme: ThemeDataclass = theme

    def get_color(self, key: str) -> str:
        """Возвращает цвет темы по ключу.

        Args:
            key: Идентификатор цвета.

        Returns:
            Цвет в формате HEX.

        Example:
            >>> theme.get_color("bg")
            '#000000'
        """
        attr = _COLOR_KEY_MAP.get(key, f"{key}_color")
        color: Optional[str] = getattr(self._theme, attr, None)
        if color is None:
            raise KeyError(f"Цвет '{key}' не найден в теме '{self.name}'")
        return color

    def get_font(self, key: str) -> tuple[str, int, str]:
        """Возвращает шрифт темы.

        Args:
            key: Идентификатор шрифта (игнорируется, возвращается базовый).

        Returns:
            Кортеж (семейство, размер, стиль).
        """
        return (
            self._theme.font_family,
            self._theme.font_size,
            "normal",
        )

    def apply_to_widget(self, widget: tk.Widget, style: str) -> None:
        """Применяет тему к виджету.

        Настраивает цвета фона, текста и шрифт виджета
        согласно текущей активной теме.

        Args:
            widget: Tkinter виджет для стилизации.
            style: Тип стиля (например, "button", "entry", "label").
        """
        if not hasattr(widget, "configure"):
            return

        bg_color = self._theme.bg_color
        fg_color = self._theme.fg_color
        accent_color = self._theme.accent_color
        font = (self._theme.font_family, self._theme.font_size)

        # Базовые настройки для всех виджетов
        try:
            widget.configure(bg=bg_color)  # type: ignore[call-arg]
        except tk.TclError:
            pass

        try:
            widget.configure(fg=fg_color)  # type: ignore[call-arg]
        except tk.TclError:
            pass

        try:
            widget.configure(font=font)  # type: ignore[call-arg]
        except tk.TclError:
            pass

        # Специфичные настройки по стилю
        if style in ("button", "tk.Button"):
            try:
                widget.configure(
                    activebackground=accent_color,
                    activeforeground=bg_color,
                )  # type: ignore[call-arg]
            except tk.TclError:
                pass

        elif style in ("entry", "tk.Entry", "text", "tk.Text"):
            try:
                widget.configure(
                    insertbackground=fg_color,
                    selectbackground=accent_color,
                    selectforeground=bg_color,
                )  # type: ignore[call-arg]
            except tk.TclError:
                pass
