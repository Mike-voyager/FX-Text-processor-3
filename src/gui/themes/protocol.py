"""Протокол темы для FX Text Processor 3.

Определяет интерфейс ThemeProtocol для получения цветов, шрифтов
и применения стилей к Tkinter виджетам.

Example:
    >>> from src.gui.themes.protocol import ThemeProtocol
    >>> theme: ThemeProtocol = ClassicGreenTheme()
    >>> theme.get_color("bg")
    '#000000'
    >>> theme.get_font("default")
    ('Courier New', 12, 'normal')
    >>> theme.apply_to_widget(button, "button")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Protocol


class ThemeProtocol(Protocol):
    """Протокол темы оформления GUI.

    Определяет интерфейс для получения цветов, шрифтов
    и применения стилей к Tkinter виджетам.

    Attributes:
        name: Уникальное имя темы.

    Example:
        >>> theme = ClassicGreenTheme()
        >>> theme.get_color("bg")
        '#000000'
        >>> theme.get_font("default")
        ('Courier New', 12, 'normal')
        >>> theme.apply_to_widget(button, "button")
    """

    name: str

    def get_color(self, key: str) -> str:
        """Возвращает цвет темы по ключу.

        Args:
            key: Идентификатор цвета (например, "bg", "fg", "accent").

        Returns:
            Color в формате HEX (#RRGGBB).
        """
        ...

    def get_font(self, key: str) -> tuple[str, int, str]:
        """Возвращает шрифт темы по ключу.

        Args:
            key: Идентификатор шрифта (например, "default", "header").

        Returns:
            Кортеж (семейство, размер, стиль).
        """
        ...

    def apply_to_widget(self, widget: tk.Widget, style: str) -> None:
        """Применяет стиль темы к виджету.

        Args:
            widget: Tkinter виджет для стилизации.
            style: Тип стиля (например, "button", "entry", "label").
        """
        ...
