"""Примитивный виджет Label для FX Text Processor 3.

Модуль содержит ThemedLabel — стилизованную метку с поддержкой тем оформления.

Example:
    >>> from src.gui.components.primitive.label import ThemedLabel
    >>> label = ThemedLabel(widget_id="title_label", text="Document Title")
    >>> tk_widget = label.mount(parent_frame)
    >>> label.set_text("New Title")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional, cast

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.gui.themes import get_theme_manager


class ThemedLabel(BaseWidget):
    """Стилизованная метка с поддержкой тем оформления.

    Реализует простой текстовый виджет с возможностью обновления текста
    и применения цветовой темы через ThemeManager.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _text: Текущий текст метки.
        _controller: Ссылка на контроллер для callbacks (опционально).
        _tk_widget: Ссылка на Tkinter виджет Label.

    Example:
        >>> label = ThemedLabel(widget_id="header", text="Header Text")
        >>> label.get_text()
        'Header Text'
        >>> label.set_text("Updated Text")
        >>> label.get_text()
        'Updated Text'
    """

    def __init__(
        self,
        widget_id: str,
        text: str = "",
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация стилизованной метки.

        Args:
            widget_id: Уникальный идентификатор виджета.
            text: Начальный текст метки.
            controller: Опциональная ссылка на контроллер.

        Raises:
            ValueError: Если widget_id пустой.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._text: str = text
        self._theme_manager = get_theme_manager()

    def set_text(self, text: str) -> None:
        """Устанавливает текст метки.

        Args:
            text: Новый текст для отображения.

        Note:
            Если виджет смонтирован, текст обновляется в реальном времени.

        Example:
            >>> label = ThemedLabel(widget_id="test", text="Old")
            >>> label.set_text("New")
            >>> label.get_text()
            'New'
        """
        self._text = text
        if self._tk_widget is not None:
            label_widget = cast(tk.Label, self._tk_widget)
            label_widget.configure(text=text)

    def get_text(self) -> str:
        """Возвращает текущий текст метки.

        Returns:
            Текущий текст метки.

        Example:
            >>> label = ThemedLabel(widget_id="test", text="Hello")
            >>> label.get_text()
            'Hello'
        """
        return self._text

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter Label виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter Label.

        Note:
            Применяет текущую тему через ThemeManager.
        """
        theme = self._theme_manager.get_current_theme()

        # Создаём Label с базовыми настройками темы
        label = tk.Label(
            parent,
            text=self._text,
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            padx=4,
            pady=2,
        )
        return label


__all__: list[str] = ["ThemedLabel"]
