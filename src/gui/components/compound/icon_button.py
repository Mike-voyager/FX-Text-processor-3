"""Кнопка с иконкой и tooltip.

Модуль предоставляет IconButton — compound-виджет кнопки
с иконкой (emoji) и всплывающей подсказкой.

Example:
    >>> btn = IconButton(
    ...     widget_id="save_btn",
    ...     icon="💾",
    ...     tooltip="Сохранить документ",
    ...     command=lambda: print("Save")
    ... )
    >>> btn.mount(parent)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol

CommandCallback = Optional[Callable[[], None]]


class IconButton(BaseWidget):
    """Кнопка с иконкой и tooltip.

    Реализует compound-виджет:
    - Кнопка с текстом-иконкой (emoji)
    - Всплывающая подсказка при наведении
    - Конфигурируемый размер и callback

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _icon: Текст иконки.
        _tooltip_text: Текст подсказки.
        _command: Callback при нажатии.
        _size: Размер кнопки.
    """

    def __init__(
        self,
        widget_id: str,
        icon: str,
        tooltip: str = "",
        command: CommandCallback = None,
        size: int = 16,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализирует кнопку с иконкой.

        Args:
            widget_id: Уникальный идентификатор виджета.
            icon: Иконка (emoji или символ).
            tooltip: Текст всплывающей подсказки.
            command: Callback при нажатии.
            size: Размер шрифта иконки.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._icon: str = icon
        self._tooltip_text: str = tooltip
        self._command: CommandCallback = command
        self._size: int = size

        self._button: Optional[tk.Button] = None
        self._tooltip_window: Optional[tk.Toplevel] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Button с иконкой.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Button.
        """
        self._button = tk.Button(
            parent,
            text=self._icon,
            command=self._on_click,
            font=("Courier", self._size),
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            padx=4,
            pady=2,
        )

        if self._tooltip_text:
            self._button.bind("<Enter>", self._show_tooltip)
            self._button.bind("<Leave>", self._hide_tooltip)

        return self._button

    def _setup_bindings(self) -> None:
        """Bindings настроены в _create_tk_widget."""
        pass

    def set_icon(self, icon: str) -> None:
        """Устанавливает иконку.

        Args:
            icon: Новая иконка.
        """
        self._icon = icon
        if self._button is not None:
            self._button.config(text=icon)

    def set_tooltip(self, text: str) -> None:
        """Устанавливает текст подсказки.

        Args:
            text: Текст подсказки.
        """
        self._tooltip_text = text
        if self._button is not None:
            if text:
                self._button.bind("<Enter>", self._show_tooltip)
                self._button.bind("<Leave>", self._hide_tooltip)
            else:
                self._button.unbind("<Enter>")
                self._button.unbind("<Leave>")

    def _on_click(self) -> None:
        """Вызывает command callback."""
        if self._command is not None:
            self._command()

    def _show_tooltip(self, event: Optional[tk.Event] = None) -> None:
        """Показывает tooltip.

        Args:
            event: Событие Tkinter.
        """
        if not self._tooltip_text or self._button is None:
            return
        x = self._button.winfo_rootx() + 20
        y = self._button.winfo_rooty() + self._button.winfo_height() + 5
        self._tooltip_window = tk.Toplevel(self._button)
        self._tooltip_window.wm_overrideredirect(True)
        self._tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self._tooltip_window,
            text=self._tooltip_text,
            bg="#FFFFE0",
            fg="#000000",
            font=("Courier", 9),
            relief=tk.SOLID,
            bd=1,
            padx=4,
            pady=2,
        )
        label.pack()

    def _hide_tooltip(self, event: Optional[tk.Event] = None) -> None:
        """Скрывает tooltip.

        Args:
            event: Событие Tkinter.
        """
        if self._tooltip_window is not None:
            try:
                self._tooltip_window.destroy()
            except tk.TclError:
                pass
            self._tooltip_window = None

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании."""
        self._hide_tooltip()
        self._button = None


__all__: list[str] = ["IconButton"]
