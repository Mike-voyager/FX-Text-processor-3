"""Примитивный виджет Button для FX Text Processor 3.

Модуль содержит ThemedButton — стилизованную кнопку с поддержкой тем оформления
и hover-эффектов.

Example:
    >>> from src.gui.components.primitive.button import ThemedButton
    >>> def on_click():
    ...     print("Clicked!")
    >>> button = ThemedButton(
    ...     widget_id="save_btn",
    ...     text="Save",
    ...     command=on_click
    ... )
    >>> tk_widget = button.mount(parent_frame)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional, Tuple, cast

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.gui.themes import get_theme_manager


class ThemedButton(BaseWidget):
    """Стилизованная кнопка с поддержкой тем оформления и hover-эффектов.

    Реализует интерактивную кнопку с возможностью:
    - Обновления текста
    - Включения/выключения
    - Hover-эффектов (изменение цвета при наведении)
    - Применения цветовой темы через ThemeManager

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _text: Текущий текст кнопки.
        _command: Callback при нажатии.
        _enabled: Флаг доступности кнопки.
        _controller: Ссылка на контроллер для callbacks.
        _theme_manager: Менеджер тем для стилизации.
        _hover_handlers: Хранит ссылки на hover event handlers.

    Example:
        >>> def handler():
        ...     print("Button pressed")
        >>> button = ThemedButton(widget_id="btn_1", text="Click Me", command=handler)
        >>> button.set_enabled(False)  # Отключает кнопку
        >>> button.set_enabled(True)   # Включает кнопку
    """

    def __init__(
        self,
        widget_id: str,
        text: str,
        command: Callable[[], None],
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация стилизованной кнопки.

        Args:
            widget_id: Уникальный идентификатор виджета.
            text: Текст кнопки.
            command: Функция, вызываемая при нажатии.
            controller: Опциональная ссылка на контроллер.

        Raises:
            ValueError: Если widget_id пустой.
            TypeError: Если command не callable.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        if not callable(command):
            raise TypeError("command должен быть callable")

        self._text: str = text
        self._command: Callable[[], None] = command
        self._enabled: bool = True
        self._theme_manager = get_theme_manager()
        self._hover_handlers: Optional[
            Tuple[Callable[[tk.Event], None], Callable[[tk.Event], None]]
        ] = None

        # Цвета для разных состояний
        self._normal_bg: str = "#2d2d2d"
        self._normal_fg: str = "#00ff00"
        self._hover_bg: str = "#3d3d3d"
        self._hover_fg: str = "#00ff00"
        self._disabled_bg: str = "#1a1a1a"
        self._disabled_fg: str = "#666666"

    def set_text(self, text: str) -> None:
        """Устанавливает текст кнопки.

        Args:
            text: Новый текст для кнопки.

        Example:
            >>> button = ThemedButton(widget_id="test", text="Old", command=lambda: None)
            >>> button.set_text("New")
            >>> button.get_text()
            'New'
        """
        self._text = text
        if self._tk_widget is not None:
            button_widget = cast(tk.Button, self._tk_widget)
            button_widget.configure(text=text)

    def get_text(self) -> str:
        """Возвращает текущий текст кнопки.

        Returns:
            Текущий текст кнопки.
        """
        return self._text

    def set_enabled(self, enabled: bool) -> None:
        """Устанавливает доступность кнопки.

        Args:
            enabled: True для включения, False для отключения.

        Example:
            >>> button = ThemedButton(widget_id="test", text="Save", command=lambda: None)
            >>> button.set_enabled(False)  # Кнопка становится неактивной
            >>> button.set_enabled(True)   # Кнопка активна
        """
        self._enabled = enabled
        if self._tk_widget is not None:
            button_widget = cast(tk.Button, self._tk_widget)
            state_str: str = "normal" if enabled else "disabled"
            button_widget.configure(**{"state": state_str})

            # Обновляем цвета в зависимости от состояния
            if enabled:
                button_widget.configure(
                    bg=self._normal_bg,
                    fg=self._normal_fg,
                )
            else:
                button_widget.configure(
                    bg=self._disabled_bg,
                    fg=self._disabled_fg,
                )

    def is_enabled(self) -> bool:
        """Проверяет, доступна ли кнопка.

        Returns:
            True если кнопка доступна, False если отключена.
        """
        return self._enabled

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter Button виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter Button.

        Note:
            Применяет текущую тему через ThemeManager и настраивает hover-эффекты.
        """
        theme_name = self._theme_manager.get_current_theme_name()

        # Определяем цвета на основе темы
        if "dark" in theme_name or "classic" in theme_name:
            self._normal_bg = "#2d2d2d"
            self._normal_fg = "#00ff00"
            self._hover_bg = "#3d3d3d"
            self._hover_fg = "#00ff00"
            self._disabled_bg = "#1a1a1a"
            self._disabled_fg = "#666666"
        else:
            self._normal_bg = "#e0e0e0"
            self._normal_fg = "#000000"
            self._hover_bg = "#d0d0d0"
            self._hover_fg = "#000000"
            self._disabled_bg = "#f0f0f0"
            self._disabled_fg = "#999999"

        button = tk.Button(
            parent,
            text=self._text,
            command=self._command,
            font=("Courier", 10, "bold"),
            bg=self._normal_bg,
            fg=self._normal_fg,
            activebackground=self._hover_bg,
            activeforeground=self._hover_fg,
            disabledforeground=self._disabled_fg,
            padx=12,
            pady=4,
            relief=tk.RAISED,
            bd=2,
            cursor="hand2" if self._enabled else "arrow",
            state="normal" if self._enabled else "disabled",
        )
        return button

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для hover-эффектов.

        Подключает обработчики для событий Enter и Leave
        для изменения цвета кнопки при наведении мыши.
        """
        if self._tk_widget is None:
            return

        def _on_enter(event: tk.Event) -> None:  # noqa: ARG001
            """Обработчик наведения мыши."""
            if self._enabled and self._tk_widget is not None:
                button_widget = cast(tk.Button, self._tk_widget)
                button_widget.configure(bg=self._hover_bg, fg=self._hover_fg)

        def _on_leave(event: tk.Event) -> None:  # noqa: ARG001
            """Обработчик ухода мыши."""
            if self._enabled and self._tk_widget is not None:
                button_widget = cast(tk.Button, self._tk_widget)
                button_widget.configure(bg=self._normal_bg, fg=self._normal_fg)

        # Сохраняем ссылки для возможной отписки
        self._hover_handlers = (_on_enter, _on_leave)

        self._tk_widget.bind("<Enter>", _on_enter)
        self._tk_widget.bind("<Leave>", _on_leave)

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании.

        Отвязывает hover event handlers от Tkinter виджета.
        """
        if self._tk_widget is not None and self._hover_handlers is not None:
            self._tk_widget.unbind("<Enter>")
            self._tk_widget.unbind("<Leave>")
        self._hover_handlers = None
