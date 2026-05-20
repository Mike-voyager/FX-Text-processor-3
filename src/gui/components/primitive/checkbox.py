"""Виджет чекбокса для FX Text Processor 3.

Модуль предоставляет ThemedCheckbox - тематизированный чекбокс
с поддержкой callback при изменении состояния и интеграцией
с Controller через BaseWidget.

Classes:
    ThemedCheckbox: Тематизированный чекбокс.

Example:
    >>> checkbox = ThemedCheckbox(
    ...     widget_id="auto_save",
    ...     text="Автосохранение",
    ...     on_change=lambda checked: print(f"Auto-save: {checked}"),
    ...     controller=my_controller
    ... )
    >>> checkbox.mount(parent_frame)
    >>> checkbox.set(True)
    >>> checkbox.get()
    True

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.gui.themes import get_theme_manager


class ThemedCheckbox(BaseWidget):
    """Тематизированный чекбокс.

    Расширяет BaseWidget, добавляя функциональность чекбокса:
    - Получение/установка состояния (checked/unchecked)
    - Callback при изменении состояния
    - Интеграция с Controller через dispatch

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        _text: Текст метки чекбокса.
        _on_change: Callback функция при изменении состояния.
        _variable: Tkinter IntVar для хранения состояния.

    Example:
        >>> def on_toggle(checked: bool) -> None:
        ...     print(f"Checkbox is now: {'checked' if checked else 'unchecked'}")
        >>> cb = ThemedCheckbox(
        ...     widget_id="agree",
        ...     text="Я согласен с условиями",
        ...     on_change=on_toggle,
        ...     controller=ctrl
        ... )
        >>> cb.mount(parent)
        >>> cb.toggle()  # Вызовет on_toggle(True)
    """

    def __init__(
        self,
        widget_id: str,
        text: str = "",
        on_change: Optional[Callable[[bool], None]] = None,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация чекбокса.

        Args:
            widget_id: Уникальный идентификатор виджета.
            text: Текст метки рядом с чекбоксом.
            on_change: Callback функция, вызываемая при изменении состояния.
            controller: Ссылка на контроллер для callbacks.

        Raises:
            ValueError: Если widget_id пустой.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._text: str = text
        self._on_change: Optional[Callable[[bool], None]] = on_change
        self._variable: Optional[tk.IntVar] = None
        self._is_checked: bool = False

    def get(self) -> bool:
        """Возвращает текущее состояние чекбокса.

        Returns:
            True если чекбокс отмечен (checked), False если снят.

        Example:
            >>> checkbox.set(True)
            >>> checkbox.get()
            True
            >>> checkbox.set(False)
            >>> checkbox.get()
            False
        """
        if self._variable is not None:
            return bool(self._variable.get())
        return self._is_checked

    def set(self, checked: bool) -> None:
        """Устанавливает состояние чекбокса.

        Args:
            checked: True для отметки, False для снятия.

        Example:
            >>> checkbox.set(True)   # Отметить
            >>> checkbox.set(False)  # Снять отметку
        """
        if self.get() != checked:
            self._is_checked = checked
            if self._variable is not None:
                self._variable.set(1 if checked else 0)
            self._notify_change(checked)

    def toggle(self) -> None:
        """Переключает состояние чекбокса.

        Инвертирует текущее состояние и вызывает on_change callback.

        Example:
            >>> checkbox.set(False)
            >>> checkbox.toggle()  # Теперь True
            >>> checkbox.toggle()  # Теперь False
        """
        new_state = not self.get()
        self._is_checked = new_state
        if self._variable is not None:
            self._variable.set(1 if new_state else 0)
        self._notify_change(new_state)

    def _notify_change(self, checked: bool) -> None:
        """Уведомляет об изменении состояния.

        Вызывает on_change callback и dispatch в controller.

        Args:
            checked: Новое состояние чекбокса.
        """
        if self._on_change is not None:
            self._on_change(checked)

        if self._controller is not None:
            self._controller.dispatch(
                "checkbox_changed",
                widget_id=self._widget_id,
                checked=checked,
            )

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter Checkbutton виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный tk.Checkbutton виджет.
        """
        # Создаём IntVar только при монтировании (когда есть root)
        self._variable = tk.IntVar(value=1 if self._is_checked else 0)

        checkbox = tk.Checkbutton(
            parent,
            text=self._text,
            variable=self._variable,
            command=self._on_checkbox_clicked,
        )

        # Применяем тему
        theme_manager = get_theme_manager()
        theme_manager.apply_to_widget(checkbox)

        return checkbox

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Checkbutton.

        Дополнительная настройка после создания виджета.
        Основная логика обработки в _on_checkbox_clicked через command.
        """
        # Command уже установлен в _create_tk_widget
        pass

    def _on_checkbox_clicked(self) -> None:
        """Обработчик клика по чекбоксу.

        Вызывается автоматически Tkinter при изменении состояния.
        """
        checked = self.get()
        self._notify_change(checked)


__all__: list[str] = ["ThemedCheckbox"]
