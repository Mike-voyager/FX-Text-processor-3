"""Группа ввода с меткой, полем и валидацией.

Модуль предоставляет InputGroup — compound-виджет,
состоящий из Label + Entry + optional ErrorLabel.

Example:
    >>> group = InputGroup(
    ...     widget_id="email_group",
    ...     label="Email",
    ...     validator=lambda v: None if "@" in v else "Некорректный email"
    ... )
    >>> group.mount(parent)
    >>> group.set_value("user@example.com")
    >>> assert group.validate()

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol


ValidatorResult = Optional[str]
ValidatorCallable = Optional[Callable[[str], ValidatorResult]]


class InputGroup(BaseWidget):
    """Группа: label + entry + optional error message.

    Реализует compound-виджет формы с валидацией,
    отображением ошибок и синхронизацией состояния.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _label_text: Текст метки.
        _validator: Функция валидации (возвращает None или сообщение об ошибке).
        _value: Текущее значение поля.
        _error_message: Текущее сообщение об ошибке.
    """

    def __init__(
        self,
        widget_id: str,
        label: str,
        validator: ValidatorCallable = None,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация группы ввода.

        Args:
            widget_id: Уникальный идентификатор виджета.
            label: Текст метки.
            validator: Функция валидации, возвращает None или сообщение об ошибке.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._label_text: str = label
        self._validator: ValidatorCallable = validator
        self._value: str = ""
        self._error_message: Optional[str] = None

        # Tk widgets (created in mount)
        self._label_widget: Optional[tk.Label] = None
        self._entry_widget: Optional[tk.Entry] = None
        self._error_widget: Optional[tk.Label] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame с label, entry и error label.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame.
        """
        frame = tk.Frame(parent)

        self._label_widget = tk.Label(
            frame,
            text=self._label_text,
            anchor=tk.W,
            font=("Courier", 10, "bold"),
        )
        self._label_widget.pack(fill=tk.X, pady=(0, 2))

        self._entry_widget = tk.Entry(frame, font=("Courier", 10))
        self._entry_widget.pack(fill=tk.X)
        self._entry_widget.insert(0, self._value)

        self._error_widget = tk.Label(
            frame,
            text="",
            fg="#F44336",
            font=("Courier", 9),
            anchor=tk.W,
            wraplength=300,
        )
        self._error_widget.pack(fill=tk.X, pady=(2, 0))

        # Bind validation on focus out
        self._entry_widget.bind("<FocusOut>", self._on_focus_out)
        self._entry_widget.bind("<KeyRelease>", self._on_key_release)

        if self._error_message:
            self._update_error_display()

        return frame

    def _setup_bindings(self) -> None:
        """Bindings настроены в _create_tk_widget."""
        pass

    def get_value(self) -> str:
        """Возвращает текущее значение поля ввода.

        Returns:
            Текст, введённый пользователем.
        """
        if self._entry_widget is not None:
            return self._entry_widget.get()
        return self._value

    def set_value(self, value: str) -> None:
        """Устанавливает значение поля ввода.

        Args:
            value: Новое значение.
        """
        self._value = value
        self.clear_error()
        if self._entry_widget is not None:
            self._entry_widget.delete(0, tk.END)
            self._entry_widget.insert(0, value)

    def set_error(self, message: Optional[str]) -> None:
        """Устанавливает или очищает сообщение об ошибке.

        Args:
            message: Сообщение об ошибке или None для очистки.
        """
        self._error_message = message
        self._update_error_display()

    def _update_error_display(self) -> None:
        """Обновляет отображение ошибки."""
        if self._error_widget is not None:
            text = self._error_message or ""
            self._error_widget.config(text=text)
            if self._entry_widget is not None:
                if text:
                    self._entry_widget.config(highlightbackground="#F44336", highlightcolor="#F44336", highlightthickness=2)
                else:
                    self._entry_widget.config(highlightbackground="#9E9E9E", highlightcolor="#2196F3", highlightthickness=1)

    def clear_error(self) -> None:
        """Очищает сообщение об ошибке."""
        self.set_error(None)

    def validate(self) -> bool:
        """Выполняет валидацию текущего значения.

        Returns:
            True если значение валидно, иначе False.
        """
        if self._validator is None:
            self.clear_error()
            return True

        text = self.get_value()
        error = self._validator(text)
        if error:
            self.set_error(error)
            return False

        self.clear_error()
        return True

    def _on_focus_out(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик потери фокуса — запускает валидацию.

        Args:
            event: Событие Tkinter.
        """
        self.validate()

    def _on_key_release(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик отпускания клавиши — очищает ошибку при вводе.

        Args:
            event: Событие Tkinter.
        """
        if self._error_message:
            self.clear_error()

    def _cleanup(self) -> None:
        """Очищает ссылки на внутренние виджеты."""
        self._label_widget = None
        self._entry_widget = None
        self._error_widget = None


__all__: list[str] = ["InputGroup"]
