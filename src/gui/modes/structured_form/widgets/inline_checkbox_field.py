"""Inline-виджет чекбокса для STRUCTURED_FORM режима.

Предоставляет:
- InlineCheckboxField: чекбокс с boolean значением, наследует BaseField.

Example:
    >>> field = InlineCheckboxField(
    ...     parent=frame,
    ...     field_id="agreed",
    ...     label="Согласен",
    ...     on_change=on_field_change,
    ... )
    >>> field.pack(fill=tk.X)
    >>> field.set_value(True)
    >>> assert field.get_value() is True

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.gui.modes.structured_form.widgets.base_field import BaseField


class InlineCheckboxField(BaseField):
    """Inline-чекбокс (boolean) на базе BaseField.

    Attributes:
        _var: Переменная состояния чекбокса.
        _checkbutton: Виджет tk.Checkbutton.
        _required: Флаг обязательности поля.

    Example:
        >>> field = InlineCheckboxField(parent, field_id="flag", label="Флаг")
        >>> field.set_value(True)
        >>> field.get_value()
        True
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        label: str,
        required: bool = False,
        readonly: bool = False,
        on_change: Optional[Callable[[str, Any], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация inline-чекбокса.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Уникальный идентификатор поля.
            label: Текст метки поля.
            required: Обязательность поля.
            readonly: Только для чтения.
            on_change: Callback при изменении значения.
            **kwargs: Дополнительные аргументы для tk.Frame.
        """
        super().__init__(
            parent=parent,
            field_id=field_id,
            label=label,
            on_change=on_change,
            **kwargs,
        )

        self._required: bool = required
        self._readonly: bool = readonly
        self._var: tk.BooleanVar = tk.BooleanVar(master=self, value=False)
        self._checkbutton: Optional[tk.Checkbutton] = None

        # Переупаковываем label: слева от checkbox
        self._label_widget.pack_forget()

        container = tk.Frame(self)
        container.pack(fill=tk.X, expand=True)

        self._checkbutton = tk.Checkbutton(
            container,
            variable=self._var,
            command=self._on_toggled,
            font=("TkDefaultFont", 10),
        )
        self._checkbutton.pack(side=tk.LEFT)

        self._label_widget.config(font=("TkDefaultFont", 10))
        self._label_widget.pack(side=tk.LEFT, padx=(4, 0))

        if self._readonly:
            self._checkbutton.config(state="disabled")

    def _on_toggled(self) -> None:
        """Обработчик переключения чекбокса."""
        value = self._var.get()
        self._value = value
        if self._on_change is not None:
            self._on_change(self.field_id, value)

    def get_value(self) -> bool:
        """Возвращает текущее значение чекбокса.

        Returns:
            True если чекбокс отмечен, иначе False.
        """
        return bool(self._var.get())

    def set_value(self, value: Any) -> None:
        """Устанавливает состояние чекбокса.

        Args:
            value: Новое boolean значение.
        """
        bool_value = bool(value) if value is not None else False
        self._var.set(bool_value)
        self._value = bool_value
        if self._on_change is not None:
            self._on_change(self.field_id, bool_value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        if self._required and not self.get_value():
            self.set_error("Поле должно быть отмечено")
            return False
        self.set_error(None)
        return True

    def focus(self) -> None:
        """Устанавливает фокус на чекбокс."""
        if self._checkbutton is not None:
            self._checkbutton.focus_set()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные поля."""
        self._var.set(False)
        self._value = False
        self.set_error(None)


__all__: list[str] = ["InlineCheckboxField"]
