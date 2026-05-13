"""Виджет выпадающего списка.

Предоставляет:
- DropdownWidget: выпадающий список с опциями из field_def

Example:
    >>> widget = DropdownWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value("Option 1")
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class DropdownWidget(BaseFieldWidget):
    """Выпадающий список.

    Attributes:
        _var: Переменная для выбранного значения.
        _combobox: Tkinter Combobox widget.
        _options: Список доступных опций.

    Example:
        >>> widget = DropdownWidget(parent, field_def)
        >>> widget.set_value("Option 1")
        >>> widget.get_value()
        'Option 1'
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация выпадающего списка.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._var: tk.StringVar = tk.StringVar()
        self._combobox: Optional[ttk.Combobox] = None
        self._options: tuple[str, ...] = field_def.options or ()

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет выпадающего списка.

        Returns:
            Tkinter Combobox widget с опциями.
        """
        frame = tk.Frame(self._main_frame)

        # Create combobox
        self._combobox = ttk.Combobox(
            frame,
            textvariable=self._var,
            values=list(self._options),
            state="readonly" if self._field_def.readonly else "normal",
            width=30,
        )
        self._combobox.pack(fill=tk.X, expand=True)

        # Set initial value
        if self._field_def.default_value is not None:
            default = str(self._field_def.default_value)
            if default in self._options:
                self._var.set(default)
                self._value = default
            elif self._options:
                self._var.set(self._options[0])
                self._value = self._options[0]
        elif self._options:
            self._var.set(self._options[0])
            self._value = self._options[0]

        # Bind selection event
        self._combobox.bind("<<ComboboxSelected>>", self._on_selection_changed)

        return frame

    def _on_selection_changed(self, event: tk.Event[Any]) -> None:
        """Обработчик изменения выбора.

        Args:
            event: Событие изменения.
        """
        value = self._var.get()
        super().set_value(value)

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Выбранное значение или пустая строка.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение выпадающего списка.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""

        # Validate that value is in options
        if str_value and self._options and str_value not in self._options:
            # Value not in options - use first option or empty
            if self._options:
                str_value = self._options[0]
            else:
                str_value = ""

        # Update variable
        if self._var is not None:
            self._var.set(str_value)

        super().set_value(str_value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        value = self.get_value()

        if not value and self._field_def.required:
            self._update_validation_state(
                False, [f"Поле '{self._field_def.label}' обязательно для заполнения"]
            )
            return False

        # Check if value is in allowed options
        if self._options and value not in self._options:
            self._update_validation_state(
                False, [f"Значение должно быть одним из: {', '.join(self._options)}"]
            )
            return False

        self._update_validation_state(True, [])
        return True

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        # Note: ttk.Combobox font styling is theme-dependent
        # For custom font, we'd need to create a custom style
        pass

    def set_options(self, options: list[str]) -> None:
        """Обновляет список опций.

        Args:
            options: Новый список опций.
        """
        self._options = tuple(options)
        if self._combobox is not None:
            self._combobox.config(values=list(self._options))

        # Check if current value is still valid
        current = self.get_value()
        if current not in self._options and self._options:
            self.set_value(self._options[0])

    def get_options(self) -> tuple[str, ...]:
        """Возвращает список опций.

        Returns:
            Кортеж доступных опций.
        """
        return self._options

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        if self._var is not None:
            self._var.set("")
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на поле."""
        if self._combobox is not None:
            self._combobox.focus_set()


__all__: list[str] = [
    "DropdownWidget",
]
