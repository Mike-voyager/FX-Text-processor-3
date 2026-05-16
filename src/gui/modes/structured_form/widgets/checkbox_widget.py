"""Виджет чекбокса (boolean поле).

Предоставляет:
- CheckboxWidget: чекбокс с boolean значением

Example:
    >>> widget = CheckboxWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value(True)
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class CheckboxWidget(BaseFieldWidget):
    """Чекбокс (boolean).

    Attributes:
        _var: Переменная состояния чекбокса.
        _checkbutton: Tkinter Checkbutton widget.

    Example:
        >>> widget = CheckboxWidget(parent, field_def)
        >>> widget.set_value(True)
        >>> widget.get_value()
        True
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация чекбокса.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._var: tk.BooleanVar = tk.BooleanVar(master=self._tk_widget)
        self._checkbutton: Optional[tk.Checkbutton] = None

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет чекбокса.

        Returns:
            Tkinter Checkbutton widget с label справа.
        """
        frame = tk.Frame(self._main_frame)

        # Create checkbutton
        self._checkbutton = tk.Checkbutton(
            frame,
            variable=self._var,
            command=self._on_toggled,
            font=("TkDefaultFont", 10),
        )
        self._checkbutton.pack(side=tk.LEFT)

        # Create label
        label_text = self._field_def.label
        if self._field_def.required:
            label_text += " *"

        self._label_widget = tk.Label(
            frame,
            text=label_text,
            font=("TkDefaultFont", 10),
            anchor=tk.W,
        )
        self._label_widget.pack(side=tk.LEFT, padx=(4, 0))

        # Set initial value
        if self._field_def.default_value is not None:
            initial_value = bool(self._field_def.default_value)
            self._var.set(initial_value)
            self._value = initial_value

        # Apply readonly state
        if self._field_def.readonly:
            self._checkbutton.config(state="disabled")

        return frame

    def _on_toggled(self) -> None:
        """Обработчик переключения чекбокса."""
        value = self._var.get()
        super().set_value(value)

    def get_value(self) -> bool:
        """Возвращает текущее значение.

        Returns:
            Boolean значение чекбокса.
        """
        return bool(self._value) if self._value is not None else False

    def set_value(self, value: Any) -> None:
        """Устанавливает значение чекбокса.

        Args:
            value: Новое boolean значение.
        """
        bool_value = bool(value) if value is not None else False

        # Update variable
        if self._var is not None:
            self._var.set(bool_value)

        super().set_value(bool_value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.

        Note:
            Для чекбокса всегда валидно (True/False).
        """
        # Boolean is always valid, just check if required and False
        if self._field_def.required and not self.get_value():
            self._update_validation_state(
                False, [f"Поле '{self._field_def.label}' должно быть отмечено"]
            )
            return False

        self._update_validation_state(True, [])
        return True

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        font_size = max(8, min(14, 14 - (self._cpi - 10) // 2))
        if self._label_widget is not None and hasattr(self._label_widget, "config"):
            self._label_widget.config(font=("TkDefaultFont", font_size))

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        if self._var is not None:
            self._var.set(False)
        if self._checkbutton is not None:
            self._checkbutton.deselect()
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на чекбокс."""
        if self._checkbutton is not None:
            self._checkbutton.focus_set()

    def toggle(self) -> None:
        """Переключает состояние чекбокса."""
        if self._var is not None:
            new_value = not self._var.get()
            self._var.set(new_value)
            self._on_toggled()


__all__: list[str] = [
    "CheckboxWidget",
]
