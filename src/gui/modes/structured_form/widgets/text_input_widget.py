"""Виджет однострочного текстового поля.

Предоставляет:
- TextInputWidget: однострочное текстовое поле с валидацией

Example:
    >>> widget = TextInputWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value("Hello")
"""

from __future__ import annotations

import re
import tkinter as tk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class TextInputWidget(BaseFieldWidget):
    """Однострочное текстовое поле.

    Attributes:
        _entry: Tkinter Entry widget для ввода текста.
        _show_char: Символ для отображения (для паролей).

    Example:
        >>> widget = TextInputWidget(parent, field_def)
        >>> widget.set_value("Hello")
        >>> widget.get_value()
        'Hello'
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        show_char: Optional[str] = None,
    ) -> None:
        """Инициализация текстового поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            show_char: Символ для маскирования (для паролей).
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._show_char: Optional[str] = show_char
        self._entry: Optional[tk.Entry] = None
        self._placeholder: str = field_def.placeholder or ""

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет текстового поля.

        Returns:
            Tkinter Entry widget с настройками валидации.
        """
        frame = tk.Frame(self._main_frame)

        # Create entry widget
        show_char = self._show_char if self._show_char else ""
        self._entry = tk.Entry(
            frame,
            show=show_char,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
        )

        # Set max length if specified
        if self._field_def.max_length:
            self._entry.config(
                validate="key",
                validatecommand=(frame.register(self._validate_length), "%P"),
            )

        self._entry.pack(fill=tk.X, expand=True)

        # Add placeholder
        if self._placeholder:
            self._entry.insert(0, self._placeholder)
            self._entry.config(fg="gray")

            # Bind focus events for placeholder
            self._entry.bind("<FocusIn>", self._on_focus_in)
            self._entry.bind("<FocusOut>", self._on_focus_out)

        # Bind value change
        self._entry.bind("<KeyRelease>", self._on_value_changed)
        self._entry.bind("<FocusOut>", self._on_focus_out, add=True)

        # Set initial value
        if self._field_def.default_value:
            self._entry.delete(0, tk.END)
            self._entry.insert(0, str(self._field_def.default_value))
            self._entry.config(fg="black")

        # Apply readonly state
        if self._field_def.readonly:
            self._entry.config(state="readonly")

        return frame

    def _validate_length(self, new_value: str) -> bool:
        """Валидирует длину ввода.

        Args:
            new_value: Новое значение поля.

        Returns:
            True если длина допустима.
        """
        if self._field_def.max_length is None:
            return True
        return len(new_value) <= self._field_def.max_length

    def _on_focus_in(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик получения фокуса.

        Args:
            event: Событие фокуса.
        """
        if self._entry and self._placeholder:
            current = self._entry.get()
            if current == self._placeholder:
                self._entry.delete(0, tk.END)
                self._entry.config(fg="black")

    def _on_focus_out(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие потери фокуса.
        """
        if self._entry and self._placeholder:
            current = self._entry.get()
            if not current:
                self._entry.insert(0, self._placeholder)
                self._entry.config(fg="gray")

        # Validate on focus out
        self._update_value_from_widget()

    def _on_value_changed(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик изменения значения.

        Args:
            event: Событие изменения.
        """
        self._update_value_from_widget()

    def _update_value_from_widget(self) -> None:
        """Обновляет внутреннее значение из виджета."""
        if self._entry is not None:
            value = self._entry.get()
            # Skip placeholder value
            if value == self._placeholder:
                value = ""
            self.set_value(value)

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Текущее значение поля.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""

        # Update entry if exists and value differs
        if self._entry is not None:
            current = self._entry.get()
            if current != str_value and str_value != self._placeholder:
                self._entry.delete(0, tk.END)
                if str_value:
                    self._entry.insert(0, str_value)
                    self._entry.config(fg="black")
                elif self._placeholder:
                    self._entry.insert(0, self._placeholder)
                    self._entry.config(fg="gray")

        super().set_value(str_value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        # Additional pattern validation for text input
        if self._value and self._field_def.validation_pattern:
            try:
                if not re.match(self._field_def.validation_pattern, str(self._value)):
                    self.set_error("Значение не соответствует шаблону")
                    return False
            except re.error:
                pass  # Invalid regex pattern

        return super().validate()

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        if self._entry is not None:
            # Map CPI to font size (approximate)
            font_size = max(8, min(14, 14 - (self._cpi - 10) // 2))
            self._entry.config(font=("Courier", font_size))

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        if self._entry is not None:
            self._entry.delete(0, tk.END)
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на поле."""
        if self._entry is not None:
            self._entry.focus_set()


__all__: list[str] = [
    "TextInputWidget",
]
