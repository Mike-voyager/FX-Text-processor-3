"""Виджет числового поля ввода.

Предоставляет:
- NumberInputWidget: числовое поле с валидацией для NUMBER_INPUT и CURRENCY

Example:
    >>> widget = NumberInputWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value(Decimal("123.45"))
"""

from __future__ import annotations

import re
import tkinter as tk
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Optional, Union

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class NumberInputWidget(BaseFieldWidget):
    """Числовое поле с валидацией.

    Attributes:
        _entry: Tkinter Entry widget для ввода числа.
        _decimal_places: Количество десятичных знаков для CURRENCY.
        _currency_symbol: Символ валюты для CURRENCY.
        _use_thousands_separator: Использовать разделитель тысяч.

    Example:
        >>> widget = NumberInputWidget(parent, field_def)
        >>> widget.set_value(Decimal("123.45"))
        >>> widget.get_value()
        Decimal('123.45')
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        decimal_places: int = 2,
        currency_symbol: str = "₽",
        use_thousands_separator: bool = True,
    ) -> None:
        """Инициализация числового поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            decimal_places: Количество десятичных знаков.
            currency_symbol: Символ валюты.
            use_thousands_separator: Использовать разделитель тысяч.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._decimal_places: int = decimal_places
        self._currency_symbol: str = currency_symbol
        self._use_thousands_separator: bool = use_thousands_separator
        self._entry: Optional[tk.Entry] = None
        self._is_currency: bool = field_def.field_type == FieldType.CURRENCY

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет числового поля.

        Returns:
            Tkinter Entry widget с валидацией чисел.
        """
        frame = tk.Frame(self._main_frame)

        # Currency symbol label
        if self._is_currency:
            self._symbol_label = tk.Label(
                frame,
                text=self._currency_symbol,
                font=("Courier", 11),
            )
            self._symbol_label.pack(side=tk.LEFT, padx=(0, 2))

        # Create entry widget
        self._entry = tk.Entry(
            frame,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
            justify=tk.RIGHT,
        )

        # Set max length if specified
        if self._field_def.max_length:
            self._entry.config(
                validate="key",
                validatecommand=(frame.register(self._validate_input), "%P"),
            )
        else:
            # Default validation for numbers
            self._entry.config(
                validate="key",
                validatecommand=(frame.register(self._validate_input), "%P"),
            )

        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Bind events
        self._entry.bind("<KeyRelease>", self._on_value_changed)
        self._entry.bind("<FocusOut>", self._on_focus_out)

        # Set initial value
        if self._field_def.default_value is not None:
            try:
                value = Decimal(str(self._field_def.default_value))
                self._entry.insert(0, self._format_value(value))
            except (InvalidOperation, ValueError):
                pass

        # Apply readonly state
        if self._field_def.readonly:
            self._entry.config(state="readonly")

        return frame

    def _validate_input(self, new_value: str) -> bool:
        """Валидирует ввод числа.

        Args:
            new_value: Новое значение поля.

        Returns:
            True если ввод допустим.
        """
        if not new_value:
            return True

        # Allow negative sign and decimal point
        pattern = r"^-?\d*\.?\d*$"
        if not re.match(pattern, new_value):
            return False

        # Check max length
        if self._field_def.max_length and len(new_value) > self._field_def.max_length:
            return False

        return True

    def _format_value(self, value: Decimal) -> str:
        """Форматирует число для отображения.

        Args:
            value: Числовое значение.

        Returns:
            Отформатированная строка.
        """
        if value is None:
            return ""

        # Format with decimal places
        formatted = f"{value:,.{self._decimal_places}f}"

        # Replace comma with space for thousands separator (Russian format)
        if self._use_thousands_separator:
            formatted = formatted.replace(",", " ")
        else:
            formatted = formatted.replace(",", "")

        return formatted

    def _parse_value(self, text: str) -> Optional[Decimal]:
        """Парсит значение из текста.

        Args:
            text: Текстовое значение.

        Returns:
            Decimal значение или None.
        """
        if not text or text.strip() == "":
            return None

        # Remove formatting
        clean_text = text.replace(" ", "").replace(",", "").replace(self._currency_symbol, "")

        try:
            return Decimal(clean_text)
        except (InvalidOperation, ValueError):
            return None

    def _on_value_changed(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик изменения значения.

        Args:
            event: Событие изменения.
        """
        if self._entry is not None:
            text = self._entry.get()
            value = self._parse_value(text)
            if value is not None:
                super().set_value(value)

    def _on_focus_out(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие потери фокуса.
        """
        if self._entry is not None:
            text = self._entry.get()
            value = self._parse_value(text)

            # Reformat on focus out
            if value is not None:
                formatted = self._format_value(value)
                self._entry.delete(0, tk.END)
                self._entry.insert(0, formatted)
                super().set_value(value)

    def get_value(self) -> Optional[Decimal]:
        """Возвращает текущее значение.

        Returns:
            Decimal значение или None.
        """
        if self._value is None:
            return None
        try:
            return Decimal(str(self._value))
        except (InvalidOperation, ValueError):
            return None

    def set_value(self, value: Union[Decimal, int, float, str, None]) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое числовое значение.
        """
        if value is None:
            parsed_value = None
        else:
            try:
                parsed_value = Decimal(str(value))
            except (InvalidOperation, ValueError):
                parsed_value = None

        # Update entry if exists
        if self._entry is not None and parsed_value is not None:
            formatted = self._format_value(parsed_value)
            current = self._entry.get()
            if current != formatted:
                self._entry.delete(0, tk.END)
                self._entry.insert(0, formatted)

        # Call parent set_value with Decimal
        if parsed_value is not None:
            super().set_value(parsed_value)
        else:
            self._value = None
            if self._on_change:
                self._on_change(self.field_id, None)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        if self._value is None or self._value == "":
            if self._field_def.required:
                self._update_validation_state(
                    False, [f"Поле '{self._field_def.label}' обязательно"]
                )
                return False
            self._update_validation_state(True, [])
            return True

        # Parse value
        try:
            value = Decimal(str(self._value))
        except (InvalidOperation, ValueError):
            self._update_validation_state(False, ["Некорректное числовое значение"])
            return False

        # Min/max value check
        errors: list[str] = []

        if self._field_def.min_value is not None:
            if value < Decimal(str(self._field_def.min_value)):
                errors.append(f"Значение должно быть не менее {self._field_def.min_value}")

        if self._field_def.max_value is not None:
            if value > Decimal(str(self._field_def.max_value)):
                errors.append(f"Значение должно быть не более {self._field_def.max_value}")

        self._update_validation_state(len(errors) == 0, errors)
        return len(errors) == 0

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        if self._entry is not None:
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
    "NumberInputWidget",
]
