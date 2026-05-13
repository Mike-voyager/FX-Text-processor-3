"""Виджет поля ввода даты.

Предоставляет:
- DateInputWidget: поле даты с валидацией

Example:
    >>> widget = DateInputWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value(date(2026, 4, 7))
"""

from __future__ import annotations

import tkinter as tk
from datetime import date, datetime
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class DateInputWidget(BaseFieldWidget):
    """Поле даты.

    Attributes:
        _day_var: Переменная для дня.
        _month_var: Переменная для месяца.
        _year_var: Переменная для года.
        _format: Формат даты (DD.MM.YYYY).

    Example:
        >>> widget = DateInputWidget(parent, field_def)
        >>> widget.set_value(date(2026, 4, 7))
        >>> widget.get_value()
        datetime.date(2026, 4, 7)
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация поля даты.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._day_var: tk.StringVar = tk.StringVar()
        self._month_var: tk.StringVar = tk.StringVar()
        self._year_var: tk.StringVar = tk.StringVar()
        self._format: str = "DD.MM.YYYY"
        self._day_spinbox: Optional[tk.Spinbox] = None
        self._month_spinbox: Optional[tk.Spinbox] = None
        self._year_spinbox: Optional[tk.Spinbox] = None
        self._entry: Optional[tk.Entry] = None

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет поля даты.

        Returns:
            Frame с виджетами ввода даты.
        """
        frame = tk.Frame(self._main_frame)

        # Entry-based date input (single field)
        self._entry = tk.Entry(
            frame,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
            width=12,
        )
        self._entry.pack(side=tk.LEFT)

        # Calendar button
        self._calendar_btn = tk.Button(
            frame,
            text="📅",
            font=("TkDefaultFont", 9),
            command=self._show_calendar,
            relief=tk.RAISED,
            borderwidth=1,
        )
        self._calendar_btn.pack(side=tk.LEFT, padx=(4, 0))

        # Bind events
        self._entry.bind("<FocusOut>", self._on_focus_out)
        self._entry.bind("<KeyRelease>", self._on_value_changed)

        # Set initial value
        if isinstance(self._field_def.default_value, date):
            self._entry.insert(0, self._format_date(self._field_def.default_value))
        elif isinstance(self._field_def.default_value, str):
            self._entry.insert(0, self._field_def.default_value)
        else:
            # Default to today
            self._entry.insert(0, self._format_date(date.today()))

        # Apply readonly state
        if self._field_def.readonly:
            self._entry.config(state="readonly")
            self._calendar_btn.config(state="disabled")

        return frame

    def _format_date(self, d: date) -> str:
        """Форматирует дату в строку.

        Args:
            d: Дата для форматирования.

        Returns:
            Строка в формате DD.MM.YYYY.
        """
        return d.strftime("%d.%m.%Y")

    def _parse_date(self, text: str) -> Optional[date]:
        """Парсит дату из строки.

        Args:
            text: Текстовое значение.

        Returns:
            Объект date или None.
        """
        if not text or not text.strip():
            return None

        # Try DD.MM.YYYY format
        formats = ["%d.%m.%Y", "%d-%m-%Y", "%Y-%m-%d", "%d/%m/%Y"]

        for fmt in formats:
            try:
                return datetime.strptime(text.strip(), fmt).date()
            except ValueError:
                continue

        return None

    def _on_value_changed(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик изменения значения.

        Args:
            event: Событие изменения.
        """
        if self._entry is not None:
            text = self._entry.get()
            parsed = self._parse_date(text)
            if parsed is not None:
                super().set_value(parsed)

    def _on_focus_out(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие потери фокуса.
        """
        if self._entry is not None:
            text = self._entry.get()
            parsed = self._parse_date(text)

            if parsed is not None:
                # Reformat on focus out
                self._entry.delete(0, tk.END)
                self._entry.insert(0, self._format_date(parsed))
                super().set_value(parsed)

    def _show_calendar(self) -> None:
        """Показывает календарь для выбора даты."""
        if self._main_frame is None:
            return
        current = self._parse_date(self._entry.get()) if self._entry else None
        from src.gui.dialogs.calendar_dialog import CalendarDialog

        dialog = CalendarDialog(parent=self._main_frame, initial_date=current)
        result = dialog.show()
        if result is not None:
            self.set_value(result)

    def get_value(self) -> Optional[date]:
        """Возвращает текущее значение.

        Returns:
            Объект date или None.
        """
        if self._value is None:
            return None
        if isinstance(self._value, date):
            return self._value
        return self._parse_date(str(self._value))

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение даты.
        """
        parsed_value: Optional[date] = None

        if value is None:
            parsed_value = None
        elif isinstance(value, date):
            parsed_value = value
        elif isinstance(value, str):
            parsed_value = self._parse_date(value)

        # Update entry if exists
        if self._entry is not None and parsed_value is not None:
            formatted = self._format_date(parsed_value)
            current = self._entry.get()
            if current != formatted:
                self._entry.delete(0, tk.END)
                self._entry.insert(0, formatted)

        # Set value
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
        parsed: Optional[date]
        if isinstance(self._value, date):
            parsed = self._value
        else:
            parsed = self._parse_date(str(self._value))

        if parsed is None:
            self._update_validation_state(False, ["Некорректный формат даты (DD.MM.YYYY)"])
            return False

        # Min/max date check
        errors: list[str] = []

        if self._field_def.min_date is not None:
            if parsed < self._field_def.min_date:
                min_date_str = self._format_date(self._field_def.min_date)
                errors.append(f"Дата должна быть не раньше {min_date_str}")

        if self._field_def.max_date is not None:
            if parsed > self._field_def.max_date:
                max_date_str = self._format_date(self._field_def.max_date)
                errors.append(f"Дата должна быть не позже {max_date_str}")

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
    "DateInputWidget",
]
