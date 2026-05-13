"""Поле ввода даты с валидацией формата DD.MM.YYYY.

Предоставляет:
- DateEntry: Entry с placeholder, regex-валидацией и парсингом даты.

Features:
- Placeholder "ДД.ММ.ГГГГ"
- Валидация regex r"\\d{2}\\.\\d{2}\\.\\d{4}"
- Парсинг при потере фокуса и FocusOut on_change

Example:
    >>> entry = DateEntry(
    ...     parent=frame,
    ...     field_id="issue_date",
    ...     label="Дата выдачи",
    ...     on_change=on_changed,
    ... )
    >>> entry.pack(fill=tk.X)
    >>> entry.set_value("15.04.2026")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import re
import tkinter as tk
from datetime import date
from typing import Any, Callable, Optional

from src.gui.modes.structured_form.widgets.base_field import BaseField


class DateEntry(BaseField):
    """Поле ввода даты с placeholder и валидацией DD.MM.YYYY.

    Attributes:
        PLACEHOLDER: Подсказка пустого поля.
        FORMAT: Формат даты для валидации.

    Example:
        >>> entry = DateEntry(parent, field_id="date", label="Дата")
        >>> entry.pack(fill=tk.X)
    """

    PLACEHOLDER: str = "ДД.ММ.ГГГГ"
    PATTERN: str = r"^(\d{2})\.(\d{2})\.(\d{4})$"

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        label: str,
        on_change: Optional[Callable[[str, Any], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация поля даты.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Идентификатор поля.
            label: Текст метки поля.
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
        self._entry: Optional[tk.Entry] = None
        self._has_placeholder: bool = True

        self._create_content()

    def _create_content(self) -> None:
        """Создаёт Entry с placeholder."""
        self._entry = tk.Entry(
            self,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
            width=12,
            fg="gray",
        )
        self._entry.pack(fill=tk.X, expand=True)
        self._entry.insert(0, self.PLACEHOLDER)

        self._entry.bind("<FocusIn>", self._on_focus_in)
        self._entry.bind("<FocusOut>", self._on_focus_out)
        self._entry.bind("<KeyRelease>", self._on_key_release)

    def _on_focus_in(self, event: tk.Event[Any]) -> None:
        """Убирает placeholder при получении фокуса.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._entry is not None and self._has_placeholder:
            self._entry.delete(0, tk.END)
            self._entry.config(fg="black")
            self._has_placeholder = False

    def _on_focus_out(self, event: tk.Event[Any]) -> None:
        """Парсит и форматирует дату при потере фокуса.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._entry is None:
            return

        text = self._entry.get()
        if not text:
            self._entry.insert(0, self.PLACEHOLDER)
            self._entry.config(fg="gray")
            self._has_placeholder = True
            self._value = None
        else:
            parsed = self._parse_date(text)
            if parsed is not None:
                self._value = parsed
                formatted = parsed.strftime("%d.%m.%Y")
                self._entry.delete(0, tk.END)
                self._entry.insert(0, formatted)
                self._entry.config(fg="black")
                self._has_placeholder = False
            else:
                self._value = None

        if self._on_change is not None:
            self._on_change(self.field_id, self._value)

    def _on_key_release(self, event: tk.Event[Any]) -> None:
        """Обновляет внутреннее значение при наборе.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._entry is not None and not self._has_placeholder:
            text = self._entry.get()
            parsed = self._parse_date(text)
            if parsed is not None:
                self._value = parsed
                if self._on_change is not None:
                    self._on_change(self.field_id, self._value)

    def _parse_date(self, text: str) -> Optional[date]:
        """Парсит дату из строки по формату DD.MM.YYYY.

        Args:
            text: Текстовое значение.

        Returns:
            Объект date или None при ошибке.
        """
        if not text or text.strip() == self.PLACEHOLDER:
            return None

        match = re.match(self.PATTERN, text.strip())
        if not match:
            return None

        day_str, month_str, year_str = match.groups()
        try:
            return date(int(year_str), int(month_str), int(day_str))
        except ValueError:
            return None

    def get_value(self) -> Optional[date]:
        """Возвращает текущее значение даты.

        Returns:
            Объект date или None.
        """
        if isinstance(self._value, date):
            return self._value
        if self._entry is not None and not self._has_placeholder:
            parsed: Optional[date] = self._parse_date(self._entry.get())
            return parsed
        return None

    def set_value(self, value: Any) -> None:
        """Устанавливает значение даты.

        Args:
            value: Строка в формате DD.MM.YYYY или объект date.
        """
        parsed: Optional[date] = None

        if value is None:
            parsed = None
        elif isinstance(value, date):
            parsed = value
        elif isinstance(value, str):
            parsed = self._parse_date(value)

        self._value = parsed

        if self._entry is not None:
            self._entry.delete(0, tk.END)
            if parsed is not None:
                self._entry.insert(0, parsed.strftime("%d.%m.%Y"))
                self._entry.config(fg="black")
                self._has_placeholder = False
            else:
                self._entry.insert(0, self.PLACEHOLDER)
                self._entry.config(fg="gray")
                self._has_placeholder = True

        if self._on_change is not None:
            self._on_change(self.field_id, self._value)

    def validate(self) -> bool:
        """Валидирует значение поля даты.

        Returns:
            True если значение валидно или пустое.
        """
        if self._value is None:
            self._is_valid = True
            self.set_error(None)
            return True

        if isinstance(self._value, date):
            self._is_valid = True
            self.set_error(None)
            return True

        self._is_valid = False
        self.set_error("Некорректный формат даты (ДД.ММ.ГГГГ)")
        return False

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода."""
        if self._entry is not None:
            self._entry.focus_set()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        if self._entry is not None:
            self._entry.delete(0, tk.END)
            self._entry.insert(0, self.PLACEHOLDER)
            self._entry.config(fg="gray")
        self._has_placeholder = True
        self._value = None


__all__: list[str] = ["DateEntry"]
