"""Виджет поля ввода email.

Предоставляет:
- EmailWidget: поле ввода email с валидацией по упрощённому RFC 5322
  и подсветкой при ошибке.

Example:
    >>> widget = EmailWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change,
    ... )
    >>> widget.set_value("user@example.com")
"""

from __future__ import annotations

import re
import tkinter as tk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget

# Упрощённое регулярное выражение для RFC 5322
_EMAIL_PATTERN: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class EmailWidget(BaseFieldWidget):
    """Поле ввода email.

    Attributes:
        _entry: Tkinter Entry widget для ввода email.
        _placeholder: Подсказка в поле.

    Example:
        >>> widget = EmailWidget(parent, field_def)
        >>> widget.set_value("test@domain.ru")
        >>> widget.get_value()
        'test@domain.ru'
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация виджета email.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._entry: Optional[tk.Entry] = None
        self._placeholder: str = field_def.placeholder or ""

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет поля email.

        Returns:
            Tkinter Entry widget с валидацией email.
        """
        frame = tk.Frame(self._main_frame)

        self._entry = tk.Entry(
            frame,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
        )
        self._entry.pack(fill=tk.X, expand=True)

        # Placeholder
        if self._placeholder:
            self._entry.insert(0, self._placeholder)
            self._entry.config(fg="gray")
            self._entry.bind("<FocusIn>", self._on_focus_in)

        self._entry.bind("<FocusOut>", self._on_focus_out)
        self._entry.bind("<KeyRelease>", self._on_key_release)

        # Начальное значение
        if self._field_def.default_value is not None:
            self._entry.delete(0, tk.END)
            self._entry.insert(0, str(self._field_def.default_value))
            self._entry.config(fg="black")
            self._value = str(self._field_def.default_value)

        # Readonly
        if self._field_def.readonly:
            self._entry.config(state="readonly")

        return frame

    def _on_focus_in(self, event: tk.Event[tk.Misc]) -> None:
        """Обработчик получения фокуса.

        Args:
            event: Событие фокуса.
        """
        if self._entry is not None and self._placeholder:
            if self._entry.get() == self._placeholder:
                self._entry.delete(0, tk.END)
                self._entry.config(fg="black")

    def _on_focus_out(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Обработчик потери фокуса: валидация и подсветка.

        Args:
            event: Событие потери фокуса (опционально).
        """
        if self._entry is None:
            return

        current = self._entry.get()
        if self._placeholder and current == "":
            self._entry.insert(0, self._placeholder)
            self._entry.config(fg="gray")
            self.set_value("")
            return

        self._entry.config(fg="black")
        self.set_value(current)
        self._apply_highlight(current)

    def _on_key_release(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Обработчик отпускания клавиши.

        Args:
            event: Событие нажатия клавиши (опционально).
        """
        if self._entry is not None:
            current = self._entry.get()
            if self._placeholder and current == self._placeholder:
                return
            self.set_value(current)
            self._apply_highlight(current)

    def _apply_highlight(self, value: str) -> None:
        """Подсвечивает поле красным при невалидном email.

        Args:
            value: Текущее значение.
        """
        if self._entry is None:
            return

        if not value:
            try:
                self._entry.config(
                    highlightbackground="SystemButtonFace", highlightcolor="SystemButtonFace"
                )
            except tk.TclError:
                self._entry.config(highlightbackground="gray", highlightcolor="gray")
            return

        if _EMAIL_PATTERN.match(value):
            try:
                self._entry.config(
                    highlightbackground="SystemButtonFace", highlightcolor="SystemButtonFace"
                )
            except tk.TclError:
                self._entry.config(highlightbackground="gray", highlightcolor="gray")
        else:
            self._entry.config(highlightbackground="red", highlightcolor="red")

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Текущее значение email.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""

        if self._entry is not None:
            current = self._entry.get()
            if current != str_value:
                self._entry.delete(0, tk.END)
                if str_value:
                    self._entry.insert(0, str_value)
                    self._entry.config(fg="black")
                elif self._placeholder:
                    self._entry.insert(0, self._placeholder)
                    self._entry.config(fg="gray")

            self._apply_highlight(str_value)

        super().set_value(str_value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        value_str = str(self._value) if self._value is not None else ""
        if value_str == "":
            return super().validate()

        if not _EMAIL_PATTERN.match(value_str):
            self._update_validation_state(
                False,
                [f"Поле '{self._field_def.label}' содержит неверный email"],
            )
            return False

        return super().validate()

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


__all__: list[str] = ["EmailWidget"]
