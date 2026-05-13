"""Виджет многострочного текстового поля.

Предоставляет:
- MultiLineWidget: многострочный текст с прокруткой

Example:
    >>> widget = MultiLineWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value("Line 1\\nLine 2")
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class MultiLineWidget(BaseFieldWidget):
    """Многострочный текст.

    Attributes:
        _text_widget: Tkinter Text widget.
        _scrollbar: Scrollbar для текстового поля.
        _height: Высота виджета в строках.
        _placeholder: Текст-подсказка.

    Example:
        >>> widget = MultiLineWidget(parent, field_def, height=5)
        >>> widget.set_value("Line 1\\nLine 2")
        >>> widget.get_value()
        'Line 1\nLine 2'
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        height: int = 4,
    ) -> None:
        """Инициализация многострочного поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            height: Высота виджета в строках.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._height: int = height
        self._text_widget: Optional[tk.Text] = None
        self._scrollbar: Optional[tk.Scrollbar] = None
        self._placeholder: str = field_def.placeholder or ""
        self._is_placeholder_active: bool = False

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет многострочного текста.

        Returns:
            Frame с Text widget и scrollbar.
        """
        frame = tk.Frame(self._main_frame)

        # Create text widget
        self._text_widget = tk.Text(
            frame,
            height=self._height,
            wrap=tk.WORD,
            font=("Courier", 10),
            relief=tk.SUNKEN,
            borderwidth=1,
            undo=True,
            maxundo=-1,
        )

        # Create scrollbar
        self._scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=self._text_widget.yview)
        self._text_widget.config(yscrollcommand=self._scrollbar.set)

        # Layout
        self._text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Set initial value or placeholder
        if self._field_def.default_value is not None:
            self._text_widget.insert("1.0", str(self._field_def.default_value))
            self._value = str(self._field_def.default_value)
        elif self._placeholder:
            self._text_widget.insert("1.0", self._placeholder)
            self._text_widget.config(fg="gray")
            self._is_placeholder_active = True

        # Bind events
        self._text_widget.bind("<FocusIn>", self._on_focus_in)
        self._text_widget.bind("<FocusOut>", self._on_focus_out)
        self._text_widget.bind("<KeyRelease>", self._on_value_changed)

        # Apply readonly state
        if self._field_def.readonly:
            self._text_widget.config(state="disabled")

        return frame

    def _on_focus_in(self, event: tk.Event[Any]) -> None:
        """Обработчик получения фокуса.

        Args:
            event: Событие фокуса.
        """
        if self._text_widget and self._is_placeholder_active:
            self._text_widget.delete("1.0", tk.END)
            self._text_widget.config(fg="black")
            self._is_placeholder_active = False

    def _on_focus_out(self, event: tk.Event[Any]) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие потери фокуса.
        """
        if self._text_widget and self._placeholder:
            current = self._text_widget.get("1.0", tk.END).strip()
            if not current:
                self._text_widget.insert("1.0", self._placeholder)
                self._text_widget.config(fg="gray")
                self._is_placeholder_active = True

        # Update value on focus out
        self._update_value_from_widget()

    def _on_value_changed(self, event: tk.Event[Any]) -> None:
        """Обработчик изменения значения.

        Args:
            event: Событие изменения.
        """
        if not self._is_placeholder_active:
            self._update_value_from_widget()

    def _update_value_from_widget(self) -> None:
        """Обновляет внутреннее значение из виджета."""
        if self._text_widget is not None and not self._is_placeholder_active:
            value = self._text_widget.get("1.0", tk.END).rstrip("\n")
            super().set_value(value)

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Текст из виджета.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""

        # Update text widget if exists and differs
        if self._text_widget is not None:
            current = self._text_widget.get("1.0", tk.END).rstrip("\n")
            if current != str_value:
                self._text_widget.delete("1.0", tk.END)
                if str_value:
                    self._text_widget.insert("1.0", str_value)
                    self._text_widget.config(fg="black")
                    self._is_placeholder_active = False
                elif self._placeholder:
                    self._text_widget.insert("1.0", self._placeholder)
                    self._text_widget.config(fg="gray")
                    self._is_placeholder_active = True

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

        # Check max_length (for multiline, check total length)
        if self._field_def.max_length is not None:
            if len(value) > self._field_def.max_length:
                self._update_validation_state(
                    False, [f"Текст должен быть не более {self._field_def.max_length} символов"]
                )
                return False

        # Check validation pattern
        if self._field_def.validation_pattern and value:
            import re

            try:
                if not re.match(self._field_def.validation_pattern, value, re.MULTILINE):
                    self._update_validation_state(False, ["Текст не соответствует шаблону"])
                    return False
            except re.error:
                pass  # Invalid regex pattern

        self._update_validation_state(True, [])
        return True

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        if self._text_widget is not None:
            font_size = max(8, min(14, 14 - (self._cpi - 10) // 2))
            self._text_widget.config(font=("Courier", font_size))

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        if self._text_widget is not None:
            self._text_widget.delete("1.0", tk.END)
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на текстовое поле."""
        if self._text_widget is not None:
            self._text_widget.focus_set()

    def append_text(self, text: str) -> None:
        """Добавляет текст в конец поля.

        Args:
            text: Текст для добавления.
        """
        if self._text_widget is not None:
            if self._is_placeholder_active:
                self._text_widget.delete("1.0", tk.END)
                self._text_widget.config(fg="black")
                self._is_placeholder_active = False
            self._text_widget.insert(tk.END, text)
            self._update_value_from_widget()

    def clear(self) -> None:
        """Очищает текстовое поле."""
        if self._text_widget is not None:
            self._text_widget.delete("1.0", tk.END)
            if self._placeholder:
                self._text_widget.insert("1.0", self._placeholder)
                self._text_widget.config(fg="gray")
                self._is_placeholder_active = True
            self._value = ""

    def get_line_count(self) -> int:
        """Возвращает количество строк.

        Returns:
            Количество строк в тексте.
        """
        if self._text_widget is not None:
            return int(self._text_widget.index(tk.END).split(".")[0]) - 1
        return 0


__all__: list[str] = [
    "MultiLineWidget",
]
