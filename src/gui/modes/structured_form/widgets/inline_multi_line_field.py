"""Inline-виджет многострочного текста для STRUCTURED_FORM режима.

Предоставляет:
- InlineMultiLineField: tk.Text (height=4), наследует BaseField.

Example:
    >>> field = InlineMultiLineField(
    ...     parent=frame,
    ...     field_id="notes",
    ...     label="Примечания",
    ...         on_change=on_field_change,
    ...     )
    >>> field.pack(fill=tk.X)
    >>> field.set_value("Строка 1\nСтрока 2")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.gui.modes.structured_form.widgets.base_field import BaseField


class InlineMultiLineField(BaseField):
    """Inline-многострочное текстовое поле на базе BaseField.

    Attributes:
        _text_widget: Виджет tk.Text.
        _scrollbar: Полоса прокрутки.
        _required: Флаг обязательности.
        _max_length: Максимальная длина текста.
        _placeholder: Текст-подсказка.
        _is_placeholder_active: Активна ли подсказка.

    Example:
        >>> field = InlineMultiLineField(parent, field_id="desc", label="Описание")
        >>> field.set_value("Текст")
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        label: str,
        required: bool = False,
        readonly: bool = False,
        max_length: Optional[int] = None,
        placeholder: str = "",
        on_change: Optional[Callable[[str, Any], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация inline-многострочного поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Уникальный идентификатор поля.
            label: Текст метки поля.
            required: Обязательность поля.
            readonly: Только для чтения.
            max_length: Максимальная длина текста.
            placeholder: Текст-подсказка.
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
        self._max_length: Optional[int] = max_length
        self._placeholder: str = placeholder
        self._is_placeholder_active: bool = False
        self._text_widget: Optional[tk.Text] = None
        self._scrollbar: Optional[tk.Scrollbar] = None

        self._create_content()

    def _create_content(self) -> None:
        """Создаёт Text widget со scrollbar."""
        container = tk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True)

        self._text_widget = tk.Text(
            container,
            height=4,
            wrap=tk.WORD,
            font=("Courier", 10),
            relief=tk.SUNKEN,
            borderwidth=1,
            undo=True,
            maxundo=-1,
        )
        self._text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._scrollbar = tk.Scrollbar(
            container, orient=tk.VERTICAL, command=self._text_widget.yview
        )
        self._text_widget.config(yscrollcommand=self._scrollbar.set)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        if self._placeholder:
            self._text_widget.insert("1.0", self._placeholder)
            self._text_widget.config(fg="gray")
            self._is_placeholder_active = True

        self._text_widget.bind("<FocusIn>", self._on_focus_in)
        self._text_widget.bind("<FocusOut>", self._on_focus_out)
        self._text_widget.bind("<KeyRelease>", self._on_value_changed)

        if self._readonly:
            self._text_widget.config(state="disabled")

    def _on_focus_in(self, event: tk.Event[Any]) -> None:
        """Убирает placeholder при получении фокуса.

        Args:
            event: Событие фокуса.
        """
        _ = event
        if self._text_widget and self._is_placeholder_active:
            self._text_widget.delete("1.0", tk.END)
            self._text_widget.config(fg="black")
            self._is_placeholder_active = False

    def _on_focus_out(self, event: tk.Event[Any]) -> None:
        """Восстанавливает placeholder если поле пустое.

        Args:
            event: Событие потери фокуса.
        """
        _ = event
        if self._text_widget and self._placeholder:
            current = self._text_widget.get("1.0", tk.END).rstrip("\n")
            if not current:
                self._text_widget.insert("1.0", self._placeholder)
                self._text_widget.config(fg="gray")
                self._is_placeholder_active = True
        self._update_value()

    def _on_value_changed(self, event: tk.Event[Any]) -> None:
        """Обновляет значение при наборе текста.

        Args:
            event: Событие клавиши.
        """
        _ = event
        if not self._is_placeholder_active:
            self._update_value()

    def _update_value(self) -> None:
        """Считывает значение из Text и вызывает on_change."""
        if self._text_widget is not None and not self._is_placeholder_active:
            value = self._text_widget.get("1.0", tk.END).rstrip("\n")
            self._value = value
            if self._on_change is not None:
                self._on_change(self.field_id, value)

    def get_value(self) -> str:
        """Возвращает текущий текст.

        Returns:
            Текст из виджета без завершающего переноса строки.
        """
        if self._text_widget is not None and not self._is_placeholder_active:
            return self._text_widget.get("1.0", tk.END).rstrip("\n")
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает текст в поле.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""

        if self._text_widget is not None:
            self._text_widget.delete("1.0", tk.END)
            if str_value:
                self._text_widget.insert("1.0", str_value)
                self._text_widget.config(fg="black")
                self._is_placeholder_active = False
            elif self._placeholder:
                self._text_widget.insert("1.0", self._placeholder)
                self._text_widget.config(fg="gray")
                self._is_placeholder_active = True

        self._value = str_value
        if self._on_change is not None:
            self._on_change(self.field_id, str_value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        value = self.get_value()

        if not value and self._required:
            self.set_error("Поле обязательно для заполнения")
            return False

        if self._max_length is not None and len(value) > self._max_length:
            self.set_error(f"Текст должен быть не более {self._max_length} символов")
            return False

        self.set_error(None)
        return True

    def focus(self) -> None:
        """Устанавливает фокус на текстовое поле."""
        if self._text_widget is not None:
            self._text_widget.focus_set()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные поля."""
        if self._text_widget is not None:
            self._text_widget.delete("1.0", tk.END)
        self._value = ""
        self.set_error(None)


__all__: list[str] = ["InlineMultiLineField"]
