"""Inline-виджет группы радиокнопок для STRUCTURED_FORM режима.

Предоставляет:
- InlineRadioGroupField: группа радиокнопок, наследует BaseField.

Example:
    >>> field = InlineRadioGroupField(
    ...     parent=frame,
    ...     field_id="priority",
    ...     label="Приоритет",
    ...     options=("Низкий", "Средний", "Высокий"),
    ...     on_change=on_field_change,
    ... )
    >>> field.pack(fill=tk.X)
    >>> field.set_value("Средний")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.gui.modes.structured_form.widgets.base_field import BaseField


class InlineRadioGroupField(BaseField):
    """Inline-группа радиокнопок на базе BaseField.

    Attributes:
        _var: Переменная выбранного значения.
        _options: Доступные опции.
        _radiobuttons: Список виджетов Radiobutton.
        _buttons_frame: Фрейм для размещения кнопок.

    Example:
        >>> field = InlineRadioGroupField(parent, field_id="type", label="Тип", options=("A", "B"))
        >>> field.set_value("A")
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        label: str,
        options: Optional[tuple[str, ...]] = None,
        required: bool = False,
        readonly: bool = False,
        on_change: Optional[Callable[[str, Any], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация inline-группы радиокнопок.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Уникальный идентификатор поля.
            label: Текст метки поля.
            options: Допустимые значения.
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
        self._options: tuple[str, ...] = options or ()
        initial_value = self._options[0] if self._options else ""
        self._var: tk.StringVar = tk.StringVar(master=self, value=initial_value)
        self._radiobuttons: list[tk.Radiobutton] = []
        self._buttons_frame: Optional[tk.Frame] = None

        self._create_content()

    def _create_content(self) -> None:
        """Создаёт радиокнопки внутри фрейма."""
        self._buttons_frame = tk.Frame(self)
        self._buttons_frame.pack(fill=tk.X, expand=True)

        for option in self._options:
            rb = tk.Radiobutton(
                self._buttons_frame,
                text=option,
                variable=self._var,
                value=option,
                command=self._on_selection_changed,
                font=("TkDefaultFont", 10),
                anchor=tk.W,
            )
            rb.pack(anchor=tk.W, pady=1)
            self._radiobuttons.append(rb)

            if self._readonly:
                rb.config(state="disabled")

    def _on_selection_changed(self) -> None:
        """Обработчик изменения выбора."""
        value = self._var.get()
        self._value = value
        if self._on_change is not None:
            self._on_change(self.field_id, value)

    def get_value(self) -> str:
        """Возвращает текущее выбранное значение.

        Returns:
            Строка с выбранной опцией.
        """
        return str(self._var.get())

    def set_value(self, value: Any) -> None:
        """Устанавливает значение группы радиокнопок.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""
        if str_value and self._options and str_value not in self._options:
            str_value = self._options[0] if self._options else ""

        self._var.set(str_value)
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

        if self._options and value not in self._options:
            self.set_error(f"Значение должно быть одним из: {', '.join(self._options)}")
            return False

        self.set_error(None)
        return True

    def focus(self) -> None:
        """Устанавливает фокус на первую радиокнопку."""
        if self._radiobuttons:
            self._radiobuttons[0].focus_set()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные поля.

        Security:
            Сбрасывает выбранное значение и очищает состояние виджета.
        """
        self._var.set("")
        self._value = None
        self.set_error(None)


__all__: list[str] = ["InlineRadioGroupField"]
