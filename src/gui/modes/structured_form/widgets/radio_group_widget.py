"""Виджет группы радиокнопок.

Предоставляет:
- RadioGroupWidget: группа радиокнопок с горизонтальным или вертикальным layout

Example:
    >>> widget = RadioGroupWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change,
    ...     orientation="horizontal"
    ... )
    >>> widget.set_value("option1")
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Literal, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class RadioGroupWidget(BaseFieldWidget):
    """Группа радиокнопок.

    Attributes:
        _var: Переменная для выбранного значения.
        _radiobuttons: Список радиокнопок.
        _orientation: Ориентация группы (horizontal/vertical).
        _frame: Frame для размещения радиокнопок.

    Example:
        >>> widget = RadioGroupWidget(parent, field_def, orientation="horizontal")
        >>> widget.set_value("option1")
        >>> widget.get_value()
        'option1'
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        orientation: Literal["horizontal", "vertical"] = "vertical",
    ) -> None:
        """Инициализация группы радиокнопок.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            orientation: Ориентация группы (horizontal или vertical).
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._orientation: Literal["horizontal", "vertical"] = orientation
        self._var: tk.StringVar = tk.StringVar(master=parent)
        self._radiobuttons: list[tk.Radiobutton] = []
        self._frame: Optional[tk.Frame] = None
        self._options: tuple[str, ...] = field_def.options or ()

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет группы радиокнопок.

        Returns:
            Frame с радиокнопками.
        """
        self._frame = tk.Frame(self._main_frame)

        # Create radiobuttons for each option
        self._radiobuttons = []

        for i, option in enumerate(self._options):
            rb = tk.Radiobutton(
                self._frame,
                text=option,
                variable=self._var,
                value=option,
                command=self._on_selection_changed,
                font=("TkDefaultFont", 10),
                anchor=tk.W,
            )

            if self._orientation == "horizontal":
                rb.grid(row=0, column=i, sticky=tk.W, padx=(0, 10))
            else:
                rb.grid(row=i, column=0, sticky=tk.W, pady=2)

            self._radiobuttons.append(rb)

            # Apply readonly state
            if self._field_def.readonly:
                rb.config(state="disabled")

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

        return self._frame

    def _on_selection_changed(self) -> None:
        """Обработчик изменения выбора."""
        value = self._var.get()
        super().set_value(value)

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Выбранное значение или пустая строка.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение группы радиокнопок.

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
        font_size = max(8, min(12, 12 - (self._cpi - 10) // 2))
        for rb in self._radiobuttons:
            rb.config(font=("TkDefaultFont", font_size))

    def set_options(self, options: list[str]) -> None:
        """Обновляет список опций.

        Args:
            options: Новый список опций.
        """
        self._options = tuple(options)

        # Destroy old radiobuttons
        for rb in self._radiobuttons:
            rb.destroy()
        self._radiobuttons.clear()

        # Create new radiobuttons
        if self._frame is not None:
            for i, option in enumerate(self._options):
                rb = tk.Radiobutton(
                    self._frame,
                    text=option,
                    variable=self._var,
                    value=option,
                    command=self._on_selection_changed,
                    font=("TkDefaultFont", 10),
                    anchor=tk.W,
                )

                if self._orientation == "horizontal":
                    rb.grid(row=0, column=i, sticky=tk.W, padx=(0, 10))
                else:
                    rb.grid(row=i, column=0, sticky=tk.W, pady=2)

                self._radiobuttons.append(rb)

                # Apply readonly state
                if self._field_def.readonly:
                    rb.config(state="disabled")

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

    def set_orientation(self, orientation: Literal["horizontal", "vertical"]) -> None:
        """Изменяет ориентацию группы.

        Args:
            orientation: Новая ориентация.
        """
        if self._orientation == orientation:
            return

        self._orientation = orientation

        # Re-grid radiobuttons
        for i, rb in enumerate(self._radiobuttons):
            rb.grid_forget()
            if self._orientation == "horizontal":
                rb.grid(row=0, column=i, sticky=tk.W, padx=(0, 10))
            else:
                rb.grid(row=i, column=0, sticky=tk.W, pady=2)

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        if self._var is not None:
            self._var.set("")
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на первую радиокнопку."""
        if self._radiobuttons:
            self._radiobuttons[0].focus_set()


__all__: list[str] = [
    "RadioGroupWidget",
]
