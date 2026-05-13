"""Виджет поля ввода телефона с маской.

Предоставляет:
- PhoneWidget: поле ввода телефона с форматированием
  по маске +X (XXX) XXX-XX-XX или +X XXX XXX-XX-XX.

Example:
    >>> widget = PhoneWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change,
    ... )
    >>> widget.set_value("+79031234567")
"""

from __future__ import annotations

import re
import tkinter as tk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class PhoneWidget(BaseFieldWidget):
    """Поле ввода телефона с маской.

    Attributes:
        _entry: Tkinter Entry widget для ввода телефона.
        _mask: Строка маски (X -- цифра).
        _placeholder: Подсказка в поле.

    Example:
        >>> widget = PhoneWidget(parent, field_def)
        >>> widget.set_value("+79031234567")
        >>> widget.get_value()
        '+7 (903) 123-45-67'
    """

    _DEFAULT_MASK: str = "+X (XXX) XXX-XX-XX"
    _ALT_MASK: str = "+X XXX XXX-XX-XX"

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        mask: Optional[str] = None,
    ) -> None:
        """Инициализация виджета телефона.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            mask: Маска форматирования (по умолчанию +X (XXX) XXX-XX-XX).
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._mask: str = mask if mask is not None else self._DEFAULT_MASK
        self._entry: Optional[tk.Entry] = None
        self._placeholder: str = field_def.placeholder or ""

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет поля телефона.

        Returns:
            Tkinter Entry widget с маской ввода.
        """
        frame = tk.Frame(self._main_frame)

        self._entry = tk.Entry(
            frame,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
        )

        # Валидация ввода на лету
        self._entry.config(
            validate="key",
            validatecommand=(frame.register(self._validate_input), "%P"),
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
            raw = self._extract_digits(str(self._field_def.default_value))
            formatted = self._apply_mask(raw)
            self._entry.delete(0, tk.END)
            self._entry.insert(0, formatted)
            self._entry.config(fg="black")
            self._value = formatted

        # Readonly
        if self._field_def.readonly:
            self._entry.config(state="readonly")

        return frame

    def _validate_input(self, new_value: str) -> bool:
        """Проверяет допустимость вводимых символов.

        Args:
            new_value: Новое значение поля.

        Returns:
            True если ввод допустим.
        """
        if new_value == "":
            return True
        # Разрешаем цифры, +, -, (, ), пробел
        return bool(re.fullmatch(r"[\d\+\-\(\) ]*", new_value))

    def _extract_digits(self, text: str) -> str:
        """Извлекает только цифры из строки.

        Args:
            text: Исходная строка.

        Returns:
            Строка, содержащая только цифры.
        """
        return "".join(ch for ch in text if ch.isdigit())

    def _apply_mask(self, digits: str) -> str:
        """Применяет маску к строке цифр.

        Args:
            digits: Строка из цифр.

        Returns:
            Отформатированная строка по маске.
        """
        result: list[str] = []
        digit_index: int = 0
        for ch in self._mask:
            if ch == "X":
                if digit_index < len(digits):
                    result.append(digits[digit_index])
                    digit_index += 1
                else:
                    break
            else:
                if digit_index < len(digits):
                    result.append(ch)
                else:
                    break
        return "".join(result)

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
        """Обработчик потери фокуса: форматирование.

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

        digits = self._extract_digits(current)
        formatted = self._apply_mask(digits)
        if self._entry.get() != formatted:
            self._entry.delete(0, tk.END)
            self._entry.insert(0, formatted)
        self._entry.config(fg="black")
        self.set_value(formatted)

    def _on_key_release(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Обработчик отпускания клавиши.

        Args:
            event: Событие нажатия клавиши (опционально).
        """
        if self._entry is not None:
            current = self._entry.get()
            if self._placeholder and current == self._placeholder:
                return
            digits = self._extract_digits(current)
            formatted = self._apply_mask(digits)
            if current != formatted:
                # Восстанавливаем позицию курсора относительно длины
                cursor = self._entry.index(tk.INSERT)
                self._entry.delete(0, tk.END)
                self._entry.insert(0, formatted)
                new_cursor = min(cursor, len(formatted))
                self._entry.icursor(new_cursor)
            self.set_value(formatted)

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Отформатированное значение телефона.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""
        digits = self._extract_digits(str_value)
        formatted = self._apply_mask(digits)

        if self._entry is not None:
            current = self._entry.get()
            if current != formatted:
                self._entry.delete(0, tk.END)
                if formatted:
                    self._entry.insert(0, formatted)
                    self._entry.config(fg="black")
                elif self._placeholder:
                    self._entry.insert(0, self._placeholder)
                    self._entry.config(fg="gray")

        super().set_value(formatted)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        if self._value is None or self._value == "":
            return super().validate()

        digits = self._extract_digits(str(self._value))
        # Минимум цифр по маске
        min_digits = self._mask.count("X")
        if len(digits) < min_digits:
            self._update_validation_state(
                False,
                [f"Поле '{self._field_def.label}' должно содержать {min_digits} цифр"],
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


__all__: list[str] = ["PhoneWidget"]
