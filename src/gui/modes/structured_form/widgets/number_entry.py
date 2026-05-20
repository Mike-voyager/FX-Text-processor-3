"""Поле ввода числа с валидацией для STRUCTURED_FORM режима.

Предоставляет:
- NumberEntry: Entry с валидацией чисел (int/float), min/max clamping.

Features:
- validatecommand: только цифры, точка/запятая
- При потере фокуса — clamp к min/max, вызов on_change

Example:
    >>> entry = NumberEntry(
    ...     parent=frame,
    ...     field_id="amount",
    ...     label="Сумма",
    ...     min_value=0.0,
    ...     max_value=999999.99,
    ...     decimal_places=2,
    ...     on_change=on_changed,
    ... )
    >>> entry.pack(fill=tk.X)
    >>> entry.set_value(123.45)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Callable, Optional

from src.gui.modes.structured_form.widgets.base_field import BaseField

logger: logging.Logger = logging.getLogger(__name__)


class NumberEntry(BaseField):
    """Числовое поле ввода с валидацией и clamping.

    Attributes:
        min_value: Минимально допустимое значение.
        max_value: Максимально допустимое значение.
        decimal_places: Количество десятичных знаков (None = любое).

    Example:
        >>> entry = NumberEntry(parent, field_id="qty", label="Кол-во")
        >>> entry.pack(fill=tk.X)
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        label: str,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
        decimal_places: Optional[int] = None,
        on_change: Optional[Callable[[str, Any], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация числового поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Идентификатор поля.
            label: Текст метки поля.
            min_value: Минимальное значение (None = без ограничения).
            max_value: Максимальное значение (None = без ограничения).
            decimal_places: Количество десятичных знаков (None = любое).
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

        self._min_value: Optional[Decimal] = (
            Decimal(str(min_value)) if min_value is not None else None
        )
        self._max_value: Optional[Decimal] = (
            Decimal(str(max_value)) if max_value is not None else None
        )
        self._decimal_places: Optional[int] = decimal_places
        self._entry: Optional[tk.Entry] = None

        self._create_content()

    def _create_content(self) -> None:
        """Создаёт виджет Entry с числовой валидацией."""
        self._entry = tk.Entry(
            self,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
            justify=tk.RIGHT,
        )
        self._entry.pack(fill=tk.X, expand=True)

        # validatecommand: только цифры, точка/запятая, минус
        self._entry.config(
            validate="key",
            validatecommand=(self.register(self._validate_input), "%P"),
        )

        self._entry.bind("<KeyRelease>", self._on_key_release)
        self._entry.bind("<FocusOut>", self._on_focus_out)

    def _validate_input(self, new_value: str) -> bool:
        """Проверяет допустимость ввода символа.

        Args:
            new_value: Новое значение после ввода.

        Returns:
            True если ввод допустим на данном этапе.
        """
        if new_value == "":
            return True

        # Разрешаем: цифры, одну точку/запятую, минус в начале
        pattern = r"^-?\d*[.,]?\d*$"
        if not re.match(pattern, new_value):
            return False

        # Не более одной точки/запятой
        if new_value.count(".") + new_value.count(",") > 1:
            return False

        # Минус только в начале
        if "-" in new_value[1:]:
            return False

        return True

    def _on_key_release(self, event: tk.Event[Any]) -> None:
        """Обновляет внутреннее значение при наборе.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._entry is not None:
            text = self._entry.get().replace(",", ".")
            if text == "" or text == "-":
                self._value = None
            else:
                try:
                    self._value = Decimal(text)
                except (InvalidOperation, ValueError, TypeError):
                    logger.debug("Failed to parse decimal value: %s", text)
                    self._value = None

    def _on_focus_out(self, event: tk.Event[Any]) -> None:
        """Обработчик потери фокуса: clamp и on_change.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._entry is None:
            return

        text = self._entry.get().replace(",", ".")
        if text == "" or text == "-":
            self._value = None
            self._entry.delete(0, tk.END)
        else:
            try:
                value = Decimal(text)
                self._value = self._clamp_and_round(value)
                formatted = self._format_value(self._value)
                self._entry.delete(0, tk.END)
                self._entry.insert(0, formatted)
            except (ValueError, TypeError, InvalidOperation):
                logger.debug("Failed to format/clamp value: %s", text)
                self._value = None

        if self._on_change is not None:
            self._on_change(self.field_id, self._value)

    def _clamp_and_round(self, value: Decimal) -> Decimal:
        """Применяет min/max и округление.

        Args:
            value: Исходное числовое значение.

        Returns:
            Значение после clamping и округления.
        """
        if self._min_value is not None and value < self._min_value:
            value = self._min_value
        if self._max_value is not None and value > self._max_value:
            value = self._max_value
        if self._decimal_places is not None:
            value = value.quantize(
                Decimal("1." + "0" * self._decimal_places), rounding=ROUND_HALF_UP
            )
        return value

    def _format_value(self, value: Decimal) -> str:
        """Форматирует значение для отображения.

        Args:
            value: Числовое значение.

        Returns:
            Строка с заменой точки на запятую (русский формат).
        """
        text = str(value)
        return text.replace(".", ",")

    def get_value(self) -> Optional[Decimal]:
        """Возвращает текущее числовое значение.

        Returns:
            Decimal значение или None.
        """
        if isinstance(self._value, Decimal):
            return self._value
        return None

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое числовое значение.
        """
        if value is None or value == "":
            self._value = None
            if self._entry is not None:
                self._entry.delete(0, tk.END)
        else:
            try:
                d = Decimal(str(value))
                self._value = self._clamp_and_round(d)
                if self._entry is not None:
                    self._entry.delete(0, tk.END)
                    self._entry.insert(0, self._format_value(self._value))
            except (InvalidOperation, ValueError, TypeError):
                logger.debug("Failed to parse/set value: %s", value)
                self._value = None

        if self._on_change is not None:
            self._on_change(self.field_id, self._value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        if self._value is None:
            self._is_valid = True
            self.set_error(None)
            return True

        errors: list[str] = []
        if self._min_value is not None and self._value < self._min_value:
            errors.append(f"Значение должно быть не менее {self._min_value}")
        if self._max_value is not None and self._value > self._max_value:
            errors.append(f"Значение должно быть не более {self._max_value}")

        self._is_valid = len(errors) == 0
        if not self._is_valid:
            self.set_error("; ".join(errors))
        else:
            self.set_error(None)
        return self._is_valid

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода."""
        if self._entry is not None:
            self._entry.focus_set()


__all__: list[str] = ["NumberEntry"]
