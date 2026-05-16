"""Виджет поля штрих-кода.

Предоставляет:
- BarcodeWidget: поле ввода данных штрих-кода с отображением
  (software через SoftwareBarcodeRenderer или hardware placeholder).

Example:
    >>> widget = BarcodeWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change,
    ...     barcode_type="EAN-13",
    ...     barcode_mode="software",
    ... )
    >>> widget.set_value("5901234123457")
    >>> widget.validate()
    True
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Final, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget
from src.gui.renderers.barcode_canvas_renderer import SoftwareBarcodeRenderer

# =============================================================================
# CONSTANTS
# =============================================================================

_BARCODE_TYPES: Final[frozenset[str]] = frozenset({"EAN-13", "EAN-8", "CODE39", "CODE128"})
_TYPE_MAP: Final[dict[str, str]] = {
    "EAN-13": "EAN13",
    "EAN-8": "EAN8",
    "CODE39": "CODE39",
    "CODE128": "CODE128",
}
_CODE39_ALLOWED: Final[frozenset[str]] = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%")


# =============================================================================
# WIDGET
# =============================================================================


class BarcodeWidget(BaseFieldWidget):
    """Виджет поля штрих-кода для Structured Form.

    Attributes:
        _barcode_type: Тип штрих-кода (EAN-13, EAN-8, CODE39, CODE128).
        _barcode_mode: Режим отображения ('software' или 'hardware').
        _renderer: Рендерер для software-режима.
        _entry: Поле ввода данных.
        _display_canvas: Canvas для software-рендеринга.
        _display_label: Label для hardware-режима.
        _insert_btn: Кнопка подтверждения вставки.

    Example:
        >>> widget = BarcodeWidget(parent, field_def)
        >>> widget.set_value("5901234123457")
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        barcode_type: str = "EAN-13",
        barcode_mode: str = "hardware",
    ) -> None:
        """Инициализация виджета штрих-кода.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения (field_id, value).
            on_validate: Callback при валидации.
            barcode_type: Тип штрих-кода.
            barcode_mode: Режим отображения ('software' или 'hardware').
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._barcode_type: str = barcode_type if barcode_type in _BARCODE_TYPES else "EAN-13"
        self._barcode_mode: str = (
            barcode_mode if barcode_mode in {"software", "hardware"} else "hardware"
        )
        self._renderer: Optional[SoftwareBarcodeRenderer] = None
        self._entry: Optional[tk.Entry] = None
        self._display_canvas: Optional[tk.Canvas] = None
        self._display_label: Optional[tk.Label] = None
        self._insert_btn: Optional[tk.Button] = None

    def _create_widget(self) -> tk.Widget:
        """Создаёт составной виджет с Entry, отображением и кнопкой.

        Returns:
            Frame с элементами управления штрих-кодом.
        """
        if self._main_frame is None:
            raise AssertionError("_main_frame is not set")
        frame = tk.Frame(self._main_frame)

        # Поле ввода данных
        self._entry = tk.Entry(
            frame,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
        )
        self._entry.pack(fill=tk.X, expand=True, pady=(0, 4))

        # Привязка горячих клавиш
        self._entry.bind("<Return>", self._on_insert)
        self._entry.bind("<FocusOut>", self._on_focus_out)

        # Canvas для software-рендеринга
        self._display_canvas = tk.Canvas(
            frame,
            height=100,
            bg="white",
            highlightthickness=1,
            highlightbackground="#cccccc",
        )

        # Метка для hardware-режима (placeholder)
        self._display_label = tk.Label(
            frame,
            text="",
            font=("Courier", 10),
            bg="#fff3cd",
            fg="#856404",
            relief=tk.SOLID,
            borderwidth=1,
            padx=4,
            pady=4,
        )

        # Кнопка подтверждения
        self._insert_btn = tk.Button(
            frame,
            text="Insert",
            command=lambda: self._on_insert(),
        )
        self._insert_btn.pack(anchor=tk.E, pady=(0, 4))

        # Переключение отображения по режиму
        if self._barcode_mode == "software":
            self._renderer = SoftwareBarcodeRenderer(self._display_canvas)
            self._display_canvas.pack(fill=tk.X, expand=True, pady=(0, 4))
        else:
            self._display_label.pack(fill=tk.X, expand=True, pady=(0, 4))

        # Начальное значение
        if self._field_def.default_value is not None:
            self._entry.delete(0, tk.END)
            self._entry.insert(0, str(self._field_def.default_value))
            self._entry.config(fg="black")

        # Readonly
        if self._field_def.readonly:
            self._entry.config(state="readonly")
            self._insert_btn.config(state="disabled")

        return frame

    def _on_insert(self, event: Optional[Any] = None) -> None:
        """Обработчик подтверждения ввода (кнопка или Enter).

        Валидирует данные штрих-кода и обновляет состояние поля.

        Args:
            event: Событие Tkinter (при вызове по bind), иначе None.
        """
        if self._entry is None:
            return

        data = self._entry.get().strip()
        if not data:
            self.set_value("")
            self.set_error("Данные штрих-кода не могут быть пустыми")
            return

        is_valid, error_msg = self._validate_barcode_data(self._barcode_type, data)
        if not is_valid:
            self.set_error(error_msg or "Некорректные данные штрих-кода")
            return

        self.set_error(None)
        self.set_value(data)

    def _on_focus_out(self, event: Optional[Any] = None) -> None:
        """Обработчик потери фокуса для запуска валидации.

        Args:
            event: Событие Tkinter.
        """
        self._on_insert(event)

    @staticmethod
    def _validate_barcode_data(barcode_type: str, data: str) -> tuple[bool, Optional[str]]:
        """Валидирует данные штрих-кода согласно типу.

        Args:
            barcode_type: Тип штрих-кода.
            data: Строка данных для проверки.

        Returns:
            Кортеж (валидно, сообщение_об_ошибке).
        """
        if barcode_type in ("EAN-13", "EAN13"):
            if not data.isdigit():
                return False, "EAN-13 должен содержать только цифры"
            if len(data) != 13:
                return False, "EAN-13 должен содержать ровно 13 цифр"
            expected = BarcodeWidget._calculate_ean_checksum(data[:-1])
            if expected != int(data[-1]):
                return False, "Неверная контрольная сумма EAN-13"
            return True, None

        if barcode_type in ("EAN-8", "EAN8"):
            if not data.isdigit():
                return False, "EAN-8 должен содержать только цифры"
            if len(data) != 8:
                return False, "EAN-8 должен содержать ровно 8 цифр"
            expected = BarcodeWidget._calculate_ean_checksum(data[:-1])
            if expected != int(data[-1]):
                return False, "Неверная контрольная сумма EAN-8"
            return True, None

        if barcode_type == "CODE39":
            if not data:
                return False, "CODE39 не может быть пустым"
            invalid_chars = set(data) - _CODE39_ALLOWED
            if invalid_chars:
                return (
                    False,
                    f"Недопустимые символы для CODE39: {''.join(sorted(invalid_chars))}",
                )
            return True, None

        if barcode_type == "CODE128":
            if not data:
                return False, "CODE128 не может быть пустым"
            return True, None

        return False, f"Неизвестный тип штрих-кода: {barcode_type}"

    @staticmethod
    def _calculate_ean_checksum(digits: str) -> int:
        """Вычисляет контрольную сумму EAN по алгоритму mod 10.

        Реализует стандартный алгоритм GTIN (UCC/EAN-128).

        Args:
            digits: Цифры без контрольной суммы.

        Returns:
            Контрольная цифра (0–9).
        """
        total = sum(int(d) * (3 if i % 2 == 0 else 1) for i, d in enumerate(reversed(digits)))
        return (10 - (total % 10)) % 10

    def _update_display(self, data: str) -> None:
        """Обновляет визуальное представление штрих-кода.

        Args:
            data: Подтверждённые данные штрих-кода.
        """
        if self._barcode_mode == "hardware":
            if self._display_label is not None:
                self._display_label.config(text=f"[Barcode: {self._barcode_type} - {data}]")
            return

        if self._renderer is not None and self._display_canvas is not None:
            self._renderer.clear()
            self._renderer.render(
                barcode_type=_TYPE_MAP.get(self._barcode_type, "EAN13"),
                data=data,
                x=10,
                y=10,
                width=180,
                height=80,
                show_text=True,
            )

    def get_value(self) -> str:
        """Возвращает текущее значение поля.

        Returns:
            Строка с данными штрих-кода.
        """
        if self._value is None:
            return ""
        return str(self._value)

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля и обновляет отображение.

        Args:
            value: Новые данные штрих-кода.
        """
        str_value = str(value) if value is not None else ""

        if self._entry is not None:
            current = self._entry.get()
            if current != str_value:
                self._entry.delete(0, tk.END)
                if str_value:
                    self._entry.insert(0, str_value)
                    self._entry.config(fg="black")

        super().set_value(str_value)
        self._update_display(str_value)

    def validate(self) -> bool:
        """Валидирует текущее значение штрих-кода.

        Returns:
            True если значение соответствует типу штрих-кода.
        """
        value = self.get_value()
        if not value:
            if not self._field_def.required:
                self.set_error(None)
                return True
            self.set_error(f"Поле '{self._field_def.label}' обязательно для заполнения")
            return False

        is_valid, error_msg = self._validate_barcode_data(self._barcode_type, value)
        if not is_valid:
            self.set_error(error_msg or "Некорректные данные штрих-кода")
            return False

        # Дополнительная валидация полей (pattern, max_length и т.д.)
        self.set_error(None)
        return super().validate()

    def _update_font(self) -> None:
        """Обновляет шрифт поля ввода."""
        if self._entry is not None:
            font_size = max(8, min(14, 14 - (self._cpi - 10) // 2))
            self._entry.config(font=("Courier", font_size))

    def wipe_sensitive_data(self) -> None:
        """Очищает чувствительные данные поля.

        Security:
            Удаляет текст из Entry и очищает canvas.
        """
        if self._entry is not None:
            self._entry.delete(0, tk.END)
        if self._renderer is not None and self._display_canvas is not None:
            self._renderer.clear()
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода."""
        if self._entry is not None:
            self._entry.focus_set()


__all__ = ["BarcodeWidget"]
