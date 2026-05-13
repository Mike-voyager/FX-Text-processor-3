"""Тесты для NumberInputWidget.

Author: Mike Voyager
Date: 2026-04-07
"""

from __future__ import annotations

import tkinter as tk
from decimal import Decimal

import pytest

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets.number_input_widget import NumberInputWidget


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestNumberInputWidget:
    """Тесты для NumberInputWidget."""

    @pytest.fixture
    def number_field(self) -> FieldDefinition:
        """Создаёт тестовое определение числового поля."""
        return FieldDefinition(
            field_id="test_number",
            field_type=FieldType.NUMBER_INPUT,
            label="Test Number",
            min_value="0",
            max_value="1000",
        )

    @pytest.fixture
    def currency_field(self) -> FieldDefinition:
        """Создаёт тестовое определение поля валюты."""
        return FieldDefinition(
            field_id="test_currency",
            field_type=FieldType.CURRENCY,
            label="Test Currency",
            min_value="0.00",
            max_value="1000000.00",
        )

    @pytest.fixture
    def widget(self, root: tk.Tk, number_field: FieldDefinition) -> NumberInputWidget:
        """Создаёт виджет для тестирования."""
        widget = NumberInputWidget(
            parent=root,
            field_def=number_field,
            decimal_places=2,
        )
        widget.mount(root)
        root.update_idletasks()
        return widget

    def test_widget_creation(self, widget: NumberInputWidget) -> None:
        """Тест создания виджета."""
        assert widget._entry is not None
        assert widget._decimal_places == 2

    def test_set_get_value_decimal(self, widget: NumberInputWidget) -> None:
        """Тест установки/получения Decimal значения."""
        widget.set_value(Decimal("123.45"))
        result = widget.get_value()

        assert result is not None
        assert isinstance(result, Decimal)
        assert result == Decimal("123.45")

    def test_set_get_value_int(self, widget: NumberInputWidget) -> None:
        """Тест установки/получения int значения."""
        widget.set_value(42)
        result = widget.get_value()

        assert result is not None
        assert result == Decimal("42")

    def test_set_get_value_float(self, widget: NumberInputWidget) -> None:
        """Тест установки/получения float значения."""
        widget.set_value(3.14159)
        result = widget.get_value()

        assert result is not None
        assert abs(float(result) - 3.14159) < 0.00001

    def test_min_value_validation(self, widget: NumberInputWidget) -> None:
        """Тест валидации минимального значения."""
        widget.set_value(Decimal("-10"))
        assert widget.validate() is False

        widget.set_value(Decimal("0"))
        assert widget.validate() is True

    def test_max_value_validation(self, widget: NumberInputWidget) -> None:
        """Тест валидации максимального значения."""
        widget.set_value(Decimal("1001"))
        assert widget.validate() is False

        widget.set_value(Decimal("1000"))
        assert widget.validate() is True

    def test_invalid_number_validation(self, widget: NumberInputWidget) -> None:
        """Тест валидации некорректного числа."""
        widget.set_value("not a number")
        # get_value должен вернуть None для невалидного значения
        assert widget.get_value() is None

    def test_currency_widget(self, root: tk.Tk, currency_field: FieldDefinition) -> None:
        """Тест виджета валюты."""
        widget = NumberInputWidget(
            parent=root,
            field_def=currency_field,
            decimal_places=2,
            currency_symbol="₽",
        )
        widget.mount(root)

        assert widget._is_currency is True
        assert widget._currency_symbol == "₽"

    def test_required_number_field(self, root: tk.Tk) -> None:
        """Тест обязательного числового поля."""
        field_def = FieldDefinition(
            field_id="required_number",
            field_type=FieldType.NUMBER_INPUT,
            label="Required Number",
            required=True,
        )

        widget = NumberInputWidget(
            parent=root,
            field_def=field_def,
        )
        widget.mount(root)

        # Empty value should fail validation
        widget.set_value(None)
        assert widget.validate() is False

        # Valid value should pass
        widget.set_value(Decimal("100"))
        assert widget.validate() is True

    def test_wipe_sensitive_data(self, widget: NumberInputWidget) -> None:
        """Тест очистки sensitive данных."""
        widget.set_value(Decimal("999999.99"))
        assert widget.get_value() is not None

        widget.wipe_sensitive_data()
        assert widget.get_value() is None

    def test_format_value(self, widget: NumberInputWidget) -> None:
        """Тест форматирования значения."""
        formatted = widget._format_value(Decimal("1234567.89"))

        assert "1" in formatted
        assert "2" in formatted
        assert "." in formatted or "," in formatted

    def test_parse_value(self, widget: NumberInputWidget) -> None:
        """Тест парсинга значения."""
        # Parse formatted number
        parsed = widget._parse_value("1 234 567.89")
        assert parsed == Decimal("1234567.89")

        # Parse simple number
        parsed = widget._parse_value("123.45")
        assert parsed == Decimal("123.45")

        # Parse empty string
        parsed = widget._parse_value("")
        assert parsed is None

    def test_validate_input(self, widget: NumberInputWidget) -> None:
        """Тест валидации ввода."""
        # Valid inputs
        assert widget._validate_input("") is True
        assert widget._validate_input("123") is True
        assert widget._validate_input("-123") is True
        assert widget._validate_input("123.45") is True
        assert widget._validate_input("-123.45") is True

        # Invalid inputs
        assert widget._validate_input("abc") is False
        assert widget._validate_input("12.34.56") is False

    def test_on_change_callback(self, root: tk.Tk, number_field: FieldDefinition) -> None:
        """Тест callback при изменении."""
        callback_calls = []

        def on_change(field_id: str, value: object) -> None:
            callback_calls.append((field_id, value))

        widget = NumberInputWidget(
            parent=root,
            field_def=number_field,
            on_change=on_change,
        )
        widget.mount(root)

        widget.set_value(Decimal("500"))

        # Callback должен быть вызван
        assert len(callback_calls) > 0
        assert callback_calls[-1][0] == "test_number"
