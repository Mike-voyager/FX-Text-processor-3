"""Тесты для CalculatedWidget.

Author: AI Agent
Date: 2026-05-04
"""

from __future__ import annotations

import tkinter as tk

import pytest
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets.calculated_widget import (
    CalculatedWidget,
    FormulaSecurityError,
)


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestCalculatedWidget:
    """Тесты для CalculatedWidget."""

    @pytest.fixture
    def field_def(self) -> FieldDefinition:
        """Создаёт тестовое определение вычисляемого поля."""
        return FieldDefinition(
            field_id="total",
            field_type=FieldType.CALCULATED,
            label="Итого",
            formula="price * quantity",
            default_value="0.00",
        )

    @pytest.fixture
    def widget(self, root: tk.Tk, field_def: FieldDefinition) -> CalculatedWidget:
        """Создаёт виджет для тестирования."""
        widget = CalculatedWidget(
            parent=root,
            field_def=field_def,
        )
        widget.mount(root)
        root.update_idletasks()
        return widget

    def test_widget_creation(self, widget: CalculatedWidget) -> None:
        """Тест создания виджета."""
        assert widget._value_label is not None
        assert widget.field_id == "total"
        assert widget.field_type == FieldType.CALCULATED

    def test_formula_preprocessing(self, widget: CalculatedWidget) -> None:
        """Тест предварительной обработки формулы."""
        processed = widget._preprocess_formula("price * quantity")
        assert processed == "price * quantity"

        processed_with_brackets = widget._preprocess_formula("{price} * {quantity}")
        assert processed_with_brackets == "price * quantity"

    def test_recalculate_basic(self, widget: CalculatedWidget) -> None:
        """Тест пересчёта с простой формулой."""
        widget.recalculate({"price": 100, "quantity": 2})
        assert pytest.approx(widget.get_value()) == 200.0

    def test_recalculate_with_brackets(self, root: tk.Tk) -> None:
        """Тест пересчёта с фигурными скобками."""
        field_def = FieldDefinition(
            field_id="sum",
            field_type=FieldType.CALCULATED,
            label="Сумма",
            formula="{a} + {b}",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)

        widget.recalculate({"a": 10, "b": 5})
        assert pytest.approx(widget.get_value()) == 15.0

    def test_recalculate_arithmetic(self, root: tk.Tk) -> None:
        """Тест всех базовых арифметических операций."""
        tests = [
            ("a + b", {"a": 10, "b": 3}, 13.0),
            ("a - b", {"a": 10, "b": 3}, 7.0),
            ("a * b", {"a": 10, "b": 3}, 30.0),
            ("a / b", {"a": 10, "b": 2}, 5.0),
            ("a // b", {"a": 10, "b": 3}, 3.0),
            ("a % b", {"a": 10, "b": 3}, 1.0),
            ("a ** b", {"a": 2, "b": 3}, 8.0),
        ]
        for formula, context, expected in tests:
            field_def = FieldDefinition(
                field_id="calc",
                field_type=FieldType.CALCULATED,
                label="Тест",
                formula=formula,
            )
            widget = CalculatedWidget(parent=root, field_def=field_def)
            widget.mount(root)
            widget.recalculate(context)
            assert pytest.approx(widget.get_value()) == expected, f"Failed: {formula}"

    def test_recalculate_parens(self, root: tk.Tk) -> None:
        """Тест скобок."""
        field_def = FieldDefinition(
            field_id="calc",
            field_type=FieldType.CALCULATED,
            label="Тест",
            formula="(a + b) * c",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)
        widget.recalculate({"a": 2, "b": 3, "c": 4})
        assert pytest.approx(widget.get_value()) == 20.0

    def test_recalculate_unary(self, root: tk.Tk) -> None:
        """Тест унарных операторов."""
        field_def = FieldDefinition(
            field_id="calc",
            field_type=FieldType.CALCULATED,
            label="Тест",
            formula="-a + +b",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)
        widget.recalculate({"a": 5, "b": 3})
        assert pytest.approx(widget.get_value()) == -2.0

    def test_recalculate_division_by_zero(self, root: tk.Tk) -> None:
        """Тест деления на ноль — результат пустой строкой."""
        field_def = FieldDefinition(
            field_id="div",
            field_type=FieldType.CALCULATED,
            label="Div",
            formula="price / quantity",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)
        widget.recalculate({"price": 10, "quantity": 0})
        result = widget.get_value()
        assert result == "" or result is None

    def test_recalculate_missing_field(self, widget: CalculatedWidget) -> None:
        """Тест несуществующего поля — результат пустой строкой."""
        widget.recalculate({"price": 10})
        result = widget.get_value()
        assert result == "" or result is None

    def test_recalculate_empty_formula(self, root: tk.Tk) -> None:
        """Тест пустой формулы."""
        field_def = FieldDefinition(
            field_id="empty",
            field_type=FieldType.CALCULATED,
            label="Пусто",
            formula="",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)
        widget.recalculate({})
        assert widget.get_value() == "" or widget.get_value() is None

    def test_recalculate_string_values(self, widget: CalculatedWidget) -> None:
        """Тест что строковые значения конвертируются в float."""
        widget.recalculate({"price": "100", "quantity": "2.5"})
        assert pytest.approx(widget.get_value()) == 250.0

    def test_security_banned_names(self, root: tk.Tk) -> None:
        """Тест запрета опасных имён."""
        field_def = FieldDefinition(
            field_id="bad",
            field_type=FieldType.CALCULATED,
            label="Bad",
            formula="__import__('os').system('ls')",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)
        # recalculate перехватывает FormulaSecurityError и показывает пустое значение
        widget.recalculate({})
        assert widget.get_value() == "" or widget.get_value() is None

    def test_eval_is_not_called(self, widget: CalculatedWidget) -> None:
        """Проверка что eval() не вызывается."""
        # Если eval вызывается с опасным кодом — произойдёт ошибка из-за запрета AST
        widget._formula = "__import__('os').system('echo pwned')"
        widget.recalculate({})
        assert widget.get_value() == "" or widget.get_value() is None

    def test_formula_with_excel_prefix(self, root: tk.Tk) -> None:
        """Тест формулы с Excel префиксом '='."""
        field_def = FieldDefinition(
            field_id="excel",
            field_type=FieldType.CALCULATED,
            label="Excel",
            formula="=a + b",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)
        widget.recalculate({"a": 5, "b": 10})
        assert pytest.approx(widget.get_value()) == 15.0

    def test_display_formatting(self, root: tk.Tk) -> None:
        """Тест форматирования чисел при отображении."""
        field_def = FieldDefinition(
            field_id="money",
            field_type=FieldType.CALCULATED,
            label="Деньги",
            formula="a * b",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def, decimal_places=2)
        widget.mount(root)
        widget.recalculate({"a": 3, "b": 3})
        assert pytest.approx(widget.get_value()) == 9.0
        assert widget._value_label is not None
        assert "9.00" in widget._value_label.cget("text")

    def test_validate_always_true(self, widget: CalculatedWidget) -> None:
        """Вычисляемое поле всегда валидно."""
        assert widget.validate() is True

    def test_wipe_sensitive_data(self, widget: CalculatedWidget) -> None:
        """Тест очистки чувствительных данных."""
        widget.recalculate({"price": 100, "quantity": 2})
        assert widget.get_value() is not None

        widget.wipe_sensitive_data()
        assert widget.get_value() is None or widget.get_value() == ""
        assert widget._value_label is not None
        assert widget._value_label.cget("text") == ""

    def test_formula_with_invalid_braces(self, root: tk.Tk) -> None:
        """Тест некорректного содержимого в скобках."""
        field_def = FieldDefinition(
            field_id="bad",
            field_type=FieldType.CALCULATED,
            label="Bad",
            formula="{price stuff} * 2",
        )
        widget = CalculatedWidget(parent=root, field_def=field_def)
        widget.mount(root)
        # recalculate перехватывает синтаксические ошибки
        widget.recalculate({})
        assert widget.get_value() == "" or widget.get_value() is None

    def test_on_change_not_fired(self, root: tk.Tk, field_def: FieldDefinition) -> None:
        """Тест что recalculate не генерирует on_change."""
        calls: list[tuple[str, object]] = []

        def on_change(field_id: str, value: object) -> None:
            calls.append((field_id, value))

        widget = CalculatedWidget(
            parent=root,
            field_def=field_def,
            on_change=on_change,
        )
        widget.mount(root)
        widget.recalculate({"price": 10, "quantity": 2})
        assert len(calls) == 0
