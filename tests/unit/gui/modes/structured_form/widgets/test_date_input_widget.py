"""Тесты для DateInputWidget.

Author: Mike Voyager
Date: 2026-04-07
"""

from __future__ import annotations

import tkinter as tk
from datetime import date, datetime

import pytest

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets.date_input_widget import DateInputWidget


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestDateInputWidget:
    """Тесты для DateInputWidget."""

    @pytest.fixture
    def field_def(self) -> FieldDefinition:
        """Создаёт тестовое определение поля даты."""
        return FieldDefinition(
            field_id="test_date",
            field_type=FieldType.DATE_INPUT,
            label="Test Date",
        )

    @pytest.fixture
    def widget(self, root: tk.Tk, field_def: FieldDefinition) -> DateInputWidget:
        """Создаёт виджет для тестирования."""
        widget = DateInputWidget(
            parent=root,
            field_def=field_def,
        )
        widget.mount(root)
        root.update_idletasks()
        return widget

    def test_widget_creation(self, widget: DateInputWidget) -> None:
        """Тест создания виджета."""
        assert widget.field_id == "test_date"
        assert widget.field_type == FieldType.DATE_INPUT

    def test_get_set_value(self, widget: DateInputWidget) -> None:
        """Тест получения/установки значения даты."""
        test_date = date(2026, 4, 7)
        widget.set_value(test_date)

        result = widget.get_value()
        assert isinstance(result, date)
        assert result == test_date

    def test_set_value_string(self, widget: DateInputWidget) -> None:
        """Тест установки значения из строки."""
        widget.set_value("2026-04-07")

        result = widget.get_value()
        assert isinstance(result, date)
        assert result.year == 2026
        assert result.month == 4
        assert result.day == 7

    def test_wipe_sensitive_data(self, widget: DateInputWidget) -> None:
        """Тест очистки sensitive данных."""
        widget.set_value(date(2026, 4, 7))
        assert widget.get_value() is not None

        widget.wipe_sensitive_data()
        assert widget.get_value() is None
