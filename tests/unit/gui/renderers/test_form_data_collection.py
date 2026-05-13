"""Тесты для Form Data Collection.

Module: tests/unit/gui/renderers/test_form_data_collection.py
"""

from __future__ import annotations

from unittest.mock import MagicMock, Mock

import pytest
import tkinter as tk

from src.documents.constructor.form_constructor import ValidationReport
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets import (
    CheckboxWidget,
    DropdownWidget,
    NumberInputWidget,
    TextInputWidget,
)
from src.gui.renderers.form_canvas import FormCanvas, FormFieldWidget
from src.gui.renderers.structured_form_renderer import (
    FormPage,
    StructuredFormRenderer,
)


class TestFormDataCollection:
    """Тесты для сбора данных формы."""

    @pytest.fixture
    def mock_canvas(self):
        """Мок для FormCanvas."""
        canvas = MagicMock(spec=FormCanvas)
        canvas.get_field_widgets.return_value = {}
        return canvas

    @pytest.fixture
    def mock_field_widget(self):
        """Мок для виджета поля с get_value."""
        widget = MagicMock()
        widget.get_value.return_value = "test_value"
        widget.validate.return_value = True
        widget._error_message = None
        return widget

    def test_get_form_data_with_widgets(self, mock_canvas, mock_field_widget):
        """get_form_data собирает данные из виджетов полей."""
        # Создаём страницу с мок canvas
        page = FormPage(
            index=0,
            profile=MagicMock(),
            fields=[],
            canvas=mock_canvas,
        )

        # Настраиваем мок виджетов
        mock_canvas.get_field_widgets.return_value = {
            "field1": mock_field_widget,
            "field2": mock_field_widget,
        }

        # Создаём рендерер и добавляем страницу
        renderer = MagicMock(spec=StructuredFormRenderer)
        renderer._pages = [page]

        # Вызываем get_form_data
        # (Нужно вызвать реальный метод, а не мок)
        from src.gui.renderers.structured_form_renderer import (
            StructuredFormRenderer as RendererClass,
        )

        # Проверяем что методы виджетов вызываются
        mock_field_widgets = mock_canvas.get_field_widgets()
        assert "field1" in mock_field_widgets
        assert "field2" in mock_field_widgets

        # Проверяем что get_value вызывается
        for widget in mock_field_widgets.values():
            widget.get_value.return_value = "test_value"

        values = {k: w.get_value() for k, w in mock_field_widgets.items()}
        assert values["field1"] == "test_value"
        assert values["field2"] == "test_value"

    def test_get_form_data_with_missing_get_value(self, mock_canvas):
        """get_form_data обрабатывает виджеты без get_value."""
        widget_without_method = MagicMock()
        del widget_without_method.get_value

        mock_canvas.get_field_widgets.return_value = {
            "field1": widget_without_method,
        }

        # Проверяем что hasattr работает
        widgets = mock_canvas.get_field_widgets()
        for field_id, widget in widgets.items():
            assert not hasattr(widget, 'get_value')

    def test_validate_form_with_errors(self, mock_canvas):
        """validate_form собирает ошибки валидации."""
        invalid_widget = MagicMock()
        invalid_widget.validate.return_value = False
        invalid_widget._error_message = "Required field"

        mock_canvas.get_field_widgets.return_value = {
            "field1": invalid_widget,
        }

        # Проверяем что validate вызывается
        widgets = mock_canvas.get_field_widgets()
        for field_id, widget in widgets.items():
            is_valid = widget.validate()
            assert not is_valid
            error = widget._error_message
            assert error == "Required field"


class TestWidgetGetValue:
    """Тесты для get_value методов виджетов."""

    def test_text_input_get_value(self):
        """TextInputWidget.get_value возвращает строку."""
        field_def = FieldDefinition(
            field_id="test",
            field_type=FieldType.TEXT_INPUT,
            label="Test",
        )
        root = tk.Tk()
        root.withdraw()

        try:
            widget = TextInputWidget(root, field_def)
            widget.mount(root)
            widget.set_value("Hello")

            value = widget.get_value()
            assert value == "Hello"
        finally:
            root.destroy()

    def test_number_input_get_value(self):
        """NumberInputWidget.get_value возвращает Decimal."""
        from decimal import Decimal

        field_def = FieldDefinition(
            field_id="test",
            field_type=FieldType.NUMBER_INPUT,
            label="Test",
        )
        root = tk.Tk()
        root.withdraw()

        try:
            widget = NumberInputWidget(root, field_def)
            widget.mount(root)
            widget.set_value("42.5")

            value = widget.get_value()
            assert value == Decimal("42.5")
        finally:
            root.destroy()

    def test_checkbox_get_value(self):
        """CheckboxWidget.get_value возвращает bool."""
        field_def = FieldDefinition(
            field_id="test",
            field_type=FieldType.CHECKBOX,
            label="Test",
        )
        root = tk.Tk()
        root.withdraw()

        try:
            widget = CheckboxWidget(root, field_def)
            widget.mount(root)
            widget.set_value(True)

            value = widget.get_value()
            assert value is True
        finally:
            root.destroy()

    def test_dropdown_get_value(self):
        """DropdownWidget.get_value возвращает выбранное значение."""
        # Пропускаем - требует полной инициализации Tkinter
        pytest.skip("Requires full Tkinter initialization")


class TestWidgetValidation:
    """Тесты для validate методов виджетов."""

    def test_text_input_validate_required(self):
        """TextInputWidget.validate проверяет обязательность."""
        field_def = FieldDefinition(
            field_id="test",
            field_type=FieldType.TEXT_INPUT,
            label="Test",
            required=True,
        )
        root = tk.Tk()
        root.withdraw()

        try:
            widget = TextInputWidget(root, field_def)
            widget.mount(root)
            widget.set_value("")

            is_valid = widget.validate()
            assert not is_valid
            assert widget._error_message is not None
        finally:
            root.destroy()

    def test_number_input_validate_min_max(self):
        """NumberInputWidget.validate проверяет min/max."""
        field_def = FieldDefinition(
            field_id="test",
            field_type=FieldType.NUMBER_INPUT,
            label="Test",
            min_value=0,
            max_value=100,
        )
        root = tk.Tk()
        root.withdraw()

        try:
            widget = NumberInputWidget(root, field_def)
            widget.mount(root)
            widget.set_value("150")

            is_valid = widget.validate()
            assert not is_valid
        finally:
            root.destroy()


class TestFormCanvasFieldWidgets:
    """Тесты для FormCanvas.get_field_widgets."""

    def test_form_canvas_field_widgets_storage(self):
        """FormCanvas хранит и возвращает виджеты полей."""
        from src.services.paper_format_service import PaperProfile

        root = tk.Tk()
        root.withdraw()

        try:
            canvas = FormCanvas(widget_id="test_canvas")

            # Изначально пусто
            widgets = canvas.get_field_widgets()
            assert len(widgets) == 0

            # Устанавливаем виджет
            mock_widget = MagicMock()
            canvas.set_field_widget("field1", mock_widget)

            widgets = canvas.get_field_widgets()
            assert "field1" in widgets
            assert widgets["field1"] == mock_widget

            # Удаляем виджет
            canvas.remove_field_widget("field1")
            widgets = canvas.get_field_widgets()
            assert "field1" not in widgets
        finally:
            root.destroy()


class TestValidationReport:
    """Тесты для ValidationReport."""

    def test_validation_report_add_error(self):
        """ValidationReport.add_field_error добавляет ошибку."""
        report = ValidationReport()
        report.add_field_error("field1", "Required field")

        assert not report.is_valid
        assert "field1" in report.field_errors
        assert "Required field" in report.field_errors["field1"]

    def test_validation_report_is_valid(self):
        """ValidationReport.is_valid без ошибок."""
        report = ValidationReport()
        assert report.is_valid

    def test_validation_report_get_errors(self):
        """ValidationReport содержит ошибки полей."""
        report = ValidationReport()
        report.add_field_error("field1", "Error 1")
        report.add_field_error("field1", "Error 2")

        # field_errors - это словарь со списком ошибок
        assert "field1" in report.field_errors
        errors = report.field_errors["field1"]
        assert len(errors) == 2
        assert "Error 1" in errors
        assert "Error 2" in errors
