"""Тесты для TemplateToDesignerConverter.

Module: tests/unit/gui/form_designer/converters/test_template_to_designer.py
"""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, Mock

import pytest

from src.documents.constructor.form_constructor import FormTemplate
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.form_designer.converters import TemplateToDesignerConverter
from src.gui.form_designer.types import DesignerPage
from src.gui.renderers.form_canvas import FieldPosition, FormCanvas, FormFieldWidget
from src.services.paper_format_service import PaperProfile


class TestTemplateToDesignerConverter:
    """Тесты для TemplateToDesignerConverter."""

    @pytest.fixture
    def canvas_factory(self):
        """Фабрика для создания мок canvas."""
        def factory():
            canvas = MagicMock(spec=FormCanvas)
            canvas.create_field = Mock()
            return canvas
        return factory

    @pytest.fixture
    def converter(self, canvas_factory) -> TemplateToDesignerConverter:
        """Фикстура для конвертера."""
        return TemplateToDesignerConverter(canvas_factory=canvas_factory)

    def test_convert_empty_template(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация пустого шаблона."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={},
        )

        pages = converter.convert(template)

        assert pages == []

    def test_convert_single_field(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация одного поля."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "test_field": {
                    "field_id": "test_field",
                    "field_type": "text_input",
                    "label": "Test Label",
                    "required": True,
                    "position": {
                        "page": 0,
                        "row": 5,
                        "col": 10,
                        "width": 20,
                        "height": 1,
                    },
                }
            },
        )

        pages = converter.convert(template)

        assert len(pages) == 1
        page = pages[0]
        assert isinstance(page, DesignerPage)
        assert page.index == 0
        assert len(page.fields) == 1

        field_widget = page.fields[0]
        assert field_widget.field_id == "test_field"
        assert field_widget.field_def.field_type == FieldType.TEXT_INPUT
        assert field_widget.field_def.label == "Test Label"
        assert field_widget.field_def.required is True
        assert field_widget.position.row == 5
        assert field_widget.position.col == 10
        assert field_widget.position.width == 20
        assert field_widget.position.height == 1

    def test_convert_multiple_pages(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация полей на нескольких страницах."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "field1": {
                    "field_id": "field1",
                    "field_type": "text_input",
                    "label": "Field 1",
                    "required": False,
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                },
                "field2": {
                    "field_id": "field2",
                    "field_type": "number_input",
                    "label": "Field 2",
                    "required": True,
                    "position": {"page": 1, "row": 0, "col": 0, "width": 10, "height": 1},
                },
            },
        )

        pages = converter.convert(template)

        assert len(pages) == 2
        assert pages[0].index == 0
        assert pages[1].index == 1
        assert len(pages[0].fields) == 1
        assert len(pages[1].fields) == 1

    def test_convert_field_with_dates(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация поля с датами."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "date_field": {
                    "field_id": "date_field",
                    "field_type": "date_input",
                    "label": "Date Field",
                    "required": False,
                    "min_date": "2024-01-01",
                    "max_date": "2024-12-31",
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                }
            },
        )

        pages = converter.convert(template)

        field_widget = pages[0].fields[0]
        assert field_widget.field_def.min_date == date(2024, 1, 1)
        assert field_widget.field_def.max_date == date(2024, 12, 31)

    def test_convert_field_with_options(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация поля с опциями."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "dropdown_field": {
                    "field_id": "dropdown_field",
                    "field_type": "dropdown",
                    "label": "Dropdown",
                    "required": False,
                    "options": ["Option 1", "Option 2", "Option 3"],
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                }
            },
        )

        pages = converter.convert(template)

        field_widget = pages[0].fields[0]
        assert field_widget.field_def.options == ("Option 1", "Option 2", "Option 3")

    def test_convert_field_with_i18n_labels(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация поля с мультиязычными метками."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "i18n_field": {
                    "field_id": "i18n_field",
                    "field_type": "text_input",
                    "label": "Name",
                    "label_i18n": {"ru": "Имя", "de": "Name"},
                    "required": False,
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                }
            },
        )

        pages = converter.convert(template)

        field_widget = pages[0].fields[0]
        assert field_widget.field_def.label == "Name"
        assert field_widget.field_def.label_i18n == {"ru": "Имя", "de": "Name"}

    def test_convert_page_profile_from_metadata(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация использует профиль из метаданных страницы."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "field1": {
                    "field_id": "field1",
                    "field_type": "text_input",
                    "label": "Field 1",
                    "required": False,
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                }
            },
            metadata={
                "pages": [
                    {"index": 0, "profile_name": "letter_tractor"},
                ]
            },
        )

        pages = converter.convert(template)

        # Page should be created with profile from metadata
        assert len(pages) == 1

    def test_convert_field_with_validation(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация поля с validation pattern и max_length."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "validated_field": {
                    "field_id": "validated_field",
                    "field_type": "text_input",
                    "label": "Validated Field",
                    "required": True,
                    "validation_pattern": r"^[A-Z]{3}-\d{4}$",
                    "max_length": 10,
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                }
            },
        )

        pages = converter.convert(template)

        field_widget = pages[0].fields[0]
        assert field_widget.field_def.validation_pattern == r"^[A-Z]{3}-\d{4}$"
        assert field_widget.field_def.max_length == 10

    def test_convert_field_with_number_constraints(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация числового поля с min/max значениями."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "number_field": {
                    "field_id": "number_field",
                    "field_type": "number_input",
                    "label": "Number",
                    "required": False,
                    "min_value": 0,
                    "max_value": 100,
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                }
            },
        )

        pages = converter.convert(template)

        field_widget = pages[0].fields[0]
        assert field_widget.field_def.field_type == FieldType.NUMBER_INPUT
        assert field_widget.field_def.min_value == 0
        assert field_widget.field_def.max_value == 100

    def test_convert_field_with_help_and_placeholder(self, converter: TemplateToDesignerConverter) -> None:
        """Конвертация поля с help_text и placeholder."""
        template = FormTemplate(
            type_code="CUSTOM",
            subtype="01",
            series="GEN",
            field_defaults={
                "help_field": {
                    "field_id": "help_field",
                    "field_type": "text_input",
                    "label": "Field",
                    "required": False,
                    "help_text": "Enter your full name",
                    "placeholder": "John Doe",
                    "tab_index": 1,
                    "position": {"page": 0, "row": 0, "col": 0, "width": 10, "height": 1},
                }
            },
        )

        pages = converter.convert(template)

        field_widget = pages[0].fields[0]
        assert field_widget.field_def.help_text == "Enter your full name"
        assert field_widget.field_def.placeholder == "John Doe"
        assert field_widget.field_def.tab_index == 1


class TestRoundTripConversion:
    """Тесты для round-trip конвертации (Designer -> Template -> Designer)."""

    @pytest.fixture
    def canvas_factory(self):
        """Фабрика для создания мок canvas."""
        def factory():
            canvas = MagicMock(spec=FormCanvas)
            canvas.create_field = Mock()
            return canvas
        return factory

    def test_round_trip_preserves_field_data(self, canvas_factory) -> None:
        """Round-trip сохраняет данные поля."""
        from src.gui.form_designer.converters import (
            DesignerToTemplateConverter,
            TemplateToDesignerConverter,
        )

        # Create original field
        field_def = FieldDefinition(
            field_id="original_field",
            field_type=FieldType.TEXT_INPUT,
            label="Original Label",
            required=True,
            default_value="Default",
            max_length=50,
        )
        position = FieldPosition(row=5, col=10, width=20, height=1)
        original_field = FormFieldWidget(
            field_id="original_field",
            field_def=field_def,
            position=position,
        )

        mock_profile = MagicMock(spec=PaperProfile)
        mock_profile.name = "a4_tractor"

        original_page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=MagicMock(),
            frame=MagicMock(),
            fields=[original_field],
        )

        # Designer -> Template
        to_template = DesignerToTemplateConverter()
        template = to_template.convert([original_page])

        # Template -> Designer
        to_designer = TemplateToDesignerConverter(canvas_factory=canvas_factory)
        restored_pages = to_designer.convert(template)

        # Verify
        assert len(restored_pages) == 1
        restored_field = restored_pages[0].fields[0]
        assert restored_field.field_id == "original_field"
        assert restored_field.field_def.field_type == FieldType.TEXT_INPUT
        assert restored_field.field_def.label == "Original Label"
        assert restored_field.field_def.required is True
        assert restored_field.field_def.default_value == "Default"
        assert restored_field.field_def.max_length == 50
        assert restored_field.position.row == 5
        assert restored_field.position.col == 10
        assert restored_field.position.width == 20
        assert restored_field.position.height == 1
