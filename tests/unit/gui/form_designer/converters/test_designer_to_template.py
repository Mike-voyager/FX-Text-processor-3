"""Тесты для DesignerToTemplateConverter.

Module: tests/unit/gui/form_designer/converters/test_designer_to_template.py
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, Mock

import pytest

from src.documents.constructor.form_constructor import FormTemplate
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.form_designer.converters import DesignerToTemplateConverter
from src.gui.form_designer.types import DesignerPage
from src.gui.renderers.form_canvas import FieldPosition, FormFieldWidget
from src.services.paper_format_service import PaperProfile


class TestDesignerToTemplateConverter:
    """Тесты для DesignerToTemplateConverter."""

    @pytest.fixture
    def converter(self) -> DesignerToTemplateConverter:
        """Фикстура для конвертера."""
        return DesignerToTemplateConverter()

    @pytest.fixture
    def mock_profile(self) -> MagicMock:
        """Мок для профиля бумаги."""
        profile = MagicMock(spec=PaperProfile)
        profile.name = "a4_tractor"
        return profile

    def test_convert_empty_pages(self, converter: DesignerToTemplateConverter) -> None:
        """Конвертация пустых страниц создаёт пустой шаблон."""
        pages: list[DesignerPage] = []

        template = converter.convert(pages)

        assert isinstance(template, FormTemplate)
        assert template.field_defaults == {}
        assert template.metadata["page_count"] == 0

    def test_convert_single_field(
        self,
        converter: DesignerToTemplateConverter,
        mock_profile: MagicMock,
    ) -> None:
        """Конвертация одного поля."""
        field_def = FieldDefinition(
            field_id="test_field",
            field_type=FieldType.TEXT_INPUT,
            label="Test Label",
            required=True,
        )
        position = FieldPosition(row=5, col=10, width=20, height=1)
        field_widget = FormFieldWidget(
            field_id="test_field",
            field_def=field_def,
            position=position,
        )

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=MagicMock(),
            frame=MagicMock(),
            fields=[field_widget],
        )

        template = converter.convert([page])

        assert "test_field" in template.field_defaults
        field_data = template.field_defaults["test_field"]
        assert field_data["field_id"] == "test_field"
        assert field_data["field_type"] == "text_input"
        assert field_data["label"] == "Test Label"
        assert field_data["required"] is True
        assert field_data["position"]["page"] == 0
        assert field_data["position"]["row"] == 5
        assert field_data["position"]["col"] == 10
        assert field_data["position"]["width"] == 20
        assert field_data["position"]["height"] == 1

    def test_convert_multiple_pages(
        self,
        converter: DesignerToTemplateConverter,
        mock_profile: MagicMock,
    ) -> None:
        """Конвертация полей на нескольких страницах."""
        field1 = FormFieldWidget(
            field_id="field1",
            field_def=MagicMock(spec=FieldDefinition),
            position=FieldPosition(row=0, col=0, width=10, height=1),
        )
        field1.field_def.field_type = FieldType.TEXT_INPUT
        field1.field_def.label = "Field 1"
        field1.field_def.required = False
        field1.field_def.label_i18n = {}
        field1.field_def.readonly = False
        field1.field_def.default_value = None
        field1.field_def.validation_pattern = None
        field1.field_def.max_length = None
        field1.field_def.options = None
        field1.field_def.min_value = None
        field1.field_def.max_value = None
        field1.field_def.min_date = None
        field1.field_def.max_date = None
        field1.field_def.required_if = None
        field1.field_def.help_text = None
        field1.field_def.placeholder = None
        field1.field_def.tab_index = None

        field2 = FormFieldWidget(
            field_id="field2",
            field_def=MagicMock(spec=FieldDefinition),
            position=FieldPosition(row=0, col=0, width=10, height=1),
        )
        field2.field_def.field_type = FieldType.NUMBER_INPUT
        field2.field_def.label = "Field 2"
        field2.field_def.required = True
        field2.field_def.label_i18n = {}
        field2.field_def.readonly = False
        field2.field_def.default_value = None
        field2.field_def.validation_pattern = None
        field2.field_def.max_length = None
        field2.field_def.options = None
        field2.field_def.min_value = 0
        field2.field_def.max_value = 100
        field2.field_def.min_date = None
        field2.field_def.max_date = None
        field2.field_def.required_if = None
        field2.field_def.help_text = None
        field2.field_def.placeholder = None
        field2.field_def.tab_index = None

        page1 = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=MagicMock(),
            frame=MagicMock(),
            fields=[field1],
        )
        page2 = DesignerPage(
            index=1,
            profile=mock_profile,
            canvas=MagicMock(),
            frame=MagicMock(),
            fields=[field2],
        )

        template = converter.convert([page1, page2])

        assert len(template.field_defaults) == 2
        assert "field1" in template.field_defaults
        assert "field2" in template.field_defaults
        assert template.field_defaults["field1"]["position"]["page"] == 0
        assert template.field_defaults["field2"]["position"]["page"] == 1
        assert template.metadata["page_count"] == 2

    def test_convert_with_metadata(self, converter: DesignerToTemplateConverter) -> None:
        """Конвертация с пользовательскими метаданными."""
        pages: list[DesignerPage] = []
        metadata = {
            "type_code": "INVOICE",
            "subtype": "99",
            "series": "INV",
            "custom_key": "custom_value",
        }

        template = converter.convert(pages, metadata)

        assert template.type_code == "INVOICE"
        assert template.subtype == "99"
        assert template.series == "INV"
        assert template.metadata["custom_key"] == "custom_value"

    def test_convert_field_with_dates(
        self,
        converter: DesignerToTemplateConverter,
        mock_profile: MagicMock,
    ) -> None:
        """Конвертация поля с датами."""
        from datetime import date

        field_def = MagicMock(spec=FieldDefinition)
        field_def.field_type = FieldType.DATE_INPUT
        field_def.label = "Date Field"
        field_def.label_i18n = {}
        field_def.required = False
        field_def.readonly = False
        field_def.default_value = None
        field_def.validation_pattern = None
        field_def.max_length = None
        field_def.options = None
        field_def.min_value = None
        field_def.max_value = None
        field_def.min_date = date(2024, 1, 1)
        field_def.max_date = date(2024, 12, 31)
        field_def.required_if = None
        field_def.help_text = None
        field_def.placeholder = None
        field_def.tab_index = None

        field_widget = FormFieldWidget(
            field_id="date_field",
            field_def=field_def,
            position=FieldPosition(row=0, col=0, width=10, height=1),
        )

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=MagicMock(),
            frame=MagicMock(),
            fields=[field_widget],
        )

        template = converter.convert([page])

        field_data = template.field_defaults["date_field"]
        assert field_data["min_date"] == "2024-01-01"
        assert field_data["max_date"] == "2024-12-31"

    def test_convert_field_with_options(
        self,
        converter: DesignerToTemplateConverter,
        mock_profile: MagicMock,
    ) -> None:
        """Конвертация поля с опциями (dropdown)."""
        field_def = MagicMock(spec=FieldDefinition)
        field_def.field_type = FieldType.DROPDOWN
        field_def.label = "Dropdown"
        field_def.label_i18n = {}
        field_def.required = False
        field_def.readonly = False
        field_def.default_value = None
        field_def.validation_pattern = None
        field_def.max_length = None
        field_def.options = ("Option 1", "Option 2", "Option 3")
        field_def.min_value = None
        field_def.max_value = None
        field_def.min_date = None
        field_def.max_date = None
        field_def.required_if = None
        field_def.help_text = None
        field_def.placeholder = None
        field_def.tab_index = None

        field_widget = FormFieldWidget(
            field_id="dropdown_field",
            field_def=field_def,
            position=FieldPosition(row=0, col=0, width=10, height=1),
        )

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=MagicMock(),
            frame=MagicMock(),
            fields=[field_widget],
        )

        template = converter.convert([page])

        field_data = template.field_defaults["dropdown_field"]
        assert field_data["options"] == ("Option 1", "Option 2", "Option 3")

    def test_convert_includes_created_at(self, converter: DesignerToTemplateConverter) -> None:
        """Конвертация добавляет timestamp создания."""
        pages: list[DesignerPage] = []

        template = converter.convert(pages)

        assert "created_at" in template.metadata
        # Verify it's a valid ISO format
        created_at = template.metadata["created_at"]
        parsed = datetime.fromisoformat(created_at)
        assert isinstance(parsed, datetime)

    def test_convert_pages_metadata(
        self,
        converter: DesignerToTemplateConverter,
        mock_profile: MagicMock,
    ) -> None:
        """Конвертация включает метаданные страниц."""
        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=MagicMock(),
            frame=MagicMock(),
            fields=[],
        )

        template = converter.convert([page])

        assert "pages" in template.metadata
        pages_meta = template.metadata["pages"]
        assert len(pages_meta) == 1
        assert pages_meta[0]["index"] == 0
        assert pages_meta[0]["profile_name"] == "a4_tractor"
