"""Тесты для built-in типа DVN (verbal note).

Покрытие:
- DVN type definition
- STRUCTURED_FORM mode
- Index template (DVN-SUBTYPE-SERIES-SEQ)
- Field schema
- Subtypes
"""

from __future__ import annotations

import pytest
from src.documents.types.builtin.verbal_note import DVN
from src.documents.types.document_type import DocumentMode
from src.documents.types.index_template import SegmentType
from src.documents.types.type_schema import FieldType


class TestDVNType:
    """Тесты для DVN типа."""

    def test_dvn_code(self) -> None:
        """Код типа DVN."""
        assert DVN.code == "DVN"

    def test_dvn_name(self) -> None:
        """Название типа DVN."""
        assert DVN.name == "Вербальная нота"

    def test_dvn_is_root(self) -> None:
        """DVN — корневой тип."""
        assert DVN.is_root is True
        assert DVN.parent_code is None

    def test_dvn_structured_form_mode(self) -> None:
        """DVN — STRUCTURED_FORM режим."""
        assert DVN.document_mode == DocumentMode.STRUCTURED_FORM


class TestDVNIndexTemplate:
    """Тесты шаблона индекса DVN."""

    def test_dvn_has_index_template(self) -> None:
        """DVN имеет шаблон индекса."""
        assert DVN.index_template is not None

    def test_dvn_index_segments_count(self) -> None:
        """DVN имеет 4 сегмента."""
        assert DVN.index_template is not None
        assert len(DVN.index_template.segments) == 4

    def test_dvn_index_segment_types(self) -> None:
        """Типы сегментов: ROOT_CODE, SUBTYPE, SERIES, SEQUENCE."""
        assert DVN.index_template is not None
        segments = DVN.index_template.segments
        assert segments[0].segment_type == SegmentType.ROOT_CODE
        assert segments[1].segment_type == SegmentType.SUBTYPE
        assert segments[2].segment_type == SegmentType.SERIES
        assert segments[3].segment_type == SegmentType.SEQUENCE

    def test_dvn_index_segment_names(self) -> None:
        """Имена сегментов."""
        assert DVN.index_template is not None
        segments = DVN.index_template.segments
        assert segments[0].name == "type"
        assert segments[1].name == "subtype"
        assert segments[2].name == "series"
        assert segments[3].name == "seq"

    def test_dvn_index_last_is_sequence(self) -> None:
        """Последний сегмент — SEQUENCE."""
        assert DVN.index_template is not None
        assert DVN.index_template.sequence_segment.segment_type == SegmentType.SEQUENCE

    def test_dvn_index_separator(self) -> None:
        """Сепаратор — дефис."""
        assert DVN.index_template is not None
        assert DVN.index_template.separator == "-"

    def test_dvn_index_example(self) -> None:
        """Пример индекса DVN-44-K53-IX."""
        assert DVN.index_template is not None
        index = DVN.index_template.format(
            values={"type": "DVN", "subtype": "44", "series": "K53"},
            sequence=9,
        )
        assert index == "DVN-44-K53-IX"


class TestDVNFieldSchema:
    """Тесты схемы полей DVN."""

    def test_dvn_has_fields(self) -> None:
        """DVN имеет поля."""
        assert len(DVN.field_schema.fields) > 0

    def test_dvn_index_field(self) -> None:
        """Поле index."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "index")
        assert field is not None
        assert field.required is True
        assert field.readonly is True

    def test_dvn_date_field(self) -> None:
        """Поле date."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "date")
        assert field is not None
        assert field.field_type == FieldType.DATE_INPUT

    def test_dvn_from_entity_field(self) -> None:
        """Поле from_entity."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "from_entity")
        assert field is not None

    def test_dvn_to_entity_field(self) -> None:
        """Поле to_entity."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "to_entity")
        assert field is not None

    def test_dvn_topic_field(self) -> None:
        """Поле topic."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "topic")
        assert field is not None

    def test_dvn_content_field(self) -> None:
        """Поле content."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "content")
        assert field is not None
        assert field.field_type == FieldType.MULTI_LINE_TEXT

    def test_dvn_executor_field(self) -> None:
        """Поле executor."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "executor")
        assert field is not None

    def test_dvn_attachments_field(self) -> None:
        """Поле attachments."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "attachments")
        assert field is not None
        assert field.field_type == FieldType.TABLE

    def test_dvn_signature_field(self) -> None:
        """Поле signature."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "signature")
        assert field is not None
        assert field.field_type == FieldType.SIGNATURE

    def test_dvn_stamp_field(self) -> None:
        """Поле stamp."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "stamp")
        assert field is not None
        assert field.field_type == FieldType.STAMP

    def test_dvn_qr_code_field(self) -> None:
        """Поле qr_code."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "qr_code")
        assert field is not None
        assert field.field_type == FieldType.QR


class TestDVNFieldTypes:
    """Тесты типов полей DVN."""

    def test_index_is_text_input(self) -> None:
        """index — TEXT_INPUT."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "index")
        assert field.field_type == FieldType.TEXT_INPUT

    def test_date_is_date_input(self) -> None:
        """date — DATE_INPUT."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "date")
        assert field.field_type == FieldType.DATE_INPUT

    def test_from_entity_is_text(self) -> None:
        """from_entity — TEXT_INPUT."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "from_entity")
        assert field.field_type == FieldType.TEXT_INPUT

    def test_to_entity_is_text(self) -> None:
        """to_entity — TEXT_INPUT."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "to_entity")
        assert field.field_type == FieldType.TEXT_INPUT

    def test_topic_is_text(self) -> None:
        """topic — TEXT_INPUT."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "topic")
        assert field.field_type == FieldType.TEXT_INPUT

    def test_content_is_multi_line(self) -> None:
        """content — MULTI_LINE_TEXT."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "content")
        assert field.field_type == FieldType.MULTI_LINE_TEXT

    def test_attachments_is_table(self) -> None:
        """attachments — TABLE."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "attachments")
        assert field.field_type == FieldType.TABLE


class TestDVNFieldOptional:
    """Тесты необязательных полей DVN."""

    def test_reference_number_optional(self) -> None:
        """reference_number — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "reference_number")
        assert field.required is False

    def test_reference_date_optional(self) -> None:
        """reference_date — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "reference_date")
        assert field.required is False

    def test_executor_contact_optional(self) -> None:
        """executor_contact — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "executor_contact")
        assert field.required is False

    def test_approved_by_optional(self) -> None:
        """approved_by — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "approved_by")
        assert field.required is False

    def test_attachments_optional(self) -> None:
        """attachments — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "attachments")
        assert field.required is False

    def test_signature_optional(self) -> None:
        """signature — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "signature")
        assert field.required is False

    def test_stamp_optional(self) -> None:
        """stamp — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "stamp")
        assert field.required is False

    def test_qr_code_optional(self) -> None:
        """qr_code — необязательное."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "qr_code")
        assert field.required is False


class TestDVNSubtypes:
    """Тесты подтипов DVN."""

    def test_dvn_has_subtypes(self) -> None:
        """DVN имеет подтипы."""
        assert DVN.has_subtypes is True
        assert len(DVN.subtypes) == 2

    def test_dvn_subtype_01(self) -> None:
        """Подтип 01."""
        subtype = next(s for s in DVN.subtypes if s.code == "01")
        assert subtype.name == "Обычная"

    def test_dvn_subtype_44(self) -> None:
        """Подтип 44."""
        subtype = next(s for s in DVN.subtypes if s.code == "44")
        assert subtype.name == "Специальная"


class TestDVNFrozen:
    """Тесты неизменяемости DVN."""

    def test_dvn_is_frozen(self) -> None:
        """DVN immutable."""
        with pytest.raises(AttributeError):
            DVN.code = "NEW"  # type: ignore


class TestDVNIndexValidation:
    """Тесты валидации индекса DVN."""

    def test_index_field_validation_pattern(self) -> None:
        """Валидация поля index."""
        field = next(f for f in DVN.field_schema.fields if f.field_id == "index")
        assert field.validation_pattern is not None
        assert "DVN" in field.validation_pattern
