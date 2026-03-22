"""Тесты для built-in типа INV (invoice).

Покрытие:
- INV type definition
- STRUCTURED_FORM mode
- Index template (INV-SERIES-SEQ)
- Field schema
"""

from __future__ import annotations

import pytest
from src.documents.types.builtin.invoice import INV
from src.documents.types.document_type import DocumentMode
from src.documents.types.index_template import SegmentType
from src.documents.types.type_schema import FieldType


class TestINVType:
    """Тесты для INV типа."""

    def test_inv_code(self) -> None:
        """Код типа INV."""
        assert INV.code == "INV"

    def test_inv_name(self) -> None:
        """Название типа INV."""
        assert INV.name == "Счёт"

    def test_inv_is_root(self) -> None:
        """INV — корневой тип."""
        assert INV.is_root is True
        assert INV.parent_code is None

    def test_inv_structured_form_mode(self) -> None:
        """INV — STRUCTURED_FORM режим."""
        assert INV.document_mode == DocumentMode.STRUCTURED_FORM


class TestINVIndexTemplate:
    """Тесты шаблона индекса INV."""

    def test_inv_has_index_template(self) -> None:
        """INV имеет шаблон индекса."""
        assert INV.index_template is not None

    def test_inv_index_segments_count(self) -> None:
        """INV имеет 3 сегмента."""
        assert INV.index_template is not None
        assert len(INV.index_template.segments) == 3

    def test_inv_index_segment_types(self) -> None:
        """Типы сегментов: ROOT_CODE, SERIES, SEQUENCE."""
        assert INV.index_template is not None
        segments = INV.index_template.segments
        assert segments[0].segment_type == SegmentType.ROOT_CODE
        assert segments[1].segment_type == SegmentType.SERIES
        assert segments[2].segment_type == SegmentType.SEQUENCE

    def test_inv_index_segment_names(self) -> None:
        """Имена сегментов."""
        assert INV.index_template is not None
        segments = INV.index_template.segments
        assert segments[0].name == "type"
        assert segments[1].name == "series"
        assert segments[2].name == "seq"

    def test_inv_index_last_is_sequence(self) -> None:
        """Последний сегмент — SEQUENCE."""
        assert INV.index_template is not None
        assert INV.index_template.sequence_segment.segment_type == SegmentType.SEQUENCE

    def test_inv_index_separator(self) -> None:
        """Сепаратор — дефис."""
        assert INV.index_template is not None
        assert INV.index_template.separator == "-"


class TestINVFieldSchema:
    """Тесты схемы полей INV."""

    def test_inv_has_fields(self) -> None:
        """INV имеет поля."""
        assert len(INV.field_schema.fields) > 0

    def test_inv_invoice_number_field(self) -> None:
        """Поле invoice_number."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "invoice_number" for f in fields)

    def test_inv_date_field(self) -> None:
        """Поле date."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "date" for f in fields)

    def test_inv_supplier_field(self) -> None:
        """Поле supplier."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "supplier" for f in fields)

    def test_inv_buyer_field(self) -> None:
        """Поле buyer."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "buyer" for f in fields)

    def test_inv_items_table_field(self) -> None:
        """Поле items_table."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "items_table" for f in fields)

    def test_inv_subtotal_field(self) -> None:
        """Поле subtotal."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "subtotal" for f in fields)

    def test_inv_vat_field(self) -> None:
        """Поле vat."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "vat" for f in fields)

    def test_inv_total_field(self) -> None:
        """Поле total (вычисляемое)."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "total" for f in fields)

    def test_inv_payment_details_field(self) -> None:
        """Поле payment_details."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "payment_details" for f in fields)

    def test_inv_signature_field(self) -> None:
        """Поле signature."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "signature" for f in fields)

    def test_inv_stamp_field(self) -> None:
        """Поле stamp."""
        fields = INV.field_schema.fields
        assert any(f.field_id == "stamp" for f in fields)


class TestINVFieldTypes:
    """Тесты типов полей INV."""

    def test_invoice_number_is_text_input(self) -> None:
        """invoice_number — TEXT_INPUT."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "invoice_number")
        assert field.field_type == FieldType.TEXT_INPUT
        assert field.required is True

    def test_date_is_date_input(self) -> None:
        """date — DATE_INPUT."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "date")
        assert field.field_type == FieldType.DATE_INPUT

    def test_items_table_is_table(self) -> None:
        """items_table — TABLE."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "items_table")
        assert field.field_type == FieldType.TABLE

    def test_subtotal_is_currency(self) -> None:
        """subtotal — CURRENCY."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "subtotal")
        assert field.field_type == FieldType.CURRENCY

    def test_vat_is_currency(self) -> None:
        """vat — CURRENCY."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "vat")
        assert field.field_type == FieldType.CURRENCY

    def test_total_is_calculated(self) -> None:
        """total — CALCULATED."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "total")
        assert field.field_type == FieldType.CALCULATED

    def test_payment_details_is_multi_line(self) -> None:
        """payment_details — MULTI_LINE_TEXT."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "payment_details")
        assert field.field_type == FieldType.MULTI_LINE_TEXT
        assert field.required is False

    def test_signature_is_signature(self) -> None:
        """signature — SIGNATURE."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "signature")
        assert field.field_type == FieldType.SIGNATURE
        assert field.required is False

    def test_stamp_is_stamp(self) -> None:
        """stamp — STAMP."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "stamp")
        assert field.field_type == FieldType.STAMP
        assert field.required is False


class TestINVFieldValidations:
    """Тесты валидаций полей INV."""

    def test_invoice_number_validation(self) -> None:
        """Валидация invoice_number."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "invoice_number")
        assert field.validation_pattern is not None

    def test_supplier_inn_validation(self) -> None:
        """Валидация supplier_inn."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "supplier_inn")
        assert field.validation_pattern is not None
        # Паттерн для ИНН: 10 или 12 цифр
        assert r"^\d{10}|\d{12}$" == field.validation_pattern

    def test_buyer_inn_validation(self) -> None:
        """Валидация buyer_inn."""
        field = next(f for f in INV.field_schema.fields if f.field_id == "buyer_inn")
        assert field.validation_pattern is not None


class TestINVNoSubtypes:
    """Тесты подтипов INV."""

    def test_inv_no_subtypes(self) -> None:
        """INV без подтипов."""
        assert INV.has_subtypes is False
        assert INV.subtypes == ()


class TestINVFrozen:
    """Тесты неизменяемости INV."""

    def test_inv_is_frozen(self) -> None:
        """INV immutable."""
        with pytest.raises(AttributeError):
            INV.code = "NEW"  # type: ignore
