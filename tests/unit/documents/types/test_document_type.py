"""Тесты для модуля document_type.

Покрытие:
- DocumentMode Enum
- DocumentSubtype dataclass
- DocumentType dataclass
- Методы DocumentType
"""

from __future__ import annotations

import pytest
from src.documents.types.document_type import (
    DocumentMode,
    DocumentSubtype,
    DocumentType,
)
from src.documents.types.index_template import IndexSegmentDef, IndexTemplate, SegmentType
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

# ============ DocumentMode Enum Tests ============


class TestDocumentMode:
    """Тесты для DocumentMode Enum."""

    def test_document_mode_values(self) -> None:
        """Проверка значений DocumentMode."""
        assert DocumentMode.FREE_FORM.value == "free_form"
        assert DocumentMode.STRUCTURED_FORM.value == "structured_form"

    def test_document_mode_is_str(self) -> None:
        """Проверка что DocumentMode наследуется от str."""
        assert isinstance(DocumentMode.FREE_FORM, str)
        assert DocumentMode.FREE_FORM.value == "free_form"

    def test_document_mode_comparison(self) -> None:
        """Сравнение DocumentMode."""
        # Проверка что разные enum значения имеют разные строковые значения
        assert DocumentMode.FREE_FORM.value != DocumentMode.STRUCTURED_FORM.value  # type: ignore[comparison-overlap]
        assert DocumentMode.FREE_FORM.value == DocumentMode.FREE_FORM.value


# ============ DocumentSubtype Tests ============


class TestDocumentSubtype:
    """Тесты для DocumentSubtype dataclass."""

    def test_create_subtype_minimal(self) -> None:
        """Создание подтипа с минимальными параметрами."""
        subtype = DocumentSubtype(
            code="01",
            name="Обычный",
        )
        assert subtype.code == "01"
        assert subtype.name == "Обычный"
        assert subtype.extra_fields == ()

    def test_create_subtype_with_extra_fields(self) -> None:
        """Создание подтипа с дополнительными полями."""
        extra = (FieldDefinition("extra", FieldType.TEXT_INPUT, "Extra"),)
        subtype = DocumentSubtype(
            code="special",
            name="Special",
            extra_fields=extra,
        )
        assert subtype.extra_fields == extra

    def test_subtype_frozen(self) -> None:
        """Проверка что DocumentSubtype immutable."""
        subtype = DocumentSubtype(code="01", name="Test")
        with pytest.raises(AttributeError):
            subtype.code = "02"  # type: ignore


# ============ DocumentType Tests ============


class TestDocumentType:
    """Тесты для DocumentType dataclass."""

    def test_create_document_type_minimal(self) -> None:
        """Создание DocumentType с минимальными параметрами."""
        doc_type = DocumentType(
            code="TEST",
            name="Test Type",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        assert doc_type.code == "TEST"
        assert doc_type.name == "Test Type"
        assert doc_type.parent_code is None
        assert doc_type.document_mode == DocumentMode.FREE_FORM
        assert doc_type.index_template is None
        assert doc_type.field_schema.fields == ()
        assert doc_type.subtypes == ()
        assert doc_type.metadata == ()

    def test_create_document_type_full(self) -> None:
        """Создание DocumentType со всеми параметрами."""
        index_template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"TEST",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        subtypes = (
            DocumentSubtype(code="01", name="Subtype 1"),
            DocumentSubtype(code="02", name="Subtype 2"),
        )
        metadata = (("key1", "value1"), ("key2", "value2"))

        doc_type = DocumentType(
            code="FULL",
            name="Full Type",
            parent_code="PARENT",
            document_mode=DocumentMode.STRUCTURED_FORM,
            index_template=index_template,
            field_schema=TypeSchema(
                fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),)
            ),
            subtypes=subtypes,
            metadata=metadata,
        )
        assert doc_type.code == "FULL"
        assert doc_type.name == "Full Type"
        assert doc_type.parent_code == "PARENT"
        assert doc_type.document_mode == DocumentMode.STRUCTURED_FORM
        assert doc_type.index_template == index_template
        assert len(doc_type.field_schema.fields) == 1
        assert doc_type.subtypes == subtypes
        assert doc_type.metadata == metadata


class TestDocumentTypePostInit:
    """Тесты валидации в __post_init__."""

    def test_post_init_empty_code_raises(self) -> None:
        """Пустой код вызывает ValueError."""
        with pytest.raises(ValueError, match="code cannot be empty"):
            DocumentType(
                code="",
                name="Test",
                parent_code=None,
                document_mode=DocumentMode.FREE_FORM,
                index_template=None,
                field_schema=TypeSchema(fields=()),
            )

    def test_post_init_empty_name_raises(self) -> None:
        """Пустое имя вызывает ValueError."""
        with pytest.raises(ValueError, match="name cannot be empty"):
            DocumentType(
                code="TEST",
                name="",
                parent_code=None,
                document_mode=DocumentMode.FREE_FORM,
                index_template=None,
                field_schema=TypeSchema(fields=()),
            )

    def test_post_init_valid(self) -> None:
        """Валидные значения проходят."""
        doc_type = DocumentType(
            code="VALID",
            name="Valid Type",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        assert doc_type.code == "VALID"


class TestDocumentTypeProperties:
    """Тесты свойств DocumentType."""

    def test_is_root_true(self) -> None:
        """is_root возвращает True когда parent_code is None."""
        doc_type = DocumentType(
            code="ROOT",
            name="Root Type",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        assert doc_type.is_root is True

    def test_is_root_false(self) -> None:
        """is_root возвращает False когда parent_code есть."""
        doc_type = DocumentType(
            code="CHILD",
            name="Child Type",
            parent_code="PARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        assert doc_type.is_root is False

    def test_has_subtypes_true(self) -> None:
        """has_subtypes возвращает True когда есть подтипы."""
        doc_type = DocumentType(
            code="WITH_SUBTYPES",
            name="With Subtypes",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            subtypes=(DocumentSubtype(code="01", name="Subtype 1"),),
        )
        assert doc_type.has_subtypes is True

    def test_has_subtypes_false(self) -> None:
        """has_subtypes возвращает False когда нет подтипов."""
        doc_type = DocumentType(
            code="NO_SUBTYPES",
            name="No Subtypes",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        assert doc_type.has_subtypes is False


class TestDocumentTypeGetSubtype:
    """Тесты для DocumentType.get_subtype."""

    def test_get_subtype_exists(self) -> None:
        """Получение существующего подтипа."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            subtypes=(
                DocumentSubtype(code="01", name="First"),
                DocumentSubtype(code="02", name="Second"),
            ),
        )
        subtype = doc_type.get_subtype("02")
        assert subtype is not None
        assert subtype.code == "02"
        assert subtype.name == "Second"

    def test_get_subtype_not_exists(self) -> None:
        """Получение несуществующего подтипа."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            subtypes=(DocumentSubtype(code="01", name="First"),),
        )
        subtype = doc_type.get_subtype("99")
        assert subtype is None

    def test_get_subtype_empty(self) -> None:
        """Получение подтипа когда их нет."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        subtype = doc_type.get_subtype("01")
        assert subtype is None


class TestDocumentTypeGetMetadata:
    """Тесты для DocumentType.get_metadata."""

    def test_get_metadata_exists(self) -> None:
        """Получение существующего значения."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            metadata=(("key1", "value1"), ("key2", "value2")),
        )
        assert doc_type.get_metadata("key1") == "value1"
        assert doc_type.get_metadata("key2") == "value2"

    def test_get_metadata_not_exists(self) -> None:
        """Получение несуществующего значения."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            metadata=(("key1", "value1"),),
        )
        assert doc_type.get_metadata("missing") is None

    def test_get_metadata_empty(self) -> None:
        """Получение из пустых метаданных."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        assert doc_type.get_metadata("any") is None

    def test_get_metadata_complex_value(self) -> None:
        """Получение сложного значения."""
        complex_value = {"nested": "data"}
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            metadata=(("complex", complex_value),),
        )
        assert doc_type.get_metadata("complex") == complex_value


class TestDocumentTypeWithFieldSchema:
    """Тесты для DocumentType.with_field_schema."""

    def test_with_field_schema_creates_new_instance(self) -> None:
        """Создание нового экземпляра с новой схемой."""
        original = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        new_schema = TypeSchema(
            fields=(FieldDefinition("new_field", FieldType.TEXT_INPUT, "New Field"),)
        )
        new_doc_type = original.with_field_schema(new_schema)

        # Новый экземпляр
        assert new_doc_type is not original
        # Новая схема
        assert new_doc_type.field_schema == new_schema
        # Остальные поля неизменны
        assert new_doc_type.code == original.code
        assert new_doc_type.name == original.name
        assert new_doc_type.parent_code == original.parent_code

    def test_with_field_schema_preserves_other_attributes(self) -> None:
        """Сохранение других атрибутов."""
        original = DocumentType(
            code="TEST",
            name="Test",
            parent_code="PARENT",
            document_mode=DocumentMode.STRUCTURED_FORM,
            index_template=IndexTemplate(
                segments=(
                    IndexSegmentDef(
                        name="seq",
                        segment_type=SegmentType.SEQUENCE,
                        label="Number",
                        label_en="Number",
                        pattern=r"[IVXLCDM]+",
                    ),
                ),
            ),
            field_schema=TypeSchema(fields=()),
            subtypes=(DocumentSubtype(code="01", name="Subtype"),),
            metadata=(("key", "value"),),
        )
        new_schema = TypeSchema(fields=(FieldDefinition("field", FieldType.TEXT_INPUT, "Field"),))
        new_doc_type = original.with_field_schema(new_schema)

        assert new_doc_type.code == "TEST"
        assert new_doc_type.parent_code == "PARENT"
        assert new_doc_type.document_mode == DocumentMode.STRUCTURED_FORM
        assert new_doc_type.subtypes == original.subtypes
        assert new_doc_type.metadata == original.metadata


class TestDocumentTypeWithIndexTemplate:
    """Тесты для DocumentType.with_index_template."""

    def test_with_index_template_creates_new_instance(self) -> None:
        """Создание нового экземпляра с новым шаблоном."""
        original = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        new_template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Number",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        new_doc_type = original.with_index_template(new_template)

        # Новый экземпляр
        assert new_doc_type is not original
        # Новый шаблон
        assert new_doc_type.index_template == new_template
        # Остальные поля неизменны
        assert new_doc_type.code == original.code
        assert new_doc_type.name == original.name
        assert new_doc_type.field_schema == original.field_schema

    def test_with_index_template_replaces_existing(self) -> None:
        """Замена существующего шаблона."""
        old_template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="old",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Old",
                    label_en="Old",
                    pattern=r"OLD",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Number",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        original = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=old_template,
            field_schema=TypeSchema(fields=()),
        )
        new_template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Number",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        new_doc_type = original.with_index_template(new_template)

        assert new_doc_type.index_template == new_template
        assert new_doc_type.index_template != old_template


# ============ DocumentType Frozen Tests ============


class TestDocumentTypeFrozen:
    """Тесты неизменяемости DocumentType."""

    def test_document_type_frozen(self) -> None:
        """DocumentType immutable (frozen=True)."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        with pytest.raises(AttributeError):
            doc_type.code = "NEW"  # type: ignore

    def test_document_type_hashable(self) -> None:
        """DocumentType hashable."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        hash(doc_type)
