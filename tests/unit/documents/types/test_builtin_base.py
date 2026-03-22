"""Тесты для built-in типа DOC (base document).

Покрытие:
- DOC type definition
- FREE_FORM mode
- Empty field schema
"""

from __future__ import annotations

import pytest
from src.documents.types.builtin.base import DOC
from src.documents.types.document_type import DocumentMode


class TestDOCType:
    """Тесты для DOC типа."""

    def test_doc_code(self) -> None:
        """Код типа DOC."""
        assert DOC.code == "DOC"

    def test_doc_name(self) -> None:
        """Название типа DOC."""
        assert DOC.name == "Базовый документ"

    def test_doc_is_root(self) -> None:
        """DOC — корневой тип."""
        assert DOC.is_root is True
        assert DOC.parent_code is None

    def test_doc_free_form_mode(self) -> None:
        """DOC — FREE_FORM режим."""
        assert DOC.document_mode == DocumentMode.FREE_FORM

    def test_doc_no_index_template(self) -> None:
        """DOC без шаблона индекса."""
        assert DOC.index_template is None

    def test_doc_empty_field_schema(self) -> None:
        """DOC с пустой схемой полей."""
        assert len(DOC.field_schema.fields) == 0

    def test_doc_no_subtypes(self) -> None:
        """DOC без подтипов."""
        assert DOC.has_subtypes is False
        assert DOC.subtypes == ()

    def test_doc_version(self) -> None:
        """Версия схемы DOC."""
        assert DOC.field_schema.version == "1.0"

    def test_doc_frozen(self) -> None:
        """DOC immutable."""
        with pytest.raises(AttributeError):
            DOC.code = "NEW"  # type: ignore


class TestDOCAsParent:
    """Тесты DOC как родительского типа."""

    def test_doc_can_be_parent(self) -> None:
        """DOC может быть родителем."""
        from src.documents.types.document_type import DocumentType
        from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

        child = DocumentType(
            code="CHILD",
            name="Child",
            parent_code="DOC",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(FieldDefinition("extra", FieldType.TEXT_INPUT, "Extra"),)
            ),
        )
        assert child.parent_code == "DOC"
        assert child.is_root is False
