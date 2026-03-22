"""Тесты для модуля inheritance.

Покрытие:
- resolve_schema
- merge_schemas
- get_inherited_field_names
- get_own_field_names
- filter_fields_by_type
- get_required_fields
- get_optional_fields
"""

from __future__ import annotations

from unittest.mock import Mock

from src.documents.types.document_type import DocumentMode, DocumentType
from src.documents.types.inheritance import (
    filter_fields_by_type,
    get_inherited_field_names,
    get_optional_fields,
    get_own_field_names,
    get_required_fields,
    merge_schemas,
    resolve_schema,
)
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

# ============ resolve_schema Tests ============


class TestResolveSchema:
    """Тесты для resolve_schema."""

    def test_resolve_schema_no_parent(self) -> None:
        """Тип без родителя — возвращает свою схему."""
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),)
            ),
        )
        registry = Mock()

        result = resolve_schema(doc_type, registry)

        assert len(result.fields) == 1
        assert result.fields[0].field_id == "field1"

    def test_resolve_schema_parent_not_in_registry(self) -> None:
        """Родитель не в registry — возвращает свою схему."""
        doc_type = DocumentType(
            code="CHILD",
            name="Child",
            parent_code="MISSING",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),)
            ),
        )
        registry = Mock()
        registry.get.side_effect = KeyError("MISSING")

        result = resolve_schema(doc_type, registry)

        assert len(result.fields) == 1
        assert result.fields[0].field_id == "field1"

    def test_resolve_schema_inherits_from_parent(self) -> None:
        """Наследование полей от родителя."""
        parent_schema = TypeSchema(
            fields=(FieldDefinition("parent_field", FieldType.TEXT_INPUT, "Parent Field"),)
        )
        parent_type = DocumentType(
            code="PARENT",
            name="Parent",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=parent_schema,
        )
        child_type = DocumentType(
            code="CHILD",
            name="Child",
            parent_code="PARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(FieldDefinition("child_field", FieldType.NUMBER_INPUT, "Child Field"),)
            ),
        )
        registry = Mock()
        registry.get.return_value = parent_type

        result = resolve_schema(child_type, registry)

        # Должно быть 2 поля
        assert len(result.fields) == 2
        field_ids = {f.field_id for f in result.fields}
        assert field_ids == {"parent_field", "child_field"}

    def test_resolve_schema_child_overrides_parent(self) -> None:
        """Поле потомка переопределяет поле родителя."""
        parent_schema = TypeSchema(
            fields=(FieldDefinition("shared", FieldType.TEXT_INPUT, "Parent Shared"),)
        )
        parent_type = DocumentType(
            code="PARENT",
            name="Parent",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=parent_schema,
        )
        child_type = DocumentType(
            code="CHILD",
            name="Child",
            parent_code="PARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(FieldDefinition("shared", FieldType.NUMBER_INPUT, "Child Shared"),)
            ),
        )
        registry = Mock()
        registry.get.return_value = parent_type

        result = resolve_schema(child_type, registry)

        # Должно быть 1 поле (переопределённое)
        assert len(result.fields) == 1
        field = result.fields[0]
        assert field.field_id == "shared"
        assert field.field_type == FieldType.NUMBER_INPUT
        assert field.label == "Child Shared"

    def test_resolve_schema_marks_inherited_fields(self) -> None:
        """Унаследованные поля помечаются inherited_from."""
        parent_schema = TypeSchema(
            fields=(FieldDefinition("parent_field", FieldType.TEXT_INPUT, "Parent Field"),)
        )
        parent_type = DocumentType(
            code="PARENT",
            name="Parent",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=parent_schema,
        )
        child_type = DocumentType(
            code="CHILD",
            name="Child",
            parent_code="PARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(FieldDefinition("child_field", FieldType.NUMBER_INPUT, "Child Field"),)
            ),
        )
        registry = Mock()
        registry.get.return_value = parent_type

        result = resolve_schema(child_type, registry)

        # Находим поля
        parent_field = next(f for f in result.fields if f.field_id == "parent_field")
        child_field = next(f for f in result.fields if f.field_id == "child_field")

        assert parent_field.inherited_from == "PARENT"
        assert child_field.inherited_from is None

    def test_resolve_schema_recursive_inheritance(self) -> None:
        """Рекурсивное наследование (дедушка -> родитель -> потомок)."""
        grandparent_schema = TypeSchema(
            fields=(FieldDefinition("gp_field", FieldType.TEXT_INPUT, "GP Field"),)
        )
        grandparent_type = DocumentType(
            code="GRANDPARENT",
            name="Grandparent",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=grandparent_schema,
        )
        parent_schema = TypeSchema(
            fields=(FieldDefinition("parent_field", FieldType.NUMBER_INPUT, "Parent Field"),)
        )
        parent_type = DocumentType(
            code="PARENT",
            name="Parent",
            parent_code="GRANDPARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=parent_schema,
        )
        child_type = DocumentType(
            code="CHILD",
            name="Child",
            parent_code="PARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(FieldDefinition("child_field", FieldType.DATE_INPUT, "Child Field"),)
            ),
        )

        def mock_get(code: str) -> DocumentType:
            if code == "GRANDPARENT":
                return grandparent_type
            if code == "PARENT":
                return parent_type
            raise KeyError(code)

        registry = Mock()
        registry.get.side_effect = mock_get

        result = resolve_schema(child_type, registry)

        # Должно быть 3 поля
        assert len(result.fields) == 3
        field_ids = {f.field_id for f in result.fields}
        assert field_ids == {"gp_field", "parent_field", "child_field"}


# ============ merge_schemas Tests ============


class TestMergeSchemas:
    """Тесты для merge_schemas."""

    def test_merge_empty_base(self) -> None:
        """Пустая база + override."""
        base = TypeSchema(fields=())
        override = TypeSchema(fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),))
        result = merge_schemas(base, override)
        assert len(result.fields) == 1
        assert result.fields[0].field_id == "field1"

    def test_merge_empty_override(self) -> None:
        """Base + пустой override."""
        base = TypeSchema(fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),))
        override = TypeSchema(fields=())
        result = merge_schemas(base, override)
        assert len(result.fields) == 1

    def test_merge_override_replaces(self) -> None:
        """Override заменяет поля."""
        base = TypeSchema(fields=(FieldDefinition("shared", FieldType.TEXT_INPUT, "Base"),))
        override = TypeSchema(
            fields=(FieldDefinition("shared", FieldType.NUMBER_INPUT, "Override"),)
        )
        result = merge_schemas(base, override)
        assert len(result.fields) == 1
        assert result.fields[0].field_type == FieldType.NUMBER_INPUT

    def test_merge_combines_different(self) -> None:
        """Объединение разных полей."""
        base = TypeSchema(fields=(FieldDefinition("base_field", FieldType.TEXT_INPUT, "Base"),))
        override = TypeSchema(
            fields=(FieldDefinition("override_field", FieldType.NUMBER_INPUT, "Override"),)
        )
        result = merge_schemas(base, override)
        assert len(result.fields) == 2
        field_ids = {f.field_id for f in result.fields}
        assert field_ids == {"base_field", "override_field"}

    def test_merge_preserves_version(self) -> None:
        """Сохранение версии из override."""
        base = TypeSchema(fields=(), version="1.0")
        override = TypeSchema(fields=(), version="2.0")
        result = merge_schemas(base, override)
        assert result.version == "2.0"


# ============ get_inherited_field_names Tests ============


class TestGetInheritedFieldNames:
    """Тесты для get_inherited_field_names."""

    def test_no_inherited_fields(self) -> None:
        """Нет унаследованных полей."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),
                FieldDefinition("field2", FieldType.NUMBER_INPUT, "Field 2"),
            )
        )
        result = get_inherited_field_names(schema)
        assert result == set()

    def test_some_inherited_fields(self) -> None:
        """Некоторые унаследованные поля."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("own", FieldType.TEXT_INPUT, "Own"),
                FieldDefinition(
                    "inherited", FieldType.NUMBER_INPUT, "Inherited", inherited_from="PARENT"
                ),
            )
        )
        result = get_inherited_field_names(schema)
        assert result == {"inherited"}

    def test_all_inherited_fields(self) -> None:
        """Все поля унаследованы."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1", inherited_from="A"),
                FieldDefinition("field2", FieldType.NUMBER_INPUT, "Field 2", inherited_from="B"),
            )
        )
        result = get_inherited_field_names(schema)
        assert result == {"field1", "field2"}

    def test_empty_schema(self) -> None:
        """Пустая схема."""
        schema = TypeSchema(fields=())
        result = get_inherited_field_names(schema)
        assert result == set()


# ============ get_own_field_names Tests ============


class TestGetOwnFieldNames:
    """Тесты для get_own_field_names."""

    def test_all_own_fields(self) -> None:
        """Все поля собственные."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),
                FieldDefinition("field2", FieldType.NUMBER_INPUT, "Field 2"),
            )
        )
        result = get_own_field_names(schema)
        assert result == {"field1", "field2"}

    def test_some_own_fields(self) -> None:
        """Некоторые собственные поля."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("own", FieldType.TEXT_INPUT, "Own"),
                FieldDefinition(
                    "inherited", FieldType.NUMBER_INPUT, "Inherited", inherited_from="PARENT"
                ),
            )
        )
        result = get_own_field_names(schema)
        assert result == {"own"}

    def test_no_own_fields(self) -> None:
        """Нет собственных полей."""
        schema = TypeSchema(
            fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1", inherited_from="A"),)
        )
        result = get_own_field_names(schema)
        assert result == set()


# ============ filter_fields_by_type Tests ============


class TestFilterFieldsByType:
    """Тесты для filter_fields_by_type."""

    def test_filter_by_type_found(self) -> None:
        """Найдены поля нужного типа."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("text1", FieldType.TEXT_INPUT, "Text 1"),
                FieldDefinition("num1", FieldType.NUMBER_INPUT, "Number 1"),
                FieldDefinition("text2", FieldType.TEXT_INPUT, "Text 2"),
            )
        )
        result = filter_fields_by_type(schema, FieldType.TEXT_INPUT)
        assert len(result) == 2
        assert all(f.field_type == FieldType.TEXT_INPUT for f in result)

    def test_filter_by_type_not_found(self) -> None:
        """Нет полей нужного типа."""
        schema = TypeSchema(fields=(FieldDefinition("field", FieldType.TEXT_INPUT, "Field"),))
        result = filter_fields_by_type(schema, FieldType.DATE_INPUT)
        assert result == []

    def test_filter_empty_schema(self) -> None:
        """Пустая схема."""
        schema = TypeSchema(fields=())
        result = filter_fields_by_type(schema, FieldType.TEXT_INPUT)
        assert result == []

    def test_filter_all_match(self) -> None:
        """Все поля совпадают."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("text1", FieldType.TEXT_INPUT, "Text 1"),
                FieldDefinition("text2", FieldType.TEXT_INPUT, "Text 2"),
            )
        )
        result = filter_fields_by_type(schema, FieldType.TEXT_INPUT)
        assert len(result) == 2


# ============ get_required_fields Tests ============


class TestGetRequiredFields:
    """Тесты для get_required_fields."""

    def test_all_required(self) -> None:
        """Все поля обязательны."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),
                FieldDefinition("field2", FieldType.NUMBER_INPUT, "Field 2"),
            )
        )
        result = get_required_fields(schema)
        assert len(result) == 2

    def test_some_required(self) -> None:
        """Некоторые поля обязательны."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("required", FieldType.TEXT_INPUT, "Required"),
                FieldDefinition("optional", FieldType.TEXT_INPUT, "Optional", required=False),
            )
        )
        result = get_required_fields(schema)
        assert len(result) == 1
        assert result[0].field_id == "required"

    def test_none_required(self) -> None:
        """Нет обязательных полей."""
        schema = TypeSchema(
            fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1", required=False),)
        )
        result = get_required_fields(schema)
        assert result == []


# ============ get_optional_fields Tests ============


class TestGetOptionalFields:
    """Тесты для get_optional_fields."""

    def test_all_optional(self) -> None:
        """Все поля необязательны."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1", required=False),
                FieldDefinition("field2", FieldType.NUMBER_INPUT, "Field 2", required=False),
            )
        )
        result = get_optional_fields(schema)
        assert len(result) == 2

    def test_some_optional(self) -> None:
        """Некоторые поля необязательны."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("required", FieldType.TEXT_INPUT, "Required"),
                FieldDefinition("optional", FieldType.TEXT_INPUT, "Optional", required=False),
            )
        )
        result = get_optional_fields(schema)
        assert len(result) == 1
        assert result[0].field_id == "optional"

    def test_none_optional(self) -> None:
        """Нет необязательных полей."""
        schema = TypeSchema(fields=(FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),))
        result = get_optional_fields(schema)
        assert result == []
