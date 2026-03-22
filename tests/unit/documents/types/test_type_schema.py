"""Тесты для модуля type_schema.

Покрытие:
- FieldType Enum
- OverflowBehavior Enum
- FieldDefinition dataclass
- TypeSchema dataclass
- Валидация значений
"""

from __future__ import annotations

from datetime import date
from typing import Any, List

import pytest
from src.documents.types.type_schema import (
    FieldDefinition,
    FieldType,
    OverflowBehavior,
    TypeSchema,
)

# ============ FieldType Enum Tests ============


class TestFieldType:
    """Тесты для FieldType Enum."""

    def test_field_type_values(self) -> None:
        """Проверка всех значений FieldType."""
        assert FieldType.STATIC_TEXT.value == "static_text"
        assert FieldType.TEXT_INPUT.value == "text_input"
        assert FieldType.NUMBER_INPUT.value == "number_input"
        assert FieldType.DATE_INPUT.value == "date_input"
        assert FieldType.TABLE.value == "table"
        assert FieldType.EXCEL_IMPORT.value == "excel_import"
        assert FieldType.CALCULATED.value == "calculated"
        assert FieldType.QR.value == "qr"
        assert FieldType.BARCODE.value == "barcode"
        assert FieldType.SIGNATURE.value == "signature"
        assert FieldType.STAMP.value == "stamp"
        assert FieldType.CHECKBOX.value == "checkbox"
        assert FieldType.DROPDOWN.value == "dropdown"
        assert FieldType.RADIO_GROUP.value == "radio_group"
        assert FieldType.CURRENCY.value == "currency"
        assert FieldType.MULTI_LINE_TEXT.value == "multi_line_text"
        assert FieldType.PHONE.value == "phone"
        assert FieldType.EMAIL.value == "email"

    def test_field_type_is_str(self) -> None:
        """Проверка что FieldType наследуется от str."""
        assert isinstance(FieldType.TEXT_INPUT, str)
        assert FieldType.TEXT_INPUT.value == "text_input"

    @pytest.mark.parametrize("field_type", list(FieldType))
    def test_all_field_types_have_values(self, field_type: FieldType) -> None:
        """Все FieldType имеют непустые значения."""
        assert field_type.value
        assert isinstance(field_type.value, str)


# ============ OverflowBehavior Enum Tests ============


class TestOverflowBehavior:
    """Тесты для OverflowBehavior Enum."""

    def test_overflow_behavior_values(self) -> None:
        """Проверка значений OverflowBehavior."""
        assert OverflowBehavior.TRUNCATE.value == "truncate"
        assert OverflowBehavior.WRAP.value == "wrap"
        assert OverflowBehavior.SHRINK_FONT.value == "shrink_font"

    def test_overflow_behavior_is_str(self) -> None:
        """Проверка что OverflowBehavior наследуется от str."""
        assert isinstance(OverflowBehavior.TRUNCATE, str)


# ============ FieldDefinition Tests ============


class TestFieldDefinition:
    """Тесты для FieldDefinition dataclass."""

    def test_create_field_definition_minimal(self) -> None:
        """Создание FieldDefinition с минимальными параметрами."""
        field = FieldDefinition(
            field_id="test_field",
            field_type=FieldType.TEXT_INPUT,
            label="Test Field",
        )
        assert field.field_id == "test_field"
        assert field.field_type == FieldType.TEXT_INPUT
        assert field.label == "Test Field"

    def test_field_definition_defaults(self) -> None:
        """Проверка значений по умолчанию."""
        field = FieldDefinition(
            field_id="test",
            field_type=FieldType.TEXT_INPUT,
            label="Test",
        )
        assert field.label_i18n == {}
        assert field.required is True
        assert field.readonly is False
        assert field.default_value is None
        assert field.validation_pattern is None
        assert field.max_length is None
        assert field.options is None
        assert field.escp_variable is None
        assert field.inherited_from is None
        assert field.min_value is None
        assert field.max_value is None
        assert field.min_date is None
        assert field.max_date is None
        assert field.required_if is None
        assert field.cross_field_rules == ()
        assert field.visibility_condition is None
        assert field.read_only_condition is None
        assert field.enabled_condition is None
        assert field.tab_index is None
        assert field.input_mask is None
        assert field.placeholder is None
        assert field.autocomplete_source is None
        assert field.help_text is None
        assert field.table_schema is None

    def test_field_definition_full(self) -> None:
        """Создание FieldDefinition со всеми параметрами."""
        field = FieldDefinition(
            field_id="full_field",
            field_type=FieldType.NUMBER_INPUT,
            label="Full Field",
            label_i18n={"en": "Full Field", "de": "Voll Feld"},
            required=False,
            readonly=True,
            default_value=42,
            validation_pattern=r"^\d+$",
            max_length=10,
            options=("option1", "option2"),
            escp_variable="VAR_001",
            inherited_from="PARENT",
            min_value=0,
            max_value=100,
            min_date=date(2020, 1, 1),
            max_date=date(2025, 12, 31),
            required_if="type == 'special'",
            cross_field_rules=("field1 + field2 > 0",),
            visibility_condition="show_if",
            read_only_condition="never",
            enabled_condition="always",
            tab_index=1,
            input_mask="000-000",
            placeholder="Enter value",
            autocomplete_source="users",
            help_text="This is a help text",
        )
        assert field.field_id == "full_field"
        assert field.field_type == FieldType.NUMBER_INPUT
        assert field.label == "Full Field"
        assert field.label_i18n == {"en": "Full Field", "de": "Voll Feld"}
        assert field.required is False
        assert field.readonly is True
        assert field.default_value == 42
        assert field.validation_pattern == r"^\d+$"
        assert field.max_length == 10
        assert field.options == ("option1", "option2")
        assert field.escp_variable == "VAR_001"
        assert field.inherited_from == "PARENT"
        assert field.min_value == 0
        assert field.max_value == 100
        assert field.min_date == date(2020, 1, 1)
        assert field.max_date == date(2025, 12, 31)
        assert field.required_if == "type == 'special'"
        assert field.cross_field_rules == ("field1 + field2 > 0",)
        assert field.visibility_condition == "show_if"
        assert field.read_only_condition == "never"
        assert field.enabled_condition == "always"
        assert field.tab_index == 1
        assert field.input_mask == "000-000"
        assert field.placeholder == "Enter value"
        assert field.autocomplete_source == "users"
        assert field.help_text == "This is a help text"

    def test_field_definition_frozen(self) -> None:
        """Проверка что FieldDefinition immutable (frozen=True)."""
        field = FieldDefinition(
            field_id="frozen_test",
            field_type=FieldType.TEXT_INPUT,
            label="Frozen Test",
        )
        with pytest.raises(AttributeError):
            field.field_id = "new_id"  # type: ignore

    def test_field_definition_hashable(self) -> None:
        """Проверка что FieldDefinition hashable."""
        field = FieldDefinition(
            field_id="hash_test",
            field_type=FieldType.TEXT_INPUT,
            label="Hash Test",
        )
        # frozen dataclass должен быть hashable
        hash(field)


# ============ TypeSchema Tests ============


class TestTypeSchema:
    """Тесты для TypeSchema dataclass."""

    def test_create_empty_schema(self) -> None:
        """Создание пустой схемы."""
        schema = TypeSchema(fields=())
        assert schema.fields == ()
        assert schema.version == "1.0"
        assert schema.compatibility_version == "1.0"
        assert schema.deprecated_fields == ()

    def test_create_schema_with_fields(self) -> None:
        """Создание схемы с полями."""
        fields = (
            FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),
            FieldDefinition("field2", FieldType.NUMBER_INPUT, "Field 2"),
        )
        schema = TypeSchema(fields=fields)
        assert len(schema.fields) == 2
        assert schema.fields[0].field_id == "field1"
        assert schema.fields[1].field_id == "field2"

    def test_schema_version_custom(self) -> None:
        """Создание схемы с кастомной версией."""
        schema = TypeSchema(
            fields=(),
            version="2.0",
            compatibility_version="1.5",
        )
        assert schema.version == "2.0"
        assert schema.compatibility_version == "1.5"

    def test_schema_deprecated_fields(self) -> None:
        """Создание схемы с устаревшими полями."""
        schema = TypeSchema(
            fields=(),
            deprecated_fields=("old_field1", "old_field2"),
        )
        assert schema.deprecated_fields == ("old_field1", "old_field2")

    def test_post_init_empty_schema_valid(self) -> None:
        """Пустая схема допустима."""
        schema = TypeSchema(fields=())
        assert schema.fields == ()

    def test_post_init_duplicate_field_ids_raises(self) -> None:
        """Дублирующиеся field_id вызывают ValueError."""
        with pytest.raises(ValueError, match="Field IDs must be unique"):
            TypeSchema(
                fields=(
                    FieldDefinition("duplicate", FieldType.TEXT_INPUT, "First"),
                    FieldDefinition("duplicate", FieldType.NUMBER_INPUT, "Second"),
                )
            )

    def test_post_init_unique_field_ids_ok(self) -> None:
        """Уникальные field_id допустимы."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("field1", FieldType.TEXT_INPUT, "First"),
                FieldDefinition("field2", FieldType.NUMBER_INPUT, "Second"),
            )
        )
        assert len(schema.fields) == 2


# ============ TypeSchema Methods Tests ============


class TestTypeSchemaGetField:
    """Тесты для TypeSchema.get_field."""

    def test_get_field_exists(self) -> None:
        """Получение существующего поля."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("name", FieldType.TEXT_INPUT, "Name"),
                FieldDefinition("age", FieldType.NUMBER_INPUT, "Age"),
            )
        )
        field = schema.get_field("name")
        assert field.field_id == "name"
        assert field.field_type == FieldType.TEXT_INPUT

    def test_get_field_not_exists_raises(self) -> None:
        """Получение несуществующего поля вызывает KeyError."""
        schema = TypeSchema(fields=(FieldDefinition("name", FieldType.TEXT_INPUT, "Name"),))
        with pytest.raises(KeyError, match="Field not found: missing"):
            schema.get_field("missing")


class TestTypeSchemaHasField:
    """Тесты для TypeSchema.has_field."""

    def test_has_field_true(self) -> None:
        """Проверка существующего поля."""
        schema = TypeSchema(fields=(FieldDefinition("name", FieldType.TEXT_INPUT, "Name"),))
        assert schema.has_field("name") is True

    def test_has_field_false(self) -> None:
        """Проверка несуществующего поля."""
        schema = TypeSchema(fields=(FieldDefinition("name", FieldType.TEXT_INPUT, "Name"),))
        assert schema.has_field("missing") is False

    def test_has_field_empty_schema(self) -> None:
        """Проверка в пустой схеме."""
        schema = TypeSchema(fields=())
        assert schema.has_field("any") is False


class TestTypeSchemaRequiredFields:
    """Тесты для TypeSchema.required_fields property."""

    def test_required_fields_empty(self) -> None:
        """Пустая схема — пустой список обязательных."""
        schema = TypeSchema(fields=())
        assert schema.required_fields == []

    def test_required_fields_all_required(self) -> None:
        """Все поля обязательны."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("field1", FieldType.TEXT_INPUT, "Field 1"),
                FieldDefinition("field2", FieldType.NUMBER_INPUT, "Field 2"),
            )
        )
        assert len(schema.required_fields) == 2

    def test_required_fields_mixed(self) -> None:
        """Смешанные обязательные и необязательные."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("req", FieldType.TEXT_INPUT, "Required"),
                FieldDefinition("opt", FieldType.TEXT_INPUT, "Optional", required=False),
            )
        )
        required = schema.required_fields
        assert len(required) == 1
        assert required[0].field_id == "req"


class TestTypeSchemaOptionalFields:
    """Тесты для TypeSchema.optional_fields property."""

    def test_optional_fields_empty(self) -> None:
        """Пустая схема — пустой список необязательных."""
        schema = TypeSchema(fields=())
        assert schema.optional_fields == []

    def test_optional_fields_mixed(self) -> None:
        """Смешанные поля."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("req", FieldType.TEXT_INPUT, "Required"),
                FieldDefinition("opt", FieldType.TEXT_INPUT, "Optional", required=False),
            )
        )
        optional = schema.optional_fields
        assert len(optional) == 1
        assert optional[0].field_id == "opt"


class TestTypeSchemaGetFieldsByType:
    """Тесты для TypeSchema.get_fields_by_type."""

    def test_get_fields_by_type_found(self) -> None:
        """Поиск полей по типу."""
        schema = TypeSchema(
            fields=(
                FieldDefinition("text1", FieldType.TEXT_INPUT, "Text 1"),
                FieldDefinition("num1", FieldType.NUMBER_INPUT, "Number 1"),
                FieldDefinition("text2", FieldType.TEXT_INPUT, "Text 2"),
            )
        )
        text_fields = schema.get_fields_by_type(FieldType.TEXT_INPUT)
        assert len(text_fields) == 2
        assert all(f.field_type == FieldType.TEXT_INPUT for f in text_fields)

    def test_get_fields_by_type_not_found(self) -> None:
        """Тип не найден."""
        schema = TypeSchema(fields=(FieldDefinition("name", FieldType.TEXT_INPUT, "Name"),))
        date_fields = schema.get_fields_by_type(FieldType.DATE_INPUT)
        assert date_fields == []


# ============ TypeSchema Validation Tests ============


class TestTypeSchemaValidateValue:
    """Тесты для TypeSchema.validate_value."""

    def test_validate_unknown_field(self) -> None:
        """Валидация неизвестного поля."""
        schema = TypeSchema(fields=())
        errors = schema.validate_value("unknown", "value")
        assert errors == ["Unknown field: unknown"]

    def test_validate_required_empty(self) -> None:
        """Обязательное пустое поле."""
        schema = TypeSchema(fields=(FieldDefinition("req", FieldType.TEXT_INPUT, "Required"),))
        errors = schema.validate_value("req", "")
        assert len(errors) == 1
        assert "is required" in errors[0]

    def test_validate_required_none(self) -> None:
        """Обязательное None поле."""
        schema = TypeSchema(fields=(FieldDefinition("req", FieldType.TEXT_INPUT, "Required"),))
        errors = schema.validate_value("req", None)
        assert len(errors) == 1
        assert "is required" in errors[0]

    def test_validate_optional_empty(self) -> None:
        """Необязательное пустое поле — валидно."""
        schema = TypeSchema(
            fields=(FieldDefinition("opt", FieldType.TEXT_INPUT, "Optional", required=False),)
        )
        errors = schema.validate_value("opt", "")
        assert errors == []

    def test_validate_number_valid(self) -> None:
        """Валидное число."""
        schema = TypeSchema(fields=(FieldDefinition("num", FieldType.NUMBER_INPUT, "Number"),))
        errors = schema.validate_value("num", 42)
        assert errors == []

    def test_validate_number_from_string(self) -> None:
        """Число из строки."""
        schema = TypeSchema(fields=(FieldDefinition("num", FieldType.NUMBER_INPUT, "Number"),))
        errors = schema.validate_value("num", "42.5")
        assert errors == []

    def test_validate_number_invalid(self) -> None:
        """Невалидное число."""
        schema = TypeSchema(fields=(FieldDefinition("num", FieldType.NUMBER_INPUT, "Number"),))
        errors = schema.validate_value("num", "not a number")
        assert len(errors) == 1
        assert "Invalid number" in errors[0]

    def test_validate_number_min_value(self) -> None:
        """Число меньше минимума."""
        schema = TypeSchema(
            fields=(FieldDefinition("num", FieldType.NUMBER_INPUT, "Number", min_value=0),)
        )
        errors = schema.validate_value("num", -5)
        assert len(errors) == 1
        assert "less than minimum" in errors[0]

    def test_validate_number_max_value(self) -> None:
        """Число больше максимума."""
        schema = TypeSchema(
            fields=(FieldDefinition("num", FieldType.NUMBER_INPUT, "Number", max_value=100),)
        )
        errors = schema.validate_value("num", 150)
        assert len(errors) == 1
        assert "greater than maximum" in errors[0]

    def test_validate_number_in_range(self) -> None:
        """Число в диапазоне."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    "num", FieldType.NUMBER_INPUT, "Number", min_value=0, max_value=100
                ),
            )
        )
        errors = schema.validate_value("num", 50)
        assert errors == []

    def test_validate_pattern_match(self) -> None:
        """Совпадение с паттерном."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    "code", FieldType.TEXT_INPUT, "Code", validation_pattern=r"^[A-Z]{3}$"
                ),
            )
        )
        errors = schema.validate_value("code", "ABC")
        assert errors == []

    def test_validate_pattern_no_match(self) -> None:
        """Несовпадение с паттерном."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    "code", FieldType.TEXT_INPUT, "Code", validation_pattern=r"^[A-Z]{3}$"
                ),
            )
        )
        errors = schema.validate_value("code", "abc123")
        assert len(errors) == 1
        assert "doesn't match pattern" in errors[0]

    def test_validate_max_length_ok(self) -> None:
        """Длина в пределах."""
        schema = TypeSchema(
            fields=(FieldDefinition("name", FieldType.TEXT_INPUT, "Name", max_length=10),)
        )
        errors = schema.validate_value("name", "Short")
        assert errors == []

    def test_validate_max_length_exceeded(self) -> None:
        """Превышение max_length."""
        schema = TypeSchema(
            fields=(FieldDefinition("name", FieldType.TEXT_INPUT, "Name", max_length=5),)
        )
        errors = schema.validate_value("name", "Too long text")
        assert len(errors) == 1
        assert "at most 5 characters" in errors[0]

    def test_validate_options_valid(self) -> None:
        """Значение из списка options."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    "status", FieldType.DROPDOWN, "Status", options=("active", "inactive")
                ),
            )
        )
        errors = schema.validate_value("status", "active")
        assert errors == []

    def test_validate_options_invalid(self) -> None:
        """Значение не из списка options."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    "status", FieldType.DROPDOWN, "Status", options=("active", "inactive")
                ),
            )
        )
        errors = schema.validate_value("status", "unknown")
        assert len(errors) == 1
        assert "must be one of" in errors[0]

    def test_validate_date_input(self) -> None:
        """Валидация DATE_INPUT — базовая проверка."""
        schema = TypeSchema(fields=(FieldDefinition("date", FieldType.DATE_INPUT, "Date"),))
        # DATE_INPUT валидация — плейсхолдер
        errors = schema.validate_value("date", "2026-03-22")
        assert errors == []


# ============ Parametrized Edge Cases ============


class TestTypeSchemaEdgeCases:
    """Граничные случаи TypeSchema."""

    @pytest.mark.parametrize(
        "field_type",
        [
            FieldType.STATIC_TEXT,
            FieldType.TEXT_INPUT,
            FieldType.MULTI_LINE_TEXT,
            FieldType.PHONE,
            FieldType.EMAIL,
        ],
    )
    def test_text_types_no_special_validation(self, field_type: FieldType) -> None:
        """Текстовые типы без специальной валидации."""
        schema = TypeSchema(fields=(FieldDefinition("text", field_type, "Text"),))
        errors = schema.validate_value("text", "any value")
        assert errors == []

    @pytest.mark.parametrize(
        "field_type,value,expected_error",
        [
            (FieldType.CHECKBOX, True, []),
            (FieldType.CHECKBOX, False, []),
            (FieldType.CURRENCY, 100.50, []),
            (FieldType.CURRENCY, 0, []),
        ],
    )
    def test_other_types_validation(
        self,
        field_type: FieldType,
        value: Any,
        expected_error: List[str],
    ) -> None:
        """Другие типы полей."""
        schema = TypeSchema(fields=(FieldDefinition("field", field_type, "Field", required=False),))
        errors = schema.validate_value("field", value)
        assert errors == expected_error
