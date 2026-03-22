"""Тесты для модуля field_builder.

Покрытие:
- FieldPosition dataclass
- FieldBuilder инициализация
- build_field() метод
- build_fields_from_schema() batch создание
- calculate_field_bounds()
"""

from __future__ import annotations

from datetime import date

import pytest
from src.documents.constructor.field_builder import (
    FieldBuilder,
    FieldPosition,
    OverflowBehavior,
)
from src.documents.types.type_schema import FieldDefinition, FieldType


class TestFieldPosition:
    """Тесты для FieldPosition."""

    def test_create_minimal(self) -> None:
        """Создание с минимальными параметрами."""
        pos = FieldPosition(x_column=0, y_row=0)
        assert pos.x_column == 0
        assert pos.y_row == 0
        assert pos.width_chars is None
        assert pos.height_rows == 1
        assert pos.overflow_behavior == OverflowBehavior.TRUNCATE

    def test_create_full(self) -> None:
        """Создание со всеми параметрами."""
        pos = FieldPosition(
            x_column=10,
            y_row=5,
            width_chars=20,
            height_rows=3,
            overflow_behavior=OverflowBehavior.WRAP,
        )
        assert pos.x_column == 10
        assert pos.y_row == 5
        assert pos.width_chars == 20
        assert pos.height_rows == 3
        assert pos.overflow_behavior == OverflowBehavior.WRAP


class TestOverflowBehavior:
    """Тесты для OverflowBehavior."""

    def test_truncate(self) -> None:
        """TRUNCATE."""
        assert OverflowBehavior.TRUNCATE.value == "truncate"

    def test_wrap(self) -> None:
        """WRAP."""
        assert OverflowBehavior.WRAP.value == "wrap"

    def test_shrink_font(self) -> None:
        """SHRINK_FONT."""
        assert OverflowBehavior.SHRINK_FONT.value == "shrink_font"


class TestFieldBuilderInit:
    """Тесты инициализации FieldBuilder."""

    def test_create_builder(self) -> None:
        """Создание построителя."""
        builder = FieldBuilder()
        assert builder is not None
        assert builder._counter == 0


class TestBuildField:
    """Тесты метода build_field."""

    @pytest.fixture
    def builder(self) -> FieldBuilder:
        """Фикстура для построителя."""
        return FieldBuilder()

    @pytest.fixture
    def simple_field(self) -> FieldDefinition:
        """Простое поле."""
        return FieldDefinition(
            field_id="test_field",
            field_type=FieldType.TEXT_INPUT,
            label="Тестовое поле",
        )

    def test_build_basic_field(self, builder: FieldBuilder, simple_field: FieldDefinition) -> None:
        """Создание базового поля."""
        position = FieldPosition(x_column=0, y_row=0)
        result = builder.build_field(simple_field, position)

        assert result["field_id"] == "test_field"
        assert result["field_type"] == "text_input"
        assert result["label"] == "Тестовое поле"
        assert result["id"] == "field_1"

    def test_field_has_position(self, builder: FieldBuilder, simple_field: FieldDefinition) -> None:
        """Позиция в результате."""
        position = FieldPosition(x_column=10, y_row=5, width_chars=20)
        result = builder.build_field(simple_field, position)

        assert result["position"]["x"] == 10
        assert result["position"]["y"] == 5
        assert result["position"]["width"] == 20

    def test_field_counter_increment(
        self, builder: FieldBuilder, simple_field: FieldDefinition
    ) -> None:
        """Счётчик увеличивается."""
        position = FieldPosition(x_column=0, y_row=0)
        result1 = builder.build_field(simple_field, position)
        result2 = builder.build_field(simple_field, position)

        assert result1["id"] == "field_1"
        assert result2["id"] == "field_2"

    def test_field_with_value(self, builder: FieldBuilder, simple_field: FieldDefinition) -> None:
        """Поле со значением."""
        position = FieldPosition(x_column=0, y_row=0)
        result = builder.build_field(simple_field, position, value="Test Value")

        assert result["value"] == "Test Value"

    def test_field_with_default_value(self, builder: FieldBuilder) -> None:
        """Поле с default_value из определения."""
        field = FieldDefinition(
            field_id="field_with_default",
            field_type=FieldType.TEXT_INPUT,
            label="Поле",
            default_value="Default",
        )
        position = FieldPosition(x_column=0, y_row=0)
        result = builder.build_field(field, position)

        assert result["value"] == "Default"

    def test_field_label_i18n(self, builder: FieldBuilder, simple_field: FieldDefinition) -> None:
        """label_i18n в результате."""
        position = FieldPosition(x_column=0, y_row=0)
        result = builder.build_field(simple_field, position)

        assert "label_i18n" in result
        assert result["label_i18n"] == {}

    def test_field_validation_rules(self, builder: FieldBuilder) -> None:
        """Правила валидации."""
        field = FieldDefinition(
            field_id="validated",
            field_type=FieldType.NUMBER_INPUT,
            label="Число",
            validation_pattern=r"^\d+$",
            min_value=0,
            max_value=100,
        )
        position = FieldPosition(x_column=0, y_row=0)
        result = builder.build_field(field, position)

        assert result["validation"] == [r"^\d+$"]
        assert result["validation_rules"]["min_value"] == 0
        assert result["validation_rules"]["max_value"] == 100

    def test_field_with_date(self, builder: FieldBuilder) -> None:
        """Поле с датами."""
        min_d = date(2024, 1, 1)
        max_d = date(2024, 12, 31)
        field = FieldDefinition(
            field_id="date_field",
            field_type=FieldType.DATE_INPUT,
            label="Дата",
            min_date=min_d,
            max_date=max_d,
        )
        position = FieldPosition(x_column=0, y_row=0)
        result = builder.build_field(field, position)

        assert result["validation_rules"]["min_date"] == "2024-01-01"
        assert result["validation_rules"]["max_date"] == "2024-12-31"

    def test_field_ux_properties(self, builder: FieldBuilder) -> None:
        """UX свойства."""
        field = FieldDefinition(
            field_id="ux_field",
            field_type=FieldType.TEXT_INPUT,
            label="UX",
            tab_index=1,
            input_mask="###",
            placeholder="Введите",
            help_text="Подсказка",
        )
        position = FieldPosition(x_column=0, y_row=0)
        result = builder.build_field(field, position)

        assert result["ux"]["tab_index"] == 1
        assert result["ux"]["input_mask"] == "###"
        assert result["ux"]["placeholder"] == "Введите"
        assert result["ux"]["help_text"] == "Подсказка"


class TestBuildFieldsFromSchema:
    """Тесты метода build_fields_from_schema."""

    @pytest.fixture
    def builder(self) -> FieldBuilder:
        """Фикстура для построителя."""
        return FieldBuilder()

    @pytest.fixture
    def schema_fields(self) -> list[FieldDefinition]:
        """Поля схемы."""
        return [
            FieldDefinition("field1", FieldType.TEXT_INPUT, "Поле 1"),
            FieldDefinition("field2", FieldType.TEXT_INPUT, "Поле 2"),
            FieldDefinition("field3", FieldType.TEXT_INPUT, "Поле 3"),
        ]

    def test_build_multiple_fields(
        self, builder: FieldBuilder, schema_fields: list[FieldDefinition]
    ) -> None:
        """Создание нескольких полей."""
        results = builder.build_fields_from_schema(schema_fields)
        assert len(results) == 3

    def test_auto_positioning(
        self, builder: FieldBuilder, schema_fields: list[FieldDefinition]
    ) -> None:
        """Авто-позиционирование."""
        results = builder.build_fields_from_schema(
            schema_fields, start_x=0, start_y=0, row_height=2
        )

        assert results[0]["position"]["y"] == 0
        assert results[1]["position"]["y"] == 2
        assert results[2]["position"]["y"] == 4

    def test_empty_fields(self, builder: FieldBuilder) -> None:
        """Пустой список полей."""
        results = builder.build_fields_from_schema([])
        assert results == []


class TestCalculateFieldBounds:
    """Тесты метода calculate_field_bounds."""

    @pytest.fixture
    def builder(self) -> FieldBuilder:
        """Фикстура для построителя."""
        return FieldBuilder()

    def test_empty_value(self, builder: FieldBuilder) -> None:
        """Пустое значение."""
        field = FieldDefinition("test", FieldType.TEXT_INPUT, "Тест")
        width, height = builder.calculate_field_bounds(field, "")
        assert width == 20
        assert height == 1

    def test_short_text(self, builder: FieldBuilder) -> None:
        """Короткий текст."""
        field = FieldDefinition("test", FieldType.TEXT_INPUT, "Тест")
        width, height = builder.calculate_field_bounds(field, "Hello")
        assert width == 5
        assert height == 1

    def test_long_text(self, builder: FieldBuilder) -> None:
        """Длинный текст."""
        field = FieldDefinition("test", FieldType.TEXT_INPUT, "Тест")
        # Text longer than max_width
        text = "x" * 100
        width, height = builder.calculate_field_bounds(field, text)
        assert width == 80  # max_width
        assert height >= 2

    def test_number_value(self, builder: FieldBuilder) -> None:
        """Числовое значение."""
        field = FieldDefinition("num", FieldType.NUMBER_INPUT, "Число")
        width, height = builder.calculate_field_bounds(field, "12345")
        assert width == 5


class TestFieldBuilderAllExports:
    """Тесты экспортируемых имен."""

    def test_exports_field_builder(self) -> None:
        """FieldBuilder экспортирован."""
        from src.documents.constructor.field_builder import FieldBuilder

        assert FieldBuilder is not None

    def test_exports_field_position(self) -> None:
        """FieldPosition экспортирован."""
        from src.documents.constructor.field_builder import FieldPosition

        assert FieldPosition is not None

    def test_exports_overflow_behavior(self) -> None:
        """OverflowBehavior экспортирован."""
        from src.documents.constructor.field_builder import OverflowBehavior

        assert OverflowBehavior is not None
