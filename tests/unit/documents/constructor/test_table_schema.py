"""Tests for table_schema module.

Covers:
- SummaryFunction enum
- ColumnDefinition dataclass
- TableSchema dataclass with validation
"""

from __future__ import annotations

import pytest
from src.documents.constructor.table_schema import (
    ColumnDefinition,
    SummaryFunction,
    TableSchema,
)
from src.documents.types.type_schema import FieldType


class TestSummaryFunction:
    """Tests for SummaryFunction enum."""

    def test_summary_function_values(self) -> None:
        """SummaryFunction has correct values."""
        assert SummaryFunction.SUM.value == "sum"
        assert SummaryFunction.COUNT.value == "count"
        assert SummaryFunction.AVG.value == "avg"
        assert SummaryFunction.MIN.value == "min"
        assert SummaryFunction.MAX.value == "max"

    def test_summary_function_localized_names(self) -> None:
        """Localized names are correct."""
        assert SummaryFunction.SUM.localized_name == "Сумма"
        assert SummaryFunction.COUNT.localized_name == "Количество"
        assert SummaryFunction.AVG.localized_name == "Среднее"
        assert SummaryFunction.MIN.localized_name == "Минимум"
        assert SummaryFunction.MAX.localized_name == "Максимум"


class TestColumnDefinition:
    """Tests for ColumnDefinition dataclass."""

    def test_basic_creation(self) -> None:
        """Can create ColumnDefinition with required fields."""
        col = ColumnDefinition(
            column_id="test_col",
            header="Test Column",
            column_type=FieldType.TEXT_INPUT,
        )
        assert col.column_id == "test_col"
        assert col.header == "Test Column"
        assert col.column_type == FieldType.TEXT_INPUT
        assert col.editable is True
        assert col.sortable is True

    def test_full_creation(self) -> None:
        """Can create ColumnDefinition with all fields."""
        col = ColumnDefinition(
            column_id="price",
            header="Цена",
            column_type=FieldType.NUMBER_INPUT,
            width_chars=15,
            editable=True,
            sortable=True,
            required=True,
            default_value=0.0,
            summary_function=SummaryFunction.SUM,
            validation_pattern=r"^\d+(\.\d{2})?$",
            max_length=20,
        )
        assert col.column_id == "price"
        assert col.header == "Цена"
        assert col.column_type == FieldType.NUMBER_INPUT
        assert col.width_chars == 15
        assert col.editable is True
        assert col.sortable is True
        assert col.required is True
        assert col.default_value == 0.0
        assert col.summary_function == SummaryFunction.SUM
        assert col.validation_pattern == r"^\d+(\.\d{2})?$"
        assert col.max_length == 20

    def test_empty_column_id_raises(self) -> None:
        """Empty column_id raises ValueError."""
        with pytest.raises(ValueError, match="column_id не может быть пустым"):
            ColumnDefinition(
                column_id="",
                header="Test",
                column_type=FieldType.TEXT_INPUT,
            )

    def test_empty_header_raises(self) -> None:
        """Empty header raises ValueError."""
        with pytest.raises(ValueError, match="header не может быть пустым"):
            ColumnDefinition(
                column_id="test",
                header="",
                column_type=FieldType.TEXT_INPUT,
            )

    def test_invalid_column_id_type(self) -> None:
        """Non-string column_id raises TypeError."""
        with pytest.raises(TypeError, match="column_id должен быть str"):
            ColumnDefinition(
                column_id=123,  # type: ignore[arg-type]
                header="Test",
                column_type=FieldType.TEXT_INPUT,
            )

    def test_invalid_width_chars_type(self) -> None:
        """Non-int width_chars raises TypeError."""
        with pytest.raises(TypeError, match="width_chars должен быть int или None"):
            ColumnDefinition(
                column_id="test",
                header="Test",
                column_type=FieldType.TEXT_INPUT,
                width_chars="20",  # type: ignore[arg-type]
            )

    def test_negative_width_chars(self) -> None:
        """Negative width_chars raises ValueError."""
        with pytest.raises(ValueError, match="width_chars должен быть >= 1"):
            ColumnDefinition(
                column_id="test",
                header="Test",
                column_type=FieldType.TEXT_INPUT,
                width_chars=-1,
            )

    def test_get_display_width_with_explicit(self) -> None:
        """get_display_width returns explicit width."""
        col = ColumnDefinition(
            column_id="test",
            header="Test",
            column_type=FieldType.TEXT_INPUT,
            width_chars=25,
        )
        assert col.get_display_width(default_width=20) == 25

    def test_get_display_width_with_default(self) -> None:
        """get_display_width returns default when width_chars is None."""
        col = ColumnDefinition(
            column_id="test",
            header="Test",
            column_type=FieldType.TEXT_INPUT,
            width_chars=None,
        )
        assert col.get_display_width(default_width=20) == 20

    def test_can_have_summary_numeric(self) -> None:
        """Numeric columns can have summary."""
        col = ColumnDefinition(
            column_id="price",
            header="Price",
            column_type=FieldType.NUMBER_INPUT,
            summary_function=SummaryFunction.SUM,
        )
        assert col.can_have_summary() is True

    def test_can_have_summary_text(self) -> None:
        """Text columns cannot have summary."""
        col = ColumnDefinition(
            column_id="name",
            header="Name",
            column_type=FieldType.TEXT_INPUT,
        )
        assert col.can_have_summary() is False


class TestTableSchema:
    """Tests for TableSchema dataclass."""

    @pytest.fixture
    def basic_columns(self) -> tuple[ColumnDefinition, ...]:
        """Basic columns for testing."""
        return (
            ColumnDefinition(
                column_id="item",
                header="Наименование",
                column_type=FieldType.TEXT_INPUT,
                width_chars=40,
            ),
            ColumnDefinition(
                column_id="qty",
                header="Кол-во",
                column_type=FieldType.NUMBER_INPUT,
                width_chars=10,
                summary_function=SummaryFunction.SUM,
            ),
        )

    def test_basic_creation(self, basic_columns: tuple[ColumnDefinition, ...]) -> None:
        """Can create TableSchema with basic fields."""
        schema = TableSchema(columns=basic_columns)
        assert schema.column_count == 2
        assert schema.min_rows == 0
        assert schema.max_rows is None

    def test_full_creation(self, basic_columns: tuple[ColumnDefinition, ...]) -> None:
        """Can create TableSchema with all fields."""
        schema = TableSchema(
            columns=basic_columns,
            min_rows=1,
            max_rows=100,
            auto_number=True,
            show_summary_row=True,
            summary_functions=(SummaryFunction.SUM,),
            row_height=2,
        )
        assert schema.column_count == 2
        assert schema.min_rows == 1
        assert schema.max_rows == 100
        assert schema.auto_number is True
        assert schema.show_summary_row is True
        assert schema.summary_functions == (SummaryFunction.SUM,)
        assert schema.row_height == 2

    def test_empty_columns(self) -> None:
        """Empty columns tuple is valid."""
        schema = TableSchema(columns=())
        assert schema.column_count == 0

    def test_columns_must_be_tuple(self) -> None:
        """Columns must be tuple, not list."""
        with pytest.raises(TypeError, match="columns должен быть tuple"):
            TableSchema(
                columns=[  # type: ignore[arg-type]
                    ColumnDefinition("a", "A", FieldType.TEXT_INPUT),
                ]
            )

    def test_duplicate_column_ids_raise(self) -> None:
        """Duplicate column_ids raise ValueError."""
        with pytest.raises(ValueError, match="Column IDs must be unique"):
            TableSchema(
                columns=(
                    ColumnDefinition("dup", "First", FieldType.TEXT_INPUT),
                    ColumnDefinition("dup", "Second", FieldType.TEXT_INPUT),
                )
            )

    def test_negative_min_rows(self) -> None:
        """Negative min_rows raises ValueError."""
        with pytest.raises(ValueError, match="min_rows не может быть отрицательным"):
            TableSchema(
                columns=(),
                min_rows=-1,
            )

    def test_max_rows_less_than_min_rows(self) -> None:
        """max_rows < min_rows raises ValueError."""
        with pytest.raises(ValueError, match="max_rows .* должен быть >= min_rows"):
            TableSchema(
                columns=(),
                min_rows=10,
                max_rows=5,
            )

    def test_get_column(self, basic_columns: tuple[ColumnDefinition, ...]) -> None:
        """Can get column by ID."""
        schema = TableSchema(columns=basic_columns)
        col = schema.get_column("item")
        assert col.column_id == "item"
        assert col.header == "Наименование"

    def test_get_column_not_found(self, basic_columns: tuple[ColumnDefinition, ...]) -> None:
        """get_column raises KeyError for unknown column."""
        schema = TableSchema(columns=basic_columns)
        with pytest.raises(KeyError, match="Column not found: unknown"):
            schema.get_column("unknown")

    def test_has_column(self, basic_columns: tuple[ColumnDefinition, ...]) -> None:
        """has_column returns correct result."""
        schema = TableSchema(columns=basic_columns)
        assert schema.has_column("item") is True
        assert schema.has_column("qty") is True
        assert schema.has_column("unknown") is False

    def test_editable_columns(self, basic_columns: tuple[ColumnDefinition, ...]) -> None:
        """editable_columns returns only editable columns."""
        columns = (
            ColumnDefinition(
                column_id="readonly",
                header="Readonly",
                column_type=FieldType.TEXT_INPUT,
                editable=False,
            ),
            ColumnDefinition(
                column_id="editable",
                header="Editable",
                column_type=FieldType.TEXT_INPUT,
                editable=True,
            ),
        )
        schema = TableSchema(columns=columns)
        editable = schema.editable_columns
        assert len(editable) == 1
        assert editable[0].column_id == "editable"

    def test_sortable_columns(self, basic_columns: tuple[ColumnDefinition, ...]) -> None:
        """sortable_columns returns only sortable columns."""
        columns = (
            ColumnDefinition(
                column_id="fixed",
                header="Fixed",
                column_type=FieldType.TEXT_INPUT,
                sortable=False,
            ),
            ColumnDefinition(
                column_id="sortable",
                header="Sortable",
                column_type=FieldType.TEXT_INPUT,
                sortable=True,
            ),
        )
        schema = TableSchema(columns=columns)
        sortable = schema.sortable_columns
        assert len(sortable) == 1
        assert sortable[0].column_id == "sortable"

    def test_required_columns(self) -> None:
        """required_columns returns only required columns."""
        columns = (
            ColumnDefinition(
                column_id="optional",
                header="Optional",
                column_type=FieldType.TEXT_INPUT,
                required=False,
            ),
            ColumnDefinition(
                column_id="required",
                header="Required",
                column_type=FieldType.TEXT_INPUT,
                required=True,
            ),
        )
        schema = TableSchema(columns=columns)
        required = schema.required_columns
        assert len(required) == 1
        assert required[0].column_id == "required"

    def test_get_columns_with_summary(self) -> None:
        """get_columns_with_summary returns columns with summary_function."""
        columns = (
            ColumnDefinition(
                column_id="name",
                header="Name",
                column_type=FieldType.TEXT_INPUT,
            ),
            ColumnDefinition(
                column_id="price",
                header="Price",
                column_type=FieldType.NUMBER_INPUT,
                summary_function=SummaryFunction.SUM,
            ),
            ColumnDefinition(
                column_id="qty",
                header="Qty",
                column_type=FieldType.NUMBER_INPUT,
                summary_function=SummaryFunction.COUNT,
            ),
        )
        schema = TableSchema(columns=columns)
        summary_cols = schema.get_columns_with_summary()
        assert len(summary_cols) == 2
        assert {c.column_id for c in summary_cols} == {"price", "qty"}

    def test_validate_row_count_valid(self) -> None:
        """validate_row_count returns empty list for valid counts."""
        schema = TableSchema(columns=(), min_rows=1, max_rows=10)
        assert schema.validate_row_count(5) == []

    def test_validate_row_count_too_few(self) -> None:
        """validate_row_count returns error for too few rows."""
        schema = TableSchema(columns=(), min_rows=5)
        errors = schema.validate_row_count(2)
        assert len(errors) == 1
        assert "at least 5 rows" in errors[0]

    def test_validate_row_count_too_many(self) -> None:
        """validate_row_count returns error for too many rows."""
        schema = TableSchema(columns=(), max_rows=10)
        errors = schema.validate_row_count(15)
        assert len(errors) == 1
        assert "at most 10 rows" in errors[0]

    def test_get_total_width(self) -> None:
        """get_total_width sums column widths."""
        columns = (
            ColumnDefinition("a", "A", FieldType.TEXT_INPUT, width_chars=10),
            ColumnDefinition("b", "B", FieldType.TEXT_INPUT, width_chars=20),
        )
        schema = TableSchema(columns=columns)
        assert schema.get_total_width(default_column_width=15) == 30

    def test_get_total_width_with_defaults(self) -> None:
        """get_total_width uses default for columns without width_chars."""
        columns = (
            ColumnDefinition("a", "A", FieldType.TEXT_INPUT, width_chars=10),
            ColumnDefinition("b", "B", FieldType.TEXT_INPUT, width_chars=None),
        )
        schema = TableSchema(columns=columns)
        assert schema.get_total_width(default_column_width=25) == 35

    def test_to_dict_round_trip(self) -> None:
        """to_dict/from_dict round-trip preserves data."""
        schema = TableSchema(
            columns=(
                ColumnDefinition(
                    column_id="price",
                    header="Price",
                    column_type=FieldType.NUMBER_INPUT,
                    width_chars=15,
                    summary_function=SummaryFunction.SUM,
                ),
            ),
            min_rows=1,
            max_rows=100,
            auto_number=True,
            show_summary_row=True,
        )
        data = schema.to_dict()
        restored = TableSchema.from_dict(data)

        assert restored.column_count == 1
        assert restored.min_rows == 1
        assert restored.max_rows == 100
        assert restored.auto_number is True
        assert restored.show_summary_row is True

        col = restored.get_column("price")
        assert col.header == "Price"
        assert col.column_type == FieldType.NUMBER_INPUT
        assert col.summary_function == SummaryFunction.SUM

    def test_from_dict_empty(self) -> None:
        """from_dict handles empty columns."""
        data = {"columns": [], "min_rows": 0}
        schema = TableSchema.from_dict(data)
        assert schema.column_count == 0


class TestTableSchemaSerialization:
    """Tests for serialization/deserialization."""

    def test_serialization_complete(self) -> None:
        """Complete serialization round-trip."""
        original = TableSchema(
            columns=(
                ColumnDefinition(
                    column_id="name",
                    header="Name",
                    column_type=FieldType.TEXT_INPUT,
                    width_chars=30,
                    editable=True,
                    sortable=True,
                    required=True,
                    default_value="",
                    summary_function=None,
                    validation_pattern=None,
                    max_length=100,
                ),
            ),
            min_rows=0,
            max_rows=50,
            auto_number=False,
            show_summary_row=False,
            summary_functions=(),
            row_height=1,
        )

        data = original.to_dict()

        # Check structure
        assert "columns" in data
        assert len(data["columns"]) == 1
        assert data["columns"][0]["column_id"] == "name"
        assert data["columns"][0]["column_type"] == "text_input"

        # Restore
        restored = TableSchema.from_dict(data)
        assert restored.column_count == 1
        assert restored.get_column("name").max_length == 100


class TestEdgeCases:
    """Edge case tests."""

    def test_very_long_column_id(self) -> None:
        """Very long column_id is accepted."""
        long_id = "a" * 1000
        col = ColumnDefinition(
            column_id=long_id,
            header="Test",
            column_type=FieldType.TEXT_INPUT,
        )
        assert col.column_id == long_id

    def test_unicode_header(self) -> None:
        """Unicode in header is accepted."""
        col = ColumnDefinition(
            column_id="test",
            header="Тестовая колонка с эмодзи 🎉",
            column_type=FieldType.TEXT_INPUT,
        )
        assert "🎉" in col.header

    def test_zero_max_rows(self) -> None:
        """max_rows=0 is invalid."""
        with pytest.raises(ValueError, match="max_rows должен быть >= 1"):
            TableSchema(columns=(), max_rows=0)

    def test_zero_row_height(self) -> None:
        """row_height=0 is invalid."""
        with pytest.raises(ValueError, match="row_height должен быть >= 1"):
            TableSchema(columns=(), row_height=0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
