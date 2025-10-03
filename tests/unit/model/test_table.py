"""
Unit tests for src/model/table.py module.

Tests cover Cell and Table classes, border styles, cell manipulation,
validation, serialization, and grid operations.
"""

import logging
from typing import Any

import pytest

from src.model.paragraph import Paragraph
from src.model.run import Run
from src.model.table import (
    MAX_SPAN,
    MIN_SPAN,
    Cell,
    Table,
    TableBorder,
)


class TestTableBorder:
    """Test TableBorder enum."""

    def test_table_border_values(self) -> None:
        """Test that all border values are defined."""
        assert TableBorder.NONE.value == "none"
        assert TableBorder.SINGLE.value == "single"
        assert TableBorder.DOUBLE.value == "double"
        assert TableBorder.ASCII_ART.value == "ascii_art"

    def test_table_border_from_string(self) -> None:
        """Test creating border from string value."""
        assert TableBorder("none") == TableBorder.NONE
        assert TableBorder("single") == TableBorder.SINGLE
        assert TableBorder("double") == TableBorder.DOUBLE
        assert TableBorder("ascii_art") == TableBorder.ASCII_ART

    def test_table_border_invalid_string(self) -> None:
        """Test that invalid string raises ValueError."""
        with pytest.raises(ValueError):
            TableBorder("invalid")


class TestCellInitialization:
    """Test Cell initialization and post-init validation."""

    def test_minimal_initialization(self) -> None:
        """Test creating cell with default values."""
        cell = Cell()

        assert isinstance(cell.content, Paragraph)
        assert cell.colspan == 1
        assert cell.rowspan == 1

    def test_full_initialization(self) -> None:
        """Test creating cell with all parameters."""
        para = Paragraph()
        para.add_run(Run(text="Test"))
        cell = Cell(content=para, colspan=2, rowspan=3)

        assert cell.content.get_text() == "Test"
        assert cell.colspan == 2
        assert cell.rowspan == 3

    def test_colspan_clamping_too_high(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that excessive colspan is clamped."""
        with caplog.at_level(logging.WARNING):
            cell = Cell(colspan=999)

        assert cell.colspan == MAX_SPAN
        assert "out of range" in caplog.text

    def test_colspan_clamping_too_low(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that zero/negative colspan is clamped."""
        with caplog.at_level(logging.WARNING):
            cell = Cell(colspan=0)

        assert cell.colspan == MIN_SPAN

    def test_rowspan_clamping_too_high(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that excessive rowspan is clamped."""
        with caplog.at_level(logging.WARNING):
            cell = Cell(rowspan=999)

        assert cell.rowspan == MAX_SPAN

    def test_rowspan_clamping_too_low(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that zero/negative rowspan is clamped."""
        with caplog.at_level(logging.WARNING):
            cell = Cell(rowspan=-1)

        assert cell.rowspan == MIN_SPAN


class TestCellValidation:
    """Test cell validation logic."""

    def test_validate_valid_cell(self) -> None:
        """Test validating cell with valid content."""
        cell = Cell()
        cell.content.add_run(Run(text="Valid"))
        cell.validate()  # Should not raise

    def test_validate_empty_cell(self) -> None:
        """Test validating empty cell."""
        cell = Cell()
        cell.validate()  # Empty paragraph is OK

    def test_validate_invalid_content_type(self) -> None:
        """Test that non-Paragraph content raises TypeError."""
        cell = Cell()
        object.__setattr__(cell, "content", "not a paragraph")

        with pytest.raises(TypeError, match="must be Paragraph"):
            cell.validate()

    def test_validate_colspan_out_of_range(self) -> None:
        """Test validation fails for out-of-range colspan."""
        cell = Cell()
        object.__setattr__(cell, "colspan", 999)

        with pytest.raises(ValueError, match="colspan .* out of range"):
            cell.validate()

    def test_validate_rowspan_out_of_range(self) -> None:
        """Test validation fails for out-of-range rowspan."""
        cell = Cell()
        object.__setattr__(cell, "rowspan", 0)

        with pytest.raises(ValueError, match="rowspan .* out of range"):
            cell.validate()

    def test_validate_invalid_paragraph_content(self) -> None:
        """Test validation fails when paragraph validation fails."""
        cell = Cell()
        cell.content.add_run(Run(text=""))  # Empty run - invalid

        with pytest.raises(ValueError, match="content validation failed"):
            cell.validate()


class TestCellCopy:
    """Test cell copying functionality."""

    def test_copy_creates_independent_cell(self) -> None:
        """Test that copy creates independent instance."""
        cell = Cell()
        cell.content.add_run(Run(text="Original"))
        cell_copy = cell.copy()

        assert cell_copy is not cell
        assert cell_copy.content is not cell.content

    def test_copy_preserves_attributes(self) -> None:
        """Test that copy preserves all attributes."""
        cell = Cell(colspan=2, rowspan=3)
        cell.content.add_run(Run(text="Test"))
        cell_copy = cell.copy()

        assert cell_copy.colspan == 2
        assert cell_copy.rowspan == 3
        assert cell_copy.content.get_text() == "Test"

    def test_copy_modification_does_not_affect_original(self) -> None:
        """Test that modifying copy doesn't affect original."""
        cell = Cell()
        cell.content.add_run(Run(text="Original"))

        cell_copy = cell.copy()
        cell_copy.content.runs[0].text = "Modified"

        assert cell.content.runs[0].text == "Original"
        assert cell_copy.content.runs[0].text == "Modified"


class TestCellSerialization:
    """Test cell serialization."""

    def test_to_dict_minimal(self) -> None:
        """Test serialization with default values."""
        cell = Cell()
        data = cell.to_dict()

        assert "content" in data
        assert data["colspan"] == 1
        assert data["rowspan"] == 1

    def test_to_dict_full(self) -> None:
        """Test serialization with all attributes."""
        cell = Cell(colspan=2, rowspan=3)
        cell.content.add_run(Run(text="Test"))
        data = cell.to_dict()

        assert data["colspan"] == 2
        assert data["rowspan"] == 3
        assert data["content"]["runs"][0]["text"] == "Test"

    def test_from_dict_minimal(self) -> None:
        """Test deserialization with minimal data."""
        data: dict[str, Any] = {}
        cell = Cell.from_dict(data)

        assert cell.colspan == 1
        assert cell.rowspan == 1
        assert isinstance(cell.content, Paragraph)

    def test_from_dict_full(self) -> None:
        """Test deserialization with complete data."""
        data = {
            "content": {"runs": [{"text": "Test"}]},
            "colspan": 2,
            "rowspan": 3,
        }
        cell = Cell.from_dict(data)

        assert cell.colspan == 2
        assert cell.rowspan == 3
        assert cell.content.get_text() == "Test"

    def test_from_dict_invalid_type(self) -> None:
        """Test that non-dict input raises TypeError."""
        with pytest.raises(TypeError, match="Expected dict"):
            Cell.from_dict("not a dict")  # type: ignore[arg-type]

    def test_roundtrip_serialization(self) -> None:
        """Test that to_dict/from_dict roundtrip preserves data."""
        original = Cell(colspan=2, rowspan=3)
        original.content.add_run(Run(text="Roundtrip"))

        data = original.to_dict()
        restored = Cell.from_dict(data)

        assert restored.colspan == original.colspan
        assert restored.rowspan == original.rowspan
        assert restored.content.get_text() == original.content.get_text()


class TestCellRepr:
    """Test cell string representation."""

    def test_repr_default(self) -> None:
        """Test __repr__ with default values."""
        cell = Cell()
        repr_str = repr(cell)

        assert "Cell" in repr_str
        assert "colspan=1" in repr_str
        assert "rowspan=1" in repr_str

    def test_repr_with_spanning(self) -> None:
        """Test __repr__ with spanning cell."""
        cell = Cell(colspan=3, rowspan=2)
        repr_str = repr(cell)

        assert "colspan=3" in repr_str
        assert "rowspan=2" in repr_str


class TestTableInitialization:
    """Test Table initialization."""

    def test_minimal_initialization(self) -> None:
        """Test creating table with default values."""
        table = Table()

        assert table.rows == []
        assert table.border_style == TableBorder.SINGLE
        assert table.column_widths is None

    def test_full_initialization(self) -> None:
        """Test creating table with all parameters."""
        rows = [[Cell(), Cell()]]
        table = Table(
            rows=rows,
            border_style=TableBorder.DOUBLE,
            column_widths=[2.0, 3.0],
        )

        assert len(table.rows) == 1
        assert table.border_style == TableBorder.DOUBLE
        assert table.column_widths == [2.0, 3.0]


class TestTableRowManipulation:
    """Test table row operations."""

    def test_add_row(self) -> None:
        """Test adding rows to table."""
        table = Table()
        row1 = [Cell(), Cell()]
        row2 = [Cell(), Cell()]

        table.add_row(row1)
        assert len(table.rows) == 1

        table.add_row(row2)
        assert len(table.rows) == 2

    def test_add_row_invalid_type(self) -> None:
        """Test that adding non-list raises TypeError."""
        table = Table()

        with pytest.raises(TypeError, match="cells must be list"):
            table.add_row("not a list")  # type: ignore[arg-type]

    def test_add_row_non_cell_elements(self) -> None:
        """Test that non-Cell elements raise TypeError."""
        table = Table()

        with pytest.raises(TypeError, match="must be Cell instances"):
            table.add_row([Cell(), "not a cell"])  # type: ignore[list-item]

    def test_add_row_inconsistent_length(self) -> None:
        """Test that inconsistent row length raises ValueError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(ValueError, match="doesn't match table width"):
            table.add_row([Cell()])

    def test_insert_row_at_start(self) -> None:
        """Test inserting row at the beginning."""
        table = Table()
        row1 = [Cell(), Cell()]
        row2 = [Cell(), Cell()]

        table.add_row(row1)
        table.insert_row(0, row2)

        assert len(table.rows) == 2
        assert table.rows[0] == row2

    def test_insert_row_at_end(self) -> None:
        """Test inserting row at the end."""
        table = Table()
        row1 = [Cell(), Cell()]
        row2 = [Cell(), Cell()]

        table.add_row(row1)
        table.insert_row(1, row2)

        assert len(table.rows) == 2
        assert table.rows[1] == row2

    def test_insert_row_invalid_index(self) -> None:
        """Test that invalid insert index raises IndexError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(IndexError, match="out of range"):
            table.insert_row(-1, [Cell(), Cell()])

        with pytest.raises(IndexError, match="out of range"):
            table.insert_row(10, [Cell(), Cell()])

    def test_remove_row(self) -> None:
        """Test removing row by index."""
        table = Table()
        row1 = [Cell(), Cell()]
        row2 = [Cell(), Cell()]
        table.add_row(row1)
        table.add_row(row2)

        removed = table.remove_row(0)
        assert removed == row1
        assert len(table.rows) == 1
        assert table.rows[0] == row2

    def test_remove_row_invalid_index(self) -> None:
        """Test that invalid remove index raises IndexError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(IndexError, match="out of range"):
            table.remove_row(-1)

        with pytest.raises(IndexError, match="out of range"):
            table.remove_row(10)


class TestTableCellAccess:
    """Test getting and setting individual cells."""

    def test_get_cell_valid_position(self) -> None:
        """Test getting cell at valid position."""
        table = Table()
        cell = Cell()
        table.add_row([cell, Cell()])

        retrieved = table.get_cell(0, 0)
        assert retrieved == cell

    def test_get_cell_invalid_row(self) -> None:
        """Test that invalid row index raises IndexError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(IndexError, match="Row index .* out of range"):
            table.get_cell(10, 0)

    def test_get_cell_invalid_col(self) -> None:
        """Test that invalid column index raises IndexError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(IndexError, match="Column index .* out of range"):
            table.get_cell(0, 10)

    def test_get_cell_empty_table(self) -> None:
        """Test that getting cell from empty table raises IndexError."""
        table = Table()

        with pytest.raises(IndexError, match="Row index .* out of range"):
            table.get_cell(0, 0)

    def test_set_cell_valid_position(self) -> None:
        """Test setting cell at valid position."""
        table = Table()
        table.add_row([Cell(), Cell()])

        new_cell = Cell()
        new_cell.content.add_run(Run(text="New"))
        table.set_cell(0, 0, new_cell)

        assert table.get_cell(0, 0) == new_cell

    def test_set_cell_invalid_type(self) -> None:
        """Test that setting non-Cell raises TypeError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(TypeError, match="Expected Cell instance"):
            table.set_cell(0, 0, "not a cell")  # type: ignore[arg-type]

    def test_set_cell_invalid_row(self) -> None:
        """Test that invalid row index raises IndexError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(IndexError, match="Row index .* out of range"):
            table.set_cell(10, 0, Cell())

    def test_set_cell_invalid_col(self) -> None:
        """Test that invalid column index raises IndexError."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(IndexError, match="Column index .* out of range"):
            table.set_cell(0, 10, Cell())

    def test_set_cell_empty_table(self) -> None:
        """Test that setting cell in empty table raises IndexError."""
        table = Table()

        with pytest.raises(IndexError, match="Row index .* out of range"):
            table.set_cell(0, 0, Cell())


class TestTableDimensions:
    """Test table dimension queries."""

    def test_get_dimensions_empty_table(self) -> None:
        """Test dimensions of empty table."""
        table = Table()
        assert table.get_dimensions() == (0, 0)

    def test_get_dimensions_single_row(self) -> None:
        """Test dimensions with single row."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])
        assert table.get_dimensions() == (1, 3)

    def test_get_dimensions_multiple_rows(self) -> None:
        """Test dimensions with multiple rows."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])
        assert table.get_dimensions() == (3, 2)


class TestTableValidation:
    """Test table validation logic."""

    def test_validate_empty_table(self) -> None:
        """Test validating empty table."""
        table = Table()
        table.validate()  # Should not raise

    def test_validate_valid_table(self) -> None:
        """Test validating table with valid structure."""
        table = Table()
        row1 = [Cell(), Cell()]
        row1[0].content.add_run(Run(text="A"))
        row1[1].content.add_run(Run(text="B"))
        table.add_row(row1)

        table.validate()  # Should not raise

    def test_validate_inconsistent_row_lengths(self) -> None:
        """Test validation fails for inconsistent row lengths."""
        table = Table()
        table.rows.append([Cell(), Cell()])
        table.rows.append([Cell()])  # Different length

        with pytest.raises(ValueError, match="has .* cells, expected"):
            table.validate()

    def test_validate_non_cell_in_row(self) -> None:
        """Test validation fails for non-Cell in row."""
        table = Table()
        table.rows.append([Cell(), "not a cell"])  # type: ignore[list-item]

        with pytest.raises(TypeError, match="not a Cell instance"):
            table.validate()

    def test_validate_invalid_cell_content(self) -> None:
        """Test validation fails when cell validation fails."""
        table = Table()
        cell = Cell()
        cell.content.add_run(Run(text=""))  # Empty run - invalid
        table.add_row([cell])

        with pytest.raises(ValueError, match="validation failed"):
            table.validate()

    def test_validate_column_widths_mismatch(self) -> None:
        """Test validation fails when column_widths length doesn't match."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])
        table.column_widths = [1.0, 2.0]  # Only 2 widths for 3 columns

        with pytest.raises(ValueError, match="doesn't match table width"):
            table.validate()

    def test_validate_column_widths_match(self) -> None:
        """Test validation passes when column_widths match."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])
        table.column_widths = [1.0, 2.0, 3.0]

        table.validate()  # Should not raise


class TestTableCopy:
    """Test table copying functionality."""

    def test_copy_empty_table(self) -> None:
        """Test copying empty table."""
        table = Table()
        table_copy = table.copy()

        assert table_copy is not table
        assert table_copy.rows is not table.rows

    def test_copy_preserves_settings(self) -> None:
        """Test that copy preserves all settings."""
        table = Table(
            border_style=TableBorder.DOUBLE,
            column_widths=[1.0, 2.0],
        )
        table.add_row([Cell(), Cell()])
        table_copy = table.copy()

        assert table_copy.border_style == table.border_style
        assert table_copy.column_widths == table.column_widths
        assert len(table_copy.rows) == len(table.rows)

    def test_copy_creates_independent_cells(self) -> None:
        """Test that copied cells are independent."""
        table = Table()
        cell = Cell()
        cell.content.add_run(Run(text="Original"))
        table.add_row([cell])

        table_copy = table.copy()
        table_copy.rows[0][0].content.runs[0].text = "Modified"

        assert table.rows[0][0].content.runs[0].text == "Original"
        assert table_copy.rows[0][0].content.runs[0].text == "Modified"

    def test_copy_multiple_rows(self) -> None:
        """Test copying table with multiple rows."""
        table = Table()
        for i in range(3):
            row = [Cell(), Cell()]
            row[0].content.add_run(Run(text=f"Row {i}"))
            table.add_row(row)

        table_copy = table.copy()

        assert len(table_copy.rows) == 3
        for i in range(3):
            assert table_copy.rows[i][0].content.get_text() == f"Row {i}"


class TestTableSerialization:
    """Test table serialization."""

    def test_to_dict_minimal(self) -> None:
        """Test serialization with default values."""
        table = Table()
        data = table.to_dict()

        assert data["rows"] == []
        assert data["border_style"] == "single"
        assert data["column_widths"] is None

    def test_to_dict_full(self) -> None:
        """Test serialization with all attributes."""
        table = Table(
            border_style=TableBorder.DOUBLE,
            column_widths=[1.0, 2.0],
        )
        cell = Cell()
        cell.content.add_run(Run(text="Test"))
        table.add_row([cell, Cell()])

        data = table.to_dict()

        assert data["border_style"] == "double"
        assert data["column_widths"] == [1.0, 2.0]
        assert len(data["rows"]) == 1
        assert len(data["rows"][0]) == 2

    def test_from_dict_minimal(self) -> None:
        """Test deserialization with minimal data."""
        data: dict[str, Any] = {}
        table = Table.from_dict(data)

        assert len(table.rows) == 0
        assert table.border_style == TableBorder.SINGLE

    def test_from_dict_full(self) -> None:
        """Test deserialization with complete data."""
        data = {
            "rows": [
                [
                    {"content": {"runs": [{"text": "A"}]}, "colspan": 1, "rowspan": 1},
                    {"content": {"runs": [{"text": "B"}]}, "colspan": 1, "rowspan": 1},
                ]
            ],
            "border_style": "double",
            "column_widths": [1.0, 2.0],
        }

        table = Table.from_dict(data)

        assert len(table.rows) == 1
        assert len(table.rows[0]) == 2
        assert table.rows[0][0].content.get_text() == "A"
        assert table.border_style == TableBorder.DOUBLE
        assert table.column_widths == [1.0, 2.0]

    def test_from_dict_invalid_type(self) -> None:
        """Test that non-dict input raises TypeError."""
        with pytest.raises(TypeError, match="Expected dict"):
            Table.from_dict("not a dict")  # type: ignore[arg-type]

    def test_from_dict_invalid_border_style(self) -> None:
        """Test that invalid border_style raises ValueError."""
        data = {"border_style": "invalid"}

        with pytest.raises(ValueError, match="Invalid border_style"):
            Table.from_dict(data)

    def test_from_dict_rows_not_list(self) -> None:
        """Test that non-list rows raises TypeError."""
        data = {"rows": "not a list"}

        with pytest.raises(TypeError, match="'rows' must be list"):
            Table.from_dict(data)

    def test_roundtrip_serialization(self) -> None:
        """Test that to_dict/from_dict roundtrip preserves data."""
        original = Table(border_style=TableBorder.ASCII_ART)
        cell = Cell(colspan=2)
        cell.content.add_run(Run(text="Test"))
        original.add_row([cell, Cell()])

        data = original.to_dict()
        restored = Table.from_dict(data)

        assert restored.border_style == original.border_style
        assert len(restored.rows) == len(original.rows)
        assert restored.rows[0][0].colspan == 2


class TestTableRepr:
    """Test table string representation."""

    def test_repr_empty_table(self) -> None:
        """Test __repr__ for empty table."""
        table = Table()
        repr_str = repr(table)

        assert "Table" in repr_str
        assert "rows=0" in repr_str
        assert "cols=0" in repr_str

    def test_repr_with_content(self) -> None:
        """Test __repr__ for table with content."""
        table = Table(border_style=TableBorder.DOUBLE)
        table.add_row([Cell(), Cell(), Cell()])
        table.add_row([Cell(), Cell(), Cell()])

        repr_str = repr(table)

        assert "rows=2" in repr_str
        assert "cols=3" in repr_str
        assert "border='double'" in repr_str


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_table_with_single_cell(self) -> None:
        """Test table with single cell."""
        table = Table()
        table.add_row([Cell()])

        assert table.get_dimensions() == (1, 1)
        table.validate()

    def test_cell_with_large_span(self) -> None:
        """Test cell with maximum allowed span."""
        cell = Cell(colspan=MAX_SPAN, rowspan=MAX_SPAN)
        cell.validate()

        assert cell.colspan == MAX_SPAN
        assert cell.rowspan == MAX_SPAN

    def test_all_border_styles(self) -> None:
        """Test creating tables with all border styles."""
        for border_style in TableBorder:
            table = Table(border_style=border_style)
            assert table.border_style == border_style

    def test_large_table(self) -> None:
        """Test table with many rows and columns."""
        table = Table()
        for _ in range(50):
            table.add_row([Cell() for _ in range(10)])

        assert table.get_dimensions() == (50, 10)
        table.validate()


class TestIntegration:
    """Integration tests combining multiple operations."""

    def test_build_validate_serialize(self) -> None:
        """Test complete workflow: build, validate, serialize."""
        table = Table(border_style=TableBorder.DOUBLE)

        # Add rows with content
        for i in range(3):
            row = []
            for j in range(4):
                cell = Cell()
                cell.content.add_run(Run(text=f"R{i}C{j}"))
                row.append(cell)
            table.add_row(row)

        table.validate()
        data = table.to_dict()
        restored = Table.from_dict(data)

        assert restored.get_dimensions() == table.get_dimensions()
        assert restored.border_style == table.border_style

    def test_modify_and_validate(self) -> None:
        """Test modifying table and revalidating."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.validate()

        # Modify a cell
        new_cell = Cell()
        new_cell.content.add_run(Run(text="Modified"))
        table.set_cell(0, 0, new_cell)

        table.validate()

        # ИСПРАВЛЕНО: проверка на None перед доступом к content
        retrieved_cell = table.get_cell(0, 0)
        assert retrieved_cell is not None
        assert retrieved_cell.content.get_text() == "Modified"

    def test_complex_table_structure(self) -> None:
        """Test table with complex cell structure."""
        table = Table(border_style=TableBorder.ASCII_ART)

        # First row: 3 cells (first has colspan=2 for rendering)
        row1 = [Cell(colspan=2), Cell(), Cell()]
        row1[0].content.add_run(Run(text="Merged", bold=True))

        # Second row: 3 cells
        row2 = [Cell(), Cell(), Cell()]
        for i, cell in enumerate(row2):
            cell.content.add_run(Run(text=f"Cell {i}"))

        table.add_row(row1)
        table.add_row(row2)

        table.validate()
        assert table.get_dimensions() == (2, 3)
        assert table.rows[0][0].colspan == 2
