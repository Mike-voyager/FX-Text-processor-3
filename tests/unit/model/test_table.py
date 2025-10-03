"""
Unit tests for src/model/table.py module.

Tests cover Cell and Table classes, ESC/P generation, auto-sizing,
column operations, merged cells handling, and serialization with
comprehensive edge case coverage for FX-890 compatibility.

Version: 1.0 (production-ready)
"""

import logging
from typing import Any

import pytest

from src.model.table import (
    Cell,
    Table,
    TableBorder,
    TableStyle,
    TableMetrics,
    BorderChars,
    CellBorders,
    ColumnSizingMode,
    MIN_SPAN,
    MAX_SPAN,
)
from src.model.paragraph import Paragraph, Alignment
from src.model.run import Run


# =============================================================================
# CELL TESTS
# =============================================================================


class TestCellInitialization:
    """Test Cell initialization and validation."""

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

        assert cell.content == para
        assert cell.colspan == 2
        assert cell.rowspan == 3

    def test_clamping_colspan(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that out-of-range colspan is clamped."""
        with caplog.at_level(logging.WARNING):
            cell = Cell(colspan=200)  # Exceeds MAX_SPAN

        assert cell.colspan == MAX_SPAN
        assert "colspan" in caplog.text
        assert "clamping" in caplog.text

    def test_clamping_rowspan(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that out-of-range rowspan is clamped."""
        with caplog.at_level(logging.WARNING):
            cell = Cell(rowspan=0)  # Below MIN_SPAN

        assert cell.rowspan == MIN_SPAN
        assert "rowspan" in caplog.text


class TestCellValidation:
    """Test Cell validation logic."""

    def test_validate_valid_cell(self) -> None:
        """Test that valid cell passes validation."""
        cell = Cell()
        cell.content.add_run(Run(text="Valid"))
        cell.validate()  # Should not raise

    def test_validate_invalid_content(self) -> None:
        """Test that non-Paragraph content fails validation."""
        cell = Cell()
        object.__setattr__(cell, "content", "not a paragraph")

        with pytest.raises(TypeError, match="Cell content must be Paragraph"):
            cell.validate()

    def test_validate_invalid_colspan(self) -> None:
        """Test that invalid colspan fails validation after manual change."""
        cell = Cell(colspan=5)
        # Manually set invalid value (bypassing __post_init__)
        object.__setattr__(cell, "colspan", 200)

        with pytest.raises(ValueError, match="colspan .* out of range"):
            cell.validate()


class TestCellOperations:
    """Test Cell operations."""

    def test_copy_cell(self) -> None:
        """Test cell copying."""
        cell = Cell(colspan=2, rowspan=3)
        cell.content.add_run(Run(text="Test"))

        copied = cell.copy()

        assert copied is not cell
        assert copied.content is not cell.content
        assert copied.colspan == cell.colspan
        assert copied.rowspan == cell.rowspan
        assert copied.content.get_text() == cell.content.get_text()

    def test_to_dict(self) -> None:
        """Test cell serialization."""
        cell = Cell(colspan=2)
        cell.content.add_run(Run(text="Test"))

        data: dict[str, Any] = cell.to_dict()

        assert data["colspan"] == 2
        assert data["rowspan"] == 1
        assert "content" in data

    def test_from_dict(self) -> None:
        """Test cell deserialization."""
        data = {
            "content": {"runs": [], "alignment": "left"},
            "colspan": 3,
            "rowspan": 2,
        }

        cell = Cell.from_dict(data)

        assert cell.colspan == 3
        assert cell.rowspan == 2

    def test_repr(self) -> None:
        """Test cell string representation."""
        cell = Cell(colspan=2, rowspan=3)
        cell.content.add_run(Run(text="Test"))

        repr_str = repr(cell)

        assert "Cell(" in repr_str
        assert "colspan=2" in repr_str
        assert "rowspan=3" in repr_str


# =============================================================================
# TABLE TESTS
# =============================================================================


class TestTableInitialization:
    """Test Table initialization."""

    def test_minimal_initialization(self) -> None:
        """Test creating empty table."""
        table = Table()

        assert table.rows == []
        assert table.border_style == TableBorder.SINGLE
        assert table.column_widths is None

    def test_full_initialization(self) -> None:
        """Test creating table with rows."""
        rows = [[Cell(), Cell()]]
        table = Table(
            rows=rows,
            border_style=TableBorder.DOUBLE,
            column_widths=[2.0, 3.0],
        )

        assert len(table.rows) == 1
        assert table.border_style == TableBorder.DOUBLE
        assert table.column_widths == [2.0, 3.0]


class TestTableRowManagement:
    """Test table row operations."""

    def test_add_row(self) -> None:
        """Test adding row to table."""
        table = Table()
        row = [Cell(), Cell(), Cell()]

        table.add_row(row)

        assert len(table.rows) == 1
        assert len(table.rows[0]) == 3

    def test_add_row_invalid_type(self) -> None:
        """Test that adding non-list raises error."""
        table = Table()

        with pytest.raises(TypeError, match="cells must be list"):
            table.add_row("not a list")  # type: ignore

    def test_add_row_inconsistent_length(self) -> None:
        """Test that inconsistent row length raises error."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(ValueError, match="doesn't match table width"):
            table.add_row([Cell()])  # Different length

    def test_insert_row(self) -> None:
        """Test inserting row at specific index."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])

        table.insert_row(1, [Cell(), Cell()])

        assert len(table.rows) == 3

    def test_remove_row(self) -> None:
        """Test removing row."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])

        removed = table.remove_row(0)

        assert len(removed) == 2
        assert len(table.rows) == 1


class TestTableCellAccess:
    """Test table cell access methods."""

    def test_get_cell(self) -> None:
        """Test getting cell at position."""
        table = Table()
        table.add_row([Cell(), Cell()])

        cell = table.get_cell(0, 0)

        assert cell is not None
        assert isinstance(cell, Cell)

    def test_get_cell_out_of_range(self) -> None:
        """Test getting cell with invalid index."""
        table = Table()
        table.add_row([Cell(), Cell()])

        with pytest.raises(IndexError, match="out of range"):
            table.get_cell(5, 0)

    def test_set_cell(self) -> None:
        """Test setting cell at position."""
        table = Table()
        table.add_row([Cell(), Cell()])

        new_cell = Cell()
        new_cell.content.add_run(Run(text="New"))

        table.set_cell(0, 0, new_cell)

        # ИСПРАВЛЕНИЕ: добавить assert
        cell = table.get_cell(0, 0)
        assert cell is not None
        assert cell.content.get_text() == "New"

    def test_get_dimensions(self) -> None:
        """Test getting table dimensions."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])
        table.add_row([Cell(), Cell(), Cell()])

        rows, cols = table.get_dimensions()

        assert rows == 2
        assert cols == 3


# =============================================================================
# AUTO-SIZING TESTS
# =============================================================================


class TestTableAutoSizing:
    """Test column width auto-sizing."""

    def test_calculate_column_widths_auto(self) -> None:
        """Test auto-sizing based on content."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])
        table.rows[0][0].content.add_run(Run(text="Short"))
        table.rows[0][1].content.add_run(Run(text="Medium text"))
        table.rows[0][2].content.add_run(Run(text="Very long text content"))

        widths = table.calculate_column_widths(7.0, mode=ColumnSizingMode.AUTO)

        assert len(widths) == 3
        # Longer content should get wider columns
        assert widths[2] > widths[1] > widths[0]

    def test_calculate_column_widths_equal(self) -> None:
        """Test equal width distribution."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])

        widths = table.calculate_column_widths(6.0, mode=ColumnSizingMode.EQUAL)

        assert len(widths) == 3
        assert widths[0] == widths[1] == widths[2] == 2.0

    def test_calculate_column_widths_fixed(self) -> None:
        """Test fixed width mode."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.column_widths = [3.0, 4.0]

        widths = table.calculate_column_widths(10.0, mode=ColumnSizingMode.FIXED)

        assert widths == [3.0, 4.0]

    def test_calculate_column_widths_proportional(self) -> None:
        """Test proportional width distribution."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])
        table.rows[0][0].content.add_run(Run(text="A"))
        table.rows[0][1].content.add_run(Run(text="AAAA"))
        table.rows[0][2].content.add_run(Run(text="AA"))

        widths = table.calculate_column_widths(7.0, mode=ColumnSizingMode.PROPORTIONAL)

        assert len(widths) == 3
        # Should be proportional to content: 1:4:2

    def test_calculate_column_widths_with_min_width(self) -> None:
        """Test minimum column width constraint."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.rows[0][0].content.add_run(Run(text="A"))

        widths = table.calculate_column_widths(5.0, mode=ColumnSizingMode.AUTO, min_col_width=2.0)

        # Even short content should get at least min_col_width
        assert all(w >= 2.0 for w in widths)

    def test_calculate_column_widths_scale_down(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test scaling down when content exceeds available width."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.rows[0][0].content.add_run(Run(text="A" * 100))
        table.rows[0][1].content.add_run(Run(text="B" * 100))

        with caplog.at_level(logging.DEBUG):
            widths = table.calculate_column_widths(5.0, mode=ColumnSizingMode.AUTO)

        # Should scale down to fit
        assert sum(widths) <= 5.0
        assert "Scaled column widths" in caplog.text

    def test_calculate_content_widths(self) -> None:
        """Test content width calculation helper."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.rows[0][0].content.add_run(Run(text="Short"))
        table.rows[0][1].content.add_run(Run(text="Longer text"))

        char_widths = table._calculate_content_widths(page_cpi=10)

        assert len(char_widths) == 2
        assert char_widths[0] == 5  # "Short"
        assert char_widths[1] == 11  # "Longer text"

    def test_calculate_content_widths_with_colspan(self) -> None:
        """Test content width calculation with merged cells."""
        table = Table()
        cell1 = Cell(colspan=2)
        cell1.content.add_run(Run(text="Spanning"))
        table.add_row([cell1, Cell()])

        char_widths = table._calculate_content_widths(page_cpi=10)

        # Spanning text should be distributed across columns
        assert len(char_widths) == 2


# =============================================================================
# COLUMN OPERATIONS TESTS
# =============================================================================


class TestTableColumnOperations:
    """Test column manipulation methods."""

    def test_add_column(self) -> None:
        """Test adding column to table."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])

        table.add_column([Cell(), Cell()])

        rows, cols = table.get_dimensions()
        assert cols == 3

    def test_add_column_at_index(self) -> None:
        """Test adding column at specific index."""
        table = Table()
        table.add_row([Cell(), Cell()])

        table.add_column([Cell()], index=1)

        rows, cols = table.get_dimensions()
        assert cols == 3

    def test_add_column_invalid_count(self) -> None:
        """Test that wrong cell count raises error."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])

        with pytest.raises(ValueError, match="doesn't match row count"):
            table.add_column([Cell()])  # Only 1 cell for 2 rows

    def test_remove_column(self) -> None:
        """Test removing column."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])

        removed = table.remove_column(1)

        assert len(removed) == 1
        rows, cols = table.get_dimensions()
        assert cols == 2

    def test_remove_last_column_fails(self) -> None:
        """Test that removing last column raises error."""
        table = Table()
        table.add_row([Cell()])

        with pytest.raises(ValueError, match="Cannot remove last column"):
            table.remove_column(0)

    def test_swap_columns(self) -> None:
        """Test swapping two columns."""
        table = Table()
        cell1 = Cell()
        cell1.content.add_run(Run(text="A"))
        cell2 = Cell()
        cell2.content.add_run(Run(text="B"))

        table.add_row([cell1, cell2])

        table.swap_columns(0, 1)

        # ИСПРАВЛЕНИЕ: добавить assert для обоих
        cell_at_0 = table.get_cell(0, 0)
        assert cell_at_0 is not None
        assert cell_at_0.content.get_text() == "B"

        cell_at_1 = table.get_cell(0, 1)
        assert cell_at_1 is not None
        assert cell_at_1.content.get_text() == "A"


# =============================================================================
# MERGED CELLS TESTS
# =============================================================================


class TestTableMergedCells:
    """Test merged cells handling (colspan/rowspan)."""

    def test_resolve_merged_cells_simple(self) -> None:
        """Test cell position resolution without merges."""
        table = Table()
        table.add_row([Cell(), Cell()])

        cell_map = table.resolve_merged_cells()

        assert (0, 0) in cell_map
        assert (0, 1) in cell_map

    def test_resolve_merged_cells_with_colspan(self) -> None:
        """Test cell position resolution with colspan."""
        table = Table()
        cell = Cell(colspan=2)
        table.add_row([cell, Cell()])

        cell_map = table.resolve_merged_cells()

        # Both positions should point to same cell
        assert cell_map[(0, 0)][2] == cell
        assert cell_map[(0, 1)][2] == cell

    def test_resolve_merged_cells_with_rowspan(self) -> None:
        """Test cell position resolution with rowspan."""
        table = Table()
        cell = Cell(rowspan=2)
        table.add_row([cell, Cell()])
        table.add_row([Cell(), Cell()])

        cell_map = table.resolve_merged_cells()

        # Positions in both rows should point to same cell
        assert cell_map[(0, 0)][2] == cell
        assert cell_map[(1, 0)][2] == cell

    def test_get_effective_cell(self) -> None:
        """Test getting effective cell at position."""
        table = Table()
        cell = Cell(colspan=2)
        table.add_row([cell, Cell()])

        result = table.get_effective_cell(0, 1)

        assert result is not None
        effective_cell, source_row, source_col = result
        assert effective_cell == cell
        assert source_row == 0
        assert source_col == 0

    def test_is_merged_position(self) -> None:
        """Test checking if position is covered by merge."""
        table = Table()
        cell = Cell(colspan=2)
        table.add_row([cell, Cell()])

        assert not table.is_merged_position(0, 0)  # Source position
        assert table.is_merged_position(0, 1)  # Covered by colspan

    def test_count_effective_cells(self) -> None:
        """Test counting unique cells."""
        table = Table()
        cell1 = Cell(colspan=2)
        cell2 = Cell()
        table.add_row([cell1, cell2])

        count = table.count_effective_cells()

        assert count == 2  # Only 2 unique cells


# =============================================================================
# ESC/P GENERATION TESTS
# =============================================================================


class TestTableEscpGeneration:
    """Test ESC/P command generation."""

    def test_to_escp_minimal(self) -> None:
        """Test ESC/P generation for minimal table."""
        table = Table()
        table.add_row([Cell(), Cell()])

        escp = table.to_escp(page_width=8.5, page_cpi=10)

        assert isinstance(escp, bytes)
        assert len(escp) > 0

    def test_to_escp_with_content(self) -> None:
        """Test ESC/P generation with cell content."""
        table = Table()
        cell = Cell()
        cell.content.add_run(Run(text="Test"))
        table.add_row([cell, Cell()])

        escp = table.to_escp()

        assert b"Test" in escp

    def test_to_escp_with_borders(self) -> None:
        """Test ESC/P generation with borders."""
        table = Table(border_style=TableBorder.SINGLE)
        table.add_row([Cell(), Cell()])

        escp = table.to_escp()

        # Should contain border characters
        assert b"-" in escp or b"|" in escp

    def test_to_escp_no_borders(self) -> None:
        """Test ESC/P generation without borders."""
        table = Table(border_style=TableBorder.NONE)
        table.add_row([Cell(), Cell()])

        escp = table.to_escp()

        assert isinstance(escp, bytes)

    def test_to_escp_empty_table(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test ESC/P generation for empty table."""
        table = Table()

        with caplog.at_level(logging.WARNING):
            escp = table.to_escp()

        assert escp == b""
        assert "empty table" in caplog.text

    def test_render_border_line(self) -> None:
        """Test border line rendering."""
        table = Table()
        table.add_row([Cell(), Cell()])

        border_chars = BorderChars.single_line()
        col_widths = [2.0, 3.0]

        border = table._render_border_line(col_widths, border_chars, "top", page_cpi=10)

        assert isinstance(border, bytes)
        assert len(border) > 0

    def test_render_row(self) -> None:
        """Test row rendering."""
        table = Table()
        cell = Cell()
        cell.content.add_run(Run(text="Test"))
        row = [cell, Cell()]

        border_chars = BorderChars.single_line()
        style = TableStyle()
        col_widths = [2.0, 2.0]

        row_escp = table._render_row(row, col_widths, border_chars, style, 10)

        assert isinstance(row_escp, bytes)
        assert b"Test" in row_escp

    def test_render_cell(self) -> None:
        """Test cell rendering."""
        table = Table()
        cell = Cell()
        cell.content.add_run(Run(text="Test"))

        style = TableStyle()

        cell_escp = table._render_cell(cell, 2.0, style, 10)

        assert isinstance(cell_escp, bytes)
        assert b"Test" in cell_escp


# =============================================================================
# METRICS TESTS
# =============================================================================


class TestTableMetrics:
    """Test table metrics calculation."""

    def test_calculate_metrics_basic(self) -> None:
        """Test basic metrics calculation."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])

        metrics = table.calculate_metrics(page_width=8.5, page_cpi=10)

        assert isinstance(metrics, TableMetrics)
        assert metrics.total_width_inches > 0
        assert metrics.total_height_inches > 0
        assert len(metrics.column_widths) == 3
        assert len(metrics.row_heights) == 1

    def test_calculate_metrics_empty_table(self) -> None:
        """Test metrics for empty table."""
        table = Table()

        metrics = table.calculate_metrics()

        assert metrics.total_width_inches == 0.0
        assert metrics.total_height_inches == 0.0
        assert metrics.cell_count == 0

    def test_calculate_metrics_with_content(self) -> None:
        """Test metrics with actual content."""
        table = Table()
        cell = Cell()
        cell.content.add_run(Run(text="Test content"))
        table.add_row([cell, Cell()])

        metrics = table.calculate_metrics()

        assert metrics.cell_count == 2
        assert metrics.escp_byte_count > 0

    def test_calculate_metrics_with_borders(self) -> None:
        """Test metrics accounting for borders."""
        table = Table(border_style=TableBorder.SINGLE)
        table.add_row([Cell(), Cell()])

        metrics = table.calculate_metrics()

        assert metrics.border_char_count > 0

    def test_metrics_to_dict(self) -> None:
        """Test metrics serialization."""
        table = Table()
        table.add_row([Cell(), Cell()])

        metrics = table.calculate_metrics()
        data: dict[str, Any] = metrics.to_dict()

        assert isinstance(data, dict)
        assert "total_width_inches" in data
        assert "cell_count" in data

    def test_estimate_print_time(self) -> None:
        """Test print time estimation."""
        table = Table()
        cell = Cell()
        cell.content.add_run(Run(text="A" * 100))
        table.add_row([cell, Cell()])

        time_seconds = table.estimate_print_time(chars_per_second=300)

        assert time_seconds > 0
        assert isinstance(time_seconds, float)


# =============================================================================
# VALIDATION TESTS
# =============================================================================


class TestTableValidation:
    """Test table validation."""

    def test_validate_valid_table(self) -> None:
        """Test that valid table passes validation."""
        table = Table()
        table.add_row([Cell(), Cell()])

        table.validate()  # Should not raise

    def test_validate_empty_table(self) -> None:
        """Test validation of empty table."""
        table = Table()

        table.validate()  # Should not raise

    def test_validate_inconsistent_row_lengths(self) -> None:
        """Test that inconsistent row lengths fail validation."""
        table = Table()
        table.add_row([Cell(), Cell()])
        # Manually add inconsistent row (bypassing add_row checks)
        table.rows.append([Cell()])

        with pytest.raises(ValueError, match="Row .* has .* cells, expected"):
            table.validate()

    def test_validate_non_cell_object(self) -> None:
        """Test that non-Cell object fails validation."""
        table = Table()
        table.add_row([Cell(), Cell()])
        # Manually corrupt table
        table.rows[0][0] = "not a cell"  # type: ignore

        with pytest.raises(TypeError, match="not a Cell instance"):
            table.validate()

    def test_validate_invalid_cell(self) -> None:
        """Test that invalid cell content fails validation."""
        table = Table()
        cell = Cell()
        # Make cell content invalid
        object.__setattr__(cell.content, "alignment", "invalid")
        table.add_row([cell])

        with pytest.raises(ValueError, match="Cell .* validation failed"):
            table.validate()

    def test_validate_column_widths_mismatch(self) -> None:
        """Test that mismatched column_widths fails validation."""
        table = Table()
        table.add_row([Cell(), Cell(), Cell()])
        table.column_widths = [1.0, 2.0]  # Only 2 widths for 3 columns

        with pytest.raises(ValueError, match="column_widths length .* doesn't match"):
            table.validate()


# =============================================================================
# SERIALIZATION TESTS
# =============================================================================


class TestTableSerialization:
    """Test table serialization."""

    def test_to_dict_minimal(self) -> None:
        """Test serialization of empty table."""
        table = Table()

        data: dict[str, Any] = table.to_dict()

        assert data["rows"] == []
        assert data["border_style"] == "single"
        assert data["column_widths"] is None

    def test_to_dict_with_rows(self) -> None:
        """Test serialization with rows."""
        table = Table()
        table.add_row([Cell(), Cell()])

        data: dict[str, Any] = table.to_dict()

        assert len(data["rows"]) == 1
        assert len(data["rows"][0]) == 2

    def test_from_dict_minimal(self) -> None:
        """Test deserialization of minimal data."""
        data: dict[str, Any] = {
            "rows": [],
            "border_style": "single",
            "column_widths": None,
        }

        table = Table.from_dict(data)

        assert len(table.rows) == 0
        assert table.border_style == TableBorder.SINGLE

    def test_from_dict_invalid_border_style(self) -> None:
        """Test that invalid border_style raises error."""
        data: dict[str, Any] = {  # ← ADD TYPE
            "rows": [],
            "border_style": "invalid",
        }

        with pytest.raises(ValueError, match="Invalid border_style"):
            Table.from_dict(data)

    def test_roundtrip_serialization(self) -> None:
        """Test that to_dict/from_dict roundtrip preserves data."""
        original = Table(border_style=TableBorder.DOUBLE)
        cell = Cell(colspan=2)
        cell.content.add_run(Run(text="Test"))
        original.add_row([cell, Cell()])

        data = original.to_dict()
        restored = Table.from_dict(data)

        assert restored.border_style == original.border_style
        assert len(restored.rows) == len(original.rows)
        assert restored.rows[0][0].colspan == original.rows[0][0].colspan


# =============================================================================
# UTILITY METHODS TESTS
# =============================================================================


class TestTableUtilityMethods:
    """Test utility methods."""

    def test_clear(self) -> None:
        """Test clearing table."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])

        table.clear()

        assert len(table.rows) == 0

    def test_transpose(self) -> None:
        """Test transposing table."""
        table = Table()
        cell1 = Cell()
        cell1.content.add_run(Run(text="A"))
        cell2 = Cell()
        cell2.content.add_run(Run(text="B"))
        cell3 = Cell()
        cell3.content.add_run(Run(text="C"))
        cell4 = Cell()
        cell4.content.add_run(Run(text="D"))

        table.add_row([cell1, cell2])
        table.add_row([cell3, cell4])

        transposed = table.transpose()

        # Original: [[A, B], [C, D]]
        # Transposed: [[A, C], [B, D]]
        assert transposed.get_dimensions() == (2, 2)

        # ИСПРАВЛЕНИЕ: добавить assert для всех
        cell_00 = transposed.get_cell(0, 0)
        assert cell_00 is not None  # ← ADD THIS
        assert cell_00.content.get_text() == "A"

        cell_01 = transposed.get_cell(0, 1)
        assert cell_01 is not None  # ← ADD THIS
        assert cell_01.content.get_text() == "C"

        cell_10 = transposed.get_cell(1, 0)
        assert cell_10 is not None  # ← ADD THIS
        assert cell_10.content.get_text() == "B"

        cell_11 = transposed.get_cell(1, 1)
        assert cell_11 is not None  # ← ADD THIS
        assert cell_11.content.get_text() == "D"

    def test_transpose_empty_table(self) -> None:
        """Test transposing empty table."""
        table = Table()

        transposed = table.transpose()

        assert len(transposed.rows) == 0

    def test_fill_cells(self) -> None:
        """Test filling all cells with text."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])

        table.fill_cells("Test")

        for row in table.rows:
            for cell in row:
                assert cell.content.get_text() == "Test"

    def test_copy_table(self) -> None:
        """Test table copying."""
        table = Table(border_style=TableBorder.DOUBLE)
        table.add_row([Cell(), Cell()])

        copied = table.copy()

        assert copied is not table
        assert copied.rows is not table.rows
        assert copied.border_style == table.border_style


# =============================================================================
# MAGIC METHODS TESTS
# =============================================================================


class TestTableMagicMethods:
    """Test magic methods."""

    def test_len(self) -> None:
        """Test __len__ returns row count."""
        table = Table()
        assert len(table) == 0

        table.add_row([Cell(), Cell()])
        assert len(table) == 1

        table.add_row([Cell(), Cell()])
        assert len(table) == 2

    def test_getitem(self) -> None:
        """Test __getitem__ for row access."""
        table = Table()
        row = [Cell(), Cell()]
        table.add_row(row)

        retrieved_row = table[0]

        assert retrieved_row == row

    def test_iter(self) -> None:
        """Test __iter__ for iteration."""
        table = Table()
        table.add_row([Cell(), Cell()])
        table.add_row([Cell(), Cell()])

        rows = list(table)

        assert len(rows) == 2

    def test_eq_identical_tables(self) -> None:
        """Test equality of identical tables."""
        table1 = Table(border_style=TableBorder.DOUBLE)
        table1.add_row([Cell(), Cell()])

        table2 = Table(border_style=TableBorder.DOUBLE)
        table2.add_row([Cell(), Cell()])

        assert table1 == table2

    def test_eq_different_tables(self) -> None:
        """Test inequality of different tables."""
        table1 = Table(border_style=TableBorder.SINGLE)
        table2 = Table(border_style=TableBorder.DOUBLE)

        assert table1 != table2

    def test_repr(self) -> None:
        """Test __repr__ output."""
        table = Table(border_style=TableBorder.DOUBLE)
        table.add_row([Cell(), Cell(), Cell()])
        table.add_row([Cell(), Cell(), Cell()])

        repr_str = repr(table)

        assert "Table(" in repr_str
        assert "rows=2" in repr_str
        assert "cols=3" in repr_str
        assert "border='double'" in repr_str


# =============================================================================
# BORDER CHARS TESTS
# =============================================================================


class TestBorderChars:
    """Test BorderChars dataclass."""

    def test_single_line(self) -> None:
        """Test single-line border characters."""
        chars = BorderChars.single_line()

        assert chars.horizontal == "-"
        assert chars.vertical == "|"
        assert chars.top_left == "+"

    def test_double_line(self) -> None:
        """Test double-line border characters."""
        chars = BorderChars.double_line()

        assert chars.horizontal == "="
        assert chars.top_left == "+"

    def test_box_drawing(self) -> None:
        """Test box-drawing characters."""
        chars = BorderChars.box_drawing()

        assert chars.horizontal == "─"
        assert chars.vertical == "│"
        assert chars.top_left == "┌"

    def test_for_style(self) -> None:
        """Test getting chars for style."""
        chars_single = BorderChars.for_style(TableBorder.SINGLE)
        chars_double = BorderChars.for_style(TableBorder.DOUBLE)
        chars_ascii = BorderChars.for_style(TableBorder.ASCII_ART)

        assert chars_single.horizontal == "-"
        assert chars_double.horizontal == "="
        assert chars_ascii.horizontal == "─"


# =============================================================================
# TABLE STYLE TESTS
# =============================================================================


class TestTableStyle:
    """Test TableStyle dataclass."""

    def test_default_initialization(self) -> None:
        """Test default style values."""
        style = TableStyle()

        assert style.border == TableBorder.SINGLE
        assert style.cell_padding == 0.05
        assert style.row_spacing == 0.0
        assert style.column_spacing == 0.0

    def test_custom_initialization(self) -> None:
        """Test custom style values."""
        style = TableStyle(
            border=TableBorder.DOUBLE,
            cell_padding=0.1,
            row_spacing=0.05,
            column_spacing=0.05,
        )

        assert style.border == TableBorder.DOUBLE
        assert style.cell_padding == 0.1

    def test_validate(self) -> None:
        """Test style validation."""
        style = TableStyle()
        style.validate()  # Should not raise

    def test_validate_negative_padding(self) -> None:
        """Test that negative padding fails validation."""
        style = TableStyle(cell_padding=-0.1)

        with pytest.raises(ValueError, match="cell_padding cannot be negative"):
            style.validate()

    def test_to_dict(self) -> None:
        """Test style serialization."""
        style = TableStyle(border=TableBorder.DOUBLE, cell_padding=0.1)

        data: dict[str, Any] = style.to_dict()

        assert data["border"] == "double"
        assert data["cell_padding"] == 0.1

    def test_from_dict(self) -> None:
        """Test style deserialization."""
        data = {
            "border": "double",
            "cell_padding": 0.1,
            "row_spacing": 0.05,
            "column_spacing": 0.0,
        }

        style = TableStyle.from_dict(data)

        assert style.border == TableBorder.DOUBLE
        assert style.cell_padding == 0.1


# =============================================================================
# EDGE CASES AND INTEGRATION TESTS
# =============================================================================


class TestTableEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_large_table(self) -> None:
        """Test table with many rows."""
        table = Table()
        for _ in range(100):
            table.add_row([Cell(), Cell()])

        assert len(table.rows) == 100
        table.validate()

    def test_very_wide_table(self) -> None:
        """Test table with many columns."""
        table = Table()
        row = [Cell() for _ in range(50)]
        table.add_row(row)

        rows, cols = table.get_dimensions()
        assert cols == 50

    def test_complex_merged_cells(self) -> None:
        """Test complex cell merging scenario."""
        table = Table()
        cell1 = Cell(colspan=2, rowspan=2)
        cell2 = Cell()
        cell3 = Cell(colspan=2)

        table.add_row([cell1, cell2])
        table.add_row([cell3, Cell()])

        table.validate()
        cell_map = table.resolve_merged_cells()
        assert len(cell_map) > 0


class TestTableIntegration:
    """Integration tests combining multiple features."""

    def test_full_workflow(self) -> None:
        """Test complete workflow: create, populate, render."""
        table = Table(border_style=TableBorder.SINGLE)

        # Add rows with content
        for i in range(3):
            row = []
            for j in range(3):
                cell = Cell()
                cell.content.add_run(Run(text=f"Cell{i}{j}"))
                row.append(cell)
            table.add_row(row)

        # Validate
        table.validate()

        # Calculate metrics
        metrics = table.calculate_metrics()
        assert metrics.cell_count == 9

        # Generate ESC/P
        escp = table.to_escp(page_width=8.5, page_cpi=10)
        assert len(escp) > 0

        # Serialize

        data: dict[str, Any] = table.to_dict()
        restored = Table.from_dict(data)
        assert restored.get_dimensions() == table.get_dimensions()
