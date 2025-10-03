"""
Модель таблицы с ячейками, границами и поддержкой объединения.

Table model representing a grid structure with cells, borders, and merge
capabilities for ESC/P matrix printer output. Each cell contains a paragraph
with formatted text.

Module: src/model/table.py
Project: ESC/P Text Editor
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

from src.model.paragraph import Paragraph

logger: Final = logging.getLogger(__name__)


class TableBorder(Enum):
    """Border styles for table rendering."""

    NONE = "none"
    SINGLE = "single"
    DOUBLE = "double"
    ASCII_ART = "ascii_art"


# Cell span constraints
MIN_SPAN: Final[int] = 1
MAX_SPAN: Final[int] = 100


@dataclass(slots=True)
class Cell:
    """
    Represents a single cell in a table.

    A Cell contains formatted content (Paragraph) and can span multiple
    rows/columns through colspan and rowspan attributes.

    Attributes:
        content: Paragraph containing the cell's formatted text.
        colspan: Number of columns this cell spans (≥1).
        rowspan: Number of rows this cell spans (≥1).

    Example:
        >>> cell = Cell()
        >>> cell.content.add_run(Run(text="Cell content"))
        >>> cell.colspan = 2
        >>> cell.validate()
    """

    content: Paragraph = field(default_factory=Paragraph)
    colspan: int = 1
    rowspan: int = 1

    def __post_init__(self) -> None:
        """Validate and normalize attributes after initialization."""
        # Clamp colspan
        if not (MIN_SPAN <= self.colspan <= MAX_SPAN):
            logger.warning(
                f"colspan {self.colspan} out of range [{MIN_SPAN}, {MAX_SPAN}], clamping"
            )
            object.__setattr__(self, "colspan", max(MIN_SPAN, min(self.colspan, MAX_SPAN)))

        # Clamp rowspan
        if not (MIN_SPAN <= self.rowspan <= MAX_SPAN):
            logger.warning(
                f"rowspan {self.rowspan} out of range [{MIN_SPAN}, {MAX_SPAN}], clamping"
            )
            object.__setattr__(self, "rowspan", max(MIN_SPAN, min(self.rowspan, MAX_SPAN)))

    def validate(self) -> None:
        """
        Validate cell content and span values.

        Raises:
            ValueError: If span values are invalid.
            TypeError: If content is not a Paragraph.

        Example:
            >>> cell = Cell()
            >>> cell.validate()  # OK
        """
        if not isinstance(self.content, Paragraph):
            raise TypeError(f"Cell content must be Paragraph, got {type(self.content).__name__}")

        if not (MIN_SPAN <= self.colspan <= MAX_SPAN):
            raise ValueError(f"colspan {self.colspan} out of range [{MIN_SPAN}, {MAX_SPAN}]")

        if not (MIN_SPAN <= self.rowspan <= MAX_SPAN):
            raise ValueError(f"rowspan {self.rowspan} out of range [{MIN_SPAN}, {MAX_SPAN}]")

        # Validate content
        try:
            self.content.validate()
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Cell content validation failed: {exc}") from exc

        logger.debug(f"Validated cell: colspan={self.colspan}, rowspan={self.rowspan}")

    def copy(self) -> "Cell":
        """
        Create a deep copy of the cell.

        Returns:
            A new Cell with copied content and span values.

        Example:
            >>> cell = Cell()
            >>> cell_copy = cell.copy()
            >>> cell_copy is not cell
            True
        """
        return Cell(
            content=self.content.copy(),
            colspan=self.colspan,
            rowspan=self.rowspan,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize cell to dictionary.

        Returns:
            Dictionary with cell attributes.

        Example:
            >>> cell = Cell(colspan=2)
            >>> data = cell.to_dict()
            >>> data["colspan"]
            2
        """
        return {
            "content": self.content.to_dict(),
            "colspan": self.colspan,
            "rowspan": self.rowspan,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Cell":
        """
        Deserialize cell from dictionary.

        Args:
            data: Dictionary with cell attributes.

        Returns:
            Cell instance reconstructed from dictionary.

        Raises:
            TypeError: If data is not a dictionary.

        Example:
            >>> data = {"content": {}, "colspan": 2}
            >>> cell = Cell.from_dict(data)
            >>> cell.colspan
            2
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        content_data = data.get("content", {})
        content = Paragraph.from_dict(content_data)

        return Cell(
            content=content,
            colspan=data.get("colspan", 1),
            rowspan=data.get("rowspan", 1),
        )

    def __repr__(self) -> str:
        """Return string representation."""
        return f"Cell(colspan={self.colspan}, rowspan={self.rowspan}, chars={len(self.content)})"


@dataclass(slots=True)
class Table:
    """
    Represents a table with rows and columns.

    A Table is a 2D grid of Cell objects with support for borders,
    column widths, and cell merging through colspan/rowspan.

    Attributes:
        rows: 2D list of Cell objects (rows × columns).
        border_style: Border rendering style for the table.
        column_widths: Optional explicit column widths in inches.

    Example:
        >>> table = Table()
        >>> row = [Cell(), Cell(), Cell()]
        >>> table.add_row(row)
        >>> table.get_dimensions()
        (1, 3)
    """

    rows: list[list[Cell]] = field(default_factory=list)
    border_style: TableBorder = TableBorder.SINGLE
    column_widths: list[float] | None = None

    def add_row(self, cells: list[Cell]) -> None:
        """
        Append a row to the table.

        Args:
            cells: List of Cell objects for the new row.

        Raises:
            TypeError: If cells is not a list or contains non-Cell objects.
            ValueError: If row length doesn't match existing rows.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> table.get_dimensions()
            (1, 2)
        """
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")

        if not all(isinstance(cell, Cell) for cell in cells):
            raise TypeError("All elements in cells must be Cell instances")

        # Check row length consistency
        if self.rows and len(cells) != len(self.rows[0]):
            raise ValueError(
                f"Row length {len(cells)} doesn't match table width {len(self.rows[0])}"
            )

        self.rows.append(cells)
        logger.debug(f"Added row to table, total rows: {len(self.rows)}")

    def insert_row(self, index: int, cells: list[Cell]) -> None:
        """
        Insert a row at the specified index.

        Args:
            index: Position to insert the row (0-based).
            cells: List of Cell objects for the new row.

        Raises:
            TypeError: If cells is not a list or contains non-Cell objects.
            IndexError: If index is out of valid range.
            ValueError: If row length doesn't match existing rows.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> table.insert_row(0, [Cell(), Cell()])
            >>> len(table.rows)
            2
        """
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")

        if not all(isinstance(cell, Cell) for cell in cells):
            raise TypeError("All elements in cells must be Cell instances")

        if not (0 <= index <= len(self.rows)):
            raise IndexError(f"Insert index {index} out of range for {len(self.rows)} rows")

        # Check row length consistency
        if self.rows and len(cells) != len(self.rows[0]):
            raise ValueError(
                f"Row length {len(cells)} doesn't match table width {len(self.rows[0])}"
            )

        self.rows.insert(index, cells)
        logger.debug(f"Inserted row at index {index}, total rows: {len(self.rows)}")

    def remove_row(self, index: int) -> list[Cell]:
        """
        Remove and return the row at the specified index.

        Args:
            index: Position of the row to remove (0-based).

        Returns:
            The removed list of Cell objects.

        Raises:
            IndexError: If index is out of range.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> removed = table.remove_row(0)
            >>> len(removed)
            2
        """
        if not (0 <= index < len(self.rows)):
            raise IndexError(f"Remove index {index} out of range for {len(self.rows)} rows")

        removed = self.rows.pop(index)
        logger.debug(f"Removed row at index {index}, remaining: {len(self.rows)}")
        return removed

    def get_cell(self, row: int, col: int) -> Cell | None:
        """
        Get the cell at the specified position.

        Returns None if the position is covered by a merged cell's span.

        Args:
            row: Row index (0-based).
            col: Column index (0-based).

        Returns:
            Cell at the position, or None if covered by a span.

        Raises:
            IndexError: If row or col is out of range.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> cell = table.get_cell(0, 0)
            >>> cell is not None
            True
        """
        if not (0 <= row < len(self.rows)):
            raise IndexError(f"Row index {row} out of range for {len(self.rows)} rows")

        if not self.rows:
            raise IndexError("Cannot get cell from empty table")

        if not (0 <= col < len(self.rows[0])):
            raise IndexError(f"Column index {col} out of range for {len(self.rows[0])} columns")

        return self.rows[row][col]

    def set_cell(self, row: int, col: int, cell: Cell) -> None:
        """
        Set the cell at the specified position.

        Args:
            row: Row index (0-based).
            col: Column index (0-based).
            cell: Cell object to place at the position.

        Raises:
            IndexError: If row or col is out of range.
            TypeError: If cell is not a Cell instance.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> new_cell = Cell()
            >>> table.set_cell(0, 0, new_cell)
        """
        if not isinstance(cell, Cell):
            raise TypeError(f"Expected Cell instance, got {type(cell).__name__}")

        if not (0 <= row < len(self.rows)):
            raise IndexError(f"Row index {row} out of range for {len(self.rows)} rows")

        if not self.rows:
            raise IndexError("Cannot set cell in empty table")

        if not (0 <= col < len(self.rows[0])):
            raise IndexError(f"Column index {col} out of range for {len(self.rows[0])} columns")

        self.rows[row][col] = cell
        logger.debug(f"Set cell at ({row}, {col})")

    def get_dimensions(self) -> tuple[int, int]:
        """
        Get table dimensions (rows, columns).

        Returns:
            Tuple of (row_count, column_count).

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell(), Cell()])
            >>> table.get_dimensions()
            (1, 3)
        """
        if not self.rows:
            return (0, 0)
        return (len(self.rows), len(self.rows[0]))

    def validate(self) -> None:
        """
        Validate table structure and all cells.

        Checks that:
        - All rows have the same length
        - All cells are valid
        - Column widths match table width (if specified)

        Raises:
            ValueError: If table structure is invalid.
            TypeError: If rows contain non-Cell objects.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> table.validate()  # OK
        """
        if not self.rows:
            logger.debug("Validated empty table")
            return

        # Check all rows have same length
        first_row_len = len(self.rows[0])
        for i, row in enumerate(self.rows):
            if len(row) != first_row_len:
                raise ValueError(f"Row {i} has {len(row)} cells, expected {first_row_len}")

            # Validate each cell
            for j, cell in enumerate(row):
                if not isinstance(cell, Cell):
                    raise TypeError(
                        f"Cell at ({i}, {j}) is not a Cell instance: {type(cell).__name__}"
                    )
                try:
                    cell.validate()
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"Cell at ({i}, {j}) validation failed: {exc}") from exc

        # Validate column widths if specified
        if self.column_widths is not None:
            if len(self.column_widths) != first_row_len:
                raise ValueError(
                    f"column_widths length {len(self.column_widths)} "
                    f"doesn't match table width {first_row_len}"
                )

        rows, cols = self.get_dimensions()
        logger.debug(f"Validated table: {rows}x{cols}, border={self.border_style.value}")

    def copy(self) -> "Table":
        """
        Create a deep copy of the table.

        Returns:
            A new Table with copied cells and settings.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> table_copy = table.copy()
            >>> table_copy is not table
            True
        """
        return Table(
            rows=[[cell.copy() for cell in row] for row in self.rows],
            border_style=self.border_style,
            column_widths=self.column_widths.copy() if self.column_widths else None,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize table to dictionary.

        Returns:
            Dictionary with table attributes.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> data = table.to_dict()
            >>> len(data["rows"])
            1
        """
        return {
            "rows": [[cell.to_dict() for cell in row] for row in self.rows],
            "border_style": self.border_style.value,
            "column_widths": self.column_widths,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Table":
        """
        Deserialize table from dictionary.

        Args:
            data: Dictionary with table attributes.

        Returns:
            Table instance reconstructed from dictionary.

        Raises:
            TypeError: If data is not a dictionary.
            ValueError: If border_style is invalid.

        Example:
            >>> data = {"rows": [[]], "border_style": "single"}
            >>> table = Table.from_dict(data)
            >>> table.border_style
            <TableBorder.SINGLE: 'single'>
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        # Parse rows
        rows_data = data.get("rows", [])
        if not isinstance(rows_data, list):
            raise TypeError(f"'rows' must be list, got {type(rows_data).__name__}")

        rows = [[Cell.from_dict(cell_data) for cell_data in row_data] for row_data in rows_data]

        # Parse border style
        border_style_str = data.get("border_style", "single")
        try:
            border_style = TableBorder(border_style_str)
        except ValueError as exc:
            raise ValueError(f"Invalid border_style value: {border_style_str!r}") from exc

        return Table(
            rows=rows,
            border_style=border_style,
            column_widths=data.get("column_widths"),
        )

    def __repr__(self) -> str:
        """
        Return string representation.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> repr(table)
            "Table(rows=1, cols=2, border='single')"
        """
        rows, cols = self.get_dimensions()
        return f"Table(rows={rows}, cols={cols}, border='{self.border_style.value}')"
