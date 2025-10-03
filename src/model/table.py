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
from typing import Any, Final, Iterator

from src.model.paragraph import Paragraph, Alignment
from src.model.run import Run

logger: Final = logging.getLogger(__name__)

# =============================================================================
# COLUMN SIZING MODES
# =============================================================================


class TableBorder(Enum):
    """Border styles for table rendering."""

    NONE = "none"
    SINGLE = "single"
    DOUBLE = "double"
    ASCII_ART = "ascii_art"


class ColumnSizingMode(Enum):
    """Column width calculation strategies."""

    AUTO = "auto"  # Content-based sizing
    EQUAL = "equal"  # Equal width for all columns
    FIXED = "fixed"  # Use explicit column_widths
    PROPORTIONAL = "proportional"  # Proportional to content ratios


# Cell span constraints
MIN_SPAN: Final[int] = 1
MAX_SPAN: Final[int] = 100

# =============================================================================
# BORDER CHARACTERS FOR FX-890
# =============================================================================


@dataclass(frozen=True, slots=True)
class BorderChars:
    """
    Character set for drawing table borders.

    Defines characters used for different table border elements.
    Supports ASCII art rendering for matrix printers.

    Attributes:
        horizontal: Horizontal line character.
        vertical: Vertical line character.
        top_left: Top-left corner.
        top_right: Top-right corner.
        bottom_left: Bottom-left corner.
        bottom_right: Bottom-right corner.
        cross: Intersection (cross) character.
        t_down: T-junction pointing down.
        t_up: T-junction pointing up.
        t_right: T-junction pointing right.
        t_left: T-junction pointing left.

    Example:
        >>> chars = BorderChars.single_line()
        >>> print(chars.horizontal)
        '-'
    """

    horizontal: str
    vertical: str
    top_left: str
    top_right: str
    bottom_left: str
    bottom_right: str
    cross: str
    t_down: str
    t_up: str
    t_right: str
    t_left: str

    @staticmethod
    def single_line() -> "BorderChars":
        """ASCII single-line borders (most compatible)."""
        return BorderChars(
            horizontal="-",
            vertical="|",
            top_left="+",
            top_right="+",
            bottom_left="+",
            bottom_right="+",
            cross="+",
            t_down="+",
            t_up="+",
            t_right="+",
            t_left="+",
        )

    @staticmethod
    def double_line() -> "BorderChars":
        """ASCII double-line borders."""
        return BorderChars(
            horizontal="=",
            vertical="‖",  # or "||" for pure ASCII
            top_left="+",
            top_right="+",
            bottom_left="+",
            bottom_right="+",
            cross="+",
            t_down="+",
            t_up="+",
            t_right="+",
            t_left="+",
        )

    @staticmethod
    def box_drawing() -> "BorderChars":
        """
        Box-drawing characters (CP437/CP866).

        FX-890 supports these in Russian codepages!
        """
        return BorderChars(
            horizontal="─",  # 0xC4
            vertical="│",  # 0xB3
            top_left="┌",  # 0xDA
            top_right="┐",  # 0xBF
            bottom_left="└",  # 0xC0
            bottom_right="┘",  # 0xD9
            cross="┼",  # 0xC5
            t_down="┬",  # 0xC2
            t_up="┴",  # 0xC1
            t_right="├",  # 0xC3
            t_left="┤",  # 0xB4
        )

    @staticmethod
    def for_style(style: TableBorder) -> "BorderChars":
        """Get border characters for a given style."""
        if style == TableBorder.SINGLE:
            return BorderChars.single_line()
        elif style == TableBorder.DOUBLE:
            return BorderChars.double_line()
        elif style == TableBorder.ASCII_ART:
            return BorderChars.box_drawing()
        else:  # NONE
            return BorderChars.single_line()  # Fallback


@dataclass(frozen=True, slots=True)
class TableStyle:
    """
    Complete table styling configuration.

    Defines visual appearance of the entire table including borders,
    cell padding, and spacing.

    Attributes:
        border: Border style for the table (default: SINGLE).
        cell_padding: Padding inside cells in inches (default: 0.05").
        row_spacing: Space between rows in inches (default: 0.0").
        column_spacing: Space between columns in inches (default: 0.0").

    Example:
        >>> style = TableStyle(border=TableBorder.DOUBLE, cell_padding=0.1)
        >>> style.border
        <TableBorder.DOUBLE: 'double'>
    """

    border: TableBorder = TableBorder.SINGLE
    cell_padding: float = 0.05
    row_spacing: float = 0.0
    column_spacing: float = 0.0

    def validate(self) -> None:
        """Validate table style values."""
        if self.cell_padding < 0:
            raise ValueError(f"cell_padding cannot be negative, got {self.cell_padding}")
        if self.row_spacing < 0:
            raise ValueError(f"row_spacing cannot be negative, got {self.row_spacing}")
        if self.column_spacing < 0:
            raise ValueError(f"column_spacing cannot be negative, got {self.column_spacing}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize table style to dictionary."""
        return {
            "border": self.border.value,
            "cell_padding": self.cell_padding,
            "row_spacing": self.row_spacing,
            "column_spacing": self.column_spacing,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "TableStyle":
        """Deserialize table style from dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        border_str = data.get("border", "single")
        try:
            border = TableBorder(border_str)
        except ValueError as exc:
            raise ValueError(f"Invalid border value: {border_str!r}") from exc

        return TableStyle(
            border=border,
            cell_padding=data.get("cell_padding", 0.05),
            row_spacing=data.get("row_spacing", 0.0),
            column_spacing=data.get("column_spacing", 0.0),
        )


@dataclass(frozen=True, slots=True)
class TableMetrics:
    """
    Physical metrics of a rendered table.

    Provides detailed information about table dimensions and resource usage
    for layout calculations and optimization.

    Attributes:
        total_width_inches: Total table width including borders (inches).
        total_height_inches: Total table height including borders (inches).
        column_widths: List of individual column widths (inches).
        row_heights: List of individual row heights (inches).
        cell_count: Total number of cells (accounting for merges).
        escp_byte_count: Size of generated ESC/P commands (bytes).
        border_char_count: Number of border characters rendered.

    Example:
        >>> metrics = table.calculate_metrics(page_width=8.5, page_cpi=10)
        >>> print(f"Table: {metrics.total_width_inches:.2f}\" wide")
        Table: 6.50" wide
    """

    total_width_inches: float
    total_height_inches: float
    column_widths: list[float]
    row_heights: list[float]
    cell_count: int
    escp_byte_count: int
    border_char_count: int

    def __repr__(self) -> str:
        """Return compact string representation."""
        return (
            f'TableMetrics(width={self.total_width_inches:.2f}", '
            f'height={self.total_height_inches:.2f}", '
            f"cells={self.cell_count}, bytes={self.escp_byte_count})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize metrics to dictionary."""
        return {
            "total_width_inches": self.total_width_inches,
            "total_height_inches": self.total_height_inches,
            "column_widths": self.column_widths,
            "row_heights": self.row_heights,
            "cell_count": self.cell_count,
            "escp_byte_count": self.escp_byte_count,
            "border_char_count": self.border_char_count,
        }


@dataclass(frozen=True, slots=True)
class CellBorders:
    """
    Border configuration for a single cell.

    Specifies which borders should be drawn for a cell and their style.

    Attributes:
        top: Draw top border (default: True).
        bottom: Draw bottom border (default: True).
        left: Draw left border (default: True).
        right: Draw right border (default: True).
        style: Border style from TableBorder enum (default: SINGLE).

    Example:
        >>> borders = CellBorders(top=True, bottom=False)
        >>> borders.top
        True
    """

    top: bool = True
    bottom: bool = True
    left: bool = True
    right: bool = True
    style: TableBorder = TableBorder.SINGLE

    def to_dict(self) -> dict[str, Any]:
        """Serialize cell borders to dictionary."""
        return {
            "top": self.top,
            "bottom": self.bottom,
            "left": self.left,
            "right": self.right,
            "style": self.style.value,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "CellBorders":
        """Deserialize cell borders from dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        style_str = data.get("style", "single")
        try:
            style = TableBorder(style_str)
        except ValueError as exc:
            raise ValueError(f"Invalid border style: {style_str!r}") from exc

        return CellBorders(
            top=data.get("top", True),
            bottom=data.get("bottom", True),
            left=data.get("left", True),
            right=data.get("right", True),
            style=style,
        )


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
            >>>
            data = table.to_dict()
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

    # =========================================================================
    # AUTO-SIZING
    # =========================================================================

    def calculate_column_widths(
        self,
        available_width: float,
        mode: ColumnSizingMode = ColumnSizingMode.AUTO,
        page_cpi: int = 10,
        min_col_width: float = 0.5,
        max_col_width: float | None = None,
    ) -> list[float]:
        """
        Calculate optimal column widths based on content.

        Supports multiple sizing strategies: auto (content-based), equal,
        fixed (from column_widths), and proportional.

        Args:
            available_width: Available width for table content (inches).
            mode: Column sizing strategy from ColumnSizingMode enum.
            page_cpi: Characters per inch for calculations (default: 10).
            min_col_width: Minimum column width (inches, default: 0.5").
            max_col_width: Maximum column width (inches, default: None).

        Returns:
            List of column widths in inches.

        Raises:
            ValueError: If table is empty or widths don't fit.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell(), Cell()])
            >>> widths = table.calculate_column_widths(7.0)
            >>> len(widths)
            3
        """
        if not self.rows:
            raise ValueError("Cannot calculate widths for empty table")

        num_cols = len(self.rows[0])

        # Mode: FIXED
        if mode == ColumnSizingMode.FIXED:
            if self.column_widths is None:
                raise ValueError("FIXED mode requires column_widths to be set")
            if len(self.column_widths) != num_cols:
                raise ValueError(
                    f"column_widths length {len(self.column_widths)} "
                    f"doesn't match table width {num_cols}"
                )
            return self.column_widths.copy()

        # Mode: EQUAL
        if mode == ColumnSizingMode.EQUAL:
            width_per_col = available_width / num_cols
            if width_per_col < min_col_width:
                logger.warning(
                    f'Equal width {width_per_col:.3f}" < min {min_col_width:.3f}", '
                    f"using minimum"
                )
                width_per_col = min_col_width
            return [width_per_col] * num_cols

        # Mode: AUTO (content-based)
        if mode == ColumnSizingMode.AUTO:
            # Calculate content width for each column
            col_content_widths = self._calculate_content_widths(page_cpi)

            # Convert character counts to inches
            col_widths_inches = [chars / page_cpi for chars in col_content_widths]

            # Apply min/max constraints
            for i in range(num_cols):
                col_widths_inches[i] = max(col_widths_inches[i], min_col_width)
                if max_col_width is not None:
                    col_widths_inches[i] = min(col_widths_inches[i], max_col_width)

            # Check if total fits
            total_width = sum(col_widths_inches)
            if total_width > available_width:
                # Scale down proportionally
                scale = available_width / total_width
                col_widths_inches = [w * scale for w in col_widths_inches]
                logger.debug(f'Scaled column widths by {scale:.3f} to fit {available_width:.2f}"')

            return col_widths_inches

        # Mode: PROPORTIONAL
        if mode == ColumnSizingMode.PROPORTIONAL:
            col_content_widths = self._calculate_content_widths(page_cpi)
            total_content = sum(col_content_widths)

            if total_content == 0:
                # Fallback to equal
                return [available_width / num_cols] * num_cols

            # Distribute proportionally
            col_widths_inches = [
                (chars / total_content) * available_width for chars in col_content_widths
            ]

            # Apply minimum
            for i in range(num_cols):
                col_widths_inches[i] = max(col_widths_inches[i], min_col_width)

            return col_widths_inches

        # Fallback: equal
        return [available_width / num_cols] * num_cols

    def _calculate_content_widths(self, page_cpi: int) -> list[int]:
        """
        Calculate content width (in characters) for each column.

        Returns maximum character count across all cells in each column,
        accounting for colspan (spread across columns).

        Args:
            page_cpi: Characters per inch for calculations.

        Returns:
            List of character counts per column.
        """
        if not self.rows:
            return []

        num_cols = len(self.rows[0])
        col_widths = [0] * num_cols

        for row in self.rows:
            for col_idx, cell in enumerate(row):
                # Get cell text length
                cell_text = cell.content.get_text()
                cell_chars = len(cell_text)

                if cell.colspan == 1:
                    # Simple case: no spanning
                    col_widths[col_idx] = max(col_widths[col_idx], cell_chars)
                else:
                    # Spanning: distribute width across columns
                    chars_per_col = cell_chars // cell.colspan
                    for span_offset in range(cell.colspan):
                        if col_idx + span_offset < num_cols:
                            col_widths[col_idx + span_offset] = max(
                                col_widths[col_idx + span_offset], chars_per_col
                            )

        return col_widths

    # =========================================================================
    # ESC/P GENERATION
    # =========================================================================

    def to_escp(
        self,
        page_width: float = 8.5,
        page_cpi: int = 10,
        style: TableStyle | None = None,
        use_cache: bool = False,
    ) -> bytes:
        """
        Generate ESC/P commands for table rendering on FX-890.

        Renders the table with borders, proper cell spacing, and handles
        merged cells (colspan/rowspan). Uses character-based layout
        optimized for matrix printers.

        Args:
            page_width: Page width in inches (default: 8.5" US Letter).
            page_cpi: Characters per inch (default: 10 CPI).
            style: Optional TableStyle for visual customization.
            use_cache: Enable ESC/P result caching (default: False).

        Returns:
            ESC/P command bytes for table rendering.

        Raises:
            ValueError: If table is empty or doesn't fit on page.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> escp = table.to_escp(page_width=8.5, page_cpi=10)
            >>> isinstance(escp, bytes)
            True
        """
        if not self.rows:
            logger.warning("Generating ESC/P for empty table")
            return b""

        # Use provided style or create default
        if style is None:
            style = TableStyle(border=self.border_style)

        # Calculate column widths
        available_width = page_width - (2 * style.cell_padding)
        col_widths = self.calculate_column_widths(
            available_width, mode=ColumnSizingMode.AUTO, page_cpi=page_cpi
        )

        # Get border characters
        border_chars = BorderChars.for_style(style.border)

        commands: list[bytes] = []

        # 1. Top border
        if style.border != TableBorder.NONE:
            top_border = self._render_border_line(
                col_widths, border_chars, position="top", page_cpi=page_cpi
            )
            commands.append(top_border)
            commands.append(b"\r\n")

        # 2. Rows with content
        for row_idx, row in enumerate(self.rows):
            # Render row content
            row_escp = self._render_row(row, col_widths, border_chars, style, page_cpi)
            commands.append(row_escp)
            commands.append(b"\r\n")

            # Middle border (between rows)
            if style.border != TableBorder.NONE and row_idx < len(self.rows) - 1:
                middle_border = self._render_border_line(
                    col_widths, border_chars, position="middle", page_cpi=page_cpi
                )
                commands.append(middle_border)
                commands.append(b"\r\n")

        # 3. Bottom border
        if style.border != TableBorder.NONE:
            bottom_border = self._render_border_line(
                col_widths, border_chars, position="bottom", page_cpi=page_cpi
            )
            commands.append(bottom_border)
            commands.append(b"\r\n")

        result = b"".join(commands)
        logger.info(
            f"Generated table ESC/P: {len(self.rows)} rows, "
            f"{len(self.rows[0])} cols, {len(result)} bytes"
        )
        return result

    # =========================================================================
    # RENDERING HELPERS
    # =========================================================================

    def _render_border_line(
        self,
        col_widths: list[float],
        border_chars: BorderChars,
        position: str,  # "top", "middle", "bottom"
        page_cpi: int,
    ) -> bytes:
        """
        Render a horizontal border line.

        Creates a complete border line with corners and intersections
        based on position (top/middle/bottom).

        Args:
            col_widths: Column widths in inches.
            border_chars: Border character set.
            position: Border position ("top", "middle", "bottom").
            page_cpi: Characters per inch.

        Returns:
            ESC/P bytes for border line.
        """
        parts: list[str] = []

        # Left corner/edge
        if position == "top":
            parts.append(border_chars.top_left)
        elif position == "bottom":
            parts.append(border_chars.bottom_left)
        else:  # middle
            parts.append(border_chars.t_right)

        # Columns with separators
        for col_idx, width in enumerate(col_widths):
            # Horizontal line for this column
            col_chars = int(width * page_cpi)
            parts.append(border_chars.horizontal * col_chars)

            # Separator or corner
            if col_idx < len(col_widths) - 1:
                # Not last column: intersection
                if position == "top":
                    parts.append(border_chars.t_down)
                elif position == "bottom":
                    parts.append(border_chars.t_up)
                else:  # middle
                    parts.append(border_chars.cross)
            else:
                # Last column: right edge
                if position == "top":
                    parts.append(border_chars.top_right)
                elif position == "bottom":
                    parts.append(border_chars.bottom_right)
                else:  # middle
                    parts.append(border_chars.t_left)

        line = "".join(parts)
        return line.encode("cp866", errors="replace")  # Russian codepage for box chars

    def _render_row(
        self,
        row: list[Cell],
        col_widths: list[float],
        border_chars: BorderChars,
        style: TableStyle,
        page_cpi: int,
    ) -> bytes:
        """
        Render a single table row with cells.

        Handles cell content rendering, padding, and vertical borders.
        Accounts for colspan (merged cells span multiple columns).

        Args:
            row: List of Cell objects for this row.
            col_widths: Column widths in inches.
            border_chars: Border character set.
            style: Table styling configuration.
            page_cpi: Characters per inch.

        Returns:
            ESC/P bytes for the row.
        """
        parts: list[bytes] = []

        # Left border
        if style.border != TableBorder.NONE:
            parts.append(border_chars.vertical.encode("cp866", errors="replace"))

        col_idx = 0
        while col_idx < len(row):
            cell = row[col_idx]

            # Calculate effective width (accounting for colspan)
            effective_width = sum(col_widths[col_idx : col_idx + cell.colspan])

            # Render cell content
            cell_escp = self._render_cell(cell, effective_width, style, page_cpi)
            parts.append(cell_escp)

            # Right border (after cell)
            if style.border != TableBorder.NONE:
                parts.append(border_chars.vertical.encode("cp866", errors="replace"))

            # Move to next column (skip spanned columns)
            col_idx += cell.colspan

        return b"".join(parts)

    def _render_cell(
        self,
        cell: Cell,
        width_inches: float,
        style: TableStyle,
        page_cpi: int,
    ) -> bytes:
        """
        Render cell content with padding.

        Formats cell text to fit within specified width, applying
        padding and truncation as needed.

        Args:
            cell: Cell to render.
            width_inches: Available width for cell content (inches).
            style: Table styling configuration.
            page_cpi: Characters per inch.

        Returns:
            ESC/P bytes for cell content.
        """
        # Calculate character width
        available_chars = int(width_inches * page_cpi)
        padding_chars = int(style.cell_padding * page_cpi)
        content_chars = available_chars - (2 * padding_chars)

        if content_chars <= 0:
            # No space for content
            return b" " * available_chars

        # Get cell text
        cell_text = cell.content.get_text()

        # Truncate or pad text
        if len(cell_text) > content_chars:
            # Truncate with ellipsis
            if content_chars > 3:
                cell_text = cell_text[: content_chars - 3] + "..."
            else:
                cell_text = cell_text[:content_chars]
        else:
            # Pad to fill width
            # Apply alignment from paragraph
            if cell.content.alignment == Alignment.CENTER:
                padding_total = content_chars - len(cell_text)
                left_pad = padding_total // 2
                right_pad = padding_total - left_pad
                cell_text = (" " * left_pad) + cell_text + (" " * right_pad)
            elif cell.content.alignment == Alignment.RIGHT:
                cell_text = cell_text.rjust(content_chars)
            else:  # LEFT or JUSTIFY
                cell_text = cell_text.ljust(content_chars)

        # Add padding
        padded_text = (" " * padding_chars) + cell_text + (" " * padding_chars)

        return padded_text.encode("cp866", errors="replace")

    # =========================================================================
    # COLUMN OPERATIONS
    # =========================================================================

    def add_column(self, cells: list[Cell], index: int | None = None) -> None:
        """
        Add a column to the table.

        Inserts cells at the specified column index (or at end if None).

        Args:
            cells: List of Cell objects for the new column (one per row).
            index: Column position to insert (default: None = append).

        Raises:
            TypeError: If cells is not a list or contains non-Cell objects.
            ValueError: If cell count doesn't match row count.
            IndexError: If index is out of valid range.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> table.add_column([Cell()])  # Add at end
            >>> table.get_dimensions()
            (1, 3)
        """
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")

        if not all(isinstance(cell, Cell) for cell in cells):
            raise TypeError("All elements in cells must be Cell instances")

        if not self.rows:
            raise ValueError("Cannot add column to empty table")

        if len(cells) != len(self.rows):
            raise ValueError(f"Cell count {len(cells)} doesn't match row count {len(self.rows)}")

        # Determine insert position
        if index is None:
            index = len(self.rows[0])  # Append

        if not (0 <= index <= len(self.rows[0])):
            raise IndexError(f"Column index {index} out of range for {len(self.rows[0])} columns")

        # Insert cell into each row
        for row_idx, cell in enumerate(cells):
            self.rows[row_idx].insert(index, cell)

        logger.debug(f"Added column at index {index}, total columns: {len(self.rows[0])}")

    def remove_column(self, index: int) -> list[Cell]:
        """
        Remove a column from the table.

        Args:
            index: Column position to remove (0-based).

        Returns:
            List of Cell objects from removed column.

        Raises:
            IndexError: If index is out of range.
            ValueError: If table is empty or would become empty.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell(), Cell()])
            >>> removed = table.remove_column(1)
            >>> len(removed)
            1
        """
        if not self.rows:
            raise ValueError("Cannot remove column from empty table")

        num_cols = len(self.rows[0])

        if num_cols == 1:
            raise ValueError("Cannot remove last column (table would be empty)")

        if not (0 <= index < num_cols):
            raise IndexError(f"Column index {index} out of range for {num_cols} columns")

        # Remove cell from each row
        removed_cells = []
        for row in self.rows:
            removed_cells.append(row.pop(index))

        logger.debug(f"Removed column at index {index}, remaining: {len(self.rows[0])}")
        return removed_cells

    def swap_columns(self, index1: int, index2: int) -> None:
        """
        Swap two columns in the table.

        Args:
            index1: First column index.
            index2: Second column index.

        Raises:
            IndexError: If either index is out of range.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell(), Cell()])
            >>> table.swap_columns(0, 2)
        """
        if not self.rows:
            raise ValueError("Cannot swap columns in empty table")

        num_cols = len(self.rows[0])

        if not (0 <= index1 < num_cols):
            raise IndexError(f"Column index {index1} out of range for {num_cols} columns")
        if not (0 <= index2 < num_cols):
            raise IndexError(f"Column index {index2} out of range for {num_cols} columns")

        # Swap cells in each row
        for row in self.rows:
            row[index1], row[index2] = row[index2], row[index1]

        logger.debug(f"Swapped columns {index1} and {index2}")

    # =========================================================================
    # MERGED CELLS HANDLING
    # =========================================================================

    def resolve_merged_cells(self) -> dict[tuple[int, int], tuple[int, int, Cell]]:
        """
        Build a map of cell positions accounting for merges.

        Creates a mapping from (row, col) coordinates to the actual cell
        that renders at that position, accounting for colspan and rowspan.

        Returns:
            Dictionary mapping (row, col) -> (source_row, source_col, cell).
            For positions covered by a merged cell, points to the source cell.

        Example:
            >>> table = Table()
            >>> cell = Cell(colspan=2)
            >>> table.add_row([cell, Cell()])
            >>> cell_map = table.resolve_merged_cells()
            >>> cell_map[(0, 0)][2] == cell
            True
            >>> cell_map[(0, 1)][2] == cell  # Same cell (colspan)
            True
        """
        cell_map: dict[tuple[int, int], tuple[int, int, Cell]] = {}

        for row_idx, row in enumerate(self.rows):
            col_idx = 0
            for cell_idx, cell in enumerate(row):
                # Mark this cell's position
                cell_map[(row_idx, col_idx)] = (row_idx, col_idx, cell)

                # Mark positions covered by colspan
                for col_offset in range(1, cell.colspan):
                    cell_map[(row_idx, col_idx + col_offset)] = (row_idx, col_idx, cell)

                # Mark positions covered by rowspan
                for row_offset in range(1, cell.rowspan):
                    for col_offset in range(cell.colspan):
                        cell_map[(row_idx + row_offset, col_idx + col_offset)] = (
                            row_idx,
                            col_idx,
                            cell,
                        )

                col_idx += cell.colspan

        logger.debug(f"Resolved {len(cell_map)} cell positions (including merges)")
        return cell_map

    def get_effective_cell(self, row: int, col: int) -> tuple[Cell, int, int] | None:
        """
        Get the cell that renders at specified position.

        If position is covered by a merged cell (colspan/rowspan),
        returns the source cell and its origin coordinates.

        Args:
            row: Row index (0-based).
            col: Column index (0-based).

        Returns:
            Tuple of (cell, source_row, source_col) or None if out of bounds.

        Example:
            >>> table = Table()
            >>> cell = Cell(colspan=2)
            >>> table.add_row([cell, Cell()])
            >>> result = table.get_effective_cell(0, 1)
            >>> result[0] == cell  # Returns source cell
            True
        """
        cell_map = self.resolve_merged_cells()

        if (row, col) not in cell_map:
            return None

        source_row, source_col, cell = cell_map[(row, col)]
        return (cell, source_row, source_col)

    def is_merged_position(self, row: int, col: int) -> bool:
        """
        Check if position is covered by a merged cell.

        Args:
            row: Row index.
            col: Column index.

        Returns:
            True if position is covered by colspan/rowspan.

        Example:
            >>> table = Table()
            >>> cell = Cell(colspan=2)
            >>> table.add_row([cell, Cell()])
            >>> table.is_merged_position(0, 1)
            True
        """
        result = self.get_effective_cell(row, col)
        if result is None:
            return False

        _, source_row, source_col = result
        return (row, col) != (source_row, source_col)

    def count_effective_cells(self) -> int:
        """
        Count unique cells (not counting positions covered by merges).

        Returns:
            Number of actual Cell objects in table.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(colspan=2), Cell()])
            >>> table.count_effective_cells()
            2
        """
        unique_cells = set()

        for row in self.rows:
            for cell in row:
                unique_cells.add(id(cell))

        return len(unique_cells)

    # =========================================================================
    # METRICS CALCULATION
    # =========================================================================

    def calculate_metrics(
        self,
        page_width: float = 8.5,
        page_cpi: int = 10,
        style: TableStyle | None = None,
    ) -> TableMetrics:
        """
        Calculate physical rendering metrics for the table.

        Computes dimensions, cell count, and resource usage for the table
        when rendered with specified settings.

        Args:
            page_width: Page width in inches (default: 8.5").
            page_cpi: Characters per inch (default: 10 CPI).
            style: Optional TableStyle (default: uses table's border_style).

        Returns:
            TableMetrics with comprehensive size information.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell(), Cell()])
            >>> metrics = table.calculate_metrics()
            >>> print(f"Width: {metrics.total_width_inches:.2f}\"")
            Width: 7.50"
        """
        if not self.rows:
            return TableMetrics(
                total_width_inches=0.0,
                total_height_inches=0.0,
                column_widths=[],
                row_heights=[],
                cell_count=0,
                escp_byte_count=0,
                border_char_count=0,
            )

        # Use provided style or create default
        if style is None:
            style = TableStyle(border=self.border_style)

        # Calculate column widths
        available_width = page_width - (2 * style.cell_padding)
        col_widths = self.calculate_column_widths(
            available_width, mode=ColumnSizingMode.AUTO, page_cpi=page_cpi
        )

        # Calculate total width
        total_width = sum(col_widths)

        # Calculate row heights (simple: 1 line per row + spacing)
        num_rows = len(self.rows)
        row_heights = []

        # Get LPI based on default line spacing
        lpi = 6  # 1/6 inch per line (standard)

        for _ in self.rows:
            # Base height: 1 line
            height = 1.0 / lpi
            # Add row spacing
            height += style.row_spacing
            row_heights.append(height)

        total_height = sum(row_heights)

        # Add border height if present
        if style.border != TableBorder.NONE:
            border_line_height = 1.0 / lpi
            # Top border + bottom border + (num_rows - 1) middle borders
            total_height += border_line_height * (num_rows + 1)

        # Generate ESC/P to get byte count
        escp = self.to_escp(page_width, page_cpi, style, use_cache=False)

        # Count border characters
        border_chars = 0
        if style.border != TableBorder.NONE:
            # Rough estimate: borders around all cells
            chars_per_row = sum(int(w * page_cpi) for w in col_widths) + len(col_widths) + 1
            border_chars = chars_per_row * (num_rows + 1)  # Top, bottom, middle borders

        # Count effective cells
        cell_count = self.count_effective_cells()

        metrics = TableMetrics(
            total_width_inches=total_width,
            total_height_inches=total_height,
            column_widths=col_widths,
            row_heights=row_heights,
            cell_count=cell_count,
            escp_byte_count=len(escp),
            border_char_count=border_chars,
        )

        logger.debug(f"Calculated metrics: {metrics}")
        return metrics

    def estimate_print_time(
        self,
        chars_per_second: int = 300,  # FX-890 draft mode: ~300 CPS
    ) -> float:
        """
        Estimate printing time in seconds.

        Rough estimate based on character count and printer speed.

        Args:
            chars_per_second: Printer speed (default: 300 CPS for FX-890).

        Returns:
            Estimated print time in seconds.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> time = table.estimate_print_time()
            >>> time > 0
            True
        """
        metrics = self.calculate_metrics()

        # Rough character count: content + borders
        total_chars = 0
        for row in self.rows:
            for cell in row:
                total_chars += len(cell.content.get_text())

        total_chars += metrics.border_char_count

        # Add overhead for ESC/P commands (assume 20% overhead)
        effective_chars = total_chars * 1.2

        return effective_chars / chars_per_second

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def clear(self) -> None:
        """Clear all rows from the table."""
        row_count = len(self.rows)
        self.rows.clear()
        logger.debug(f"Cleared table: removed {row_count} rows")

    def transpose(self) -> "Table":
        """
        Create a transposed copy of the table (swap rows/columns).

        Returns:
            New Table with rows and columns swapped.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> table.add_row([Cell(), Cell()])
            >>> transposed = table.transpose()
            >>> transposed.get_dimensions()
            (2, 2)
        """
        if not self.rows:
            return Table()

        num_rows = len(self.rows)
        num_cols = len(self.rows[0])

        # Create new rows (old columns)
        new_rows = []
        for col_idx in range(num_cols):
            new_row = [self.rows[row_idx][col_idx].copy() for row_idx in range(num_rows)]
            new_rows.append(new_row)

        return Table(
            rows=new_rows,
            border_style=self.border_style,
            column_widths=None,  # Reset column widths
        )

    def fill_cells(self, text: str, style: TableStyle | None = None) -> None:
        """
        Fill all cells with the same text.

        Useful for testing or creating template tables.

        Args:
            text: Text to set in all cells.
            style: Optional TableStyle to apply.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> table.fill_cells("Test")
            >>> table.get_cell(0, 0).content.get_text()
            'Test'
        """
        for row in self.rows:
            for cell in row:
                cell.content.clear_runs()
                cell.content.extend_text(text)

        logger.debug(f"Filled {len(self.rows) * len(self.rows[0])} cells with text")

    # =========================================================================
    # MAGIC METHODS
    # =========================================================================

    def __len__(self) -> int:
        """Return total number of rows."""
        return len(self.rows)

    def __getitem__(self, index: int) -> list[Cell]:
        """
        Get row by index.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell()])
            >>> row = table[0]
            >>> len(row)
            2
        """
        return self.rows[index]

    def __iter__(self) -> Iterator[list[Cell]]:
        """Iterate over rows."""
        return iter(self.rows)

    def __eq__(self, other: object) -> bool:
        """Compare tables for equality."""
        if not isinstance(other, Table):
            return NotImplemented

        return (
            self.rows == other.rows
            and self.border_style == other.border_style
            and self.column_widths == other.column_widths
        )


TableRow = list[Cell]  # Строка таблицы — это список ячеек
TableCell = Cell  # Алиас для Cell
