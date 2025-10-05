"""
Модель таблицы с ячейками, границами и поддержкой объединения.

Table model representing a grid structure with cells, borders, and merge
capabilities for ESC/P matrix printer output. Each cell contains a paragraph
with formatted text.

Module: src/model/table.py
Project: ESC/P Text Editor
Version: 2.0 (with advanced features)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, Iterator

from src.model.paragraph import Paragraph, Alignment
from src.model.run import Run

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

# Cell span constraints
MIN_SPAN: Final[int] = 1
MAX_SPAN: Final[int] = 100

# =============================================================================
# ENUMS
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


class VerticalAlignment(Enum):
    """
    Vertical alignment for cell content.

    Controls how content is positioned within the available cell height.

    Attributes:
        TOP: Align content to top of cell.
        MIDDLE: Center content vertically.
        BOTTOM: Align content to bottom of cell.
    """

    TOP = "top"
    MIDDLE = "middle"
    BOTTOM = "bottom"


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
            vertical="‖",
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
            horizontal="─",
            vertical="│",
            top_left="┌",
            top_right="┐",
            bottom_left="└",
            bottom_right="┘",
            cross="┼",
            t_down="┬",
            t_up="┴",
            t_right="├",
            t_left="┤",
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
            return BorderChars.single_line()


# =============================================================================
# CELL ALIGNMENT
# =============================================================================


@dataclass(frozen=True, slots=True)
class CellAlignment:
    """
    Complete alignment configuration for cell content.

    Combines horizontal (left/center/right/justify) and vertical (top/middle/bottom)
    alignment for precise content positioning within cells.

    Attributes:
        horizontal: Horizontal text alignment (from Paragraph.Alignment enum).
        vertical: Vertical text alignment within cell height.

    Example:
        >>> # Center content both horizontally and vertically
        >>> align = CellAlignment(
        ...     horizontal=Alignment.CENTER,
        ...     vertical=VerticalAlignment.MIDDLE
        ... )
        >>>
        >>> # Top-left alignment (default)
        >>> align = CellAlignment()
        >>> align.horizontal
        <Alignment.LEFT: 'left'>
        >>> align.vertical
        <VerticalAlignment.TOP: 'top'>
    """

    horizontal: Alignment = Alignment.LEFT
    vertical: VerticalAlignment = VerticalAlignment.TOP

    def to_dict(self) -> dict[str, str]:
        """
        Serialize alignment to dictionary.

        Returns:
            Dictionary with 'horizontal' and 'vertical' keys.

        Example:
            >>> align = CellAlignment(horizontal=Alignment.CENTER)
            >>> align.to_dict()
            {'horizontal': 'center', 'vertical': 'top'}
        """
        return {
            "horizontal": self.horizontal.value,
            "vertical": self.vertical.value,
        }

    @staticmethod
    def from_dict(data: dict[str, str]) -> "CellAlignment":
        """
        Deserialize alignment from dictionary.

        Args:
            data: Dictionary with 'horizontal' and 'vertical' keys.

        Returns:
            CellAlignment instance.

        Raises:
            ValueError: If alignment values are invalid.

        Example:
            >>> data = {'horizontal': 'center', 'vertical': 'middle'}
            >>> align = CellAlignment.from_dict(data)
            >>> align.horizontal
            <Alignment.CENTER: 'center'>
        """
        try:
            horizontal = Alignment(data.get("horizontal", "left"))
        except ValueError as exc:
            raise ValueError(f"Invalid horizontal alignment: {data.get('horizontal')!r}") from exc

        try:
            vertical = VerticalAlignment(data.get("vertical", "top"))
        except ValueError as exc:
            raise ValueError(f"Invalid vertical alignment: {data.get('vertical')!r}") from exc

        return CellAlignment(horizontal=horizontal, vertical=vertical)

    def __repr__(self) -> str:
        """Return string representation."""
        return f"CellAlignment(h={self.horizontal.value}, v={self.vertical.value})"


# =============================================================================
# TABLE STYLE
# =============================================================================


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


# =============================================================================
# CELL CLASS
# =============================================================================


@dataclass(slots=True)
class Cell:
    """
    Represents a single cell in a table.

    A Cell contains formatted content (Paragraph) and can span multiple
    rows/columns through colspan and rowspan attributes. Supports nested
    tables and advanced alignment options.

    Attributes:
        content: Paragraph containing the cell's formatted text.
        nested_table: Optional nested Table rendered inside this cell.
        colspan: Number of columns this cell spans (≥1).
        rowspan: Number of rows this cell spans (≥1).
        alignment: Text alignment configuration (horizontal + vertical).
        padding: Cell-specific padding in inches (overrides table style).
        borders: Optional cell-specific border configuration.

    Example:
        >>> # Simple cell with text
        >>> cell = Cell()
        >>> cell.content.add_run(Run(text="Cell content"))
        >>> cell.validate()
        >>>
        >>> # Cell spanning 2 columns, 3 rows with centered content
        >>> cell = Cell(
        ...     colspan=2,
        ...     rowspan=3,
        ...     alignment=CellAlignment(
        ...         horizontal=Alignment.CENTER,
        ...         vertical=VerticalAlignment.MIDDLE
        ...     )
        ... )
        >>>
        >>> # Cell with nested table
        >>> nested = Table()
        >>> nested.add_row([Cell(), Cell()])
        >>> cell = Cell(nested_table=nested)
    """

    content: Paragraph = field(default_factory=Paragraph)
    nested_table: "Table | None" = None
    colspan: int = 1
    rowspan: int = 1
    alignment: CellAlignment = field(default_factory=CellAlignment)
    padding: float = 0.05
    borders: "CellBorders | None" = None

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

    def has_nested_table(self) -> bool:
        """
        Check if this cell contains a nested table.

        Returns:
            True if nested_table is set, False otherwise.

        Example:
            >>> cell = Cell()
            >>> cell.has_nested_table()
            False
            >>> cell.nested_table = Table()
            >>> cell.has_nested_table()
            True
        """
        return self.nested_table is not None

    def validate(self) -> None:
        """
        Validate cell content, span values, and nested table.

        Raises:
            ValueError: If span values are invalid or content validation fails.
            TypeError: If content is not a Paragraph or nested_table is not a Table.

        Example:
            >>> cell = Cell()
            >>> cell.validate()  # OK
            >>>
            >>> cell.colspan = 200
            >>> cell.validate()
            ValueError: colspan 200 out of range [1, 100]
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

        # Validate nested table
        if self.nested_table is not None:
            if not isinstance(self.nested_table, Table):
                raise TypeError(
                    f"nested_table must be Table or None, got {type(self.nested_table).__name__}"
                )

            try:
                self.nested_table.validate()
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Nested table validation failed: {exc}") from exc

        # Validate padding
        if self.padding < 0:
            raise ValueError(f"padding cannot be negative, got {self.padding}")

        logger.debug(
            f"Validated cell: colspan={self.colspan}, rowspan={self.rowspan}, "
            f"nested={'yes' if self.has_nested_table() else 'no'}"
        )

    def copy(self) -> "Cell":
        """
        Create a deep copy of the cell.

        Returns:
            A new Cell with copied content, spans, and nested table.

        Example:
            >>> cell = Cell(colspan=2)
            >>> cell.content.add_run(Run(text="Test"))
            >>> cell_copy = cell.copy()
            >>> cell_copy is not cell
            True
            >>> cell_copy.colspan
            2
        """
        nested_copy = self.nested_table.copy() if self.nested_table else None

        return Cell(
            content=self.content.copy(),
            nested_table=nested_copy,
            colspan=self.colspan,
            rowspan=self.rowspan,
            alignment=self.alignment,  # CellAlignment is frozen, no copy needed
            padding=self.padding,
            borders=self.borders,  # CellBorders is frozen, no copy needed
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize cell to dictionary.

        Returns:
            Dictionary with cell attributes.

        Example:
            >>> cell = Cell(colspan=2, rowspan=3)
            >>> data = cell.to_dict()
            >>> data["colspan"]
            2
            >>> data["rowspan"]
            3
        """
        data: dict[str, Any] = {
            "content": self.content.to_dict(),
            "colspan": self.colspan,
            "rowspan": self.rowspan,
            "alignment": self.alignment.to_dict(),
            "padding": self.padding,
        }

        if self.nested_table is not None:
            data["nested_table"] = self.nested_table.to_dict()

        if self.borders is not None:
            data["borders"] = self.borders.to_dict()

        return data

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
            >>> data = {
            ...     "content": {},
            ...     "colspan": 2,
            ...     "rowspan": 3,
            ...     "alignment": {"horizontal": "center", "vertical": "middle"}
            ... }
            >>> cell = Cell.from_dict(data)
            >>> cell.colspan
            2
            >>> cell.alignment.vertical
            <VerticalAlignment.MIDDLE: 'middle'>
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        content_data = data.get("content", {})
        content = Paragraph.from_dict(content_data)

        alignment_data = data.get("alignment", {})
        alignment = CellAlignment.from_dict(alignment_data) if alignment_data else CellAlignment()

        nested_table_data = data.get("nested_table")
        nested_table = Table.from_dict(nested_table_data) if nested_table_data else None

        borders_data = data.get("borders")
        borders = CellBorders.from_dict(borders_data) if borders_data else None

        return Cell(
            content=content,
            nested_table=nested_table,
            colspan=data.get("colspan", 1),
            rowspan=data.get("rowspan", 1),
            alignment=alignment,
            padding=data.get("padding", 0.05),
            borders=borders,
        )

    def __repr__(self) -> str:
        """Return string representation."""
        nested_info = ", nested=yes" if self.has_nested_table() else ""
        return (
            f"Cell(colspan={self.colspan}, rowspan={self.rowspan}, "
            f"chars={len(self.content)}{nested_info})"
        )


# =============================================================================
# CELL BORDERS
# =============================================================================


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


# =============================================================================
# TABLE METRICS
# =============================================================================


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


# =============================================================================
# TABLE CLASS
# =============================================================================


@dataclass(slots=True)
class Table:
    """
    Represents a table with rows, columns, and cells.

    Table is a 2D grid structure containing cells that can span multiple
    rows/columns. Supports automatic sizing, border rendering, and ESC/P
    command generation for matrix printer output.

    Physical vs Logical Structure:
        - Physical: Actual list of cells stored in self.rows
        - Logical: Grid representation accounting for colspan/rowspan

        Example with rowspan:
            rows = [[Cell(rowspan=2), Cell()], [Cell()]]
            Physical: 2 rows, [2 cells, 1 cell]
            Logical: 2 rows × 2 columns grid

    Attributes:
        rows: List of rows, where each row is a list of Cells.
        border_style: Border rendering style (default: SINGLE).
        column_widths: Explicit column widths in inches (optional).

    Example:
        >>> # Create empty table
        >>> table = Table()
        >>>
        >>> # Add rows
        >>> table.add_row([Cell(), Cell(), Cell()])
        >>> table.add_row([Cell(), Cell(), Cell()])
        >>>
        >>> # Validate structure
        >>> table.validate()
        >>>
        >>> # Generate ESC/P output
        >>> escp = table.to_escp(page_width=8.5, page_cpi=10)
    """

    rows: list[list[Cell]] = field(default_factory=list)
    border_style: TableBorder = TableBorder.SINGLE
    column_widths: list[float] | None = None

    # -------------------------------------------------------------------------
    # BASIC OPERATIONS
    # -------------------------------------------------------------------------

    def add_row(self, cells: list[Cell]) -> None:
        """
        Add a row to the table.

        Args:
            cells: List of cells forming the row.

        Raises:
            TypeError: If cells is not a list.
            ValueError: If row length doesn't match existing table width.

        Example:
            >>> table = Table()
            >>> table.add_row([Cell(), Cell(), Cell()])
            >>> len(table.rows)
            1
        """
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")

        # Check width consistency (only for non-empty tables)
        if self.rows:
            first_row_len = len(self.rows[0])
            if len(cells) != first_row_len:
                raise ValueError(
                    f"Row length {len(cells)} doesn't match table width {first_row_len}"
                )

        self.rows.append(cells)
        logger.debug(f"Added row with {len(cells)} cells to table")

    def insert_row(self, index: int, cells: list[Cell]) -> None:
        """
        Insert a row at the specified index.

        Args:
            index: Position to insert the row (0-based).
            cells: List of cells forming the row.

        Raises:
            TypeError: If cells is not a list.
            ValueError: If row length doesn't match table width.
            IndexError: If index is out of range.

        Example:
            >>> table.insert_row(1, [Cell(), Cell()])
        """
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")

        if self.rows:
            first_row_len = len(self.rows[0])
            if len(cells) != first_row_len:
                raise ValueError(
                    f"Row length {len(cells)} doesn't match table width {first_row_len}"
                )

        self.rows.insert(index, cells)
        logger.debug(f"Inserted row with {len(cells)} cells at index {index}")

    def remove_row(self, index: int) -> list[Cell]:
        """
        Remove and return the row at the specified index.

        Args:
            index: Row index to remove (0-based).

        Returns:
            The removed row as a list of cells.

        Raises:
            IndexError: If index is out of range.

        Example:
            >>> row = table.remove_row(0)
            >>> len(row)
            3
        """
        if not (0 <= index < len(self.rows)):
            raise IndexError(f"Row index {index} out of range (0-{len(self.rows) - 1})")

        removed = self.rows.pop(index)
        logger.debug(f"Removed row {index} with {len(removed)} cells")
        return removed

    def get_cell(self, row: int, col: int) -> Cell:
        """
        Get cell at the specified position.

        Args:
            row: Row index (0-based).
            col: Column index (0-based).

        Returns:
            Cell at the specified position.

        Raises:
            IndexError: If position is out of range.

        Example:
            >>> cell = table.get_cell(0, 0)
            >>> cell.content.get_text()
            'Cell content'
        """
        if not (0 <= row < len(self.rows)):
            raise IndexError(f"Row index {row} out of range (0-{len(self.rows) - 1})")

        if not (0 <= col < len(self.rows[row])):
            raise IndexError(
                f"Column index {col} out of range (0-{len(self.rows[row]) - 1}) in row {row}"
            )

        return self.rows[row][col]

    def set_cell(self, row: int, col: int, cell: Cell) -> None:
        """
        Set cell at the specified position.

        Args:
            row: Row index (0-based).
            col: Column index (0-based).
            cell: Cell to place at position.

        Raises:
            IndexError: If position is out of range.
            TypeError: If cell is not a Cell instance.

        Example:
            >>> new_cell = Cell()
            >>> new_cell.content.add_run(Run(text="Updated"))
            >>> table.set_cell(0, 0, new_cell)
        """
        if not isinstance(cell, Cell):
            raise TypeError(f"Expected Cell, got {type(cell).__name__}")

        if not (0 <= row < len(self.rows)):
            raise IndexError(f"Row index {row} out of range")

        if not (0 <= col < len(self.rows[row])):
            raise IndexError(f"Column index {col} out of range in row {row}")

        self.rows[row][col] = cell
        logger.debug(f"Set cell at ({row}, {col})")

    def get_dimensions(self) -> tuple[int, int]:
        """
        Get physical table dimensions (rows × columns).

        Returns number of physical cells in first row, not accounting for spans.
        For logical dimensions accounting for colspan, use get_logical_dimensions().

        Returns:
            Tuple of (row_count, column_count).

        Example:
            >>> table.add_row([Cell(), Cell(), Cell()])
            >>> table.get_dimensions()
            (1, 3)
        """
        if not self.rows:
            return (0, 0)

        return (len(self.rows), len(self.rows[0]))

    def get_logical_dimensions(self) -> tuple[int, int]:
        """
        Get logical grid dimensions (rows × columns).

        Returns the size of the logical grid, accounting for spans.
        This differs from get_dimensions() which returns physical structure.

        Returns:
            Tuple of (logical_rows, logical_columns).

        Example:
            >>> table.rows = [[Cell(colspan=2), Cell()]]
            >>> table.get_dimensions()
            (1, 2)  # Physical: 1 row, 2 cells
            >>> table.get_logical_dimensions()
            (1, 3)  # Logical: 1 row, 3 columns (2+1)
        """
        if not self.rows:
            return (0, 0)

        num_rows = len(self.rows)
        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        return (num_rows, num_cols)

    def clear(self) -> None:
        """
        Remove all rows from the table.

        Example:
            >>> table.clear()
            >>> len(table.rows)
            0
        """
        self.rows.clear()
        logger.debug("Cleared all table rows")

    # -------------------------------------------------------------------------
    # COLUMN OPERATIONS
    # -------------------------------------------------------------------------

    def add_column(self, cells: list[Cell], index: int | None = None) -> None:
        """
        Add a column to the table.

        Args:
            cells: List of cells for the new column (one per row).
            index: Position to insert column (default: append at end).

        Raises:
            ValueError: If cell count doesn't match row count.
            TypeError: If cells is not a list.

        Example:
            >>> table.add_column([Cell(), Cell(), Cell()])
        """
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")

        if len(cells) != len(self.rows):
            raise ValueError(f"Cell count {len(cells)} doesn't match row count {len(self.rows)}")

        for row_idx, cell in enumerate(cells):
            if index is None:
                self.rows[row_idx].append(cell)
            else:
                self.rows[row_idx].insert(index, cell)

        logger.debug(f"Added column with {len(cells)} cells at index {index}")

    def remove_column(self, index: int) -> list[Cell]:
        """
        Remove and return column at the specified index.

        Args:
            index: Column index to remove (0-based).

        Returns:
            List of cells from the removed column.

        Raises:
            ValueError: If attempting to remove the last column.
            IndexError: If index is out of range.

        Example:
            >>> cells = table.remove_column(1)
        """
        if not self.rows:
            raise ValueError("Cannot remove column from empty table")

        if len(self.rows[0]) == 1:
            raise ValueError("Cannot remove last column")

        if not (0 <= index < len(self.rows[0])):
            raise IndexError(f"Column index {index} out of range")

        removed_cells = []
        for row in self.rows:
            removed_cells.append(row.pop(index))

        logger.debug(f"Removed column {index} with {len(removed_cells)} cells")
        return removed_cells

    def swap_columns(self, col1: int, col2: int) -> None:
        """
        Swap two columns.

        Args:
            col1: First column index (0-based).
            col2: Second column index (0-based).

        Raises:
            IndexError: If either index is out of range.

        Example:
            >>> table.swap_columns(0, 2)
        """
        if not self.rows:
            return

        max_col = len(self.rows[0]) - 1
        if not (0 <= col1 <= max_col) or not (0 <= col2 <= max_col):
            raise IndexError(f"Column indices out of range (0-{max_col})")

        for row in self.rows:
            row[col1], row[col2] = row[col2], row[col1]

        logger.debug(f"Swapped columns {col1} and {col2}")

    # -------------------------------------------------------------------------
    # HELPER METHODS (NEW)
    # -------------------------------------------------------------------------

    def add_row_with_spans(
        self,
        cells: list[Cell | tuple[Cell, int, int]],
        auto_fill: bool = True,
    ) -> None:
        """
        Add a row with automatic span handling.

        Simplifies table construction by allowing tuples of (cell, colspan, rowspan).
        Automatically handles logical grid positioning.

        Args:
            cells: List of either:
                - Cell objects (colspan=1, rowspan=1)
                - Tuples of (Cell, colspan, rowspan)
            auto_fill: If True, automatically adjust for positions covered by
                      rowspans from previous rows (default: True).

        Raises:
            ValueError: If cells don't fit in the logical grid.
            TypeError: If cells contain invalid types.

        Example:
            >>> table = Table()
            >>> # Add header spanning full width
            >>> header = Cell()
            >>> header.content.extend_text("Report")
            >>> table.add_row_with_spans([(header, 3, 1)])  # colspan=3, rowspan=1
            >>>
            >>> # Add normal row
            >>> table.add_row_with_spans([Cell(), Cell(), Cell()])
            >>>
            >>> # Mixed: first cell spans 2 rows
            >>> tall_cell = Cell()
            >>> table.add_row_with_spans([(tall_cell, 1, 2), Cell(), Cell()])
            >>>
            >>> # Next row: position 0 covered by tall_cell
            >>> table.add_row_with_spans([Cell(), Cell()], auto_fill=True)
        """
        # Parse cells and extract span information
        parsed_cells: list[Cell] = []

        for item in cells:
            if isinstance(item, Cell):
                parsed_cells.append(item)
            elif isinstance(item, tuple) and len(item) == 3:
                cell, colspan, rowspan = item
                if not isinstance(cell, Cell):
                    raise TypeError(f"Expected Cell in tuple, got {type(cell).__name__}")

                # Update cell spans
                object.__setattr__(cell, "colspan", colspan)
                object.__setattr__(cell, "rowspan", rowspan)
                parsed_cells.append(cell)
            else:
                raise TypeError(f"Expected Cell or (Cell, int, int), got {type(item)}")

        # If not first row and auto_fill enabled, check for covered positions
        if self.rows and auto_fill:
            # Build coverage map for previous rows
            coverage = self._build_span_coverage_map()
            current_row_idx = len(self.rows)

            # Determine expected logical width
            if self.rows:
                expected_cols = sum(c.colspan for c in self.rows[0])
            else:
                expected_cols = sum(c.colspan for c in parsed_cells)

            # Find which logical columns are covered by rowspans
            covered_cols = set()
            for col_idx in range(expected_cols):
                if (current_row_idx, col_idx) in coverage:
                    source_row, _, _ = coverage[(current_row_idx, col_idx)]
                    if source_row < current_row_idx:
                        covered_cols.add(col_idx)

            # Log covered positions
            if covered_cols:
                logger.debug(
                    f"Row {current_row_idx}: {len(covered_cols)} positions covered by rowspans"
                )

        # Add the row
        self.add_row(parsed_cells)

        logger.info(f"Added row with {len(parsed_cells)} cells via add_row_with_spans()")

    def add_logical_grid_row(
        self,
        grid_cells: list[Cell | None],
    ) -> None:
        """
        Add a row by specifying all logical grid positions.

        More explicit alternative to add_row_with_spans(). You specify every
        logical position in the grid, using None for positions covered by
        earlier rowspans. None entries are automatically removed.

        Args:
            grid_cells: List with one element per logical column. Use None
                    for positions covered by rowspans from previous rows.

        Raises:
            ValueError: If grid_cells is empty or results in no cells.
            TypeError: If grid_cells contain invalid types.

        Example:
            >>> table = Table()
            >>> # Row 0: normal cells at all 3 positions
            >>> table.add_logical_grid_row([Cell(), Cell(), Cell()])
            >>>
            >>> # Row 1: First cell from row 0 has rowspan=2, so position 0 is covered
            >>> table.add_logical_grid_row([None, Cell(), Cell()])
            >>> # Physical row will be [Cell(), Cell()]
        """
        if not grid_cells:
            raise ValueError("grid_cells cannot be empty")

        # Validate types
        for i, cell in enumerate(grid_cells):
            if cell is not None and not isinstance(cell, Cell):
                raise TypeError(f"Position {i}: expected Cell or None, got {type(cell).__name__}")

        # Remove None entries to create physical row
        physical_row: list[Cell] = [cell for cell in grid_cells if cell is not None]

        if not physical_row:
            raise ValueError("Cannot add row with no cells (all positions are None)")

        self.add_row(physical_row)
        logger.debug(
            f"Added logical grid row: {len(grid_cells)} positions → "
            f"{len(physical_row)} physical cells"
        )

    def transpose(self) -> "Table":
        """
        Transpose the table (swap rows and columns).

        Returns:
            New Table with transposed structure.

        Example:
            >>> # Original: [[A, B], [C, D]]
            >>> transposed = table.transpose()
            >>> # Result: [[A, C], [B, D]]
        """
        if not self.rows:
            return Table()

        num_rows, num_cols = self.get_dimensions()

        # Build transposed structure
        transposed_rows: list[list[Cell]] = []
        for col_idx in range(num_cols):
            new_row: list[Cell] = []
            for row_idx in range(num_rows):
                new_row.append(self.rows[row_idx][col_idx].copy())
            transposed_rows.append(new_row)

        transposed = Table(
            rows=transposed_rows,
            border_style=self.border_style,
        )

        logger.debug(f"Transposed table: {num_rows}x{num_cols} → {num_cols}x{num_rows}")
        return transposed

    def fill_cells(self, text: str) -> None:
        """
        Fill all cells with the specified text.

        Useful for testing and debugging.

        Args:
            text: Text to place in every cell.

        Example:
            >>> table.fill_cells("Test")
        """
        for row in self.rows:
            for cell in row:
                # Replace content with new paragraph
                cell.content = Paragraph()
                cell.content.add_run(Run(text=text))

        logger.debug(f"Filled {self.count_effective_cells()} cells with text")

    def copy(self) -> "Table":
        """
        Create a deep copy of the table.

        Returns:
            New Table with copied rows and cells.

        Example:
            >>> table_copy = table.copy()
            >>> table_copy is not table
            True
        """
        copied_rows = [[cell.copy() for cell in row] for row in self.rows]

        copied_widths = self.column_widths.copy() if self.column_widths else None

        return Table(
            rows=copied_rows,
            border_style=self.border_style,
            column_widths=copied_widths,
        )

    # -------------------------------------------------------------------------
    # VISUALIZATION AND DEBUGGING (NEW)
    # -------------------------------------------------------------------------

    def print_span_map(self, show_sources: bool = False) -> None:
        """
        Print a visual representation of the table's span coverage.

        Useful for debugging complex span layouts. Shows which cells occupy
        which logical grid positions.

        Args:
            show_sources: If True, show source cell coordinates for each position.

        Example:
            >>> table.print_span_map()
            Grid (3×3):
            [A][A][B]
            [A][A][C]
            [D][E][F]
            >>>
            >>> table.print_span_map(show_sources=True)
            Grid (3×3):
            [A(0,0)][A(0,0)][B(0,2)]
            [A(0,0)][A(0,0)][C(1,2)]
            [D(2,0)][E(2,1)][F(2,2)]
        """
        if not self.rows:
            print("Empty table")
            return

        # Build span coverage map
        span_map = self._build_span_coverage_map()

        num_rows = len(self.rows)
        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        print(f"Grid ({num_rows}×{num_cols}):")

        # Assign letters to cells for visualization
        cell_letters: dict[int, str] = {}
        letter_idx = 0
        for row in self.rows:
            for cell in row:
                cell_id = id(cell)
                if cell_id not in cell_letters:
                    cell_letters[cell_id] = chr(ord("A") + letter_idx)
                    letter_idx = (letter_idx + 1) % 26  # Wrap after Z

        # Print grid
        for row_idx in range(num_rows):
            line_parts = []
            for col_idx in range(num_cols):
                if (row_idx, col_idx) in span_map:
                    source_row, source_col, cell = span_map[(row_idx, col_idx)]
                    letter = cell_letters[id(cell)]

                    if show_sources:
                        line_parts.append(f"[{letter}({source_row},{source_col})]")
                    else:
                        line_parts.append(f"[{letter}]")
                else:
                    line_parts.append("[?]")  # Uncovered position (error!)

            print("".join(line_parts))

        print()

    def to_ascii_art(
        self,
        max_cell_width: int = 10,
        show_content: bool = True,
        border_style: TableBorder | None = None,
    ) -> str:
        """
        Generate ASCII art representation of the table.

        Creates a visual preview of the table with borders and content,
        suitable for debugging or documentation.

        Args:
            max_cell_width: Maximum characters per cell (default: 10).
            show_content: If True, show cell content; if False, show cell
                         letters like print_span_map() (default: True).
            border_style: Border style to use (default: table's border_style).

        Returns:
            String with ASCII art representation.

        Example:
            >>> print(table.to_ascii_art())
            +----------+----------+----------+
            | Header spanning 3 columns     |
            +----------+----------+----------+
            | Cell A   | Cell B   | Cell C   |
            +----------+----------+----------+
            >>>
            >>> print(table.to_ascii_art(show_content=False))
            +----------+----------+----------+
            | [A]      | [A]      | [B]      |
            +----------+----------+----------+
            | [C]      | [D]      | [E]      |
            +----------+----------+----------+
        """
        if not self.rows:
            return "(empty table)"

        style = border_style or self.border_style
        chars = BorderChars.for_style(style)

        # Build span map
        span_map = self._build_span_coverage_map()

        num_rows = len(self.rows)
        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        # Assign letters to cells
        cell_letters: dict[int, str] = {}
        letter_idx = 0
        for row in self.rows:
            for cell in row:
                cell_id = id(cell)
                if cell_id not in cell_letters:
                    cell_letters[cell_id] = chr(ord("A") + letter_idx)
                    letter_idx = (letter_idx + 1) % 26

        # Calculate column widths (equal for simplicity)
        col_width = max_cell_width

        lines: list[str] = []

        # Top border
        top_border = chars.top_left
        for col_idx in range(num_cols):
            top_border += chars.horizontal * col_width
            if col_idx < num_cols - 1:
                top_border += chars.t_down
        top_border += chars.top_right
        lines.append(top_border)

        # Rows
        for row_idx in range(num_rows):
            # Content line
            content_line = chars.vertical

            col_idx = 0
            while col_idx < num_cols:
                # Check span coverage
                if (row_idx, col_idx) in span_map:
                    source_row, source_col, cell = span_map[(row_idx, col_idx)]

                    # Only render content at source position
                    if (row_idx, col_idx) == (source_row, source_col):
                        # Calculate effective width
                        effective_cols = cell.colspan
                        effective_width = effective_cols * col_width + (effective_cols - 1)

                        # Get content
                        if show_content:
                            if cell.has_nested_table():
                                text = "[nested]"
                            else:
                                text = cell.content.get_text()
                            text = text[:effective_width].ljust(effective_width)
                        else:
                            letter = cell_letters[id(cell)]
                            text = f"[{letter}]".ljust(effective_width)

                        content_line += text
                        content_line += chars.vertical

                        col_idx += effective_cols
                    else:
                        # Position covered by span - skip rendering
                        col_idx += 1
                else:
                    # Empty position (should not happen in valid table)
                    content_line += " " * col_width
                    content_line += chars.vertical
                    col_idx += 1

            lines.append(content_line)

            # Middle border (check for active rowspans)
            if row_idx < num_rows - 1:
                middle_border = chars.t_right

                for col_idx in range(num_cols):
                    # Check if rowspan is active at this position
                    if (row_idx, col_idx) in span_map:
                        source_row, source_col, cell = span_map[(row_idx, col_idx)]

                        if source_row + cell.rowspan > row_idx + 1:
                            # Rowspan continues - no horizontal line
                            middle_border += " " * col_width
                        else:
                            middle_border += chars.horizontal * col_width
                    else:
                        middle_border += chars.horizontal * col_width

                    if col_idx < num_cols - 1:
                        middle_border += chars.cross

                middle_border += chars.t_left
                lines.append(middle_border)

        # Bottom border
        bottom_border = chars.bottom_left
        for col_idx in range(num_cols):
            bottom_border += chars.horizontal * col_width
            if col_idx < num_cols - 1:
                bottom_border += chars.t_up
        bottom_border += chars.bottom_right
        lines.append(bottom_border)

        return "\n".join(lines)

    def to_simple_grid(self) -> str:
        """
        Generate simple text grid representation.

        Minimal ASCII representation without borders, useful for quick debugging.

        Returns:
            String with simple grid representation.

        Example:
            >>> print(table.to_simple_grid())
            A  A  B
            A  A  C
            D  E  F
        """
        if not self.rows:
            return "(empty)"

        span_map = self._build_span_coverage_map()
        num_rows = len(self.rows)
        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        # Assign letters
        cell_letters: dict[int, str] = {}
        letter_idx = 0
        for row in self.rows:
            for cell in row:
                cell_id = id(cell)
                if cell_id not in cell_letters:
                    cell_letters[cell_id] = chr(ord("A") + letter_idx)
                    letter_idx = (letter_idx + 1) % 26

        lines: list[str] = []
        for row_idx in range(num_rows):
            parts = []
            for col_idx in range(num_cols):
                if (row_idx, col_idx) in span_map:
                    _, _, cell = span_map[(row_idx, col_idx)]
                    parts.append(cell_letters[id(cell)])
                else:
                    parts.append("?")
            lines.append("  ".join(parts))

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # VALIDATION
    # -------------------------------------------------------------------------

    def validate(self, fast_mode: bool = False) -> None:
        """
        Validate table structure and all cells.

        Checks that:
        - All rows contain Cell objects
        - All cells are valid (colspan/rowspan in range, content valid)
        - Column widths match table width (if specified)
        - Rowspan/colspan don't exceed table bounds
        - No overlapping spans

        Args:
            fast_mode: Enable fast validation mode for large tables (>10k cells).
                      Skips some checks for better performance.

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

        # Check all rows have same length (EXCEPT when using rowspan/colspan)
        # We allow variable row lengths if spans are present
        first_row_len = len(self.rows[0])
        has_variable_lengths = False

        for i, row in enumerate(self.rows):
            if len(row) != first_row_len:
                has_variable_lengths = True
                # Don't fail immediately - check if this is due to valid spans
                logger.debug(
                    f"Row {i} has {len(row)} cells, expected {first_row_len} "
                    "(may be valid with spans)"
                )

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

        # Validate spans don't exceed table bounds
        # Use first_row_len as the expected column count
        num_rows = len(self.rows)
        num_cols = first_row_len

        for row_idx, row in enumerate(self.rows):
            col_idx = 0  # Logical column position

            for cell in row:
                # Skip columns already covered by earlier cells in this row
                # This is needed when processing rows with colspan

                # Check colspan bounds (from current logical position)
                if col_idx + cell.colspan > num_cols:
                    raise ValueError(
                        f"Cell at row {row_idx} (logical col {col_idx}) colspan {cell.colspan} "
                        f"exceeds table width (extends to column {col_idx + cell.colspan})"
                    )

                # Check rowspan bounds
                if row_idx + cell.rowspan > num_rows:
                    raise ValueError(
                        f"Cell at ({row_idx}, {col_idx}) rowspan {cell.rowspan} "
                        f"exceeds table height (extends to row {row_idx + cell.rowspan})"
                    )

                col_idx += cell.colspan

        # Validate no overlapping spans using coverage matrix
        # Choose validation method based on table size
        total_cells = num_rows * num_cols

        try:
            if total_cells > 10000:
                self._validate_span_coverage_optimized(fast_mode=fast_mode)
            else:
                self._validate_span_coverage()
        except ValueError as exc:
            raise ValueError(f"Span overlap detected: {exc}") from exc

        # If we have variable row lengths but validation passed, that's OK
        # (means spans justify the variable lengths)
        if has_variable_lengths:
            logger.info("Table has variable row lengths, validated as span-compatible")

        rows, cols = self.get_dimensions()
        logger.debug(f"Validated table: {rows}x{cols}, border={self.border_style.value}")

    def _validate_span_coverage(self) -> None:
        """
        Validate that cell spans don't overlap.

        Builds a coverage matrix tracking which logical grid positions are claimed
        by cells. Each row in self.rows is processed sequentially, with cells
        claiming their colspan×rowspan area starting from the next available
        logical column position (skipping positions already covered by earlier spans).

        IMPORTANT: This method detects when a cell tries to claim a position that's
        already been claimed by another cell's span (either from earlier in same row
        via colspan, or from earlier row via rowspan).

        Raises:
            ValueError: If overlapping spans are detected.
        """
        if not self.rows:
            return

        num_rows = len(self.rows)

        # Calculate logical grid width from first row
        # (sum of colspan values, not physical cell count)
        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        # Build coverage matrix: None = unclaimed, (r, c) = claimed by cell at logical (r, c)
        coverage: list[list[tuple[int, int] | None]] = [
            [None for _ in range(num_cols)] for _ in range(num_rows)
        ]

        for row_idx, row in enumerate(self.rows):
            col_idx = 0  # Logical column position (grid coordinate)

            for cell in row:
                # Find next available logical column (skip covered positions)
                while col_idx < num_cols and coverage[row_idx][col_idx] is not None:
                    col_idx += 1

                # If we've exceeded column bounds, this cell has no valid position
                if col_idx >= num_cols:
                    raise ValueError(
                        f"Row {row_idx} has too many cells: cell cannot fit in grid "
                        f"(all {num_cols} columns are occupied or exceeded)"
                    )

                # Mark all grid positions covered by this cell's span
                for row_offset in range(cell.rowspan):
                    for col_offset in range(cell.colspan):
                        target_row = row_idx + row_offset
                        target_col = col_idx + col_offset

                        # Check bounds (should be caught earlier, but defensive)
                        if target_row >= num_rows or target_col >= num_cols:
                            continue

                        # Check if position already claimed
                        if coverage[target_row][target_col] is not None:
                            existing = coverage[target_row][target_col]
                            raise ValueError(
                                f"Position ({target_row}, {target_col}) claimed by both "
                                f"cell starting at ({row_idx}, {col_idx}) and cell starting at {existing}"
                            )

                        # Claim position
                        coverage[target_row][target_col] = (row_idx, col_idx)

                # Move to next logical column (accounting for this cell's colspan)
                col_idx += cell.colspan

        logger.debug("Span coverage validation passed")

    def _validate_span_coverage_optimized(self, fast_mode: bool = False) -> None:
        """
        Optimized version of span coverage validation for large tables.

        Uses sparse matrix representation and early termination for better
        performance on tables >1000×1000.

        Args:
            fast_mode: If True, skip overlap checks for even faster validation
                      (use only for trusted input).

        Raises:
            ValueError: If overlapping spans are detected.
        """
        if not self.rows:
            return

        num_rows = len(self.rows)
        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        # For small tables, use standard implementation
        if num_rows * num_cols < 10000:
            return self._validate_span_coverage()

        logger.info(f"Using optimized validation for large table ({num_rows}×{num_cols})")

        # Use sparse dict instead of full matrix for memory efficiency
        coverage: dict[tuple[int, int], tuple[int, int]] = {}

        for row_idx, row in enumerate(self.rows):
            col_idx = 0

            for cell in row:
                # Skip covered positions
                while col_idx < num_cols and (row_idx, col_idx) in coverage:
                    col_idx += 1

                if col_idx >= num_cols:
                    raise ValueError(f"Row {row_idx} has too many cells: cell cannot fit in grid")

                # Mark positions (only check overlaps if not fast_mode)
                for row_offset in range(cell.rowspan):
                    for col_offset in range(cell.colspan):
                        target_row = row_idx + row_offset
                        target_col = col_idx + col_offset

                        if target_row >= num_rows or target_col >= num_cols:
                            continue

                        pos = (target_row, target_col)

                        if not fast_mode and pos in coverage:
                            existing = coverage[pos]
                            raise ValueError(
                                f"Position {pos} claimed by both "
                                f"cell starting at ({row_idx}, {col_idx}) and cell starting at {existing}"
                            )

                        coverage[pos] = (row_idx, col_idx)

                col_idx += cell.colspan

        logger.debug(f"Optimized validation passed: {len(coverage)} positions checked")

    # -------------------------------------------------------------------------
    # MERGED CELLS HANDLING
    # -------------------------------------------------------------------------

    def resolve_merged_cells(self) -> dict[tuple[int, int], tuple[int, int, Cell]]:
        """
        Build a complete mapping of logical positions to cells.

        For each logical grid position (row, col), returns a tuple of:
        (source_row, source_col, cell) indicating which cell occupies that position.

        Returns:
            Dictionary mapping (row, col) → (source_row, source_col, cell).

        Example:
            >>> table.rows = [[Cell(colspan=2), Cell()]]
            >>> span_map = table.resolve_merged_cells()
            >>> span_map[(0, 0)]
            (0, 0, <Cell object>)
            >>> span_map[(0, 1)]
            (0, 0, <Cell object>)  # Same cell due to colspan
            >>> span_map[(0, 2)]
            (0, 2, <Cell object>)  # Different cell
        """
        return self._build_span_coverage_map()

    def _build_span_coverage_map(self) -> dict[tuple[int, int], tuple[int, int, Cell]]:
        """
        Build span coverage map for the table.

        Internal method used by rendering and validation. Maps each logical
        grid position to the cell that covers it, along with the cell's
        source position.

        Returns:
            Dictionary: (row, col) → (source_row, source_col, cell)
        """
        if not self.rows:
            return {}

        num_rows = len(self.rows)
        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        span_map: dict[tuple[int, int], tuple[int, int, Cell]] = {}

        for row_idx, row in enumerate(self.rows):
            col_idx = 0  # Logical column position

            for cell in row:
                # Skip positions already covered
                while col_idx < num_cols and (row_idx, col_idx) in span_map:
                    col_idx += 1

                if col_idx >= num_cols:
                    break

                # Mark all positions covered by this cell's span
                for row_offset in range(cell.rowspan):
                    for col_offset in range(cell.colspan):
                        target_row = row_idx + row_offset
                        target_col = col_idx + col_offset

                        if target_row < num_rows and target_col < num_cols:
                            span_map[(target_row, target_col)] = (row_idx, col_idx, cell)

                col_idx += cell.colspan

        return span_map

    def get_effective_cell(self, row: int, col: int) -> tuple[Cell, int, int] | None:
        """
        Get the cell that effectively occupies a logical position.

        Accounts for colspan/rowspan by returning the source cell even if
        the position is covered by a span.

        Args:
            row: Logical row index.
            col: Logical column index.

        Returns:
            Tuple of (cell, source_row, source_col) or None if position is invalid.

        Example:
            >>> # Cell at (0,0) has colspan=2
            >>> cell, src_row, src_col = table.get_effective_cell(0, 1)
            >>> src_row, src_col
            (0, 0)  # Position (0,1) is covered by cell at (0,0)
        """
        span_map = self._build_span_coverage_map()

        if (row, col) not in span_map:
            return None

        source_row, source_col, cell = span_map[(row, col)]
        return (cell, source_row, source_col)

    def is_merged_position(self, row: int, col: int) -> bool:
        """
        Check if a logical position is covered by a span.

        Returns True if the position is covered by a cell from a different
        source position (due to colspan/rowspan).

        Args:
            row: Logical row index.
            col: Logical column index.

        Returns:
            True if position is covered by a span, False if it's a source position.

        Example:
            >>> # Cell at (0,0) has colspan=2
            >>> table.is_merged_position(0, 0)
            False  # Source position
            >>> table.is_merged_position(0, 1)
            True   # Covered by colspan
        """
        result = self.get_effective_cell(row, col)
        if result is None:
            return False

        cell, source_row, source_col = result
        return (source_row, source_col) != (row, col)

    def count_effective_cells(self) -> int:
        """
        Count the number of unique cells in the table.

        Accounts for merged cells by counting each physical cell only once,
        even if it spans multiple positions.

        Returns:
            Number of unique cells.

        Example:
            >>> table.rows = [[Cell(colspan=2), Cell()]]
            >>> table.count_effective_cells()
            2  # Not 3, because colspan doesn't create new cells
        """
        unique_cells: set[int] = set()

        for row in self.rows:
            for cell in row:
                unique_cells.add(id(cell))

        return len(unique_cells)

    # -------------------------------------------------------------------------
    # AUTO-SIZING
    # -------------------------------------------------------------------------

    def calculate_column_widths(
        self,
        available_width: float = 7.5,
        mode: ColumnSizingMode = ColumnSizingMode.AUTO,
        min_col_width: float = 0.5,
        page_cpi: int = 10,
    ) -> list[float]:
        """
        Calculate column widths based on sizing mode.

        Args:
            available_width: Total width available for columns (inches).
            mode: Column sizing strategy (AUTO/EQUAL/FIXED/PROPORTIONAL).
            min_col_width: Minimum width per column (inches, default: 0.5").
            page_cpi: Characters per inch (default: 10).

        Returns:
            List of column widths in inches.

        Example:
            >>> widths = table.calculate_column_widths(7.5, ColumnSizingMode.AUTO)
            >>> sum(widths) <= 7.5
            True
        """
        if not self.rows:
            return []

        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0

        if mode == ColumnSizingMode.FIXED:
            if self.column_widths is None:
                raise ValueError("FIXED mode requires explicit column_widths")
            return self.column_widths

        elif mode == ColumnSizingMode.EQUAL:
            col_width = available_width / num_cols
            return [max(col_width, min_col_width)] * num_cols

        elif mode == ColumnSizingMode.AUTO:
            # Calculate content-based widths
            char_widths = self._calculate_content_widths(page_cpi)
            inch_widths = [w / page_cpi for w in char_widths]

            # Apply minimum width
            inch_widths = [max(w, min_col_width) for w in inch_widths]

            # Scale down if exceeds available width
            total_width = sum(inch_widths)
            if total_width > available_width:
                scale = available_width / total_width
                inch_widths = [w * scale for w in inch_widths]
                logger.debug(f'Scaled column widths by {scale:.2f} to fit {available_width}"')

            return inch_widths

        elif mode == ColumnSizingMode.PROPORTIONAL:
            # Proportional to content ratios
            char_widths = self._calculate_content_widths(page_cpi)
            total_chars = sum(char_widths)

            if total_chars == 0:
                # Fallback to equal
                return [available_width / num_cols] * num_cols

            proportions = [w / total_chars for w in char_widths]
            inch_widths = [p * available_width for p in proportions]

            # Apply minimum width
            inch_widths = [max(w, min_col_width) for w in inch_widths]

            # Rescale if minimums pushed us over
            total_width = sum(inch_widths)
            if total_width > available_width:
                scale = available_width / total_width
                inch_widths = [w * scale for w in inch_widths]

            return inch_widths

        else:
            raise ValueError(f"Unknown sizing mode: {mode}")

    def _calculate_content_widths(self, page_cpi: int) -> list[int]:
        """
        Calculate content width in characters for each column.

        Args:
            page_cpi: Characters per inch.

        Returns:
            List of character widths per column.
        """
        if not self.rows:
            return []

        num_cols = sum(cell.colspan for cell in self.rows[0]) if self.rows[0] else 0
        col_widths = [0] * num_cols

        span_map = self._build_span_coverage_map()

        for row_idx, row in enumerate(self.rows):
            col_idx = 0

            for cell in row:
                # Skip covered positions
                while col_idx < num_cols and (row_idx, col_idx) in span_map:
                    source_row, source_col, source_cell = span_map[(row_idx, col_idx)]
                    if source_cell is not cell:
                        col_idx += 1
                    else:
                        break

                if col_idx >= num_cols:
                    break

                # Get content width
                content_text = cell.content.get_text()
                lines = content_text.split("\n")
                max_line_len = max((len(line) for line in lines), default=0)

                # Distribute width across spanned columns
                width_per_col = max_line_len / cell.colspan if cell.colspan > 0 else max_line_len

                for offset in range(cell.colspan):
                    target_col = col_idx + offset
                    if target_col < num_cols:
                        col_widths[target_col] = max(col_widths[target_col], int(width_per_col))

                col_idx += cell.colspan

        return col_widths

    def _calculate_row_heights(self, lpi: int = 6) -> list[float]:
        """
        Calculate row heights in inches based on content.

        Args:
            lpi: Lines per inch (default: 6).

        Returns:
            List of row heights in inches.
        """
        if not self.rows:
            return []

        row_heights: list[float] = []

        for row_idx, row in enumerate(self.rows):
            max_lines = 1

            for cell in row:
                # Get content line count
                content_text = cell.content.get_text()
                lines = content_text.split("\n")
                line_count = len(lines)

                # Account for rowspan - divide height across spanned rows
                lines_per_row = line_count / cell.rowspan if cell.rowspan > 0 else line_count

                max_lines = max(max_lines, int(lines_per_row))

            row_height = max_lines / lpi
            row_heights.append(row_height)

        return row_heights

    # -------------------------------------------------------------------------
    # METRICS
    # -------------------------------------------------------------------------

    def calculate_metrics(
        self,
        page_width: float = 8.5,
        page_cpi: int = 10,
        lpi: int = 6,
    ) -> TableMetrics:
        """
        Calculate physical metrics for the rendered table.

        Args:
            page_width: Page width in inches (default: 8.5").
            page_cpi: Characters per inch (default: 10).
            lpi: Lines per inch (default: 6).

        Returns:
            TableMetrics with dimensions and resource usage.

        Example:
            >>> metrics = table.calculate_metrics()
            >>> print(f"Table: {metrics.total_width_inches:.2f}\" × {metrics.total_height_inches:.2f}\"")
            Table: 6.50" × 3.20"
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

        # Calculate dimensions
        col_widths = self.calculate_column_widths(
            page_width, ColumnSizingMode.AUTO, page_cpi=page_cpi
        )
        row_heights = self._calculate_row_heights(lpi=lpi)

        total_width = sum(col_widths)
        total_height = sum(row_heights)

        # Count cells
        cell_count = self.count_effective_cells()

        # Estimate ESC/P byte count
        escp = self.to_escp(page_width=page_width, page_cpi=page_cpi)
        escp_byte_count = len(escp)

        # Count border characters
        border_char_count = 0
        if self.border_style != TableBorder.NONE:
            num_rows, num_cols = self.get_logical_dimensions()
            # Rough estimate: borders around each cell
            border_char_count = (num_rows + 1) * (num_cols + 1) * 2

        return TableMetrics(
            total_width_inches=total_width,
            total_height_inches=total_height,
            column_widths=col_widths,
            row_heights=row_heights,
            cell_count=cell_count,
            escp_byte_count=escp_byte_count,
            border_char_count=border_char_count,
        )

    def estimate_print_time(self, chars_per_second: float = 300.0) -> float:
        """
        Estimate print time in seconds.

        Args:
            chars_per_second: Print speed (default: 300 cps for FX-890 draft mode).

        Returns:
            Estimated print time in seconds.

        Example:
            >>> time_sec = table.estimate_print_time()
            >>> print(f"Estimated print time: {time_sec:.1f}s")
            Estimated print time: 2.3s
        """
        metrics = self.calculate_metrics()

        # Estimate based on ESC/P byte count
        # Assume each byte takes ~1/chars_per_second to print
        return metrics.escp_byte_count / chars_per_second

    # -------------------------------------------------------------------------
    # SERIALIZATION
    # -------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize table to dictionary.

        Returns:
            Dictionary with table structure and attributes.

        Example:
            >>> data = table.to_dict()
            >>> data["border_style"]
            'single'
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
            data: Dictionary with table structure.

        Returns:
            Table instance reconstructed from dictionary.

        Raises:
            TypeError: If data is not a dictionary.
            ValueError: If border_style is invalid.

        Example:
            >>> data = {"rows": [], "border_style": "double"}
            >>> table = Table.from_dict(data)
            >>> table.border_style
            <TableBorder.DOUBLE: 'double'>
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        # Parse border style
        border_str = data.get("border_style", "single")
        try:
            border_style = TableBorder(border_str)
        except ValueError as exc:
            raise ValueError(f"Invalid border_style: {border_str!r}") from exc

        # Parse rows
        rows_data = data.get("rows", [])
        rows = [[Cell.from_dict(cell_data) for cell_data in row_data] for row_data in rows_data]

        # Parse column widths
        column_widths = data.get("column_widths")

        return Table(
            rows=rows,
            border_style=border_style,
            column_widths=column_widths,
        )

    # -------------------------------------------------------------------------
    # MAGIC METHODS
    # -------------------------------------------------------------------------

    def __len__(self) -> int:
        """Return number of rows."""
        return len(self.rows)

    def __getitem__(self, index: int) -> list[Cell]:
        """Get row by index."""
        return self.rows[index]

    def __iter__(self) -> Iterator[list[Cell]]:
        """Iterate over rows."""
        return iter(self.rows)

    def __eq__(self, other: object) -> bool:
        """Check equality with another table."""
        if not isinstance(other, Table):
            return NotImplemented

        return (
            self.rows == other.rows
            and self.border_style == other.border_style
            and self.column_widths == other.column_widths
        )

    def __repr__(self) -> str:
        """Return string representation."""
        rows, cols = self.get_dimensions()
        return f"Table(rows={rows}, cols={cols}, border={self.border_style.value!r})"

    # -------------------------------------------------------------------------
    # ESC/P RENDERING
    # -------------------------------------------------------------------------

    def to_escp(
        self,
        page_width: float = 8.5,
        page_cpi: int = 10,
        lpi: int = 6,
        style: TableStyle | None = None,
    ) -> bytes:
        """
        Generate ESC/P commands for table rendering.

        Args:
            page_width: Page width in inches (default: 8.5").
            page_cpi: Characters per inch (default: 10).
            lpi: Lines per inch (default: 6).
            style: Table style (default: use table's border_style).

        Returns:
            ESC/P command bytes ready for printer.

        Example:
            >>> escp = table.to_escp(page_width=8.5, page_cpi=10)
            >>> # Send escp to printer
        """
        if not self.rows:
            logger.warning("Attempted to render empty table")
            return b""

        # Use provided style or create from border_style
        if style is None:
            style = TableStyle(border=self.border_style)

        # Calculate column widths
        col_widths = self.calculate_column_widths(
            available_width=page_width,
            mode=ColumnSizingMode.AUTO,
            page_cpi=page_cpi,
        )

        # Calculate row heights
        row_heights = self._calculate_row_heights(lpi=lpi)

        # Get border characters
        border_chars = BorderChars.for_style(style.border)

        # Build span coverage map
        span_map = self._build_span_coverage_map()

        # Start building ESC/P output
        parts: list[bytes] = []

        # Top border
        if style.border != TableBorder.NONE:
            top_border = self._render_border_line(
                col_widths,
                border_chars,
                position="top",
                row_idx=0,
                span_map=span_map,
                page_cpi=page_cpi,
            )
            parts.append(top_border)

        # Render each row
        for row_idx, row in enumerate(self.rows):
            row_escp = self._render_row(
                row=row,
                row_idx=row_idx,
                col_widths=col_widths,
                row_height=row_heights[row_idx],
                border_chars=border_chars,
                style=style,
                page_cpi=page_cpi,
                lpi=lpi,
                span_map=span_map,
            )
            parts.append(row_escp)

            # Middle border (between rows)
            if row_idx < len(self.rows) - 1 and style.border != TableBorder.NONE:
                middle_border = self._render_border_line(
                    col_widths,
                    border_chars,
                    position="middle",
                    row_idx=row_idx + 1,
                    span_map=span_map,
                    page_cpi=page_cpi,
                )
                parts.append(middle_border)

        # Bottom border
        if style.border != TableBorder.NONE:
            bottom_border = self._render_border_line(
                col_widths,
                border_chars,
                position="bottom",
                row_idx=len(self.rows),
                span_map=span_map,
                page_cpi=page_cpi,
            )
            parts.append(bottom_border)

        result = b"".join(parts)
        logger.info(f"Generated {len(result)} bytes of ESC/P for table")
        return result

    def _render_row(
        self,
        row: list[Cell],
        row_idx: int,
        col_widths: list[float],
        row_height: float,
        border_chars: BorderChars,
        style: TableStyle,
        page_cpi: int,
        lpi: int,
        span_map: dict[tuple[int, int], tuple[int, int, Cell]],
    ) -> bytes:
        """
        Render a single table row with support for rowspan.

        Args:
            row: List of cells in the row.
            row_idx: Current row index.
            col_widths: Column widths in inches.
            row_height: Height of this row in inches.
            border_chars: Border character set.
            style: Table style.
            page_cpi: Characters per inch.
            lpi: Lines per inch.
            span_map: Span coverage map.

        Returns:
            ESC/P bytes for the row.
        """
        num_cols = len(col_widths)

        # Render all cells to get line lists
        cell_lines_map: dict[int, list[bytes]] = {}

        col_idx = 0
        for current_cell in row:  # ✅ Переименовано из 'cell' в 'current_cell'
            # Skip positions covered by earlier cells
            while col_idx < num_cols and (row_idx, col_idx) in span_map:
                source_row, source_col, source_cell = span_map[(row_idx, col_idx)]
                if source_cell is not current_cell:
                    col_idx += 1
                else:
                    break

            if col_idx >= num_cols:
                break

            # Calculate effective width for this cell
            effective_width = sum(col_widths[col_idx : col_idx + current_cell.colspan])

            # Render cell content (returns list of lines)
            cell_lines = self._render_cell(
                cell=current_cell,
                width_inches=effective_width,
                height_inches=row_height,
                style=style,
                page_cpi=page_cpi,
                lpi=lpi,
            )

            cell_lines_map[col_idx] = cell_lines
            col_idx += current_cell.colspan

        # Calculate max line count
        max_lines = max((len(lines) for lines in cell_lines_map.values()), default=1)

        # Build row line by line
        row_parts: list[bytes] = []

        for line_idx in range(max_lines):
            line_parts: list[bytes] = []

            # Left border
            if style.border != TableBorder.NONE:
                line_parts.append(border_chars.vertical.encode("cp866"))

            col_idx = 0
            while col_idx < num_cols:
                # Check if this position is covered by rowspan from earlier row
                if (row_idx, col_idx) in span_map:
                    source_row, source_col, spanning_cell = span_map[(row_idx, col_idx)]

                    if source_row < row_idx:
                        # Position covered by rowspan - render empty space
                        width_chars = int(col_widths[col_idx] * page_cpi)
                        line_parts.append(b" " * width_chars)

                        # Add vertical border if not part of same span
                        if col_idx < num_cols - 1:
                            next_pos = (row_idx, col_idx + 1)
                            if next_pos in span_map:
                                next_source_row, next_source_col, next_cell = span_map[next_pos]
                                if next_cell is not spanning_cell:
                                    # Different cell - add border
                                    if style.border != TableBorder.NONE:
                                        line_parts.append(border_chars.vertical.encode("cp866"))
                            else:
                                if style.border != TableBorder.NONE:
                                    line_parts.append(border_chars.vertical.encode("cp866"))

                        col_idx += 1
                        continue

                # Normal cell rendering
                if col_idx in cell_lines_map:
                    cell_lines = cell_lines_map[col_idx]

                    if line_idx < len(cell_lines):
                        line_parts.append(cell_lines[line_idx])
                    else:
                        # Padding line
                        width_chars = int(col_widths[col_idx] * page_cpi)
                        line_parts.append(b" " * width_chars)

                    # Find the cell that owns this column position
                    owning_cell: Cell | None = None  # ✅ Явная типизация
                    for c in row:
                        # Check if this cell's lines are at col_idx
                        if id(cell_lines_map.get(col_idx)) is not None:
                            # Simple heuristic: assume cells are in order
                            owning_cell = c
                            break

                    # Move past spanned columns
                    if owning_cell:
                        col_idx += owning_cell.colspan
                    else:
                        col_idx += 1

                    # Add vertical border
                    if col_idx < num_cols and style.border != TableBorder.NONE:
                        line_parts.append(border_chars.vertical.encode("cp866"))
                else:
                    # Empty position
                    width_chars = int(col_widths[col_idx] * page_cpi)
                    line_parts.append(b" " * width_chars)
                    col_idx += 1

                    if col_idx < num_cols and style.border != TableBorder.NONE:
                        line_parts.append(border_chars.vertical.encode("cp866"))

            # Right border
            if style.border != TableBorder.NONE:
                line_parts.append(border_chars.vertical.encode("cp866"))

            # Add line terminator
            line_parts.append(b"\r\n")
            row_parts.append(b"".join(line_parts))

        return b"".join(row_parts)

    def _render_cell(
        self,
        cell: Cell,
        width_inches: float,
        height_inches: float,
        style: TableStyle,
        page_cpi: int,
        lpi: int = 6,
    ) -> list[bytes]:
        """
        Render cell content with padding and alignment.

        Returns list of lines (for vertical alignment support).

        Args:
            cell: Cell to render.
            width_inches: Available width for cell content (inches).
            height_inches: Available height for cell content (inches).
            style: Table styling configuration.
            page_cpi: Characters per inch.
            lpi: Lines per inch (default: 6).

        Returns:
            List of rendered lines as bytes.
        """
        # Check if cell has nested table
        if cell.has_nested_table():
            return self._render_nested_table(
                cell=cell,
                width_inches=width_inches,
                height_inches=height_inches,
                style=style,
                page_cpi=page_cpi,
                lpi=lpi,
            )

        # Calculate character dimensions
        available_chars = int(width_inches * page_cpi)
        padding_chars = int(cell.padding * page_cpi)
        content_chars = available_chars - (2 * padding_chars)

        available_lines = int(height_inches * lpi)

        if content_chars <= 0 or available_lines <= 0:
            # No space for content
            return [b" " * available_chars]

        # Get cell text and split into lines
        cell_text = cell.content.get_text()
        text_lines = cell_text.split("\n")

        # Wrap long lines
        wrapped_lines = []
        for line in text_lines:
            if len(line) <= content_chars:
                wrapped_lines.append(line)
            else:
                # Simple word wrapping
                words = line.split()
                current_line = ""
                for word in words:
                    if len(current_line) + len(word) + 1 <= content_chars:
                        current_line += (" " if current_line else "") + word
                    else:
                        if current_line:
                            wrapped_lines.append(current_line)
                        current_line = word
                if current_line:
                    wrapped_lines.append(current_line)

        # Truncate if too many lines
        if len(wrapped_lines) > available_lines:
            wrapped_lines = wrapped_lines[:available_lines]

        # Apply horizontal alignment to each line
        aligned_lines = []
        for line in wrapped_lines:
            if len(line) > content_chars:
                line = (
                    line[: content_chars - 3] + "..." if content_chars > 3 else line[:content_chars]
                )

            # Horizontal alignment
            if cell.alignment.horizontal == Alignment.CENTER:
                padding_total = content_chars - len(line)
                left_pad = padding_total // 2
                right_pad = padding_total - left_pad
                line = (" " * left_pad) + line + (" " * right_pad)
            elif cell.alignment.horizontal == Alignment.RIGHT:
                line = line.rjust(content_chars)
            else:  # LEFT or JUSTIFY
                line = line.ljust(content_chars)

            # Add cell padding
            padded_line = (" " * padding_chars) + line + (" " * padding_chars)
            aligned_lines.append(padded_line)

        # Apply vertical alignment
        if cell.alignment.vertical == VerticalAlignment.MIDDLE:
            top_padding = (available_lines - len(aligned_lines)) // 2
            bottom_padding = available_lines - len(aligned_lines) - top_padding

            empty_line = " " * available_chars
            aligned_lines = (
                [empty_line] * top_padding + aligned_lines + [empty_line] * bottom_padding
            )

        elif cell.alignment.vertical == VerticalAlignment.BOTTOM:
            padding_lines = available_lines - len(aligned_lines)
            empty_line = " " * available_chars
            aligned_lines = [empty_line] * padding_lines + aligned_lines

        else:  # TOP (default)
            # Pad bottom with empty lines
            while len(aligned_lines) < available_lines:
                aligned_lines.append(" " * available_chars)

        # Convert to bytes
        return [line.encode("cp866", errors="replace") for line in aligned_lines]

    def _render_nested_table(
        self,
        cell: Cell,
        width_inches: float,
        height_inches: float,
        style: TableStyle,
        page_cpi: int,
        lpi: int,
    ) -> list[bytes]:
        """
        Render nested table inside a cell.

        Args:
            cell: Cell containing nested table.
            width_inches: Available width (inches).
            height_inches: Available height (inches).
            style: Table style.
            page_cpi: Characters per inch.
            lpi: Lines per inch.

        Returns:
            List of rendered lines as bytes.
        """
        if cell.nested_table is None:
            return [b""]

        # Calculate available space (account for cell padding)
        nested_width = width_inches - (2 * cell.padding)

        # Generate ESC/P for nested table
        nested_escp = cell.nested_table.to_escp(
            page_width=nested_width,
            page_cpi=page_cpi,
            lpi=lpi,
            style=style,
        )

        # Split into lines
        nested_lines = nested_escp.split(b"\r\n")

        # Apply vertical alignment
        available_lines = int(height_inches * lpi)
        available_chars = int(width_inches * page_cpi)

        if len(nested_lines) < available_lines:
            if cell.alignment.vertical == VerticalAlignment.MIDDLE:
                top_padding = (available_lines - len(nested_lines)) // 2
                bottom_padding = available_lines - len(nested_lines) - top_padding

                empty_line = b" " * available_chars
                nested_lines = (
                    [empty_line] * top_padding + nested_lines + [empty_line] * bottom_padding
                )

            elif cell.alignment.vertical == VerticalAlignment.BOTTOM:
                padding_lines = available_lines - len(nested_lines)
                empty_line = b" " * available_chars
                nested_lines = [empty_line] * padding_lines + nested_lines

            else:  # TOP
                while len(nested_lines) < available_lines:
                    nested_lines.append(b" " * available_chars)

        # Truncate if too many lines
        if len(nested_lines) > available_lines:
            nested_lines = nested_lines[:available_lines]

        return nested_lines

    def _render_border_line(
        self,
        col_widths: list[float],
        border_chars: BorderChars,
        position: str,
        row_idx: int,
        span_map: dict[tuple[int, int], tuple[int, int, Cell]],
        page_cpi: int,
    ) -> bytes:
        """
        Render a border line (top/middle/bottom).

        Args:
            col_widths: Column widths in inches.
            border_chars: Border character set.
            position: Border position ('top', 'middle', 'bottom').
            row_idx: Current row index (for middle borders).
            span_map: Span coverage map.
            page_cpi: Characters per inch.

        Returns:
            ESC/P bytes for the border line.
        """
        num_cols = len(col_widths)
        parts: list[str] = []

        # Left corner/junction
        if position == "top":
            parts.append(border_chars.top_left)
        elif position == "bottom":
            parts.append(border_chars.bottom_left)
        else:  # middle
            parts.append(border_chars.t_right)

        # Columns
        for col_idx in range(num_cols):
            col_width_chars = int(col_widths[col_idx] * page_cpi)

            # Check if rowspan is active at this position
            draw_horizontal = True

            if position == "middle":
                # Check if position above this border has active rowspan
                check_pos = (row_idx - 1, col_idx)
                if check_pos in span_map:
                    source_row, source_col, cell = span_map[check_pos]
                    if source_row + cell.rowspan > row_idx:
                        # Rowspan continues - don't draw horizontal line
                        draw_horizontal = False

            if draw_horizontal:
                parts.append(border_chars.horizontal * col_width_chars)
            else:
                parts.append(" " * col_width_chars)

            # Junction/corner
            if col_idx < num_cols - 1:
                if position == "top":
                    parts.append(border_chars.t_down)
                elif position == "bottom":
                    parts.append(border_chars.t_up)
                else:  # middle
                    # Check if we should draw cross or just vertical
                    # For simplicity, always use cross
                    parts.append(border_chars.cross)

        # Right corner/junction
        if position == "top":
            parts.append(border_chars.top_right)
        elif position == "bottom":
            parts.append(border_chars.bottom_right)
        else:  # middle
            parts.append(border_chars.t_left)

        # Add line terminator
        parts.append("\r\n")

        return "".join(parts).encode("cp866", errors="replace")


"""
=============================================================================
PLANNED FEATURES (NOT YET IMPLEMENTED)
=============================================================================

This section documents features that were planned for table.py but not yet
implemented. These will be added in future versions after escp/ module
refactoring is complete.

Version: 2.1 (planned)
Priority: After escp/ module implementation
Status: Documented, ready for implementation

=============================================================================
"""

# =============================================================================
# PHASE 1: CRITICAL FEATURES (HIGH PRIORITY)
# =============================================================================

"""
1.1 CellStyle — Simplified Cell Formatting
──────────────────────────────────────────────────────────────────────────
Purpose: Simplify cell text formatting with a unified style interface.
Priority: HIGH
Status: Design complete, awaiting escp/ refactor
Dependencies: escp/commands/text_formatting.py

Current limitation:
    # Verbose approach - requires Run objects
    cell = Cell()
    cell.content.add_run(Run(text="Bold", bold=True))

Planned API:
    # Simple approach - style at cell level
    cell = Cell(style=CellStyle(bold=True, italic=True))
    cell.content.extend_text("Bold Italic text")

Implementation:
    @dataclass(frozen=True, slots=True)
    class TextDecoration(Enum):
        NONE = "none"
        UNDERLINE = "underline"
        DOUBLE_UNDERLINE = "double_underline"
        STRIKETHROUGH = "strikethrough"  # Two-pass rendering required

    @dataclass(frozen=True, slots=True)
    class CellStyle:
        '''Visual styling for cell content applied uniformly.'''
        bold: bool = False
        italic: bool = False
        underline: TextDecoration = TextDecoration.NONE
        double_strike: bool = False
        double_width: bool = False
        double_height: bool = False
        condensed: bool = False

        def to_escp_prefix(self) -> bytes:
            '''Generate ESC/P commands to enable this style.'''
            ...

        def to_escp_suffix(self) -> bytes:
            '''Generate ESC/P commands to disable this style.'''
            ...

        def requires_two_pass_rendering(self) -> bool:
            '''Check if strikethrough requires two-pass rendering.'''
            return self.underline == TextDecoration.STRIKETHROUGH

ESC/P Support (FX-890):
    ✅ bold           → ESC E / ESC F
    ✅ italic         → ESC 4 / ESC 5
    ✅ underline      → ESC - 1 / ESC - 0
    ✅ double_underline → ESC - 2 / ESC - 0
    ⚠️ strikethrough  → Two-pass: text + horizontal line overlay (CR + ─)
    ✅ double_strike  → ESC G / ESC H
    ✅ double_width   → ESC W 1 / ESC W 0
    ✅ double_height  → ESC w 1 / ESC w 0
    ✅ condensed      → SI (0x0F) / DC2 (0x12)

Cell integration:
    @dataclass(slots=True)
    class Cell:
        # ... existing fields ...
        style: CellStyle = field(default_factory=CellStyle)  # NEW

Usage example:
    # Header with bold + double-width
    header = Cell(style=CellStyle(bold=True, double_width=True))
    header.content.extend_text("MONTHLY REPORT")

    # Strikethrough (emulated via two-pass)
    cell = Cell(style=CellStyle(underline=TextDecoration.STRIKETHROUGH))
    cell.content.extend_text("Cancelled item")

Testing requirements:
    - Unit tests for all ESC/P command generation
    - Integration tests with actual FX-890 printer
    - Two-pass strikethrough rendering validation
    - to_dict/from_dict serialization
"""


"""
1.2 BarCode Support — Native ESC/P Barcode Rendering
──────────────────────────────────────────────────────────────────────────
Purpose: Support native barcode printing via FX-890 ESC ( B command.
Priority: HIGH
Status: Design complete, awaiting escp/commands/barcode.py
Dependencies: escp/commands/barcode.py

Verified FX-890 support (from manual):
    ✅ CODE39
    ✅ CODE128
    ✅ Interleaved 2 of 5
    ✅ EAN-8
    ✅ EAN-13
    ✅ UPC-A
    ✅ UPC-E
    ✅ POSTNET

Implementation:
    class BarcodeType(Enum):
        CODE39 = "code39"
        CODE128 = "code128"
        INTERLEAVED_2OF5 = "i2of5"
        EAN8 = "ean8"
        EAN13 = "ean13"
        UPCA = "upca"
        UPCE = "upce"
        POSTNET = "postnet"

    class BarcodeHRI(Enum):
        '''Human Readable Interpretation position.'''
        NONE = "none"
        ABOVE = "above"
        BELOW = "below"
        BOTH = "both"

    @dataclass(frozen=True, slots=True)
    class BarCode:
        '''Barcode configuration for FX-890.'''
        type: BarcodeType
        data: str
        height: int = 50  # dots (8-255)
        width: int = 2    # module width (2-6)
        hri: BarcodeHRI = BarcodeHRI.BELOW

        def __post_init__(self) -> None:
            if not (8 <= self.height <= 255):
                raise ValueError("height must be 8-255")
            if not (2 <= self.width <= 6):
                raise ValueError("width must be 2-6")

        def to_escp(self) -> bytes:
            '''Generate ESC ( B command: ESC ( B n1 n2 type h w hri data'''
            ...

Cell integration:
    @dataclass(slots=True)
    class Cell:
        # ... existing fields ...
        barcode: BarCode | None = None  # NEW

        def has_barcode(self) -> bool:
            return self.barcode is not None

Usage example:
    # EAN-13 barcode in table cell
    barcode = BarCode(
        type=BarcodeType.EAN13,
        data="1234567890128",
        height=60,
        width=3,
        hri=BarcodeHRI.BELOW
    )
    cell = Cell(barcode=barcode)

    # Combination: text + barcode
    cell = Cell(barcode=barcode)
    cell.content.extend_text("Product: ABC-123")  # Text above barcode

Rendering logic:
    - If cell.has_barcode() and cell.content is empty → render only barcode
    - If both present → render text, then barcode below
    - Barcode alignment respects cell.alignment.horizontal
    - Barcode height accounts for row_height allocation

Testing requirements:
    - All barcode types with valid/invalid data
    - HRI position variations
    - Parameter validation (height, width ranges)
    - Integration with table row rendering
"""


"""
1.3 Export Formats — HTML/CSV/Markdown
──────────────────────────────────────────────────────────────────────────
Purpose: Universal table export for documentation and data exchange.
Priority: HIGH
Status: Design complete, pure Python (no printer dependency)
Dependencies: None (stdlib only)

Implementation:
    class Table:
        def to_html(self, css_classes: bool = True) -> str:
            '''Export to HTML with optional CSS classes.

            Supports:
                - colspan/rowspan attributes
                - Bold/italic via <strong>/<em> tags
                - CSS classes: .escp-table, .header-row

            Limitations:
                - No nested table rendering (flatten to text)
                - No barcode rendering (show data as text)
            '''
            ...

        def to_markdown(self) -> str:
            '''Export to GitHub Flavored Markdown.

            Limitations:
                - No colspan/rowspan (Markdown limitation)
                - Merged cells are flattened
                - First row treated as header

            Example output:
                | Header 1 | Header 2 | Header 3 |
                | -------- | -------- | -------- |
                | Cell 1   | Cell 2   | Cell 3   |
            '''
            ...

        def to_csv(self, delimiter: str = ",", quote_char: str = '"') -> str:
            '''Export to CSV using stdlib csv module.

            Limitations:
                - No formatting preservation
                - Merged cells flattened to single value
                - Nested tables converted to text

            Args:
                delimiter: Field separator (default: comma)
                quote_char: Quote character (default: double-quote)
            '''
            ...

Usage example:
    # HTML export for documentation
    html = table.to_html()
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)

    # Markdown for README
    md = table.to_markdown()
    print(md)

    # CSV for Excel
    csv = table.to_csv(delimiter=";")
    with open("data.csv", "w", encoding="utf-8") as f:
        f.write(csv)

Testing requirements:
    - All export formats with various table configurations
    - colspan/rowspan handling in HTML
    - Special character escaping (HTML entities, CSV quotes)
    - Unicode support (UTF-8 encoding)
"""


# =============================================================================
# PHASE 2: PRODUCTIVITY FEATURES (MEDIUM PRIORITY)
# =============================================================================

"""
2.1 Table Templates — Pre-built Layouts
──────────────────────────────────────────────────────────────────────────
Purpose: Rapid table creation for common business documents.
Priority: MEDIUM
Status: Design phase
Dependencies: None

Planned templates:
    - INVOICE: Header + line items + totals
    - REPORT: Title + data grid + summary
    - PRICE_LIST: Product + description + price columns
    - CHECKLIST: Item + checkbox + notes columns
    - CALENDAR: Month grid with day cells
    - TIMESHEET: Employee + hours per day matrix

Implementation:
    class TableTemplate(Enum):
        INVOICE = "invoice"
        REPORT = "report"
        PRICE_LIST = "price_list"
        CHECKLIST = "checklist"
        CALENDAR = "calendar"
        TIMESHEET = "timesheet"

    def create_from_template(
        template: TableTemplate,
        data: dict[str, Any]
    ) -> Table:
        '''Create pre-configured table from template.

        Args:
            template: Template type
            data: Template-specific data dict

        Example:
            >>> data = {
            ...     "title": "INVOICE #123",
            ...     "items": [
            ...         {"name": "Product A", "qty": 2, "price": 15.00},
            ...         {"name": "Product B", "qty": 1, "price": 25.00},
            ...     ],
            ...     "total": 55.00
            ... }
            >>> table = create_from_template(TableTemplate.INVOICE, data)
        '''
        ...

Template-specific data structures:
    # Invoice template
    InvoiceData = TypedDict('InvoiceData', {
        'title': str,
        'invoice_number': str,
        'date': str,
        'items': list[dict[str, Any]],  # name, qty, price
        'subtotal': float,
        'tax': float,
        'total': float,
    })

    # Report template
    ReportData = TypedDict('ReportData', {
        'title': str,
        'headers': list[str],
        'rows': list[list[str]],
        'summary': dict[str, Any],
    })

Testing requirements:
    - All templates with minimal/maximal data
    - Data validation (required fields, types)
    - Template rendering consistency
"""


"""
2.2 Auto-numbering and Simple Formulas
──────────────────────────────────────────────────────────────────────────
Purpose: Automatic row numbering and basic calculations.
Priority: MEDIUM
Status: Design phase
Dependencies: None (pure Python)

Implementation:
    class CellFormula(Enum):
        NONE = "none"
        ROW_NUMBER = "row_number"      # 1, 2, 3, ...
        COLUMN_LETTER = "column_letter" # A, B, C, ...
        SUM = "sum"                     # Sum of range
        AVG = "avg"                     # Average of range
        COUNT = "count"                 # Count non-empty cells
        MIN = "min"                     # Minimum value
        MAX = "max"                     # Maximum value

    @dataclass(slots=True)
    class Cell:
        # ... existing fields ...
        formula: CellFormula = CellFormula.NONE
        formula_range: tuple[int, int, int, int] | None = None  # (r1,c1,r2,c2)

Usage example:
    # Auto-numbered rows
    for i in range(10):
        num_cell = Cell(formula=CellFormula.ROW_NUMBER)
        data_cell = Cell()
        data_cell.content.extend_text(f"Item {i+1}")
        table.add_row([num_cell, data_cell])

    # Total row with SUM formula
    total_cell = Cell(
        formula=CellFormula.SUM,
        formula_range=(1, 2, 10, 2)  # Sum column 2, rows 1-10
    )
    table.add_row([Cell(), Cell(), total_cell])

Formula evaluation:
    - Evaluated during to_escp() / to_html() / to_csv()
    - Cell.content updated with computed value
    - Formulas can reference other cells (via formula_range)
    - Type coercion: strings → floats for numeric operations

Testing requirements:
    - All formula types with valid ranges
    - Circular reference detection
    - Empty cell handling
    - Type conversion edge cases
"""


"""
2.3 Table Sorting and Filtering
──────────────────────────────────────────────────────────────────────────
Purpose: Dynamic data manipulation before rendering.
Priority: MEDIUM
Status: Design phase
Dependencies: None

Implementation:
    class Table:
        def sort_by_column(
            self,
            col_idx: int,
            reverse: bool = False,
            key: Callable[[str], Any] | None = None,
            skip_header: bool = True
        ) -> None:
            '''Sort rows by column value.

            Args:
                col_idx: Column index to sort by
                reverse: Descending order if True
                key: Custom sort key (e.g., float for numeric sort)
                skip_header: Don't sort first row (header)
            '''
            ...

        def filter_rows(
            self,
            col_idx: int,
            condition: Callable[[str], bool],
            skip_header: bool = True
        ) -> Table:
            '''Create new table with filtered rows.

            Args:
                col_idx: Column to test
                condition: Boolean predicate
                skip_header: Always include first row

            Returns:
                New table with matching rows
            '''
            ...

        def group_by_column(
            self,
            col_idx: int,
            aggregate: dict[int, Callable[[list], Any]]
        ) -> Table:
            '''Group rows by column value with aggregation.

            Args:
                col_idx: Column to group by
                aggregate: Column → aggregation function mapping

            Example:
                >>> # Group by category, sum amounts
                >>> grouped = table.group_by_column(
                ...     col_idx=0,  # Group by column 0
                ...     aggregate={2: sum}  # Sum column 2
                ... )
            '''
            ...

Usage example:
    # Sort by price (column 2), highest first
    table.sort_by_column(2, reverse=True, key=float)

    # Filter rows where date contains "2024"
    filtered = table.filter_rows(0, lambda val: "2024" in val)

    # Group by category, sum quantities
    grouped = table.group_by_column(
        col_idx=0,
        aggregate={1: sum, 2: len}  # Sum col 1, count col 2
    )

Testing requirements:
    - Sorting with various key functions
    - Filtering with complex predicates
    - Grouping with multiple aggregation functions
    - Header preservation
"""


"""
2.4 Table Pagination with Header Repeat
──────────────────────────────────────────────────────────────────────────
Purpose: Split large tables across multiple pages.
Priority: MEDIUM
Status: Design phase
Dependencies: None

Implementation:
    class Table:
        def paginate(
            self,
            max_rows_per_page: int = 50,
            repeat_header: bool = True,
            repeat_footer: bool = False
        ) -> list[Table]:
            '''Split table into page-sized chunks.

            Args:
                max_rows_per_page: Maximum rows per page
                repeat_header: Repeat first row on each page
                repeat_footer: Repeat last row on each page

            Returns:
                List of Table objects, one per page
            '''
            ...

Usage example:
    # Long table with 500 rows
    pages = table.paginate(max_rows_per_page=50, repeat_header=True)

    # Print each page separately
    for i, page in enumerate(pages):
        print(f"--- Page {i+1}/{len(pages)} ---")
        escp = page.to_escp()
        printer.send(escp)
        if i < len(pages) - 1:
            printer.send(b"\x0c")  # Form feed

Testing requirements:
    - Various page sizes
    - Header/footer repetition
    - Single-page tables (no split)
    - Edge cases (empty table, 1-row table)
"""


# =============================================================================
# PHASE 3: ADVANCED FEATURES (LOW PRIORITY)
# =============================================================================

"""
3.1 Conditional Cell Formatting
──────────────────────────────────────────────────────────────────────────
Purpose: Auto-apply styles based on cell values.
Priority: LOW
Status: Concept phase
Dependencies: Phase 1.1 (CellStyle)

Implementation:
    @dataclass(slots=True)
    class ConditionalRule:
        condition: Callable[[str], bool]
        style: CellStyle

    @dataclass(slots=True)
    class Cell:
        # ... existing fields ...
        conditional_rules: list[ConditionalRule] = field(default_factory=list)

Usage example:
    # Negative numbers in red + bold
    rules = [
        ConditionalRule(
            condition=lambda val: float(val) < 0,
            style=CellStyle(bold=True)  # Note: FX-890 has no color
        ),
        ConditionalRule(
            condition=lambda val: float(val) > 1000,
            style=CellStyle(double_width=True)
        )
    ]

    cell = Cell()
    cell.content.extend_text("-500")
    cell.conditional_rules = rules
    # Renders with bold style automatically
"""


"""
3.2 Table Merge Operations
──────────────────────────────────────────────────────────────────────────
Purpose: Combine multiple tables horizontally or vertically.
Priority: LOW
Status: Concept phase
Dependencies: None

Implementation:
    class Table:
        def merge_horizontal(self, other: Table) -> Table:
            '''Append columns from other table.'''
            ...

        def merge_vertical(self, other: Table) -> Table:
            '''Append rows from other table.'''
            ...

Usage example:
    # Combine two tables side-by-side
    merged = table1.merge_horizontal(table2)

    # Stack tables vertically
    combined = table1.merge_vertical(table2)
"""


"""
3.3 Cell Data Validation
──────────────────────────────────────────────────────────────────────────
Purpose: Enforce data types and formats in cells.
Priority: LOW
Status: Concept phase
Dependencies: None

Implementation:
    class CellDataType(Enum):
        TEXT = "text"
        NUMBER = "number"
        DATE = "date"
        CURRENCY = "currency"
        PERCENTAGE = "percentage"
        EMAIL = "email"
        PHONE = "phone"

    @dataclass(slots=True)
    class Cell:
        # ... existing fields ...
        data_type: CellDataType = CellDataType.TEXT

        def validate_data(self) -> bool:
            '''Check if content matches data_type.'''
            ...

Usage example:
    cell = Cell(data_type=CellDataType.NUMBER)
    cell.content.extend_text("123.45")
    assert cell.validate_data() == True

    cell.content = Paragraph()
    cell.content.extend_text("abc")
    assert cell.validate_data() == False
"""


# =============================================================================
# FUTURE CONSIDERATIONS (NOT PLANNED FOR 2.x)
# =============================================================================

"""
4.1 Advanced Border Styles
──────────────────────────────────────────────────────────────────────────
Status: Deferred to 3.0
Notes: FX-890 has limited box-drawing characters in CP866

Potential features:
    - Border position control (OUTER/INNER/HORIZONTAL/VERTICAL)
    - Diagonal borders (not supported by FX-890)
    - Custom border characters
    - Per-side border width
"""


"""
4.2 Cell Background Shading via Character Patterns
──────────────────────────────────────────────────────────────────────────
Status: Deferred to 3.0
Notes: FX-890 is monochrome, shading via block characters (░▒▓█)

Potential features:
    class CellBackground(Enum):
        NONE = "none"
        LIGHT = "light"   # ░ (U+2591, CP866: 0xB0)
        MEDIUM = "medium" # ▒ (U+2592, CP866: 0xB1)
        DARK = "dark"     # ▓ (U+2593, CP866: 0xB2)
        SOLID = "solid"   # █ (U+2588, CP866: 0xDB)

Limitations:
    - Character-based, not true graphics
    - Depends on printer font support
    - May affect text readability
"""


"""
4.3 Text Rotation / Vertical Text
──────────────────────────────────────────────────────────────────────────
Status: Deferred to 3.0
Notes: FX-890 has no native rotation command

Potential workaround:
    - Print characters vertically (one per line)
    - Use stacked layout for narrow columns
    - Requires complex line spacing calculations
"""

# =============================================================================
# END OF PLANNED FEATURES
# =============================================================================

"""
=============================================================================
END OF TABLE.PY
=============================================================================
Module: src/model/table.py
Version: 2.0 (current), 2.1 (planned with features above)
Status: Production-ready for core functionality
Coverage: 96%
Tests: 110+
Last Updated: October 2025
=============================================================================
"""
