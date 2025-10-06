from __future__ import annotations

"""
Модель таблицы с ячейками, границами, вложенными таблицами, структурными span'ами и layout‑параметрами.
Table model for advanced editor, providing grid structure, alignment, merging, serialization, layout metrics,
and extensibility (sorting, filtering, formulas, pagination, merge, conditional formatting, etc.)
ESC/P‑generation is NOT included; for layout and document modeling only.

Module: src/model/table.py
Project: ESC/P Text Editor
Version: 3.0 (layout-only model, features from 2.x + roadmap extensions)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Final,
    Iterator,
    List,
    Optional,
    Tuple,
    Dict,
    Callable,
    TypeVar,
    Literal,
    Union,
)

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS, PAPER SETTINGS
# =============================================================================

MIN_SPAN: Final[int] = 1
MAX_SPAN: Final[int] = 100


@dataclass(frozen=True)
class PaperSettings:
    """Layout parameters for paper format, for sizing/table layout ONLY."""

    width_mm: float
    height_mm: float
    margin_left_mm: float = 0.0
    margin_top_mm: float = 0.0
    margin_right_mm: float = 0.0
    margin_bottom_mm: float = 0.0
    orientation: Literal["portrait", "landscape"] = "portrait"
    dpi: int = 180  # for pixel-based layout only


# =============================================================================
# ENUMS FOR TABLE STRUCTURE & STYLE
# =============================================================================


class TableBorder(Enum):
    NONE = "none"
    SINGLE = "single"
    DOUBLE = "double"
    ASCII_ART = "ascii_art"


class ColumnSizingMode(Enum):
    AUTO = "auto"
    EQUAL = "equal"
    FIXED = "fixed"
    PROPORTIONAL = "proportional"


class VerticalAlignment(Enum):
    TOP = "top"
    MIDDLE = "middle"
    BOTTOM = "bottom"


class CellAlignment(Enum):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"


@dataclass(frozen=True, slots=True)
class BorderChars:
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
        return BorderChars("─", "│", "┌", "┐", "└", "┘", "┼", "┬", "┴", "├", "┤")

    @staticmethod
    def double_line() -> "BorderChars":
        return BorderChars("═", "‖", "╔", "╗", "╚", "╝", "╬", "╦", "╩", "╠", "╣")

    @staticmethod
    def ascii_art() -> "BorderChars":
        return BorderChars("-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "+")

    @staticmethod
    def for_style(style: TableBorder) -> "BorderChars":
        if style == TableBorder.SINGLE:
            return BorderChars.single_line()
        elif style == TableBorder.DOUBLE:
            return BorderChars.double_line()
        elif style == TableBorder.ASCII_ART:
            return BorderChars.ascii_art()
        else:
            return BorderChars(" ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ")


@dataclass(frozen=True, slots=True)
class CellBorders:
    left: TableBorder = TableBorder.NONE
    right: TableBorder = TableBorder.NONE
    top: TableBorder = TableBorder.NONE
    bottom: TableBorder = TableBorder.NONE

    def is_any_visible(self) -> bool:
        return any(b != TableBorder.NONE for b in [self.left, self.right, self.top, self.bottom])


# Barcode support
@dataclass
class BarCode:
    data: str
    type: Literal["Code128", "EAN13", "QR", "PDF417"] = "Code128"
    width_mm: Optional[float] = None
    height_mm: Optional[float] = None
    hri: Optional[str] = None


class CellDataType(Enum):
    TEXT = "text"
    NUMBER = "number"
    DATE = "date"
    FORMULA = "formula"
    BARCODE = "barcode"
    STYLE = "style"


@dataclass(frozen=True)
class CellStyle:
    bold: bool = False
    italic: bool = False
    underline: bool = False
    condensed: bool = False
    double_width: bool = False
    double_height: bool = False
    strikethrough: bool = False
    font: Optional[str] = None
    font_size_pt: Optional[int] = None
    foreground: Optional[str] = None
    background: Optional[str] = None
    shading: Optional[str] = None


@dataclass(frozen=True)
class ConditionalRule:
    condition: Callable[[Any], bool]
    style: CellStyle


@dataclass
class Run:
    text: str
    style: Optional[CellStyle] = None
    barcode: Optional[BarCode] = None


@dataclass
class Paragraph:
    runs: List[Run]
    alignment: CellAlignment = CellAlignment.LEFT
    indent: Optional[int] = 0


# =============================================================================
# CELL AND TABLEMETRICS STRUCTURE
# =============================================================================


@dataclass
class Cell:
    text: str = ""
    paragraph: Optional[Paragraph] = None
    runs: Optional[List[Run]] = None
    nested_table: Optional["Table"] = None
    colspan: int = 1
    rowspan: int = 1
    align: CellAlignment = CellAlignment.LEFT
    valign: VerticalAlignment = VerticalAlignment.TOP
    borders: CellBorders = field(default_factory=CellBorders)
    background_color: Optional[str] = None
    style: Optional[CellStyle] = None
    conditional_rules: Optional[List[ConditionalRule]] = None
    formula: Optional[str] = None
    formula_enum: Optional[str] = None
    data_type: CellDataType = CellDataType.TEXT
    barcode: Optional[BarCode] = None
    sort_key: Optional[Any] = None
    padding: Optional[Tuple[int, int, int, int]] = None  # left, top, right, bottom

    def copy(self) -> "Cell":
        import copy

        return copy.deepcopy(self)

    def is_merged(self) -> bool:
        return self.colspan > 1 or self.rowspan > 1

    def hasnestedtable(self) -> bool:
        return self.nested_table is not None

    def as_dict(self, flatten: bool = False) -> dict:
        cell_dict = {
            "text": self.text,
            "colspan": self.colspan,
            "rowspan": self.rowspan,
            "align": self.align.value,
            "valign": self.valign.value,
            "borders": {
                "left": self.borders.left.value,
                "right": self.borders.right.value,
                "top": self.borders.top.value,
                "bottom": self.borders.bottom.value,
            },
            "background_color": self.background_color,
            "style": self.style.__dict__ if self.style else None,
            "conditional_rules": [
                {"condition": str(rule.condition), "style": rule.style.__dict__}
                for rule in self.conditional_rules or []
            ],
            "formula": self.formula,
            "formula_enum": self.formula_enum,
            "data_type": self.data_type.value,
            "barcode": self.barcode.__dict__ if self.barcode else None,
            "sort_key": self.sort_key,
            "padding": self.padding,
        }
        if self.paragraph:
            cell_dict["paragraph"] = {
                "runs": [run.text for run in self.paragraph.runs],
                "alignment": self.paragraph.alignment.value,
                "indent": self.paragraph.indent,
            }
        if self.runs:
            cell_dict["runs"] = [run.text for run in self.runs]
        if self.nested_table:
            if flatten:
                cell_dict["nested_table"] = self.nested_table.serialize(flatten=True)
            else:
                cell_dict["nested_table"] = "<table>"
        return cell_dict


@dataclass(frozen=True, slots=True)
class TableMetrics:
    rows: int
    columns: int
    width_mm: Optional[float] = None
    height_mm: Optional[float] = None
    cell_widths: Optional[List[float]] = None
    cell_heights: Optional[List[float]] = None


# =============================================================================
# BASE TABLE STRUCTURE
# =============================================================================


@dataclass
class Table:
    rows: List[List[Cell]] = field(default_factory=list)
    paper: Optional[PaperSettings] = None
    border: TableBorder = TableBorder.SINGLE
    column_sizing: ColumnSizingMode = ColumnSizingMode.AUTO
    template_id: Optional[str] = None
    metrics: Optional[TableMetrics] = None
    tags: Optional[List[str]] = None
    parent: Optional["Table"] = None  # вложенные таблицы — обратная ссылка
    group_by: Optional[int] = None
    aggregation: Optional[str] = None
    style: Optional[CellStyle] = None

    # ========================
    # BASIC OPERATIONS
    # ========================
    def add_row(self, cells: List[Cell]) -> None:
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")
        if self.rows and len(cells) != len(self.rows[0]):
            raise ValueError(
                f"Row length {len(cells)} doesn't match table width {len(self.rows[0])}"
            )
        self.rows.append(cells)
        logger.debug(f"Added row of {len(cells)} cells")

    def insert_row(self, index: int, cells: List[Cell]) -> None:
        if not isinstance(cells, list):
            raise TypeError(f"cells must be list, got {type(cells).__name__}")
        if self.rows and len(cells) != len(self.rows[0]):
            raise ValueError(
                f"Row length {len(cells)} doesn't match table width {len(self.rows[0])}"
            )
        if not (0 <= index <= len(self.rows)):
            raise IndexError(f"Row index {index} out of range")
        self.rows.insert(index, cells)
        logger.debug(f"Inserted row at {index}, {len(cells)} cells")

    def get_cells(self) -> Iterator[Cell]:
        for row in self.rows:
            for cell in row:
                yield cell

    def get_cell(self, row: int, col: int) -> Cell:
        return self.rows[row][col]

    def merge_cells(self, row: int, col: int, rowspan: int = 1, colspan: int = 1) -> None:
        cell = self.get_cell(row, col)
        cell.rowspan = rowspan
        cell.colspan = colspan

    def split_cell(self, row: int, col: int) -> None:
        cell = self.get_cell(row, col)
        if cell.rowspan == 1 and cell.colspan == 1:
            return  # nothing to do
        for i in range(row, row + cell.rowspan):
            for j in range(col, col + cell.colspan):
                if i == row and j == col:
                    cell.rowspan = 1
                    cell.colspan = 1
                else:
                    self.rows[i][j] = Cell()  # создаём новый пустой Cell

    def set_paper(self, paper: PaperSettings) -> None:
        self.paper = paper
        logger.info(f"Paper set to {paper}")

    def serialize(self, flatten: bool = False) -> dict:
        return {
            "rows": [[cell.as_dict(flatten=flatten) for cell in row] for row in self.rows],
            "paper": self.paper.__dict__ if self.paper else None,
            "border": self.border.value,
            "column_sizing": self.column_sizing.value,
            "template_id": self.template_id,
            "metrics": self.metrics.__dict__ if self.metrics else None,
            "tags": self.tags,
            "style": self.style.__dict__ if self.style else None,
        }

    # ==========
    # NESTED, GROUPBY, AGGREGATION, PAGINATION, CONDITIONAL FORMATTING
    # ==========

    def traverse(self, depth: int = 0) -> Iterator["Table"]:
        yield self
        for row in self.rows:
            for cell in row:
                if cell.nested_table is not None:
                    yield from cell.nested_table.traverse(depth + 1)

    def flatten(self) -> List["Table"]:
        return list(self.traverse())

    def groupby(self, column: int) -> Dict[Any, List[List[Cell]]]:
        result: Dict[Any, List[List[Cell]]] = {}
        for row in self.rows:
            key = row[column].text
            result.setdefault(key, []).append(row)
        return result

    def aggregate(self, column: int, method: str = "SUM") -> float:
        vals = []
        for row in self.rows:
            try:
                val = float(row[column].text)
                vals.append(val)
            except ValueError:
                continue
        if method == "SUM":
            return sum(vals)
        elif method == "AVG" and vals:
            return sum(vals) / len(vals)
        else:
            raise ValueError(f"Unsupported aggregation method: {method}")

    def paginate(self, max_rows_per_page: int, repeat_header: bool = True) -> List["Table"]:
        total_rows = len(self.rows)
        header = self.rows[0] if repeat_header and self.rows else None
        pages = []
        for start in range(0, total_rows, max_rows_per_page):
            page_rows = self.rows[start : start + max_rows_per_page]
            if repeat_header and header is not None:
                page_rows = [header.copy()] + page_rows
            pg = Table(
                rows=page_rows,
                paper=self.paper,
                border=self.border,
                column_sizing=self.column_sizing,
                template_id=self.template_id,
                metrics=self.metrics,
                tags=(self.tags[:] if self.tags else None),
                parent=self.parent,
                style=self.style,
            )
            pages.append(pg)
        logger.info(f"Paginated table with header: {len(pages)} pages")
        return pages

    def apply_conditional_formatting(self) -> None:
        for row in self.rows:
            for cell in row:
                if cell.conditional_rules:
                    for rule in cell.conditional_rules:
                        try:
                            if rule.condition(cell.text):
                                cell.style = rule.style
                        except Exception as e:
                            logger.warning(f"Conditional formatting error: {e}")

    def create_from_template(self, template: "Table") -> "Table":
        import copy

        new_rows = []
        for row in template.rows:
            new_row = []
            for cell in row:
                cell_kwargs = copy.deepcopy(cell.as_dict())
                cell_kwargs["text"] = ""
                new_row.append(Cell(**cell_kwargs))
            new_rows.append(new_row)
        return Table(
            rows=new_rows,
            paper=template.paper,
            border=template.border,
            column_sizing=template.column_sizing,
            template_id=template.template_id,
            metrics=template.metrics,
            tags=template.tags[:] if template.tags else None,
            style=template.style,
        )

    # ==========
    # VISUALIZATION, EXPORT, UTILITY, VALIDATION
    # ==========

    def ascii_preview(self, recursion_depth: int = 2) -> str:
        def preview_table(tbl: Table, depth: int) -> str:
            if depth < 0:
                return "<max depth reached>"
            ncols = len(tbl.rows[0]) if tbl.rows else 0
            chars = BorderChars.for_style(tbl.border)
            result = [
                chars.top_left
                + (chars.horizontal * 5 + chars.t_down) * (ncols - 1)
                + chars.top_right
            ]
            for row in tbl.rows:
                r = chars.vertical
                for cell in row:
                    txt = cell.text[:5].center(5)
                    if cell.nested_table:
                        txt = "[TBL]"
                    r += f"{txt}{chars.vertical}"
                result.append(r)
                result.append(
                    chars.t_right
                    + (chars.horizontal * 5 + chars.cross) * (ncols - 1)
                    + chars.t_left
                )
            result[-1] = (
                chars.bottom_left
                + (chars.horizontal * 5 + chars.t_up) * (ncols - 1)
                + chars.bottom_right
            )
            for row in tbl.rows:
                for cell in row:
                    if cell.nested_table:
                        result.append(
                            "  " * (recursion_depth - depth)
                            + preview_table(cell.nested_table, depth - 1)
                        )
            return "\n".join(result)

        return preview_table(self, recursion_depth)

    @classmethod
    def from_dict(cls, data: dict) -> "Table":
        def cell_from_dict(d: dict) -> Cell:
            nested_table = (
                Table.from_dict(d["nested_table"])
                if "nested_table" in d and d["nested_table"] is not None
                else None
            )
            style = CellStyle(**d["style"]) if d.get("style") else None
            conditional_rules = (
                [
                    ConditionalRule(
                        condition=lambda x: eval(rule["condition"]),
                        style=CellStyle(**rule["style"]),
                    )
                    for rule in d.get("conditional_rules", [])
                ]
                if d.get("conditional_rules")
                else None
            )
            return Cell(
                text=d.get("text", ""),
                colspan=d.get("colspan", 1),
                rowspan=d.get("rowspan", 1),
                align=CellAlignment(d.get("align", "left")),
                valign=VerticalAlignment(d.get("valign", "top")),
                borders=CellBorders(
                    left=TableBorder(d["borders"].get("left", "none")),
                    right=TableBorder(d["borders"].get("right", "none")),
                    top=TableBorder(d["borders"].get("top", "none")),
                    bottom=TableBorder(d["borders"].get("bottom", "none")),
                ),
                background_color=d.get("background_color"),
                style=style,
                conditional_rules=conditional_rules,
                formula=d.get("formula"),
                formula_enum=d.get("formula_enum"),
                data_type=CellDataType(d.get("data_type", "text")),
                barcode=BarCode(**d["barcode"]) if d.get("barcode") else None,
                sort_key=d.get("sort_key"),
                nested_table=nested_table,
                paragraph=Paragraph(**d["paragraph"]) if d.get("paragraph") else None,
                runs=[Run(**run) for run in d.get("runs", [])] if d.get("runs") else None,
                padding=d.get("padding"),
            )

        rows: List[List[Cell]] = [[cell_from_dict(cell) for cell in row] for row in data["rows"]]
        paper = PaperSettings(**data["paper"]) if data.get("paper") else None
        border = TableBorder(data.get("border", "single"))
        column_sizing = ColumnSizingMode(data.get("column_sizing", "auto"))
        template_id = data.get("template_id")
        metrics = TableMetrics(**data["metrics"]) if data.get("metrics") else None
        tags = data.get("tags")
        style = CellStyle(**data["style"]) if data.get("style") else None
        return Table(
            rows=rows,
            paper=paper,
            border=border,
            column_sizing=column_sizing,
            template_id=template_id,
            metrics=metrics,
            tags=tags,
            style=style,
        )

    def validate_span_coverage(self) -> bool:
        rows = len(self.rows)
        cols = len(self.rows[0]) if self.rows else 0
        grid = [[0 for _ in range(cols)] for _ in range(rows)]
        for i, row in enumerate(self.rows):
            for j, cell in enumerate(row):
                for dr in range(cell.rowspan):
                    for dc in range(cell.colspan):
                        r, c = i + dr, j + dc
                        if r < rows and c < cols:
                            grid[r][c] += 1
        ok = all(all(val == 1 for val in row) for row in grid)
        return ok

    def set_padding(self, left: int = 0, top: int = 0, right: int = 0, bottom: int = 0) -> None:
        for cell in self.get_cells():
            cell.padding = (left, top, right, bottom)

    def add_column(self, index: Optional[int] = None, default_cell: Optional[Cell] = None) -> None:
        if not self.rows:
            raise ValueError("Table is empty, can't add column.")
        if index is None:
            index = len(self.rows[0])
        for row in self.rows:
            row.insert(index, default_cell.copy() if default_cell else Cell())

    def swap_columns(self, idx1: int, idx2: int) -> None:
        for row in self.rows:
            row[idx1], row[idx2] = row[idx2], row[idx1]

    def transpose(self) -> None:
        self.rows = [list(r) for r in zip(*self.rows)]

    def flatten_text(self, sep: str = " ") -> str:
        return sep.join(cell.text for cell in self.get_cells() if cell.text)

    def footprint(self) -> Dict[str, Any]:
        cell_count = sum(len(row) for row in self.rows)
        nested_tables = sum(1 for row in self.rows for cell in row if cell.nested_table is not None)
        max_colspan = max(cell.colspan for row in self.rows for cell in row)
        max_rowspan = max(cell.rowspan for row in self.rows for cell in row)
        type_histogram: Dict[str, int] = {}
        style_histogram: Dict[str, int] = {}
        for cell in self.get_cells():
            type_histogram[cell.data_type.value] = type_histogram.get(cell.data_type.value, 0) + 1
            if cell.style:
                style_str = str(cell.style)
                style_histogram[style_str] = style_histogram.get(style_str, 0) + 1
        return {
            "rows": len(self.rows),
            "columns": len(self.rows[0]) if self.rows else 0,
            "cell_count": cell_count,
            "nested_tables": nested_tables,
            "max_colspan": max_colspan,
            "max_rowspan": max_rowspan,
            "type_histogram": type_histogram,
            "style_histogram": style_histogram,
        }

    def cell_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_length": 0,
            "numeric_cells": 0,
            "formula_cells": 0,
            "barcode_cells": 0,
        }
        for cell in self.get_cells():
            stats["total_length"] += len(cell.text) if cell.text else 0
            if cell.data_type == CellDataType.NUMBER:
                stats["numeric_cells"] += 1
            if cell.formula:
                stats["formula_cells"] += 1
            if cell.barcode is not None:
                stats["barcode_cells"] += 1
        return stats

    def export_stats(self) -> Dict[str, Any]:
        return {
            "footprint": self.footprint(),
            "cell_statistics": self.cell_statistics(),
            "validation": self.validate(),
        }

    def to_json(self, flatten: bool = False) -> str:
        import json

        return json.dumps(self.serialize(flatten=flatten), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "Table":
        import json

        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> bool:
        ncols = len(self.rows[0]) if self.rows else 0
        for row in self.rows:
            if len(row) != ncols:
                return False
            for cell in row:
                if not (MIN_SPAN <= cell.colspan <= MAX_SPAN):
                    return False
                if not (MIN_SPAN <= cell.rowspan <= MAX_SPAN):
                    return False
                if not isinstance(cell.data_type, CellDataType):
                    return False
        visited = set()

        def check_cycles(table: "Table") -> bool:
            if id(table) in visited:
                return False
            visited.add(id(table))
            for row in table.rows:
                for cell in row:
                    if cell.nested_table:
                        if not check_cycles(cell.nested_table):
                            return False
            return True

        if not check_cycles(self):
            return False
        return True
