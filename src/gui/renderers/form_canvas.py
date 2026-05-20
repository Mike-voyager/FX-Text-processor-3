"""Form Canvas для StructuredFormRenderer.

Модуль предоставляет FormCanvas — специализированный Canvas для
визуального проектирования форм с жёсткой сеткой ESC/P 80×66.

Features:
- Strict ESC/P grid: 80 columns × 66 rows
- Snap-to-grid positioning
- Zoom support (0.5x - 2.0x)
- Toggleable grid lines и margins
- Coordinate conversion utilities
- Field overlap detection с визуальным feedback
- Drag/resize полей с rollback при перекрытии

Example:
    >>> from src.gui.renderers.form_canvas import FormCanvas, FieldPosition
    >>> import tkinter as tk
    >>> root = tk.Tk()
    >>> canvas = FormCanvas("designer_1", profile=None, zoom=1.0)
    >>> canvas.mount(root)
    >>> field_widget = canvas.create_field(field_def, x=5, y=5, width=3, height=1)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from typing import Any, Final, Optional

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_COLS: Final[int] = 80
DEFAULT_ROWS: Final[int] = 66

DEFAULT_CELL_WIDTH: Final[int] = 60  # dots (ESC/P units)
DEFAULT_CELL_HEIGHT: Final[int] = 60  # dots (ESC/P units)

MIN_ZOOM: Final[float] = 0.5
MAX_ZOOM: Final[float] = 2.0
DEFAULT_ZOOM: Final[float] = 1.0

MM_TO_PIXELS: Final[float] = 10.0  # approximate scale for screen display

GRID_COLOR: Final[str] = "#d0d0d0"
GRID_COLOR_MAJOR: Final[str] = "#a0a0a0"
GRID_MAJOR_INTERVAL: Final[int] = 10

BACKGROUND_COLOR: Final[str] = "#ffffff"
MARGIN_COLOR: Final[str] = "#ffeeee"

FIELD_FILL: Final[str] = "#e8f4f8"
FIELD_BORDER: Final[str] = "#2980b9"
FIELD_BORDER_WIDTH: Final[int] = 1
FIELD_SELECTED_BORDER: Final[str] = "#e74c3c"
FIELD_SELECTED_WIDTH: Final[int] = 2

OVERLAP_PREVIEW_FILL: Final[str] = "#ffcccc"
OVERLAP_PREVIEW_BORDER: Final[str] = "#ff0000"
OVERLAP_PREVIEW_WIDTH: Final[int] = 2

ERROR_OUTLINE_COLOR: Final[str] = "#e74c3c"
ERROR_OUTLINE_WIDTH: Final[int] = 2


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class FieldPosition:
    """Позиция поля на Canvas.

    Attributes:
        col: Колонка (0-based).
        row: Строка (0-based).
        width: Ширина в ячейках.
        height: Высота в ячейках.
    """

    col: int
    row: int
    width: int
    height: int


@dataclass
class FormFieldWidget:
    """Виджет поля формы.

    Attributes:
        field_id: Уникальный идентификатор поля.
        field_def: Определение поля.
        position: Позиция на Canvas.
        selected: Флаг выделения.
    """

    field_id: str
    field_def: Any
    position: FieldPosition
    selected: bool = False

    def get_bounds(
        self,
        cell_width: int,
        cell_height: int,
    ) -> tuple[int, int, int, int]:
        """Возвращает границы поля в пикселях.

        Args:
            cell_width: Ширина ячейки в пикселях.
            cell_height: Высота ячейки в пикселях.

        Returns:
            Кортеж (x1, y1, x2, y2) в пикселях.
        """
        x1 = self.position.col * cell_width
        y1 = self.position.row * cell_height
        x2 = (self.position.col + self.position.width) * cell_width
        y2 = (self.position.row + self.position.height) * cell_height
        return (x1, y1, x2, y2)


# =============================================================================
# FORM CANVAS
# =============================================================================


class FormCanvas:
    """Canvas для размещения полей формы.

    Реализует ESC/P сетку 80×66 с поддержкой зума,
    snap-to-grid, overlap detection и визуализацией margin.

    Attributes:
        MIN_ZOOM: Минимальный уровень масштабирования.
        MAX_ZOOM: Максимальный уровень масштабирования.
    """

    MIN_ZOOM: Final[float] = MIN_ZOOM
    MAX_ZOOM: Final[float] = MAX_ZOOM

    def __init__(
        self,
        widget_id: str,
        profile: Any = None,
        zoom: float = DEFAULT_ZOOM,
        show_grid: bool = True,
        show_margins: bool = True,
        snap_to_grid: bool = True,
        controller: Any = None,
        on_field_select: Any = None,
    ) -> None:
        """Инициализация FormCanvas.

        Args:
            widget_id: Уникальный идентификатор виджета.
            profile: Профиль бумаги (duck-typed).
            zoom: Уровень масштабирования (0.5 - 2.0).
            show_grid: Показывать сетку.
            show_margins: Показывать поля.
            snap_to_grid: Привязка к сетке.
            controller: Контроллер (опционально).
            on_field_select: Callback при выборе поля.
        """
        self._widget_id = widget_id
        self._profile = profile
        self._zoom = self._clamp_zoom(zoom)
        self._show_grid = show_grid
        self._show_margins = show_margins
        self._snap_to_grid = snap_to_grid
        self._controller = controller
        self._on_field_select = on_field_select

        self._tk_widget: Optional[tk.Canvas] = None
        self._is_mounted: bool = False

        self._fields: dict[str, FormFieldWidget] = {}
        self._field_widgets: dict[str, Any] = {}
        self._selected_field_id: Optional[str] = None

        self._drag_overlap_item: Optional[int] = None
        self._error_items: dict[str, int] = {}
        self._field_rect_items: dict[str, int] = {}
        self._grid_items: list[int] = []
        self._margin_items: list[int] = []

        self._cols: int = 0
        self._rows: int = 0
        self._cell_width: int = 0
        self._cell_height: int = 0
        self._canvas_width: int = 0
        self._canvas_height: int = 0
        self._left_margin_px: int = 0
        self._right_margin_px: int = 0
        self._top_margin_px: int = 0
        self._bottom_margin_px: int = 0

        self._recalculate_grid()

    def _clamp_zoom(self, zoom: float) -> float:
        """Ограничивает zoom допустимыми пределами.

        Args:
            zoom: Желаемый уровень масштабирования.

        Returns:
            Ограниченное значение zoom.
        """
        return max(MIN_ZOOM, min(MAX_ZOOM, zoom))

    def _recalculate_grid(self) -> None:
        """Пересчитывает параметры сетки на основе профиля и zoom."""
        profile = self._profile

        if profile is not None and hasattr(profile, "width_mm"):
            width_mm = float(profile.width_mm)
            height_mm = float(profile.height_mm)
        else:
            width_mm = 210.0
            height_mm = 297.0

        # Calculate cols/rows based on profile dimensions
        # Use default 80×66 as base, scaled proportionally
        base_cols = DEFAULT_COLS
        base_rows = DEFAULT_ROWS
        base_width_mm = 210.0
        base_height_mm = 297.0

        self._cols = max(1, int(base_cols * (width_mm / base_width_mm)))
        self._rows = max(1, int(base_rows * (height_mm / base_height_mm)))

        # Ensure reasonable bounds
        self._cols = max(DEFAULT_COLS, self._cols)
        self._rows = max(DEFAULT_ROWS, self._rows)

        self._cell_width = int(DEFAULT_CELL_WIDTH * self._zoom)
        self._cell_height = int(DEFAULT_CELL_HEIGHT * self._zoom)
        self._canvas_width = self._cols * self._cell_width
        self._canvas_height = self._rows * self._cell_height

        # Margins in pixels
        if profile is not None:
            left_mm = getattr(profile, "left_margin_mm", 13.0)
            right_mm = getattr(profile, "right_margin_mm", 13.0)
            top_mm = getattr(profile, "top_margin_mm", 4.2)
            bottom_mm = getattr(profile, "bottom_margin_mm", 4.2)
        else:
            left_mm = 13.0
            right_mm = 13.0
            top_mm = 4.2
            bottom_mm = 4.2

        self._left_margin_px = int(left_mm * MM_TO_PIXELS * self._zoom)
        self._right_margin_px = int(right_mm * MM_TO_PIXELS * self._zoom)
        self._top_margin_px = int(top_mm * MM_TO_PIXELS * self._zoom)
        self._bottom_margin_px = int(bottom_mm * MM_TO_PIXELS * self._zoom)

    def _redraw(self) -> None:
        """Перерисовывает Canvas (сетка, margins, поля)."""
        if self._tk_widget is None:
            return

        self._clear_canvas_items()
        self._draw_background()
        if self._show_margins:
            self._draw_margins()
        if self._show_grid:
            self._draw_grid()
        self._redraw_fields()

    def _clear_canvas_items(self) -> None:
        """Удаляет все динамические элементы с Canvas."""
        if self._tk_widget is None:
            return

        for item_id in self._grid_items:
            self._tk_widget.delete(item_id)
        self._grid_items.clear()

        for item_id in self._margin_items:
            self._tk_widget.delete(item_id)
        self._margin_items.clear()

        for item_id in self._error_items.values():
            self._tk_widget.delete(item_id)
        self._error_items.clear()

        if self._drag_overlap_item is not None:
            self._tk_widget.delete(self._drag_overlap_item)
            self._drag_overlap_item = None

    def _draw_background(self) -> None:
        """Рисует фон Canvas."""
        if self._tk_widget is None:
            return
        self._tk_widget.configure(
            width=self._canvas_width,
            height=self._canvas_height,
            bg=BACKGROUND_COLOR,
        )

    def _draw_grid(self) -> None:
        """Рисует сетку на Canvas."""
        if self._tk_widget is None:
            return

        # Vertical lines
        for col in range(self._cols + 1):
            x = col * self._cell_width
            color = GRID_COLOR_MAJOR if col % GRID_MAJOR_INTERVAL == 0 else GRID_COLOR
            item_id = self._tk_widget.create_line(
                x,
                0,
                x,
                self._canvas_height,
                fill=color,
                width=1,
            )
            self._grid_items.append(item_id)

        # Horizontal lines
        for row in range(self._rows + 1):
            y = row * self._cell_height
            color = GRID_COLOR_MAJOR if row % GRID_MAJOR_INTERVAL == 0 else GRID_COLOR
            item_id = self._tk_widget.create_line(
                0,
                y,
                self._canvas_width,
                y,
                fill=color,
                width=1,
            )
            self._grid_items.append(item_id)

    def _draw_margins(self) -> None:
        """Рисует визуализацию margin на Canvas."""
        if self._tk_widget is None:
            return

        # Left margin
        if self._left_margin_px > 0:
            item_id = self._tk_widget.create_rectangle(
                0,
                0,
                self._left_margin_px,
                self._canvas_height,
                fill=MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(item_id)

        # Right margin
        if self._right_margin_px > 0:
            item_id = self._tk_widget.create_rectangle(
                self._canvas_width - self._right_margin_px,
                0,
                self._canvas_width,
                self._canvas_height,
                fill=MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(item_id)

        # Top margin
        if self._top_margin_px > 0:
            item_id = self._tk_widget.create_rectangle(
                0,
                0,
                self._canvas_width,
                self._top_margin_px,
                fill=MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(item_id)

        # Bottom margin
        if self._bottom_margin_px > 0:
            item_id = self._tk_widget.create_rectangle(
                0,
                self._canvas_height - self._bottom_margin_px,
                self._canvas_width,
                self._canvas_height,
                fill=MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(item_id)

    def _redraw_fields(self) -> None:
        """Перерисовывает все поля на Canvas."""
        for field_id in list(self._field_rect_items.keys()):
            if self._tk_widget is not None:
                self._tk_widget.delete(self._field_rect_items[field_id])
            del self._field_rect_items[field_id]

        for field_widget in self._fields.values():
            self._draw_field(field_widget)

    def _draw_field(self, field_widget: FormFieldWidget) -> None:
        """Рисует одно поле на Canvas.

        Args:
            field_widget: Виджет поля для отрисовки.
        """
        if self._tk_widget is None:
            return

        x1, y1, x2, y2 = field_widget.get_bounds(
            self._cell_width,
            self._cell_height,
        )

        border_color = FIELD_SELECTED_BORDER if field_widget.selected else FIELD_BORDER
        border_width = FIELD_SELECTED_WIDTH if field_widget.selected else FIELD_BORDER_WIDTH

        rect_id = self._tk_widget.create_rectangle(
            x1,
            y1,
            x2,
            y2,
            fill=FIELD_FILL,
            outline=border_color,
            width=border_width,
            tags=(f"field_{field_widget.field_id}",),
        )
        self._field_rect_items[field_widget.field_id] = rect_id

    # ==========================================================================
    # LIFECYCLE
    # ==========================================================================

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует Canvas в родительский виджет.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный tk.Canvas виджет.

        Raises:
            ValueError: Если parent is None.
            LifecycleError: Если уже смонтирован.
        """
        if parent is None:
            raise ValueError("parent не может быть None")
        if self._is_mounted and self._tk_widget is not None:
            return self._tk_widget

        self._tk_widget = tk.Canvas(
            parent,
            width=self._canvas_width,
            height=self._canvas_height,
            bg=BACKGROUND_COLOR,
            highlightthickness=0,
        )
        self._is_mounted = True
        self._redraw()
        return self._tk_widget

    def unmount(self) -> None:
        """Размонтирует Canvas и освобождает ресурсы."""
        if self._tk_widget is not None:
            self._tk_widget.destroy()
            self._tk_widget = None
        self._is_mounted = False
        self._fields.clear()
        self._field_widgets.clear()
        self._selected_field_id = None
        self._field_rect_items.clear()
        self._error_items.clear()
        self._grid_items.clear()
        self._margin_items.clear()
        if self._drag_overlap_item is not None:
            self._drag_overlap_item = None

    # ==========================================================================
    # ZOOM
    # ==========================================================================

    def zoom_in(self) -> None:
        """Увеличивает масштаб на один шаг."""
        self.set_zoom(self._zoom + 0.1)

    def zoom_out(self) -> None:
        """Уменьшает масштаб на один шаг."""
        self.set_zoom(self._zoom - 0.1)

    def set_zoom(self, zoom: float) -> None:
        """Устанавливает уровень масштабирования.

        Args:
            zoom: Новый уровень масштабирования.
        """
        old_zoom = self._zoom
        self._zoom = self._clamp_zoom(zoom)
        if self._zoom != old_zoom:
            self._recalculate_grid()
            self._redraw()

    # ==========================================================================
    # VISUALIZATION
    # ==========================================================================

    def show_grid(self, show: bool) -> None:
        """Переключает отображение сетки.

        Args:
            show: True для отображения сетки.
        """
        self._show_grid = show
        self._redraw()

    def show_margins(self, show: bool) -> None:
        """Переключает отображение полей.

        Args:
            show: True для отображения полей.
        """
        self._show_margins = show
        self._redraw()

    def set_snap_to_grid(self, enabled: bool) -> None:
        """Переключает привязку к сетке.

        Args:
            enabled: True для включения привязки.
        """
        self._snap_to_grid = enabled

    # ==========================================================================
    # PROFILE
    # ==========================================================================

    def set_profile(self, profile: Any) -> None:
        """Устанавливает новый профиль бумаги.

        Args:
            profile: Новый профиль бумаги.
        """
        self._profile = profile
        self._recalculate_grid()
        self._redraw()

    # ==========================================================================
    # FIELD MANAGEMENT
    # ==========================================================================

    def create_field(
        self,
        field_def: Any,
        x: int,
        y: int,
        width: int = 1,
        height: int = 1,
    ) -> FormFieldWidget:
        """Создаёт поле на Canvas.

        Args:
            field_def: Определение поля.
            x: Колонка (0-based).
            y: Строка (0-based).
            width: Ширина в ячейках.
            height: Высота в ячейках.

        Returns:
            Созданный виджет поля.
        """
        field_id = getattr(field_def, "field_id", str(id(field_def)))
        position = FieldPosition(col=x, row=y, width=width, height=height)
        field_widget = FormFieldWidget(
            field_id=field_id,
            field_def=field_def,
            position=position,
        )
        self._fields[field_id] = field_widget
        self._draw_field(field_widget)
        return field_widget

    def remove_field(self, field_id: str) -> bool:
        """Удаляет поле с Canvas.

        Args:
            field_id: ID поля для удаления.

        Returns:
            True если поле было удалено.
        """
        if field_id not in self._fields:
            return False

        del self._fields[field_id]
        if field_id in self._field_widgets:
            del self._field_widgets[field_id]

        if field_id == self._selected_field_id:
            self._selected_field_id = None

        if field_id in self._field_rect_items and self._tk_widget is not None:
            self._tk_widget.delete(self._field_rect_items[field_id])
            del self._field_rect_items[field_id]

        if field_id in self._error_items and self._tk_widget is not None:
            self._tk_widget.delete(self._error_items[field_id])
            del self._error_items[field_id]

        return True

    def move_field(self, field_id: str, new_x: int, new_y: int) -> bool:
        """Перемещает поле на новую позицию.

        Args:
            field_id: ID поля.
            new_x: Новая колонка.
            new_y: Новая строка.

        Returns:
            True если перемещение выполнено.
        """
        if field_id not in self._fields:
            return False

        field_widget = self._fields[field_id]
        width = field_widget.position.width
        height = field_widget.position.height

        is_valid, _ = self.validate_field_position(
            field_id,
            new_x,
            new_y,
            width,
            height,
        )
        if not is_valid:
            return False

        field_widget.position = FieldPosition(
            col=new_x,
            row=new_y,
            width=field_widget.position.width,
            height=field_widget.position.height,
        )
        self._redraw_fields()
        return True

    def select_field(self, field_id: Optional[str]) -> None:
        """Выделяет поле на Canvas.

        Args:
            field_id: ID поля для выделения.
        """
        # Deselect previous
        if self._selected_field_id is not None:
            prev = self._fields.get(self._selected_field_id)
            if prev is not None:
                prev.selected = False

        self._selected_field_id = field_id
        if field_id is not None:
            current = self._fields.get(field_id)
            if current is not None:
                current.selected = True
        else:
            current = None

        self._redraw_fields()

        if self._on_field_select is not None:
            try:
                self._on_field_select(current)
            except Exception:
                logger.debug("Field select callback failed", exc_info=True)

    def get_field_at(self, col: int, row: int) -> Optional[FormFieldWidget]:
        """Возвращает поле по координатам сетки.

        Args:
            col: Колонка.
            row: Строка.

        Returns:
            Виджет поля или None.
        """
        for field_widget in self._fields.values():
            pos = field_widget.position
            if pos.col <= col < pos.col + pos.width and pos.row <= row < pos.row + pos.height:
                return field_widget
        return None

    def get_fields(self) -> dict[str, FormFieldWidget]:
        """Возвращает копию словаря полей.

        Returns:
            Копия словаря полей.
        """
        return dict(self._fields)

    def clear_fields(self) -> None:
        """Очищает все поля с Canvas."""
        self._fields.clear()
        self._field_widgets.clear()
        self._selected_field_id = None
        self._field_rect_items.clear()
        self._error_items.clear()
        self._redraw()

    # ==========================================================================
    # WIDGET MANAGEMENT (for StructuredFormRenderer)
    # ==========================================================================

    def get_field_widgets(self) -> dict[str, Any]:
        """Возвращает словарь виджетов полей.

        Returns:
            Словарь field_id -> widget.
        """
        return dict(self._field_widgets)

    def set_field_widget(self, field_id: str, widget: Any) -> None:
        """Устанавливает виджет для поля.

        Args:
            field_id: ID поля.
            widget: Виджет.
        """
        self._field_widgets[field_id] = widget

    def remove_field_widget(self, field_id: str) -> None:
        """Удаляет виджет поля.

        Args:
            field_id: ID поля.
        """
        self._field_widgets.pop(field_id, None)

    # ==========================================================================
    # VALIDATION
    # ==========================================================================

    def validate_field_position(
        self,
        field_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> tuple[bool, str]:
        """Валидирует позицию поля.

        Args:
            field_id: ID поля (для исключения self-overlap).
            x: Колонка.
            y: Строка.
            width: Ширина в ячейках.
            height: Высота в ячейках.

        Returns:
            Кортеж (is_valid, error_code).
        """
        if x < 0 or y < 0 or width <= 0 or height <= 0:
            return (False, "out_of_bounds")

        if x + width > self._cols or y + height > self._rows:
            return (False, "out_of_bounds")

        # Margin check
        left_margin_cols = self._left_margin_px // self._cell_width if self._cell_width > 0 else 0
        right_margin_cols = self._right_margin_px // self._cell_width if self._cell_width > 0 else 0
        top_margin_rows = self._top_margin_px // self._cell_height if self._cell_height > 0 else 0
        bottom_margin_rows = (
            self._bottom_margin_px // self._cell_height if self._cell_height > 0 else 0
        )

        if x < left_margin_cols or x + width > self._cols - right_margin_cols:
            return (False, "in_margin")

        if y < top_margin_rows or y + height > self._rows - bottom_margin_rows:
            return (False, "in_margin")

        # Overlap check
        if self.check_overlap(field_id, x, y, width, height):
            return (False, "overlap")

        return (True, "")

    def check_overlap(
        self,
        field_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> bool:
        """Проверяет перекрытие с другими полями.

        Args:
            field_id: ID поля (исключается из проверки).
            x: Колонка.
            y: Строка.
            width: Ширина.
            height: Высота.

        Returns:
            True если есть перекрытие.
        """
        for existing_id, existing in self._fields.items():
            if existing_id == field_id:
                continue
            pos = existing.position
            # Check for actual overlap (not just touching)
            if (
                x < pos.col + pos.width
                and x + width > pos.col
                and y < pos.row + pos.height
                and y + height > pos.row
            ):
                return True
        return False

    # ==========================================================================
    # COORDINATE CONVERSION
    # ==========================================================================

    def _grid_to_pixel(self, col: int, row: int) -> tuple[int, int]:
        """Конвертирует координаты сетки в пиксели.

        Args:
            col: Колонка.
            row: Строка.

        Returns:
            Кортеж (x, y) в пикселях.
        """
        return (col * self._cell_width, row * self._cell_height)

    def _pixel_to_grid(self, x: int, y: int) -> tuple[int, int]:
        """Конвертирует пиксели в координаты сетки.

        Args:
            x: X в пикселях.
            y: Y в пикселях.

        Returns:
            Кортеж (col, row).
        """
        col = x // self._cell_width if self._cell_width > 0 else 0
        row = y // self._cell_height if self._cell_height > 0 else 0
        return (col, row)

    def get_printable_bounds(self) -> tuple[int, int, int, int]:
        """Возвращает границы печатной области в ячейках.

        Returns:
            Кортеж (left, top, right, bottom).
        """
        left = self._left_margin_px // self._cell_width if self._cell_width > 0 else 0
        top = self._top_margin_px // self._cell_height if self._cell_height > 0 else 0
        right = self._cols - (
            self._right_margin_px // self._cell_width if self._cell_width > 0 else 0
        )
        bottom = self._rows - (
            self._bottom_margin_px // self._cell_height if self._cell_height > 0 else 0
        )

        left = max(0, left)
        top = max(0, top)
        right = max(left, right)
        bottom = max(top, bottom)

        return (left, top, right, bottom)

    # ==========================================================================
    # OVERLAP PREVIEW
    # ==========================================================================

    def set_overlap_preview(
        self,
        field_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
        show: bool,
    ) -> None:
        """Показывает или скрывает preview перекрытия.

        Args:
            field_id: ID поля.
            x: Колонка.
            y: Строка.
            width: Ширина.
            height: Высота.
            show: True для показа, False для скрытия.
        """
        if self._tk_widget is None:
            return

        if not show:
            self.clear_overlap_preview()
            return

        self.clear_overlap_preview()

        x1 = x * self._cell_width
        y1 = y * self._cell_height
        x2 = (x + width) * self._cell_width
        y2 = (y + height) * self._cell_height

        self._drag_overlap_item = self._tk_widget.create_rectangle(
            x1,
            y1,
            x2,
            y2,
            fill=OVERLAP_PREVIEW_FILL,
            outline=OVERLAP_PREVIEW_BORDER,
            width=OVERLAP_PREVIEW_WIDTH,
            stipple="gray50",
        )

    def clear_overlap_preview(self) -> None:
        """Очищает preview перекрытия."""
        if self._tk_widget is not None and self._drag_overlap_item is not None:
            self._tk_widget.delete(self._drag_overlap_item)
        self._drag_overlap_item = None

    # ==========================================================================
    # ERROR HIGHLIGHTING
    # ==========================================================================

    def highlight_field_error(self, field_id: str, message: str) -> bool:
        """Подсвечивает поле с ошибкой.

        Args:
            field_id: ID поля.
            message: Сообщение об ошибке (не отображается на Canvas).

        Returns:
            True если поле найдено и подсвечено.
        """
        if self._tk_widget is None:
            return False
        if field_id not in self._fields:
            return False

        # Remove existing error highlight
        if field_id in self._error_items:
            self._tk_widget.delete(self._error_items[field_id])
            del self._error_items[field_id]

        field_widget = self._fields[field_id]
        x1, y1, x2, y2 = field_widget.get_bounds(
            self._cell_width,
            self._cell_height,
        )

        # Draw error outline slightly larger than field
        pad = 2
        item_id = self._tk_widget.create_rectangle(
            x1 - pad,
            y1 - pad,
            x2 + pad,
            y2 + pad,
            outline=ERROR_OUTLINE_COLOR,
            width=ERROR_OUTLINE_WIDTH,
            tags=(f"error_{field_id}",),
        )
        self._error_items[field_id] = item_id
        return True

    def clear_all_errors(self) -> None:
        """Убирает подсветку ошибок со всех полей."""
        if self._tk_widget is None:
            return

        for item_id in self._error_items.values():
            self._tk_widget.delete(item_id)
        self._error_items.clear()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "DEFAULT_CELL_HEIGHT",
    "DEFAULT_CELL_WIDTH",
    "DEFAULT_COLS",
    "DEFAULT_ROWS",
    "FieldPosition",
    "FormCanvas",
    "FormFieldWidget",
    "MAX_ZOOM",
    "MIN_ZOOM",
]
