"""Canvas с динамической сеткой для форм.

Модуль предоставляет FormCanvas — виджет для визуального редактирования
полей форм с динамической сеткой на основе PaperProfile.

Features:
- Dynamic grid based on PaperProfile (cols/rows)
- Zoom support (0.5x - 2.0x)
- Margin visualization
- Printable area highlighting
- Snap-to-grid (optional)
- Field selection and positioning

Example:
    >>> from src.services.paper_format_service import PaperFormatService
    >>> from src.gui.renderers.form_canvas import FormCanvas
    >>> service = PaperFormatService()
    >>> profile = service.get_default_profile()
    >>> canvas = FormCanvas(
    ...     parent=root,
    ...     profile=profile,
    ...     zoom=1.0,
    ...     show_grid=True,
    ...     show_margins=True,
    ... )
    >>> canvas.mount(root)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass, field
from typing import Any, Callable, Final, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.components.base.widget import BaseWidget
from src.gui.components.tooltip import TooltipManager
from src.gui.core.protocols import ControllerProtocol
from src.services.paper_format_service import PaperProfile

logger: Final = logging.getLogger(__name__)

# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class FieldPosition:
    """Позиция поля на Canvas.

    Attributes:
        col: Колонка (0-based)
        row: Строка (0-based)
        width: Ширина в колонках
        height: Высота в строках
    """

    col: int = 0
    row: int = 0
    width: int = 1
    height: int = 1


@dataclass
class FormFieldWidget:
    """Виджет поля формы на Canvas.

    Attributes:
        field_id: Уникальный идентификатор поля
        field_def: Определение поля
        position: Позиция на Canvas
        canvas_id: ID объекта на Canvas
        selected: Флаг выделения
        canvas_objects: Словарь дополнительных объектов Canvas (highlight, text, error)
    """

    field_id: str
    field_def: FieldDefinition
    position: FieldPosition = field(default_factory=FieldPosition)
    canvas_id: Optional[int] = None
    selected: bool = False
    canvas_objects: dict[str, int] = field(default_factory=dict)

    def get_bounds(self, cell_width: int, cell_height: int) -> tuple[int, int, int, int]:
        """Возвращает границы поля в пикселях.

        Args:
            cell_width: Ширина ячейки в пикселях
            cell_height: Высота ячейки в пикселях

        Returns:
            (x1, y1, x2, y2) координаты
        """
        x1 = self.position.col * cell_width
        y1 = self.position.row * cell_height
        x2 = x1 + self.position.width * cell_width
        y2 = y1 + self.position.height * cell_height
        return (x1, y1, x2, y2)


# =============================================================================
# FORM CANVAS
# =============================================================================


class FormCanvas(BaseWidget):
    """Canvas с динамической сеткой для форм.

    Features:
    - Dynamic grid based on PaperProfile (cols/rows)
    - Zoom support (0.5x - 2.0x)
    - Margin visualization
    - Printable area highlighting
    - Snap-to-grid (optional)
    - Field selection and positioning

    Example:
        >>> canvas = FormCanvas(
        ...     widget_id="form_canvas",
        ...     controller=controller,
        ...     profile=profile,
        ... )
        >>> canvas.mount(parent_frame)
        >>> canvas.create_field(field_def, x=5, y=3)
    """

    # Colors
    GRID_COLOR: Final[str] = "#e0e0e0"
    GRID_COLOR_MAJOR: Final[str] = "#c0c0c0"  # Every 10 cells
    PAGE_BORDER_COLOR: Final[str] = "#000000"
    MARGIN_COLOR: Final[str] = "#ffeeee"  # Light red for margins
    PRINTABLE_AREA_COLOR: Final[str] = "#ffffff"
    SELECTION_COLOR: Final[str] = "#3498db"
    FIELD_FILL_COLOR: Final[str] = "#e8f4f8"
    FIELD_BORDER_COLOR: Final[str] = "#2980b9"
    FIELD_TEXT_COLOR: Final[str] = "#2c3e50"
    FIELD_ERROR_COLOR: Final[str] = "#e74c3c"  # Red border for errors
    FIELD_ERROR_FILL: Final[str] = "#ffebee"  # Light red fill for errors

    # Zoom levels
    MIN_ZOOM: Final[float] = 0.5
    MAX_ZOOM: Final[float] = 2.0
    ZOOM_STEP: Final[float] = 0.1

    # DPI для расчётов
    DPI: Final[int] = 96

    # Grid major line interval
    GRID_MAJOR_INTERVAL: Final[int] = 10

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        profile: Optional[PaperProfile] = None,
        zoom: float = 1.0,
        show_grid: bool = True,
        show_margins: bool = True,
        snap_to_grid: bool = True,
        on_field_select: Optional[Callable[[Optional[str]], None]] = None,
        on_field_move: Optional[Callable[[str, int, int], None]] = None,
    ) -> None:
        """Инициализация FormCanvas.

        Args:
            widget_id: Уникальный идентификатор виджета
            controller: Опциональная ссылка на контроллер для callbacks
            profile: Профиль бумаги (определяет размер сетки)
            zoom: Масштаб (0.5 - 2.0)
            show_grid: Показывать сетку
            show_margins: Показывать области полей
            snap_to_grid: Привязывать к сетке
            on_field_select: Callback выбора поля
            on_field_move: Callback перемещения поля
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._profile: Optional[PaperProfile] = profile
        self._zoom = max(self.MIN_ZOOM, min(self.MAX_ZOOM, zoom))
        self._show_grid = show_grid
        self._show_margins = show_margins
        self._snap_to_grid = snap_to_grid
        self._on_field_select = on_field_select
        self._on_field_move = on_field_move

        # Base cell size (at zoom=1.0)
        self._base_cell_width: int = 12  # pixels
        self._base_cell_height: int = 12

        # Current cell size
        self._cell_width: int = int(self._base_cell_width * self._zoom)
        self._cell_height: int = int(self._base_cell_height * self._zoom)

        # Grid dimensions
        self._cols: int = 80  # Default ESC/P columns
        self._rows: int = 66  # Default ESC/P rows

        # Canvas dimensions
        self._canvas_width: int = self._cols * self._cell_width
        self._canvas_height: int = self._rows * self._cell_height

        # Margins in pixels
        self._left_margin_px: int = 0
        self._right_margin_px: int = 0
        self._top_margin_px: int = 0
        self._bottom_margin_px: int = 0

        # State
        self._fields: dict[str, FormFieldWidget] = {}
        self._selected_field_id: Optional[str] = None
        self._drag_data: Optional[dict[str, Any]] = None

        # Real input widgets storage for value retrieval
        self._field_widgets: dict[str, Any] = {}

        # Error tracking for validation
        self._field_errors: dict[str, str] = {}

        # Canvas item IDs
        self._grid_items: list[int] = []
        self._margin_items: list[int] = []
        self._page_border_id: Optional[int] = None

        # Grid caching for performance optimization
        self._grid_cache_valid: bool = False
        self._cached_grid_params: tuple[int, int, int, int, bool] = (0, 0, 0, 0, False)

        # Field dirty tracking for batch updates
        self._dirty_fields: set[str] = set()

        # Spatial index for O(1) field lookup: dict[(col, row), list[field_id]]
        self._spatial_index: dict[tuple[int, int], list[str]] = {}

        # Tooltip state
        self._tooltip_manager: TooltipManager = TooltipManager.get_instance()
        self._current_hovered_field: Optional[str] = None
        self._tooltip_enabled: bool = True

        # Drag overlap indicator (red outline preview during drag)
        self._drag_overlap_item: Optional[int] = None
        self._is_drag_preview_valid: bool = True

        # Initialize if profile provided
        if profile is not None:
            self._calculate_grid_dimensions()
            self._recalculate_margins()

    def _calculate_grid_dimensions(self) -> None:
        """Вычисляет размеры сетки на основе профиля."""
        if self._profile is None:
            return

        self._cols = self._calculate_cols()
        self._rows = self._calculate_rows()
        self._canvas_width = self._cols * self._cell_width
        self._canvas_height = self._rows * self._cell_height

    def _calculate_cols(self) -> int:
        """Вычисляет количество колонок на основе профиля.

        Returns:
            Количество колонок
        """
        if self._profile is None:
            return 80  # Default

        # Стандартный расчёт: ширина в мм / 2.54 * cpi
        # Используем 10 CPI как базовый
        printable_width_mm = self._profile.get_printable_area().width
        printable_width_inch = printable_width_mm / 25.4
        cols = int(printable_width_inch * 10)
        return max(40, min(cols, 200))  # Clamp between 40 and 200

    def _calculate_rows(self) -> int:
        """Вычисляет количество строк на основе профиля.

        Returns:
            Количество строк
        """
        if self._profile is None:
            return 66  # Default

        # Стандартный расчёт: высота в мм / 2.54 * lpi
        # Используем 6 LPI как базовый
        printable_height_mm = self._profile.get_printable_area().height
        printable_height_inch = printable_height_mm / 25.4
        rows = int(printable_height_inch * 6)
        return max(20, min(rows, 120))  # Clamp between 20 and 120

    def _recalculate_margins(self) -> None:
        """Пересчитывает margins в пикселях."""
        if self._profile is None:
            self._left_margin_px = 0
            self._right_margin_px = 0
            self._top_margin_px = 0
            self._bottom_margin_px = 0
            return

        printable = self._profile.get_printable_area()

        self._left_margin_px = int((printable.x / 25.4) * self.DPI * self._zoom)
        self._right_margin_px = int(
            ((self._profile.width_mm - printable.x - printable.width) / 25.4)
            * self.DPI
            * self._zoom
        )
        self._top_margin_px = int((printable.y / 25.4) * self.DPI * self._zoom)
        self._bottom_margin_px = int(
            ((self._profile.height_mm - printable.y - printable.height) / 25.4)
            * self.DPI
            * self._zoom
        )

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Canvas виджет.

        Args:
            parent: Родительский Tkinter виджет

        Returns:
            Canvas виджет
        """
        canvas = tk.Canvas(
            parent,
            width=self._canvas_width,
            height=self._canvas_height,
            bg=self.PRINTABLE_AREA_COLOR,
            highlightthickness=1,
            highlightbackground=self.PAGE_BORDER_COLOR,
        )
        self._tk_widget = canvas
        return canvas

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Canvas."""
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        # Mouse events
        self._tk_widget.bind("<Button-1>", self._on_canvas_click)
        self._tk_widget.bind("<B1-Motion>", self._on_canvas_drag)
        self._tk_widget.bind("<ButtonRelease-1>", self._on_canvas_release)

        # Tooltip hover events
        self._tk_widget.bind("<Motion>", self._on_canvas_motion)
        self._tk_widget.bind("<Leave>", self._on_canvas_leave)

        # Scroll events for zoom
        self._tk_widget.bind("<Control-MouseWheel>", self._on_mousewheel_zoom)
        self._tk_widget.bind("<Control-Button-4>", self._on_mousewheel_zoom)
        self._tk_widget.bind("<Control-Button-5>", self._on_mousewheel_zoom)

    def set_profile(self, profile: PaperProfile) -> None:
        """Меняет профиль и пересчитывает сетку.

        Args:
            profile: Новый профиль бумаги
        """
        self._profile = profile
        self._calculate_grid_dimensions()
        self._recalculate_margins()
        self._resize_canvas()
        self._redraw_all()

    def set_zoom(self, zoom: float) -> None:
        """Устанавливает масштаб.

        Args:
            zoom: Новый масштаб (0.5 - 2.0)
        """
        zoom = max(self.MIN_ZOOM, min(self.MAX_ZOOM, zoom))
        self._zoom = zoom
        self._cell_width = int(self._base_cell_width * zoom)
        self._cell_height = int(self._base_cell_height * zoom)

        if self._profile is not None:
            self._calculate_grid_dimensions()
            self._recalculate_margins()
            self._resize_canvas()
            self._redraw_all()

    def zoom_in(self) -> None:
        """Увеличивает масштаб."""
        self.set_zoom(self._zoom + self.ZOOM_STEP)

    def zoom_out(self) -> None:
        """Уменьшает масштаб."""
        self.set_zoom(self._zoom - self.ZOOM_STEP)

    def reset_zoom(self) -> None:
        """Сбрасывает масштаб к 1.0."""
        self.set_zoom(1.0)

    def show_grid(self, show: bool = True) -> None:
        """Показывает/скрывает сетку.

        Args:
            show: True для показа сетки
        """
        self._show_grid = show
        self._draw_grid()

    def show_margins(self, show: bool = True) -> None:
        """Показывает/скрывает области полей.

        Args:
            show: True для показа полей
        """
        self._show_margins = show
        self._draw_margins()

    def set_snap_to_grid(self, snap: bool = True) -> None:
        """Включает/выключает привязку к сетке.

        Args:
            snap: True для включения привязки
        """
        self._snap_to_grid = snap

    def create_field(
        self,
        field_def: FieldDefinition,
        x: int,  # col (0-based)
        y: int,  # row (0-based)
        width: int = 1,
        height: int = 1,
    ) -> FormFieldWidget:
        """Создаёт поле на Canvas.

        Args:
            field_def: Определение поля
            x: Колонка (0-based)
            y: Строка (0-based)
            width: Ширина в колонках
            height: Высота в строках

        Returns:
            Созданный виджет поля

        Raises:
            ValueError: Если Canvas не смонтирован
        """
        if not isinstance(self._tk_widget, tk.Canvas):
            raise ValueError("Canvas не смонтирован")

        field_id = field_def.field_id
        position = FieldPosition(col=x, row=y, width=width, height=height)

        field_widget = FormFieldWidget(
            field_id=field_id,
            field_def=field_def,
            position=position,
        )

        self._fields[field_id] = field_widget
        self._update_spatial_index(field_id, new_pos=position)
        self._draw_field(field_widget)

        return field_widget

    def move_field(self, field_id: str, new_x: int, new_y: int) -> bool:
        """Перемещает поле с валидацией и обновлением пространственного индекса.

        Args:
            field_id: ID поля для перемещения
            new_x: Новая колонка
            new_y: Новая строка

        Returns:
            True если перемещение успешно
        """
        if field_id not in self._fields:
            return False

        field_widget = self._fields[field_id]
        old_pos = field_widget.position

        # Validate new position
        is_valid, _ = self.validate_field_position(
            field_id,
            new_x,
            new_y,
            old_pos.width,
            old_pos.height,
        )

        if not is_valid:
            return False

        # Update spatial index
        new_pos = FieldPosition(
            col=new_x,
            row=new_y,
            width=old_pos.width,
            height=old_pos.height,
        )
        self._update_spatial_index(field_id, old_pos=old_pos, new_pos=new_pos)

        # Update position
        field_widget.position = new_pos

        # Redraw field
        self._redraw_field(field_widget)

        # Call callback
        if self._on_field_move is not None:
            self._on_field_move(field_id, new_x, new_y)

        return True

    def remove_field(self, field_id: str) -> bool:
        """Удаляет поле с Canvas.

        Args:
            field_id: ID поля для удаления

        Returns:
            True если удаление успешно
        """
        if field_id not in self._fields:
            return False

        field_widget = self._fields[field_id]

        # Remove from canvas (all objects)
        if isinstance(self._tk_widget, tk.Canvas):
            if hasattr(field_widget, "canvas_objects") and field_widget.canvas_objects:
                for obj_id in field_widget.canvas_objects.values():
                    self._tk_widget.delete(obj_id)
            elif field_widget.canvas_id:
                self._tk_widget.delete(field_widget.canvas_id)

        # Remove from spatial index
        self._update_spatial_index(field_id, old_pos=field_widget.position)

        # Remove from fields dict
        del self._fields[field_id]

        # Remove field widget
        self.remove_field_widget(field_id)

        # Clear selection if this was selected
        if self._selected_field_id == field_id:
            self._selected_field_id = None
            if self._on_field_select is not None:
                self._on_field_select(None)

        return True

    def select_field(self, field_id: Optional[str]) -> None:
        """Выделяет поле (или снимает выделение).

        Args:
            field_id: ID поля для выделения или None для снятия
        """
        # Deselect current
        if self._selected_field_id is not None:
            if self._selected_field_id in self._fields:
                old_field = self._fields[self._selected_field_id]
                old_field.selected = False
                self._redraw_field(old_field)

        # Select new
        self._selected_field_id = field_id

        if field_id is not None and field_id in self._fields:
            new_field = self._fields[field_id]
            new_field.selected = True
            self._redraw_field(new_field)

        # Call callback
        if self._on_field_select is not None:
            self._on_field_select(field_id)

    def get_field_at(self, x: int, y: int) -> Optional[FormFieldWidget]:
        """Возвращает поле по координатам сетки.

        O(1) поиск поля по координатам сетки используя пространственный индекс.

        Args:
            x: Колонка (0-based)
            y: Строка (0-based)

        Returns:
            Поле если найдено, иначе None
        """
        # Get candidates from spatial index
        candidates = self._spatial_index.get((x, y), [])

        # Exact check (handles overlapping fields)
        for field_id in candidates:
            field = self._fields.get(field_id)
            if field:
                pos = field.position
                if pos.col <= x < pos.col + pos.width and pos.row <= y < pos.row + pos.height:
                    return field
        return None

    def validate_field_position(
        self,
        field_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> tuple[bool, str]:
        """Валидирует позицию поля.

        Использует пространственный индекс для O(k) проверки перекрытий
        вместо O(N) линейного поиска.

        Args:
            field_id: ID поля
            x: Колонка
            y: Строка
            width: Ширина в колонках
            height: Высота в строках

        Returns:
            (is_valid, error_message)
            error_message: "ok", "out_of_bounds", "in_margin", "overlap"
        """
        # Bounds check (O(1))
        if x < 0 or y < 0 or x + width > self._cols or y + height > self._rows:
            return (False, "out_of_bounds")

        # Check margins (convert pixel margins to grid coordinates)
        left_margin_cols = self._left_margin_px // self._cell_width
        right_margin_cols = self._right_margin_px // self._cell_width
        top_margin_rows = self._top_margin_px // self._cell_height
        bottom_margin_rows = self._bottom_margin_px // self._cell_height

        printable_left = left_margin_cols
        printable_right = self._cols - right_margin_cols
        printable_top = top_margin_rows
        printable_bottom = self._rows - bottom_margin_rows

        if (
            x < printable_left
            or x + width > printable_right
            or y < printable_top
            or y + height > printable_bottom
        ):
            return (False, "in_margin")

        # Overlap check using spatial index (O(k), k = fields in area)
        new_pos = FieldPosition(col=x, row=y, width=width, height=height)
        cells_to_check = self._get_covered_cells(new_pos)

        checked: set[str] = set()
        for cell in cells_to_check:
            for other_id in self._spatial_index.get(cell, []):
                if other_id == field_id or other_id in checked:
                    continue
                checked.add(other_id)
                other = self._fields[other_id]
                if self._fields_overlap_at_position(other, x, y, width, height):
                    return (False, "overlap")

        return (True, "ok")

    def get_printable_bounds(self) -> tuple[int, int, int, int]:
        """Возвращает границы printable area.

        Returns:
            (left, top, right, bottom) координаты в grid cells (0-based)
        """
        left_margin_cols = self._left_margin_px // self._cell_width
        right_margin_cols = self._right_margin_px // self._cell_width
        top_margin_rows = self._top_margin_px // self._cell_height
        bottom_margin_rows = self._bottom_margin_px // self._cell_height

        left = left_margin_cols
        top = top_margin_rows
        right = self._cols - right_margin_cols
        bottom = self._rows - bottom_margin_rows

        return (left, top, right, bottom)

    def _get_covered_cells(self, pos: FieldPosition) -> list[tuple[int, int]]:
        """Возвращает ячейки сетки, покрываемые полем.

        Args:
            pos: Позиция поля

        Returns:
            Список (col, row) кортежей
        """
        cells = []
        for col in range(pos.col, min(pos.col + pos.width, self._cols)):
            for row in range(pos.row, min(pos.row + pos.height, self._rows)):
                cells.append((col, row))
        return cells

    def _fields_overlap_at_position(
        self,
        other: FormFieldWidget,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> bool:
        """Проверяет перекрытие поля с другим полем.

        Args:
            other: Другое поле для проверки перекрытия
            x: Колонка новой позиции
            y: Строка новой позиции
            width: Ширина новой позиции
            height: Высота новой позиции

        Returns:
            True если поля перекрываются
        """
        pos = other.position
        return (
            x < pos.col + pos.width
            and x + width > pos.col
            and y < pos.row + pos.height
            and y + height > pos.row
        )

    def _update_spatial_index(
        self,
        field_id: str,
        old_pos: Optional[FieldPosition] = None,
        new_pos: Optional[FieldPosition] = None,
    ) -> None:
        """Обновляет пространственный индекс при перемещении поля.

        Args:
            field_id: ID поля для обновления
            old_pos: Старая позиция (None для нового поля)
            new_pos: Новая позиция (None для удаления)
        """
        # Remove from old cells
        if old_pos is not None:
            for cell in self._get_covered_cells(old_pos):
                if field_id in self._spatial_index.get(cell, []):
                    self._spatial_index[cell].remove(field_id)
                    if not self._spatial_index[cell]:
                        del self._spatial_index[cell]

        # Add to new cells
        if new_pos is not None:
            for cell in self._get_covered_cells(new_pos):
                if cell not in self._spatial_index:
                    self._spatial_index[cell] = []
                if field_id not in self._spatial_index[cell]:
                    self._spatial_index[cell].append(field_id)

    def _rebuild_spatial_index(self) -> None:
        """Перестраивает пространственный индекс для всех полей.

        Используется при инициализации или восстановлении индекса.
        """
        self._spatial_index.clear()
        for field_id, field_widget in self._fields.items():
            self._update_spatial_index(field_id, new_pos=field_widget.position)

    def _clear_fields(self) -> None:
        """Очищает все поля и пространственный индекс."""
        self._clear_canvas()
        self._fields.clear()
        self._spatial_index.clear()
        self._dirty_fields.clear()

    def _resize_canvas(self) -> None:
        """Изменяет размер Canvas виджета."""
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        self._tk_widget.config(
            width=self._canvas_width,
            height=self._canvas_height,
        )

    def _redraw_all(self) -> None:
        """Перерисовывает всё."""
        self._clear_canvas()
        self._draw_page_border()
        if self._show_margins:
            self._draw_margins()
        if self._show_grid:
            self._draw_grid()
        self._draw_fields()

    def _clear_canvas(self) -> None:
        """Очищает Canvas и сбрасывает кэши."""
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        self._tk_widget.delete("all")
        self._grid_items.clear()
        self._margin_items.clear()
        self._page_border_id = None

        # Reset canvas IDs for fields
        for field_widget in self._fields.values():
            field_widget.canvas_id = None
            if hasattr(field_widget, "canvas_objects"):
                field_widget.canvas_objects.clear()

        # Invalidate caches
        self._grid_cache_valid = False
        self._cached_grid_params = (0, 0, 0, 0, False)
        self._dirty_fields.clear()

    def _draw_grid(self) -> None:
        """Рисует сетку с кэшированием (пропускает если параметры не изменились)."""
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        # Check if cache is valid
        current_params = (
            self._cols,
            self._rows,
            self._cell_width,
            self._cell_height,
            self._show_grid,
        )
        if self._grid_cache_valid and current_params == self._cached_grid_params:
            return  # Nothing changed, use existing grid

        # Clear only if params changed significantly (cols/rows changed)
        if self._cached_grid_params[:2] != current_params[:2]:
            for item_id in self._grid_items:
                self._tk_widget.delete(item_id)
            self._grid_items.clear()

        if not self._show_grid:
            # Update cache even when grid is hidden
            self._cached_grid_params = current_params
            self._grid_cache_valid = True
            return

        # Only create grid if we don't have items (cache miss or cols/rows changed)
        if not self._grid_items:
            self._create_grid_lines()

        # Update cache
        self._cached_grid_params = current_params
        self._grid_cache_valid = True

    def _create_grid_lines(self) -> None:
        """Создаёт линии сетки."""
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        # Draw vertical lines
        for col in range(self._cols + 1):
            x = col * self._cell_width
            color = (
                self.GRID_COLOR_MAJOR if col % self.GRID_MAJOR_INTERVAL == 0 else self.GRID_COLOR
            )
            line_id = self._tk_widget.create_line(
                x,
                0,
                x,
                self._canvas_height,
                fill=color,
                width=1 if col % self.GRID_MAJOR_INTERVAL == 0 else 1,
            )
            self._grid_items.append(line_id)

        # Draw horizontal lines
        for row in range(self._rows + 1):
            y = row * self._cell_height
            color = (
                self.GRID_COLOR_MAJOR if row % self.GRID_MAJOR_INTERVAL == 0 else self.GRID_COLOR
            )
            line_id = self._tk_widget.create_line(
                0,
                y,
                self._canvas_width,
                y,
                fill=color,
                width=1 if row % self.GRID_MAJOR_INTERVAL == 0 else 1,
            )
            self._grid_items.append(line_id)

    def _draw_margins(self) -> None:
        """Рисует области полей (colored background)."""
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        # Clear existing margins
        for item_id in self._margin_items:
            self._tk_widget.delete(item_id)
        self._margin_items.clear()

        if not self._show_margins:
            return

        # Left margin
        if self._left_margin_px > 0:
            rect_id = self._tk_widget.create_rectangle(
                0,
                0,
                self._left_margin_px,
                self._canvas_height,
                fill=self.MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(rect_id)

        # Right margin
        if self._right_margin_px > 0:
            rect_id = self._tk_widget.create_rectangle(
                self._canvas_width - self._right_margin_px,
                0,
                self._canvas_width,
                self._canvas_height,
                fill=self.MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(rect_id)

        # Top margin
        if self._top_margin_px > 0:
            rect_id = self._tk_widget.create_rectangle(
                0,
                0,
                self._canvas_width,
                self._top_margin_px,
                fill=self.MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(rect_id)

        # Bottom margin
        if self._bottom_margin_px > 0:
            rect_id = self._tk_widget.create_rectangle(
                0,
                self._canvas_height - self._bottom_margin_px,
                self._canvas_width,
                self._canvas_height,
                fill=self.MARGIN_COLOR,
                outline="",
            )
            self._margin_items.append(rect_id)

    def _draw_page_border(self) -> None:
        """Рисует границу страницы."""
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        self._page_border_id = self._tk_widget.create_rectangle(
            0,
            0,
            self._canvas_width,
            self._canvas_height,
            outline=self.PAGE_BORDER_COLOR,
            width=2,
        )

    def _draw_fields(self) -> None:
        """Рисует все поля."""
        for field_widget in self._fields.values():
            self._draw_field(field_widget)

    def _draw_field(self, field_widget: FormFieldWidget) -> None:
        """Рисует одно поле с хранением всех canvas IDs для буферизации.

        Args:
            field_widget: Виджет поля для отрисовки
        """
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        x1, y1, x2, y2 = field_widget.get_bounds(self._cell_width, self._cell_height)

        # Check if field has error
        has_error = field_widget.field_id in self._field_errors

        # Initialize canvas_objects storage
        field_widget.canvas_objects = {}

        # Selection highlight
        if field_widget.selected:
            padding = 3
            highlight_color = self.FIELD_ERROR_COLOR if has_error else self.SELECTION_COLOR
            highlight_id = self._tk_widget.create_rectangle(
                x1 - padding,
                y1 - padding,
                x2 + padding,
                y2 + padding,
                outline=highlight_color,
                width=3 if has_error else 2,
            )
            field_widget.canvas_objects["highlight"] = highlight_id

        # Field rectangle
        if has_error:
            fill_color = self.FIELD_ERROR_FILL
            border_color = self.FIELD_ERROR_COLOR
            border_width = 2
        else:
            fill_color = self.FIELD_FILL_COLOR
            if field_widget.selected:
                border_color = self.SELECTION_COLOR
            else:
                border_color = self.FIELD_BORDER_COLOR
            border_width = 2 if field_widget.selected else 1

        rect_id = self._tk_widget.create_rectangle(
            x1,
            y1,
            x2,
            y2,
            fill=fill_color,
            outline=border_color,
            width=border_width,
        )
        field_widget.canvas_id = rect_id
        field_widget.canvas_objects["rect"] = rect_id

        # Field label
        label = field_widget.field_def.label
        text_id = None
        if label:
            # Calculate text position (center)
            text_x = (x1 + x2) // 2
            text_y = (y1 + y2) // 2

            text_color = self.FIELD_ERROR_COLOR if has_error else self.FIELD_TEXT_COLOR
            text_id = self._tk_widget.create_text(
                text_x,
                text_y,
                text=label,
                fill=text_color,
                font=("Arial", max(8, int(10 * self._zoom))),
            )
            field_widget.canvas_objects["text"] = text_id

        # Error indicator (small icon or text)
        error_id = None
        if has_error:
            error_x = x1 + 5
            error_y = y1 + 5
            error_id = self._tk_widget.create_text(
                error_x,
                error_y,
                text="⚠",
                fill=self.FIELD_ERROR_COLOR,
                font=("Arial", max(8, int(8 * self._zoom))),
                anchor=tk.NW,
            )
            field_widget.canvas_objects["error"] = error_id

    def _redraw_field(self, field_widget: FormFieldWidget) -> None:
        """Перерисовывает поле через itemconfig (быстрее чем delete/create).

        Args:
            field_widget: Виджет поля для перерисовки
        """
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        # Calculate new position
        x1, y1, x2, y2 = field_widget.get_bounds(self._cell_width, self._cell_height)

        # Check if field has error
        has_error = field_widget.field_id in self._field_errors

        # If no canvas objects yet, create from scratch
        if not field_widget.canvas_id:
            self._draw_field(field_widget)
            return

        # Update highlight visibility
        if field_widget.selected:
            padding = 3
            highlight_color = self.FIELD_ERROR_COLOR if has_error else self.SELECTION_COLOR
            highlight_width = 3 if has_error else 2

            if (
                hasattr(field_widget, "canvas_objects")
                and "highlight" in field_widget.canvas_objects
            ):
                # Update existing highlight
                highlight_id = field_widget.canvas_objects["highlight"]
                self._tk_widget.coords(
                    highlight_id, x1 - padding, y1 - padding, x2 + padding, y2 + padding
                )
                self._tk_widget.itemconfig(
                    highlight_id, outline=highlight_color, width=highlight_width
                )
            else:
                # Create new highlight
                highlight_id = self._tk_widget.create_rectangle(
                    x1 - padding,
                    y1 - padding,
                    x2 + padding,
                    y2 + padding,
                    outline=highlight_color,
                    width=highlight_width,
                )
                if not hasattr(field_widget, "canvas_objects"):
                    field_widget.canvas_objects = {}
                field_widget.canvas_objects["highlight"] = highlight_id
        else:
            # Remove highlight if not selected
            if (
                hasattr(field_widget, "canvas_objects")
                and "highlight" in field_widget.canvas_objects
            ):
                self._tk_widget.delete(field_widget.canvas_objects["highlight"])
                del field_widget.canvas_objects["highlight"]

        # Update rectangle
        if has_error:
            fill_color = self.FIELD_ERROR_FILL
            border_color = self.FIELD_ERROR_COLOR
            border_width = 2
        else:
            fill_color = self.FIELD_FILL_COLOR
            if field_widget.selected:
                border_color = self.SELECTION_COLOR
            else:
                border_color = self.FIELD_BORDER_COLOR
            border_width = 2 if field_widget.selected else 1

        self._tk_widget.coords(field_widget.canvas_id, x1, y1, x2, y2)
        self._tk_widget.itemconfig(
            field_widget.canvas_id,
            fill=fill_color,
            outline=border_color,
            width=border_width,
        )

        # Update text position and color
        if hasattr(field_widget, "canvas_objects") and "text" in field_widget.canvas_objects:
            text_id = field_widget.canvas_objects["text"]
            text_x = (x1 + x2) // 2
            text_y = (y1 + y2) // 2
            text_color = self.FIELD_ERROR_COLOR if has_error else self.FIELD_TEXT_COLOR
            self._tk_widget.coords(text_id, text_x, text_y)
            self._tk_widget.itemconfig(text_id, fill=text_color)

        # Update error indicator
        if has_error:
            error_x = x1 + 5
            error_y = y1 + 5
            if hasattr(field_widget, "canvas_objects") and "error" in field_widget.canvas_objects:
                error_id = field_widget.canvas_objects["error"]
                self._tk_widget.coords(error_id, error_x, error_y)
            else:
                error_id = self._tk_widget.create_text(
                    error_x,
                    error_y,
                    text="⚠",
                    fill=self.FIELD_ERROR_COLOR,
                    font=("Arial", max(8, int(8 * self._zoom))),
                    anchor=tk.NW,
                )
                field_widget.canvas_objects["error"] = error_id
        else:
            # Remove error indicator
            if hasattr(field_widget, "canvas_objects") and "error" in field_widget.canvas_objects:
                self._tk_widget.delete(field_widget.canvas_objects["error"])
                del field_widget.canvas_objects["error"]

    def invalidate_grid_cache(self) -> None:
        """Сбрасывает кэш сетки (вызывать при изменении размеров)."""
        self._grid_cache_valid = False

    def mark_field_dirty(self, field_id: str) -> None:
        """Помечает поле как требующее перерисовки.

        Args:
            field_id: ID поля для пометки
        """
        self._dirty_fields.add(field_id)

    def flush_field_updates(self) -> None:
        """Перерисовывает только изменённые (dirty) поля."""
        for field_id in self._dirty_fields:
            if field_widget := self._fields.get(field_id):
                self._redraw_field(field_widget)
        self._dirty_fields.clear()

    def invalidate_field_cache(self, field_id: Optional[str] = None) -> None:
        """Сбрасывает кэш поля или всех полей.

        Args:
            field_id: ID поля для сброса кэша, или None для всех полей
        """
        if field_id and field_id in self._fields:
            # Clear canvas_id to force redraw on next _redraw_field
            field_widget = self._fields[field_id]
            field_widget.canvas_id = None
            if hasattr(field_widget, "canvas_objects"):
                field_widget.canvas_objects.clear()
        else:
            # Mark all fields as dirty
            for field_widget in self._fields.values():
                field_widget.canvas_id = None
                if hasattr(field_widget, "canvas_objects"):
                    field_widget.canvas_objects.clear()

    def _on_canvas_click(self, event: tk.Event[Any]) -> None:
        """Обработчик клика на Canvas.

        Args:
            event: Событие клика
        """
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        x = event.x
        y = event.y

        # Convert to grid coordinates
        col, row = self._pixel_to_grid(x, y)

        # Check if clicked on a field
        field = self.get_field_at(col, row)

        if field is not None:
            # Select field
            self.select_field(field.field_id)

            # Start drag
            self._drag_data = {
                "field_id": field.field_id,
                "start_x": x,
                "start_y": y,
                "start_col": field.position.col,
                "start_row": field.position.row,
            }
        else:
            # Deselect
            self.select_field(None)

    def _on_canvas_drag(self, event: tk.Event[Any]) -> None:
        """Обработчик drag поля.

        Args:
            event: Событие drag
        """
        if self._drag_data is None:
            return

        if not isinstance(self._tk_widget, tk.Canvas):
            return

        field_id = self._drag_data["field_id"]
        start_x = self._drag_data["start_x"]
        start_y = self._drag_data["start_y"]
        start_col = self._drag_data["start_col"]
        start_row = self._drag_data["start_row"]

        # Calculate delta in pixels
        dx = event.x - start_x
        dy = event.y - start_y

        # Convert to grid delta
        dcol = dx // self._cell_width
        drow = dy // self._cell_height

        new_col = start_col + dcol
        new_row = start_row + drow

        # Get field to check its size
        field = self._fields.get(field_id)
        if field is None:
            return

        width = field.position.width
        height = field.position.height

        # Check for overlap at new position
        has_overlap = self.check_overlap(field_id, new_col, new_row, width, height)

        # Show/hide overlap preview
        self.set_overlap_preview(field_id, new_col, new_row, width, height, has_overlap)

        # Move field only if no overlap
        if not has_overlap and self.move_field(field_id, new_col, new_row):
            # Update drag data start position
            self._drag_data["start_x"] = event.x
            self._drag_data["start_y"] = event.y
            self._drag_data["start_col"] = new_col
            self._drag_data["start_row"] = new_row

    def _on_canvas_release(self, event: tk.Event[Any]) -> None:
        """Обработчик отпускания кнопки мыши.

        Args:
            event: Событие отпускания
        """
        _ = event  # unused
        self.clear_overlap_preview()
        self._drag_data = None

    def _on_canvas_motion(self, event: tk.Event[Any]) -> None:
        """Обработчик движения мыши для тултипов.

        Args:
            event: Событие движения мыши
        """
        if not self._tooltip_enabled:
            return

        if not isinstance(self._tk_widget, tk.Canvas):
            return

        # Convert to grid coordinates
        col, row = self._pixel_to_grid(event.x, event.y)

        # Find field at this position
        field = self.get_field_at(col, row)

        if field is not None:
            # Check if we're hovering over a new field
            if self._current_hovered_field != field.field_id:
                # Hide previous tooltip
                self._hide_field_tooltip()
                # Show new tooltip
                self._show_field_tooltip(field, event.x_root, event.y_root)
        else:
            # Not over a field, hide tooltip
            if self._current_hovered_field is not None:
                self._hide_field_tooltip()

    def _on_canvas_leave(self, event: tk.Event[Any]) -> None:  # noqa: ARG002
        """Обработчик выхода мыши из Canvas.

        Args:
            event: Событие выхода
        """
        self._hide_field_tooltip()

    def _show_field_tooltip(
        self,
        field: FormFieldWidget,
        screen_x: int,
        screen_y: int,
    ) -> None:
        """Показывает тултип для поля.

        Args:
            field: Поле для отображения информации
            screen_x: X координата на экране
            screen_y: Y координата на экране
        """
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        self._current_hovered_field = field.field_id

        tooltip_text = self._format_field_tooltip(field)

        self._tooltip_manager.show(
            self._tk_widget,
            tooltip_text,
            screen_x,
            screen_y,
            delay_ms=500,
        )

    def _hide_field_tooltip(self) -> None:
        """Скрывает тултип поля."""
        self._current_hovered_field = None
        self._tooltip_manager.hide()

    def _format_field_tooltip(self, field: FormFieldWidget) -> str:
        """Форматирует текст тултипа для поля.

        Args:
            field: Поле для форматирования

        Returns:
            Отформатированный текст тултипа
        """
        pos = field.position
        field_def = field.field_def

        lines = [
            f"📄 Field: {field.field_id}",
            f"Type: {field_def.field_type.name}",
            f"Position: ({pos.col}, {pos.row}) - {pos.width * 12}×{pos.height * 12}px",
        ]

        if field_def.label:
            lines.append(f"Label: {field_def.label}")

        if field_def.required:
            lines.append("Required: Yes")

        return "\n".join(lines)

    def set_tooltip_enabled(self, enabled: bool) -> None:
        """Включает/выключает тултипы полей.

        Args:
            enabled: True для включения тултипов
        """
        self._tooltip_enabled = enabled
        if not enabled:
            self._hide_field_tooltip()

    def is_tooltip_enabled(self) -> bool:
        """Возвращает состояние тултипов.

        Returns:
            True если тултипы включены
        """
        return self._tooltip_enabled

    def check_overlap(
        self,
        field_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> bool:
        """Проверяет перекрытие поля с другими полями.

        Args:
            field_id: ID проверяемого поля (для исключения из проверки).
            x: Колонка позиции.
            y: Строка позиции.
            width: Ширина в колонках.
            height: Высота в строках.

        Returns:
            True если есть перекрытие с другим полем.
        """
        new_pos = FieldPosition(col=x, row=y, width=width, height=height)
        cells_to_check = self._get_covered_cells(new_pos)

        checked: set[str] = set()
        for cell in cells_to_check:
            for other_id in self._spatial_index.get(cell, []):
                if other_id == field_id or other_id in checked:
                    continue
                checked.add(other_id)
                other = self._fields[other_id]
                if self._fields_overlap_at_position(other, x, y, width, height):
                    return True
        return False

    def set_overlap_preview(
        self,
        field_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
        show: bool,
    ) -> None:
        """Показывает/скрывает красную рамку предпросмотра перекрытия.

        Args:
            field_id: ID поля для предпросмотра.
            x: Колонка позиции.
            y: Строка позиции.
            width: Ширина в колонках.
            height: Высота в строках.
            show: True для показа красной рамки, False для скрытия.
        """
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        # Remove existing preview
        if self._drag_overlap_item is not None:
            self._tk_widget.delete(self._drag_overlap_item)
            self._drag_overlap_item = None

        if not show:
            self._hide_overlap_tooltip()
            return

        # Calculate pixel bounds
        x1 = x * self._cell_width
        y1 = y * self._cell_height
        x2 = x1 + width * self._cell_width
        y2 = y1 + height * self._cell_height

        # Create red outline rectangle for overlap preview
        self._drag_overlap_item = self._tk_widget.create_rectangle(
            x1,
            y1,
            x2,
            y2,
            outline="red",
            width=3,
            dash=(4, 4),
        )

        # Show tooltip "Поля перекрываются!"
        self._show_overlap_tooltip(x2, y1)

    def clear_overlap_preview(self) -> None:
        """Убирает красную рамку предпросмотра перекрытия."""
        if self._drag_overlap_item is not None and isinstance(self._tk_widget, tk.Canvas):
            self._tk_widget.delete(self._drag_overlap_item)
            self._drag_overlap_item = None
        self._hide_overlap_tooltip()

    def _show_overlap_tooltip(self, x: int, y: int) -> None:
        """Показывает tooltip о перекрытии полей.

        Args:
            x: X координата (правая граница поля).
            y: Y координата (верхняя граница поля).
        """
        if not isinstance(self._tk_widget, tk.Canvas):
            return

        self._tooltip_manager.show(
            self._tk_widget,
            "⚠️ Поля перекрываются!",
            x,
            y,
            delay_ms=0,
        )

    def _hide_overlap_tooltip(self) -> None:
        """Скрывает tooltip о перекрытии полей."""
        self._tooltip_manager.hide()

    def _on_mousewheel_zoom(self, event: tk.Event[Any]) -> None:
        """Обработчик zoom колесом мыши.

        Args:
            event: Событие колеса мыши
        """
        if event.num == 4 or event.delta > 0:
            self.zoom_in()
        elif event.num == 5 or event.delta < 0:
            self.zoom_out()

    def _grid_to_pixel(self, col: int, row: int) -> tuple[int, int]:
        """Конвертирует координаты сетки в пиксели.

        Args:
            col: Колонка (0-based)
            row: Строка (0-based)

        Returns:
            (x, y) координаты в пикселях
        """
        x = col * self._cell_width
        y = row * self._cell_height
        return (x, y)

    def _pixel_to_grid(self, x: int, y: int) -> tuple[int, int]:
        """Конвертирует пиксели в координаты сетки.

        Args:
            x: X координата в пикселях
            y: Y координата в пикселях

        Returns:
            (col, row) координаты сетки (0-based)
        """
        col = x // self._cell_width
        row = y // self._cell_height

        # Clamp to grid bounds
        col = max(0, min(col, self._cols - 1))
        row = max(0, min(row, self._rows - 1))

        return (col, row)

    def get_fields(self) -> dict[str, FormFieldWidget]:
        """Возвращает все поля.

        Returns:
            Словарь полей
        """
        return dict(self._fields)

    def get_field_widgets(self) -> dict[str, Any]:
        """Возвращает реальные виджеты полей для получения значений.

        Returns:
            Словарь виджетов полей (TextInputWidget и т.д.)
        """
        return dict(self._field_widgets)

    def set_field_widget(self, field_id: str, widget: Any) -> None:
        """Устанавливает реальный виджет поля для value retrieval.

        Args:
            field_id: ID поля.
            widget: Виджет поля (TextInputWidget и т.д.)
        """
        self._field_widgets[field_id] = widget

    def remove_field_widget(self, field_id: str) -> None:
        """Удаляет виджет поля.

        Args:
            field_id: ID поля.
        """
        if field_id in self._field_widgets:
            del self._field_widgets[field_id]

    def get_selected_field(self) -> Optional[FormFieldWidget]:
        """Возвращает выделенное поле.

        Returns:
            Выделенное поле или None
        """
        if self._selected_field_id is None:
            return None
        return self._fields.get(self._selected_field_id)

    def clear_fields(self) -> None:
        """Удаляет все поля и очищает пространственный индекс."""
        field_ids = list(self._fields.keys())
        for field_id in field_ids:
            self.remove_field(field_id)

        # Clear field widgets and spatial index
        self._field_widgets.clear()
        self._spatial_index.clear()

    def highlight_field_error(self, field_id: str, error_msg: str) -> bool:
        """Подсвечивает поле с ошибкой валидации.

        Args:
            field_id: ID поля с ошибкой.
            error_msg: Сообщение об ошибке.

        Returns:
            True если поле найдено и подсвечено.
        """
        if field_id not in self._fields:
            return False

        # Store error message
        self._field_errors[field_id] = error_msg

        # Redraw field with error styling
        field_widget = self._fields[field_id]
        self._redraw_field(field_widget)

        return True

    def clear_field_error(self, field_id: str) -> bool:
        """Убирает подсветку ошибки с поля.

        Args:
            field_id: ID поля.

        Returns:
            True если ошибка была убрана.
        """
        if field_id not in self._field_errors:
            return False

        del self._field_errors[field_id]

        if field_id in self._fields:
            self._redraw_field(self._fields[field_id])

        return True

    def clear_all_errors(self) -> None:
        """Убирает подсветку ошибок со всех полей."""
        error_fields = list(self._field_errors.keys())
        self._field_errors.clear()

        for field_id in error_fields:
            if field_id in self._fields:
                self._redraw_field(self._fields[field_id])

    def get_field_errors(self) -> dict[str, str]:
        """Возвращает словарь ошибок полей.

        Returns:
            Словарь {field_id: error_message}.
        """
        return dict(self._field_errors)

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self._hide_field_tooltip()
        self.clear_fields()
        self._drag_data = None
        self._field_errors.clear()
        super()._cleanup()


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = [
    "FormCanvas",
    "FormFieldWidget",
    "FieldPosition",
]
