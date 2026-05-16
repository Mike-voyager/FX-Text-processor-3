"""ESCP Grid Canvas для Form Designer.

Модуль предоставляет ESCPGridCanvas — специализированный Canvas для
визуального проектирования форм с жёсткой сеткой ESC/P 80×66.

Features:
- Strict ESC/P grid: 80 columns × 66 rows
- Snap-to-grid positioning
- Zoom support (0.5x - 2.0x)
- Toggleable grid lines
- Coordinate conversion utilities
- Field overlap detection с визуальным feedback
- Drag/resize полей с rollback при перекрытии

Example:
    >>> from src.gui.form_designer.grid_canvas import ESCPGridCanvas
    >>> import tkinter as tk
    >>> root = tk.Tk()
    >>> canvas = ESCPGridCanvas(root, zoom=1.0, show_grid=True)
    >>> canvas.pack()
    >>> col, row = canvas.snap_to_grid(150, 200)
    >>> print(f"Snapped to: col={col}, row={row}")

Version: 2.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox
from typing import Any, Final, Optional, cast

# Direct import to avoid circular dependencies through layout/__init__.py
try:
    from src.gui.layout.layout_constants import ESCP_COLS, ESCP_ROWS
except ImportError:
    # Fallback constants if layout module has import issues
    ESCP_COLS = 80  # type: ignore[misc]
    ESCP_ROWS = 66  # type: ignore[misc]

# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_CELL_WIDTH: Final[int] = 60  # dots (ESC/P units)
DEFAULT_CELL_HEIGHT: Final[int] = 60  # dots (ESC/P units)

MIN_ZOOM: Final[float] = 0.5
MAX_ZOOM: Final[float] = 2.0
DEFAULT_ZOOM: Final[float] = 1.0

GRID_COLOR: Final[str] = "#d0d0d0"
GRID_COLOR_MAJOR: Final[str] = "#a0a0a0"  # Every 10 lines
GRID_MAJOR_INTERVAL: Final[int] = 10

BACKGROUND_COLOR: Final[str] = "#ffffff"

# Field styling
FIELD_FILL: Final[str] = "#e8f4f8"
FIELD_BORDER: Final[str] = "#2980b9"
FIELD_BORDER_WIDTH: Final[int] = 1
FIELD_OVERLAP_BORDER: Final[str] = "red"
FIELD_OVERLAP_WIDTH: Final[int] = 3


# =============================================================================
# FIELD INFO
# =============================================================================


class FieldInfo:
    """Информация о размещённом поле на Canvas.

    Attributes:
        field_id: Уникальный идентификатор поля.
        rect_id: ID прямоугольника на Canvas.
        x1: Левая граница в пикселях.
        y1: Верхняя граница в пикселях.
        x2: Правая граница в пикселях.
        y2: Нижняя граница в пикселях.
    """

    def __init__(
        self,
        field_id: str,
        rect_id: int,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
    ) -> None:
        self.field_id = field_id
        self.rect_id = rect_id
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2


# =============================================================================
# ESCP GRID CANVAS
# =============================================================================


class ESCPGridCanvas(tk.Canvas):
    """Canvas с жёсткой ESC/P сеткой 80×66 для Form Designer.

    Реализует strict grid для Epson FX-890 с возможностью
    snap-to-grid позиционирования, масштабирования и
    drag/resize полей с проверкой перекрытий.

    Attributes:
        cols: Количество колонок сетки (80).
        rows: Количество строк сетки (66).
        cell_width: Базовая ширина ячейки в пикселях.
        cell_height: Базовая высота ячейки в пикселях.
        zoom: Текущий масштаб (0.5 - 2.0).
        show_grid: Флаг отображения сетки.
    """

    def __init__(
        self,
        master: Optional[tk.Widget] = None,
        *,
        zoom: float = DEFAULT_ZOOM,
        show_grid: bool = True,
        cell_width: int = DEFAULT_CELL_WIDTH,
        cell_height: int = DEFAULT_CELL_HEIGHT,
        **kwargs: Any,
    ) -> None:
        """Инициализация ESCPGridCanvas.

        Args:
            master: Родительский виджет.
            zoom: Начальный масштаб (0.5 - 2.0).
            show_grid: Показывать сетку по умолчанию.
            cell_width: Ширина ячейки в пикселях (при zoom=1.0).
            cell_height: Высота ячейки в пикселях (при zoom=1.0).
            **kwargs: Дополнительные параметры для tk.Canvas.

        Raises:
            ValueError: Если zoom вне диапазона или cell размеры <= 0.
        """
        # Validate parameters
        if not MIN_ZOOM <= zoom <= MAX_ZOOM:
            raise ValueError(
                f"zoom должен быть в диапазоне [{MIN_ZOOM}, {MAX_ZOOM}], получен {zoom}"
            )
        if cell_width <= 0:
            raise ValueError(f"cell_width должен быть > 0, получен {cell_width}")
        if cell_height <= 0:
            raise ValueError(f"cell_height должен быть > 0, получен {cell_height}")

        # Grid dimensions (constants from layout_constants)
        self._cols: int = ESCP_COLS
        self._rows: int = ESCP_ROWS

        # Base cell size (at zoom=1.0)
        self._base_cell_width: int = cell_width
        self._base_cell_height: int = cell_height

        # Current zoom level
        self._zoom: float = zoom

        # Grid visibility
        self._show_grid: bool = show_grid

        # Calculate current cell size with zoom
        self._cell_width: int = int(self._base_cell_width * self._zoom)
        self._cell_height: int = int(self._base_cell_height * self._zoom)

        # Calculate canvas size
        canvas_width: int = self._cols * self._cell_width
        canvas_height: int = self._rows * self._cell_height

        # Initialize tk.Canvas with calculated dimensions
        super().__init__(
            master,
            width=canvas_width,
            height=canvas_height,
            bg=BACKGROUND_COLOR,
            highlightthickness=1,
            highlightbackground=GRID_COLOR_MAJOR,
            **kwargs,
        )

        # Grid line item IDs (for toggle visibility)
        self._grid_items: list[int] = []

        # Field management
        self._fields: dict[str, FieldInfo] = {}
        self._item_to_field: dict[int, str] = {}

        # Drag / resize state
        self._drag_data: Optional[dict[str, Any]] = None
        self._last_valid_position: Optional[tuple[int, int, int, int]] = None
        self._resize_mode: bool = False

        # Warning label (placed above canvas via place)
        self._warning_label: Optional[tk.Label] = None

        # Bind drag/resize events at canvas level
        self.bind("<Button-1>", self._on_drag_start)
        self.bind("<B1-Motion>", self._on_drag_motion)
        self.bind("<ButtonRelease-1>", self._on_drag_release)

        # Draw initial grid
        if self._show_grid:
            self._draw_grid()

    # =====================================================================
    # GRID
    # =====================================================================

    def _draw_grid(self) -> None:
        """Отрисовывает линии сетки.

        Рисует вертикальные и горизонтальные линии сетки
        с учётом текущего масштаба.
        """
        # Clear existing grid lines
        for item_id in self._grid_items:
            self.delete(item_id)
        self._grid_items.clear()

        if not self._show_grid:
            return

        # Draw vertical lines
        for col in range(self._cols + 1):
            x: int = col * self._cell_width
            is_major: bool = col % GRID_MAJOR_INTERVAL == 0
            color: str = GRID_COLOR_MAJOR if is_major else GRID_COLOR
            v_line_id: int = self.create_line(
                x,
                0,
                x,
                self._rows * self._cell_height,
                fill=color,
                width=1,
            )
            self._grid_items.append(v_line_id)

        # Draw horizontal lines
        for row in range(self._rows + 1):
            y: int = row * self._cell_height
            is_major = row % GRID_MAJOR_INTERVAL == 0
            color = GRID_COLOR_MAJOR if is_major else GRID_COLOR
            h_line_id: int = self.create_line(
                0,
                y,
                self._cols * self._cell_width,
                y,
                fill=color,
                width=1,
            )
            self._grid_items.append(h_line_id)

    def snap_to_grid(self, x: int, y: int) -> tuple[int, int]:
        """Привязывает пиксельные координаты к сетке.

        Args:
            x: X координата в пикселях.
            y: Y координата в пикселях.

        Returns:
            Кортеж (col, row) — координаты сетки (0-based).
            Возвращает ближайшие допустимые значения, если координаты
            выходят за границы canvas.
        """
        col: int = round(x / self._cell_width)
        row: int = round(y / self._cell_height)

        # Clamp to grid bounds
        col = max(0, min(col, self._cols - 1))
        row = max(0, min(row, self._rows - 1))

        return (col, row)

    def col_to_x(self, col: int) -> int:
        """Конвертирует колонку сетки в X координату.

        Args:
            col: Номер колонки (0-based).

        Returns:
            X координата в пикселях (левый край колонки).

        Raises:
            ValueError: Если col вне допустимого диапазона.
        """
        if not 0 <= col <= self._cols:
            raise ValueError(f"col должен быть в диапазоне [0, {self._cols}], получен {col}")
        return col * self._cell_width

    def row_to_y(self, row: int) -> int:
        """Конвертирует строку сетки в Y координату.

        Args:
            row: Номер строки (0-based).

        Returns:
            Y координата в пикселях (верхний край строки).

        Raises:
            ValueError: Если row вне допустимого диапазона.
        """
        if not 0 <= row <= self._rows:
            raise ValueError(f"row должен быть в диапазоне [0, {self._rows}], получен {row}")
        return row * self._cell_height

    def x_to_col(self, x: int) -> int:
        """Конвертирует X координату в колонку сетки.

        Args:
            x: X координата в пикселях.

        Returns:
            Номер колонки (0-based), clamped к границам сетки.
        """
        col: int = x // self._cell_width
        return max(0, min(col, self._cols - 1))

    def y_to_row(self, y: int) -> int:
        """Конвертирует Y координату в строку сетки.

        Args:
            y: Y координата в пикселях.

        Returns:
            Номер строки (0-based), clamped к границам сетки.
        """
        row: int = y // self._cell_height
        return max(0, min(row, self._rows - 1))

    def set_zoom(self, zoom: float) -> None:
        """Устанавливает масштаб canvas.

        Args:
            zoom: Новый масштаб (0.5 - 2.0).

        Raises:
            ValueError: Если zoom вне допустимого диапазона.
        """
        if not MIN_ZOOM <= zoom <= MAX_ZOOM:
            raise ValueError(
                f"zoom должен быть в диапазоне [{MIN_ZOOM}, {MAX_ZOOM}], получен {zoom}"
            )

        self._zoom = zoom

        # Recalculate cell sizes
        self._cell_width = int(self._base_cell_width * self._zoom)
        self._cell_height = int(self._base_cell_height * self._zoom)

        # Resize canvas
        new_width: int = self._cols * self._cell_width
        new_height: int = self._rows * self._cell_height
        self.config(width=new_width, height=new_height)

        # Redraw grid with new dimensions
        self._draw_grid()

        # Redraw all fields at snapped positions
        self._redraw_all_fields()

    def toggle_grid(self, show: bool) -> None:
        """Показывает или скрывает сетку.

        Args:
            show: True для показа сетки, False для скрытия.
        """
        self._show_grid = show
        self._draw_grid()

    def get_grid_size(self) -> tuple[int, int]:
        """Возвращает размер ячейки сетки.

        Returns:
            Кортеж (cell_width, cell_height) в пикселях
            с учётом текущего масштаба.
        """
        return (self._cell_width, self._cell_height)

    def get_grid_dimensions(self) -> tuple[int, int]:
        """Возвращает размеры сетки.

        Returns:
            Кортеж (cols, rows) — количество колонок и строк.
        """
        return (self._cols, self._rows)

    def get_zoom(self) -> float:
        """Возвращает текущий масштаб.

        Returns:
            Текущий zoom level (0.5 - 2.0).
        """
        return self._zoom

    def is_grid_visible(self) -> bool:
        """Проверяет видимость сетки.

        Returns:
            True если сетка отображается.
        """
        return self._show_grid

    def get_bounds(self) -> tuple[int, int, int, int]:
        """Возвращает границы canvas в пикселях.

        Returns:
            Кортеж (width, height, cols, rows) — размеры canvas
            и количество ячеек.
        """
        width: int = self._cols * self._cell_width
        height: int = self._rows * self._cell_height
        return (width, height, self._cols, self._rows)

    # =====================================================================
    # FIELD MANAGEMENT
    # =====================================================================

    def add_field(
        self,
        field_id: str,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
    ) -> None:
        """Добавляет поле на Canvas.

        Args:
            field_id: Уникальный идентификатор поля.
            x1: Левая граница в пикселях.
            y1: Верхняя граница в пикселях.
            x2: Правая граница в пикселях.
            y2: Нижняя граница в пикселях.
        """
        rect_id: int = self.create_rectangle(
            x1,
            y1,
            x2,
            y2,
            fill=FIELD_FILL,
            outline=FIELD_BORDER,
            width=FIELD_BORDER_WIDTH,
            tags=("field", field_id),
        )
        info = FieldInfo(
            field_id=field_id,
            rect_id=rect_id,
            x1=x1,
            y1=y1,
            x2=x2,
            y2=y2,
        )
        self._fields[field_id] = info
        self._item_to_field[rect_id] = field_id

    def remove_field(self, field_id: str) -> None:
        """Удаляет поле с Canvas.

        Args:
            field_id: ID поля для удаления.
        """
        info = self._fields.pop(field_id, None)
        if info is None:
            return
        self.delete(info.rect_id)
        self._item_to_field.pop(info.rect_id, None)
        if self._drag_data is not None and self._drag_data.get("field_id") == field_id:
            self._drag_data = None

    def move_field(
        self,
        field_id: str,
        new_x1: int,
        new_y1: int,
        new_x2: int,
        new_y2: int,
    ) -> bool:
        """Перемещает поле с проверкой перекрытий.

        Args:
            field_id: ID поля.
            new_x1: Новая левая граница.
            new_y1: Новая верхняя граница.
            new_x2: Новая правая граница.
            new_y2: Новая нижняя граница.

        Returns:
            True если перемещение выполнено без перекрытий.
        """
        info = self._fields.get(field_id)
        if info is None:
            return False

        overlaps = self._check_overlap(field_id, new_x1, new_y1, new_x2, new_y2)
        if overlaps:
            return False

        self.coords(info.rect_id, new_x1, new_y1, new_x2, new_y2)
        info.x1 = new_x1
        info.y1 = new_y1
        info.x2 = new_x2
        info.y2 = new_y2
        return True

    def resize_field(
        self,
        field_id: str,
        new_x2: int,
        new_y2: int,
    ) -> bool:
        """Изменяет размер поля (нижний-правый угол).

        Args:
            field_id: ID поля.
            new_x2: Новая правая граница.
            new_y2: Новая нижняя граница.

        Returns:
            True если ресайз выполнен без перекрытий.
        """
        info = self._fields.get(field_id)
        if info is None:
            return False

        overlaps = self._check_overlap(field_id, info.x1, info.y1, new_x2, new_y2)
        if overlaps:
            return False

        self.coords(info.rect_id, info.x1, info.y1, new_x2, new_y2)
        info.x2 = new_x2
        info.y2 = new_y2
        return True

    def _redraw_all_fields(self) -> None:
        """Перерисовывает все поля после изменения масштаба."""
        for info in list(self._fields.values()):
            # Snap to new grid size
            col1, row1 = self.snap_to_grid(info.x1, info.y1)
            col2, row2 = self.snap_to_grid(info.x2, info.y2)
            info.x1 = self.col_to_x(col1)
            info.y1 = self.row_to_y(row1)
            # Ensure at least 1 cell size
            if col2 <= col1:
                col2 = col1 + 1
            if row2 <= row1:
                row2 = row1 + 1
            info.x2 = self.col_to_x(col2)
            info.y2 = self.row_to_y(row2)
            self.coords(info.rect_id, info.x1, info.y1, info.x2, info.y2)

    # =====================================================================
    # OVERLAP DETECTION
    # =====================================================================

    def _check_overlap(
        self,
        field_id: str,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
    ) -> list[str]:
        """Проверяет пересечение bbox с другими полями.

        Использует ручную проверку rects_overlap (без find_overlapping)
        для совместимости с любыми Canvas-реализациями.

        Args:
            field_id: ID перемещаемого поля (исключается из проверки).
            x1: Левая граница bbox.
            y1: Верхняя граница bbox.
            x2: Правая граница bbox.
            y2: Нижняя граница bbox.

        Returns:
            Список field_id конфликтующих полей.
        """
        overlapping: list[str] = []
        for other_id, other in self._fields.items():
            if other_id == field_id:
                continue
            # Нет пересечения если один прямоугольник полностью слева,
            # справа, выше или ниже другого
            if x2 <= other.x1 or x1 >= other.x2 or y2 <= other.y1 or y1 >= other.y2:
                continue
            overlapping.append(other_id)
        return overlapping

    # =====================================================================
    # DRAG / RESIZE HANDLERS
    # =====================================================================

    def _on_drag_start(self, event: tk.Event[Any]) -> None:
        """Обработчик нажатия кнопки мыши для начала drag/resize.

        Args:
            event: Событие мыши.
        """
        item = self.find_withtag("current")
        if not item:
            return
        rect_id: int = item[0]
        field_id: Optional[str] = self._item_to_field.get(rect_id)
        if field_id is None:
            return

        info = self._fields[field_id]
        self._drag_data = {
            "field_id": field_id,
            "rect_id": rect_id,
            "start_x": event.x,
            "start_y": event.y,
            "start_x1": info.x1,
            "start_y1": info.y1,
            "start_x2": info.x2,
            "start_y2": info.y2,
        }
        self._last_valid_position = (info.x1, info.y1, info.x2, info.y2)
        # Ctrl — режим resize
        state: int = cast(int, event.state)
        self._resize_mode = (state & 0x4) != 0

    def _on_drag_motion(self, event: tk.Event[Any]) -> None:
        """Обработчик движения мыши с зажатой кнопкой.

        При обнаружении перекрытия показывает красный outline
        и предупреждающий Label. Snap-to-grid применяется
        к новым координатам.

        Args:
            event: Событие мыши.
        """
        if self._drag_data is None:
            return

        field_id: str = self._drag_data["field_id"]
        rect_id: int = self._drag_data["rect_id"]
        dx: int = event.x - self._drag_data["start_x"]
        dy: int = event.y - self._drag_data["start_y"]

        if self._resize_mode:
            new_x1: int = self._drag_data["start_x1"]
            new_y1: int = self._drag_data["start_y1"]
            new_x2: int = self._drag_data["start_x2"] + dx
            new_y2: int = self._drag_data["start_y2"] + dy
        else:
            new_x1 = self._drag_data["start_x1"] + dx
            new_y1 = self._drag_data["start_y1"] + dy
            new_x2 = self._drag_data["start_x2"] + dx
            new_y2 = self._drag_data["start_y2"] + dy

        # Snap-to-grid: привязываем верхний-левый угол
        snap_col, snap_row = self.snap_to_grid(new_x1, new_y1)
        snapped_x1 = self.col_to_x(snap_col)
        snapped_y1 = self.row_to_y(snap_row)
        delta_x = snapped_x1 - self._drag_data["start_x1"]
        delta_y = snapped_y1 - self._drag_data["start_y1"]

        if self._resize_mode:
            # Для resize привязываем нижний-правый угол
            snap_col2, snap_row2 = self.snap_to_grid(new_x2, new_y2)
            snapped_x2 = self.col_to_x(snap_col2)
            snapped_y2 = self.row_to_y(snap_row2)
            # Минимум 1 ячейка
            cw, ch = self.get_grid_size()
            if snapped_x2 - snapped_x1 < cw:
                snapped_x2 = snapped_x1 + cw
            if snapped_y2 - snapped_y1 < ch:
                snapped_y2 = snapped_y1 + ch
            new_x1, new_y1, new_x2, new_y2 = snapped_x1, snapped_y1, snapped_x2, snapped_y2
        else:
            # Для drag применяем snap-delta к обеим координатам
            new_x1 = self._drag_data["start_x1"] + delta_x
            new_y1 = self._drag_data["start_y1"] + delta_y
            new_x2 = self._drag_data["start_x2"] + delta_x
            new_y2 = self._drag_data["start_y2"] + delta_y

        # Обновляем координаты на Canvas
        self.coords(rect_id, new_x1, new_y1, new_x2, new_y2)

        overlaps = self._check_overlap(field_id, new_x1, new_y1, new_x2, new_y2)
        if overlaps:
            self.itemconfig(
                rect_id,
                outline=FIELD_OVERLAP_BORDER,
                width=FIELD_OVERLAP_WIDTH,
            )
            self._show_warning()
        else:
            self.itemconfig(
                rect_id,
                outline=FIELD_BORDER,
                width=FIELD_BORDER_WIDTH,
            )
            self._hide_warning()
            self._last_valid_position = (new_x1, new_y1, new_x2, new_y2)

    def _on_drag_release(self, event: tk.Event[Any]) -> None:
        """Обработчик отпускания кнопки мыши.

        При обнаружении перекрытия откатывает позицию к последней
        валидной и показывает messagebox.showwarning.

        Args:
            event: Событие мыши.
        """
        _ = event  # unused
        if self._drag_data is None:
            return

        field_id: str = self._drag_data["field_id"]
        rect_id: int = self._drag_data["rect_id"]

        # Получаем текущие координаты
        current = self.coords(rect_id)
        if not current:
            self._drag_data = None
            self._resize_mode = False
            self._last_valid_position = None
            self._hide_warning()
            return

        cx1 = int(current[0])
        cy1 = int(current[1])
        cx2 = int(current[2])
        cy2 = int(current[3])

        overlaps = self._check_overlap(field_id, cx1, cy1, cx2, cy2)
        if overlaps:
            # Откат к последней валидной позиции
            if self._last_valid_position is not None:
                self.coords(rect_id, *self._last_valid_position)
                info = self._fields[field_id]
                info.x1, info.y1, info.x2, info.y2 = self._last_valid_position
                self.itemconfig(
                    rect_id,
                    outline=FIELD_BORDER,
                    width=FIELD_BORDER_WIDTH,
                )
            self._hide_warning()
            overlap_names = ", ".join(overlaps)
            messagebox.showwarning(
                "Перекрытие полей",
                (
                    f"Поле '{field_id}' перекрывается с: {overlap_names}.\n"
                    f"Позиция откачена к последней валидной."
                ),
            )
        else:
            # Фиксируем новую позицию
            info = self._fields[field_id]
            info.x1, info.y1, info.x2, info.y2 = cx1, cy1, cx2, cy2

        self._drag_data = None
        self._resize_mode = False
        self._last_valid_position = None

    # =====================================================================
    # WARNING LABEL
    # =====================================================================

    def _show_warning(self) -> None:
        """Показывает предупреждающий Label над Canvas."""
        if self._warning_label is None:
            self._warning_label = tk.Label(
                self,
                text="⚠ Fields overlap",
                fg="red",
                bg="yellow",
                font=("Arial", 10, "bold"),
            )
        self._warning_label.place(x=10, y=10, anchor="nw")

    def _hide_warning(self) -> None:
        """Скрывает предупреждающий Label."""
        if self._warning_label is not None:
            self._warning_label.place_forget()


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "ESCPGridCanvas",
    "FieldInfo",
    "DEFAULT_CELL_WIDTH",
    "DEFAULT_CELL_HEIGHT",
    "MIN_ZOOM",
    "MAX_ZOOM",
    "DEFAULT_ZOOM",
]
