"""8 resize handles для выбранного поля на Canvas.

Модуль предоставляет ResizeHandles — 8 точек для изменения размера
поля формы на Canvas с привязкой к сетке.

Features:
- 8 handles: nw, n, ne, e, se, s, sw, w
- Snap-to-grid сразу (без промежуточных позиций)
- Live preview в callback on_resize
- Visual feedback (active color)
- Minimum size: 1×1 cell

Example:
    >>> from src.gui.renderers.form_canvas import FormCanvas
    >>> from src.gui.form_designer.resize_handles import ResizeHandles
    >>> canvas = FormCanvas(...)
    >>> handles = ResizeHandles(
    ...     canvas=canvas,
    ...     on_resize=lambda h, w, h: print(f"Resizing: {w}x{h}"),
    ...     on_resize_end=lambda h, w, h: print(f"Final: {w}x{h}"),
    ... )
    >>> handles.attach(field_widget)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional, Union

if TYPE_CHECKING:
    from src.gui.renderers.form_canvas import FormFieldWidget

# Import FormCanvas at module level for runtime isinstance checks
from src.gui.renderers.form_canvas import FormCanvas

TkEvent = Union[tk.Event, Any]


class ResizeHandles:
    """8 resize handles для выбранного поля на Canvas.

    Attributes:
        HANDLES: Список имён handles (nw, n, ne, e, se, s, sw, w)
        HANDLE_SIZE: Размер handle в пикселях
        HANDLE_COLOR: Color handle
        HANDLE_ACTIVE_COLOR: Color активного handle
        CURSORS: Словарь курсоров для каждого handle
        MIN_SIZE: Минимальный размер в ячейках
    """

    HANDLES: Final[list[str]] = ["nw", "n", "ne", "e", "se", "s", "sw", "w"]
    HANDLE_SIZE: Final[int] = 6  # pixels
    HANDLE_COLOR: Final[str] = "#3498db"  # Blue
    HANDLE_ACTIVE_COLOR: Final[str] = "#2980b9"  # Darker blue
    HANDLE_OUTLINE_COLOR: Final[str] = "white"
    MIN_SIZE: Final[int] = 1  # Minimum size in cells

    CURSORS: Final[dict[str, str]] = {
        "nw": "size_nw_se",
        "n": "size_ns",
        "ne": "size_ne_sw",
        "e": "size_we",
        "se": "size_nw_se",
        "s": "size_ns",
        "sw": "size_ne_sw",
        "w": "size_we",
    }

    def __init__(
        self,
        canvas: tk.Canvas,
        field_id: str,
        on_resize: Optional[Callable[[int, int, int, int], None]] = None,
        on_resize_done: Optional[Callable[[int, int, int, int], None]] = None,
        theme: str = "classic_green",
    ) -> None:
        """Инициализация ResizeHandles.

        Args:
            canvas: Canvas для отрисовки handles
            field_id: ID поля для ресайза
            on_resize: Callback при движении handle (x, y, width, height)
            on_resize_done: Callback при отпускании handle (x, y, width, height)
            theme: Theme цветов
        """
        self._canvas: tk.Canvas = canvas
        self._field_id: str = field_id
        self._on_resize_callback: Optional[Callable[[int, int, int, int], None]] = on_resize
        self._on_resize_done_callback: Optional[Callable[[int, int, int, int], None]] = (
            on_resize_done
        )
        self._theme: str = theme

        self._attached_field: Optional[FormFieldWidget] = None
        self._handles: dict[str, int] = {}  # Canvas item IDs
        self._is_visible: bool = False
        self._is_dragging: bool = False
        self._drag_start: Optional[tuple[int, int]] = None
        self._original_rect: Optional[tuple[int, int, int, int]] = None
        self._active_handle: Optional[str] = None

        # Position and size
        self._x: int = 0
        self._y: int = 0
        self._width: int = 0
        self._height: int = 0

        # Theme colors
        self._colors: dict[str, str] = self._load_theme_colors(theme)

    def _load_theme_colors(self, theme: str) -> dict[str, str]:
        """Загружает цвета темы.

        Args:
            theme: Название темы

        Returns:
            Словарь цветов
        """
        themes: dict[str, dict[str, str]] = {
            "classic_green": {
                "handle": "#3498db",
                "handle_active": "#2980b9",
                "outline": "white",
            },
            "amber": {
                "handle": "#ffb000",
                "handle_active": "#ff8c00",
                "outline": "black",
            },
            "dos_blue": {
                "handle": "#00ffff",
                "handle_active": "#00cccc",
                "outline": "black",
            },
            "paper_white": {
                "handle": "#2c3e50",
                "handle_active": "#1a252f",
                "outline": "white",
            },
            "matrix": {
                "handle": "#00ff00",
                "handle_active": "#00cc00",
                "outline": "black",
            },
        }
        return themes.get(theme, themes["classic_green"])

    def show(self, x: int, y: int, width: int, height: int) -> None:
        """Показывает handles на Canvas.

        Args:
            x: X координата поля в пикселях
            y: Y координата поля в пикселях
            width: Ширина поля в пикселях
            height: Высота поля в пикселях
        """
        # Скрываем предыдущие handles
        self.hide()

        self._x = x
        self._y = y
        self._width = width
        self._height = height
        self._is_visible = True

        # Создаём 8 handles
        self._create_handles()

    def hide(self) -> None:
        """Скрывает все handles с Canvas."""
        # Удаляем все canvas items
        for handle_id in self._handles.values():
            self._canvas.delete(handle_id)
        self._handles.clear()
        self._is_visible = False
        self._is_dragging = False
        self._active_handle = None

    def attach(self, field_widget: FormFieldWidget) -> None:
        """Прикрепляет handles к полю.

        Args:
            field_widget: Виджет поля для прикрепления handles
        """
        # Открепляем от предыдущего поля
        self.hide()

        self._attached_field = field_widget

        # Получаем позицию и размер на Canvas
        canvas = self._canvas
        if isinstance(canvas, FormCanvas):
            x1, y1, x2, y2 = field_widget.get_bounds(canvas._cell_width, canvas._cell_height)
            self.show(x1, y1, x2 - x1, y2 - y1)
        else:
            # Fallback: предполагаем прямые координаты
            x1, y1, x2, y2 = field_widget.get_bounds(12, 12)
            self.show(x1, y1, x2 - x1, y2 - y1)

    def detach(self) -> None:
        """Открепляет handles от поля."""
        self.hide()
        self._attached_field = None

    def is_visible(self) -> bool:
        """Возвращает видимость handles.

        Returns:
            True если handles отображаются
        """
        return self._is_visible

    def _create_handles(self) -> None:
        """Создаёт 8 handles на Canvas."""
        x, y = self._x, self._y
        w, h = self._width, self._height
        cx = x + w // 2  # center x
        cy = y + h // 2  # center y
        right = x + w
        bottom = y + h

        handle_positions: dict[str, tuple[int, int]] = {
            "nw": (x, y),  # Top-left
            "n": (cx, y),  # Top-center
            "ne": (right, y),  # Top-right
            "e": (right, cy),  # Right
            "se": (right, bottom),  # Bottom-right
            "s": (cx, bottom),  # Bottom-center
            "sw": (x, bottom),  # Bottom-left
            "w": (x, cy),  # Left
        }

        for handle_name, (hx, hy) in handle_positions.items():
            self._create_handle(handle_name, hx, hy)

    def _create_handle(self, handle_name: str, x: int, y: int) -> int:
        """Создаёт handle на Canvas.

        Args:
            handle_name: Имя handle (nw, n, ne, и т.д.)
            x: X координата центра handle
            y: Y координата центра handle

        Returns:
            Canvas item ID
        """
        size = self.HANDLE_SIZE
        handle_id = self._canvas.create_rectangle(
            x - size // 2,
            y - size // 2,
            x + size // 2,
            y + size // 2,
            fill=self._colors["handle"],
            outline=self._colors["outline"],
            width=1,
            tags=("resize_handle", f"handle_{handle_name}"),
        )

        # Note: Canvas item cursor not supported in all Tk versions
        # We use canvas-level cursor binding instead

        # Привязываем события
        def on_press(e: TkEvent, h: str = handle_name) -> None:
            self._on_handle_press(h, e)

        def on_drag(e: TkEvent, h: str = handle_name) -> None:
            self._on_handle_drag(h, e)

        def on_release(e: TkEvent) -> None:
            self._on_handle_release(e)

        self._canvas.tag_bind(handle_id, "<Button-1>", on_press)
        self._canvas.tag_bind(handle_id, "<B1-Motion>", on_drag)
        self._canvas.tag_bind(handle_id, "<ButtonRelease-1>", on_release)

        self._handles[handle_name] = handle_id
        return handle_id

    def _on_handle_press(self, handle: str, event: TkEvent) -> None:
        """Обработчик нажатия на handle.

        Args:
            handle: Имя handle
            event: Событие мыши
        """
        self._is_dragging = True
        self._active_handle = handle
        self._drag_start = (int(event.x), int(event.y))
        self._original_rect = (self._x, self._y, self._width, self._height)

        # Подсвечиваем handle
        handle_id = self._handles[handle]
        self._canvas.itemconfig(handle_id, fill=self._colors["handle_active"])

    def _on_handle_drag(self, handle: str, event: TkEvent) -> None:
        """Обработчик движения handle.

        Args:
            handle: Имя handle
            event: Событие мыши
        """
        if not self._is_dragging or self._original_rect is None:
            return

        # Вычисляем delta от начала drag
        drag_start = self._drag_start
        if drag_start is None:
            return
        dx = int(event.x) - drag_start[0]
        dy = int(event.y) - drag_start[1]

        # Вычисляем новую позицию и размер
        result = self._calculate_resize(
            self._original_rect[0],
            self._original_rect[1],
            self._original_rect[2],
            self._original_rect[3],
            dx,
            dy,
            handle,
        )

        new_x, new_y, new_width, new_height = result

        # Обновляем текущие значения
        self._x = new_x
        self._y = new_y
        self._width = new_width
        self._height = new_height

        # Обновляем позицию handles
        self._update_handles_position()

        # Вызываем callback
        if self._on_resize_callback:
            self._on_resize_callback(new_x, new_y, new_width, new_height)

    def _on_handle_release(self, event: TkEvent) -> None:
        """Обработчик отпускания handle.

        Args:
            event: Событие мыши
        """
        if not self._is_dragging or self._active_handle is None:
            return

        # Привязываем к сетке
        canvas = self._canvas
        if isinstance(canvas, FormCanvas):
            cell_w = canvas._cell_width
            cell_h = canvas._cell_height
            grid_x = self._snap_to_grid(self._x, cell_w)
            grid_y = self._snap_to_grid(self._y, cell_h)
            grid_w = max(self.MIN_SIZE * cell_w, self._snap_to_grid(self._width, cell_w))
            grid_h = max(self.MIN_SIZE * cell_h, self._snap_to_grid(self._height, cell_h))
        else:
            # Fallback: snap to 10-pixel grid
            grid_x = self._snap_to_grid(self._x, 10)
            grid_y = self._snap_to_grid(self._y, 10)
            grid_w = max(self.MIN_SIZE * 10, self._snap_to_grid(self._width, 10))
            grid_h = max(self.MIN_SIZE * 10, self._snap_to_grid(self._height, 10))

        # Обновляем позицию
        self._x = grid_x
        self._y = grid_y
        self._width = grid_w
        self._height = grid_h

        # Обновляем отображение
        self._update_handles_position()

        # Вызываем callback
        if self._on_resize_done_callback:
            self._on_resize_done_callback(grid_x, grid_y, grid_w, grid_h)

        # Сбрасываем состояние
        self._is_dragging = False
        self._drag_start = None
        self._original_rect = None

        # Убираем подсветку
        handle_id = self._handles.get(self._active_handle)
        if handle_id:
            self._canvas.itemconfig(handle_id, fill=self._colors["handle"])
        self._active_handle = None

    def _trigger_resize_callback(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> None:
        """Внутренний callback ресайза.

        Args:
            x: Новая X координата
            y: Новая Y координата
            width: Новая ширина
            height: Новая высота
        """
        # Этот метод используется тестами для проверки callback
        if self._on_resize_callback:
            self._on_resize_callback(x, y, width, height)

    def _calculate_resize(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
        dx: int,
        dy: int,
        handle: str,
    ) -> tuple[int, int, int, int]:
        """Вычисляет новую позицию и размер на основе handle и delta.

        Args:
            x: Текущая X координата
            y: Текущая Y координата
            width: Текущая ширина
            height: Текущая высота
            dx: Изменение X
            dy: Изменение Y
            handle: Имя handle

        Returns:
            (new_x, new_y, new_width, new_height)
        """
        new_x = x
        new_y = y
        new_width = width
        new_height = height

        # Corner handles изменяют обе размерности
        if "e" in handle:  # East side
            new_width = width + dx
        elif "w" in handle:  # West side
            new_x = x + dx
            new_width = width - dx

        if "s" in handle:  # South side
            new_height = height + dy
        elif "n" in handle:  # North side
            new_y = y + dy
            new_height = height - dy

        # Гарантируем минимальный размер
        min_w = self.MIN_SIZE * 10
        min_h = self.MIN_SIZE * 10
        # Try to get cell size from canvas if it's a FormCanvas
        try:
            canvas = self._canvas
            if hasattr(canvas, "_cell_width") and hasattr(canvas, "_cell_height"):
                min_w = self.MIN_SIZE * canvas._cell_width
                min_h = self.MIN_SIZE * canvas._cell_height
        except (AttributeError, TypeError):
            pass

        if new_width < min_w:
            if "w" in handle:
                new_x = x + width - min_w
            new_width = min_w

        if new_height < min_h:
            if "n" in handle:
                new_y = y + height - min_h
            new_height = min_h

        return (new_x, new_y, new_width, new_height)

    def _snap_to_grid(self, value: int, cell_size: int) -> int:
        """Привязывает значение к сетке.

        Args:
            value: Значение для привязки
            cell_size: Размер ячейки

        Returns:
            Значение, привязанное к сетке
        """
        return round(value / cell_size) * cell_size

    def _update_handles_position(self) -> None:
        """Обновляет позицию handles на Canvas."""
        if not self._is_visible:
            return

        x, y = self._x, self._y
        w, h = self._width, self._height
        cx = x + w // 2  # center x
        cy = y + h // 2  # center y
        right = x + w
        bottom = y + h

        handle_positions: dict[str, tuple[int, int]] = {
            "nw": (x, y),
            "n": (cx, y),
            "ne": (right, y),
            "e": (right, cy),
            "se": (right, bottom),
            "s": (cx, bottom),
            "sw": (x, bottom),
            "w": (x, cy),
        }

        size = self.HANDLE_SIZE
        for handle_name, (hx, hy) in handle_positions.items():
            handle_id = self._handles.get(handle_name)
            if handle_id:
                self._canvas.coords(
                    handle_id,
                    hx - size // 2,
                    hy - size // 2,
                    hx + size // 2,
                    hy + size // 2,
                )

    def update_position(self, x: int, y: int) -> None:
        """Обновляет позицию handles.

        Args:
            x: Новая X координата
            y: Новая Y координата
        """
        self._x = x
        self._y = y
        self._update_handles_position()

    def update_size(self, width: int, height: int) -> None:
        """Обновляет размер handles.

        Args:
            width: Новая ширина
            height: Новая высота
        """
        self._width = width
        self._height = height
        self._update_handles_position()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "ResizeHandles",
]
