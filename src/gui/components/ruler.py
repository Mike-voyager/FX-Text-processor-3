"""Линейка для отображения позиции символов в строке.

Модуль предоставляет горизонтальную линейку с метками, отображающую
положение символов с учётом текущего CPI (Characters Per Inch).

Features:
    - Отображение меток каждые 10 символов
    - Поддержка CPI: 10, 12, 15, 17, 20
    - Кликабельность для позиционирования курсора
    - Автоматическая перерисовка при изменении CPI или ширины
    - Визуальные маркеры табуляторов (LEFT, RIGHT, CENTER, DECIMAL)
    - Drag-and-drop для перемещения табуляторов
    - Двойной клик для добавления табулятора
    - Контекстное меню для изменения типа и удаления

Example:
    >>> ruler = Ruler(
    ...     widget_id="doc_ruler",
    ...     controller=ctrl,
    ...     on_click=lambda pos: print(f"Clicked at char {pos}")
    ... )
    >>> ruler.mount(parent_frame)
    >>> ruler.set_cpi(12)
    >>> ruler.set_width_chars(80)

Version: 2.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.model.tab_stop import TabStop, TabStopType
from src.model.tab_stop_manager import TabStopManager

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

# Допустимые значения CPI
VALID_CPI_VALUES: Final[tuple[int, ...]] = (10, 12, 15, 17, 20)

# Пиксели на символ для каждого CPI (базовая шкала 96 DPI)
# 10 CPI = 9.6 px/char, 12 CPI = 8 px/char, 15 CPI = 6.4 px/char
CPI_TO_PIXELS: Final[dict[int, float]] = {
    10: 9.6,
    12: 8.0,
    15: 6.4,
    17: 5.647,  # ~96/17
    20: 4.8,
}

# Размеры линейки
RULER_HEIGHT: Final[int] = 25
RULER_BG_COLOR: Final[str] = "#f0f0f0"
RULER_FG_COLOR: Final[str] = "#333333"
RULER_TICK_COLOR: Final[str] = "#666666"
RULER_HIGHLIGHT_COLOR: Final[str] = "#0078d4"

# Colorа маркеров табуляторов
TAB_MARKER_COLOR: Final[str] = "#c41e3a"  # Красный для маркеров
TAB_MARKER_ACTIVE_COLOR: Final[str] = "#0078d4"  # Синий для активного
TAB_MARKER_HOVER_COLOR: Final[str] = "#ff6b6b"  # Светло-красный для hover

# Параметры маркеров табуляторов
TAB_MARKER_HEIGHT: Final[int] = 8
TAB_MARKER_WIDTH: Final[int] = 6
TAB_MARKER_Y_OFFSET: Final[int] = 2  # Отступ от верха

# Шаг меток (каждые N символов)
TICK_INTERVAL: Final[int] = 10

# =============================================================================
# RULER
# =============================================================================


class Ruler(BaseWidget):
    """Горизонтальная линейка с метками символов и табуляторами.

    Отображает позиции символов с учётом CPI, позволяет
    кликать для позиционирования курсора, а также управлять
    табуляторами через drag-and-drop.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        on_click: Callback при клике на линейку.
        on_tabs_changed: Callback при изменении табуляторов.
        tab_stop_manager: Менеджер табуляторов документа.

    Example:
        >>> ruler = Ruler(
        ...     widget_id="ruler_main",
        ...     controller=ctrl,
        ...     on_click=lambda pos: controller.goto_char(pos)
        ... )
        >>> ruler.mount(parent)
        >>> ruler.set_cpi(12)
        >>> ruler.set_width_chars(80)
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        on_click: Optional[Callable[[int], None]] = None,
        on_tabs_changed: Optional[Callable[[list[TabStop]], None]] = None,
        tab_stop_manager: Optional[TabStopManager] = None,
        initial_cpi: int = 10,
        initial_width_chars: int = 80,
    ) -> None:
        """Инициализация линейки.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            on_click: Callback при клике на линейку.
                Принимает позицию в символах (int).
            on_tabs_changed: Callback при изменении табуляторов.
                Принимает список TabStop.
            tab_stop_manager: Менеджер табуляторов для синхронизации.
            initial_cpi: Начальное значение CPI (по умолчанию 10).
            initial_width_chars: Начальная ширина в символах (по умолчанию 80).

        Raises:
            ValueError: Если CPI недопустим.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        if initial_cpi not in VALID_CPI_VALUES:
            raise ValueError(f"Invalid CPI value: {initial_cpi}")

        self._on_click = on_click
        self._on_tabs_changed = on_tabs_changed
        self._tab_stop_manager = tab_stop_manager
        self._cpi: int = initial_cpi
        self._width_chars: int = initial_width_chars
        self._char_width_px: float = CPI_TO_PIXELS[initial_cpi]

        # Tkinter widgets
        self._canvas: Optional[tk.Canvas] = None
        self._frame: Optional[tk.Frame] = None

        # Состояние drag-and-drop для табуляторов
        self._drag_tab_stop: Optional[TabStop] = None
        self._drag_start_x: int = 0
        self._drag_current_x: int = 0

        # Словарь для хранения canvas item IDs табуляторов
        # {position: (item_id, tab_stop)}
        self._tab_markers: dict[int, tuple[int, TabStop]] = {}

        # Контекстное меню
        self._context_menu: Optional[tk.Menu] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фрейм с canvas для линейки.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный фрейм с линейкой.
        """
        # Основной фрейм
        self._frame = tk.Frame(parent, height=RULER_HEIGHT)
        self._frame.pack_propagate(False)

        # Canvas для рисования линейки
        self._canvas = tk.Canvas(
            self._frame,
            height=RULER_HEIGHT,
            bg=RULER_BG_COLOR,
            highlightthickness=0,
        )
        self._canvas.pack(fill=tk.X, expand=True)

        # Настраиваем обработку клика
        self._canvas.bind("<Button-1>", self._on_canvas_click)
        self._canvas.bind("<Double-Button-1>", self._on_ruler_double_click)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._canvas.bind("<B1-Motion>", self._on_tab_drag)
        self._canvas.bind("<ButtonRelease-1>", self._end_tab_drag)

        # Создаём контекстное меню
        self._create_context_menu()

        # Первоначальная отрисовка
        self._draw_ruler()

        # Если есть менеджер табуляторов - отрисовываем их
        if self._tab_stop_manager is not None:
            self._draw_tab_markers()

        return self._frame

    def _setup_bindings(self) -> None:
        """Настраивает дополнительные bindings."""
        # Уже настроены в _create_tk_widget
        pass

    def _create_context_menu(self) -> None:
        """Создаёт контекстное меню для табуляторов."""
        if self._canvas is None:
            return

        self._context_menu = tk.Menu(
            self._canvas,
            tearoff=0,
            bg="white",
            fg="black",
            activebackground=RULER_HIGHLIGHT_COLOR,
            activeforeground="white",
        )

    def _draw_ruler(self) -> None:
        """Отрисовывает линейку с метками."""
        if self._canvas is None:
            return

        # Очищаем canvas (кроме маркеров табуляторов, они перерисуются отдельно)
        self._canvas.delete("ruler", "tick", "label")

        # Получаем размеры
        width = self._canvas.winfo_width()
        if width <= 1:
            # Canvas ещё не отрисован, используем расчётную ширину
            width = int(self._width_chars * self._char_width_px)

        # Рисуем базовую линию
        self._canvas.create_line(
            0,
            RULER_HEIGHT - 5,
            width,
            RULER_HEIGHT - 5,
            fill=RULER_TICK_COLOR,
            width=1,
            tags=("ruler",),
        )

        # Рисуем метки
        for char_pos in range(0, self._width_chars + 1, TICK_INTERVAL):
            x = int(char_pos * self._char_width_px)

            if x > width:
                break

            # Длина засечки
            tick_height = 8 if char_pos % 50 == 0 else 5

            # Рисуем засечку
            self._canvas.create_line(
                x,
                RULER_HEIGHT - 5,
                x,
                RULER_HEIGHT - 5 - tick_height,
                fill=RULER_TICK_COLOR,
                width=1,
                tags=("tick",),
            )

            # Подпись для каждых 20 символов или кратных 50
            if char_pos > 0 and (char_pos % 20 == 0 or char_pos % 50 == 0):
                self._canvas.create_text(
                    x + 3,
                    RULER_HEIGHT - 12,
                    text=str(char_pos),
                    anchor=tk.NW,
                    fill=RULER_FG_COLOR,
                    font=("Segoe UI", 8),
                    tags=("label",),
                )

        # Рисуем вертикальную линию для каждого символа (тонкие)
        for char_pos in range(0, self._width_chars + 1):
            x = int(char_pos * self._char_width_px)

            if x > width:
                break

            # Каждый символ — маленькая засечка
            if char_pos % TICK_INTERVAL != 0:
                self._canvas.create_line(
                    x,
                    RULER_HEIGHT - 5,
                    x,
                    RULER_HEIGHT - 7,
                    fill="#cccccc",
                    width=1,
                    tags=("tick",),
                )

    def _draw_tab_markers(self) -> None:
        """Отрисовывает маркеры табуляторов."""
        if self._canvas is None:
            return

        # Удаляем старые маркеры
        self._canvas.delete("tab_marker")
        self._tab_markers.clear()

        # Если нет менеджера табуляторов - выходим
        if self._tab_stop_manager is None:
            return

        # Получаем все табуляторы и рисуем их
        tabs = self._tab_stop_manager.get_tabs()
        for tab in tabs:
            self._create_tab_marker(tab)

    def _create_tab_marker(self, tab: TabStop) -> int:
        """Создаёт визуальный маркер для табулятора.

        Args:
            tab: Табулятор для отрисовки.

        Returns:
            ID созданного canvas item.
        """
        if self._canvas is None:
            return -1

        x = int(tab.position * self._char_width_px)
        y = TAB_MARKER_Y_OFFSET
        height = TAB_MARKER_HEIGHT
        width = TAB_MARKER_WIDTH

        # Создаём маркер в зависимости от типа
        if tab.tab_type == TabStopType.LEFT:
            # Треугольник вправо ▶
            item_id = self._canvas.create_polygon(
                x,
                y + height // 2,
                x - width // 2,
                y,
                x - width // 2,
                y + height,
                fill=TAB_MARKER_COLOR,
                outline="white",
                width=1,
                tags=("tab_marker", f"tab_{tab.position}"),
            )
        elif tab.tab_type == TabStopType.RIGHT:
            # Треугольник влево ◀
            item_id = self._canvas.create_polygon(
                x,
                y + height // 2,
                x + width // 2,
                y,
                x + width // 2,
                y + height,
                fill=TAB_MARKER_COLOR,
                outline="white",
                width=1,
                tags=("tab_marker", f"tab_{tab.position}"),
            )
        elif tab.tab_type == TabStopType.CENTER:
            # Два треугольника ◀▶ (песочные часы)
            item_id = self._canvas.create_polygon(
                x - 2,
                y + height // 2,
                x - width // 2,
                y,
                x - width // 2,
                y + height,
                x,
                y + height // 2,
                x + width // 2,
                y + height,
                x + width // 2,
                y,
                fill=TAB_MARKER_COLOR,
                outline="white",
                width=1,
                tags=("tab_marker", f"tab_{tab.position}"),
            )
        else:  # DECIMAL
            # Треугольник вправо с точкой ▶·
            item_id = self._canvas.create_polygon(
                x,
                y + height // 2,
                x - width // 2,
                y,
                x - width // 2,
                y + height,
                fill=TAB_MARKER_COLOR,
                outline="white",
                width=1,
                tags=("tab_marker", f"tab_{tab.position}"),
            )
            # Добавляем точку
            self._canvas.create_oval(
                x - 1,
                y + height + 1,
                x + 1,
                y + height + 3,
                fill=TAB_MARKER_COLOR,
                outline="",
                tags=("tab_marker", f"tab_{tab.position}"),
            )

        # Привязываем обработчики к маркеру
        def _create_drag_handler(t: TabStop) -> Callable[[tk.Event], None]:
            return lambda e: self._start_tab_drag(e, t)

        def _create_context_handler(t: TabStop) -> Callable[[tk.Event], None]:
            return lambda e: self._show_tab_context_menu(e, t)

        def _create_enter_handler(item: int) -> Callable[[tk.Event], None]:
            return lambda e: self._on_tab_hover_enter(item)

        def _create_leave_handler(item: int) -> Callable[[tk.Event], None]:
            return lambda e: self._on_tab_hover_leave(item)

        self._canvas.tag_bind(
            f"tab_{tab.position}",
            "<Button-1>",
            _create_drag_handler(tab),
        )
        self._canvas.tag_bind(
            f"tab_{tab.position}",
            "<Button-3>",
            _create_context_handler(tab),
        )
        self._canvas.tag_bind(
            f"tab_{tab.position}",
            "<Enter>",
            _create_enter_handler(item_id),
        )
        self._canvas.tag_bind(
            f"tab_{tab.position}",
            "<Leave>",
            _create_leave_handler(item_id),
        )

        # Сохраняем связь позиция -> (item_id, tab)
        self._tab_markers[tab.position] = (item_id, tab)

        return item_id

    def _on_tab_hover_enter(self, item_id: int) -> None:
        """Обрабатывает наведение курсора на маркер табулятора.

        Args:
            item_id: ID canvas item.
        """
        if self._canvas is None:
            return
        # Меняем цвет на hover
        self._canvas.itemconfig(item_id, fill=TAB_MARKER_HOVER_COLOR)

    def _on_tab_hover_leave(self, item_id: int) -> None:
        """Обрабатывает уход курсора с маркера табулятора.

        Args:
            item_id: ID canvas item.
        """
        if self._canvas is None:
            return
        # Возвращаем обычный цвет
        self._canvas.itemconfig(item_id, fill=TAB_MARKER_COLOR)

    def _on_canvas_click(self, event: tk.Event) -> None:
        """Обрабатывает клик на canvas.

        Args:
            event: Событие клика мыши.
        """
        if self._canvas is None:
            return

        # Вычисляем позицию в символах
        x = event.x
        char_position = int(x / self._char_width_px)

        # Ограничиваем допустимым диапазоном
        char_position = max(0, min(char_position, self._width_chars))

        logger.debug("Клик на линейке: x=%d, char_position=%d", x, char_position)

        # Вызываем callback
        if self._on_click is not None:
            try:
                self._on_click(char_position)
            except (TypeError, ValueError) as exc:
                logger.error("Ошибка в callback on_click: %s", exc)

        # Отправляем через контроллер
        if self._controller is not None:
            self._controller.dispatch(
                "ruler_clicked",
                position=char_position,
                cpi=self._cpi,
            )

    def _on_ruler_double_click(self, event: tk.Event) -> None:
        """Обрабатывает двойной клик для добавления табулятора.

        Args:
            event: Событие двойного клика.
        """
        if self._canvas is None or self._tab_stop_manager is None:
            return

        # Вычисляем позицию в символах
        x = event.x
        char_position = int(x / self._char_width_px)

        # Ограничиваем допустимым диапазоном (минимум 1)
        char_position = max(1, min(char_position, self._width_chars))

        # Проверяем, нет ли уже табулятора в этой позиции
        if self._tab_stop_manager.has_tab_at(char_position):
            logger.debug("Табулятор уже существует в позиции %d", char_position)
            return

        # Добавляем табулятор типа LEFT по умолчанию
        tab = self._tab_stop_manager.add_tab(char_position, TabStopType.LEFT)
        if tab is not None:
            logger.debug("Добавлен табулятор: position=%d, type=LEFT", char_position)
            self._create_tab_marker(tab)
            self._notify_tabs_changed()

    def _start_tab_drag(self, event: tk.Event, tab: TabStop) -> None:
        """Начинает перетаскивание табулятора.

        Args:
            event: Событие нажатия кнопки мыши.
            tab: Табулятор для перетаскивания.
        """
        if self._canvas is None:
            return

        # Игнорируем правый клик
        if event.num == 3:
            return

        # Сохраняем данные о перетаскивании
        self._drag_tab_stop = tab
        self._drag_start_x = event.x
        self._drag_current_x = event.x

        # Подсвечиваем маркер
        if tab.position in self._tab_markers:
            item_id, _ = self._tab_markers[tab.position]
            self._canvas.itemconfig(item_id, fill=TAB_MARKER_ACTIVE_COLOR)

        logger.debug("Начато перетаскивание табулятора: position=%d", tab.position)

    def _on_tab_drag(self, event: tk.Event) -> None:
        """Обрабатывает движение мыши при перетаскивании.

        Args:
            event: Событие движения мыши.
        """
        if self._canvas is None or self._drag_tab_stop is None:
            return

        tab = self._drag_tab_stop
        current_x = event.x

        # Вычисляем новую позицию в символах
        new_position = int(current_x / self._char_width_px)
        new_position = max(1, min(new_position, self._width_chars))

        # Обновляем визуальное положение маркера
        if tab.position in self._tab_markers:
            item_id, _ = self._tab_markers[tab.position]
            # Получаем текущие координаты маркера
            coords = self._canvas.coords(item_id)
            if coords:
                # Вычисляем смещение
                old_x = tab.position * self._char_width_px
                new_x = new_position * self._char_width_px
                dx = new_x - old_x

                # Перемещаем маркер
                self._canvas.move(item_id, dx, 0)

                # Если DECIMAL, перемещаем и точку
                if tab.tab_type == TabStopType.DECIMAL:
                    # Находим связанный овал (точка)
                    overlap = self._canvas.find_overlapping(
                        new_x - 5,
                        TAB_MARKER_Y_OFFSET + TAB_MARKER_HEIGHT,
                        new_x + 5,
                        TAB_MARKER_Y_OFFSET + TAB_MARKER_HEIGHT + 5,
                    )
                    for item in overlap:
                        if "tab_marker" in self._canvas.gettags(item) and item != item_id:
                            self._canvas.move(item, dx, 0)
                            break

        self._drag_current_x = current_x

    def _end_tab_drag(self, event: tk.Event) -> None:
        """Завершает перетаскивание табулятора.

        Args:
            event: Событие отпускания кнопки мыши.
        """
        if self._canvas is None or self._tab_stop_manager is None:
            self._reset_drag_state()
            return

        tab = self._drag_tab_stop
        if tab is None:
            return

        # Вычисляем финальную позицию
        final_x = event.x
        new_position = int(final_x / self._char_width_px)
        new_position = max(1, min(new_position, self._width_chars))

        # Если позиция не изменилась - просто сбрасываем состояние
        if new_position == tab.position:
            self._reset_drag_state()
            return

        # Проверяем, не занята ли новая позиция
        if self._tab_stop_manager.has_tab_at(new_position):
            logger.debug("Позиция %d занята, отмена перемещения", new_position)
            # Перерисовываем все табуляторы для возврата к исходному состоянию
            self._draw_tab_markers()
            self._reset_drag_state()
            return

        # Перемещаем табулятор в менеджере
        moved_tab = self._tab_stop_manager.move_tab(tab.position, new_position)
        if moved_tab is not None:
            logger.debug("Табулятор перемещён: %d -> %d", tab.position, new_position)
            # Удаляем старую запись если она есть
            if tab.position in self._tab_markers:
                del self._tab_markers[tab.position]
            self._draw_tab_markers()
            self._notify_tabs_changed()
        else:
            # Перерисовываем если что-то пошло не так
            self._draw_tab_markers()

        self._reset_drag_state()

    def _reset_drag_state(self) -> None:
        """Сбрасывает состояние перетаскивания."""
        # Возвращаем обычный цвет маркерам
        if self._canvas is not None and self._drag_tab_stop is not None:
            tab = self._drag_tab_stop
            if tab.position in self._tab_markers:
                item_id, _ = self._tab_markers[tab.position]
                self._canvas.itemconfig(item_id, fill=TAB_MARKER_COLOR)

        self._drag_tab_stop = None
        self._drag_start_x = 0
        self._drag_current_x = 0

    def _show_tab_context_menu(self, event: tk.Event, tab: TabStop) -> None:
        """Показывает контекстное меню для табулятора.

        Args:
            event: Событие клика правой кнопкой.
            tab: Табулятор для которого показывается меню.
        """
        if self._context_menu is None or self._canvas is None:
            return

        # Очищаем старое меню
        self._context_menu.delete(0, tk.END)

        # Добавляем заголовок
        self._context_menu.add_command(
            label=f"Tab: pos. {tab.position}",
            state=tk.DISABLED,
        )
        self._context_menu.add_separator()

        # Подменю для смены типа
        type_menu = tk.Menu(
            self._context_menu,
            tearoff=0,
            bg="white",
            fg="black",
            activebackground=RULER_HIGHLIGHT_COLOR,
            activeforeground="white",
        )

        for tab_type in TabStopType:

            def _create_type_handler(t: TabStop, tt: TabStopType) -> Callable[[], None]:
                return lambda: self._change_tab_type(t, tt)

            type_menu.add_command(
                label=self._get_tab_type_label(tab_type),
                command=_create_type_handler(tab, tab_type),
            )

        self._context_menu.add_cascade(
            label="Change type",
            menu=type_menu,
        )

        self._context_menu.add_separator()
        self._context_menu.add_command(
            label="Delete",
            command=lambda: self._delete_tab(tab),
        )

        # Показываем меню
        self._context_menu.post(event.x_root, event.y_root)

        # Привязываем закрытие меню
        self._canvas.bind("<Button-1>", lambda e: self._hide_context_menu(), add=True)

    def _hide_context_menu(self) -> None:
        """Скрывает контекстное меню."""
        if self._context_menu is not None:
            self._context_menu.unpost()

    def _get_tab_type_label(self, tab_type: TabStopType) -> str:
        """Возвращает локализованную метку для типа табулятора.

        Args:
            tab_type: Тип табулятора.

        Returns:
            Локализованная строка с символом.
        """
        labels = {
            TabStopType.LEFT: "Левый (▶)",
            TabStopType.RIGHT: "Правый (◀)",
            TabStopType.CENTER: "Центральный (◀▶)",
            TabStopType.DECIMAL: "Десятичный (▶·)",
        }
        return labels.get(tab_type, tab_type.name)

    def _delete_tab(self, tab: TabStop) -> None:
        """Удаляет табулятор.

        Args:
            tab: Табулятор для удаления.
        """
        if self._tab_stop_manager is None:
            return

        success = self._tab_stop_manager.remove_tab(tab.position)
        if success:
            logger.debug("Табулятор удалён: position=%d", tab.position)
            self._draw_tab_markers()
            self._notify_tabs_changed()

    def _change_tab_type(self, tab: TabStop, new_type: TabStopType) -> None:
        """Изменяет тип табулятора.

        Args:
            tab: Табулятор для изменения.
            new_type: Новый тип табулятора.
        """
        if self._tab_stop_manager is None:
            return

        if tab.tab_type == new_type:
            return

        # Удаляем старый табулятор
        self._tab_stop_manager.remove_tab(tab.position)

        # Создаём новый с тем же типом
        new_tab = self._tab_stop_manager.add_tab(tab.position, new_type)
        if new_tab is not None:
            logger.debug(
                "Тип табулятора изменён: position=%d, %s -> %s",
                tab.position,
                tab.tab_type.name,
                new_type.name,
            )
            self._draw_tab_markers()
            self._notify_tabs_changed()

    def _notify_tabs_changed(self) -> None:
        """Уведомляет об изменении табуляторов."""
        if self._tab_stop_manager is None:
            return

        tabs = self._tab_stop_manager.get_tabs()

        # Вызываем callback
        if self._on_tabs_changed is not None:
            try:
                self._on_tabs_changed(tabs)
            except Exception as exc:
                logger.exception("Ошибка в callback on_tabs_changed: %s", exc)

        # Отправляем через контроллер
        if self._controller is not None:
            self._controller.dispatch(
                "tabs_changed",
                tabs=[tab.to_dict() for tab in tabs],
            )

    def _on_canvas_configure(self, event: tk.Event) -> None:
        """Обрабатывает изменение размера canvas.

        Args:
            event: Событие изменения размера.
        """
        # Перерисовываем при изменении размера
        self._draw_ruler()
        self._draw_tab_markers()

    def set_cpi(self, cpi: int) -> None:
        """Устанавливает новый CPI и перерисовывает линейку.

        Args:
            cpi: Новое значение CPI (10, 12, 15, 17, 20).

        Raises:
            ValueError: Если CPI недопустим.

        Example:
            >>> ruler.set_cpi(12)  # Elite
            >>> ruler.set_cpi(15)  # Condensed
        """
        if cpi not in VALID_CPI_VALUES:
            raise ValueError(f"Invalid CPI value: {cpi}")

        if cpi == self._cpi:
            return

        self._cpi = cpi
        self._char_width_px = CPI_TO_PIXELS[cpi]

        logger.debug("Изменён CPI: %d (%.2f px/char)", cpi, self._char_width_px)

        # Перерисовываем если смонтирован
        if self._is_mounted:
            self._draw_ruler()
            self._draw_tab_markers()

        # Уведомляем через контроллер
        if self._controller is not None:
            self._controller.dispatch("ruler_cpi_changed", cpi=cpi)

    def set_width_chars(self, chars: int) -> None:
        """Устанавливает ширину линейки в символах.

        Args:
            chars: Количество символов (обычно 80 или 132).

        Raises:
            ValueError: Если chars <= 0.

        Example:
            >>> ruler.set_width_chars(80)   # Standard
            >>> ruler.set_width_chars(132)  # Wide
        """
        if chars <= 0:
            raise ValueError(f"Width must be positive: {chars}")

        if chars == self._width_chars:
            return

        self._width_chars = chars

        logger.debug("Изменена ширина линейки: %d символов", chars)

        # Перерисовываем если смонтирован
        if self._is_mounted:
            self._draw_ruler()
            self._draw_tab_markers()

    def get_cpi(self) -> int:
        """Возвращает текущий CPI.

        Returns:
            Текущее значение CPI.
        """
        return self._cpi

    def get_width_chars(self) -> int:
        """Возвращает текущую ширину в символах.

        Returns:
            Ширина линейки в символах.
        """
        return self._width_chars

    def get_char_width_pixels(self) -> float:
        """Возвращает ширину символа в пикселях.

        Returns:
            Ширина одного символа в пикселях.
        """
        return self._char_width_px

    def set_tab_stop_manager(
        self,
        tab_stop_manager: Optional[TabStopManager],
    ) -> None:
        """Устанавливает менеджер табуляторов.

        Args:
            tab_stop_manager: Новый менеджер табуляторов или None.
        """
        self._tab_stop_manager = tab_stop_manager

        if self._is_mounted and self._canvas is not None:
            self._draw_tab_markers()

    def get_tab_stop_manager(self) -> Optional[TabStopManager]:
        """Возвращает текущий менеджер табуляторов.

        Returns:
            Текущий TabStopManager или None.
        """
        return self._tab_stop_manager

    def refresh_tabs(self) -> None:
        """Перерисовывает табуляторы.

        Вызывает перерисовку маркеров табуляторов на основе
        текущего состояния TabStopManager.
        """
        if self._is_mounted and self._canvas is not None:
            self._draw_tab_markers()

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._on_click = None
        self._on_tabs_changed = None
        self._canvas = None
        self._frame = None
        self._context_menu = None
        self._tab_markers.clear()
        self._drag_data = {
            "tab_stop": None,
            "drag_id": None,
            "start_x": 0,
            "current_x": 0,
        }


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "Ruler",
    "VALID_CPI_VALUES",
    "CPI_TO_PIXELS",
    "TICK_INTERVAL",
    "RULER_HEIGHT",
    "TAB_MARKER_COLOR",
    "TAB_MARKER_ACTIVE_COLOR",
    "TAB_MARKER_HOVER_COLOR",
]
