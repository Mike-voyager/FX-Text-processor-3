"""PageSidebar — sidebar с thumbnails страниц формы.

Provides a scrollable sidebar with page thumbnails, drag-drop reorder support,
and context menu for page operations.

Example:
    >>> sidebar = PageSidebar(
    ...     parent=root,
    ...     pages=form_pages,
    ...     on_page_select=select_handler,
    ...     on_page_add=add_handler,
    ...     on_page_remove=remove_handler,
    ... )
    >>> sidebar.mount(parent_frame)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from typing import Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.services.paper_format_service import PaperProfile

# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class SidebarPageInfo:
    """Информация о странице для sidebar.

    Attributes:
        index: Индекс страницы (0-based).
        name: Отображаемое имя.
        profile: Профиль бумаги.
        is_selected: Выбрана ли страница.
    """

    index: int
    name: str
    profile: PaperProfile
    is_selected: bool = False


# =============================================================================
# PAGE SIDEBAR
# =============================================================================


class PageSidebar(BaseWidget):
    """Sidebar с thumbnails страниц формы.

    Features:
    - Scrollable frame with thumbnails
    - Drag-drop support для reorder
    - Context menu per page
    - Visual selection indicator
    - Page count display

    Example:
        >>> sidebar = PageSidebar(
        ...     parent=root,
        ...     pages=[],
        ...     on_page_select=lambda idx: print(f"Selected {idx}"),
        ...     on_page_add=lambda: print("Add page"),
        ...     on_page_remove=lambda idx: print(f"Remove {idx}"),
        ...     on_page_duplicate=lambda idx: print(f"Duplicate {idx}"),
        ...     on_page_reorder=lambda from_idx, to_idx: print(f"Move {from_idx} -> {to_idx}"),
        ... )
    """

    # Constants
    THUMBNAIL_WIDTH: Final[int] = 120
    THUMBNAIL_HEIGHT: Final[int] = 80
    THUMBNAIL_PADDING: Final[int] = 5
    HEADER_HEIGHT: Final[int] = 25
    FOOTER_HEIGHT: Final[int] = 30

    def __init__(
        self,
        parent: tk.Widget,
        pages: list[SidebarPageInfo],
        on_page_select: Callable[[int], None],
        on_page_add: Callable[[], None],
        on_page_remove: Callable[[int], None],
        on_page_duplicate: Callable[[int], None],
        on_page_reorder: Callable[[int, int], None],
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация PageSidebar.

        Args:
            parent: Родительский Tkinter виджет.
            pages: Список страниц для отображения.
            on_page_select: Callback при выборе страницы.
            on_page_add: Callback при добавлении страницы.
            on_page_remove: Callback при удалении страницы.
            on_page_duplicate: Callback при дублировании страницы.
            on_page_reorder: Callback при изменении порядка.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(
            widget_id="page_sidebar",
            controller=controller,
        )

        self._parent: tk.Widget = parent
        self._pages: list[SidebarPageInfo] = list(pages)

        # Callbacks (use _cb suffix to avoid shadowing methods)
        self._on_page_select_cb: Callable[[int], None] = on_page_select
        self._on_page_add_cb: Callable[[], None] = on_page_add
        self._on_page_remove_cb: Callable[[int], None] = on_page_remove
        self._on_page_duplicate_cb: Callable[[int], None] = on_page_duplicate
        self._on_page_reorder_cb: Callable[[int, int], None] = on_page_reorder

        # State
        self._selected_index: int = 0
        self._drag_start_index: Optional[int] = None
        self._drag_target_index: Optional[int] = None

        # Widgets
        self._tk_frame: Optional[tk.Frame] = None
        self._header_label: Optional[tk.Label] = None
        self._canvas: Optional[tk.Canvas] = None
        self._scrollbar: Optional[tk.Scrollbar] = None
        self._add_button: Optional[tk.Button] = None

        # Thumbnail frames
        self._thumbnail_frames: list[tk.Frame] = []
        self._thumbnail_items: list[int] = []

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        # Main frame
        self._tk_frame = tk.Frame(
            parent,
            width=self.THUMBNAIL_WIDTH + 20,
            bg="#e8e8e8",
            relief=tk.RIDGE,
            bd=1,
        )
        self._tk_frame.pack_propagate(False)

        # Header
        header_frame = tk.Frame(self._tk_frame, height=self.HEADER_HEIGHT, bg="#d0d0d0")
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)

        self._header_label = tk.Label(
            header_frame,
            text="Страницы",
            bg="#d0d0d0",
            font=("Arial", 10, "bold"),
        )
        self._header_label.pack(fill=tk.BOTH, expand=True)

        # Canvas with scrollbar for thumbnails
        canvas_frame = tk.Frame(self._tk_frame, bg="#e8e8e8")
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        self._canvas = tk.Canvas(
            canvas_frame,
            bg="#e8e8e8",
            highlightthickness=0,
            width=self.THUMBNAIL_WIDTH + 10,
        )
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._scrollbar = tk.Scrollbar(
            canvas_frame,
            orient=tk.VERTICAL,
            command=self._canvas.yview,
        )
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._canvas.config(yscrollcommand=self._scrollbar.set)

        # Footer with add button
        footer_frame = tk.Frame(
            self._tk_frame,
            height=self.FOOTER_HEIGHT,
            bg="#e8e8e8",
        )
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=2, pady=2)
        footer_frame.pack_propagate(False)

        self._add_button = tk.Button(
            footer_frame,
            text="+ Добавить",
            command=self._on_add_click,
            font=("Arial", 9),
        )
        self._add_button.pack(fill=tk.X, expand=True, padx=2, pady=2)

        # Initialize thumbnails
        self._refresh_thumbnails()

        return self._tk_frame

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        if self._canvas is None:
            return

        # Mouse wheel scrolling
        self._canvas.bind("<MouseWheel>", self._on_mousewheel)
        self._canvas.bind("<Button-4>", self._on_mousewheel)  # Linux scroll up
        self._canvas.bind("<Button-5>", self._on_mousewheel)  # Linux scroll down

        # Drag-drop bindings
        self._canvas.bind("<Button-1>", self._on_drag_start)
        self._canvas.bind("<B1-Motion>", self._on_drag_motion)
        self._canvas.bind("<ButtonRelease-1>", self._on_drag_end)

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self._pages.clear()
        self._thumbnail_frames.clear()
        self._thumbnail_items.clear()

        self._canvas = None
        self._scrollbar = None
        self._header_label = None
        self._add_button = None

    # =============================================================================
    # PUBLIC API
    # =============================================================================

    def set_pages(self, pages: list[SidebarPageInfo]) -> None:
        """Устанавливает новый список страниц.

        Args:
            pages: Новый список страниц.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_pages",
                message="Виджет не смонтирован",
            )

        self._pages = list(pages)
        self._refresh_thumbnails()

    def add_page(self, page: SidebarPageInfo) -> None:
        """Добавляет страницу в sidebar.

        Args:
            page: Информация о странице.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="add_page",
                message="Виджет не смонтирован",
            )

        self._pages.append(page)
        self._refresh_thumbnails()

    def remove_page(self, index: int) -> bool:
        """Удаляет страницу из sidebar.

        Args:
            index: Индекс страницы для удаления.

        Returns:
            True если удалена успешно.
        """
        if not (0 <= index < len(self._pages)):
            return False

        self._pages.pop(index)

        # Update selection
        if self._selected_index >= len(self._pages):
            self._selected_index = max(0, len(self._pages) - 1)

        if self._is_mounted:
            self._refresh_thumbnails()

        return True

    def select_page(self, index: int) -> None:
        """Выделяет страницу.

        Args:
            index: Индекс страницы.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="select_page",
                message="Виджет не смонтирован",
            )

        if not (0 <= index < len(self._pages)):
            return

        self._selected_index = index
        self._update_selection()

    def update_page(self, index: int, page: SidebarPageInfo) -> None:
        """Обновляет информацию о странице.

        Args:
            index: Индекс страницы.
            page: Новая информация.
        """
        if not (0 <= index < len(self._pages)):
            return

        self._pages[index] = page

        if self._is_mounted:
            self._refresh_thumbnails()

    def get_selected_index(self) -> int:
        """Возвращает индекс выбранной страницы.

        Returns:
            Индекс выбранной страницы.
        """
        return self._selected_index

    def get_page_count(self) -> int:
        """Возвращает количество страниц.

        Returns:
            Количество страниц.
        """
        return len(self._pages)

    # =============================================================================
    # PRIVATE METHODS
    # =============================================================================

    def _refresh_thumbnails(self) -> None:
        """Обновляет отображение thumbnails."""
        if self._canvas is None:
            return

        # Clear existing thumbnails
        for frame in self._thumbnail_frames:
            frame.destroy()
        self._thumbnail_frames.clear()
        self._canvas.delete("all")
        self._thumbnail_items.clear()

        # Create thumbnails
        for i, page in enumerate(self._pages):
            frame = self._create_thumbnail(i, page)
            self._thumbnail_frames.append(frame)

        # Update scroll region
        self._update_scroll_region()

    def _create_thumbnail(self, index: int, page: SidebarPageInfo) -> tk.Frame:
        """Создаёт thumbnail для страницы.

        Args:
            index: Индекс страницы.
            page: Информация о странице.

        Returns:
            Frame с thumbnail.
        """
        # Determine background color based on selection
        bg_color = "#3498db" if index == self._selected_index else "#ffffff"
        fg_color = "white" if index == self._selected_index else "black"

        frame = tk.Frame(
            self._canvas,
            bg=bg_color,
            relief=tk.RAISED if index != self._selected_index else tk.SUNKEN,
            bd=1,
            width=self.THUMBNAIL_WIDTH,
            height=self.THUMBNAIL_HEIGHT,
        )
        frame.pack_propagate(False)

        # Page number label
        label = tk.Label(
            frame,
            text=f"Стр. {index + 1}",
            bg=bg_color,
            fg=fg_color,
            font=("Arial", 8),
        )
        label.pack(side=tk.BOTTOM, fill=tk.X)

        # Paper type label
        paper_label = tk.Label(
            frame,
            text=page.profile.name,
            bg="#e8e8e8" if index != self._selected_index else "#2980b9",
            fg=fg_color,
            font=("Arial", 7),
            wraplength=self.THUMBNAIL_WIDTH - 10,
        )
        paper_label.pack(side=tk.TOP, fill=tk.X)

        # Canvas for preview
        preview = tk.Canvas(
            frame,
            bg="white",
            highlightthickness=0,
            width=self.THUMBNAIL_WIDTH - 20,
            height=self.THUMBNAIL_HEIGHT - 40,
        )
        preview.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Draw simple page representation
        self._draw_page_preview(preview, page.profile, bg_color)

        # Bind events
        def make_click_handler(idx: int) -> Callable[[tk.Event], None]:
            def handler(event: tk.Event) -> None:
                _ = event
                self._on_thumbnail_click(idx)

            return handler

        def make_context_handler(idx: int) -> Callable[[tk.Event], None]:
            def handler(event: tk.Event) -> None:
                self._show_context_menu(event, idx)

            return handler

        for widget in [frame, preview, label, paper_label]:
            widget.bind("<Button-1>", make_click_handler(index))
            widget.bind("<Button-3>", make_context_handler(index))

        # Place in canvas
        if self._canvas is not None:
            y_pos = (
                index * (self.THUMBNAIL_HEIGHT + self.THUMBNAIL_PADDING) + self.THUMBNAIL_PADDING
            )
            item_id = self._canvas.create_window(
                self.THUMBNAIL_PADDING,
                y_pos,
                anchor=tk.NW,
                window=frame,
                width=self.THUMBNAIL_WIDTH,
                height=self.THUMBNAIL_HEIGHT,
            )
            self._thumbnail_items.append(item_id)

        return frame

    def _draw_page_preview(
        self,
        canvas: tk.Canvas,
        profile: PaperProfile,
        bg_color: str,
    ) -> None:
        """Рисует предпросмотр страницы.

        Args:
            canvas: Canvas для рисования.
            profile: Профиль бумаги.
            bg_color: Цвет фона.
        """
        canvas.delete("all")

        # Calculate aspect ratio
        aspect = profile.height_mm / profile.width_mm if profile.width_mm > 0 else 1.414

        canvas_width = self.THUMBNAIL_WIDTH - 24
        canvas_height = self.THUMBNAIL_HEIGHT - 44

        # Maintain aspect ratio
        pw = canvas_width
        ph = int(pw * aspect)

        if ph > canvas_height:
            ph = canvas_height
            pw = int(ph / aspect) if aspect > 0 else canvas_width

        x1 = (canvas_width - pw) // 2 + 10
        y1 = (canvas_height - ph) // 2 + 5

        # Draw page rectangle
        canvas.create_rectangle(
            x1,
            y1,
            x1 + pw,
            y1 + ph,
            outline="#000000",
            fill="#ffffff",
            width=1,
        )

        # Draw margin indicators (optional visual cue)
        margin_ratio = 0.1  # Simplified margin visualization
        mx = int(pw * margin_ratio)
        my = int(ph * margin_ratio)

        if mx > 2 and my > 2:
            canvas.create_rectangle(
                x1 + mx,
                y1 + my,
                x1 + pw - mx,
                y1 + ph - my,
                outline="#e0e0e0",
                fill="",
                dash=(2, 2),
            )

    def _update_selection(self) -> None:
        """Обновляет визуальное выделение."""
        if self._canvas is None:
            return

        for i, frame in enumerate(self._thumbnail_frames):
            if i == self._selected_index:
                frame.config(bg="#3498db", relief=tk.SUNKEN)
                for child in frame.winfo_children():
                    if isinstance(child, tk.Label):
                        child.config(bg="#3498db", fg="white")
            else:
                frame.config(bg="#ffffff", relief=tk.RAISED)
                for child in frame.winfo_children():
                    if isinstance(child, tk.Label):
                        if child.cget("text").startswith("Стр."):
                            child.config(bg="#ffffff", fg="black")
                        else:
                            child.config(bg="#e8e8e8", fg="black")

    def _update_scroll_region(self) -> None:
        """Обновляет scroll region canvas."""
        if self._canvas is None:
            return

        total_height = (
            len(self._pages) * (self.THUMBNAIL_HEIGHT + self.THUMBNAIL_PADDING)
            + self.THUMBNAIL_PADDING
        )
        self._canvas.config(scrollregion=(0, 0, self.THUMBNAIL_WIDTH + 10, total_height))

    def _show_context_menu(self, event: tk.Event, index: int) -> None:
        """Показывает контекстное меню для страницы.

        Args:
            event: Событие мыши.
            index: Индекс страницы.
        """
        menu = tk.Menu(self._tk_frame, tearoff=0)
        menu.add_command(
            label="Выбрать",
            command=lambda: self._on_thumbnail_click(index),
        )
        menu.add_separator()
        menu.add_command(
            label="Дублировать",
            command=lambda: self._on_page_duplicate_cb_call(index),
        )
        menu.add_command(
            label="Удалить",
            command=lambda: self._on_page_remove_cb_call(index),
        )
        menu.add_separator()
        menu.add_command(
            label="Вверх",
            command=lambda: self._move_page_up(index),
            state=tk.NORMAL if index > 0 else tk.DISABLED,
        )
        menu.add_command(
            label="Вниз",
            command=lambda: self._move_page_down(index),
            state=tk.NORMAL if index < len(self._pages) - 1 else tk.DISABLED,
        )

        menu.post(event.x_root, event.y_root)

    # =============================================================================
    # EVENT HANDLERS
    # =============================================================================

    def _on_thumbnail_click(self, index: int) -> None:
        """Обработчик клика по thumbnail.

        Args:
            index: Индекс страницы.
        """
        self._selected_index = index
        self._update_selection()
        self._on_page_select_cb(index)

    def _on_add_click(self) -> None:
        """Обработчик клика по кнопке добавления."""
        self._on_page_add_cb()

    def _on_page_remove_cb_call(self, index: int) -> None:
        """Обработчик удаления страницы.

        Args:
            index: Индекс страницы.
        """
        self._on_page_remove_cb(index)

    def _on_page_duplicate_cb_call(self, index: int) -> None:
        """Обработчик дублирования страницы.

        Args:
            index: Индекс страницы.
        """
        self._on_page_duplicate_cb(index)

    def _move_page_up(self, index: int) -> None:
        """Перемещает страницу вверх.

        Args:
            index: Индекс страницы.
        """
        if index > 0:
            self._on_page_reorder_cb(index, index - 1)

    def _move_page_down(self, index: int) -> None:
        """Перемещает страницу вниз.

        Args:
            index: Индекс страницы.
        """
        if index < len(self._pages) - 1:
            self._on_page_reorder_cb(index, index + 1)

    def _on_mousewheel(self, event: tk.Event) -> None:
        """Обработчик прокрутки мышью.

        Args:
            event: Событие прокрутки.
        """
        if self._canvas is None:
            return

        # Determine scroll direction
        if event.num == 4 or getattr(event, "delta", 0) > 0:
            self._canvas.yview_scroll(-3, "units")
        elif event.num == 5 or getattr(event, "delta", 0) < 0:
            self._canvas.yview_scroll(3, "units")

    def _on_drag_start(self, event: tk.Event) -> None:
        """Обработчик начала drag.

        Args:
            event: Событие мыши.
        """
        # Calculate which thumbnail was clicked
        if self._canvas is None:
            return

        y = self._canvas.canvasy(event.y)  # type: ignore[no-untyped-call]
        index = int(y / (self.THUMBNAIL_HEIGHT + self.THUMBNAIL_PADDING))

        if 0 <= index < len(self._pages):
            self._drag_start_index = index
            self._drag_target_index = index

    def _on_drag_motion(self, event: tk.Event) -> None:
        """Обработчик drag motion.

        Args:
            event: Событие мыши.
        """
        if self._drag_start_index is None or self._canvas is None:
            return

        y = self._canvas.canvasy(event.y)  # type: ignore[no-untyped-call]
        index = int(y / (self.THUMBNAIL_HEIGHT + self.THUMBNAIL_PADDING))

        # Clamp to valid range
        index = max(0, min(index, len(self._pages) - 1))

        if index != self._drag_target_index:
            self._drag_target_index = index
            self._update_drag_visual()

    def _on_drag_end(self, event: tk.Event) -> None:
        """Обработчик окончания drag.

        Args:
            event: Событие мыши.
        """
        _ = event  # unused

        if self._drag_start_index is not None and self._drag_target_index is not None:
            if self._drag_start_index != self._drag_target_index:
                self._on_page_reorder_cb(self._drag_start_index, self._drag_target_index)

        self._drag_start_index = None
        self._drag_target_index = None
        self._update_drag_visual()

    def _update_drag_visual(self) -> None:
        """Обновляет визуальную индикацию drag."""
        # Could add visual indicators during drag
        pass


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "PageSidebar",
    "SidebarPageInfo",
]
