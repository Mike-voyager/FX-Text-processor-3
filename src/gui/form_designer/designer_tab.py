"""DesignerTab для Form Designer mode (Phase 5).

Главный контейнер для визуального редактирования форм с continuous scroll layout.
Реализует three-panel интерфейс: палитра полей, canvas со страницами, панель свойств.

Features:
    - Three-panel layout (20% | 60% | 20%)
    - Continuous scroll для multi-page документов
    - Grid toggle и zoom support
    - Undo/redo через CommandStack
    - Drag-and-drop создание полей
    - Property editing в real-time

Example:
    >>> from src.gui.form_designer.designer_tab import DesignerTab
    >>> from src.services.paper_profile_service import PaperProfileService
    >>>
    >>> tab = DesignerTab(parent=root, controller=controller)
    >>> tab.mount(parent_frame)
    >>>
    >>> # Add pages
    >>> service = PaperProfileService()
    >>> profile = service.get_profile("a4_tractor")
    >>> tab.add_page(profile)
    >>> tab.add_page(profile)
    >>>
    >>> # Toggle grid
    >>> tab.toggle_grid(True)
    >>>
    >>> # Set zoom
    >>> tab.set_zoom(1.5)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Final, Optional, cast

from src.documents.constructor.form_constructor import ValidationReport
from src.documents.format.template_format import TemplateSerializer
from src.documents.types.type_schema import FieldType
from src.gui.components.base.widget import BaseWidget
from src.gui.components.tooltip import TooltipManager
from src.gui.core.commands.command_stack import CommandStack
from src.gui.core.error_handler import GUIErrorHandler
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.gui.form_designer.converters import (
    DesignerToTemplateConverter,
    TemplateToDesignerConverter,
)
from src.gui.form_designer.property_panel import PropertyPanel
from src.gui.form_designer.types import DesignerPage as _DesignerPage
from src.gui.renderers.form_canvas import FormCanvas, FormFieldWidget
from src.gui.renderers.structured_form_renderer import StructuredFormDocument
from src.services.paper_format_service import PaperProfile

# Реэкспорт для обратной совместимости
DesignerPage = _DesignerPage

# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class FieldPaletteItem:
    """Элемент палитры полей.

    Attributes:
        field_type: Тип поля.
        icon: Иконка (emoji или текст).
        label: Отображаемое название.
        description: Описание для tooltip.
    """

    field_type: FieldType
    icon: str
    label: str
    description: str


# =============================================================================
# DESIGNER TAB
# =============================================================================


class DesignerTab(BaseWidget):
    """Главный контейнер Form Designer mode с continuous scroll layout.

    Реализует three-panel layout:
    - Left (20%): Field Palette для выбора типов полей
    - Center (60%): Scrollable Canvas со страницами
    - Right (20%): Property Panel для редактирования свойств

    Features:
        - Continuous scroll для multi-page документов
        - Grid toggle и zoom support
        - Undo/redo через CommandStack
        - Drag-and-drop и click-to-place режимы
        - Real-time property editing

    Example:
        >>> tab = DesignerTab(parent=root, controller=controller)
        >>> tab.mount(parent_frame)
        >>>
        >>> # Добавить страницу
        >>> profile = PaperProfileService().get_profile("a4_tractor")
        >>> tab.add_page(profile)
        >>>
        >>> # Создать поле
        >>> tab.on_field_create(FieldType.TEXT_INPUT, x=10, y=5, page=0)
    """

    # Layout weights (проценты ширины)
    LEFT_PANEL_WEIGHT: Final[int] = 20
    CENTER_PANEL_WEIGHT: Final[int] = 60
    RIGHT_PANEL_WEIGHT: Final[int] = 20

    # Minimum panel widths (pixels)
    MIN_LEFT_WIDTH: Final[int] = 150
    MIN_CENTER_WIDTH: Final[int] = 400
    MIN_RIGHT_WIDTH: Final[int] = 150

    # Page break line height
    PAGE_BREAK_HEIGHT: Final[int] = 20

    # Palette items
    PALETTE_ITEMS: Final[list[FieldPaletteItem]] = [
        FieldPaletteItem(FieldType.TEXT_INPUT, "📝", "Text", "Single-line text field"),
        FieldPaletteItem(FieldType.NUMBER_INPUT, "🔢", "Number", "Numeric input field"),
        FieldPaletteItem(FieldType.CURRENCY, "💰", "Currency", "Monetary amount"),
        FieldPaletteItem(FieldType.DATE_INPUT, "📅", "Date", "Date field"),
        FieldPaletteItem(FieldType.MULTI_LINE_TEXT, "📄", "Text (multi-line)", "Multi-line text"),
        FieldPaletteItem(FieldType.CHECKBOX, "☐", "Checkbox", "Boolean checkbox"),
        FieldPaletteItem(FieldType.DROPDOWN, "▼", "Dropdown", "Dropdown list"),
        FieldPaletteItem(FieldType.RADIO_GROUP, "◉", "Radio buttons", "Radio button group"),
        FieldPaletteItem(FieldType.TABLE, "⊞", "Table", "Table field"),
        FieldPaletteItem(FieldType.STATIC_TEXT, "🖹", "Static text", "Read-only text"),
        FieldPaletteItem(FieldType.QR, "▩", "QR Code", "QR code for scanning"),
        FieldPaletteItem(FieldType.BARCODE, "┃", "Barcode", "Barcode"),
        FieldPaletteItem(FieldType.SIGNATURE, "✎", "Signature", "Digital signature field"),
        FieldPaletteItem(FieldType.STAMP, "🖷", "Stamp", "Stamp field"),
        FieldPaletteItem(FieldType.PHONE, "📞", "Phone", "Phone number"),
        FieldPaletteItem(FieldType.EMAIL, "✉", "Email", "Email address"),
    ]

    def __init__(
        self,
        parent: tk.Widget,
        document: Optional[StructuredFormDocument] = None,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация DesignerTab.

        Args:
            parent: Родительский Tkinter виджет.
            document: Опциональный документ для редактирования.
            controller: Опциональная ссылка на контроллер для callbacks.
        """
        super().__init__(widget_id="designer_tab", controller=controller)

        self._parent: tk.Widget = parent
        self._document: Optional[StructuredFormDocument] = document

        # Pages
        self._pages: list[DesignerPage] = []

        # Current selection
        self._current_field: Optional[FormFieldWidget] = None
        self._selected_page_index: int = 0

        # Three-panel layout frames
        self._left_frame: Optional[tk.Frame] = None
        self._center_frame: Optional[tk.Frame] = None
        self._right_frame: Optional[tk.Frame] = None
        self._bottom_frame: Optional[tk.Frame] = None

        # Scrollable canvas container
        self._outer_canvas: Optional[tk.Canvas] = None
        self._scrollbar: Optional[tk.Scrollbar] = None
        self._scrollable_frame: Optional[tk.Frame] = None

        # Child widgets (placeholders - full implementation in subclasses)
        self._field_palette: Optional[tk.Frame] = None
        self._property_panel: Optional[tk.Widget] = None
        self._property_panel_instance: Optional[PropertyPanel] = None
        self._panel_state_cache: dict[str, Any] = {}

        # State
        self._show_grid: bool = True
        self._zoom: float = 1.0
        self._mode: str = "drag_drop"  # or "click_place"
        self._pending_field_type: Optional[FieldType] = None

        # Command stack for undo/redo
        self._command_stack: CommandStack = CommandStack()

        # Tooltip manager
        self._tooltip_manager: TooltipManager = TooltipManager.get_instance()

        # Error handler
        self._error_handler: GUIErrorHandler = GUIErrorHandler()

        # Callbacks
        self._on_field_select_callback: Optional[Callable[[Optional[FormFieldWidget]], None]] = None
        self._on_field_create_callback: Optional[Callable[[FormFieldWidget, int], None]] = None
        self._on_page_change_callback: Optional[Callable[[int], None]] = None

        # Tk widget references
        self._tk_frame: Optional[tk.Frame] = None
        self._palette_buttons: dict[FieldType, tk.Button] = {}
        self._zoom_label: Optional[tk.Label] = None
        self._page_count_label: Optional[tk.Label] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        self._tk_frame = tk.Frame(parent, bg="#f5f5f5")

        # Create three-panel layout
        self._create_layout()

        # Create scrollable canvas for pages
        self._create_scrollable_canvas()

        # Create field palette
        self._create_field_palette()

        # Create property panel (placeholder)
        self._create_property_panel()

        # Create bottom toolbar
        self._create_bottom_toolbar()

        return self._tk_frame

    def _create_layout(self) -> None:
        """Создаёт three-panel layout.

        Layout:
        +------+-------------------+--------+
        |      |                   |        |
        | Left | Center (Canvas)   | Right  |
        | 20%  |   60%             | 20%    |
        |      |                   |        |
        +------+-------------------+--------+
        | Bottom toolbar                    |
        +-----------------------------------+
        """
        if self._tk_frame is None:
            return

        # Main container with grid
        main_container = tk.Frame(self._tk_frame, bg="#f5f5f5")
        main_container.pack(fill=tk.BOTH, expand=True)

        # Configure grid weights
        main_container.grid_columnconfigure(
            0, weight=self.LEFT_PANEL_WEIGHT, minsize=self.MIN_LEFT_WIDTH
        )
        main_container.grid_columnconfigure(
            1, weight=self.CENTER_PANEL_WEIGHT, minsize=self.MIN_CENTER_WIDTH
        )
        main_container.grid_columnconfigure(
            2, weight=self.RIGHT_PANEL_WEIGHT, minsize=self.MIN_RIGHT_WIDTH
        )
        main_container.grid_rowconfigure(0, weight=1)  # Main content expands
        main_container.grid_rowconfigure(1, weight=0)  # Toolbar fixed

        # Left panel - Field Palette
        self._left_frame = tk.Frame(
            main_container,
            bg="#e8e8e8",
            relief=tk.RIDGE,
            bd=1,
            width=self.MIN_LEFT_WIDTH,
        )
        self._left_frame.grid(row=0, column=0, sticky="nsew", padx=(2, 1), pady=2)
        self._left_frame.grid_propagate(False)

        # Center panel - Scrollable Canvas
        self._center_frame = tk.Frame(
            main_container,
            bg="#ffffff",
            relief=tk.SUNKEN,
            bd=1,
        )
        self._center_frame.grid(row=0, column=1, sticky="nsew", padx=1, pady=2)

        # Right panel - Property Panel
        self._right_frame = tk.Frame(
            main_container,
            bg="#e8e8e8",
            relief=tk.RIDGE,
            bd=1,
            width=self.MIN_RIGHT_WIDTH,
        )
        self._right_frame.grid(row=0, column=2, sticky="nsew", padx=(1, 2), pady=2)
        self._right_frame.grid_propagate(False)

        # Bottom toolbar
        self._bottom_frame = tk.Frame(
            main_container,
            bg="#d0d0d0",
            height=32,
            relief=tk.GROOVE,
            bd=1,
        )
        self._bottom_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=2, pady=(1, 2))
        self._bottom_frame.grid_propagate(False)

    def _create_scrollable_canvas(self) -> None:
        """Создаёт scrollable container для всех страниц.

        Реализует continuous scroll layout, где страницы располагаются
        одна под другой с разделительными линиями.
        """
        if self._center_frame is None:
            return

        # Outer canvas with scrollbar
        self._outer_canvas = tk.Canvas(
            self._center_frame,
            bg="#f0f0f0",
            highlightthickness=0,
        )
        self._outer_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar
        self._scrollbar = tk.Scrollbar(
            self._center_frame,
            orient=tk.VERTICAL,
            command=self._outer_canvas.yview,
        )
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._outer_canvas.configure(yscrollcommand=self._scrollbar.set)

        # Scrollable frame inside canvas
        self._scrollable_frame = tk.Frame(self._outer_canvas, bg="#f0f0f0")
        self._canvas_window = self._outer_canvas.create_window(
            (0, 0),
            window=self._scrollable_frame,
            anchor=tk.NW,
        )

        # Bind events for resizing
        self._scrollable_frame.bind("<Configure>", self._on_frame_configure)
        self._outer_canvas.bind("<Configure>", self._on_canvas_configure)

        # Mouse wheel scrolling
        self._outer_canvas.bind("<MouseWheel>", self._on_mousewheel)
        self._outer_canvas.bind("<Button-4>", self._on_mousewheel)  # Linux
        self._outer_canvas.bind("<Button-5>", self._on_mousewheel)  # Linux

    def _on_frame_configure(self, event: tk.Event[Any]) -> None:
        """Обработчик изменения размера scrollable frame."""
        if self._outer_canvas is not None:
            self._outer_canvas.configure(scrollregion=self._outer_canvas.bbox("all"))

    def _on_canvas_configure(self, event: tk.Event[Any]) -> None:
        """Обработчик изменения размера canvas."""
        if self._outer_canvas is not None and self._canvas_window is not None:
            # Update window width to match canvas width
            self._outer_canvas.itemconfig(self._canvas_window, width=event.width)

    def _on_mousewheel(self, event: tk.Event[Any]) -> None:
        """Обработчик скролла мышью."""
        if self._outer_canvas is None:
            return

        # Scroll amount
        if event.num == 4 or event.delta > 0:
            self._outer_canvas.yview_scroll(-3, "units")
        elif event.num == 5 or event.delta < 0:
            self._outer_canvas.yview_scroll(3, "units")

    def _create_field_palette(self) -> None:
        """Создаёт палитру полей в левой панели."""
        if self._left_frame is None:
            return

        # Header
        header = tk.Label(
            self._left_frame,
            text="Fields",
            bg="#d0d0d0",
            font=("Arial", 10, "bold"),
            anchor=tk.W,
            padx=5,
        )
        header.pack(fill=tk.X, pady=(0, 2))

        # Scrollable frame for palette items
        palette_canvas = tk.Canvas(self._left_frame, bg="#e8e8e8", highlightthickness=0)
        palette_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        palette_scrollbar = tk.Scrollbar(
            self._left_frame,
            orient=tk.VERTICAL,
            command=palette_canvas.yview,
        )
        palette_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        palette_canvas.configure(yscrollcommand=palette_scrollbar.set)

        self._field_palette = tk.Frame(palette_canvas, bg="#e8e8e8")
        palette_canvas.create_window((0, 0), window=self._field_palette, anchor=tk.NW)

        # Create palette buttons
        for item in self.PALETTE_ITEMS:
            btn = tk.Button(
                self._field_palette,
                text=f"{item.icon} {item.label}",
                anchor=tk.W,
                padx=5,
                bg="#f0f0f0",
                activebackground="#d0e0f0",
                command=lambda ft=item.field_type: self._on_palette_click(ft),  # type: ignore[misc]
            )
            btn.pack(fill=tk.X, padx=2, pady=1)
            self._palette_buttons[item.field_type] = btn

            # Tooltip on hover via TooltipManager
            self._tooltip_manager.bind_to_widget(
                btn,
                f"{item.label}: {item.description}",
                delay_ms=500,
            )

        # Update scroll region
        self._field_palette.bind(
            "<Configure>",
            lambda e: palette_canvas.configure(scrollregion=palette_canvas.bbox("all")),
        )

    def _create_property_panel(self) -> None:
        """Создаёт панель свойств в правой панели."""
        if self._right_frame is None:
            return

        self._property_panel_instance = PropertyPanel(
            parent=self._right_frame,
            on_property_change=self._on_panel_property_change,
            on_field_delete=self._on_panel_field_delete,
            on_field_duplicate=self._on_panel_field_duplicate,
            controller=self._controller,
            tooltip_manager=self._tooltip_manager,
        )
        self._property_panel = self._property_panel_instance.mount(self._right_frame)
        self._property_panel.pack(fill=tk.BOTH, expand=True)

    def _create_bottom_toolbar(self) -> None:
        """Создаёт нижнюю панель инструментов."""
        if self._bottom_frame is None:
            return

        # Left side - zoom controls
        zoom_frame = tk.Frame(self._bottom_frame, bg="#d0d0d0")
        zoom_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        zoom_out_btn = tk.Button(
            zoom_frame,
            text="−",
            width=3,
            command=self._zoom_out,
            bg="#d0d0d0",
        )
        zoom_out_btn.pack(side=tk.LEFT, padx=2)

        self._zoom_label = tk.Label(
            zoom_frame,
            text="100%",
            bg="#d0d0d0",
            width=6,
        )
        self._zoom_label.pack(side=tk.LEFT, padx=2)

        zoom_in_btn = tk.Button(
            zoom_frame,
            text="+",
            width=3,
            command=self._zoom_in,
            bg="#d0d0d0",
        )
        zoom_in_btn.pack(side=tk.LEFT, padx=2)

        # Grid toggle
        grid_btn = tk.Button(
            zoom_frame,
            text="Grid",
            command=self._toggle_grid_cmd,
            bg="#d0d0d0",
        )
        grid_btn.pack(side=tk.LEFT, padx=(10, 2))

        # Center - page info
        info_frame = tk.Frame(self._bottom_frame, bg="#d0d0d0")
        info_frame.pack(side=tk.LEFT, fill=tk.Y, expand=True)

        self._page_count_label = tk.Label(
            info_frame,
            text="Pages: 0",
            bg="#d0d0d0",
        )
        self._page_count_label.pack(side=tk.LEFT, padx=20)

        # Right side - undo/redo
        undo_frame = tk.Frame(self._bottom_frame, bg="#d0d0d0")
        undo_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5)

        undo_btn = tk.Button(
            undo_frame,
            text="Undo",
            command=self.undo,
            bg="#d0d0d0",
        )
        undo_btn.pack(side=tk.LEFT, padx=2)

        redo_btn = tk.Button(
            undo_frame,
            text="Redo",
            command=self.redo,
            bg="#d0d0d0",
        )
        redo_btn.pack(side=tk.LEFT, padx=2)

    def _on_palette_click(self, field_type: FieldType) -> None:
        """Обработчик клика на элемент палитры.

        Args:
            field_type: Выбранный тип поля.
        """
        self._pending_field_type = field_type
        self._mode = "click_place"

        # Update button states
        for ft, btn in self._palette_buttons.items():
            if ft == field_type:
                btn.config(bg="#d0e0f0", relief=tk.SUNKEN)
            else:
                btn.config(bg="#f0f0f0", relief=tk.RAISED)

        # Change cursor on all canvases
        for page in self._pages:
            if isinstance(page.canvas._tk_widget, tk.Canvas):
                page.canvas._tk_widget.config(cursor="crosshair")

    def _show_tooltip(self, text: str, x: int = 0, y: int = 0) -> None:
        """Показывает tooltip.

        Args:
            text: Текст подсказки.
            x: X координата (screen coordinates).
            y: Y координата (screen coordinates).
        """
        self._tooltip_manager.show(
            cast(tk.Widget, self._tk_frame),
            text,
            x,
            y,
            delay_ms=500,
        )

    def _hide_tooltip(self) -> None:
        """Скрывает tooltip."""
        self._tooltip_manager.hide()

    def _zoom_in(self) -> None:
        """Увеличивает масштаб."""
        new_zoom = min(2.0, self._zoom + 0.1)
        self.set_zoom(new_zoom)

    def _zoom_out(self) -> None:
        """Уменьшает масштаб."""
        new_zoom = max(0.5, self._zoom - 0.1)
        self.set_zoom(new_zoom)

    def _toggle_grid_cmd(self) -> None:
        """Переключает видимость сетки (команда кнопки)."""
        self.toggle_grid()

    def _update_zoom_label(self) -> None:
        """Обновляет метку масштаба."""
        if self._zoom_label is not None:
            self._zoom_label.config(text=f"{int(self._zoom * 100)}%")

    def _update_page_count_label(self) -> None:
        """Updates page count label."""
        if self._page_count_label is not None:
            self._page_count_label.config(text=f"Pages: {len(self._pages)}")

    # =====================================================================
    # PUBLIC API
    # =====================================================================

    def set_zoom(self, zoom: float) -> None:
        """Sets zoom level for all pages.

        Args:
            zoom: Zoom level (clamped to 0.5-2.0).
        """
        self._zoom = max(0.5, min(2.0, zoom))
        self._update_zoom_label()
        for page in self._pages:
            if page.canvas is not None:
                page.canvas.set_zoom(self._zoom)

    def toggle_grid(self, show: Optional[bool] = None) -> None:
        """Toggles grid visibility on all pages.

        Args:
            show: Force grid state, or None to toggle.
        """
        if show is None:
            self._show_grid = not self._show_grid
        else:
            self._show_grid = bool(show)
        for page in self._pages:
            if page.canvas is not None:
                page.canvas.show_grid(self._show_grid)

    def undo(self) -> bool:
        """Undoes the last command.

        Returns:
            True if undo was performed, False if nothing to undo.
        """
        try:
            self._command_stack.undo()
            self._refresh_panel_after_command()
            return True
        except RuntimeError:
            return False

    def redo(self) -> bool:
        """Redoes the last undone command.

        Returns:
            True if redo was performed, False if nothing to redo.
        """
        try:
            self._command_stack.redo()
            self._refresh_panel_after_command()
            return True
        except RuntimeError:
            return False

    def on_property_change(self, field_id: str, prop_name: str, value: Any) -> None:
        """Handles property change for a field.

        Args:
            field_id: ID of the field.
            prop_name: Name of the property.
            value: New value.
        """
        # Stub: implement in subclass or controller
        pass

    def on_field_move(self, field_id: str, new_x: int, new_y: int) -> None:
        """Handles field move on canvas.

        Args:
            field_id: ID of the field.
            new_x: New X position.
            new_y: New Y position.
        """
        # Stub: implement in subclass or controller
        pass

    def add_page(self, profile: PaperProfile) -> int:
        """Добавляет страницу в continuous scroll.

        Args:
            profile: Профиль бумаги для новой страницы.

        Returns:
            Индекс добавленной страницы.
        """
        if self._scrollable_frame is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="add_page",
                message="DesignerTab not mounted",
            )

        page_index = len(self._pages)

        # Create frame for page
        page_frame = tk.Frame(
            self._scrollable_frame,
            bg="#f0f0f0",
            padx=10,
            pady=5,
        )
        page_frame.pack(fill=tk.X, expand=False, pady=self.PAGE_BREAK_HEIGHT // 2)

        # Page header
        header = tk.Label(
            page_frame,
            text=f"Page {page_index + 1}: {profile.name}",
            bg="#d0d0d0",
            font=("Arial", 9, "bold"),
        )
        header.pack(fill=tk.X, pady=(0, 2))

        # Create canvas for page
        canvas = FormCanvas(
            widget_id=f"page_canvas_{page_index}",
            controller=self._controller,
            profile=profile,
            zoom=self._zoom,
            show_grid=self._show_grid,
            on_field_select=self._on_canvas_field_select,
        )
        canvas_widget = canvas.mount(page_frame)
        canvas_widget.pack(fill=tk.BOTH, expand=False)

        # Page break line (except for first page)
        page_break_id: Optional[int] = None
        if page_index > 0:
            separator = tk.Frame(
                self._scrollable_frame,
                height=self.PAGE_BREAK_HEIGHT,
                bg="#a0a0a0",
            )
            separator.pack(fill=tk.X, pady=5)

        # Create page object
        page = DesignerPage(
            index=page_index,
            profile=profile,
            canvas=canvas,
            frame=page_frame,
            page_break_id=page_break_id,
        )

        self._pages.append(page)
        self._update_page_count_label()

        # Update scroll region
        if self._outer_canvas is not None:
            self._outer_canvas.update_idletasks()
            self._outer_canvas.configure(scrollregion=self._outer_canvas.bbox("all"))

        return page_index

    def _mount_page_to_ui(self, page: DesignerPage) -> None:
        """Монтирует существующую страницу в UI.

        Args:
            page: Страница для монтирования.
        """
        # Page frame уже создан в конвертере
        # Просто упаковываем и настраиваем canvas
        if page.canvas is not None:
            canvas_widget = page.canvas.mount(page.frame)
            canvas_widget.pack(fill=tk.BOTH, expand=False)

        # Page break line (except for first page)
        page_index = page.index
        if page_index > 0 and self._scrollable_frame is not None:
            separator = tk.Frame(
                self._scrollable_frame,
                height=self.PAGE_BREAK_HEIGHT,
                bg="#a0a0a0",
            )
            separator.pack(fill=tk.X, pady=5)
            page.page_break_id = id(separator)

        # Update scroll region
        if self._outer_canvas is not None:
            self._outer_canvas.update_idletasks()
            self._outer_canvas.configure(scrollregion=self._outer_canvas.bbox("all"))

    def remove_page(self, index: int) -> None:
        """Удаляет страницу.

        Args:
            index: Индекс страницы для удаления.

        Raises:
            IndexError: Если индекс вне диапазона.
        """
        if not 0 <= index < len(self._pages):
            raise IndexError(f"Invalid page index: {index}")

        page = self._pages[index]

        # Remove canvas widgets
        page.canvas.unmount()

        # Destroy frame
        page.frame.destroy()

        # Remove from list
        self._pages.pop(index)

        # Reindex remaining pages (DesignerPage is frozen, recreate with new index)
        for i, p in enumerate(self._pages):
            self._pages[i] = _DesignerPage(
                index=i,
                profile=p.profile,
                canvas=p.canvas,
                frame=p.frame,
                fields=p.fields,
                page_break_id=p.page_break_id,
            )

        # Update selection
        if self._selected_page_index >= len(self._pages):
            self._selected_page_index = max(0, len(self._pages) - 1)

        self._update_page_count_label()

    def on_field_select(self, field_widget: Optional[FormFieldWidget]) -> None:
        """Обработчик выбора поля на Canvas.

        Args:
            field_widget: Выбранное поле.

        Note:
            Этот метод вызывается при выборе поля пользователем.
            Обновляет текущее поле, показывает handles, обновляет панель свойств.
        """
        # Deselect previous
        if self._current_field is not None:
            self._current_field.selected = False
            for page in self._pages:
                if field_widget in page.fields:
                    page.canvas.select_field(None)

        # Select new
        self._current_field = field_widget
        if field_widget is not None:
            field_widget.selected = True
            for page in self._pages:
                if field_widget in page.fields:
                    page.canvas.select_field(field_widget.field_id)

        # Update property panel (placeholder)
        self._update_property_panel(field_widget)

        # Call callback
        if self._on_field_select_callback is not None:
            self._on_field_select_callback(field_widget)

    def on_field_create(
        self,
        field_type: FieldType,
        x: int,
        y: int,
        page: int,
        **kwargs: Any,
    ) -> Optional[FormFieldWidget]:
        """Обработчик создания поля (из палитры).

        Args:
            field_type: Тип поля для создания.
            x: Позиция по X (колонка).
            y: Позиция по Y (строка).
            page: Индекс страницы.
            **kwargs: Дополнительные параметры поля.

        Returns:
            Созданный виджет поля или None если ошибка.

        Note:
            Собирает все поля со всех страниц, создаёт FormTemplate,
            валидирует через validate_form(), сохраняет через TemplateSerializer.
        """

    def save_template(self, path: Path) -> bool:
        """Сохраняет шаблон в .fxstpl.

        Args:
            path: Путь для сохранения.

        Returns:
            True если сохранение успешно.

        Note:
            Собирает все поля со всех страниц, создаёт FormTemplate,
            валидирует через SchemaLinter (placeholder), сохраняет через TemplateSerializer.
        """
        try:
            # Validate form before saving
            report = self.validate_form()
            if not report.is_valid:
                return False

            # Convert DesignerPage -> FormTemplate
            converter = DesignerToTemplateConverter()
            metadata = {
                "type_code": "CUSTOM",
                "subtype": "01",
                "series": "GEN",
            }
            template = converter.convert(self._pages, metadata)

            # Save
            serializer = TemplateSerializer()
            data = serializer.serialize_template(template, sign=False)

            path.write_bytes(data)
            return True
        except Exception as e:
            self._error_handler.handle_silent(
                e,
                {"operation": "save_template", "path": str(path)},
            )
            return False

    def load_template(self, path: Path) -> bool:
        """Загружает шаблон из .fxstpl.

        Args:
            path: Путь к файлу шаблона.

        Returns:
            True если загрузка успешна.

        Note:
            Очищает текущий документ, загружает через TemplateSerializer,
            пересоздаёт страницы и поля.
        """
        try:
            # Clear current
            self.clear_all()

            # Load
            serializer = TemplateSerializer()
            data = path.read_bytes()
            template = serializer.deserialize_template(data, verify_signature=False)

            # Convert FormTemplate -> DesignerPage
            converter = TemplateToDesignerConverter(canvas_factory=self._create_canvas_factory())
            pages = converter.convert(template)

            # Add pages to UI
            for page in pages:
                self._pages.append(page)
                self._mount_page_to_ui(page)

            self._update_page_count_label()

            return True
        except Exception as e:
            self._error_handler.handle_silent(
                e,
                {"operation": "load_template", "path": str(path)},
            )
            return False

    def _create_canvas_factory(self) -> Callable[[], FormCanvas]:
        """Создаёт фабрику для создания FormCanvas.

        Returns:
            Функция-фабрика для создания FormCanvas.
        """
        from src.services.paper_format_service import PaperFormatService

        profile_service = PaperFormatService()
        default_profile = profile_service.get_default_profile()

        def factory() -> FormCanvas:
            return FormCanvas(
                widget_id=f"page_canvas_{len(self._pages)}",
                controller=self._controller,
                profile=default_profile,
                zoom=self._zoom,
                show_grid=self._show_grid,
                on_field_select=self._on_canvas_field_select,
            )

        return factory

    def validate_form(self, show_errors: bool = True) -> ValidationReport:
        """Валидирует форму на конфликты.

        Args:
            show_errors: Показывать ошибки на Canvas (подсветка).

        Returns:
            ValidationReport с результатами валидации.

        Note:
            Проверяет:
            - Дубликаты field_id между страницами
            - Перекрытие полей
            - Выход за границы
            - Обязательные свойства
        """
        # Clear previous errors
        if show_errors:
            self.clear_validation_errors()

        report = ValidationReport()

        # Track all field IDs across pages
        all_field_ids: dict[str, int] = {}

        for page in self._pages:
            fields = list(page.fields)

            # Check for duplicate field IDs
            for fld in fields:
                if fld.field_id in all_field_ids:
                    other_page = all_field_ids[fld.field_id]
                    report.add_form_error(
                        f"Field {fld.field_id} duplicated on pages "
                        f"{other_page + 1} and {page.index + 1}"
                    )
                    if show_errors and page.canvas:
                        page.canvas.highlight_field_error(fld.field_id, "Duplicate ID")
                else:
                    all_field_ids[fld.field_id] = page.index

            # Check field overlaps
            for i, field1 in enumerate(fields):
                for field2 in fields[i + 1 :]:
                    if self._fields_overlap(field1, field2):
                        error_msg = f"Overlap with field {field2.field_id}"
                        report.add_field_error(field1.field_id, error_msg)
                        report.add_field_error(field2.field_id, error_msg)
                        if show_errors:
                            if page.canvas:
                                page.canvas.highlight_field_error(field1.field_id, error_msg)
                                page.canvas.highlight_field_error(field2.field_id, error_msg)

            # Check out of bounds
            for _fld in fields:
                if page.canvas:
                    is_valid, error = page.canvas.validate_field_position(
                        _fld.field_id,
                        _fld.position.col,
                        _fld.position.row,
                        _fld.position.width,
                        _fld.position.height,
                    )
                    if not is_valid:
                        error_msg = f"Out of bounds: {error}"
                        report.add_field_error(_fld.field_id, error_msg)
                        if show_errors:
                            page.canvas.highlight_field_error(_fld.field_id, error_msg)

        # Show validation summary
        if show_errors and not report.is_valid:
            self._show_validation_summary(report)

        return report

    def _show_validation_summary(self, report: ValidationReport) -> None:
        """Показывает окно с summary ошибок валидации.

        Args:
            report: Отчёт о валидации.
        """
        from tkinter import messagebox

        lines = ["The following errors were found:"]
        lines.append("")

        if report.form_errors:
            lines.append("Form errors:")
            for error in report.form_errors:
                lines.append(f"  • {error}")
            lines.append("")

        if report.field_errors:
            lines.append("Field errors:")
            for field_id, messages in report.field_errors.items():
                for msg in messages:
                    lines.append(f"  • {field_id}: {msg}")

        parent = cast(tk.Widget, self._tk_frame)
        messagebox.showwarning(
            "Validation Errors",
            "\n".join(lines),
            parent=parent,
        )

    def clear_validation_errors(self) -> None:
        """Убирает подсветку ошибок со всех полей."""
        for page in self._pages:
            if page.canvas is not None:
                page.canvas.clear_all_errors()

    def _validate_before_save(self) -> bool:
        """Валидирует форму перед сохранением.

        Returns:
            True если форма валидна или пользователь подтвердил сохранение.
        """
        report = self.validate_form(show_errors=True)

        if report.is_valid:
            return True

        from tkinter import messagebox

        parent = cast(tk.Widget, self._tk_frame)
        result = messagebox.askyesno(
            "Validation",
            "Form contains errors. Save anyway?",
            icon="warning",
            parent=parent,
        )
        return result

    def clear_all(self) -> None:
        """Очищает все страницы и поля."""
        # Remove all pages (in reverse order)
        for i in range(len(self._pages) - 1, -1, -1):
            self.remove_page(i)

        # Clear command stack
        self._command_stack.clear()

        # Reset selection
        self._current_field = None

    def get_pages(self) -> list[DesignerPage]:
        """Возвращает список страниц.

        Returns:
            Список DesignerPage.
        """
        return list(self._pages)

    def get_current_field(self) -> Optional[FormFieldWidget]:
        """Возвращает текущее выбранное поле.

        Returns:
            Текущее поле или None.
        """
        return self._current_field

    def set_on_field_select_callback(
        self,
        callback: Optional[Callable[[Optional[FormFieldWidget]], None]],
    ) -> None:
        """Устанавливает callback выбора поля.

        Args:
            callback: Функция callback(field_widget).
        """
        self._on_field_select_callback = callback

    def set_on_field_create_callback(
        self,
        callback: Optional[Callable[[FormFieldWidget, int], None]],
    ) -> None:
        """Устанавливает callback создания поля.

        Args:
            callback: Функция callback(field_widget, page_index).
        """
        self._on_field_create_callback = callback

    def _on_panel_property_change(self, prop_name: str, value: Any) -> None:
        """Обработчик изменения свойства из PropertyPanel.

        Args:
            prop_name: Имя изменённого свойства.
            value: Новое значение.
        """
        if self._current_field is None:
            return

        field_widget = self._current_field
        page = self._find_field_page(field_widget)
        if page is None:
            return

        # Simple properties routed through existing on_property_change
        if prop_name in ("label", "required", "readonly", "page"):
            self.on_property_change(field_widget.field_id, prop_name, value)
            self._capture_panel_state(field_widget)
            return

        # Position properties
        if prop_name in ("x", "y"):
            old_pos = self._panel_state_cache.get("position")
            if old_pos is None:
                old_pos = field_widget.position
            new_x = old_pos.col if prop_name != "x" else int(value)
            new_y = old_pos.row if prop_name != "y" else int(value)

            from src.gui.core.commands.design_commands import FieldMoveCommand

            move_cmd = FieldMoveCommand(
                page.canvas,
                field_widget.field_id,
                (old_pos.col, old_pos.row),
                (new_x, new_y),
            )
            move_cmd.execute()
            self._command_stack.execute(move_cmd)
            self._capture_panel_state(field_widget)
            return

        if prop_name in ("width", "height"):
            old_pos = self._panel_state_cache.get("position")
            if old_pos is None:
                old_pos = field_widget.position
            new_w = old_pos.width if prop_name != "width" else int(value)
            new_h = old_pos.height if prop_name != "height" else int(value)

            from src.gui.core.commands.design_commands import FieldResizeCommand

            resize_cmd = FieldResizeCommand(
                page.canvas,
                field_widget.field_id,
                (old_pos.width, old_pos.height),
                (new_w, new_h),
            )
            resize_cmd.execute()
            self._command_stack.execute(resize_cmd)
            self._capture_panel_state(field_widget)
            return

        # Other field_def properties wrapped in PropertyChangeCommand
        old_value = self._panel_state_cache.get(prop_name)

        if prop_name == "label_ru":
            old_value = field_widget.field_def.label_i18n.get("ru", "")
        elif prop_name == "field_id":
            old_value = field_widget.field_id
        elif prop_name == "validation_pattern":
            old_value = field_widget.field_def.validation_pattern or ""
        elif prop_name == "min_value":
            old_value = field_widget.field_def.min_value
        elif prop_name == "max_value":
            old_value = field_widget.field_def.max_value
        elif prop_name == "default_value":
            old_value = field_widget.field_def.default_value
        elif prop_name == "autocomplete_source":
            old_value = field_widget.field_def.autocomplete_source or ""
        elif prop_name == "font_family":
            old_value = getattr(field_widget.field_def, "font_family", None)
        elif prop_name == "cpi":
            old_value = getattr(field_widget.field_def, "cpi", None)
        elif prop_name == "lpi":
            old_value = getattr(field_widget.field_def, "lpi", None)

        from src.gui.core.commands.design_commands import PropertyChangeCommand

        prop_cmd = PropertyChangeCommand(
            page.canvas,
            field_widget.field_id,
            prop_name,
            old_value,
            value,
        )
        prop_cmd.execute()
        self._command_stack.execute(prop_cmd)
        self._capture_panel_state(field_widget)

    def _on_panel_field_delete(self) -> None:
        """Обработчик удаления поля из PropertyPanel."""
        if self._current_field is None:
            return

        field_widget = self._current_field
        page = self._find_field_page(field_widget)
        if page is None:
            return

        from src.gui.core.commands.design_commands import FieldDeleteCommand

        cmd = FieldDeleteCommand(page.canvas, field_widget)
        cmd.execute()
        self._command_stack.execute(cmd)

        # Remove from page fields list
        if field_widget in page.fields:
            page.fields.remove(field_widget)

        # Clear selection
        self.on_field_select(None)

    def _on_panel_field_duplicate(self) -> None:
        """Обработчик дублирования поля из PropertyPanel."""
        if self._current_field is None:
            return

        field_widget = self._current_field
        page = self._find_field_page(field_widget)
        if page is None:
            return

        old_def = field_widget.field_def
        new_field_id = f"{old_def.field_id}_copy_{uuid.uuid4().hex[:4]}"
        new_label = f"{old_def.label} (copy)"
        new_def = replace(
            old_def,
            field_id=new_field_id,
            label=new_label,
        )

        new_x = field_widget.position.col + 1
        new_y = field_widget.position.row + 1
        self.on_field_create(
            new_def.field_type,
            new_x,
            new_y,
            page.index,
            field_id=new_def.field_id,
            label=new_def.label,
            required=new_def.required,
        )

    def _find_field_page(self, field_widget: FormFieldWidget) -> Optional[DesignerPage]:
        """Находит страницу, на которой расположено поле.

        Args:
            field_widget: Поле для поиска.

        Returns:
            DesignerPage или None.
        """
        for page in self._pages:
            if field_widget in page.fields:
                return page
        return None

    def _refresh_panel_after_command(self) -> None:
        """Обновляет PropertyPanel после undo/redo."""
        if self._current_field is not None:
            self._update_property_panel(self._current_field)

    # =====================================================================
    # PRIVATE METHODS
    # =====================================================================

    def _on_canvas_field_select(self, field_id: Optional[str]) -> None:
        """Callback выбора поля от canvas.

        Args:
            field_id: ID выбранного поля или None.
        """
        if field_id is None:
            self.on_field_select(None)
            return

        # Find field
        for page in self._pages:
            for fld in page.fields:
                if fld.field_id == field_id:
                    self.on_field_select(fld)
                    return

    def _on_canvas_field_move(self, field_id: str, new_x: int, new_y: int) -> None:
        """Callback перемещения поля от canvas.

        Args:
            field_id: ID поля.
            new_x: Новая X позиция.
            new_y: Новая Y позиция.
        """
        self.on_field_move(field_id, new_x, new_y)

    def _snap_to_grid(self, value: int) -> int:
        """Привязывает значение к сетке.

        Args:
            value: Исходное значение.

        Returns:
            Значение, округленное до ближайшей ячейки.
        """
        # Snap to nearest grid cell (assuming cell size ~1)
        return round(value)

    def _validate_field_position(
        self,
        page_index: int,
        field_id: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> tuple[bool, str]:
        """Валидирует позицию поля.

        Args:
            page_index: Индекс страницы.
            field_id: ID поля (или пустая строка для нового).
            x: Позиция X.
            y: Позиция Y.
            width: Ширина.
            height: Высота.

        Returns:
            (is_valid, error_message)
        """
        if not 0 <= page_index < len(self._pages):
            return (False, "Invalid page index")

        page = self._pages[page_index]

        # Use canvas validation
        return page.canvas.validate_field_position(field_id, x, y, width, height)

    def _fields_overlap(self, field1: FormFieldWidget, field2: FormFieldWidget) -> bool:
        """Проверяет перекрытие двух полей.

        Args:
            field1: Первое поле.
            field2: Второе поле.

        Returns:
            True если поля перекрываются.
        """
        p1 = field1.position
        p2 = field2.position

        return (
            p1.col < p2.col + p2.width
            and p1.col + p1.width > p2.col
            and p1.row < p2.row + p2.height
            and p1.row + p1.height > p2.row
        )

    def _update_property_panel(self, field_widget: Optional[FormFieldWidget]) -> None:
        """Обновляет панель свойств для выбранного поля.

        Args:
            field_widget: Выбранное поле или None.
        """
        if self._property_panel_instance is not None:
            self._property_panel_instance.bind_to_field(field_widget)
            self._capture_panel_state(field_widget)

    def _capture_panel_state(self, field_widget: Optional[FormFieldWidget]) -> None:
        """Сохраняет snapshot текущего поля для undo/redo.

        Args:
            field_widget: Поле для snapshot или None.
        """
        self._panel_state_cache.clear()
        if field_widget is None:
            return
        self._panel_state_cache["field_id"] = field_widget.field_id
        self._panel_state_cache["position"] = field_widget.position
        self._panel_state_cache["label"] = field_widget.field_def.label
        self._panel_state_cache["required"] = field_widget.field_def.required
        self._panel_state_cache["readonly"] = field_widget.field_def.readonly
        self._panel_state_cache["validation_pattern"] = field_widget.field_def.validation_pattern
        self._panel_state_cache["min_value"] = field_widget.field_def.min_value
        self._panel_state_cache["max_value"] = field_widget.field_def.max_value
        self._panel_state_cache["default_value"] = field_widget.field_def.default_value
        self._panel_state_cache["autocomplete_source"] = field_widget.field_def.autocomplete_source
        label_ru = field_widget.field_def.label_i18n.get("ru", "")
        self._panel_state_cache["label_ru"] = label_ru

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        # Clear pages
        self.clear_all()

        # Unmount property panel
        if self._property_panel_instance is not None:
            self._property_panel_instance.unmount()
            self._property_panel_instance = None

        # Clear references
        self._left_frame = None
        self._center_frame = None
        self._right_frame = None
        self._bottom_frame = None
        self._outer_canvas = None
        self._scrollbar = None
        self._scrollable_frame = None
        self._field_palette = None
        self._property_panel = None
        self._current_field = None
        self._panel_state_cache.clear()

        super()._cleanup()

    def show(self) -> None:
        """Показывает виджет дизайнера."""
        if self._tk_widget is not None:
            self._tk_widget.pack(fill=tk.BOTH, expand=True)

    def hide(self) -> None:
        """Скрывает виджет дизайнера."""
        if self._tk_widget is not None:
            self._tk_widget.pack_forget()


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = [
    "DesignerTab",
    "DesignerPage",
    "FieldPaletteItem",
]
