"""Панель предпросмотра ESC/P вывода для Form Designer.

Модуль предоставляет панель предпросмотра с двумя режимами отображения:
- Визуальный предпросмотр: Canvas-рендеринг ESC/P команд
- Hex дамп: Подсвеченный hex-вид байтов с ASCII представлением

Features:
    - Tabbed интерфейс (ttk.Notebook)
    - Навигация по страницам и смещениям
    - Zoom in/out для визуального предпросмотра
    - Подсветка ESC команд в hex дампе
    - Интеграция с DocumentRenderer

Example:
    >>> from src.gui.form_designer.preview_panel import PreviewPanel, PreviewData
    >>> panel = PreviewPanel(parent=parent_frame, controller=doc_controller)
    >>> panel.mount(parent_frame)
    >>>
    >>> # Установить данные для предпросмотра
    >>> data = PreviewData(
    ...     escp_bytes=escp_data,
    ...     document_name="Test Document",
    ...     page_number=1,
    ...     total_pages=3
    ... )
    >>> panel.set_preview_data(data)
    >>>
    >>> # Переключить на hex вид
    >>> panel.show_hex_view()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import TYPE_CHECKING, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import (
    DocumentControllerProtocol,
    EventProtocol,
)

if TYPE_CHECKING:
    pass

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

HEX_BYTES_PER_LINE: Final[int] = 16
"""Количество байтов в одной строке hex дампа."""

# Colors for ESC/P preview (from escp_preview_widget.py)
PREVIEW_BG_COLOR: Final[str] = "#1e1e1e"
PREVIEW_FG_COLOR: Final[str] = "#d4d4d4"
PREVIEW_CMD_COLOR: Final[str] = "#569cd6"
PREVIEW_FF_COLOR: Final[str] = "#ce9178"
PREVIEW_SELECT_BG: Final[str] = "#264f78"
PREVIEW_FONT: Final[tuple[str, int]] = ("Courier New", 10)
PREVIEW_CMD_FONT: Final[tuple[str, int, str]] = ("Courier New", 10, "bold")

# ESC/P constants
ESC_BYTE: Final[int] = 0x1B
FF_BYTE: Final[int] = 0x0C
CR_BYTE: Final[int] = 0x0D
LF_BYTE: Final[int] = 0x0A

# Zoom limits
MIN_ZOOM: Final[float] = 0.5
MAX_ZOOM: Final[float] = 2.0
ZOOM_STEP: Final[float] = 0.1


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class PreviewData:
    """Данные для предпросмотра документа.

    Attributes:
        escp_bytes: ESC/P байты документа.
        document_name: Имя документа для отображения.
        page_number: Текущий номер страницы (1-based).
        total_pages: Общее количество страниц.

    Example:
        >>> data = PreviewData(
        ...     escp_bytes=b"\x1b@Hello World\x0c",
        ...     document_name="Test Document",
        ...     page_number=1,
        ...     total_pages=3
        ... )
        >>> data.document_name
        'Test Document'
    """

    escp_bytes: bytes
    document_name: str
    page_number: int
    total_pages: int


# =============================================================================
# PREVIEW PANEL
# =============================================================================


class PreviewPanel(BaseWidget):
    """Панель предпросмотра ESC/P вывода с hex дампом.

    Реализует WidgetProtocol, предоставляя tabbed интерфейс с двумя видами:
    - "Визуальный предпросмотр": Canvas-рендеринг ESC/P команд
    - "Hex дамп": Подсвеченный hex-вид с ASCII представлением

    Attributes:
        widget_id: Уникальный идентификатор виджета ('preview_panel').
        _controller: Ссылка на DocumentController.
        _current_data: Текущие данные предпросмотра.
        _zoom: Текущий масштаб визуального предпросмотра.

    Example:
        >>> panel = PreviewPanel(parent=root, controller=controller)
        >>> panel.mount(parent_frame)
        >>> panel.set_preview_data(preview_data)
        >>> panel.show_hex_view()
    """

    def __init__(
        self,
        parent: tk.Widget,
        controller: DocumentControllerProtocol,
    ) -> None:
        """Инициализация панели предпросмотра.

        Args:
            parent: Родительский виджет.
            controller: Контроллер документа для callbacks.
        """
        super().__init__(widget_id="preview_panel", controller=controller)

        self._parent: tk.Widget = parent
        self._controller: DocumentControllerProtocol = controller

        # State
        self._current_data: Optional[PreviewData] = None
        self._zoom: float = 1.0
        self._current_page: int = 1

        # UI components (initialized in _create_tk_widget)
        self._notebook: Optional[ttk.Notebook] = None
        self._visual_frame: Optional[tk.Frame] = None
        self._hex_frame: Optional[tk.Frame] = None
        self._visual_canvas: Optional[tk.Canvas] = None
        self._hex_text: Optional[tk.Text] = None
        self._page_label: Optional[tk.Label] = None
        self._zoom_label: Optional[tk.Label] = None

        # Scrollbars
        self._visual_v_scroll: Optional[tk.Scrollbar] = None
        self._visual_h_scroll: Optional[tk.Scrollbar] = None
        self._hex_v_scroll: Optional[tk.Scrollbar] = None
        self._hex_h_scroll: Optional[tk.Scrollbar] = None

        # Bottom toolbar buttons
        self._bottom_toolbar: Optional[tk.Frame] = None
        self._refresh_btn: Optional[tk.Button] = None
        self._print_test_btn: Optional[tk.Button] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Создаёт tabbed интерфейс с двумя вкладками:
        - Визуальный предпросмотр (Canvas)
        - Hex дамп (Text widget)

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Корневой Frame с tabbed интерфейсом.
        """
        main_frame = tk.Frame(parent, bg="#f5f5f5")
        main_frame.rowconfigure(0, weight=0)  # Toolbar
        main_frame.rowconfigure(1, weight=1)  # Notebook
        main_frame.rowconfigure(2, weight=0)  # Bottom toolbar
        main_frame.columnconfigure(0, weight=1)

        # Create toolbar
        self._create_toolbar(main_frame)

        # Create notebook
        self._notebook = ttk.Notebook(main_frame)
        self._notebook.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Create tabs
        self._create_visual_tab()
        self._create_hex_tab()

        # Create bottom toolbar
        self._create_bottom_toolbar(main_frame)

        return main_frame

    def _create_toolbar(self, parent: tk.Frame) -> None:
        """Создаёт панель инструментов с навигацией.

        Args:
            parent: Родительский Frame.
        """
        toolbar = tk.Frame(parent, bg="#e0e0e0", height=32)
        toolbar.grid(row=0, column=0, sticky="ew", padx=5, pady=(5, 0))
        toolbar.grid_propagate(False)

        # Navigation frame
        nav_frame = tk.Frame(toolbar, bg="#e0e0e0")
        nav_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        # Prev page button
        prev_btn = tk.Button(
            nav_frame,
            text="←",
            width=3,
            command=lambda: self.go_to_page(self._current_page - 1),
            bg="#d0d0d0",
        )
        prev_btn.pack(side=tk.LEFT, padx=2)

        # Page label
        self._page_label = tk.Label(
            nav_frame,
            text="Page 1/1",
            bg="#e0e0e0",
            width=15,
        )
        self._page_label.pack(side=tk.LEFT, padx=5)

        # Next page button
        next_btn = tk.Button(
            nav_frame,
            text="→",
            width=3,
            command=lambda: self.go_to_page(self._current_page + 1),
            bg="#d0d0d0",
        )
        next_btn.pack(side=tk.LEFT, padx=2)

        # Zoom frame
        zoom_frame = tk.Frame(toolbar, bg="#e0e0e0")
        zoom_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(20, 5))

        # Zoom out button
        zoom_out_btn = tk.Button(
            zoom_frame,
            text="−",
            width=3,
            command=self.zoom_out,
            bg="#d0d0d0",
        )
        zoom_out_btn.pack(side=tk.LEFT, padx=2)

        # Zoom label
        self._zoom_label = tk.Label(
            zoom_frame,
            text="100%",
            bg="#e0e0e0",
            width=6,
        )
        self._zoom_label.pack(side=tk.LEFT, padx=5)

        # Zoom in button
        zoom_in_btn = tk.Button(
            zoom_frame,
            text="+",
            width=3,
            command=self.zoom_in,
            bg="#d0d0d0",
        )
        zoom_in_btn.pack(side=tk.LEFT, padx=2)

        # Document name label
        self._doc_name_label = tk.Label(
            toolbar,
            text="",
            bg="#e0e0e0",
            fg="#666666",
            font=("Segoe UI", 9),
        )
        self._doc_name_label.pack(side=tk.RIGHT, padx=10)

    def _create_bottom_toolbar(self, parent: tk.Frame) -> None:
        """Создаёт нижнюю панель с кнопками Refresh и Print Test.

        Args:
            parent: Родительский Frame.
        """
        self._bottom_toolbar = tk.Frame(parent, bg="#e0e0e0", height=32)
        self._bottom_toolbar.grid(row=2, column=0, sticky="ew", padx=5, pady=(0, 5))
        self._bottom_toolbar.grid_propagate(False)

        self._refresh_btn = tk.Button(
            self._bottom_toolbar,
            text="Refresh",
            width=10,
            command=self._on_refresh_clicked,
            state=tk.DISABLED,
            bg="#d0d0d0",
        )
        self._refresh_btn.pack(side=tk.LEFT, padx=5, pady=3)

        self._print_test_btn = tk.Button(
            self._bottom_toolbar,
            text="Print Test",
            width=10,
            command=self._on_print_test_clicked,
            state=tk.DISABLED,
            bg="#d0d0d0",
        )
        self._print_test_btn.pack(side=tk.LEFT, padx=5, pady=3)

    def _on_refresh_clicked(self) -> None:
        """Перегенерирует hex dump и ASCII preview из текущих данных."""
        if self._current_data is not None:
            self._render_visual_preview()
            self._render_hex_dump()
            logger.debug("Preview refreshed")

    def _on_print_test_clicked(self) -> None:
        """Диспетчирует событие печати тестового ESC/P output через контроллер.

        Отправляет команду "print_test" с текущими ESC/P байтами.
        Фактическая печать зависит от реализации обработчика в контроллере.
        """
        if self._current_data is None or self._controller is None:
            return

        escp_bytes = self._current_data.escp_bytes
        document_name = self._current_data.document_name

        self._controller.dispatch(
            "print_test",
            escp_bytes=escp_bytes,
            document_name=document_name,
        )
        logger.debug("Print Test dispatched for document: %s", document_name)

    def _update_button_states(self) -> None:
        """Обновляет доступность кнопок в зависимости от наличия preview_data."""
        state = tk.NORMAL if self._current_data is not None else tk.DISABLED
        if self._refresh_btn is not None:
            self._refresh_btn.config(state=state)  # type: ignore[call-overload]
        if self._print_test_btn is not None:
            self._print_test_btn.config(state=state)  # type: ignore[call-overload]

    def _create_visual_tab(self) -> None:
        """Создаёт вкладку визуального предпросмотра."""
        if self._notebook is None:
            return

        self._visual_frame = tk.Frame(self._notebook, bg="#ffffff")
        self._notebook.add(self._visual_frame, text="Visual Preview")

        # Configure grid
        self._visual_frame.rowconfigure(0, weight=1)
        self._visual_frame.columnconfigure(0, weight=1)
        self._visual_frame.columnconfigure(1, weight=0)

        # Create canvas
        self._visual_canvas = tk.Canvas(
            self._visual_frame,
            bg=PREVIEW_BG_COLOR,
            highlightthickness=0,
        )
        self._visual_canvas.grid(row=0, column=0, sticky="nsew")

        # Vertical scrollbar
        self._visual_v_scroll = tk.Scrollbar(
            self._visual_frame,
            orient=tk.VERTICAL,
            command=self._visual_canvas.yview,
        )
        self._visual_v_scroll.grid(row=0, column=1, sticky="ns")

        # Horizontal scrollbar
        self._visual_h_scroll = tk.Scrollbar(
            self._visual_frame,
            orient=tk.HORIZONTAL,
            command=self._visual_canvas.xview,
        )
        self._visual_h_scroll.grid(row=1, column=0, sticky="ew")

        # Configure canvas scroll
        self._visual_canvas.configure(
            yscrollcommand=self._visual_v_scroll.set,
            xscrollcommand=self._visual_h_scroll.set,
        )

    def _create_hex_tab(self) -> None:
        """Создаёт вкладку hex дампа."""
        if self._notebook is None:
            return

        self._hex_frame = tk.Frame(self._notebook, bg=PREVIEW_BG_COLOR)
        self._notebook.add(self._hex_frame, text="Hex Dump")

        # Configure grid
        self._hex_frame.rowconfigure(0, weight=1)
        self._hex_frame.columnconfigure(0, weight=1)
        self._hex_frame.columnconfigure(1, weight=0)

        # Create text widget
        self._hex_text = tk.Text(
            self._hex_frame,
            wrap=tk.NONE,
            font=PREVIEW_FONT,
            bg=PREVIEW_BG_COLOR,
            fg=PREVIEW_FG_COLOR,
            selectbackground=PREVIEW_SELECT_BG,
            insertbackground=PREVIEW_FG_COLOR,
            padx=10,
            pady=10,
        )
        self._hex_text.grid(row=0, column=0, sticky="nsew")

        # Configure tags for highlighting
        self._hex_text.tag_configure(
            "esc_command",
            foreground=PREVIEW_CMD_COLOR,
            font=PREVIEW_CMD_FONT,
        )
        self._hex_text.tag_configure(
            "form_feed",
            foreground=PREVIEW_FF_COLOR,
            font=PREVIEW_CMD_FONT,
        )
        self._hex_text.tag_configure(
            "offset",
            foreground="#858585",
            font=PREVIEW_FONT,
        )
        self._hex_text.tag_configure(
            "ascii",
            foreground="#d4d4d4",
            font=PREVIEW_FONT,
        )

        # Vertical scrollbar
        self._hex_v_scroll = tk.Scrollbar(
            self._hex_frame,
            orient=tk.VERTICAL,
            command=self._hex_text.yview,
        )
        self._hex_v_scroll.grid(row=0, column=1, sticky="ns")

        # Horizontal scrollbar
        self._hex_h_scroll = tk.Scrollbar(
            self._hex_frame,
            orient=tk.HORIZONTAL,
            command=self._hex_text.xview,
        )
        self._hex_h_scroll.grid(row=1, column=0, sticky="ew")

        # Configure text scroll
        self._hex_text.configure(
            yscrollcommand=self._hex_v_scroll.set,
            xscrollcommand=self._hex_h_scroll.set,
        )

    def _setup_bindings(self) -> None:
        """Настраивает keyboard bindings."""
        if self._tk_widget is None:
            return

        # Keyboard navigation
        self._tk_widget.bind("<Prior>", lambda e: self.go_to_page(self._current_page - 1))
        self._tk_widget.bind("<Next>", lambda e: self.go_to_page(self._current_page + 1))
        self._tk_widget.bind("<Home>", lambda e: self.go_to_page(1))
        self._tk_widget.bind("<End>", lambda e: self._go_to_last_page())
        self._tk_widget.bind("<Control-plus>", lambda e: self.zoom_in())
        self._tk_widget.bind("<Control-minus>", lambda e: self.zoom_out())

    def _go_to_last_page(self) -> None:
        """Переходит на последнюю страницу."""
        if self._current_data is not None:
            self.go_to_page(self._current_data.total_pages)

    def set_preview_data(self, data: PreviewData) -> None:
        """Устанавливает данные для предпросмотра.

        Args:
            data: Данные предпросмотра с ESC/P байтами.

        Example:
            >>> data = PreviewData(escp_bytes=b"...", document_name="Doc",
            ...                    page_number=1, total_pages=3)
            >>> panel.set_preview_data(data)
        """
        self._current_data = data
        self._current_page = data.page_number

        # Update document name label
        if hasattr(self, "_doc_name_label") and self._doc_name_label is not None:
            self._doc_name_label.config(text=data.document_name)

        # Update page label
        self._update_page_label()

        # Render visual preview
        self._render_visual_preview()

        # Render hex dump
        self._render_hex_dump()

        # Update button states
        self._update_button_states()

        logger.debug(
            f"Preview data set: {data.document_name}, "
            f"page {data.page_number}/{data.total_pages}, "
            f"{len(data.escp_bytes)} bytes"
        )

    def _update_page_label(self) -> None:
        """Обновляет метку текущей страницы."""
        if self._page_label is not None and self._current_data is not None:
            self._page_label.config(
                text=f"Page {self._current_page}/{self._current_data.total_pages}"
            )

    def _render_visual_preview(self) -> None:
        """Рендерит визуальный предпросмотр на Canvas."""
        if self._visual_canvas is None or self._current_data is None:
            return

        self._visual_canvas.delete("all")

        escp_bytes = self._current_data.escp_bytes
        x_offset = 50
        y_offset = 30
        line_height = int(20 * self._zoom)
        char_width = int(10 * self._zoom)

        current_x = x_offset
        current_y = y_offset

        i = 0
        while i < len(escp_bytes):
            byte = escp_bytes[i]

            if byte == ESC_BYTE:
                # ESC command - render in command color
                cmd_text = self._get_esc_command_text(escp_bytes, i)
                self._visual_canvas.create_text(
                    current_x,
                    current_y,
                    text=cmd_text,
                    fill=PREVIEW_CMD_COLOR,
                    font=("Courier New", int(10 * self._zoom)),
                    anchor=tk.W,
                )
                current_x += len(cmd_text) * char_width
                i = self._skip_esc_command(escp_bytes, i)

            elif byte == FF_BYTE:
                # Form feed
                self._visual_canvas.create_text(
                    current_x,
                    current_y,
                    text="[FF]",
                    fill=PREVIEW_FF_COLOR,
                    font=("Courier New", int(10 * self._zoom), "bold"),
                    anchor=tk.W,
                )
                current_y += line_height * 2
                current_x = x_offset
                i += 1

            elif byte in (CR_BYTE, LF_BYTE):
                # Line break
                if byte == CR_BYTE and i + 1 < len(escp_bytes) and escp_bytes[i + 1] == LF_BYTE:
                    i += 2
                else:
                    i += 1
                current_y += line_height
                current_x = x_offset

            elif 32 <= byte < 127:
                # Printable ASCII
                char = chr(byte)
                self._visual_canvas.create_text(
                    current_x,
                    current_y,
                    text=char,
                    fill=PREVIEW_FG_COLOR,
                    font=("Courier New", int(10 * self._zoom)),
                    anchor=tk.W,
                )
                current_x += char_width
                i += 1

            else:
                # Non-printable
                self._visual_canvas.create_text(
                    current_x,
                    current_y,
                    text="·",
                    fill="#666666",
                    font=("Courier New", int(10 * self._zoom)),
                    anchor=tk.W,
                )
                current_x += char_width
                i += 1

                # Wrap long lines
            if current_x > int(700 * self._zoom):
                current_y += line_height
                current_x = x_offset

        # Update scroll region
        self._visual_canvas.configure(scrollregion=self._visual_canvas.bbox("all"))

    def _get_esc_command_text(self, escp_bytes: bytes, start: int) -> str:
        """Возвращает текстовое представление ESC команды.

        Args:
            escp_bytes: ESC/P байты.
            start: Начальная позиция (на ESC байте).

        Returns:
            Текстовое представление команды.
        """
        if start + 1 >= len(escp_bytes):
            return "[ESC]"

        cmd = escp_bytes[start + 1]

        # Parameterized commands (0x20-0x7E range)
        if 0x20 <= cmd <= 0x7E:
            param_start = start + 2
            param_end = param_start
            while param_end < len(escp_bytes) and escp_bytes[param_end] >= 0x20:
                param_end += 1
            param = escp_bytes[param_start:param_end]
            if param:
                return f"[ESC {chr(cmd)} {param.hex().upper()}]"
            return f"[ESC {chr(cmd)}]"

        return f"[ESC 0x{cmd:02X}]"

    def _skip_esc_command(self, escp_bytes: bytes, start: int) -> int:
        """Возвращает позицию после ESC команды.

        Args:
            escp_bytes: ESC/P байты.
            start: Начальная позиция (на ESC байте).

        Returns:
            Позиция после команды.
        """
        if start + 1 >= len(escp_bytes):
            return start + 1

        cmd = escp_bytes[start + 1]

        # Parameterized commands
        if 0x20 <= cmd <= 0x7E:
            param_start = start + 2
            param_end = param_start
            while param_end < len(escp_bytes) and escp_bytes[param_end] >= 0x20:
                param_end += 1
            return param_end

        return start + 2

    def _render_hex_dump(self) -> None:
        """Рендерит hex дамп в текстовом виджете."""
        if self._hex_text is None or self._current_data is None:
            return

        self._hex_text.delete("1.0", tk.END)

        escp_bytes = self._current_data.escp_bytes

        for offset in range(0, len(escp_bytes), HEX_BYTES_PER_LINE):
            line_bytes = escp_bytes[offset : offset + HEX_BYTES_PER_LINE]

            # Offset
            self._hex_text.insert(tk.END, f"{offset:08X}  ", "offset")

            # Hex bytes
            for i, byte in enumerate(line_bytes):
                if i > 0:
                    self._hex_text.insert(tk.END, " ")
                    if i == HEX_BYTES_PER_LINE // 2:
                        self._hex_text.insert(tk.END, " ")

                # Determine tag based on byte type
                tag = ""
                if byte == ESC_BYTE:
                    tag = "esc_command"
                elif byte == FF_BYTE:
                    tag = "form_feed"

                self._hex_text.insert(tk.END, f"{byte:02X}", tag)

            # Padding for last line
            remaining = HEX_BYTES_PER_LINE - len(line_bytes)
            if remaining > 0:
                pad = "   " * remaining
                if remaining > HEX_BYTES_PER_LINE // 2:
                    pad = " " + pad
                self._hex_text.insert(tk.END, pad)

            # ASCII representation
            self._hex_text.insert(tk.END, "  |", "offset")
            for byte in line_bytes:
                if 32 <= byte < 127:
                    self._hex_text.insert(tk.END, chr(byte), "ascii")
                elif byte == ESC_BYTE:
                    self._hex_text.insert(tk.END, "·", "esc_command")
                elif byte == FF_BYTE:
                    self._hex_text.insert(tk.END, "·", "form_feed")
                else:
                    self._hex_text.insert(tk.END, "·", "offset")
            self._hex_text.insert(tk.END, "|\n", "offset")

    def show_hex_view(self) -> None:
        """Переключает на вкладку hex дампа.

        Example:
            >>> panel.show_hex_view()
        """
        if self._notebook is not None:
            self._notebook.select(1)  # type: ignore[no-untyped-call] # Hex tab is second

    def show_visual_preview(self) -> None:
        """Переключает на вкладку визуального предпросмотра.

        Example:
            >>> panel.show_visual_preview()
        """
        if self._notebook is not None:
            self._notebook.select(0)  # type: ignore[no-untyped-call] # Visual tab is first

    def zoom_in(self) -> None:
        """Увеличивает масштаб визуального предпросмотра.

        Example:
            >>> panel.zoom_in()
        """
        self._zoom = min(MAX_ZOOM, self._zoom + ZOOM_STEP)
        self._update_zoom_label()
        self._render_visual_preview()

    def zoom_out(self) -> None:
        """Уменьшает масштаб визуального предпросмотра.

        Example:
            >>> panel.zoom_out()
        """
        self._zoom = max(MIN_ZOOM, self._zoom - ZOOM_STEP)
        self._update_zoom_label()
        self._render_visual_preview()

    def _update_zoom_label(self) -> None:
        """Обновляет метку масштаба."""
        if self._zoom_label is not None:
            self._zoom_label.config(text=f"{int(self._zoom * 100)}%")

    def go_to_page(self, page_number: int) -> None:
        """Переходит на указанную страницу.

        Args:
            page_number: Номер страницы (1-based).

        Example:
            >>> panel.go_to_page(3)
        """
        if self._current_data is None:
            return

        # Validate page number
        page_number = max(1, min(page_number, self._current_data.total_pages))

        if page_number != self._current_page:
            self._current_page = page_number
            self._update_page_label()
            # Re-render with new page context
            self._render_visual_preview()
            logger.debug(f"Navigated to page {page_number}")

    def go_to_offset(self, offset: int) -> None:
        """Переходит к указанному смещению в hex дампе.

        Args:
            offset: Байтовое смещение.

        Example:
            >>> panel.go_to_offset(0x100)
        """
        if self._hex_text is None:
            return

        # Calculate line number
        line_num = offset // HEX_BYTES_PER_LINE + 1

        # Scroll to line
        self._hex_text.see(f"{line_num}.0")

        # Highlight the line
        self._hex_text.tag_remove("highlight", "1.0", tk.END)
        self._hex_text.tag_configure(
            "highlight",
            background=PREVIEW_SELECT_BG,
        )
        self._hex_text.tag_add("highlight", f"{line_num}.0", f"{line_num}.end")

        logger.debug(f"Navigated to offset 0x{offset:X} (line {line_num})")

    def _highlight_escp_commands(self, hex_text: str) -> str:
        """Подсвечивает ESC команды в hex тексте.

        Этот метод используется для пост-обработки hex текста
        с добавлением ANSI цветовых кодов или HTML тегов.

        Args:
            hex_text: Исходный hex текст.

        Returns:
            Текст с подсвеченными ESC командами.

        Note:
            В текущей реализации используется Tkinter tag-based
            highlighting в _render_hex_dump(). Этот метод
            предоставлен для совместимости с требованиями API.

        Example:
            >>> text = "1B40 4865 6C6C 6F"
            >>> highlighted = panel._highlight_escp_commands(text)
        """
        # In the current implementation, highlighting is done via Tkinter tags
        # This method exists for API compatibility and potential future use
        # with other rendering backends (HTML, ANSI terminal, etc.)
        return hex_text

    def handle_event(self, event: EventProtocol) -> bool:
        """Обрабатывает входящее событие.

        Args:
            event: Событие для обработки.

        Returns:
            True если событие обработано, False для передачи дальше.
        """
        # Preview panel doesn't process specific events
        # but could handle zoom/scroll events in the future
        return False

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self._current_data = None
        self._notebook = None
        self._visual_frame = None
        self._hex_frame = None
        self._visual_canvas = None
        self._hex_text = None
        logger.debug("PreviewPanel cleanup completed")


__all__ = [
    "PreviewPanel",
    "PreviewData",
    "HEX_BYTES_PER_LINE",
]
