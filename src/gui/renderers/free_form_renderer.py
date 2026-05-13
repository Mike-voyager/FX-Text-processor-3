"""FreeFormRenderer для FX Text Processor 3.

Реализует WYSIWYG редактор для свободного текстового формата с поддержкой ESC/P.
- tk.Text виджет с monospace шрифтом
- Поддержка CPI (10, 12, 15, 17, 20)
- Tag-based форматирование (bold, italic, underline)
- Интеграция с CommandStack для undo/redo
- Security: wipe_sensitive_data, hide_content/restore_content

Example:
    >>> renderer = FreeFormRenderer(
    ...     widget_id="free_form_1",
    ...     controller=my_controller,
    ...     command_stack=command_stack,
    ... )
    >>> renderer.mount(parent_frame)
    >>> doc = FreeFormDocument(content="Hello World", cpi=10)
    >>> renderer.render(doc)
    >>> renderer.apply_format("bold", "1.0", "1.5")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Final, Optional, Set, Tuple

from src.documents.types.document_type import DocumentMode
from src.gui.components.base.widget import BaseWidget
from src.gui.components.format_toolbar import FormatToolbar
from src.gui.components.paper_visualization import (
    LineProperties,
    PaperVisualizationWidget,
)
from src.gui.core.commands import CommandStack, DeleteTextCommand, InsertTextCommand
from src.gui.core.commands.barcode_commands import (
    InsertBarcodeCommand,
    InsertPlaceholderCommand,
    InsertQRCommand,
)
from src.gui.core.commands.command import Command
from src.gui.core.commands.text_commands import DEFAULT_CPI, SetTextCommand
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.gui.layout.layout_constants import ESCP_COLS, ESCP_ROWS
from src.gui.renderers.barcode_canvas_renderer import (
    BarcodeRenderMode,
    create_barcode_renderer,
)
from src.gui.renderers.protocols import implements
from src.gui.renderers.qr_canvas_renderer import QRRenderMode, create_qr_renderer

if TYPE_CHECKING:
    pass

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

VALID_CPI_INT: Final[frozenset[int]] = frozenset({10, 12, 15, 17, 20})
"""Допустимые целочисленные значения CPI."""

DEFAULT_FONT_FAMILY: Final[str] = "Courier"
"""Шрифт по умолчанию (monospace)."""

FALLBACK_FONT_FAMILY: Final[str] = "Consolas"
"""Fallback шрифт если Courier недоступен."""

TEXT_BG_COLOR: Final[str] = "white"
"""Фоновый цвет текстового поля."""

TEXT_FG_COLOR: Final[str] = "black"
"""Цвет текста."""

TEXT_SELECT_BG: Final[str] = "#0078D7"
"""Цвет выделения (Windows blue)."""

MAX_TEXT_LENGTH: Final[int] = 100_000
"""Максимальная длина текста (security: DoS protection)."""

# Shadow row styling
SHADOW_ROW_BG: Final[str] = "#f0f0f0"
"""Фоновый цвет shadow row (строка после double-height)."""

SHADOW_ROW_FG: Final[str] = "#cccccc"
"""Цвет текста shadow row."""

# Subscript / Superscript offsets
SUBSCRIPT_OFFSET: Final[int] = -3
"""Смещение baseline subscript (пиксели)."""

SUPERSCRIPT_OFFSET: Final[int] = 3
"""Смещение baseline superscript (пиксели)."""

SCRIPT_FONT_DELTA: Final[int] = -2
"""Изменение размера шрифта для script (subscript/superscript)."""

# CPI to pixel width mapping (approximate for 96 DPI)
CPI_PIXEL_WIDTH: Final[dict[int, int]] = {
    10: 96,  # 10 CPI = ~9.6pt font
    12: 80,  # 12 CPI = ~8pt font
    15: 64,  # 15 CPI = ~6.4pt font
    17: 56,  # 17 CPI = ~5.6pt font
    20: 48,  # 20 CPI = ~4.8pt font
}

# CPI to horizontal scroll amount (in pixels)
CPI_SCROLL_AMOUNT: Final[dict[int, int]] = {
    10: 96,
    12: 80,
    15: 64,
    17: 56,
    20: 48,
}


# =============================================================================
# FORMAT RANGE
# =============================================================================


@dataclass(frozen=True)
class FormatRange:
    """Диапазон форматирования текста.

    Attributes:
        start: Начальная позиция ("line.col", например "1.0").
        end: Конечная позиция ("line.col", например "1.5").
        tag: Тег форматирования ("bold", "italic", "underline").

    Example:
        >>> fmt = FormatRange("1.0", "1.10", "bold")
        >>> fmt.start
        '1.0'
    """

    start: str
    end: str
    tag: str


# =============================================================================
# FREE FORM DOCUMENT
# =============================================================================


@dataclass
class FreeFormDocument:
    """Модель документа свободной формы.

    Attributes:
        content: Текстовое содержимое документа.
        cpi: Characters per inch (10, 12, 15, 17, 20).
        formatting: Список диапазонов форматирования.

    Example:
        >>> doc = FreeFormDocument(content="Hello World", cpi=12)
        >>> doc.content
        'Hello World'
    """

    content: str = ""
    cpi: int = 10
    formatting: list[FormatRange] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if self.cpi not in VALID_CPI_INT:
            self.cpi = int(DEFAULT_CPI)


# =============================================================================
# FREE FORM RENDERER
# =============================================================================


@implements(Any)
class FreeFormRenderer(BaseWidget):
    """Рендерер для свободного текстового редактирования.

    Реализует GUI текстовый редактор с поддержкой ESC/P форматирования:
    - tk.Text виджет с monospace шрифтом
    - Scrollbars (horizontal + vertical)
    - CPI support (10, 12, 15, 17, 20)
    - Tag-based форматирование
    - Command Pattern интеграция
    - Event callbacks для изменений

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        command_stack: Стек команд для undo/redo.

    Example:
        >>> renderer = FreeFormRenderer(
        ...     widget_id="editor_1",
        ...     command_stack=CommandStack(),
        ... )
        >>> renderer.mount(parent_frame)
        >>> renderer.set_text("Hello World")
        >>> renderer.apply_cpi(12)

    Version: 1.0
    """

    def __init__(
        self,
        widget_id: str = "free_form_renderer",
        controller: Optional[ControllerProtocol] = None,
        command_stack: Optional[CommandStack] = None,
    ) -> None:
        """Инициализация FreeFormRenderer.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер для callbacks.
            command_stack: Опциональный CommandStack для undo/redo.

        Example:
            >>> renderer = FreeFormRenderer(
            ...     widget_id="my_editor",
            ...     command_stack=CommandStack(),
            ... )
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._command_stack: Optional[CommandStack] = command_stack
        self._cpi: int = int(DEFAULT_CPI)

        # Widget references (initialized in _create_tk_widget)
        self._tk_frame: Optional[tk.Frame] = None
        self._tk_text: Optional[tk.Text] = None
        self._tk_vscroll: Optional[tk.Scrollbar] = None
        self._tk_hscroll: Optional[tk.Scrollbar] = None
        self._tk_placeholder_frame: Optional[tk.Frame] = None
        self._tk_placeholder_label: Optional[tk.Label] = None

        # SmartEdit state
        self._is_editing: bool = False
        self._edit_start_text: str = ""
        self._edit_start_cursor: Tuple[int, int] = (1, 1)

        # Callbacks
        self._on_text_change_callback: Optional[Callable[[str], None]] = None
        self._on_cursor_move_callback: Optional[Callable[[int, int], None]] = None

        # State
        self._current_text: str = ""
        self._content_hidden: bool = False
        self._hidden_content_backup: str = ""
        self._last_cursor_position: Tuple[int, int] = (1, 1)

        # Font configuration
        self._font_family: str = DEFAULT_FONT_FAMILY
        self._font_size: int = 12

        # Paper visualization
        self._paper_viz: Optional[PaperVisualizationWidget] = None
        self._line_properties: list[LineProperties] = []
        self._char_width_px: int = 9
        self._char_height_px: int = 15

        # Toolbar reference (created in create_toolbar)
        self._format_toolbar_ref: Optional[FormatToolbar] = None

        # Embedded image references (prevents GC of PhotoImage)
        self._embedded_images: list[tk.PhotoImage] = []

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Создаёт Frame с Text widget, scrollbars и placeholder.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        # Main frame
        self._tk_frame = tk.Frame(parent, bg=TEXT_BG_COLOR)

        # Create text widget with monospace font
        self._font_family = self._get_available_monospace_font()
        font = (self._font_family, self._font_size)

        self._tk_text = tk.Text(
            self._tk_frame,
            wrap="none",
            font=font,
            bg=TEXT_BG_COLOR,
            fg=TEXT_FG_COLOR,
            selectbackground=TEXT_SELECT_BG,
            width=ESCP_COLS,
            height=ESCP_ROWS,
            undo=False,  # We use our own CommandStack
            maxundo=0,
            autoseparators=False,
        )

        # Scrollbars
        self._tk_vscroll = tk.Scrollbar(
            self._tk_frame,
            orient="vertical",
            command=self._tk_text.yview,
        )
        self._tk_hscroll = tk.Scrollbar(
            self._tk_frame,
            orient="horizontal",
            command=self._tk_text.xview,
        )

        # Configure text widget scrolling
        self._tk_text.configure(
            yscrollcommand=self._tk_vscroll.set,
            xscrollcommand=self._tk_hscroll.set,
        )

        # Grid layout
        self._tk_text.grid(row=0, column=0, sticky="nsew")
        self._tk_vscroll.grid(row=0, column=1, sticky="ns")
        self._tk_hscroll.grid(row=1, column=0, sticky="ew")

        # Paper visualization canvas (positioned behind text)
        self._paper_viz = PaperVisualizationWidget(
            widget_id=f"{self._widget_id}_paper_viz",
            controller=self._controller,
        )
        paper_viz_widget = self._paper_viz.mount(self._tk_frame)
        paper_viz_widget.grid(row=0, column=0, sticky="nsew")
        self._tk_text.tkraise()  # Bring text to front, canvas stays behind

        # Configure grid weights
        self._tk_frame.grid_rowconfigure(0, weight=1)
        self._tk_frame.grid_columnconfigure(0, weight=1)

        # Placeholder frame (for session lock)
        self._tk_placeholder_frame = tk.Frame(
            self._tk_frame,
            bg="#f0f0f0",
        )
        self._tk_placeholder_label = tk.Label(
            self._tk_placeholder_frame,
            text="🔒 Session Locked",
            font=(self._font_family, 14),
            bg="#f0f0f0",
            fg="#666666",
        )
        self._tk_placeholder_label.pack(expand=True)

        # Configure formatting tags
        self._configure_format_tags()

        return self._tk_frame

    def _get_available_monospace_font(self) -> str:
        """Возвращает доступный monospace шрифт.

        Returns:
            Имя доступного шрифта (Courier, Consolas или fallback).
        """
        try:
            # Try to use font module if available
            available = (
                self._tk_frame.winfo_toplevel().tk.call("font", "families")
                if self._tk_frame
                else []
            )
            font_families = [str(f).lower() for f in available]

            if "courier" in font_families:
                return "Courier"
            elif "consolas" in font_families:
                return "Consolas"
            elif "monospace" in font_families:
                return "Monospace"
            elif "courier new" in font_families:
                return "Courier New"
        except (KeyError, AttributeError, tk.TclError) as e:
            # Theme/UI error: log as WARNING and fallback
            logging.getLogger(__name__).warning("Font lookup error: %s", e)
        except Exception as e:
            logging.getLogger(__name__).debug("Unexpected font lookup error: %s", e)

        return DEFAULT_FONT_FAMILY

    def _configure_format_tags(self) -> None:
        """Настраивает теги форматирования tk.Text.

        Создаёт теги для:
        - bold, italic, underline, bold_italic
        - double_height (метка для ESC/P double-height)
        - shadow_row (следующая строка после double-height)
        - subscript/superscript (смещение baseline и уменьшенный шрифт)
        - CPI масштабирование
        """
        if self._tk_text is None:
            return

        # Bold tag
        self._tk_text.tag_configure(
            "bold",
            font=(self._font_family, self._font_size, "bold"),
        )

        # Italic tag
        self._tk_text.tag_configure(
            "italic",
            font=(self._font_family, self._font_size, "italic"),
        )

        # Underline tag
        self._tk_text.tag_configure(
            "underline",
            underline=True,
        )

        # Combined tags
        self._tk_text.tag_configure(
            "bold_italic",
            font=(self._font_family, self._font_size, "bold italic"),
        )

        # Double-height tag (метка для ESC/P double-height строки)
        self._tk_text.tag_configure(
            "double_height",
            font=(self._font_family, self._font_size + 2, "bold"),
        )

        # Shadow row tag (следующая строка после double-height)
        # elide=True скрывает текст из отображения, но индексы сохраняются
        self._tk_text.tag_configure(
            "shadow_row",
            background=SHADOW_ROW_BG,
            foreground=SHADOW_ROW_FG,
            elide=True,
        )

        # Subscript tag: меньший шрифт + смещение вниз
        script_font_size = max(6, self._font_size + SCRIPT_FONT_DELTA)
        self._tk_text.tag_configure(
            "subscript",
            font=(self._font_family, script_font_size),
            offset=f"{SUBSCRIPT_OFFSET}p",
        )

        # Superscript tag: меньший шрифт + смещение вверх
        self._tk_text.tag_configure(
            "superscript",
            font=(self._font_family, script_font_size),
            offset=f"{SUPERSCRIPT_OFFSET}p",
        )

        # CPI tags
        for cpi in VALID_CPI_INT:
            # Scale font size based on CPI
            base_size = 12
            if cpi == 10:
                size = base_size
            elif cpi == 12:
                size = 10
            elif cpi == 15:
                size = 8
            elif cpi == 17:
                size = 7
            else:  # 20
                size = 6

            self._tk_text.tag_configure(
                f"cpi_{cpi}",
                font=(self._font_family, size),
            )

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        if self._tk_text is None:
            return

        # Key bindings for command creation
        self._tk_text.bind("<Key>", self._on_key_press)
        self._tk_text.bind("<KeyRelease>", self._on_key_release)

        # SmartEdit FocusIn/FocusOut bindings
        self._tk_text.bind("<FocusIn>", self._on_focus_in)
        self._tk_text.bind("<FocusOut>", self._on_focus_out)

        # Cursor movement tracking
        self._tk_text.bind("<ButtonRelease-1>", self._on_cursor_moved)
        self._tk_text.bind("<KeyRelease-Up>", self._on_cursor_moved)
        self._tk_text.bind("<KeyRelease-Down>", self._on_cursor_moved)
        self._tk_text.bind("<KeyRelease-Left>", self._on_cursor_moved)
        self._tk_text.bind("<KeyRelease-Right>", self._on_cursor_moved)
        self._tk_text.bind("<KeyRelease-Home>", self._on_cursor_moved)
        self._tk_text.bind("<KeyRelease-End>", self._on_cursor_moved)

        # Mouse wheel for horizontal scroll (with Shift)
        self._tk_text.bind("<Shift-MouseWheel>", self._on_horizontal_scroll)

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self._command_stack = None
        self._on_text_change_callback = None
        self._on_cursor_move_callback = None
        self._current_text = ""
        self._hidden_content_backup = ""

        if self._paper_viz is not None:
            self._paper_viz.unmount()
            self._paper_viz = None
        self._line_properties = []
        self._embedded_images.clear()

        self._tk_text = None
        self._tk_vscroll = None
        self._tk_hscroll = None
        self._tk_placeholder_frame = None
        self._tk_placeholder_label = None
        self._tk_frame = None

    # =============================================================================
    # EVENT HANDLERS
    # =============================================================================

    def _on_key_press(self, event: tk.Event) -> Optional[str]:
        """Обрабатывает нажатие клавиши.

        Создаёт команды для undo при редактировании.

        Args:
            event: Событие нажатия клавиши.

        Returns:
            None для продолжения обработки, "break" для остановки.
        """
        if self._tk_text is None or self._command_stack is None:
            return None

        # Ignore special keys
        if event.keysym in (
            "Shift_L",
            "Shift_R",
            "Control_L",
            "Control_R",
            "Alt_L",
            "Alt_R",
            "Caps_Lock",
            "Num_Lock",
            "Up",
            "Down",
            "Left",
            "Right",
            "Home",
            "End",
            "Page_Up",
            "Page_Down",
        ):
            return None

        # Handle Backspace and Delete specially
        if event.keysym == "BackSpace":
            self._handle_backspace()
            return "break"

        if event.keysym == "Delete":
            self._handle_delete()
            return "break"

        # Handle regular character input
        if event.char and event.char.isprintable():
            self._handle_char_insert(event.char)
            return "break"

        return None

    def _on_key_release(self, event: tk.Event) -> None:
        """Обрабатывает отпускание клавиши.

        Args:
            event: Событие отпускания клавиши.
        """
        # Trigger text change callback
        if self._on_text_change_callback is not None and self._tk_text is not None:
            current_text = self._tk_text.get("1.0", "end-1c")
            if current_text != self._current_text:
                self._current_text = current_text
                self._on_text_change_callback(current_text)

    def _on_cursor_moved(self, event: tk.Event) -> None:
        """Обрабатывает движение курсора.

        Args:
            event: Событие движения курсора.
        """
        if self._tk_text is None:
            return

        pos = self.get_cursor_position()
        if pos != self._last_cursor_position:
            self._last_cursor_position = pos
            if self._on_cursor_move_callback is not None:
                self._on_cursor_move_callback(pos[0], pos[1])

    def _on_horizontal_scroll(self, event: tk.Event) -> None:
        """Обрабатывает горизонтальную прокрутку колесом мыши.

        Args:
            event: Событие прокрутки.
        """
        if self._tk_text is None:
            return

        if event.delta > 0:
            self._tk_text.xview_scroll(-1, "units")
        else:
            self._tk_text.xview_scroll(1, "units")

    # =============================================================================
    # SMART EDIT (FocusIn/FocusOut)
    # =============================================================================

    def _on_focus_in(self, event: tk.Event) -> None:
        """Обрабатывает получение фокуса текстовым полем.

        Входит в режим редактирования SmartEdit, сохраняя
        начальное состояние текста для последующего сравнения.

        Args:
            event: Событие FocusIn.
        """
        self._enter_edit_mode()

    def _on_focus_out(self, event: tk.Event) -> None:
        """Обрабатывает потерю фокуса текстовым полем.

        Выходит из режима редактирования SmartEdit, сравнивает
        текущий текст с начальным и при необходимости синхронизирует
        с контроллером и создаёт Command для undo.

        Args:
            event: Событие FocusOut.
        """
        self._exit_edit_mode()

    def _enter_edit_mode(self) -> None:
        """Входит в режим редактирования SmartEdit.

        Сохраняет текущий текст и позицию курсора для последующего
        сравнения при выходе из редактирования.
        """
        if self._tk_text is None:
            return

        self._is_editing = True
        self._edit_start_text = self._tk_text.get("1.0", "end-1c")
        self._edit_start_cursor = self.get_cursor_position()

    def _exit_edit_mode(self) -> None:
        """Выходит из режима редактирования SmartEdit.

        Сравнивает текущий текст с сохранённым при входе.
        Если текст изменился:
        - Синхронизирует с контроллером через dispatch
        - Создаёт SetTextCommand для undo/redo
        - Вызывает callback изменения текста
        """
        if self._tk_text is None:
            self._is_editing = False
            return

        self._is_editing = False
        current_text = self._tk_text.get("1.0", "end-1c")

        if current_text != self._edit_start_text:
            # Синхронизация с контроллером
            if self._controller is not None:
                self._controller.dispatch("text_changed", text=current_text)

            # Callback для внешних слушателей
            if self._on_text_change_callback is not None:
                self._on_text_change_callback(current_text)

            # Создание команды для undo агрегированного изменения
            if self._command_stack is not None:
                cmd = SetTextCommand(
                    self._tk_text,
                    self._edit_start_text,
                    current_text,
                )
                self._command_stack.execute(cmd)

            self._current_text = current_text

    def _preserve_cursor_position(self, operation: Callable[[], None]) -> None:
        """Сохраняет и восстанавливает позицию курсора при операции.

        Args:
            operation: Функция, выполняющая операцию с текстом.
        """
        if self._tk_text is None:
            operation()
            return

        cursor_pos = self._tk_text.index(tk.INSERT)
        operation()
        try:
            self._tk_text.mark_set(tk.INSERT, cursor_pos)
            self._tk_text.see(cursor_pos)
        except tk.TclError:
            # Индекс мог стать невалидным после операции
            pass

    def _handle_backspace(self) -> None:
        """Обрабатывает нажатие Backspace."""
        if self._tk_text is None or self._command_stack is None:
            return

        cursor = self._tk_text.index(tk.INSERT)
        line, col = cursor.split(".")

        if line == "1" and col == "0":
            return  # Already at beginning

        # Calculate start position
        start_idx = f"{line}.{int(col) - 1}" if int(col) > 0 else f"{int(line) - 1}.end"

        cmd = DeleteTextCommand(self._tk_text, start_idx, cursor)
        self._command_stack.execute(cmd)

    def _handle_delete(self) -> None:
        """Обрабатывает нажатие Delete."""
        if self._tk_text is None or self._command_stack is None:
            return

        cursor = self._tk_text.index(tk.INSERT)

        # Check if there's text after cursor
        next_char = self._tk_text.get(cursor, f"{cursor} + 1 char")
        if next_char:
            cmd = DeleteTextCommand(
                self._tk_text,
                cursor,
                f"{cursor} + 1 char",
            )
            self._command_stack.execute(cmd)

    def _handle_char_insert(self, char: str) -> None:
        """Обрабатывает вставку символа.

        Args:
            char: Символ для вставки.
        """
        if self._tk_text is None or self._command_stack is None:
            return

        cursor = self._tk_text.index(tk.INSERT)
        cmd = InsertTextCommand(self._tk_text, char, cursor)
        self._command_stack.execute(cmd)

    # =============================================================================
    # CALLBACK SETTERS
    # =============================================================================

    def set_on_text_change_callback(self, callback: Callable[[str], None]) -> None:
        """Устанавливает callback для изменения текста.

        Args:
            callback: Функция, вызываемая при изменении текста.

        Example:
            >>> renderer.set_on_text_change_callback(
            ...     lambda text: print(f"Text changed: {len(text)}")
            ... )
        """
        self._on_text_change_callback = callback

    def set_on_cursor_move_callback(self, callback: Callable[[int, int], None]) -> None:
        """Устанавливает callback для движения курсора.

        Args:
            callback: Функция, вызываемая при движении курсора.
                Принимает (line, column) в 1-based координатах.

        Example:
            >>> renderer.set_on_cursor_move_callback(
            ...     lambda line, col: print(f"Cursor: {line}:{col}")
            ... )
        """
        self._on_cursor_move_callback = callback

    # =============================================================================
    # DOCUMENT METHODS
    # =============================================================================

    def render(self, document: FreeFormDocument) -> None:
        """Загружает содержимое документа в редактор.

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> doc = FreeFormDocument(content="Hello", cpi=12)
            >>> renderer.render(doc)
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="render",
                message="Виджет не смонтирован",
            )

        self._render_to_text_widget(document)

    def display_document(self, document: FreeFormDocument) -> None:
        """Отображает документ с учётом SmartEdit режима.

        Если редактор находится в режиме редактирования
        (_is_editing=True), вызов игнорируется для защиты
        пользовательского ввода от внешних обновлений.

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="display_document",
                message="Виджет не смонтирован",
            )

        # SmartEdit: игнорируем внешние обновления во время редактирования
        if self._is_editing:
            return

        self._render_to_text_widget(document)

    def _render_to_text_widget(self, document: FreeFormDocument) -> None:
        """Внутренний метод рендеринга документа в tk.Text.

        Сохраняет позицию курсора при обновлении текста.

        Args:
            document: Документ для отображения.
        """
        if self._tk_text is None:
            return

        # Сохраняем позицию курсора
        cursor_pos: Optional[str] = self._tk_text.index(tk.INSERT)

        # Clear current content
        self._tk_text.delete("1.0", tk.END)

        # Set text content
        safe_content = document.content[:MAX_TEXT_LENGTH]
        self._tk_text.insert("1.0", safe_content)
        self._current_text = safe_content

        # Apply CPI
        self.apply_cpi(document.cpi)

        # Apply formatting
        for fmt_range in document.formatting:
            self.apply_format(fmt_range.tag, fmt_range.start, fmt_range.end)

        # Восстанавливаем позицию курсора (если возможно)
        if cursor_pos is not None:
            try:
                self._tk_text.mark_set(tk.INSERT, cursor_pos)
                self._tk_text.see(cursor_pos)
            except tk.TclError:
                # Fallback: установить курсор в начало
                self._tk_text.mark_set(tk.INSERT, "1.0")
        else:
            self._tk_text.mark_set(tk.INSERT, "1.0")

    def create_toolbar(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт FormatToolbar для свободного текстового режима.

        Strategy Pattern метод: создаёт и монтирует FormatToolbar
        в предоставленный parent виджет.

        Args:
            parent: Родительский виджет для toolbar.

        Returns:
            Корневой виджет FormatToolbar.

        Raises:
            ValueError: Если parent is None.
        """
        if parent is None:
            raise ValueError("parent cannot be None")

        toolbar = FormatToolbar(
            widget_id=f"{self._widget_id}_format_toolbar",
            on_cpi_change=self._on_cpi_changed,
            on_format_toggle=self._on_format_toggled,
        )
        widget = toolbar.mount(parent)
        widget.pack(fill=tk.BOTH, expand=True)

        self._format_toolbar_ref = toolbar
        return widget

    def create_editor(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт редактор в указанном parent.

        Если рендерер ещё не смонтирован, выполняет mount.
        Иначе возвращает уже созданный корневой виджет.

        Args:
            parent: Родительский виджет для редактора.

        Returns:
            Корневой виджет редактора (Frame с tk.Text).

        Raises:
            ValueError: Если parent is None.
        """
        if parent is None:
            raise ValueError("parent cannot be None")

        if not self._is_mounted:
            self.mount(parent)

        if self._tk_frame is None:
            raise RuntimeError("Editor widget not created after mount")

        return self._tk_frame

    def get_editor_state(self) -> dict[str, Any]:
        """Возвращает текущее состояние редактора.

        Returns:
            Словарь с cursor_line, cursor_column, selection,
            text_length, cpi, is_editing.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_editor_state",
                message="Виджет не смонтирован",
            )

        line, col = self.get_cursor_position()
        selection = self.get_selection()

        return {
            "cursor_line": line,
            "cursor_column": col,
            "selection_start": selection[0] if selection else None,
            "selection_end": selection[1] if selection else None,
            "text_length": len(self._current_text),
            "cpi": self._cpi,
            "is_editing": self._is_editing,
            "content_hidden": self._content_hidden,
        }

    def _on_cpi_changed(self, cpi: int) -> None:
        """Внутренний обработчик изменения CPI из FormatToolbar.

        Args:
            cpi: Новое значение CPI.
        """
        self.apply_cpi(cpi)

    def _on_format_toggled(self, format_type: str, active: bool) -> None:
        """Внутренний обработчик переключения формата из FormatToolbar.

        Args:
            format_type: Тип форматирования.
            active: True если активирован.
        """
        selection = self.get_selection()
        if selection is not None:
            start, end = selection
            if active:
                self.apply_format(format_type, start, end)
            else:
                self.remove_format(format_type, start, end)
        else:
            line, col = self.get_cursor_position()
            start = f"{line}.{col - 1}"
            end = f"{line}.{col}"
            if active:
                self.apply_format(format_type, start, end)

    def get_text(self) -> str:
        """Возвращает весь текст из редактора.

        Returns:
            Текстовое содержимое редактора.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> text = renderer.get_text()
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_text",
                message="Виджет не смонтирован",
            )

        return self._tk_text.get("1.0", "end-1c")

    def get_content(self) -> str:
        """Возвращает текущее содержимое редактора.

        Returns:
            Текстовое содержимое редактора.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        return self.get_text()

    def set_text(self, text: str) -> None:
        """Устанавливает текст в редактор.

        Создаёт команду через CommandStack если он доступен.

        Args:
            text: Текст для установки.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.set_text("New content")
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_text",
                message="Виджет не смонтирован",
            )

        # Security: truncate long text
        safe_text = text[:MAX_TEXT_LENGTH]

        if self._command_stack is not None:
            # Clear current text via command
            current = self._tk_text.get("1.0", tk.END)
            if current.strip():
                del_cmd: DeleteTextCommand = DeleteTextCommand(self._tk_text, "1.0", tk.END)
                self._command_stack.execute(del_cmd)

            # Insert new text
            if safe_text:
                ins_cmd: InsertTextCommand = InsertTextCommand(self._tk_text, safe_text, "1.0")
                self._command_stack.execute(ins_cmd)
        else:
            # Direct update without commands
            self._tk_text.delete("1.0", tk.END)
            self._tk_text.insert("1.0", safe_text)

        self._current_text = safe_text

    def get_cursor_position(self) -> Tuple[int, int]:
        """Возвращает позицию курсора.

        Returns:
            Кортеж (line, column) в 1-based координатах.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> line, col = renderer.get_cursor_position()
            >>> print(f"Cursor at line {line}, column {col}")
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_cursor_position",
                message="Виджет не смонтирован",
            )

        idx = self._tk_text.index(tk.INSERT)
        line_str, col_str = idx.split(".")
        return (int(line_str), int(col_str) + 1)

    def set_cursor_position(self, line: int, column: int) -> None:
        """Устанавливает позицию курсора.

        Args:
            line: Строка (1-based).
            column: Столбец (1-based).

        Raises:
            LifecycleError: Если виджет не смонтирован.
            ValueError: Если позиция некорректна.

        Example:
            >>> renderer.set_cursor_position(1, 1)  # Start of document
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_cursor_position",
                message="Виджет не смонтирован",
            )

        if line < 1 or column < 1:
            raise ValueError("Строка и столбец должны быть >= 1")

        # tk.Text uses 0-based columns
        idx = f"{line}.{column - 1}"
        self._tk_text.mark_set(tk.INSERT, idx)
        self._tk_text.see(idx)

        self._last_cursor_position = (line, column)

    def get_selection(self) -> Optional[Tuple[str, str]]:
        """Возвращает выделенный диапазон.

        Returns:
            Кортеж (start, end) или None если выделения нет.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> selection = renderer.get_selection()
            >>> if selection:
            ...     start, end = selection
            ...     print(f"Selected from {start} to {end}")
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_selection",
                message="Виджет не смонтирован",
            )

        try:
            start = self._tk_text.index(tk.SEL_FIRST)
            end = self._tk_text.index(tk.SEL_LAST)
            return (start, end)
        except tk.TclError:
            return None

    def insert_text(self, position: str, text: str) -> None:
        """Вставляет текст в указанную позицию.

        Создаёт InsertTextCommand через CommandStack.

        Args:
            position: Позиция вставки (например, "1.0" или "end").
            text: Текст для вставки.

        Raises:
            LifecycleError: Если виджет не смонтирован.
            RuntimeError: Если CommandStack не установлен.

        Example:
            >>> renderer.insert_text("1.0", "Hello")
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="insert_text",
                message="Виджет не смонтирован",
            )

        if self._command_stack is None:
            raise RuntimeError("CommandStack not set")

        safe_text = text[:MAX_TEXT_LENGTH]
        cmd = InsertTextCommand(self._tk_text, safe_text, position)
        self._command_stack.execute(cmd)

    def delete_text(self, start: str, end: str) -> None:
        """Удаляет текст в указанном диапазоне.

        Создаёт DeleteTextCommand через CommandStack.

        Args:
            start: Начальная позиция (например, "1.0").
            end: Конечная позиция (например, "1.10" или "end").

        Raises:
            LifecycleError: Если виджет не смонтирован.
            RuntimeError: Если CommandStack не установлен.

        Example:
            >>> renderer.delete_text("1.0", "1.5")
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="delete_text",
                message="Виджет не смонтирован",
            )

        if self._command_stack is None:
            raise RuntimeError("CommandStack not set")

        cmd = DeleteTextCommand(self._tk_text, start, end)
        self._command_stack.execute(cmd)

    def insert_text_at_cursor(self, text: str) -> None:
        """Вставляет текст в позицию курсора.

        Args:
            text: Текст для вставки.

        Raises:
            LifecycleError: Если виджет не смонтирован.
            RuntimeError: Если CommandStack не установлен.
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="insert_text_at_cursor",
                message="Виджет не смонтирован",
            )

        if self._command_stack is None:
            raise RuntimeError("CommandStack not set")

        cursor = self._tk_text.index(tk.INSERT)
        safe_text = text[:MAX_TEXT_LENGTH]
        cmd = InsertTextCommand(self._tk_text, safe_text, cursor)
        self._command_stack.execute(cmd)

    def insert_barcode_at_cursor(
        self,
        barcode_type: str,
        data: str,
        mode: str = "software",
        settings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Вставляет штрих-код в позицию курсора.

        Variant A: вставляет placeholder текст ┇BARCODE:{type}:{data}┇
        через InsertTextCommand.

        Variant B: если mode == "software" и settings["render_image"] == True,
        генерирует PhotoImage через SoftwareBarcodeRenderer и вставляет
        в tk.Text через image_create с поддержкой undo/redo.

        Args:
            barcode_type: Тип штрих-кода (CODE128, EAN13 и т.д.).
            data: Данные для кодирования.
            mode: Режим ("hardware", "software", "placeholder").
            settings: Дополнительные настройки, включая "render_image".

        Returns:
            True при успешной вставке, False при ошибке.
        """
        if not self._is_mounted or self._tk_text is None:
            return False

        if self._command_stack is None:
            return False

        settings = settings or {}
        use_image = (
            mode == "software"
            and isinstance(settings, dict)
            and settings.get("render_image", False)
        )

        if use_image:
            try:
                # Создаём временный Canvas для рендеринга
                temp_canvas = tk.Canvas(self._tk_text, width=1, height=1)
                renderer = create_barcode_renderer(
                    canvas=temp_canvas,
                    mode="software",
                    render_mode=BarcodeRenderMode.REAL,
                )
                # Генерируем изображение на временном canvas
                renderer.render(
                    barcode_type=barcode_type,
                    data=data,
                    x=0,
                    y=0,
                    width=settings.get("width_mm", 50) * 4,
                    height=settings.get("height_mm", 25) * 4,
                    show_text=settings.get("show_text", True),
                )

                # Извлекаем последний PhotoImage из рендерера
                if renderer._photo_images:
                    photo: tk.PhotoImage = renderer._photo_images[-1]
                    # Сохраняем ссылку для предотвращения GC
                    self._embedded_images.append(photo)

                    cursor = self._tk_text.index(tk.INSERT)
                    self._command_stack.execute(
                        InsertBarcodeCommand(
                            self._tk_text,
                            photo,
                            cursor,
                        )
                    )
                    return True

                # Fallback если PhotoImage не создан
                logger.warning("Barcode PhotoImage not generated, falling back to placeholder")

            except Exception as e:
                logger.error("Barcode image insertion error: %s", e)
                # Fallback к placeholder

        # Variant A: placeholder текст
        try:
            cursor = self._tk_text.index(tk.INSERT)
            self._command_stack.execute(
                InsertPlaceholderCommand(
                    self._tk_text,
                    f"BARCODE:{barcode_type}",
                    data,
                    cursor,
                )
            )
            return True
        except Exception as e:
            logger.error("Barcode placeholder insertion error: %s", e)
            return False

    def insert_qr_at_cursor(
        self,
        data: str,
        settings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Вставляет QR-код в позицию курсора.

        Variant A: вставляет placeholder текст ┇QR:{data}┇
        через InsertTextCommand.

        Variant B: если settings["render_image"] == True,
        генерирует PhotoImage через SoftwareQRRenderer и вставляет
        в tk.Text через image_create с поддержкой undo/redo.

        Args:
            data: Данные для кодирования.
            settings: Дополнительные настройки, включая "render_image".

        Returns:
            True при успешной вставке, False при ошибке.
        """
        if not self._is_mounted or self._tk_text is None:
            return False

        if self._command_stack is None:
            return False

        settings = settings or {}
        use_image = isinstance(settings, dict) and settings.get("render_image", False)

        if use_image:
            try:
                # Создаём временный Canvas для рендеринга
                temp_canvas = tk.Canvas(self._tk_text, width=1, height=1)
                renderer = create_qr_renderer(
                    canvas=temp_canvas,
                    mode="software",
                    render_mode=QRRenderMode.REAL,
                    error_correction=settings.get("error_correction", "M"),
                    box_size=settings.get("box_size", 4),
                    border=settings.get("border", 4),
                )
                size = settings.get("size", 200)
                renderer.render_qr(
                    data=data,
                    x=0,
                    y=0,
                    size=size,
                )

                # Извлекаем последний PhotoImage из рендерера
                if renderer._photo_images:
                    photo: tk.PhotoImage = renderer._photo_images[-1]
                    # Сохраняем ссылку для предотвращения GC
                    self._embedded_images.append(photo)

                    cursor = self._tk_text.index(tk.INSERT)
                    self._command_stack.execute(
                        InsertQRCommand(
                            self._tk_text,
                            photo,
                            cursor,
                        )
                    )
                    return True

                logger.warning("QR PhotoImage not generated, falling back to placeholder")

            except Exception as e:
                logger.error("QR image insertion error: %s", e)

        # Variant A: placeholder текст
        try:
            cursor = self._tk_text.index(tk.INSERT)
            self._command_stack.execute(
                InsertPlaceholderCommand(
                    self._tk_text,
                    "QR",
                    data,
                    cursor,
                )
            )
            return True
        except Exception as e:
            logger.error("QR placeholder insertion error: %s", e)
            return False

    def apply_cpi(self, cpi: int) -> None:
        """Применяет CPI (characters per inch) к документу.

        Args:
            cpi: Значение CPI (10, 12, 15, 17, 20).

        Raises:
            LifecycleError: Если виджет не смонтирован.
            ValueError: Если CPI недопустимо.

        Example:
            >>> renderer.apply_cpi(12)  # Elite font
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="apply_cpi",
                message="Виджет не смонтирован",
            )

        if cpi not in VALID_CPI_INT:
            raise ValueError(f"Invalid CPI: {cpi}. Valid values: {sorted(VALID_CPI_INT)}")

        self._cpi = cpi

        # Apply CPI tag to entire document
        self._tk_text.tag_remove("cpi_10", "1.0", tk.END)
        self._tk_text.tag_remove("cpi_12", "1.0", tk.END)
        self._tk_text.tag_remove("cpi_15", "1.0", tk.END)
        self._tk_text.tag_remove("cpi_17", "1.0", tk.END)
        self._tk_text.tag_remove("cpi_20", "1.0", tk.END)

        self._tk_text.tag_add(f"cpi_{cpi}", "1.0", tk.END)

    def get_cpi(self) -> int:
        """Возвращает текущее значение CPI.

        Returns:
            Текущее значение CPI (10, 12, 15, 17, 20).

        Example:
            >>> cpi = renderer.get_cpi()
        """
        return self._cpi

    def apply_format(self, tag: str, start: str, end: str) -> None:
        """Применяет форматирование к диапазону текста.

        Поддерживаемые теги:
        - "bold", "italic", "underline", "bold_italic"
        - "double_height" — двойная высота ESC/P (помечает следующую строку shadow_row)
        - "subscript", "superscript" — смещение baseline и уменьшенный шрифт

        При применении "double_height" автоматически помечается
        следующая строка тегом "shadow_row" (скрывается при печати).

        Args:
            tag: Тег форматирования.
            start: Начальная позиция ("line.col").
            end: Конечная позиция ("line.col").

        Raises:
            LifecycleError: Если виджет не смонтирован.
            ValueError: Если тег не поддерживается.

        Example:
            >>> renderer.apply_format("bold", "1.0", "1.10")
            >>> renderer.apply_format("subscript", "2.5", "2.8")
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="apply_format",
                message="Виджет не смонтирован",
            )

        valid_tags = {
            "bold",
            "italic",
            "underline",
            "bold_italic",
            "double_height",
            "subscript",
            "superscript",
        }
        if tag not in valid_tags:
            raise ValueError(f"Invalid tag: {tag}. Valid: {valid_tags}")

        self._tk_text.tag_add(tag, start, end)

        # Обновляем shadow_row при изменении double_height
        if tag == "double_height":
            self._update_shadow_rows()

    def remove_format(self, tag: str, start: str, end: str) -> None:
        """Удаляет форматирование из диапазона текста.

        При удалении "double_height" автоматически пересчитываются shadow_row.

        Args:
            tag: Тег форматирования для удаления.
            start: Начальная позиция.
            end: Конечная позиция.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.remove_format("bold", "1.0", "1.10")
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="remove_format",
                message="Виджет не смонтирован",
            )

        self._tk_text.tag_remove(tag, start, end)

        if tag == "double_height":
            self._update_shadow_rows()

    def _update_shadow_rows(self) -> None:
        """Пересчитывает shadow_row строки на основе double_height тегов.

        Для каждой строки, содержащей double_height, следующая строка
        помечается тегом "shadow_row" (серый фон, скрывается при печати).
        """
        if self._tk_text is None:
            return

        # Очищаем старые shadow_row
        self._tk_text.tag_remove("shadow_row", "1.0", tk.END)

        # Находим все строки с double_height
        double_height_lines: Set[int] = set()
        ranges = self._tk_text.tag_ranges("double_height")
        for i in range(0, len(ranges), 2):
            if i + 1 >= len(ranges):
                continue
            start_idx = str(ranges[i])
            end_idx = str(ranges[i + 1])
            start_line = int(start_idx.split(".")[0])
            end_line = int(end_idx.split(".")[0])
            for line in range(start_line, end_line + 1):
                double_height_lines.add(line)

        # Применяем shadow_row к следующим строкам
        for line in double_height_lines:
            shadow_line = line + 1
            shadow_start = f"{shadow_line}.0"
            try:
                self._tk_text.index(shadow_start)
                self._tk_text.tag_add("shadow_row", shadow_start, f"{shadow_line}.end")
            except tk.TclError:
                pass  # Следующая строка не существует

    def get_shadow_row_lines(self) -> Set[int]:
        """Возвращает множество shadow row строк.

        Shadow rows — строки, следующие за double-height строками.
        При печати/экспорте эти строки пропускаются.

        Returns:
            Множество номеров строк (1-based), помеченных shadow_row.

        Example:
            >>> rows = renderer.get_shadow_row_lines()
            >>> print(rows)
            {2, 4, 6}
        """
        if not self._is_mounted or self._tk_text is None:
            return set()

        shadow_lines: Set[int] = set()
        ranges = self._tk_text.tag_ranges("shadow_row")
        for i in range(0, len(ranges), 2):
            if i + 1 >= len(ranges):
                continue
            start_idx = str(ranges[i])
            line = int(start_idx.split(".")[0])
            shadow_lines.add(line)
        return shadow_lines

    def is_shadow_row(self, line: int) -> bool:
        """Проверяет, является ли строка shadow row.

        Args:
            line: Номер строки (1-based).

        Returns:
            True если строка помечена тегом "shadow_row".

        Example:
            >>> renderer.is_shadow_row(2)
            True
        """
        return line in self.get_shadow_row_lines()

    def is_line_double_height(self, line: int) -> bool:
        """Проверяет, содержит ли строка double-height форматирование.

        Args:
            line: Номер строки (1-based).

        Returns:
            True если строка содержит double_height тег.

        Example:
            >>> renderer.is_line_double_height(1)
            True
        """
        if not self._is_mounted or self._tk_text is None:
            return False

        ranges = self._tk_text.tag_ranges("double_height")
        for i in range(0, len(ranges), 2):
            if i + 1 >= len(ranges):
                continue
            start_idx = str(ranges[i])
            start_line = int(start_idx.split(".")[0])
            end_idx = str(ranges[i + 1])
            end_line = int(end_idx.split(".")[0])
            if start_line <= line <= end_line:
                return True
        return False

    def get_text_for_export(self) -> str:
        """Возвращает текст для экспорта/печати без shadow row строк.

        Shadow rows — визуальные placeholders для double-height символов
        в GUI и не должны попадать в ESC/P вывод.

        Returns:
            Текстовое содержимое без строк, помеченных shadow_row.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> text = renderer.get_text_for_export()
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_text_for_export",
                message="Виджет не смонтирован",
            )

        full_text = self._tk_text.get("1.0", "end-1c")
        if not full_text:
            return ""

        shadow_lines = self.get_shadow_row_lines()
        if not shadow_lines:
            return full_text

        lines = full_text.split("\n")
        # Собираем строки, пропуская shadow rows
        result_lines: list[str] = []
        for i, line_text in enumerate(lines, start=1):
            if i not in shadow_lines:
                result_lines.append(line_text)
        return "\n".join(result_lines)

    def highlight_line(self, line: int, active: bool) -> None:
        """Подсвечивает или снимает подсветку со строки.

        Используется Navigator для обратной связи при double-height:
        при активном double-height для строки N подсвечивается строка N+1.

        Args:
            line: Номер строки (1-based).
            active: True для подсветки, False для снятия.

        Example:
            >>> renderer.highlight_line(2, True)   # Подсветить строку 2
            >>> renderer.highlight_line(2, False)  # Снять подсветку
        """
        if not self._is_mounted or self._tk_text is None:
            return

        tag = "navigator_highlight"
        start = f"{line}.0"
        end = f"{line}.end"

        if active:
            # Настраиваем тег если ещё не настроен
            self._tk_text.tag_configure(
                tag,
                background="#e6f3ff",
                foreground="#333333",
            )
            try:
                self._tk_text.tag_add(tag, start, end)
            except tk.TclError:
                pass
        else:
            try:
                self._tk_text.tag_remove(tag, start, end)
            except tk.TclError:
                pass

    def get_formatting(self) -> list[FormatRange]:
        """Возвращает список применённого форматирования.

        Returns:
            Список FormatRange с текущими тегами.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> formatting = renderer.get_formatting()
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_formatting",
                message="Виджет не смонтирован",
            )

        formatting: list[FormatRange] = []
        valid_tags = {
            "bold",
            "italic",
            "underline",
            "bold_italic",
            "double_height",
            "subscript",
            "superscript",
        }

        for tag in valid_tags:
            ranges = self._tk_text.tag_ranges(tag)
            for i in range(0, len(ranges), 2):
                if i + 1 < len(ranges):
                    start = str(ranges[i])
                    end = str(ranges[i + 1])
                    formatting.append(FormatRange(start, end, tag))

        return formatting

    # =============================================================================
    # SECURITY METHODS
    # =============================================================================

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные из редактора.

        Очищает текст, undo историю и все ссылки на данные.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.wipe_sensitive_data()
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="wipe_sensitive_data",
                message="Виджет не смонтирован",
            )

        # Clear text
        self._tk_text.delete("1.0", tk.END)

        # Clear command history
        if self._command_stack is not None:
            self._command_stack.clear()

        # Clear internal state
        self._current_text = ""
        self._hidden_content_backup = ""
        self._edit_start_text = ""
        self._is_editing = False

        # Reset cursor
        self._tk_text.mark_set(tk.INSERT, "1.0")

    def hide_content(self) -> None:
        """Скрывает содержимое редактора (session lock).

        Показывает placeholder frame вместо текстового содержимого.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.hide_content()  # Session locked
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="hide_content",
                message="Виджет не смонтирован",
            )

        if self._content_hidden:
            return

        self._content_hidden = True

        # Save current content
        if self._tk_text is not None:
            self._hidden_content_backup = self._tk_text.get("1.0", tk.END)

        # Show placeholder, hide text widget
        if self._tk_frame is not None and self._tk_text is not None:
            self._tk_text.grid_remove()
            if self._tk_vscroll is not None:
                self._tk_vscroll.grid_remove()
            if self._tk_hscroll is not None:
                self._tk_hscroll.grid_remove()

            if self._tk_placeholder_frame is not None:
                self._tk_placeholder_frame.grid(
                    row=0, column=0, rowspan=2, columnspan=2, sticky="nsew"
                )

    def restore_content(self) -> None:
        """Восстанавливает содержимое редактора (session unlock).

        Возвращает текстовое содержимое после блокировки сессии.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.restore_content()  # Session unlocked
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="restore_content",
                message="Виджет не смонтирован",
            )

        if not self._content_hidden:
            return

        self._content_hidden = False

        # Hide placeholder, show text widget
        if self._tk_frame is not None and self._tk_text is not None:
            if self._tk_placeholder_frame is not None:
                self._tk_placeholder_frame.grid_remove()

            self._tk_text.grid(row=0, column=0, sticky="nsew")
            if self._tk_vscroll is not None:
                self._tk_vscroll.grid(row=0, column=1, sticky="ns")
            if self._tk_hscroll is not None:
                self._tk_hscroll.grid(row=1, column=0, sticky="ew")

        # Restore content if needed
        if self._hidden_content_backup and self._tk_text is not None:
            current = self._tk_text.get("1.0", tk.END)
            if not current.strip() and self._hidden_content_backup.strip():
                self._tk_text.insert("1.0", self._hidden_content_backup)

        self._hidden_content_backup = ""

    # =============================================================================
    # PROTOCOL METHODS (DocumentRendererProtocol)
    # =============================================================================

    def apply_command(self, command: Command) -> None:
        """Применяет команду к документу.

        Args:
            command: Команда для выполнения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если команда неприменима к документу.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="apply_command",
                message="Виджет не смонтирован",
            )

        # Execute command through CommandStack
        if self._command_stack is not None:
            self._command_stack.execute(command)
        else:
            # Fallback: execute directly
            command.execute()

    def can_handle(self, mode: DocumentMode) -> bool:
        """Проверяет, может ли рендерер обрабатывать данный режим.

        Args:
            mode: Режим документа для проверки.

        Returns:
            True если рендерер поддерживает данный режим.
        """
        return mode == DocumentMode.FREE_FORM

    def supports_formatting(self) -> bool:
        """Проверяет, поддерживает ли рендерер форматирование текста.

        Returns:
            True для FreeFormRenderer (CPI, bold, italic, underline).
        """
        return True

    def set_command_stack(self, stack: CommandStack) -> None:
        """Устанавливает CommandStack для undo/redo операций.

        Args:
            stack: Стек команд для данного рендерера.
        """
        self._command_stack = stack

    def supports_workflow(self) -> bool:
        """Проверяет, поддерживает ли рендерер workflow-переходы.

        Returns:
            False для FreeFormRenderer (workflow не применим).
        """
        return False

    def get_undo_manager(self) -> Any:
        """Возвращает менеджер undo/redo операций.

        Returns:
            CommandStack или None если не установлен.
        """
        return self._command_stack

    # =============================================================================
    # PAPER VISUALIZATION METHODS
    # =============================================================================

    def set_line_properties(self, properties: list[LineProperties]) -> None:
        """Устанавливает свойства строк для визуализации.

        Args:
            properties: Список LineProperties для каждой строки.

        Example:
            >>> renderer.set_line_properties([
            ...     LineProperties(is_double_height=True),
            ...     LineProperties(),
            ... ])
        """
        self._line_properties = list(properties)
        self._update_paper_visualization()

    def set_envelope_type(self, envelope_type: Optional[str]) -> None:
        """Устанавливает тип конверта для оверлея.

        Args:
            envelope_type: Тип конверта ("DL", "C5", "C4") или None.

        Example:
            >>> renderer.set_envelope_type("DL")
        """
        if self._paper_viz is not None:
            self._paper_viz.set_envelope_type(envelope_type)

    def set_paper_size(self, width_px: int, height_px: int) -> None:
        """Устанавливает размер бумаги в пикселях.

        Args:
            width_px: Ширина в пикселях.
            height_px: Высота в пикселях.

        Example:
            >>> renderer.set_paper_size(595, 842)
        """
        if self._paper_viz is not None:
            self._paper_viz.set_paper_size(width_px, height_px)

    def set_character_size(self, width_px: int, height_px: int) -> None:
        """Устанавливает размер символа для расчёта gutter.

        Args:
            width_px: Ширина символа в пикселях.
            height_px: Высота символа в пикселях.
        """
        self._char_width_px = width_px
        self._char_height_px = height_px
        if self._paper_viz is not None:
            self._paper_viz.set_character_size(width_px, height_px)

    def set_document_size(self, lines: int, cols: int) -> None:
        """Устанавливает размер документа.

        Args:
            lines: Количество строк.
            cols: Количество колонок.
        """
        if self._paper_viz is not None:
            self._paper_viz.set_document_size(lines, cols)

    def _update_paper_visualization(self) -> None:
        """Обновляет визуализацию бумаги."""
        if self._paper_viz is None:
            return

        self._paper_viz.set_line_properties(self._line_properties)

        if self._tk_text is not None:
            self._paper_viz.set_document_size(
                lines=self._tk_text.cget("height"),
                cols=self._tk_text.cget("width"),
            )

        self._paper_viz.update()

    # =============================================================================
    # UTILITY METHODS
    # =============================================================================

    def focus(self) -> None:
        """Устанавливает фокус на текстовое поле.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.focus()
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="focus",
                message="Виджет не смонтирован",
            )

        self._tk_text.focus_set()

    def select_all(self) -> None:
        """Выделяет весь текст.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.select_all()
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="select_all",
                message="Виджет не смонтирован",
            )

        self._tk_text.tag_add(tk.SEL, "1.0", tk.END)
        self._tk_text.mark_set(tk.INSERT, "1.0")
        self._tk_text.see(tk.INSERT)

    def clear_selection(self) -> None:
        """Снимает выделение текста.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> renderer.clear_selection()
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="clear_selection",
                message="Виджет не смонтирован",
            )

        self._tk_text.tag_remove(tk.SEL, "1.0", tk.END)

    def copy_selection(self) -> Optional[str]:
        """Копирует выделенный текст и возвращает его.

        Returns:
            Выделенный текст или None если выделения нет.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> text = renderer.copy_selection()
            >>> if text:
            ...     clipboard.copy_text(text)
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="copy_selection",
                message="Виджет не смонтирован",
            )

        selection = self.get_selection()
        if selection is None:
            return None

        start, end = selection
        try:
            return self._tk_text.get(start, end)
        except tk.TclError:
            return None

    def cut_selection(self) -> Optional[str]:
        """Вырезает выделенный текст и возвращает его.

        Returns:
            Вырезанный текст или None если выделения нет.

        Raises:
            LifecycleError: Если виджет не смонтирован.
            RuntimeError: Если CommandStack не установлен.

        Example:
            >>> text = renderer.cut_selection()
            >>> if text:
            ...     clipboard.cut_text(text)
        """
        text = self.copy_selection()
        if text is not None:
            selection = self.get_selection()
            if selection is not None:
                start, end = selection
                self.delete_text(start, end)
        return text

    def paste_at_cursor(self, text: str) -> bool:
        """Вставляет текст в позицию курсора.

        Args:
            text: Текст для вставки.

        Returns:
            True при успешной вставке.

        Raises:
            LifecycleError: Если виджет не смонтирован.
            RuntimeError: Если CommandStack не установлен.

        Example:
            >>> renderer.paste_at_cursor("Hello, World!")
            True
        """
        if not self._is_mounted or self._tk_text is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="paste_at_cursor",
                message="Виджет не смонтирован",
            )

        if self._command_stack is None:
            raise RuntimeError("CommandStack not set")

        try:
            # Получаем текущую позицию курсора
            cursor_pos = self._tk_text.index(tk.INSERT)

            # Вставляем текст через CommandStack
            self.insert_text(cursor_pos, text)

            # Перемещаем курсор за вставленный текст
            inserted_end = f"{cursor_pos} + {len(text)} chars"
            self._tk_text.mark_set(tk.INSERT, inserted_end)
            self._tk_text.see(tk.INSERT)

            return True
        except tk.TclError:
            return False

    def show(self) -> None:
        """Показывает рендерер.

        Note:
            Поскольку FreeFormRenderer монтирован в родительский фрейм,
            показываем/скрываем через родительский фрейм.

        Example:
            >>> renderer.show()
        """
        if self._tk_widget is not None:
            self._tk_widget.pack(fill=tk.BOTH, expand=True)

    def hide(self) -> None:
        """Скрывает рендерер.

        Example:
            >>> renderer.hide()
        """
        if self._tk_widget is not None:
            self._tk_widget.pack_forget()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "FreeFormRenderer",
    "FreeFormDocument",
    "FormatRange",
    "VALID_CPI_INT",
]
