"""SideBar для FX Text Processor 3.

Реализует SideBarViewProtocol с двумя режимами отображения:
- SECTIONS: список секций (DOCUMENTS, TEMPLATES, BLANKS, SUPER DOCS)
- TREE: иерархическое дерево документов

Features:
- Collapsible (сворачивание до минимальной ширины)
- Search/filter functionality
- Section selection callbacks
- Tree item selection callbacks

Security:
- Input sanitization (max 100 chars, alphanumeric only)
- No eval/exec

Example:
    >>> sidebar = SideBar(
    ...     on_section_select=lambda s: print(f"Section: {s}"),
    ...     on_tree_select=lambda i: print(f"Item: {i}"),
    ... )
    >>> sidebar.mount(parent_frame)
    >>> sidebar.set_mode(SideBarMode.TREE)
    >>> sidebar.filter_items("report")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Final, Optional, TypedDict

from src.gui.components.base.widget import BaseWidget
from src.gui.components.sync.side_bar_sync_ui import (
    SideBarSyncManager,
    TreeItemDragHandle,
)
from src.gui.core.protocols import SyncServiceProtocol
from src.gui.layout.layout_constants import (
    PADDING_NORMAL,
    PADDING_SMALL,
    SIDEBAR_COLLAPSED_WIDTH,
    SIDEBAR_WIDTH,
)
from src.gui.services.drag_drop_service import (
    DATA_TYPE_DOCUMENT,
    DragData,
    DragDropService,
    DropOperation,
)
from src.gui.services.window_manager import WindowManager
from src.gui.views import SideBarMode

# Sync data type constants
DATA_SIDEBAR_STATE: Final[str] = "sidebar_state"


class SyncMessage(TypedDict):
    """Сообщение для синхронизации между окнами."""

    data_type: str
    data: dict[str, Any]


# Sync status enum and colors
class SyncStatus:
    """Статусы синхронизации."""

    SYNCED: Final[str] = "synced"
    SYNCING: Final[str] = "syncing"
    CONFLICT: Final[str] = "conflict"
    OFFLINE: Final[str] = "offline"


SYNC_STATUS_COLORS: Final[dict[str, str]] = {
    SyncStatus.SYNCED: "#4CAF50",
    SyncStatus.SYNCING: "#2196F3",
    SyncStatus.CONFLICT: "#FF9800",
    SyncStatus.OFFLINE: "#9E9E9E",
}

SYNC_STATUS_ICONS: Final[dict[str, str]] = {
    SyncStatus.SYNCED: "●",
    SyncStatus.SYNCING: "⟳",
    SyncStatus.CONFLICT: "⚠",
    SyncStatus.OFFLINE: "✗",
}


# File type icons mapping
FILE_TYPE_ICONS: Final[dict[str, str]] = {
    ".fxsd": "📄",
    ".fxsd.enc": "🔒",
    ".fxstpl": "📋",
    ".fxsblank": "🔐",
    ".fxskeystore.enc": "🔐",
    ".fxssig": "✍",
    ".fxsconfig": "⚙",
    ".fxsbackup": "💾",
    ".fxsbundle.enc": "📦",
    ".escp": "🖨️",
    ".escps": "📜",
}


def get_file_icon(filename: str) -> str:
    """Возвращает иконку для файла по имени.

    Args:
        filename: Имя файла.

    Returns:
        Иконка для типа файла.
    """
    for ext, icon in FILE_TYPE_ICONS.items():
        if filename.endswith(ext):
            return icon
    return "📄"


# Section definitions
SECTIONS: Final[list[tuple[str, str]]] = [
    ("DOCUMENTS", "📄 Documents"),
    ("TEMPLATES", "📋 Templates"),
    ("BLANKS", "📑 Blanks"),
    ("SUPER DOCS", "🗂️ Super Docs"),
]

# Default colors
DEFAULT_BG: Final[str] = "#f5f5f5"
DEFAULT_FG: Final[str] = "#333333"
HEADER_BG: Final[str] = "#e0e0e0"
SELECTED_BG: Final[str] = "#0078d4"
SELECTED_FG: Final[str] = "#ffffff"

# Security limits
MAX_QUERY_LENGTH: Final[int] = 100

# Drag-drop threshold
DRAG_THRESHOLD: Final[int] = 5
"""Порог смещения в пикселях для начала drag операции."""

# Placeholder constants
PLACEHOLDER_TEXT: Final[str] = "Search..."
PLACEHOLDER_FG: Final[str] = "#999999"


class SideBar(BaseWidget):
    """SideBar с двумя режимами отображения (SECTIONS и TREE).

    Реализует SideBarViewProtocol, предоставляя навигацию по секциям
    и иерархическому дереву документов.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        on_section_select: Callback при выборе секции.
        on_tree_select: Callback при выборе элемента дерева.

    Example:
        >>> def on_section(section: str) -> None:
        ...     print(f"Selected: {section}")
        >>> sidebar = SideBar(on_section_select=on_section)
        >>> sidebar.mount(parent_frame)
        >>> sidebar.set_mode(SideBarMode.SECTIONS)
    """

    def __init__(
        self,
        widget_id: str = "sidebar",
        controller: Optional[Any] = None,
        on_section_select: Optional[Callable[[str], None]] = None,
        on_tree_select: Optional[Callable[[str], None]] = None,
        sync_service: Optional[SyncServiceProtocol] = None,
        window_manager: Optional[WindowManager] = None,
        drag_drop_service: Optional[DragDropService] = None,
        is_special_mode: bool = False,
        on_sync_status_click: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация SideBar.

        Args:
            widget_id: Уникальный идентификатор виджета (default: "sidebar").
            controller: Опциональная ссылка на контроллер для callbacks.
            on_section_select: Callback при выборе секции.
            on_tree_select: Callback при выборе элемента дерева.
            sync_service: Сервис синхронизации для межоконного обмена.
            window_manager: Менеджер окон для drag-drop операций.
            drag_drop_service: Сервис drag-drop для межоконных операций.
            is_special_mode: Режим Special (показ sync indicator).
            on_sync_status_click: Callback при клике на sync indicator.

        Example:
            >>> sidebar = SideBar(
            ...     on_section_select=lambda s: print(f"Section: {s}"),
            ...     on_tree_select=lambda i: print(f"Tree: {i}"),
            ... )
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._on_section_select: Optional[Callable[[str], None]] = on_section_select
        self._on_tree_select_callback: Optional[Callable[[str], None]] = on_tree_select

        # Sync service integration
        self._sync_service: Optional[SyncServiceProtocol] = sync_service
        self._sync_handler_id: Optional[str] = None

        # Window manager and drag-drop
        self._window_manager: Optional[WindowManager] = window_manager
        self._drag_drop_service: Optional[DragDropService] = drag_drop_service
        self._is_special_mode: bool = is_special_mode
        self._on_sync_status_click: Optional[Callable[[], None]] = on_sync_status_click

        # Sync status
        self._sync_status: str = SyncStatus.OFFLINE
        self._sync_target_window_id: Optional[str] = None

        # Internal state
        self._mode: SideBarMode = SideBarMode.SECTIONS
        self._is_collapsed: bool = False
        self._selected_section: Optional[str] = None
        self._selected_tree_item: Optional[str] = None
        self._filter_query: str = ""
        self._selected_item: Optional[str] = None
        self._sync_enabled: bool = False

        # Drag-drop state (tree items)
        self._drag_item_id: Optional[str] = None
        self._drag_start_x: int = 0
        self._drag_start_y: int = 0
        self._drag_active: bool = False
        self._drag_floating_label: Optional[tk.Toplevel] = None
        self._drag_window_id: Optional[str] = None

        # Tree data storage (item_id -> (display_name, file_path))
        self._tree_data: dict[str, tuple[str, Optional[str]]] = {}

        # Detached tree items (item_id -> parent) for filter restore
        self._detached_parents: dict[str, str] = {}

        # Sync manager / drag handle
        self._sync_manager: Optional[SideBarSyncManager] = None
        self._drag_handle: Optional[TreeItemDragHandle] = None

        # Widget references
        self._tk_frame: Optional[tk.Frame] = None
        self._tk_header_frame: Optional[tk.Frame] = None
        self._tk_content_frame: Optional[tk.Frame] = None
        self._tk_collapse_btn: Optional[tk.Button] = None
        self._tk_search_entry: Optional[tk.Entry] = None
        self._tk_sections_frame: Optional[tk.Frame] = None
        self._tk_tree: Optional[ttk.Treeview] = None
        self._tk_tree_frame: Optional[tk.Frame] = None
        self._section_buttons: dict[str, tk.Button] = {}
        self._tk_sync_indicator: Optional[tk.Label] = None
        self._tk_sync_label: Optional[tk.Label] = None
        self._tk_sync_enabled_indicator: Optional[tk.Label] = None
        self._tk_no_matches_label: Optional[tk.Label] = None
        self._tk_tooltip_window: Optional[tk.Toplevel] = None
        self._tk_drag_popup: Optional[tk.Toplevel] = None

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame SideBar.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._tk_frame is None:
            raise RuntimeError("SideBar not mounted")
        return self._tk_frame

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует виджет и регистрирует sync handler.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.
        """
        widget = super().mount(parent)

        # Register sync handler if service available
        if self._sync_service:
            self._sync_handler_id = self._sync_service.register_handler(
                DATA_SIDEBAR_STATE,
                self.widget_id,
                self._on_sync_message,
            )

        # Create sync indicator in special mode
        if self._is_special_mode:
            self._create_sync_indicator()

        return widget

    def unmount(self) -> None:
        """Демонтирует виджет и очищает sync handler."""
        # Unregister sync handler before cleanup
        if self._sync_service and self._sync_handler_id:
            self._sync_service.unregister_handler(self._sync_handler_id)
            self._sync_handler_id = None

        super().unmount()

    def show(self) -> None:
        """Показывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.pack()

    def hide(self) -> None:
        """Скрывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.pack_forget()

    def is_visible(self) -> bool:
        """Проверяет видимость компонента.

        Returns:
            True если виджет отображается.
        """
        if self._tk_frame is None:
            return False
        return self._tk_frame.winfo_viewable() == 1

    def set_mode(self, mode: SideBarMode) -> None:
        """Устанавливает режим отображения SideBar.

        Args:
            mode: Режим отображения (SECTIONS или TREE).

        Example:
            >>> sidebar.set_mode(SideBarMode.TREE)
            >>> # Переключается на отображение дерева
        """
        self._mode = mode
        self._apply_mode()

    def set_collapsed(self, collapsed: bool) -> None:
        """Устанавливает состояние свёрнутости SideBar.

        Args:
            collapsed: True для сворачивания, False для разворачивания.

        Example:
            >>> sidebar.set_collapsed(True)
            >>> # Сжимается до SIDEBAR_COLLAPSED_WIDTH
        """
        self._is_collapsed = collapsed
        self._apply_collapsed_state()

    def filter_items(self, query: str) -> None:
        """Фильтрует элементы по запросу.

        Args:
            query: Строка поиска для фильтрации.

        Security:
            - Query ограничен 100 символами
            - Спецсимволы удаляются
            - Не используется eval/exec

        Example:
            >>> sidebar.filter_items("report")
            >>> # Показывает только элементы, содержащие "report"
        """
        sanitized = self._sanitize_query(query)
        self._filter_query = sanitized.lower()
        self._apply_filter()

    def get_selected(self) -> str | None:
        """Возвращает выбранный элемент.

        Returns:
            ID выбранной секции или элемента дерева, или None.

        Example:
            >>> selected = sidebar.get_selected()
            >>> if selected:
            ...     print(f"Selected: {selected}")
        """
        if self._mode == SideBarMode.SECTIONS:
            return self._selected_section
        else:
            return self._selected_tree_item

    def add_tree_item(
        self,
        item_id: str,
        display_name: str,
        parent: str = "",
        file_path: Optional[str] = None,
        sync_status: str = SyncStatus.OFFLINE,
    ) -> None:
        """Добавляет элемент в дерево.

        Args:
            item_id: Уникальный идентификатор элемента.
            display_name: Отображаемое имя.
            parent: ID родительского элемента (пусто для корня).
            file_path: Путь к файлу для определения иконки.
            sync_status: Начальный статус синхронизации (default: OFFLINE).

        Example:
            >>> sidebar.add_tree_item("doc_1", "Report Q1", "")
            >>> sidebar.add_tree_item("doc_1_1", "Section A", "doc_1")
        """
        self._tree_data[item_id] = (display_name, file_path)
        if self._tk_tree is not None:
            icon = get_file_icon(file_path or display_name)
            base_text = f"{icon} {display_name}"
            self._tk_tree.insert(
                parent if parent else "",
                "end",
                iid=item_id,
                text=base_text,
            )
            if self._sync_manager is not None:
                self._sync_manager.register_item(item_id, base_text, sync_status)

    def clear_tree(self) -> None:
        """Очищает дерево.

        Example:
            >>> sidebar.clear_tree()
            >>> # Все элементы дерева удалены
        """
        self._tree_data.clear()
        if self._tk_tree is not None:
            for item in self._tk_tree.get_children():
                self._tk_tree.delete(item)

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame SideBar.
        """
        # Root frame
        self._tk_frame = tk.Frame(
            parent,
            width=SIDEBAR_WIDTH,
            bg=DEFAULT_BG,
            relief="flat",
        )
        self._tk_frame.pack_propagate(False)

        # Header frame
        self._tk_header_frame = tk.Frame(self._tk_frame, bg=HEADER_BG, height=35)
        self._tk_header_frame.pack(fill="x", side="top")
        self._tk_header_frame.pack_propagate(False)

        # Collapse button
        self._tk_collapse_btn = tk.Button(
            self._tk_header_frame,
            text="[=]",
            bg=HEADER_BG,
            fg=DEFAULT_FG,
            relief="flat",
            cursor="hand2",
            command=self._on_collapse_click,
        )
        self._tk_collapse_btn.pack(side="left", padx=PADDING_SMALL)

        # Search entry
        self._tk_search_entry = tk.Entry(
            self._tk_header_frame,
            bg="white",
            fg=PLACEHOLDER_FG,
            relief="sunken",
            bd=1,
        )
        self._tk_search_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=PADDING_SMALL,
            pady=PADDING_SMALL,
        )
        self._tk_search_entry.insert(0, PLACEHOLDER_TEXT)
        self._tk_search_entry.bind("<KeyRelease>", self._on_search_change)
        self._tk_search_entry.bind("<FocusIn>", self._on_search_focus_in)
        self._tk_search_entry.bind("<FocusOut>", self._on_search_focus_out)

        # Sync enabled indicator (initially hidden, shown in special mode)
        self._tk_sync_enabled_indicator = tk.Label(
            self._tk_header_frame,
            text="⟳",
            font=("Segoe UI Emoji", 11),
            bg=HEADER_BG,
            fg="#0080FF",
            cursor="hand2",
        )
        self._tk_sync_enabled_indicator.bind("<Enter>", self._on_sync_tooltip_show)
        self._tk_sync_enabled_indicator.bind("<Leave>", self._on_sync_tooltip_hide)
        if self._is_special_mode:
            self._tk_sync_enabled_indicator.pack(side="right", padx=PADDING_SMALL)

        # Content frame
        self._tk_content_frame = tk.Frame(self._tk_frame, bg=DEFAULT_BG)
        self._tk_content_frame.pack(fill="both", expand=True)

        # No matches label (initially hidden)
        self._tk_no_matches_label = tk.Label(
            self._tk_content_frame,
            text="No matches",
            bg=DEFAULT_BG,
            fg=PLACEHOLDER_FG,
            font=("Helvetica", 10),
        )

        # Create sections and tree views
        self._create_sections_view()
        self._create_tree_view()

        # Apply initial mode
        self._apply_mode()

        return self._tk_frame

    def set_special_mode(self, enabled: bool) -> None:
        """Устанавливает Special Mode.

        Args:
            enabled: True для включения Special Mode.
        """
        self._is_special_mode = enabled
        if self._tk_frame is not None and self._is_special_mode:
            self._create_sync_indicator()
            if self._tk_sync_enabled_indicator is not None:
                self._tk_sync_enabled_indicator.pack(side="right", padx=PADDING_SMALL)
                self.set_sync_enabled(self._sync_enabled)
        else:
            if self._tk_sync_indicator is not None:
                self._tk_sync_indicator.pack_forget()
            if self._tk_sync_label is not None:
                self._tk_sync_label.pack_forget()
            if self._tk_sync_enabled_indicator is not None:
                self._tk_sync_enabled_indicator.pack_forget()

    def set_sync_enabled(self, enabled: bool) -> None:
        """Устанавливает состояние индикатора синхронизации.

        Args:
            enabled: True для отображения индикатора синхронизации.
        """
        self._sync_enabled = enabled
        if self._tk_sync_enabled_indicator is None:
            return
        if self._is_special_mode and enabled:
            self._tk_sync_enabled_indicator.pack(side="right", padx=PADDING_SMALL)
        else:
            self._tk_sync_enabled_indicator.pack_forget()

    def set_sync_status(self, status: str, target_window_id: Optional[str] = None) -> None:
        """Устанавливает статус синхронизации.

        Args:
            status: Статус из SyncStatus (SYNCED, SYNCING, CONFLICT, OFFLINE).
            target_window_id: ID целевого окна для синхронизации.
        """
        self._sync_status = status
        self._sync_target_window_id = target_window_id
        self._update_sync_indicator()

    def _create_sync_indicator(self) -> None:
        """Создаёт индикатор синхронизации."""
        if self._tk_header_frame is None:
            return

        indicator_frame = tk.Frame(self._tk_header_frame, bg=HEADER_BG)
        indicator_frame.pack(side="right", padx=PADDING_SMALL)

        icon = SYNC_STATUS_ICONS.get(self._sync_status, "●")
        color = SYNC_STATUS_COLORS.get(self._sync_status, "#9E9E9E")

        self._tk_sync_indicator = tk.Label(
            indicator_frame,
            text=f"[{icon}]",
            font=("Segoe UI Emoji", 10),
            bg=HEADER_BG,
            fg=color,
            cursor="hand2",
        )
        self._tk_sync_indicator.pack(side="left", padx=(0, 2))
        self._tk_sync_indicator.bind("<Button-1>", self._on_sync_indicator_click)

        self._tk_sync_label = tk.Label(
            indicator_frame,
            text="Synced",
            font=("Helvetica", 8),
            bg=HEADER_BG,
            fg=DEFAULT_FG,
        )
        self._tk_sync_label.pack(side="left")
        self._tk_sync_label.bind("<Button-1>", self._on_sync_indicator_click)

    def _update_sync_indicator(self) -> None:
        """Обновляет отображение индикатора синхронизации.

        Обновляет заголовок и все статусы элементов дерева.
        """
        if self._tk_sync_indicator is None or self._tk_sync_label is None:
            return

        icon = SYNC_STATUS_ICONS.get(self._sync_status, "●")
        color = SYNC_STATUS_COLORS.get(self._sync_status, "#9E9E9E")
        status_text = self._get_sync_status_text()

        self._tk_sync_indicator.config(text=f"[{icon}]", fg=color)
        self._tk_sync_label.config(text=status_text)

        if self._sync_manager is not None:
            self._sync_manager.update_all(self._sync_status)

    def _get_sync_status_text(self) -> str:
        """Возвращает текст статуса синхронизации.

        Returns:
            Текст статуса.
        """
        status_map = {
            SyncStatus.SYNCED: "Synced",
            SyncStatus.SYNCING: "Syncing...",
            SyncStatus.CONFLICT: "Conflict",
            SyncStatus.OFFLINE: "Offline",
        }
        return status_map.get(self._sync_status, "Unknown")

    def _on_sync_indicator_click(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает клик по индикатору синхронизации."""
        if self._on_sync_status_click is not None:
            self._on_sync_status_click()

    def start_document_drag(self, item_id: str, event: tk.Event[Any]) -> None:
        """Начинает drag документа из SideBar.

        Args:
            item_id: ID элемента дерева для drag.
            event: Событие мыши.
        """
        if self._drag_drop_service is None or self._window_manager is None:
            return

        if item_id not in self._tree_data:
            return

        display_name, file_path = self._tree_data[item_id]
        if file_path is None:
            file_path = display_name

        drag_data = DragData(
            source_window_id=self._window_manager.get_main_window_id() or "",
            data_type=DATA_TYPE_DOCUMENT,
            data={"item_id": item_id, "file_path": file_path},
            preview_text=display_name,
            allowed_operations=(DropOperation.MOVE, DropOperation.COPY),
        )

        self._drag_drop_service.start_drag(
            source_window_id=self._window_manager.get_main_window_id() or "",
            data=drag_data,
        )

    def _create_sections_view(self) -> None:
        """Создаёт view для режима SECTIONS."""
        self._tk_sections_frame = tk.Frame(self._tk_content_frame, bg=DEFAULT_BG)

        for section_id, display_text in SECTIONS:
            btn = self._create_section_button(section_id, display_text)
            btn.pack(fill="x", pady=(0, 1))
            self._section_buttons[section_id] = btn

    def _create_section_button(self, section_id: str, display_text: str) -> tk.Button:
        """Создаёт кнопку секции.

        Args:
            section_id: Идентификатор секции.
            display_text: Отображаемый текст.

        Returns:
            Созданная кнопка.
        """

        def _on_click() -> None:
            self._handle_section_click(section_id)

        return tk.Button(
            self._tk_sections_frame,
            text=display_text,
            bg=DEFAULT_BG,
            fg=DEFAULT_FG,
            activebackground=SELECTED_BG,
            activeforeground=SELECTED_FG,
            relief="flat",
            anchor="w",
            padx=PADDING_NORMAL,
            pady=PADDING_SMALL,
            cursor="hand2",
            command=_on_click,
        )

    def _create_tree_view(self) -> None:
        """Создаёт view для режима TREE.

        Добавляет колонки sync_status и drag_handle;
        инициализирует SideBarSyncManager и TreeItemDragHandle.
        """
        tree_frame = tk.Frame(self._tk_content_frame, bg=DEFAULT_BG)

        self._tk_tree = ttk.Treeview(
            tree_frame,
            show="tree",
            selectmode="browse",
            columns=("sync_status", "drag_handle"),
        )

        scrollbar = ttk.Scrollbar(
            tree_frame,
            orient="vertical",
            command=self._tk_tree.yview,
        )
        self._tk_tree.configure(yscrollcommand=scrollbar.set)

        self._tk_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._tk_tree.bind("<<TreeviewSelect>>", self._handle_tree_select_event)

        # Sync manager: следит за статусами элементов
        self._sync_manager = SideBarSyncManager(
            self._tk_tree, SYNC_STATUS_COLORS, SYNC_STATUS_ICONS
        )

        # Drag handle: hover-иконка для drag
        self._drag_handle = TreeItemDragHandle(
            self._tk_tree,
            on_handle_state_change=self._on_drag_handle_state_change,
        )

        # Drag-drop bindings on left mouse button
        if self._drag_drop_service is not None:
            self._tk_tree.bind("<ButtonPress-1>", self._on_tree_drag_press)
            self._tk_tree.bind("<B1-Motion>", self._on_tree_drag_motion)
            self._tk_tree.bind("<ButtonRelease-1>", self._on_tree_drag_release)

        self._tk_tree_frame = tree_frame

    def _on_drag_handle_state_change(self, item_id: str, visible: bool) -> None:
        """Обрабатывает смену hover-состояния drag handle.

        Args:
            item_id: Идентификатор элемента.
            visible: True если handle стал видимым.
        """
        if self._sync_manager is not None:
            self._sync_manager.set_handle_visible(item_id, visible)

    def _on_tree_drag_press(self, event: Optional[tk.Event[Any]] = None) -> None:
        """Обрабатывает нажатие кнопки мыши на элементе дерева.

        Запоминает item_id и начальные координаты для определения drag.
        Не блокирует обычный click/select — drag начинается только при
        смещении курсора на DRAG_THRESHOLD пикселей.

        Args:
            event: Событие нажатия мыши.
        """
        if self._tk_tree is None or event is None:
            return

        item_id = self._tk_tree.identify_row(event.y)
        if not item_id or item_id not in self._tree_data:
            return

        self._drag_item_id = item_id
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root
        # Если handle активен — уменьшаем порог начала drag
        if self._drag_handle is not None and self._drag_handle.is_handle_active(item_id):
            self._drag_active = True
            self._show_floating_label(event.x_root, event.y_root)
            if self._drag_drop_service is not None and self._window_manager is not None:
                self.start_document_drag(self._drag_item_id, event)
        else:
            self._drag_active = False
        self._drag_window_id = (
            self._window_manager.get_main_window_id() if self._window_manager else None
        )

    def _on_tree_drag_motion(self, event: Optional[tk.Event[Any]] = None) -> None:
        """Обрабатывает движение мыши с зажатой кнопкой.

        Если смещение превышает DRAG_THRESHOLD — инициирует drag через
        DragDropService и показывает floating label.

        Args:
            event: Событие движения мыши.
        """
        if self._drag_item_id is None or event is None:
            return

        dx = abs(event.x_root - self._drag_start_x)
        dy = abs(event.y_root - self._drag_start_y)

        if not self._drag_active and max(dx, dy) >= DRAG_THRESHOLD:
            self._drag_active = True
            self._show_floating_label(event.x_root, event.y_root)
            # Start drag via DragDropService
            if self._drag_drop_service is not None and self._window_manager is not None:
                self.start_document_drag(self._drag_item_id, event)

        if self._drag_active and self._drag_floating_label is not None:
            self._update_floating_label(event.x_root, event.y_root)

    def _on_tree_drag_release(self, event: Optional[tk.Event[Any]] = None) -> None:
        """Обрабатывает отпускание кнопки мыши.

        Если drag был активен — определяет целевое окно и показывает popup
        с выбором операции (Move / Copy / Cancel). DragDropService сессия
        завершается только после выбора пользователя, а не отменяется
        преждевременно. Обычный click/select при коротком нажатии не ломается.

        Args:
            event: Событие отпускания мыши.
        """
        if not self._drag_active:
            # Это был обычный клик — drag не начинался
            self._reset_drag_state()
            return

        self._drag_active = False
        # Сохраняем item_id до сброса состояния
        item_id = self._drag_item_id

        try:
            # Identify target window at release coordinates
            target_window_id: Optional[str] = None
            if self._window_manager is not None and event is not None:
                target_window_id = self._find_target_window_at(event.x_root, event.y_root)

            if item_id and target_window_id:
                self._show_drag_popup(item_id, target_window_id)
            else:
                # Нет валидной цели — отменяем сессию DragDropService
                if self._drag_drop_service is not None and self._drag_drop_service.is_dragging():
                    self._drag_drop_service.cancel_drag()
        finally:
            self._reset_drag_state()
            self._destroy_floating_label()

    def _show_floating_label(self, x: int, y: int) -> None:
        """Создаёт floating label с превью перетаскиваемого документа.

        Args:
            x: X координата экрана.
            y: Y координата экрана.
        """
        if self._drag_item_id is None or self._tk_frame is None:
            return

        display_name, file_path = self._tree_data.get(self._drag_item_id, ("", None))
        label_text = f"Move {display_name or file_path or 'Document'}"

        self._drag_floating_label = tk.Toplevel(self._tk_frame)
        self._drag_floating_label.wm_overrideredirect(True)
        self._drag_floating_label.attributes("-alpha", 0.8)
        self._drag_floating_label.attributes("-topmost", True)

        frame = tk.Frame(
            self._drag_floating_label,
            bg="#4a90d9",
            padx=12,
            pady=6,
            relief=tk.RAISED,
            bd=1,
        )
        frame.pack()

        lbl = tk.Label(
            frame,
            text=label_text,
            font=("Helvetica", 9, "bold"),
            bg="#4a90d9",
            fg="white",
            wraplength=180,
        )
        lbl.pack()

        self._update_floating_label(x, y)

    def _update_floating_label(self, x: int, y: int) -> None:
        """Обновляет позицию floating label.

        Args:
            x: X координата экрана.
            y: Y координата экрана.
        """
        if self._drag_floating_label is not None:
            self._drag_floating_label.wm_geometry(f"+{x + 12}+{y + 12}")

    def _destroy_floating_label(self) -> None:
        """Уничтожает floating label."""
        if self._drag_floating_label is not None:
            try:
                self._drag_floating_label.destroy()
            except tk.TclError:
                pass
            self._drag_floating_label = None

    def _reset_drag_state(self) -> None:
        """Сбрасывает drag состояние."""
        self._drag_item_id = None
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._drag_active = False
        self._drag_window_id = None

    def _find_target_window_at(self, x: int, y: int) -> Optional[str]:
        """Находит ID окна под указанными координатами.

        Args:
            x: X координата экрана.
            y: Y координата экрана.

        Returns:
            Идентификатор целевого окна или None.
        """
        if self._window_manager is None:
            return None

        for info in self._window_manager.get_window_list():
            try:
                widget = info.toplevel
                wx = widget.winfo_rootx()
                wy = widget.winfo_rooty()
                ww = widget.winfo_width()
                wh = widget.winfo_height()
                if wx <= x <= wx + ww and wy <= y <= wy + wh:
                    return info.window_id
            except tk.TclError:
                continue

        return None

    def _show_drag_popup(self, item_id: str, target_window_id: str) -> None:
        """Показывает popup с выбором операции при drop на другое окно.

        DragDropService сессия завершается только после выбора пользователя:
        - Move/Copy: завершает сессию после инициирования операции.
        - Cancel: отменяет сессию явно.

        Args:
            item_id: ID перетаскиваемого элемента.
            target_window_id: ID целевого окна.
        """
        if self._tk_frame is None:
            return

        # Уничтожаем предыдущий popup если существует
        if self._tk_drag_popup is not None:
            try:
                self._tk_drag_popup.destroy()
            except tk.TclError:
                pass
            self._tk_drag_popup = None

        self._tk_drag_popup = tk.Toplevel(self._tk_frame)
        self._tk_drag_popup.title("Перемещение документа")
        self._tk_drag_popup.geometry("240x100")
        self._tk_drag_popup.resizable(False, False)
        self._tk_drag_popup.transient(self._tk_frame)  # type: ignore[call-overload]
        try:
            self._tk_drag_popup.grab_set()
        except tk.TclError:
            pass

        # Center popup over current window
        self._tk_frame.update_idletasks()
        px = self._tk_frame.winfo_rootx() + (self._tk_frame.winfo_width() // 2) - 120
        py = self._tk_frame.winfo_rooty() + (self._tk_frame.winfo_height() // 2) - 50
        self._tk_drag_popup.geometry(f"+{px}+{py}")

        display_name, _ = self._tree_data.get(item_id, (item_id, None))
        msg = tk.Label(
            self._tk_drag_popup,
            text=f'"{display_name}" to window {target_window_id[:8]}...',
            font=("Helvetica", 10),
        )
        msg.pack(pady=(8, 4))

        btn_frame = tk.Frame(self._tk_drag_popup)
        btn_frame.pack(pady=4)

        def _move() -> None:
            if self._tk_drag_popup is not None:
                try:
                    self._tk_drag_popup.destroy()
                except tk.TclError:
                    pass
                self._tk_drag_popup = None
            self._perform_move_or_copy("move", item_id, target_window_id)
            # Завершаем сессию drag после инициирования операции
            if self._drag_drop_service is not None and self._drag_drop_service.is_dragging():
                self._drag_drop_service.cancel_drag()

        def _copy() -> None:
            if self._tk_drag_popup is not None:
                try:
                    self._tk_drag_popup.destroy()
                except tk.TclError:
                    pass
                self._tk_drag_popup = None
            self._perform_move_or_copy("copy", item_id, target_window_id)
            # Завершаем сессию drag после инициирования операции
            if self._drag_drop_service is not None and self._drag_drop_service.is_dragging():
                self._drag_drop_service.cancel_drag()

        def _cancel() -> None:
            if self._tk_drag_popup is not None:
                try:
                    self._tk_drag_popup.destroy()
                except tk.TclError:
                    pass
                self._tk_drag_popup = None
            # Явная отмена сессии drag
            if self._drag_drop_service is not None and self._drag_drop_service.is_dragging():
                self._drag_drop_service.cancel_drag()

        tk.Button(btn_frame, text="➕ Move here", command=_move).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="➕ Copy here", command=_copy).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="➖ Cancel", command=_cancel).pack(side=tk.LEFT, padx=4)

    def _perform_move_or_copy(self, operation: str, item_id: str, target_window_id: str) -> None:
        """Выполняет перемещение или копирование документа через контроллер.

        Делегирует фактическую операцию через controller.dispatch или
        напрямую через WindowManager / SyncService.

        Args:
            operation: Операция ("move" или "copy").
            item_id: ID документа.
            target_window_id: ID целевого окна.
        """
        source_window_id = self._drag_window_id or (
            self._window_manager.get_main_window_id() if self._window_manager else None
        )

        # Prefer controller dispatch (architecture compliant)
        if self._controller is not None:
            self._controller.dispatch(
                "document_transfer",
                operation=operation,
                item_id=item_id,
                source_window_id=source_window_id,
                target_window_id=target_window_id,
            )
            return

        # Fallback: direct WindowManager / SyncService calls
        if operation == "move" and self._window_manager is not None and source_window_id:
            self._window_manager.transfer_document(source_window_id, target_window_id, item_id)

        if self._sync_service is not None:
            self._sync_service.broadcast(
                source_window_id=source_window_id or "",
                data_type="document_update",
                data={
                    "action": operation,
                    "item_id": item_id,
                    "source_window_id": source_window_id,
                    "target_window_id": target_window_id,
                },
            )

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        # Escape to clear search
        if self._tk_search_entry is not None:
            self._tk_search_entry.bind("<Escape>", self._on_search_escape)

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        if self._sync_manager is not None:
            self._sync_manager.unmount()
            self._sync_manager = None
        if self._drag_handle is not None:
            self._drag_handle.unmount()
            self._drag_handle = None
        # Уничтожаем Toplevel окна, чтобы не осталось висячих
        if self._tk_tooltip_window is not None:
            try:
                self._tk_tooltip_window.destroy()
            except tk.TclError:
                pass
            self._tk_tooltip_window = None
        if self._drag_floating_label is not None:
            try:
                self._drag_floating_label.destroy()
            except tk.TclError:
                pass
            self._drag_floating_label = None
        if self._tk_drag_popup is not None:
            try:
                self._tk_drag_popup.destroy()
            except tk.TclError:
                pass
            self._tk_drag_popup = None
        self._section_buttons.clear()
        self._tree_data.clear()
        self._tk_sections_frame = None
        self._tk_tree_frame = None
        self._tk_tree = None
        self._tk_search_entry = None
        self._tk_collapse_btn = None
        self._tk_header_frame = None
        self._tk_content_frame = None
        self._tk_frame = None

    def _apply_mode(self) -> None:
        """Применяет текущий режим отображения."""
        if self._tk_sections_frame is None or self._tk_tree_frame is None:
            return

        # Hide both first
        self._tk_sections_frame.pack_forget()
        self._tk_tree_frame.pack_forget()

        # Show active mode
        if self._mode == SideBarMode.SECTIONS:
            self._tk_sections_frame.pack(fill="both", expand=True)
        else:
            self._tk_tree_frame.pack(fill="both", expand=True)

        self._apply_filter()

    def _apply_collapsed_state(self) -> None:
        """Применяет состояние свёрнутости."""
        if self._tk_frame is None:
            return

        if self._is_collapsed:
            self._tk_frame.config(width=SIDEBAR_COLLAPSED_WIDTH)
            # Hide header elements except collapse button
            if self._tk_search_entry is not None:
                self._tk_search_entry.pack_forget()
            if self._tk_sync_enabled_indicator is not None:
                self._tk_sync_enabled_indicator.pack_forget()
            if self._tk_sync_indicator is not None:
                self._tk_sync_indicator.pack_forget()
            if self._tk_sync_label is not None:
                self._tk_sync_label.pack_forget()
            # Update collapse button icon
            if self._tk_collapse_btn is not None:
                self._tk_collapse_btn.config(text=">")
        else:
            self._tk_frame.config(width=SIDEBAR_WIDTH)
            # Show search entry
            if self._tk_search_entry is not None:
                self._tk_search_entry.pack(
                    side="left",
                    fill="x",
                    expand=True,
                    padx=PADDING_SMALL,
                    pady=PADDING_SMALL,
                )
            # Восстанавливаем sync indicator, если special mode включён
            if self._is_special_mode:
                if self._sync_enabled and self._tk_sync_enabled_indicator is not None:
                    self._tk_sync_enabled_indicator.pack(side="right", padx=PADDING_SMALL)
                if self._tk_sync_indicator is not None:
                    self._tk_sync_indicator.pack(side="left", padx=(0, 2))
                if self._tk_sync_label is not None:
                    self._tk_sync_label.pack(side="left")
            # Update collapse button icon
            if self._tk_collapse_btn is not None:
                self._tk_collapse_btn.config(text="[=]")

    def _apply_filter(self) -> None:
        """Применяет фильтрацию к текущему режиму."""
        if not self._filter_query:
            # Show all
            self._show_all_items()
            return

        if self._mode == SideBarMode.SECTIONS:
            self._filter_sections()
        else:
            self._filter_tree()

    def _show_all_items(self) -> None:
        """Показывает все элементы (сброс фильтра)."""
        self._hide_no_matches()

        # Show all sections
        for btn in self._section_buttons.values():
            btn.pack(fill="x", pady=(0, 1))

        # Show all tree items
        if self._tk_tree is not None:
            self._restore_tree_items()

    def _filter_sections(self) -> None:
        """Фильтрует секции по запросу."""
        # Build lookup dict for safe access
        section_display: dict[str, str] = {s[0]: s[1] for s in SECTIONS}

        any_visible = False
        for section_id, btn in self._section_buttons.items():
            display_text = section_display.get(section_id, section_id)
            if self._filter_query in display_text.lower():
                btn.pack(fill="x", pady=(0, 1))
                any_visible = True
            else:
                btn.pack_forget()

        if not any_visible:
            self._show_no_matches()
        else:
            self._hide_no_matches()

    def _filter_tree(self) -> None:
        """Фильтрует элементы дерева по запросу."""
        if self._tk_tree is None:
            return

        # Get all visible items
        visible_items: set[str] = set()
        for item_id, (display_name, _) in self._tree_data.items():
            if self._filter_query in display_name.lower():
                visible_items.add(item_id)
                # Add all parents
                parent = self._tk_tree.parent(item_id)
                while parent:
                    visible_items.add(parent)
                    parent = self._tk_tree.parent(parent)

        # Собираем ID успешно восстановленных элементов, чтобы удалить
        # их из _detached_parents после завершения рекурсии (не во время).
        restored_ids: set[str] = set()
        any_visible = False
        for item_id in self._tk_tree.get_children():
            if self._filter_tree_recursive(item_id, visible_items, restored_ids):
                any_visible = True

        # Удаляем успешно восстановленные записи из _detached_parents
        for restored_id in restored_ids:
            self._detached_parents.pop(restored_id, None)

        if not any_visible:
            self._show_no_matches()
        else:
            self._hide_no_matches()

    def _filter_tree_recursive(
        self, item_id: str, visible_items: set[str], restored_ids: set[str]
    ) -> bool:
        """Рекурсивно фильтрует дерево.

        Не модифицирует _detached_parents во время рекурсии (pop).
        Вместо этого собирает ID восстановленных элементов в restored_ids,
        которые удаляются из _detached_parents после завершения обхода.

        Args:
            item_id: Текущий элемент.
            visible_items: Множество видимых элементов.
            restored_ids: Множество ID успешно восстановленных элементов
                (заполняется во время рекурсии, удаляется из _detached_parents
                после её завершения).

        Returns:
            True если элемент или его потомки видимы.
        """
        if self._tk_tree is None:
            return False

        # Check children first
        has_visible_children = False
        for child_id in self._tk_tree.get_children(item_id):
            if self._filter_tree_recursive(child_id, visible_items, restored_ids):
                has_visible_children = True

        is_visible = item_id in visible_items or has_visible_children

        if is_visible:
            self._tk_tree.item(item_id, open=True)
            if item_id in self._detached_parents:
                parent_id = self._detached_parents[item_id]
                try:
                    self._tk_tree.move(item_id, parent_id, "end")
                    restored_ids.add(item_id)
                except tk.TclError:
                    pass
        else:
            parent = self._tk_tree.parent(item_id)
            if parent:
                self._detached_parents[item_id] = parent
            try:
                self._tk_tree.detach(item_id)
            except tk.TclError:
                pass

        return is_visible

    def _restore_tree_items(self) -> None:
        """Восстанавливает все элементы дерева."""
        if self._tk_tree is None:
            return

        for item_id, parent_id in self._detached_parents.items():
            try:
                self._tk_tree.move(item_id, parent_id, "end")
            except tk.TclError:
                pass
        self._detached_parents.clear()

        for item_id in self._tk_tree.get_children():
            self._tk_tree.item(item_id, open=True)

    def _show_no_matches(self) -> None:
        """Показывает сообщение об отсутствии результатов."""
        if self._tk_no_matches_label is not None:
            self._tk_no_matches_label.place(relx=0.5, rely=0.5, anchor="center")

    def _hide_no_matches(self) -> None:
        """Скрывает сообщение об отсутствии результатов."""
        if self._tk_no_matches_label is not None:
            self._tk_no_matches_label.place_forget()

    def _on_search_focus_in(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает получение фокуса полем поиска."""
        if self._tk_search_entry is not None:
            current = self._tk_search_entry.get()
            if current == PLACEHOLDER_TEXT:
                self._tk_search_entry.delete(0, "end")
                self._tk_search_entry.config(fg=DEFAULT_FG)

    def _on_search_focus_out(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает потерю фокуса полем поиска."""
        if self._tk_search_entry is not None:
            current = self._tk_search_entry.get()
            if current == "":
                self._tk_search_entry.insert(0, PLACEHOLDER_TEXT)
                self._tk_search_entry.config(fg=PLACEHOLDER_FG)

    def _on_sync_tooltip_show(self, event: Optional[tk.Event] = None) -> None:
        """Показывает tooltip для индикатора синхронизации."""
        if self._tk_sync_enabled_indicator is None or self._tk_frame is None:
            return
        if self._tk_tooltip_window is not None:
            try:
                if self._tk_tooltip_window.winfo_exists():
                    return
            except tk.TclError:
                pass
            self._tk_tooltip_window = None

        x = self._tk_sync_enabled_indicator.winfo_rootx()
        y = self._tk_sync_enabled_indicator.winfo_rooty() - 20
        self._tk_tooltip_window = tk.Toplevel(self._tk_frame)
        self._tk_tooltip_window.wm_overrideredirect(True)
        self._tk_tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self._tk_tooltip_window,
            text="Sync enabled",
            bg="white",
            fg="black",
            relief="solid",
            bd=1,
            font=("Helvetica", 9),
        )
        label.pack()

    def _on_sync_tooltip_hide(self, event: Optional[tk.Event] = None) -> None:
        """Скрывает tooltip для индикатора синхронизации."""
        if self._tk_tooltip_window is not None:
            try:
                self._tk_tooltip_window.destroy()
            except tk.TclError:
                pass
            self._tk_tooltip_window = None

    def _on_collapse_click(self) -> None:
        """Обрабатывает клик по кнопке сворачивания."""
        self.set_collapsed(not self._is_collapsed)

        # Broadcast changes to other windows
        if self._sync_service:
            self._sync_service.broadcast(
                self.widget_id,
                DATA_SIDEBAR_STATE,
                {"collapsed": self._is_collapsed, "selected": self._selected_item},
            )

    def _on_sync_message(self, message: SyncMessage) -> None:
        """Обработка входящих синхронизационных сообщений.

        Args:
            message: Сообщение синхронизации с данными.
        """
        if message["data_type"] == DATA_SIDEBAR_STATE:
            self._apply_sidebar_state(message["data"])

    def _apply_sidebar_state(self, data: dict[str, Any]) -> None:
        """Применяет состояние SideBar из синхронизации.

        Args:
            data: Данные состояния с ключами collapsed и selected.
        """
        if "collapsed" in data:
            self.set_collapsed(data["collapsed"])
        if "selected" in data:
            self._selected_item = data["selected"]

    def _on_search_change(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает изменение в поле поиска."""
        if self._tk_search_entry is not None:
            query = self._tk_search_entry.get()
            if query == PLACEHOLDER_TEXT:
                query = ""
            self.filter_items(query)

    def _on_search_escape(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает нажатие Escape в поле поиска."""
        if self._tk_search_entry is not None:
            self._tk_search_entry.delete(0, "end")
            self._tk_search_entry.insert(0, PLACEHOLDER_TEXT)
            self._tk_search_entry.config(fg=PLACEHOLDER_FG)
            self.filter_items("")

    def _handle_section_click(self, section_id: str) -> None:
        """Обрабатывает клик по секции.

        Args:
            section_id: Идентификатор выбранной секции.
        """
        self._selected_section = section_id

        # Update visual selection
        for sid, btn in self._section_buttons.items():
            if sid == section_id:
                btn.config(bg=SELECTED_BG, fg=SELECTED_FG)
            else:
                btn.config(bg=DEFAULT_BG, fg=DEFAULT_FG)

        # Call callback
        if self._on_section_select is not None:
            self._on_section_select(section_id)

    def _handle_tree_select_event(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает выбор элемента в дереве."""
        if self._tk_tree is None:
            return

        selection = self._tk_tree.selection()
        if selection:
            self._selected_tree_item = selection[0]
            if self._on_tree_select_callback is not None:
                self._on_tree_select_callback(self._selected_tree_item)

    def _sanitize_query(self, query: str) -> str:
        """Очищает входной запрос от опасных символов.

        Security:
            - Ограничивает длину до 100 символов
            - Удаляет спецсимволы, оставляя alphanumeric + пробелы + дефисы
            - Не использует eval/exec

        Args:
            query: Исходный запрос.

        Returns:
            Очищенный запрос.
        """
        # Limit length
        query = query[:MAX_QUERY_LENGTH]

        # Remove dangerous characters (allow alphanumeric, spaces, hyphens, underscores)
        sanitized = re.sub(r"[^\w\s\-]", "", query)

        return sanitized.strip()


# Module exports
__all__: list[str] = [
    "SideBar",
    "SECTIONS",
    "MAX_QUERY_LENGTH",
    "SyncStatus",
    "SYNC_STATUS_COLORS",
    "SYNC_STATUS_ICONS",
    "FILE_TYPE_ICONS",
    "get_file_icon",
]

__version__: Final[str] = "1.0"
__author__: Final[str] = "FX Text Processor Team"
__date__: Final[str] = "April 2026"
