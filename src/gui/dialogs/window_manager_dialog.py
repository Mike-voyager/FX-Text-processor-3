"""Диалог менеджера окон для FX Text Processor 3.

Предоставляет UI для управления всеми окнами приложения:
- Отображение списка окон с информацией о документах
- Управление Z-order (на передний план)
- Свертывание и закрытие окон
- Групповые операции со всеми окнами
- Автоматическое обновление через SyncService

Example:
    >>> from src.gui.dialogs.window_manager_dialog import WindowManagerDialog
    >>> from src.gui.services.window_manager import WindowManager
    >>> dialog = WindowManagerDialog(
    ...     parent=root,
    ...     window_manager=window_manager,
    ...     sync_service=sync_service,
    ... )
    >>> dialog.show()

Version: 1.0
Date: April 11, 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.services.sync_service import (
    DATA_WINDOW_LIST_CHANGED,
    SyncMessage,
    SyncService,
)
from src.gui.services.window_manager import WindowInfo, WindowManager

logger = logging.getLogger(__name__)

# UI Constants
DIALOG_WIDTH: Final[int] = 600
DIALOG_HEIGHT: Final[int] = 450
MIN_DIALOG_WIDTH: Final[int] = 500
MIN_DIALOG_HEIGHT: Final[int] = 350

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_TEXT: Final[str] = "#212529"

# Window type labels
WINDOW_TYPE_MAIN: Final[str] = "Main Window"
WINDOW_TYPE_DOCUMENT: Final[str] = "Document"
WINDOW_TYPE_DIALOG: Final[str] = "Dialog"


class WindowManagerDialog(BaseDialog):
    """Диалог управления окнами приложения.

    Отображает список всех окон приложения с возможностью
    управления: вывод на передний план, сворачивание,
    закрытие. Поддерживает групповые операции и
    автоматическое обновление списка.

    Attributes:
        _window_manager: Менеджер окон для управления.
        _sync_service: Сервис синхронизации для авто-обновления.
        _handler_id: ID обработчика SyncService для отписки.
        _window_list: Текущий список окон.
        _current_selection: ID выбранного окна в treeview.

    Example:
        >>> dialog = WindowManagerDialog(parent, window_manager, sync_service)
        >>> dialog.show()
    """

    def __init__(
        self,
        parent: tk.Tk,
        window_manager: WindowManager,
        sync_service: Optional[SyncService] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Инициализация диалога менеджера окон.

        Args:
            parent: Родительский виджет.
            window_manager: Менеджер окон для управления.
            sync_service: Сервис синхронизации для авто-обновления.
            *args: Дополнительные аргументы для Toplevel.
            **kwargs: Дополнительные именованные аргументы.
        """
        super().__init__(parent, *args, **kwargs)

        self._parent: tk.Tk = parent
        self._window_manager: WindowManager = window_manager
        self._sync_service: Optional[SyncService] = sync_service
        self._handler_id: Optional[str] = None
        self._window_list: list[WindowInfo] = []
        self._current_selection: Optional[str] = None

        self._create_ui()
        self._setup_window()
        self._setup_sync_subscription()
        self._load_window_list()

    def _setup_window(self) -> None:
        """Настраивает параметры окна диалога."""
        self.title("Manage Windows")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center the dialog
        self.update_idletasks()
        parent_x = self._parent.winfo_rootx()
        parent_y = self._parent.winfo_rooty()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2
        self.geometry(f"+{x}+{y}")

        # Bind ESC to close
        self.bind("<Escape>", lambda _: self._close())

    def _setup_sync_subscription(self) -> None:
        """Настраивает подписку на обновления списка окон."""
        if self._sync_service is not None:
            self._handler_id = self._sync_service.register_handler(
                DATA_WINDOW_LIST_CHANGED,
                "window_manager_dialog",
                self._on_window_list_changed,
            )

    def _on_window_list_changed(self, message: SyncMessage) -> None:
        """Обрабатывает изменение списка окон.

        Args:
            message: Сообщение синхронизации.
        """
        # Обновляем список окон в главном потоке
        self._after_ids.append(self.after(0, self._load_window_list))

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        self.config(bg=COLOR_BG)

        # Main container with padding
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)  # Treeview row

        # Header section
        self._create_header(main_frame)

        # Treeview section
        self._create_treeview(main_frame)

        # Button bar
        self._create_button_bar(main_frame)

    def _create_header(self, parent: ttk.Frame) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский фрейм.
        """
        # Title
        title = ttk.Label(
            parent,
            text="Manage Windows",
            font=("Helvetica", 14, "bold"),
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

    def _create_treeview(self, parent: ttk.Frame) -> None:
        """Создаёт Treeview для отображения списка окон.

        Args:
            parent: Родительский фрейм.
        """
        # Treeview frame with label
        tree_frame = ttk.LabelFrame(parent, text="Open windows:", padding="10")
        tree_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Treeview with columns
        columns = ("title", "document", "type")
        self._tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=12,
            selectmode="browse",
        )

        # Configure headings
        self._tree.heading("title", text="Title")
        self._tree.heading("document", text="Document")
        self._tree.heading("type", text="Type")

        # Configure column widths
        self._tree.column("title", width=200, minwidth=150)
        self._tree.column("document", width=250, minwidth=150)
        self._tree.column("type", width=100, minwidth=80)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self._tree.yview,
        )
        self._tree.configure(yscrollcommand=scrollbar.set)

        # Grid placement
        self._tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Bind selection event
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _create_button_bar(self, parent: ttk.Frame) -> None:
        """Создаёт панель кнопок.

        Args:
            parent: Родительский фрейм.
        """
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        button_frame.columnconfigure(0, weight=1)

        # Arrange section (per UI_SPEC §15.1)
        arrange_frame = ttk.LabelFrame(button_frame, text="Arrange", padding="5")
        arrange_frame.grid(row=0, column=0, sticky="w", padx=(0, 10))

        ttk.Button(
            arrange_frame,
            text="Tile Horizontally",
            command=self._tile_horizontal,
        ).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            arrange_frame,
            text="Tile Vertically",
            command=self._tile_vertical,
        ).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            arrange_frame,
            text="Cascade",
            command=self._cascade,
        ).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            arrange_frame,
            text="Minimize All",
            command=self._minimize_all,
        ).pack(side=tk.LEFT)

        # Left side - individual actions
        left_buttons = ttk.Frame(button_frame)
        left_buttons.grid(row=1, column=0, sticky="w", pady=(10, 0))

        self._bring_to_front_button = ttk.Button(
            left_buttons,
            text="Bring to Front",
            command=self._bring_to_front,
            state=tk.DISABLED,
        )
        self._bring_to_front_button.pack(side=tk.LEFT, padx=(0, 5))

        self._minimize_button = ttk.Button(
            left_buttons,
            text="Minimize",
            command=self._minimize_selected,
            state=tk.DISABLED,
        )
        self._minimize_button.pack(side=tk.LEFT, padx=(0, 5))

        self._close_button = ttk.Button(
            left_buttons,
            text="Close",
            command=self._close_selected,
            state=tk.DISABLED,
        )
        self._close_button.pack(side=tk.LEFT)

        # Middle - group operations + New Window
        middle_buttons = ttk.Frame(button_frame)
        middle_buttons.grid(row=1, column=1, sticky="ew", padx=(20, 0), pady=(10, 0))

        ttk.Button(
            middle_buttons,
            text="New Window",
            command=self._new_window,
        ).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            middle_buttons,
            text="Close All Except Main",
            command=self._close_all_except_main,
        ).pack(side=tk.LEFT)

        # Right side - Close dialog button
        self._close_dialog_button = ttk.Button(
            button_frame,
            text="Close",
            command=self._close,
        )
        self._close_dialog_button.grid(row=1, column=2, sticky="e", pady=(10, 0))

    def _load_window_list(self) -> None:
        """Загружает и отображает список окон."""
        # Clear existing items
        for item in self._tree.get_children():
            self._tree.delete(item)

        self._window_list = self._window_manager.get_window_list()
        self._current_selection = None
        self._update_button_states()

        # Determine active window (highest z_order)
        active_window_id: Optional[str] = None
        if self._window_list:
            active_window_id = max(
                self._window_list, key=lambda w: getattr(w, "z_order", 0)
            ).window_id

        # Populate treeview
        for window_info in self._window_list:
            window_type = self._get_window_type(window_info)
            document = self._get_document_display(window_info)
            title = window_info.title
            if window_info.window_id == active_window_id:
                title = f"{title} (active)"

            # Use window_id as iid for easy lookup
            self._tree.insert(
                "",
                tk.END,
                iid=window_info.window_id,
                values=(
                    title,
                    document,
                    window_type,
                ),
                tags=(
                    "main"
                    if window_info.window_id == self._window_manager.get_main_window_id()
                    else "normal",
                ),
            )

        # Configure tags
        self._tree.tag_configure("main", foreground="#0066cc")

    def _get_window_type(self, window_info: WindowInfo) -> str:
        """Определяет тип окна для отображения.

        Args:
            window_info: Информация об окне.

        Returns:
            Строковое представление типа окна.
        """
        if self._window_manager.is_main_window(window_info.window_id):
            return WINDOW_TYPE_MAIN
        elif window_info.is_modal:
            return WINDOW_TYPE_DIALOG
        else:
            return WINDOW_TYPE_DOCUMENT

    def _get_document_display(self, window_info: WindowInfo) -> str:
        """Форматирует путь к документу для отображения.

        Args:
            window_info: Информация об окне.

        Returns:
            Строковое представление пути к документу.
        """
        if window_info.document_path is None:
            return "-"

        path = window_info.document_path
        if isinstance(path, Path):
            # Show filename only, with parent directory
            return f"{path.parent.name}/{path.name}"
        return str(path)

    def _on_tree_select(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает выбор элемента в Treeview.

        Args:
            event: Событие выбора (опционально).
        """
        selection = self._tree.selection()
        if not selection:
            self._current_selection = None
        else:
            self._current_selection = selection[0]

        self._update_button_states()

    def _update_button_states(self) -> None:
        """Обновляет состояние кнопок в зависимости от выбора."""
        if self._current_selection:
            self._bring_to_front_button.configure(state=tk.NORMAL)
            self._minimize_button.configure(state=tk.NORMAL)
            self._close_button.configure(state=tk.NORMAL)
        else:
            self._bring_to_front_button.configure(state=tk.DISABLED)
            self._minimize_button.configure(state=tk.DISABLED)
            self._close_button.configure(state=tk.DISABLED)

    def _bring_to_front(self) -> None:
        """Выводит выбранное окно на передний план."""
        if not self._current_selection:
            return

        try:
            self._window_manager.bring_to_front(self._current_selection)
            self._load_window_list()  # Refresh the list
        except KeyError:
            # Window no longer exists
            self._load_window_list()

    def _minimize_selected(self) -> None:
        """Сворачивает выбранное окно."""
        if not self._current_selection:
            return

        window = self._window_manager.get_window(self._current_selection)
        if window:
            try:
                window.iconify()
                self._load_window_list()  # Refresh the list
            except tk.TclError:
                pass

    def _close_selected(self) -> None:
        """Закрывает выбранное окно."""
        if not self._current_selection:
            return

        # Don't allow closing the main window via this dialog
        if self._window_manager.is_main_window(self._current_selection):
            messagebox.showwarning(
                "Cannot Close",
                "Main window cannot be closed via Window Manager.",
                parent=self,
            )
            return

        window = self._window_manager.get_window(self._current_selection)
        if window:
            try:
                window.destroy()
                # unregister will be called from destroy handler
                self._load_window_list()  # Refresh the list
            except tk.TclError:
                pass

    def _minimize_all(self) -> None:
        """Сворачивает все окна кроме главного."""
        count = self._window_manager.minimize_all()
        if count > 0:
            self._load_window_list()  # Refresh the list

    def _close_all_except_main(self) -> None:
        """Закрывает все окна кроме главного."""
        # Ask for confirmation
        result = messagebox.askyesno(
            "Confirmation",
            "Close all windows except main?\nUnsaved changes will be lost.",
            parent=self,
        )
        if result:
            count = self._window_manager.close_all_except_main()
            if count > 0:
                self._load_window_list()  # Refresh the list

    def _tile_horizontal(self) -> None:
        """Располагает окна горизонтально (stub)."""
        logger.info("Tile Horizontally requested")

    def _tile_vertical(self) -> None:
        """Располагает окна вертикально (stub)."""
        logger.info("Tile Vertically requested")

    def _cascade(self) -> None:
        """Каскадное расположение окон (stub)."""
        logger.info("Cascade requested")

    def _new_window(self) -> None:
        """Создаёт новое окно (stub)."""
        logger.info("New Window requested")

    def _close(self) -> None:
        """Закрывает диалог."""
        # Unsubscribe from sync service
        if self._sync_service is not None and self._handler_id is not None:
            try:
                self._sync_service.unregister_handler(self._handler_id)
            except KeyError:
                pass  # Handler already unregistered

        self.destroy()

    def show(self) -> None:
        """Показывает модальный диалог.

        Блокирует взаимодействие с родительским окном
        до закрытия диалога.
        """
        self.wait_window()


__all__: list[str] = [
    "WindowManagerDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
    "COLOR_BG",
    "WINDOW_TYPE_MAIN",
    "WINDOW_TYPE_DOCUMENT",
    "WINDOW_TYPE_DIALOG",
]
