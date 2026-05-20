"""Диалоги навигации по документу.

Компоненты:
- GotoDialog: Переход к строке/странице
- BookmarksDialog: Управление закладками

Example:
    >>> goto = GotoDialog(parent, total_pages=10, current_page=5)
    >>> page = goto.show()
    >>> if page:
    ...     print(f"Jump to page {page}")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.model.bookmark import Bookmark, BookmarkManager

logger: Final = logging.getLogger(__name__)

# Constants
DIALOG_WIDTH: Final[int] = 400
DIALOG_HEIGHT: Final[int] = 300
MIN_DIALOG_WIDTH: Final[int] = 350
MIN_DIALOG_HEIGHT: Final[int] = 250

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_PRIMARY: Final[str] = "#3498db"
COLOR_SUCCESS: Final[str] = "#28a745"
COLOR_ERROR: Final[str] = "#dc3545"


@dataclass(frozen=True)
class BookmarkItem:
    """Элемент закладки для UI.

    Attributes:
        id: Уникальный ID закладки.
        name: Название закладки.
        page: Номер страницы (1-based).
        line: Номер строки (опционально).
        description: Описание.
    """

    id: str
    name: str
    page: int
    line: int = 0
    description: str = ""
    tags: list[str] = field(default_factory=list)


class GotoDialog(BaseDialog):
    """Диалог перехода к позиции в документе.

    Поддерживает переход:
    - По номеру страницы
    - По номеру строки
    - По проценту документа
    - К закладке

    Example:
        >>> dialog = GotoDialog(parent, total_pages=100, current_page=50)
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Go to page {result['page']}, line {result['line']}")

    Attributes:
        _total_pages: Общее количество страниц.
        _current_page: Текущая страница.
    """

    def __init__(
        self,
        parent: tk.Widget,
        total_pages: int,
        current_page: int = 1,
        total_lines: Optional[int] = None,
        bookmarks: Optional[list[BookmarkItem]] = None,
    ) -> None:
        """Инициализация диалога перехода.

        Args:
            parent: Родительский виджет.
            total_pages: Общее количество страниц.
            current_page: Текущая страница (1-based).
            total_lines: Общее количество строк (для перехода по строке).
            bookmarks: Список закладок для быстрого перехода.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._total_pages: int = max(1, total_pages)
        self._current_page: int = max(1, min(current_page, total_pages))
        self._total_lines: Optional[int] = total_lines
        self._bookmarks: list[BookmarkItem] = bookmarks or []
        self._result: Optional[dict[str, int]] = None

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title("Go To")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (DIALOG_WIDTH // 2)
        y = (self.winfo_screenheight() // 2) - (DIALOG_HEIGHT // 2)
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI диалога."""
        self.config(bg=COLOR_BG)

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(
            main_frame,
            text="Go To Position",
            font=("Helvetica", 12, "bold"),
        )
        header.pack(anchor="w", pady=(0, 10))

        # Current position info
        info_text = f"Current position: page {self._current_page} of {self._total_pages}"
        if self._total_lines:
            info_text += f", {self._total_lines} строк"
        ttk.Label(main_frame, text=info_text, foreground="gray").pack(anchor="w", pady=(0, 10))

        # Notebook for different goto methods
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Page tab
        page_tab = ttk.Frame(notebook, padding="10")
        notebook.add(page_tab, text="Page")
        self._create_page_tab(page_tab)

        # Line tab (if available)
        if self._total_lines:
            line_tab = ttk.Frame(notebook, padding="10")
            notebook.add(line_tab, text="Line")
            self._create_line_tab(line_tab)

        # Percent tab
        percent_tab = ttk.Frame(notebook, padding="10")
        notebook.add(percent_tab, text="% of Document")
        self._create_percent_tab(percent_tab)

        # Bookmarks tab (if available)
        if self._bookmarks:
            bookmark_tab = ttk.Frame(notebook, padding="10")
            notebook.add(bookmark_tab, text="Bookmarks")
            self._create_bookmark_tab(bookmark_tab)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Go To", command=self._on_ok).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)

    def _create_page_tab(self, parent: ttk.Frame) -> None:
        """Создаёт вкладку перехода по странице."""
        ttk.Label(parent, text="Page number:", font=("Helvetica", 10, "bold")).pack(
            anchor="w", pady=(0, 5)
        )

        self._page_var = tk.IntVar(master=self, value=self._current_page)
        page_spin = ttk.Spinbox(
            parent,
            from_=1,
            to=self._total_pages,
            textvariable=self._page_var,
            width=10,
        )
        page_spin.pack(anchor="w", pady=(0, 5))

        ttk.Label(parent, text=f"Range: 1-{self._total_pages}", foreground="gray").pack(anchor="w")

        # Quick buttons
        quick_frame = ttk.Frame(parent)
        quick_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(quick_frame, text="Start", command=lambda: self._page_var.set(1)).pack(
            side=tk.LEFT, padx=(0, 5)
        )
        ttk.Button(
            quick_frame, text="Current", command=lambda: self._page_var.set(self._current_page)
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            quick_frame, text="End", command=lambda: self._page_var.set(self._total_pages)
        ).pack(side=tk.LEFT, padx=5)

    def _create_line_tab(self, parent: ttk.Frame) -> None:
        """Создаёт вкладку перехода по строке."""
        ttk.Label(parent, text="Line number:", font=("Helvetica", 10, "bold")).pack(
            anchor="w", pady=(0, 5)
        )

        self._line_var = tk.IntVar(master=self, value=1)
        line_spin = ttk.Spinbox(
            parent,
            from_=1,
            to=self._total_lines or 9999,
            textvariable=self._line_var,
            width=10,
        )
        line_spin.pack(anchor="w", pady=(0, 5))

        if self._total_lines:
            ttk.Label(parent, text=f"Range: 1-{self._total_lines}", foreground="gray").pack(
                anchor="w"
            )

    def _create_percent_tab(self, parent: ttk.Frame) -> None:
        """Создаёт вкладку перехода по проценту."""
        ttk.Label(parent, text="Position in document:", font=("Helvetica", 10, "bold")).pack(
            anchor="w", pady=(0, 5)
        )

        self._percent_var = tk.IntVar(master=self, value=50)
        scale = ttk.Scale(
            parent,
            from_=0,
            to=100,
            orient=tk.HORIZONTAL,
            variable=self._percent_var,
        )
        scale.pack(fill=tk.X, pady=(0, 5))

        percent_label = ttk.Label(parent, text="50%")
        percent_label.pack(anchor="w")

        # Update label on scale change
        def update_label(*args: Any) -> None:
            percent_label.config(text=f"{self._percent_var.get()}%")

        self._percent_var.trace_add("write", update_label)

        # Quick buttons
        quick_frame = ttk.Frame(parent)
        quick_frame.pack(fill=tk.X, pady=(10, 0))

        def _make_percent_cmd(value: int) -> Callable[[], None]:
            return lambda: self._percent_var.set(value)

        for percent in [0, 25, 50, 75, 100]:
            ttk.Button(
                quick_frame,
                text=f"{percent}%",
                command=_make_percent_cmd(percent),
            ).pack(side=tk.LEFT, padx=(0, 5))

    def _create_bookmark_tab(self, parent: ttk.Frame) -> None:
        """Создаёт вкладку перехода по закладкам."""
        ttk.Label(parent, text="Select bookmark:", font=("Helvetica", 10, "bold")).pack(
            anchor="w", pady=(0, 5)
        )

        # Listbox with scrollbar
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._bookmark_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            font=("Helvetica", 10),
        )
        self._bookmark_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self._bookmark_listbox.yview)

        # Populate bookmarks
        self._bookmark_map: dict[str, BookmarkItem] = {}
        for bookmark in self._bookmarks:
            display = f"{bookmark.name} (page {bookmark.page})"
            self._bookmark_listbox.insert(tk.END, display)
            self._bookmark_map[display] = bookmark

        self._bookmark_listbox.bind("<Double-1>", lambda e: self._on_bookmark_selected())

    def _on_bookmark_selected(self) -> None:
        """Обработчик выбора закладки."""
        selection = self._bookmark_listbox.curselection()  # type: ignore[no-untyped-call]
        if selection:
            display = self._bookmark_listbox.get(selection[0])
            bookmark = self._bookmark_map.get(display)
            if bookmark:
                self._result = {"page": bookmark.page, "line": bookmark.line}
                self.destroy()

    def _on_ok(self) -> None:
        """Обработчик кнопки 'Перейти'."""
        try:
            # Get current tab
            page = self._page_var.get()
            page = max(1, min(page, self._total_pages))

            line = 0
            if hasattr(self, "_line_var"):
                line = self._line_var.get()
                if self._total_lines:
                    line = max(1, min(line, self._total_lines))

            self._result = {"page": page, "line": line}
            self.destroy()

        except (ValueError, TypeError) as e:
            logger.error("Goto error: %s", e)
            messagebox.showerror("Error", f"Invalid position: {e}")

    def _on_cancel(self) -> None:
        """Обработчик кнопки 'Отмена'."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[dict[str, int]]:
        """Показывает диалог и возвращает позицию.

        Returns:
            Словарь с ключами 'page' и 'line' или None.
        """
        self.wait_window()
        return self._result


class BookmarksDialog(BaseDialog):
    """Диалог управления закладками.

    Позволяет:
    - Просматривать все закладки
    - Добавлять новые закладки
    - Переименовывать существующие
    - Удалять закладки
    - Переходить к закладке
    - Искать закладки по имени

    Example:
        >>> dialog = BookmarksDialog(parent, bookmark_manager)
        >>> result = dialog.show()
        >>> if result and result['action'] == 'goto':
        ...     print(f"Go to page {result['page']}")

    Attributes:
        _bookmark_manager: Менеджер закладок.
        _bookmarks: Список закладок.
    """

    def __init__(
        self,
        parent: tk.Widget,
        bookmark_manager: BookmarkManager,
        current_page: int = 1,
        on_goto: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Инициализация диалога закладок.

        Args:
            parent: Родительский виджет.
            bookmark_manager: Менеджер закладок.
            current_page: Текущая страница (для новой закладки).
            on_goto: Callback при переходе к закладке.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._bookmark_manager: BookmarkManager = bookmark_manager
        self._current_page: int = current_page
        self._on_goto_callback: Optional[Callable[[int, int], None]] = on_goto
        self._result: Optional[dict[str, Any]] = None

        self._create_ui()
        self._setup_window()
        self._load_bookmarks()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title("Bookmarks")
        self.geometry("550x480")
        self.minsize(450, 400)

    def _create_ui(self) -> None:
        """Создаёт UI диалога."""
        self.config(bg=COLOR_BG)

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(
            main_frame,
            text="Manage Bookmarks",
            font=("Helvetica", 12, "bold"),
        )
        header.pack(anchor="w", pady=(0, 10))

        # Toolbar
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(toolbar, text="Add", command=self._on_add).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Rename", command=self._on_rename).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Delete", command=self._on_delete).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Find", command=self._on_find).pack(side=tk.LEFT, padx=5)

        # Bookmarks list
        list_frame = ttk.LabelFrame(main_frame, text="Bookmarks", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Treeview: Name | Line | Added
        columns = ("name", "line", "added")
        self._tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")

        self._tree.heading("name", text="Name")
        self._tree.heading("line", text="Line")
        self._tree.heading("added", text="Added")

        self._tree.column("name", width=180)
        self._tree.column("line", width=80, anchor="center")
        self._tree.column("added", width=150, anchor="center")

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Double-click to goto
        self._tree.bind("<Double-1>", lambda e: self._on_goto())

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Go To", command=self._on_goto).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(btn_frame, text="Close", command=self._on_close).pack(side=tk.RIGHT)

    def _load_bookmarks(self) -> None:
        """Загружает закладки в список."""
        # Clear existing
        for item in self._tree.get_children():
            self._tree.delete(item)

        # Load from manager
        try:
            bookmarks = self._bookmark_manager.get_all_bookmarks()
            for bookmark in bookmarks:
                added_str = bookmark.created_at.strftime("%Y-%m-%d %H:%M")
                self._tree.insert(
                    "",
                    tk.END,
                    iid=bookmark.name,
                    values=(
                        bookmark.name,
                        bookmark.paragraph_index,
                        added_str,
                    ),
                )
        except (ValueError, TypeError) as e:
            logger.error("Failed to load bookmarks: %s", e)

    def _get_selected_bookmark(self) -> Optional[Bookmark]:
        """Возвращает выбранную закладку."""
        selection = self._tree.selection()
        if not selection:
            return None

        return self._bookmark_manager.get_bookmark(selection[0])

    def _on_add(self) -> None:
        """Обработчик добавления закладки."""
        name = simpledialog.askstring(
            "New Bookmark",
            "Enter bookmark name:",
            parent=self,
        )

        if name:
            try:
                from src.model.bookmark import DocumentPosition

                pos = DocumentPosition(
                    paragraph_index=self._current_page,
                    run_index=0,
                    offset=0,
                )
                self._bookmark_manager.add_bookmark(name, pos)
                self._load_bookmarks()
                logger.info("Bookmark added: %s (line %s)", name, self._current_page)
            except (ValueError, TypeError) as e:
                logger.error("Failed to add bookmark: %s", e)
                messagebox.showerror("Error", f"Failed to add bookmark: {e}")

    def _on_rename(self) -> None:
        """Обработчик переименования закладки."""
        bookmark = self._get_selected_bookmark()
        if not bookmark:
            messagebox.showwarning("Warning", "Select a bookmark to rename")
            return

        new_name = simpledialog.askstring(
            "Rename Bookmark",
            "New name:",
            parent=self,
            initialvalue=bookmark.name,
        )

        if new_name and new_name != bookmark.name:
            try:
                self._bookmark_manager.rename_bookmark(bookmark.name, new_name)
                self._load_bookmarks()
                # Select renamed item
                if self._tree.exists(new_name):
                    self._tree.selection_set(new_name)
                    self._tree.focus(new_name)
                logger.info("Bookmark renamed: %s -> %s", bookmark.name, new_name)
            except (ValueError, TypeError) as e:
                logger.error("Failed to rename bookmark: %s", e)
                messagebox.showerror("Error", f"Failed to rename bookmark: {e}")

    def _on_delete(self) -> None:
        """Обработчик удаления закладки."""
        bookmark = self._get_selected_bookmark()
        if not bookmark:
            messagebox.showwarning("Warning", "Select a bookmark to delete")
            return

        if messagebox.askyesno(
            "Confirm",
            f"Delete bookmark '{bookmark.name}'?",
        ):
            try:
                self._bookmark_manager.remove_bookmark(bookmark.name)
                self._load_bookmarks()
                logger.info("Bookmark removed: %s", bookmark.name)
            except (ValueError, TypeError) as e:
                logger.error("Failed to remove bookmark: %s", e)
                messagebox.showerror("Error", f"Failed to delete bookmark: {e}")

    def _on_find(self) -> None:
        """Обработчик поиска закладки по имени."""
        query = simpledialog.askstring(
            "Find Bookmark",
            "Search:",
            parent=self,
        )

        if not query:
            return

        query_lower = query.lower()
        for item_id in self._tree.get_children():
            values = self._tree.item(item_id, "values")
            if values and query_lower in str(values[0]).lower():
                self._tree.selection_set(item_id)
                self._tree.focus(item_id)
                self._tree.see(item_id)
                return

        messagebox.showinfo("Find Bookmark", f"No bookmark matching '{query}' found.")

    def _on_goto(self) -> None:
        """Обработчик перехода к закладке."""
        bookmark = self._get_selected_bookmark()
        if not bookmark:
            messagebox.showwarning("Warning", "Select a bookmark")
            return

        self._result = {
            "action": "goto",
            "page": bookmark.paragraph_index,
            "line": bookmark.paragraph_index,
        }

        if self._on_goto_callback:
            self._on_goto_callback(bookmark.paragraph_index, bookmark.paragraph_index)

        self.destroy()

    def _on_close(self) -> None:
        """Обработчик закрытия диалога."""
        if self._result is None:
            self._result = {"action": "close"}
        self.destroy()

    def show(self) -> Optional[dict[str, Any]]:
        """Показывает диалог и возвращает результат.

        Returns:
            Результат действия или None.
        """
        self.wait_window()
        return self._result
