"""Диалог поиска и замены текста.

Предоставляет интерфейс для:
- Поиска текста в документе
- Замены текста (одиночная/все)
- Настройки поиска (регистр, целые слова, regex)
- Выбор направления поиска

Example:
    >>> dialog = FindReplaceDialog(parent=root, text_widget=editor)
    >>> dialog.show()

Version: 1.0
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from tkinter import ttk
from typing import Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 350

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_FOUND: Final[str] = "#fff3cd"  # Yellow highlight
COLOR_ACTIVE: Final[str] = "#3498db"


# =============================================================================
# FindReplaceDialog
# =============================================================================


class FindReplaceDialog(BaseDialog):
    """Диалог поиска и замены.

    Attributes:
        parent: Родительский виджет.
        _text_widget: Текстовый виджет для поиска.
        _search_var: Переменная для поискового запроса.
        _replace_var: Переменная для замены.
        _found_count: Счётчик найденных совпадений.

    Example:
        >>> dialog = FindReplaceDialog(parent=root, text_widget=editor)
        >>> dialog.show()
    """

    def __init__(
        self,
        parent: tk.Widget,
        text_widget: tk.Text,
        on_find: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Инициализация диалога поиска и замены.

        Args:
            parent: Родительский виджет.
            text_widget: Текстовый виджет для поиска.
            on_find: Callback при поиске.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._text_widget: tk.Text = text_widget
        self._on_find: Optional[Callable[[str], None]] = on_find

        # State
        self._search_var: tk.StringVar = tk.StringVar(master=self)
        self._replace_var: tk.StringVar = tk.StringVar(master=self)
        self._found_count: int = 0
        self._current_match: Optional[str] = None

        # Options
        self._match_case: tk.BooleanVar = tk.BooleanVar(master=self, value=True)
        self._whole_words: tk.BooleanVar = tk.BooleanVar(master=self, value=False)
        self._use_regex: tk.BooleanVar = tk.BooleanVar(master=self, value=False)
        self._search_direction: tk.StringVar = tk.StringVar(master=self, value="down")

        # UI references
        self._status_label: Optional[tk.Label] = None
        self._find_entry: Optional[tk.Entry] = None

        # Configure window
        self.title("🔍 Find and Replace")
        self.resizable(False, False)

        # Create UI
        self._create_ui()

        # Center window

        # Protocol

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        parent = self._parent
        parent_x = parent.winfo_rootx() if hasattr(parent, "winfo_rootx") else 0
        parent_y = parent.winfo_rooty() if hasattr(parent, "winfo_rooty") else 0
        parent_width = parent.winfo_width() if hasattr(parent, "winfo_width") else 800
        parent_height = parent.winfo_height() if hasattr(parent, "winfo_height") else 600

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2

        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        # Main container
        main_frame = tk.Frame(self, padx=20, pady=20, bg=COLOR_BG)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Find section
        self._create_find_section(main_frame)

        # Replace section
        self._create_replace_section(main_frame)

        # Options section
        self._create_options_section(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Status and buttons
        self._create_status_and_buttons(main_frame)

    def _create_find_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию поиска.

        Args:
            parent: Родительский виджет.
        """
        find_frame = tk.Frame(parent, bg=COLOR_BG)
        find_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            find_frame,
            text="Find:",
            font=("Arial", 10),
            bg=COLOR_BG,
            width=8,
            anchor=tk.E,
        ).pack(side=tk.LEFT)

        self._find_entry = tk.Entry(
            find_frame,
            textvariable=self._search_var,
            font=("Arial", 10),
            width=30,
        )
        self._find_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        self._find_entry.focus_set()

        # Find buttons
        btn_frame = tk.Frame(find_frame, bg=COLOR_BG)
        btn_frame.pack(side=tk.LEFT)

        tk.Button(
            btn_frame,
            text="🔍 Find Next",
            command=self._on_find_next,
            font=("Arial", 9),
            width=12,
        ).pack(side=tk.LEFT, padx=(0, 5))

    def _create_replace_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию замены.

        Args:
            parent: Родительский виджет.
        """
        replace_frame = tk.Frame(parent, bg=COLOR_BG)
        replace_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            replace_frame,
            text="Replace:",
            font=("Arial", 10),
            bg=COLOR_BG,
            width=8,
            anchor=tk.E,
        ).pack(side=tk.LEFT)

        replace_entry = tk.Entry(
            replace_frame,
            textvariable=self._replace_var,
            font=("Arial", 10),
            width=30,
        )
        replace_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)

        # Replace buttons
        btn_frame = tk.Frame(replace_frame, bg=COLOR_BG)
        btn_frame.pack(side=tk.LEFT)

        tk.Button(
            btn_frame,
            text="🔄 Replace",
            command=self._on_replace,
            font=("Arial", 9),
            width=12,
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            btn_frame,
            text="🔄 Replace All",
            command=self._on_replace_all,
            font=("Arial", 9),
            width=12,
        ).pack(side=tk.LEFT)

    def _create_options_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию опций.

        Args:
            parent: Родительский виджет.
        """
        options_frame = tk.LabelFrame(
            parent,
            text="Options",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            padx=10,
            pady=10,
        )
        options_frame.pack(fill=tk.X, pady=(0, 10))

        # Checkboxes
        cb_frame = tk.Frame(options_frame, bg=COLOR_BG)
        cb_frame.pack(fill=tk.X)

        tk.Checkbutton(
            cb_frame,
            text="Match case",
            variable=self._match_case,
            bg=COLOR_BG,
            font=("Arial", 9),
        ).pack(anchor=tk.W)

        tk.Checkbutton(
            cb_frame,
            text="Whole words only",
            variable=self._whole_words,
            bg=COLOR_BG,
            font=("Arial", 9),
        ).pack(anchor=tk.W)

        tk.Checkbutton(
            cb_frame,
            text="Regular expressions",
            variable=self._use_regex,
            bg=COLOR_BG,
            font=("Arial", 9),
        ).pack(anchor=tk.W)

        tk.Checkbutton(
            cb_frame,
            text="Search in current document only",
            onvalue=True,
            offvalue=False,
            bg=COLOR_BG,
            font=("Arial", 9),
        ).pack(anchor=tk.W)

        # Direction
        direction_frame = tk.Frame(options_frame, bg=COLOR_BG)
        direction_frame.pack(fill=tk.X, pady=(10, 0))

        tk.Label(
            direction_frame,
            text="Direction:",
            font=("Arial", 9),
            bg=COLOR_BG,
        ).pack(side=tk.LEFT)

        tk.Radiobutton(
            direction_frame,
            text="Down",
            variable=self._search_direction,
            value="down",
            bg=COLOR_BG,
            font=("Arial", 9),
        ).pack(side=tk.LEFT, padx=(10, 0))

        tk.Radiobutton(
            direction_frame,
            text="Up",
            variable=self._search_direction,
            value="up",
            bg=COLOR_BG,
            font=("Arial", 9),
        ).pack(side=tk.LEFT, padx=(10, 0))

    def _create_status_and_buttons(self, parent: tk.Widget) -> None:
        """Создаёт статус и кнопки.

        Args:
            parent: Родительский виджет.
        """
        # Status
        self._status_label = tk.Label(
            parent,
            text="Enter search term",
            font=("Arial", 9, "italic"),
            bg=COLOR_BG,
            fg="#7f8c8d",
            anchor=tk.W,
        )
        self._status_label.pack(fill=tk.X, pady=(0, 10))

        # Buttons
        btn_frame = tk.Frame(parent, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X)

        tk.Frame(btn_frame, bg=COLOR_BG).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Button(
            btn_frame,
            text="Cancel",
            command=self._on_close,
            font=("Arial", 9),
            width=10,
        ).pack(side=tk.RIGHT)

    def _get_search_pattern(self) -> tuple[str, int]:
        """Получает паттерн поиска и флаги.

        Returns:
            Кортеж (паттерн, флаги regex).
        """
        pattern = self._search_var.get()

        if not pattern:
            return "", 0

        flags = 0
        if not self._match_case.get():
            flags |= re.IGNORECASE

        if self._whole_words.get():
            pattern = r"\b" + re.escape(pattern) + r"\b"
        elif not self._use_regex.get():
            pattern = re.escape(pattern)

        return pattern, flags

    def _on_find_next(self) -> None:
        """Обработчик поиска следующего."""
        pattern, flags = self._get_search_pattern()

        if not pattern:
            if self._status_label is not None:
                self._status_label.config(text="⚠️ Enter search term", fg="#f39c12")
            return

        try:
            # Get current position
            start_pos = self._text_widget.index(tk.INSERT)

            if self._search_direction.get() == "down":
                # Search forward
                match_start = self._text_widget.search(
                    pattern,
                    start_pos,
                    stopindex=tk.END,
                    regexp=self._use_regex.get(),
                    nocase=not self._match_case.get(),
                )
            else:
                # Search backward
                match_start = self._text_widget.search(
                    pattern,
                    start_pos,
                    backwards=True,
                    regexp=self._use_regex.get(),
                    nocase=not self._match_case.get(),
                )

            if match_start:
                # Calculate end position
                line, col = match_start.split(".")
                match_end = f"{line}.{int(col) + len(self._search_var.get())}"

                # Select text
                self._text_widget.tag_remove("found", "1.0", tk.END)
                self._text_widget.tag_add("found", match_start, match_end)
                self._text_widget.tag_config("found", background=COLOR_FOUND)
                self._text_widget.see(match_start)
                self._text_widget.mark_set(tk.INSERT, match_end)

                self._current_match = match_start

                if self._status_label is not None:
                    self._status_label.config(text=f"✓ Found at {match_start}", fg="#27ae60")

                if self._on_find is not None:
                    self._on_find(pattern)
            else:
                if self._status_label is not None:
                    self._status_label.config(text="❌ Not found", fg="#e74c3c")

        except re.error as e:
            if self._status_label is not None:
                self._status_label.config(text=f"❌ Regex error: {e}", fg="#e74c3c")

    def _on_replace(self) -> None:
        """Обработчик замены."""
        if self._current_match is None:
            self._on_find_next()
            if self._current_match is None:
                return

        replace_text = self._replace_var.get()

        # Remove found tag
        self._text_widget.tag_remove("found", "1.0", tk.END)

        # Replace text
        if self._current_match:
            line, col = self._current_match.split(".")
            match_end = f"{line}.{int(col) + len(self._search_var.get())}"
            self._text_widget.delete(self._current_match, match_end)
            self._text_widget.insert(self._current_match, replace_text)

        # Find next
        self._current_match = None
        self._on_find_next()

    def _on_replace_all(self) -> None:
        """Обработчик замены всех."""
        pattern, flags = self._get_search_pattern()
        replace_text = self._replace_var.get()

        if not pattern:
            return

        count = 0
        start_pos = "1.0"

        while True:
            match_start = self._text_widget.search(
                pattern,
                start_pos,
                stopindex=tk.END,
                regexp=self._use_regex.get(),
                nocase=not self._match_case.get(),
            )

            if not match_start:
                break

            line, col = match_start.split(".")
            match_end = f"{line}.{int(col) + len(self._search_var.get())}"

            self._text_widget.delete(match_start, match_end)
            self._text_widget.insert(match_start, replace_text)

            count += 1
            start_pos = match_start

        if self._status_label is not None:
            self._status_label.config(
                text=f"✓ Replaced {count} occurrence(s)",
                fg="#27ae60" if count > 0 else "#f39c12",
            )

        logger.info("Replaced %d occurrences", count)

    def _on_close(self) -> None:
        """Обработчик закрытия."""
        # Remove highlights
        self._text_widget.tag_remove("found", "1.0", tk.END)
        self.destroy()

    def show(self) -> None:
        """Показывает диалог модально.

        Блокирует родительское окно до закрытия диалога.
        """
        self.wait_window()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "FindReplaceDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
]
