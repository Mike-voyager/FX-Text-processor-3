"""Диалог вставки специальных символов.

Предоставляет интерфейс для выбора и вставки специальных символов ESC/P
включая кириллицу PC866, псевдографику, математические символы,
типографику и ESC/P control sequences (debug-режим).

Example:
    >>> dialog = SpecialCharacterDialog(parent)
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Выбран: {result.char} (категория: {result.category})")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog

# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class SpecialCharResult:
    """Результат выбора специального символа.

    Attributes:
        char: Выбранный символ или ESC/P control sequence.
        category: Категория символа (вкладка).
        is_control: True если char содержит ESC/P control sequence.
    """

    char: str
    category: str
    is_control: bool = False


# =============================================================================
# CONSTANTS
# =============================================================================

BUTTONS_PER_ROW: Final[int] = 10
FONT_FAMILY: Final[str] = "Courier"
FONT_SIZE: Final[int] = 14

TAB_PC866: Final[str] = "PC866 Cyrillic"
TAB_BOX_DRAWING: Final[str] = "Box Drawing"
TAB_MATH: Final[str] = "Math & Symbols"
_TAB_TYPOGRAPHY: Final[str] = "Typography"
_TAB_ESC_P: Final[str] = "ESC/P Controls"

# (Character, Description) tuples for each tab
_PC866_CHARS: Final[tuple[tuple[str, str], ...]] = (
    # Basic Cyrillic upper
    ("А", "Cyrillic А"),
    ("Б", "Cyrillic Б"),
    ("В", "Cyrillic В"),
    ("Г", "Cyrillic Г"),
    ("Д", "Cyrillic Д"),
    ("Е", "Cyrillic Е"),
    ("Ё", "Cyrillic Ё"),
    ("Ж", "Cyrillic Ж"),
    ("З", "Cyrillic З"),
    ("И", "Cyrillic И"),
    ("Й", "Cyrillic Й"),
    ("К", "Cyrillic К"),
    ("Л", "Cyrillic Л"),
    ("М", "Cyrillic М"),
    ("Н", "Cyrillic Н"),
    ("О", "Cyrillic О"),
    ("П", "Cyrillic П"),
    ("Р", "Cyrillic Р"),
    ("С", "Cyrillic С"),
    ("Т", "Cyrillic Т"),
    ("У", "Cyrillic У"),
    ("Ф", "Cyrillic Ф"),
    ("Х", "Cyrillic Х"),
    ("Ц", "Cyrillic Ц"),
    ("Ч", "Cyrillic Ч"),
    ("Ш", "Cyrillic Ш"),
    ("Щ", "Cyrillic Щ"),
    ("Ъ", "Cyrillic Ъ"),
    ("Ы", "Cyrillic Ы"),
    ("Ь", "Cyrillic Ь"),
    ("Э", "Cyrillic Э"),
    ("Ю", "Cyrillic Ю"),
    ("Я", "Cyrillic Я"),
    # Lower case
    ("а", "Cyrillic а"),
    ("б", "Cyrillic б"),
    ("в", "Cyrillic в"),
    ("г", "Cyrillic г"),
    ("д", "Cyrillic д"),
    ("е", "Cyrillic е"),
    ("ё", "Cyrillic ё"),
    ("ж", "Cyrillic ж"),
    ("з", "Cyrillic з"),
    ("и", "Cyrillic и"),
    ("й", "Cyrillic й"),
    ("к", "Cyrillic к"),
    ("л", "Cyrillic л"),
    ("м", "Cyrillic м"),
    ("н", "Cyrillic н"),
    ("о", "Cyrillic о"),
    ("п", "Cyrillic п"),
    ("р", "Cyrillic р"),
    ("с", "Cyrillic с"),
    ("т", "Cyrillic т"),
    ("у", "Cyrillic у"),
    ("ф", "Cyrillic ф"),
    ("х", "Cyrillic х"),
    ("ц", "Cyrillic ц"),
    ("ч", "Cyrillic ч"),
    ("ш", "Cyrillic ш"),
    ("щ", "Cyrillic щ"),
    ("ъ", "Cyrillic ъ"),
    ("ы", "Cyrillic ы"),
    ("ь", "Cyrillic ь"),
    ("э", "Cyrillic э"),
    ("ю", "Cyrillic ю"),
    ("я", "Cyrillic я"),
    # Special
    ("°", "Degree sign"),
    ("·", "Middle dot"),
)

_BOX_SINGLE: Final[tuple[str, ...]] = (
    "─",
    "│",
    "┌",
    "┐",
    "└",
    "┘",
    "├",
    "┤",
    "┬",
    "┴",
    "┼",
)
_BOX_DOUBLE: Final[tuple[str, ...]] = (
    "═",
    "║",
    "╔",
    "╗",
    "╚",
    "╝",
    "╠",
    "╣",
    "╦",
    "╩",
    "╬",
)
_MATH_CHARS: Final[tuple[tuple[str, str], ...]] = (
    ("≡", "Identical to"),
    ("±", "Plus-minus"),
    ("≥", "Greater than or equal"),
    ("≤", "Less than or equal"),
    ("÷", "Division"),
    ("≈", "Almost equal"),
    ("°", "Degree sign"),
    ("²", "Superscript two"),
    ("³", "Superscript three"),
    ("¹", "Superscript one"),
    ("₤", "Lira"),
    ("§", "Section"),
    ("¶", "Pilcrow"),
)

_TYPOGRAPHY_CHARS: Final[tuple[tuple[str, str], ...]] = (
    ("№", "Numero"),
    ("«", "Left guillemet"),
    ("»", "Right guillemet"),
    ("—", "Em dash"),
    ("–", "En dash"),
    ("…", "Horizontal ellipsis"),
    ("©", "Copyright"),
    ("®", "Registered"),
    ("™", "Trademark"),
    ("€", "Euro"),
)

# ESC/P Controls: (label, literal_bytes, description)
_ESC_P_CONTROLS: Final[tuple[tuple[str, str, str], ...]] = (
    ("HT", "\t", "Horizontal Tab"),
    ("VT", "\x0b", "Vertical Tab"),
    ("FF", "\x0c", "Form Feed"),
    ("CR", "\r", "Carriage Return"),
    ("BEL", "\x07", "Bell"),
    ("SO", "\x0e", "Shift Out"),
    ("SI", "\x0f", "Shift In"),
    ("ESC @", "\x1b@", "Initialize"),
    ("ESC E", "\x1bE", "Bold On"),
    ("ESC F", "\x1bF", "Bold Off"),
    ("ESC 4", "\x1b4", "Italic On"),
    ("ESC 5", "\x1b5", "Italic Off"),
    ("ESC - 1", "\x1b-1", "Underline On"),
    ("ESC - 0", "\x1b-0", "Underline Off"),
)


# =============================================================================
# DIALOG
# =============================================================================


class SpecialCharacterDialog(BaseDialog):
    """Модальный диалог выбора специального символа.

    Содержит вкладки с символами PC866, псевдографикой,
    математическими символами, типографикой и ESC/P controls.

    Attributes:
        _selected_char: Текущий выбранный символ.
        _selected_category: Категория выбранного символа.
        _selected_is_control: True если ESC/P control.
    """

    def __init__(
        self,
        parent: tk.Widget,
        initial_debug: bool = False,
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительский виджет.
            initial_debug: Показывать вкладку ESC/P Controls по умолчанию.
        """
        super().__init__(parent, title="Special Characters", modal=True)

        self._selected_char: str = ""
        self._selected_category: str = ""
        self._selected_is_control: bool = False

        self._notebook: Optional[ttk.Notebook] = None
        self._esc_tab_widget: Optional[ttk.Frame] = None
        self._esc_tab_visible: bool = False
        self._status_label: Optional[ttk.Label] = None
        self._debug_var: tk.BooleanVar = tk.BooleanVar(master=self, value=initial_debug)

        self._create_ui()
        self._update_esc_tab_visibility()

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        self.minsize(400, 300)

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._notebook = ttk.Notebook(main_frame)
        assert self._notebook is not None
        self._notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Tab 1: PC866 Cyrillic
        self._create_char_tab(
            TAB_PC866,
            _PC866_CHARS,
            wrap_after=33,
        )

        # Tab 2: Box Drawing
        self._create_box_drawing_tab()

        # Tab 3: Math & Symbols
        self._create_char_tab(
            TAB_MATH,
            _MATH_CHARS,
            wrap_after=BUTTONS_PER_ROW,
        )

        # Tab 4: Typography
        self._create_char_tab(
            _TAB_TYPOGRAPHY,
            _TYPOGRAPHY_CHARS,
            wrap_after=BUTTONS_PER_ROW,
        )

        # Tab 5: ESC/P Controls (debug)
        esc_tab = ttk.Frame(self._notebook)
        self._esc_tab_widget = esc_tab
        self._notebook.add(esc_tab, text=_TAB_ESC_P)
        self._create_esc_p_tab(esc_tab)

        # Bottom area: status + controls
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=(5, 0))

        self._status_label = ttk.Label(
            bottom_frame,
            text="Selected: (none)",
            font=(FONT_FAMILY, FONT_SIZE),
        )
        self._status_label.pack(side=tk.LEFT)

        debug_check = ttk.Checkbutton(
            bottom_frame,
            text="Debug: show ESC/P controls",
            variable=self._debug_var,
            command=self._on_debug_toggle,
        )
        debug_check.pack(side=tk.RIGHT)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(
            btn_frame,
            text="OK",
            command=self._on_ok,
        ).pack(side=tk.RIGHT, padx=(5, 0))

        ttk.Button(
            btn_frame,
            text="Cancel",
            command=self._on_cancel,
        ).pack(side=tk.RIGHT)

    def _make_char_button(
        self,
        parent: tk.Widget,
        char_val: str,
        tab_name: str,
        description: str,
        is_control: bool,
        row: int,
        col: int,
    ) -> tk.Button:
        """Создаёт кнопку символа.

        Args:
            parent: Родительский виджет.
            char_val: Символ для отображения.
            tab_name: Название вкладки.
            description: Описание символа.
            is_control: True если ESC/P control.
            row: Строка grid.
            col: Колонка grid.

        Returns:
            Созданная кнопка.
        """
        handler: Callable[[], None] = self._build_handler(
            char_val,
            tab_name,
            description,
            is_control,
        )
        btn = tk.Button(
            parent,
            text=char_val,
            width=3,
            height=1,
            font=(FONT_FAMILY, FONT_SIZE),
            relief=tk.RAISED,
            command=handler,
        )
        btn.grid(row=row, column=col, padx=2, pady=2, sticky="nsew")
        return btn

    def _build_handler(
        self,
        char_val: str,
        tab_name: str,
        description: str,
        is_control: bool,
    ) -> Callable[[], None]:
        """Создаёт обработчик выбора символа.

        Args:
            char_val: Символ для выбора.
            tab_name: Название вкладки.
            description: Описание символа.
            is_control: True если ESC/P control.

        Returns:
            Функция-обработчик.
        """

        def handler() -> None:
            self._on_char_selected(char_val, tab_name, description, is_control)

        return handler

    def _create_char_tab(
        self,
        tab_name: str,
        chars: tuple[tuple[str, str], ...],
        wrap_after: int,
    ) -> None:
        """Создаёт вкладку с сеткой символов.

        Args:
            tab_name: Название вкладки (заголовок таба).
            chars: Список (символ, описание) для отображения.
            wrap_after: Количество кнопок в ряд.
        """
        notebook = self._notebook
        assert notebook is not None
        tab = ttk.Frame(notebook)
        notebook.add(tab, text=tab_name)

        row = 0
        col = 0
        for char_val, desc in chars:
            self._make_char_button(
                tab,
                char_val,
                tab_name,
                desc,
                False,
                row,
                col,
            )
            col += 1
            if col >= wrap_after:
                col = 0
                row += 1

        for i in range(min(len(chars), wrap_after)):
            tab.grid_columnconfigure(i, weight=1)
        for i in range((len(chars) + wrap_after - 1) // wrap_after):
            tab.grid_rowconfigure(i, weight=1)

    def _create_box_drawing_tab(self) -> None:
        """Создаёт вкладку с символами псевдографики."""
        notebook = self._notebook
        assert notebook is not None
        parent = ttk.Frame(notebook)
        notebook.add(parent, text=TAB_BOX_DRAWING)

        single_label = ttk.Label(parent, text="Single:")
        single_label.grid(row=0, column=0, columnspan=BUTTONS_PER_ROW, sticky="w", pady=(5, 0))

        for idx, char_val in enumerate(_BOX_SINGLE):
            handler: Callable[[], None] = self._build_handler(
                char_val,
                TAB_BOX_DRAWING,
                "Single line",
                False,
            )
            btn = tk.Button(
                parent,
                text=char_val,
                width=3,
                height=1,
                font=(FONT_FAMILY, FONT_SIZE),
                relief=tk.RAISED,
                command=handler,
            )
            btn.grid(row=1, column=idx, padx=2, pady=2, sticky="nsew")

        double_label = ttk.Label(parent, text="Double:")
        double_label.grid(row=2, column=0, columnspan=BUTTONS_PER_ROW, sticky="w", pady=(10, 0))

        for idx, char_val in enumerate(_BOX_DOUBLE):
            handler = self._build_handler(
                char_val,
                TAB_BOX_DRAWING,
                "Double line",
                False,
            )
            btn = tk.Button(
                parent,
                text=char_val,
                width=3,
                height=1,
                font=(FONT_FAMILY, FONT_SIZE),
                relief=tk.RAISED,
                command=handler,
            )
            btn.grid(row=3, column=idx, padx=2, pady=2, sticky="nsew")

        for i in range(BUTTONS_PER_ROW):
            parent.grid_columnconfigure(i, weight=1)
        for i in range(4):
            parent.grid_rowconfigure(i, weight=1)

    def _create_esc_p_tab(self, parent: ttk.Frame) -> None:
        """Создаёт вкладку ESC/P Controls.

        Args:
            parent: Родительский фрейм вкладки.
        """
        cols = 2
        for idx, (label, literal, desc) in enumerate(_ESC_P_CONTROLS):
            row = idx // cols
            col = idx % cols

            hex_str = " ".join(f"0x{b:02X}" for b in literal.encode("latin1"))
            display = f"{label} — {desc} ({hex_str})"

            handler = self._build_handler(literal, _TAB_ESC_P, desc, True)
            btn = tk.Button(
                parent,
                text=display,
                height=1,
                font=(FONT_FAMILY, 10),
                relief=tk.RAISED,
                anchor="w",
                command=handler,
            )
            btn.grid(row=row, column=col, padx=3, pady=2, sticky="nsew")

        for i in range(cols):
            parent.grid_columnconfigure(i, weight=1)
        rows = (len(_ESC_P_CONTROLS) + cols - 1) // cols
        for i in range(rows):
            parent.grid_rowconfigure(i, weight=1)

    def _on_char_selected(
        self,
        char: str,
        category: str,
        description: str,
        is_control: bool,
    ) -> None:
        """Обработчик выбора символа.

        Args:
            char: Выбранный символ или ESC/P control sequence.
            category: Категория символа (вкладка).
            description: Человекочитаемое описание.
            is_control: True если ESC/P control sequence.
        """
        self._selected_char = char
        self._selected_category = category
        self._selected_is_control = is_control

        if is_control:
            hex_str = " ".join(f"0x{b:02X}" for b in char.encode("latin1"))
            status = f"Selected: {description} ({hex_str})"
        else:
            status = f"Selected: {char} — {description}"

        if self._status_label is not None:
            self._status_label.config(text=status)

    def _on_debug_toggle(self) -> None:
        """Обработчик переключения debug-режима."""
        self._update_esc_tab_visibility()

    def is_esc_tab_visible(self) -> bool:
        """Проверяет видимость вкладки ESC/P Controls.

        Returns:
            True если вкладка ESC/P Controls видима.
        """
        return self._esc_tab_visible

    def _update_esc_tab_visibility(self) -> None:
        """Показывает или скрывает вкладку ESC/P Controls."""
        if self._notebook is None:
            return

        show = self._debug_var.get()
        esc_tab = self._esc_tab_widget
        if esc_tab is None:
            return

        if show and not self._esc_tab_visible:
            try:
                self._notebook.add(esc_tab, text=_TAB_ESC_P)
                self._esc_tab_visible = True
            except tk.TclError:
                pass
        elif not show and self._esc_tab_visible:
            try:
                self._notebook.hide(esc_tab)
                self._esc_tab_visible = False
            except tk.TclError:
                pass

    def _on_ok(self) -> None:
        """Обработчик OK: возвращает результат и закрывает диалог."""
        if self._selected_char:
            result = SpecialCharResult(
                char=self._selected_char,
                category=self._selected_category,
                is_control=self._selected_is_control,
            )
            self.close(result)
        else:
            self.close(None)

    def _on_cancel(self) -> None:
        """Обработчик Отмена: закрывает диалог без результата."""
        self.close(None)

    def show(self) -> Optional[SpecialCharResult]:
        """Показывает диалог модально и возвращает результат.

        Returns:
            SpecialCharResult если символ выбран, иначе None.
        """
        super().show()
        result = self.get_result()
        if result is None:
            return None
        if isinstance(result, SpecialCharResult):
            return result
        return None
