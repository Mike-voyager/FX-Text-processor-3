"""Диалог управления paper profiles.

Предоставляет интерфейс для:
- Быстрого выбора из избранных профилей (6 tiles)
- Просмотра всех профилей по категориям
- Редактирования margins и параметров
- Управления списком избранного

Features:
    - Favorites grid (2×3 tiles)
    - Accordion/Tree view всех профилей
    - Real-time printable area calculation
    - Tear-off perforation toggle (continuous only)
    - Persisted favorites

Example:
    >>> service = PaperProfileService()
    >>> dialog = PaperProfileDialog(parent=root, service=service)
    >>> profile = dialog.show()
    >>> if profile:
    ...     print(f"Selected: {profile.name_ru}")

Module: src/gui/dialogs/paper_profile_dialog.py
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Final, Literal, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog
from src.model.enums import FontFamily
from src.services.paper_profile_service import (
    MAX_FAVORITES,
    PaperProfile,
    PaperProfileService,
)

logger: logging.Logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 700
DIALOG_HEIGHT: Final[int] = 600
FAVORITES_ROWS: Final[int] = 2
FAVORITES_COLS: Final[int] = 3

# Colors
COLOR_FAVORITE_BG: Final[str] = "#f0f0f0"
COLOR_FAVORITE_ACTIVE: Final[str] = "#e0e8f0"
COLOR_FAVORITE_SELECTED: Final[str] = "#c5d8f0"
COLOR_CATEGORY_CONTINUOUS: Final[str] = "#e8f5e9"
COLOR_CATEGORY_SHEET: Final[str] = "#e3f2fd"
COLOR_CATEGORY_ENVELOPE: Final[str] = "#fff3e0"

# Margins
PADDING_SMALL: Final[int] = 5
PADDING_NORMAL: Final[int] = 10
PADDING_LARGE: Final[int] = 15

# Min/max values
MIN_MARGIN_MM: Final[float] = 0.0
MAX_MARGIN_MM: Final[float] = 50.0
MIN_DIMENSION_MM: Final[float] = 50.0
MAX_DIMENSION_MM: Final[float] = 500.0

# Type alias for Event
TkEvent = Any


# =============================================================================
# PaperProfileDialog
# =============================================================================


class PaperProfileDialog(BaseDialog):
    """Диалог управления paper profiles с favorites.

    Attributes:
        parent: Родительский виджет.
        service: Сервис профилей.
        on_select: Callback при выборе профиля.
        _selected_profile: Текущий выбранный профиль.
        _favorites_widgets: Виджеты избранных профилей.
        _result: Результат диалога.

    Example:
        >>> dialog = PaperProfileDialog(parent=root, service=service)
        >>> profile = dialog.show()
        >>> if profile:
        ...     print(f"Selected: {profile.name}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        service: Optional[PaperProfileService] = None,
        on_select: Optional[Callable[[PaperProfile], None]] = None,
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительский виджет.
            service: Сервис профилей (optional, создаётся если не передан).
            on_select: Callback при выборе профиля (optional).
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._service: PaperProfileService = service or PaperProfileService()
        self._on_select: Optional[Callable[[PaperProfile], None]] = on_select
        self._result: Optional[PaperProfile] = None
        self._selected_profile: Optional[PaperProfile] = None

        # UI references
        self._favorites_widgets: list[dict[str, Any]] = []
        self._tree: Optional[ttk.Treeview] = None
        self._details_frame: Optional[tk.Widget] = None

        # Variables
        self._profile_vars: dict[str, tk.Variable] = {}
        self._tear_off_var: tk.BooleanVar = tk.BooleanVar(master=self)
        self._tear_off_check: Optional[tk.Checkbutton] = None
        self._tear_off_info: Optional[tk.Label] = None
        self._printable_label: Optional[tk.Label] = None
        self._recalc_btn: Optional[tk.Button] = None

        # Configure window
        self.title("Select Paper Profile")
        self.resizable(True, True)

        # Create UI
        self._create_ui()

        # Center window

        # Protocol

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        width = DIALOG_WIDTH
        height = DIALOG_HEIGHT

        parent = self._parent
        parent_x = parent.winfo_rootx() if hasattr(parent, "winfo_rootx") else 0
        parent_y = parent.winfo_rooty() if hasattr(parent, "winfo_rooty") else 0
        parent_width = parent.winfo_width() if hasattr(parent, "winfo_width") else 800
        parent_height = parent.winfo_height() if hasattr(parent, "winfo_height") else 600

        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        # Main container
        main_frame = tk.Frame(self, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Favorites section
        favorites_section = self._create_favorites_section()
        favorites_section.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=PADDING_SMALL)

        # Bottom section: Tree (left) + Details (right)
        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(fill=tk.BOTH, expand=True)

        # All papers tree (left)
        tree_section = self._create_all_papers_section(bottom_frame)
        tree_section.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, PADDING_NORMAL))

        # Details panel (right)
        self._details_frame = self._create_details_panel(bottom_frame)
        self._details_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(PADDING_NORMAL, 0))

        # Separator before buttons
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=PADDING_NORMAL)

        # Buttons
        self._create_buttons(main_frame)

    def _create_favorites_section(self) -> tk.Widget:
        """Создаёт секцию избранных профилей (6 tiles).

        Returns:
            Фрейм с tiles избранных.
        """
        frame = tk.LabelFrame(self, text="Favorites", padx=PADDING_NORMAL, pady=PADDING_NORMAL)

        # Grid: 2 rows × 3 columns
        for row in range(FAVORITES_ROWS):
            for col in range(FAVORITES_COLS):
                idx = row * FAVORITES_COLS + col
                tile = self._create_favorite_tile(frame, idx)
                tile.grid(
                    row=row, column=col, padx=PADDING_SMALL, pady=PADDING_SMALL, sticky="nsew"
                )

        # Configure grid weights
        for col in range(FAVORITES_COLS):
            frame.grid_columnconfigure(col, weight=1, uniform="col")
        for row in range(FAVORITES_ROWS):
            frame.grid_rowconfigure(row, weight=1, uniform="row")

        return frame

    def _create_favorite_tile(self, parent: tk.Widget, index: int) -> tk.Frame:
        """Создаёт tile для избранного профиля.

        Args:
            parent: Родительский виджет.
            index: Индекс tile.

        Returns:
            Фрейм tile.
        """
        tile = tk.Frame(
            parent,
            width=150,
            height=80,
            bg=COLOR_FAVORITE_BG,
            relief=tk.RAISED,
            bd=2,
            cursor="hand2",
        )
        tile.grid_propagate(False)

        # Icon label
        icon_lbl = tk.Label(
            tile,
            text="📄",
            bg=COLOR_FAVORITE_BG,
            font=("Arial", 20),
        )
        icon_lbl.pack(pady=(10, 0))

        # Name label
        name_lbl = tk.Label(
            tile,
            text="—",
            bg=COLOR_FAVORITE_BG,
            font=("Arial", 10),
            wraplength=130,
        )
        name_lbl.pack(pady=(5, 0))

        # Bind click - use helper methods instead of lambdas
        def make_click_handler(idx: int) -> Callable[[TkEvent], None]:
            def handler(event: TkEvent) -> None:
                self._on_favorite_click(idx)

            return handler

        def make_enter_handler(t: tk.Frame) -> Callable[[TkEvent], None]:
            def handler(event: TkEvent) -> None:
                self._on_tile_hover(t, True)

            return handler

        def make_leave_handler(t: tk.Frame) -> Callable[[TkEvent], None]:
            def handler(event: TkEvent) -> None:
                self._on_tile_hover(t, False)

            return handler

        tile.bind("<Button-1>", make_click_handler(index))
        icon_lbl.bind("<Button-1>", make_click_handler(index))
        name_lbl.bind("<Button-1>", make_click_handler(index))

        # Hover effects
        for widget in (tile, icon_lbl, name_lbl):
            widget.bind("<Enter>", make_enter_handler(tile))
            widget.bind("<Leave>", make_leave_handler(tile))

        self._favorites_widgets.append(
            {
                "frame": tile,
                "icon": icon_lbl,
                "name": name_lbl,
                "profile": None,
            }
        )

        return tile

    def _on_tile_hover(self, tile: tk.Frame, entering: bool) -> None:
        """Обрабатывает hover эффект на tile.

        Args:
            tile: Фрейм tile.
            entering: True если курсор входит.
        """
        color = COLOR_FAVORITE_ACTIVE if entering else COLOR_FAVORITE_BG
        for child in tile.winfo_children():
            if isinstance(child, tk.Label):
                child.config(bg=color)
        tile.config(bg=color)

    def _update_favorites_display(self) -> None:
        """Обновляет отображение избранных профилей."""
        favorites = self._service.get_favorites()

        for idx, widget_data in enumerate(self._favorites_widgets):
            if idx < len(favorites):
                profile = favorites[idx]
                widget_data["profile"] = profile
                name_lbl: tk.Label = widget_data["name"]
                icon_lbl: tk.Label = widget_data["icon"]
                name_lbl.config(text=profile.name_ru)
                # Update icon based on category
                icon = {
                    "continuous": "📜",
                    "sheet": "📄",
                    "envelope": "✉️",
                }.get(profile.category, "📄")
                icon_lbl.config(text=icon)
            else:
                widget_data["profile"] = None
                name_lbl = cast(tk.Label, widget_data["name"])
                icon_lbl = cast(tk.Label, widget_data["icon"])
                name_lbl.config(text="—")
                icon_lbl.config(text="➕")

    def _on_favorite_click(self, index: int) -> None:
        """Обрабатывает клик по избранному.

        Args:
            index: Индекс tile.
        """
        if index < len(self._favorites_widgets):
            profile = self._favorites_widgets[index]["profile"]
            if profile:
                self._select_profile(profile)
            else:
                # Empty slot - open manage favorites
                self._open_manage_favorites()

    def _open_manage_favorites(self) -> None:
        """Открывает диалог управления избранными."""
        # Simple dialog for now
        ManageFavoritesDialog(cast(Any, self), self._service)

    def _create_all_papers_section(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт секцию всех paper types.

        Args:
            parent: Родительский виджет.

        Returns:
            Фрейм с деревом профилей.
        """
        frame = tk.LabelFrame(parent, text="All Profiles", padx=PADDING_NORMAL, pady=PADDING_NORMAL)

        # Treeview
        self._tree = ttk.Treeview(
            frame,
            columns=("name", "size"),
            show="tree headings",
            selectmode="browse",
            height=15,
        )
        self._tree.heading("#0", text="Category")
        self._tree.heading("name", text="Name")
        self._tree.heading("size", text="Size")
        self._tree.column("#0", width=120, stretch=False)
        self._tree.column("name", width=180)
        self._tree.column("size", width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind selection
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # Populate tree
        self._populate_tree()

        return frame

    def _populate_tree(self) -> None:
        """Заполняет дерево профилями."""
        if self._tree is None:
            return

        # Clear existing
        for item in self._tree.get_children():
            self._tree.delete(item)

        # Categories
        categories: dict[str, tuple[str, str]] = {
            "continuous": ("Continuous Forms", COLOR_CATEGORY_CONTINUOUS),
            "sheet": ("Sheet Feed", COLOR_CATEGORY_SHEET),
            "envelope": ("Envelopes", COLOR_CATEGORY_ENVELOPE),
        }

        favorites_ids = {p.id for p in self._service.get_favorites()}

        for cat_key, (cat_name, _color) in categories.items():
            # Category node
            cat_node = self._tree.insert(
                "",
                tk.END,
                text=f" {cat_name}",
                values=("", ""),
                tags=("category",),
            )

            profiles = self._service.get_profiles_by_category(
                cast(Literal["continuous", "sheet", "envelope"], cat_key)
            )
            for profile in profiles:
                if profile.id not in favorites_ids:  # Skip favorites (they're on top)
                    self._tree.insert(
                        cat_node,
                        tk.END,
                        text="",
                        values=(profile.name_ru, f"{profile.width_mm:.0f}×{profile.height_mm:.0f}"),
                        tags=(profile.id,),
                    )

        # Configure tags
        self._tree.tag_configure("category", font=("Arial", 10, "bold"))

    def _on_tree_select(self, event: TkEvent) -> None:
        """Обрабатывает выбор в дереве.

        Args:
            event: Событие.
        """
        if self._tree is None:
            return

        selection = self._tree.selection()
        if selection:
            item = selection[0]
            tags = self._tree.item(item, "tags")
            if tags and tags[0] not in ("category",):
                profile = self._service.get_profile(tags[0])
                if profile:
                    self._select_profile(profile)

    def _create_details_panel(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт панель редактирования выбранного профиля.

        Args:
            parent: Родительский виджет.

        Returns:
            Фрейм с полями редактирования.
        """
        frame = tk.LabelFrame(
            parent,
            text="Profile Parameters",
            padx=PADDING_NORMAL,
            pady=PADDING_NORMAL,
            width=280,
        )
        frame.pack_propagate(False)

        # Name
        tk.Label(frame, text="Name:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self._profile_vars["name"] = tk.StringVar(master=self)
        tk.Entry(frame, textvariable=self._profile_vars["name"], width=20, state="readonly").grid(
            row=0, column=1, sticky=tk.W, pady=2
        )

        # Paper Type
        tk.Label(frame, text="Type:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self._profile_vars["paper_type"] = tk.StringVar(master=self)
        tk.Entry(
            frame, textvariable=self._profile_vars["paper_type"], width=20, state="readonly"
        ).grid(row=1, column=1, sticky=tk.W, pady=2)

        # Dimensions
        dim_frame = tk.LabelFrame(frame, text="Dimensions (mm)", padx=5, pady=5)
        dim_frame.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=PADDING_SMALL)

        tk.Label(dim_frame, text="Width:").grid(row=0, column=0, sticky=tk.W)
        self._profile_vars["width"] = tk.StringVar(master=self)
        tk.Spinbox(
            dim_frame,
            textvariable=self._profile_vars["width"],
            from_=MIN_DIMENSION_MM,
            to=MAX_DIMENSION_MM,
            width=8,
            command=self._on_dimension_change,
        ).grid(row=0, column=1, sticky=tk.W, padx=(5, 0))

        tk.Label(dim_frame, text="Height:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self._profile_vars["height"] = tk.StringVar(master=self)
        tk.Spinbox(
            dim_frame,
            textvariable=self._profile_vars["height"],
            from_=MIN_DIMENSION_MM,
            to=MAX_DIMENSION_MM,
            width=8,
            command=self._on_dimension_change,
        ).grid(row=1, column=1, sticky=tk.W, padx=(5, 0), pady=2)

        # Margins
        margins_frame = tk.LabelFrame(frame, text="Margins (mm)", padx=5, pady=5)
        margins_frame.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=PADDING_SMALL)

        # Left
        tk.Label(margins_frame, text="Left:").grid(row=0, column=0, sticky=tk.W)
        self._profile_vars["left_margin"] = tk.DoubleVar(master=self)
        tk.Spinbox(
            margins_frame,
            textvariable=self._profile_vars["left_margin"],
            from_=MIN_MARGIN_MM,
            to=MAX_MARGIN_MM,
            width=8,
            increment=0.5,
            command=self._on_margin_change,
        ).grid(row=0, column=1, sticky=tk.W, padx=(5, 0))

        # Right
        tk.Label(margins_frame, text="Right:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        self._profile_vars["right_margin"] = tk.DoubleVar(master=self)
        tk.Spinbox(
            margins_frame,
            textvariable=self._profile_vars["right_margin"],
            from_=MIN_MARGIN_MM,
            to=MAX_MARGIN_MM,
            width=8,
            increment=0.5,
            command=self._on_margin_change,
        ).grid(row=0, column=3, sticky=tk.W, padx=(5, 0))

        # Top
        tk.Label(margins_frame, text="Top:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self._profile_vars["top_margin"] = tk.DoubleVar(master=self)
        tk.Spinbox(
            margins_frame,
            textvariable=self._profile_vars["top_margin"],
            from_=MIN_MARGIN_MM,
            to=MAX_MARGIN_MM,
            width=8,
            increment=0.5,
            command=self._on_margin_change,
        ).grid(row=1, column=1, sticky=tk.W, padx=(5, 0), pady=2)

        # Bottom
        tk.Label(margins_frame, text="Bottom:").grid(row=1, column=2, sticky=tk.W, padx=(10, 0))
        self._profile_vars["bottom_margin"] = tk.DoubleVar(master=self)
        tk.Spinbox(
            margins_frame,
            textvariable=self._profile_vars["bottom_margin"],
            from_=MIN_MARGIN_MM,
            to=MAX_MARGIN_MM,
            width=8,
            increment=0.5,
            command=self._on_margin_change,
        ).grid(row=1, column=3, sticky=tk.W, padx=(5, 0), pady=2)

        # Tear-off checkbox (only for continuous)
        self._tear_off_var = tk.BooleanVar(master=self)
        self._tear_off_check = tk.Checkbutton(
            frame,
            text="Tear-off perforation",
            variable=self._tear_off_var,
            command=self._on_tear_off_change,
        )
        self._tear_off_check.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=2)

        self._tear_off_info = tk.Label(
            frame, text="(+10mm to side margins)", font=("Arial", 8), fg="gray"
        )
        self._tear_off_info.grid(row=5, column=0, columnspan=2, sticky=tk.W)

        # Defaults
        defaults_frame = tk.LabelFrame(frame, text="Defaults", padx=5, pady=5)
        defaults_frame.grid(row=6, column=0, columnspan=2, sticky=tk.EW, pady=PADDING_SMALL)

        # CPI
        tk.Label(defaults_frame, text="CPI:").grid(row=0, column=0, sticky=tk.W)
        self._profile_vars["cpi"] = tk.IntVar(master=self)
        cpi_combo = ttk.Combobox(
            defaults_frame,
            textvariable=self._profile_vars["cpi"],
            values=["10", "12", "15", "17", "20"],
            width=8,
            state="readonly",
        )
        cpi_combo.grid(row=0, column=1, sticky=tk.W, padx=(5, 0))
        cpi_combo.bind("<<ComboboxSelected>>", lambda e: self._update_printable_display())

        # LPI
        tk.Label(defaults_frame, text="LPI:").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        self._profile_vars["lpi"] = tk.IntVar(master=self)
        lpi_combo = ttk.Combobox(
            defaults_frame,
            textvariable=self._profile_vars["lpi"],
            values=["6", "8"],
            width=8,
            state="readonly",
        )
        lpi_combo.grid(row=0, column=3, sticky=tk.W, padx=(5, 0))
        lpi_combo.bind("<<ComboboxSelected>>", lambda e: self._update_printable_display())

        # Font
        tk.Label(defaults_frame, text="Font:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self._profile_vars["font"] = tk.StringVar(master=self)
        font_combo = ttk.Combobox(
            defaults_frame,
            textvariable=self._profile_vars["font"],
            values=[f.localized_name("en") for f in FontFamily],
            width=15,
            state="readonly",
        )
        font_combo.grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=(5, 0), pady=2)

        # Printable area display
        printable_frame = tk.LabelFrame(frame, text="Printable Area", padx=5, pady=5)
        printable_frame.grid(row=7, column=0, columnspan=2, sticky=tk.EW, pady=PADDING_SMALL)

        printable_label = tk.Label(
            printable_frame,
            text="—",
            font=("Arial", 9),
            justify=tk.LEFT,
        )
        printable_label.pack(anchor=tk.W)
        self._printable_label = printable_label

        # Recalculate button
        recalc_btn = tk.Button(
            frame, text="↻ Recalculate", command=self._update_printable_display
        )
        recalc_btn.grid(row=8, column=0, columnspan=2, pady=PADDING_SMALL)
        self._recalc_btn = recalc_btn

        # Initial state: disabled
        self._set_details_enabled(False)

        return frame

    def _set_details_enabled(self, enabled: bool) -> None:
        """Включает/отключает поля редактирования.

        Args:
            enabled: True для включения.
        """
        state: str = tk.NORMAL if enabled else tk.DISABLED

        if self._tear_off_check:
            self._tear_off_check.config(state=cast(Any, state))

        if enabled and self._selected_profile:
            if self._tear_off_check:
                self._tear_off_check.config(
                    state=cast(
                        Any, tk.NORMAL if self._selected_profile.is_continuous else tk.DISABLED
                    )
                )

    def _select_profile(self, profile: PaperProfile) -> None:
        """Выбирает профиль для редактирования.

        Args:
            profile: Выбранный профиль.
        """
        self._selected_profile = profile
        self._set_details_enabled(True)

        # Populate fields
        name_var = cast(tk.StringVar, self._profile_vars["name"])
        name_var.set(profile.name_ru)

        paper_type_var = cast(tk.StringVar, self._profile_vars["paper_type"])
        paper_type_var.set(profile.paper_type.localized_name("en"))

        width_var = cast(tk.StringVar, self._profile_vars["width"])
        width_var.set(str(int(profile.width_mm)))

        height_var = cast(tk.StringVar, self._profile_vars["height"])
        height_var.set(str(int(profile.height_mm)))

        left_margin_var = cast(tk.DoubleVar, self._profile_vars["left_margin"])
        left_margin_var.set(profile.left_margin_mm)

        right_margin_var = cast(tk.DoubleVar, self._profile_vars["right_margin"])
        right_margin_var.set(profile.right_margin_mm)

        top_margin_var = cast(tk.DoubleVar, self._profile_vars["top_margin"])
        top_margin_var.set(profile.top_margin_mm)

        bottom_margin_var = cast(tk.DoubleVar, self._profile_vars["bottom_margin"])
        bottom_margin_var.set(profile.bottom_margin_mm)

        cpi_var = cast(tk.IntVar, self._profile_vars["cpi"])
        cpi_var.set(profile.default_cpi)

        lpi_var = cast(tk.IntVar, self._profile_vars["lpi"])
        lpi_var.set(profile.default_lpi)

        font_var = cast(tk.StringVar, self._profile_vars["font"])
        font_var.set(profile.default_font.localized_name("en"))

        self._tear_off_var.set(profile.tear_off_perforation)

        # Update tear-off visibility
        if profile.is_continuous:
            if self._tear_off_check:
                self._tear_off_check.config(state=tk.NORMAL)
            if self._tear_off_info:
                self._tear_off_info.config(fg="gray")
        else:
            if self._tear_off_check:
                self._tear_off_check.config(state=tk.DISABLED)
            if self._tear_off_info:
                self._tear_off_info.config(fg="lightgray")

        self._update_printable_display()

    def _on_dimension_change(self) -> None:
        """Обрабатывает изменение размеров."""
        self._update_printable_display()

    def _on_margin_change(self) -> None:
        """Обрабатывает изменение margins."""
        self._update_printable_display()

    def _on_tear_off_change(self) -> None:
        """Обрабатывает изменение tear-off."""
        self._update_printable_display()

    def _update_printable_display(self) -> None:
        """Обновляет отображение печатной области."""
        if self._selected_profile is None or self._printable_label is None:
            return

        # Get current values
        try:
            width_var = cast(tk.StringVar, self._profile_vars["width"])
            height_var = cast(tk.StringVar, self._profile_vars["height"])
            left_margin_var = cast(tk.DoubleVar, self._profile_vars["left_margin"])
            right_margin_var = cast(tk.DoubleVar, self._profile_vars["right_margin"])
            top_margin_var = cast(tk.DoubleVar, self._profile_vars["top_margin"])
            bottom_margin_var = cast(tk.DoubleVar, self._profile_vars["bottom_margin"])
            cpi_var = cast(tk.IntVar, self._profile_vars["cpi"])
            lpi_var = cast(tk.IntVar, self._profile_vars["lpi"])

            width = float(width_var.get())
            height = float(height_var.get())
            left = float(left_margin_var.get())
            right = float(right_margin_var.get())
            top = float(top_margin_var.get())
            bottom = float(bottom_margin_var.get())
            cpi = int(cpi_var.get())
            lpi = int(lpi_var.get())
            tear_off = self._tear_off_var.get()

            # Create temporary profile
            temp_profile = PaperProfile(
                id="temp",
                name="temp",
                name_ru="temp",
                category="sheet",
                paper_type=self._selected_profile.paper_type,
                width_mm=width,
                height_mm=height,
                left_margin_mm=left,
                right_margin_mm=right,
                top_margin_mm=top,
                bottom_margin_mm=bottom,
                tear_off_perforation=tear_off,
                default_cpi=cpi,
                default_lpi=lpi,
            )

            text = temp_profile.get_printable_area_display()
            self._printable_label.config(text=text)
        except (ValueError, tk.TclError):
            self._printable_label.config(text="—")

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки OK/Cancel/Manage.

        Args:
            parent: Родительский виджет.
        """
        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill=tk.X)

        # Manage Favorites button (left)
        manage_btn = tk.Button(
            btn_frame, text="⚙️ Manage Favorites", command=self._open_manage_favorites
        )
        manage_btn.pack(side=tk.LEFT)

        # Spacer
        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # OK button
        ok_btn = tk.Button(btn_frame, text="OK", width=10, command=self._on_ok)
        ok_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        # Cancel button
        cancel_btn = tk.Button(btn_frame, text="Cancel", width=10, command=self._on_cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        # Apply button
        apply_btn = tk.Button(btn_frame, text="Apply", width=10, command=self._on_apply)
        apply_btn.pack(side=tk.RIGHT)

    def _on_ok(self) -> None:
        """Обрабатывает OK."""
        if self._apply_changes():
            self._result = self._selected_profile
            if self._on_select and self._selected_profile:
                self._on_select(self._selected_profile)
            self.destroy()

    def _on_cancel(self) -> None:
        """Обрабатывает Cancel."""
        self._result = None
        self.destroy()

    def _on_apply(self) -> None:
        """Обрабатывает Apply."""
        self._apply_changes()
        if self._on_select and self._selected_profile:
            self._on_select(self._selected_profile)

    def _apply_changes(self) -> bool:
        """Применяет изменения к профилю.

        Returns:
            True если успешно.
        """
        if self._selected_profile is None:
            return False

        try:
            # Get values from UI
            left_margin_var = cast(tk.DoubleVar, self._profile_vars["left_margin"])
            right_margin_var = cast(tk.DoubleVar, self._profile_vars["right_margin"])
            top_margin_var = cast(tk.DoubleVar, self._profile_vars["top_margin"])
            bottom_margin_var = cast(tk.DoubleVar, self._profile_vars["bottom_margin"])
            cpi_var = cast(tk.IntVar, self._profile_vars["cpi"])
            lpi_var = cast(tk.IntVar, self._profile_vars["lpi"])

            left = float(left_margin_var.get())
            right = float(right_margin_var.get())
            top = float(top_margin_var.get())
            bottom = float(bottom_margin_var.get())
            tear_off = self._tear_off_var.get()
            cpi = int(cpi_var.get())
            lpi = int(lpi_var.get())

            # Update profile
            updated = self._service.update_profile(
                self._selected_profile.id,
                left_margin_mm=left,
                right_margin_mm=right,
                top_margin_mm=top,
                bottom_margin_mm=bottom,
                tear_off_perforation=tear_off,
                default_cpi=cpi,
                default_lpi=lpi,
            )

            if updated:
                self._selected_profile = updated
                self._update_favorites_display()
                return True
        except (ValueError, tk.TclError) as exc:
            logger.warning("Ошибка применения изменений: %s", exc)

        return False

    def show(self) -> Optional[PaperProfile]:
        """Показывает диалог модально.

        Returns:
            Выбранный профиль или None.
        """
        self._update_favorites_display()
        self.wait_window()
        return self._result


# =============================================================================
# ManageFavoritesDialog
# =============================================================================


class ManageFavoritesDialog(BaseDialog):
    """Диалог управления списком избранного.

    Attributes:
        parent: Родительский диалог.
        service: Сервис профилей.
    """

    def __init__(self, parent: tk.Widget, service: PaperProfileService) -> None:
        """Инициализация.

        Args:
            parent: Родительский виджет.
            service: Сервис профилей.
        """
        super().__init__(parent)

        self._service = service
        self._selected: list[str] = []

        self.title("Manage Favorites")
        self.resizable(False, False)

        self._listbox: tk.Listbox = tk.Listbox(self)
        self._profile_ids: list[str] = []

        self._create_ui()

    def _center_window(self) -> None:
        """Центрирует окно."""
        self.update_idletasks()
        width = 400
        height = 500
        x = self.winfo_screenwidth() // 2 - width // 2
        y = self.winfo_screenheight() // 2 - height // 2
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI."""
        frame = tk.Frame(self, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        frame.pack(fill=tk.BOTH, expand=True)

        # Instructions
        favorites_str = str(MAX_FAVORITES)
        tk.Label(frame, text=f"Select up to {favorites_str} profiles:", anchor=tk.W).pack(
            fill=tk.X, pady=(0, PADDING_SMALL)
        )

        # Listbox with checkboxes
        list_frame = tk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._listbox = tk.Listbox(
            list_frame, selectmode=tk.MULTIPLE, yscrollcommand=scrollbar.set, height=15
        )
        self._listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self._listbox.yview)

        # Populate
        favorites = self._service.get_favorites()
        favorite_ids = {p.id for p in favorites}

        self._profile_ids = []
        all_profiles = self._service.get_all_profiles()

        for idx, profile in enumerate(all_profiles):
            self._listbox.insert(tk.END, f"{profile.name_ru} ({profile.category})")
            self._profile_ids.append(profile.id)
            if profile.id in favorite_ids:
                self._listbox.select_set(idx)

        # Buttons
        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=PADDING_NORMAL)

        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Button(btn_frame, text="Cancel", width=10, command=self.destroy).pack(
            side=tk.RIGHT, padx=(PADDING_SMALL, 0)
        )
        tk.Button(btn_frame, text="Save", width=10, command=self._on_save).pack(side=tk.RIGHT)

    def _on_save(self) -> None:
        """Сохраняет изменения."""
        # tkinter Listbox.curselection returns tuple[int, ...]
        selected_indices: tuple[int, ...] = self._listbox.curselection()  # type: ignore[no-untyped-call]
        selected_ids = [self._profile_ids[i] for i in selected_indices]

        if len(selected_ids) > MAX_FAVORITES:
            messagebox.showwarning(
                "Too Many",
                f"You can select at most {MAX_FAVORITES} profiles.",
            )
            return

        self._service.set_favorites(selected_ids)
        self.destroy()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "PaperProfileDialog",
    "ManageFavoritesDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
]
