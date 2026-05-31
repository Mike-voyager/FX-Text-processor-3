"""Диалоги для работы с 1D штрих-кодами.

Компоненты:
- BarcodeTypeSelector: Выбор типа штрих-кода с режимом Hardware/Software
- BarcodeSettingsPanel: Настройки параметров штрих-кода
- BarcodeConflictDialog: Диалог предупреждения о конфликте типов

Поддерживаемые режимы:
    - Hardware: ESC/P команды для FX-890 (EAN-13, EAN-8, CODE39, CODE128)
    - Software: PNG рендеринг через python-barcode (все типы)

Example:
    >>> from src.gui.dialogs.barcode_dialog import BarcodeTypeSelector
    >>> selector = BarcodeTypeSelector(parent)
    >>> result = selector.show()
    >>> if result:
    ...     print(f"Type: {result.barcode_type}, Mode: {result.mode}")

Module: src/gui/dialogs/barcode_dialog.py
Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from enum import Enum, auto
from tkinter import messagebox, ttk
from typing import Any, Final, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.renderers.barcode_canvas_renderer import SoftwareBarcodeRenderer
from src.gui.themes import ThemeRegistry, get_theme_manager
from src.model.enums import BarcodeType

logger: Final = logging.getLogger(__name__)

# =============================================================================
# THEME HELPERS
# =============================================================================


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Color в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except (AttributeError, KeyError, RuntimeError):
        return "#333333"


# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 550
DIALOG_HEIGHT: Final[int] = 500
MIN_DIALOG_WIDTH: Final[int] = 450
MIN_DIALOG_HEIGHT: Final[int] = 400

# Hardware supported types (FX-890 ESC/P)
HARDWARE_TYPES: Final[set[str]] = {
    BarcodeType.EAN13.value,
    BarcodeType.EAN8.value,
    BarcodeType.CODE39.value,
    BarcodeType.CODE128.value,
    BarcodeType.UPCA.value,
}

# All supported types with labels
BARCODE_TYPES: Final[list[tuple[str, str, str]]] = [
    (BarcodeType.CODE128.value, "Code 128", "Universal, all ASCII characters"),
    (BarcodeType.CODE39.value, "Code 39", "Alphanumeric, industrial"),
    (BarcodeType.EAN13.value, "EAN-13", "Product barcode (13 digits)"),
    (BarcodeType.EAN8.value, "EAN-8", "Small product barcode (8 digits)"),
    (BarcodeType.UPCA.value, "UPC-A", "North American product"),
    (BarcodeType.ITF.value, "ITF-14", "Logistics, transport packages"),
    (BarcodeType.CODABAR.value, "Codabar", "Medical, laboratories"),
]


class BarcodeMode(Enum):
    """Режим генерации штрих-кода.

    Attributes:
        HARDWARE: ESC/P команды для принтера FX-890.
        SOFTWARE: PNG изображение через python-barcode.
    """

    HARDWARE = auto()
    SOFTWARE = auto()

    def label(self) -> str:
        """Returns human-readable label."""
        labels = {
            BarcodeMode.HARDWARE: "Hardware (FX-890 ESC/P)",
            BarcodeMode.SOFTWARE: "Software (preview/export)",
        }
        return labels.get(self, str(self))

    def description(self) -> str:
        """Returns mode description."""
        descriptions = {
            BarcodeMode.HARDWARE: "Fast ESC/P printing (limited types)",
            BarcodeMode.SOFTWARE: "Image rendering (all types, slower)",
        }
        return descriptions.get(self, "")


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class BarcodeSelectionResult:
    """Результат выбора типа штрих-кода.

    Attributes:
        barcode_type: Выбранный тип штрих-кода.
        mode: Режим генерации (Hardware/Software).
        data: Данные для кодирования.

    Example:
        >>> result = BarcodeSelectionResult(
        ...     barcode_type="CODE128",
        ...     mode=BarcodeMode.SOFTWARE,
        ...     data="12345",
        ... )
    """

    barcode_type: str
    mode: BarcodeMode
    data: str


@dataclass(frozen=True)
class BarcodeSettings:
    """Настройки штрих-кода.

    Attributes:
        width_mm: Ширина в миллиметрах.
        height_mm: Высота в миллиметрах.
        dpi: Разрешение печати.
        show_text: Показывать ли текст под штрих-кодом.
        hri_position: Позиция HRI (Below/Above/Both/None).
    """

    width_mm: float = 50.0
    height_mm: float = 25.0
    dpi: int = 300
    show_text: bool = True
    hri_position: str = "Below"


# =============================================================================
# DIALOG CLASSES
# =============================================================================


class BarcodeTypeSelector(BaseDialog):
    """Диалог выбора типа штрих-кода с выбором режима Hardware/Software.

    Позволяет выбрать тип штрих-кода и режим генерации.
    При выборе Hardware mode показывает предупреждение для
    несовместимых типов.

    Attributes:
        _selected_type: Выбранный тип штрих-кода.
        _selected_mode: Выбранный режим генерации.
        _data: Данные для кодирования.
        _result: Результат диалога.

    Example:
        >>> dialog = BarcodeTypeSelector(parent)
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Selected: {result.barcode_type}")
        ...     print(f"Mode: {result.mode.label()}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        current_type: str = "",
        current_mode: BarcodeMode = BarcodeMode.SOFTWARE,
        default_data: str = "",
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительский виджет.
            current_type: Текущий выбранный тип (для подсветки).
            current_mode: Текущий режим генерации.
            default_data: Данные по умолчанию.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._current_type: str = current_type
        self._selected_type: str = current_type or BarcodeType.CODE128.value
        self._selected_mode: BarcodeMode = current_mode
        self._data: str = default_data
        self._result: Optional[BarcodeSelectionResult] = None

        self._theme_manager = get_theme_manager()

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна диалога."""
        self.title("Barcode Type")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (DIALOG_WIDTH // 2)
        y = (self.winfo_screenheight() // 2) - (DIALOG_HEIGHT // 2)
        self.geometry(f"+{x}+{y}")

        # Apply theme
        self._theme_manager.apply_to_widget(self)

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        self.config(bg=_theme_color("dialog_bg"))

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(
            main_frame,
            text="Barcode",
            font=("Helvetica", 14, "bold"),
        )
        header.pack(anchor="w", pady=(0, 5))

        # Description
        desc = ttk.Label(
            main_frame,
            text="Select barcode type and generation mode:",
            wraplength=DIALOG_WIDTH - 60,
            foreground=_theme_color("text_secondary"),
        )
        desc.pack(anchor="w", pady=(0, 15))

        # Mode selection frame
        self._create_mode_section(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Type selection frame
        self._create_type_section(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Data section
        self._create_data_section(main_frame)

        # Warning label (initially hidden)
        self._warning_var = tk.StringVar(master=self, value="")
        self._warning_label = ttk.Label(
            main_frame,
            textvariable=self._warning_var,
            foreground=_theme_color("warning"),
            font=("Helvetica", 9, "bold"),
            wraplength=DIALOG_WIDTH - 60,
        )
        self._warning_label.pack(anchor="w", pady=(10, 0))

        # Preview section
        preview_frame = ttk.LabelFrame(main_frame, text="Preview", padding="5")
        preview_frame.pack(fill=tk.X, pady=(10, 0))
        self._preview_canvas = tk.Canvas(
            preview_frame,
            height=130,
            bg="white",
            highlightthickness=1,
            highlightbackground="#cccccc",
        )
        self._preview_canvas.pack(fill=tk.X, expand=True)
        self._preview_renderer = SoftwareBarcodeRenderer(self._preview_canvas)

        # Overlay item ID for hardware mode text (tracked for cleanup)
        self._preview_overlay_id: Optional[int] = None

        # Buttons
        self._create_button_section(main_frame)

        # Initial update
        self._update_ui_state()

    def _create_mode_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию выбора режима Hardware/Software.

        Args:
            parent: Родительский фрейм.
        """
        mode_frame = ttk.LabelFrame(
            parent,
            text="Generation Mode",
            padding="10",
        )
        mode_frame.pack(fill=tk.X, pady=(0, 10))

        self._mode_var = tk.IntVar(master=self, value=self._selected_mode.value)

        # Hardware mode
        hw_frame = ttk.Frame(mode_frame)
        hw_frame.pack(fill=tk.X, pady=5)

        self._hw_radio = ttk.Radiobutton(
            hw_frame,
            text=BarcodeMode.HARDWARE.label(),
            variable=self._mode_var,
            value=BarcodeMode.HARDWARE.value,
            command=self._on_mode_changed,
        )
        self._hw_radio.pack(side=tk.LEFT)

        hw_desc = ttk.Label(
            hw_frame,
            text=BarcodeMode.HARDWARE.description(),
            foreground=_theme_color("text_secondary"),
            font=("Helvetica", 9),
        )
        hw_desc.pack(side=tk.LEFT, padx=(10, 0))

        # Hardware supported types hint
        hw_types = ttk.Label(
            mode_frame,
            text="Supported types: EAN-13, EAN-8, CODE39, CODE128, UPC-A",
            foreground=_theme_color("info"),
            font=("Helvetica", 8),
        )
        hw_types.pack(anchor="w", padx=(20, 0))

        # Software mode
        sw_frame = ttk.Frame(mode_frame)
        sw_frame.pack(fill=tk.X, pady=5)

        self._sw_radio = ttk.Radiobutton(
            sw_frame,
            text=BarcodeMode.SOFTWARE.label(),
            variable=self._mode_var,
            value=BarcodeMode.SOFTWARE.value,
            command=self._on_mode_changed,
        )
        self._sw_radio.pack(side=tk.LEFT)

        sw_desc = ttk.Label(
            sw_frame,
            text=BarcodeMode.SOFTWARE.description(),
            foreground=_theme_color("text_secondary"),
            font=("Helvetica", 9),
        )
        sw_desc.pack(side=tk.LEFT, padx=(10, 0))

    def _create_type_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию выбора типа штрих-кода.

        Args:
            parent: Родительский фрейм.
        """
        type_frame = ttk.LabelFrame(
            parent,
            text="Barcode Type",
            padding="10",
        )
        type_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Scrollable list
        list_container = ttk.Frame(type_frame)
        list_container.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._listbox = tk.Listbox(
            list_container,
            yscrollcommand=scrollbar.set,
            font=("Helvetica", 10),
            selectmode=tk.SINGLE,
            height=8,
        )
        self._listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self._listbox.yview)

        # Populate listbox
        self._type_map: dict[str, str] = {}
        for code, name, description in BARCODE_TYPES:
            is_hw_supported = code in HARDWARE_TYPES
            hw_badge = " 📠" if is_hw_supported else ""
            display_text = f"{name:<12} │ {description}{hw_badge}"
            self._listbox.insert(tk.END, display_text)
            self._type_map[display_text] = code

            # Select current type
            if code == self._current_type:
                self._listbox.selection_set(tk.END)
                self._listbox.see(tk.END)

        # Bind selection
        self._listbox.bind("<<ListboxSelect>>", self._on_type_changed)
        self._listbox.bind("<Double-1>", lambda e: self._on_ok())

        # Info label
        self._info_var = tk.StringVar(master=self, value="Select barcode type from list")
        self._info_label = ttk.Label(
            type_frame,
            textvariable=self._info_var,
            foreground=_theme_color("text_secondary"),
            font=("Helvetica", 9),
        )
        self._info_label.pack(anchor="w", pady=(10, 0))

    def _create_data_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию ввода данных.

        Args:
            parent: Родительский фрейм.
        """
        data_frame = ttk.Frame(parent)
        data_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            data_frame,
            text="Data:",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w", pady=(0, 5))

        self._data_var = tk.StringVar(master=self, value=self._data)
        self._data_entry = ttk.Entry(
            data_frame,
            textvariable=self._data_var,
            font=("Helvetica", 10),
        )
        self._data_entry.pack(fill=tk.X)

        # Validation hint
        self._data_hint = ttk.Label(
            data_frame,
            text="Enter data to encode in barcode",
            foreground=_theme_color("text_secondary"),
            font=("Helvetica", 8),
        )
        self._data_hint.pack(anchor="w", pady=(5, 0))

    def _create_button_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию кнопок.

        Args:
            parent: Родительский фрейм.
        """
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        # Preview button
        self._preview_btn = ttk.Button(
            btn_frame,
            text="Preview",
            command=self._on_preview,
            state=tk.DISABLED,
        )
        self._preview_btn.pack(side=tk.LEFT)

        # OK button
        self._ok_btn = ttk.Button(
            btn_frame,
            text="Insert",
            command=self._on_ok,
            state=tk.DISABLED,
        )
        self._ok_btn.pack(side=tk.RIGHT, padx=(10, 0))

        # Cancel button
        ttk.Button(
            btn_frame,
            text="Cancel",
            command=self._on_cancel,
        ).pack(side=tk.RIGHT)

    def _on_mode_changed(self) -> None:
        """Обработчик изменения режима."""
        mode_value = self._mode_var.get()
        self._selected_mode = BarcodeMode(mode_value)
        self._update_ui_state()

    def _on_type_changed(self, event: tk.Event) -> None:
        """Обработчик изменения выбора типа."""
        selection = self._listbox.curselection()  # type: ignore[no-untyped-call]
        if selection:
            display_text = self._listbox.get(selection[0])
            code = self._type_map.get(display_text, "")
            self._selected_type = code

            # Update info label
            type_info = next((t for t in BARCODE_TYPES if t[0] == code), None)
            if type_info:
                hw_supported = code in HARDWARE_TYPES
                hw_text = "Hardware mode supported" if hw_supported else "Software mode only"
                self._info_var.set(f"{type_info[1]}: {type_info[2]} | {hw_text}")

        self._update_ui_state()

    def _update_ui_state(self) -> None:
        """Обновляет состояние UI в зависимости от выбора."""
        has_selection = bool(self._selected_type)
        has_data = bool(self._data_var.get().strip())

        # Check hardware compatibility
        is_hw_mode = self._selected_mode == BarcodeMode.HARDWARE
        is_hw_supported = self._selected_type in HARDWARE_TYPES

        if is_hw_mode and has_selection and not is_hw_supported:
            self._warning_var.set(
                f"⚠️ {self._selected_type} does not support Hardware mode. "
                "Software mode will be used."
            )
            self._ok_btn.config(state=tk.NORMAL if has_data else tk.DISABLED)
        elif is_hw_mode and is_hw_supported:
            self._warning_var.set("📠 Fast ESC/P printing")
            self._ok_btn.config(state=tk.NORMAL if has_data else tk.DISABLED)
        elif self._selected_mode == BarcodeMode.SOFTWARE:
            self._warning_var.set("" if not has_selection else "🖼️ Image rendering")
            self._ok_btn.config(state=tk.NORMAL if has_data else tk.DISABLED)
        else:
            self._warning_var.set("")
            self._ok_btn.config(state=tk.DISABLED)

        self._preview_btn.config(state=tk.NORMAL if (has_selection and has_data) else tk.DISABLED)

    def _on_preview(self) -> None:
        """Обработчик кнопки предпросмотра.

        Рендерит штрих-код на canvas предпросмотра в диалоге.
        В режиме Hardware добавляет текстовую метку поверх рендера.
        Предыдущий оверлей корректно удаляется перед новым рендером.
        """
        data = self._data_var.get().strip()
        if not data or not self._selected_type:
            return

        # Удаляем предыдущий оверлей hardware-режима
        if self._preview_overlay_id is not None:
            try:
                self._preview_canvas.delete(self._preview_overlay_id)
            except tk.TclError:
                pass
            self._preview_overlay_id = None

        self._preview_renderer.clear()
        self._preview_renderer.render(
            barcode_type=self._selected_type,
            data=data,
            x=10,
            y=10,
            width=350,
            height=110,
            show_text=True,
        )

        if self._selected_mode == BarcodeMode.HARDWARE:
            self._preview_overlay_id = self._preview_canvas.create_text(
                180,
                65,
                text="Hardware (FX-890 ESC/P)",
                fill="#856404",
                font=("Helvetica", 10, "bold"),
            )

    def _on_ok(self) -> None:
        """Обработчик кнопки OK — подтверждает выбор штрих-кода."""
        data = self._data_var.get().strip()
        if not data:
            messagebox.showwarning(
                "Warning",
                "Enter data for encoding",
                parent=self,
            )
            return

        final_mode = self._selected_mode
        final_type = self._selected_type

        # Conflict dialog for hardware mode + unsupported type (e.g. CODE128, PDF417)
        if final_mode == BarcodeMode.HARDWARE and final_type not in HARDWARE_TYPES:
            conflict = BarcodeConflictDialog(
                parent=cast(Any, self),
                barcode_type=final_type,
                reason=f"{final_type} не поддерживается в Hardware mode",
                suggested_type=BarcodeType.CODE39.value,
            )
            success, choice = conflict.show()
            if not success or choice == "cancel":
                self._result = None
                self.close(None)
                return
            elif choice == "switch":
                final_type = BarcodeType.CODE39.value
                final_mode = BarcodeMode.HARDWARE
            else:
                # "software" — render as image
                final_mode = BarcodeMode.SOFTWARE

        self._result = BarcodeSelectionResult(
            barcode_type=final_type,
            mode=final_mode,
            data=data,
        )
        self.close(self._result)

    def _on_cancel(self) -> None:
        """Обработчик кнопки Отмена — закрывает диалог без результата."""
        self._result = None
        self.close(None)

    def show(self) -> Optional[BarcodeSelectionResult]:
        """Показывает диалог модально и возвращает результат.

        Returns:
            BarcodeSelectionResult с выбранными параметрами или None.
        """
        super().show()
        return self._result


class BarcodeSettingsPanel(ttk.Frame):
    """Панель настроек штрих-кода.

    Позволяет настраивать размеры, разрешение и параметры
    отображения текста для штрих-кода.

    Attributes:
        _settings: Текущие настройки.

    Example:
        >>> panel = BarcodeSettingsPanel(parent)
        >>> panel.set_settings(current_settings)
        >>> settings = panel.get_settings()
        >>> print(f"Width: {settings.width_mm}mm")
    """

    def __init__(self, parent: tk.Widget, *args: Any, **kwargs: Any) -> None:
        """Инициализация панели настроек.

        Args:
            parent: Родительский виджет.
        """
        super().__init__(parent, *args, **kwargs)

        self._settings = BarcodeSettings()

        self._create_ui()

    def _create_ui(self) -> None:
        """Создаёт UI компоненты панели."""
        self.config(padding="15")

        # Header
        header = ttk.Label(
            self,
            text="Barcode Settings",
            font=("Helvetica", 11, "bold"),
        )
        header.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 15))

        # Width
        ttk.Label(self, text="Width (mm):").grid(row=1, column=0, sticky="w", pady=5)
        self._width_var = tk.DoubleVar(master=self, value=self._settings.width_mm)
        width_spin = ttk.Spinbox(self, from_=10, to=200, textvariable=self._width_var, width=10)
        width_spin.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=5)
        ttk.Label(self, text="10-200 mm", foreground=_theme_color("text_secondary")).grid(
            row=1, column=2, sticky="w", padx=(5, 0)
        )

        # Height
        ttk.Label(self, text="Height (mm):").grid(row=2, column=0, sticky="w", pady=5)
        self._height_var = tk.DoubleVar(master=self, value=self._settings.height_mm)
        height_spin = ttk.Spinbox(self, from_=5, to=100, textvariable=self._height_var, width=10)
        height_spin.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=5)
        ttk.Label(self, text="5-100 mm", foreground=_theme_color("text_secondary")).grid(
            row=2, column=2, sticky="w", padx=(5, 0)
        )

        # DPI
        ttk.Label(self, text="DPI:").grid(row=3, column=0, sticky="w", pady=5)
        self._dpi_var = tk.IntVar(master=self, value=self._settings.dpi)
        dpi_combo = ttk.Combobox(
            self,
            textvariable=self._dpi_var,
            values=["150", "200", "300", "600"],
            width=10,
            state="readonly",
        )
        dpi_combo.grid(row=3, column=1, sticky="w", padx=(10, 0), pady=5)
        ttk.Label(self, text="dots/inch", foreground=_theme_color("text_secondary")).grid(
            row=3, column=2, sticky="w", padx=(5, 0)
        )

        # Separator
        ttk.Separator(self, orient=tk.HORIZONTAL).grid(
            row=4, column=0, columnspan=3, sticky="ew", pady=15
        )

        # HRI Position
        ttk.Label(self, text="HRI (human readable):").grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(0, 5)
        )

        self._hri_var = tk.StringVar(master=self, value=self._settings.hri_position)
        hri_frame = ttk.Frame(self)
        hri_frame.grid(row=6, column=0, columnspan=3, sticky="w")

        hri_options = [
            ("Below", "Below"),
            ("Above", "Above"),
            ("Both", "Both"),
            ("None", "None"),
        ]

        for value, label in hri_options:
            ttk.Radiobutton(hri_frame, text=label, variable=self._hri_var, value=value).pack(
                side=tk.LEFT, padx=(0, 15)
            )

        self.columnconfigure(1, weight=0)

    def get_settings(self) -> BarcodeSettings:
        """Возвращает текущие настройки панели.

        Returns:
            Объект BarcodeSettings с текущими значениями.
        """
        return BarcodeSettings(
            width_mm=self._width_var.get(),
            height_mm=self._height_var.get(),
            dpi=self._dpi_var.get(),
            show_text=self._settings.show_text,
            hri_position=self._hri_var.get(),
        )

    def set_settings(self, settings: BarcodeSettings) -> None:
        """Устанавливает настройки панели.

        Args:
            settings: Новые настройки.
        """
        self._settings = settings
        self._width_var.set(settings.width_mm)
        self._height_var.set(settings.height_mm)
        self._dpi_var.set(settings.dpi)
        self._hri_var.set(settings.hri_position)


class BarcodeConflictDialog(BaseDialog):
    """Диалог предупреждения о конфликте типа штрих-кода.

    Отображается когда выбранный тип несовместим с данными
    или выбранным режимом генерации.

    Attributes:
        _barcode_type: Тип штрих-кода с конфликтом.
        _reason: Причина конфликта.
        _suggested_type: Рекомендуемый тип (опционально).
        _result: Результат выбора пользователя.

    Example:
        >>> dialog = BarcodeConflictDialog(
        ...     parent,
        ...     barcode_type="CODE128",
        ...     reason="Несовместим с Hardware mode",
        ...     suggested_type="CODE39",
        ... )
        >>> if dialog.show():
        ...     print("Пользователь решил продолжить")
    """

    def __init__(
        self,
        parent: tk.Widget,
        barcode_type: str,
        reason: str,
        suggested_type: Optional[str] = None,
    ) -> None:
        """Инициализация диалога конфликта.

        Args:
            parent: Родительский виджет.
            barcode_type: Тип штрих-кода с конфликтом.
            reason: Описание проблемы.
            suggested_type: Рекомендуемый альтернативный тип.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._barcode_type: str = barcode_type
        self._reason: str = reason
        self._suggested_type: Optional[str] = suggested_type
        self._result: bool = False
        self._choice: Optional[str] = None

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Configures dialog window parameters."""
        self.title("⚠️ Barcode Type Conflict")
        self.geometry("450x350")
        self.minsize(400, 300)

        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (225)
        y = (self.winfo_screenheight() // 2) - (175)
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Creates dialog UI components."""
        self.config(bg=_theme_color("dialog_bg"))

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Warning header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))

        warning_label = ttk.Label(
            header_frame,
            text="⚠️",
            font=("Helvetica", 32),
            foreground=_theme_color("warning"),
        )
        warning_label.pack(side=tk.LEFT, padx=(0, 15))

        title_label = ttk.Label(
            header_frame,
            text="Conflict Detected",
            font=("Helvetica", 14, "bold"),
        )
        title_label.pack(side=tk.LEFT)

        # Conflict details
        details_frame = ttk.LabelFrame(main_frame, text="Conflict Information", padding="10")
        details_frame.pack(fill=tk.X, pady=(0, 15))

        ttk.Label(
            details_frame,
            text=f"Type: {self._barcode_type}",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            details_frame,
            text=f"Problem: {self._reason}",
            wraplength=380,
            foreground=_theme_color("text_secondary"),
        ).pack(anchor="w", pady=(5, 0))

        # Suggestion
        if self._suggested_type:
            ttk.Label(
                details_frame,
                text=f"💡 Recommended: {self._suggested_type}",
                foreground=_theme_color("success"),
                font=("Helvetica", 10, "bold"),
            ).pack(anchor="w", pady=(10, 0))

        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Action Options", padding="10")
        options_frame.pack(fill=tk.X, expand=True, pady=(0, 15))

        self._choice_var = tk.StringVar(master=self, value="software")

        ttk.Radiobutton(
            options_frame,
            text="Render as image (software)",
            variable=self._choice_var,
            value="software",
        ).pack(anchor="w", pady=5)

        if self._suggested_type:
            ttk.Radiobutton(
                options_frame,
                text=f"Switch to {self._suggested_type} (hardware)",
                variable=self._choice_var,
                value="switch",
            ).pack(anchor="w", pady=5)

        ttk.Radiobutton(
            options_frame,
            text="Cancel insertion",
            variable=self._choice_var,
            value="cancel",
        ).pack(anchor="w", pady=5)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Button(btn_frame, text="Continue", command=self._on_continue).pack(
            side=tk.RIGHT, padx=(10, 0)
        )

        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)

    def _on_continue(self) -> None:
        """Обработчик кнопки Продолжить — подтверждает выбор пользователя."""
        choice = self._choice_var.get()
        if choice == "cancel":
            self._result = False
        else:
            self._result = True
            self._choice = choice
        self.close(self._result)

    def _on_cancel(self) -> None:
        """Обработчик кнопки Отмена — отменяет операцию."""
        self._result = False
        self.close(False)

    def show(self) -> tuple[bool, Optional[str]]:
        """Показывает диалог модально и возвращает результат.

        Returns:
            Кортеж (success, choice) где:
            - success: True если пользователь выбрал продолжить
            - choice: "software", "switch" или None
        """
        super().show()
        return self._result, self._choice
