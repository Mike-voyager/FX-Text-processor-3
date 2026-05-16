"""Диалог настройки параметров бумаги.

Предоставляет единый диалог настройки страницы с тремя вкладками:
- Margins (Отступы): Top, Bottom, Left, Right в мм. Валидация: 0–500 мм.
- Paper (Бумага): Размер, источник, перфорация, тип бумаги.
- Layout (Макет): Ориентация, межстрочный интервал, skip perforation.

Security:
    - Строгая валидация числовых значений (no negative, no overflow)
    - Санитизация user input
    - Callback on_apply получает только валидированный PaperConfig

Example:
    >>> dialog = PaperSetupDialog(
    ...     parent=root,
    ...     initial_config=PaperConfig(paper_size=PaperSize.A4),
    ...     on_apply=lambda cfg: print(f"Applied: {cfg}"),
    ... )
    >>> dialog.show()

Version: 2.0
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, Final, List, Optional, Tuple, cast

from src.gui.components.paper_toolbar import PaperConfig
from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.layout.layout_constants import PADDING_LARGE, PADDING_NORMAL, PADDING_SMALL
from src.gui.themes import ThemeRegistry
from src.services.paper_format_service import Orientation, PaperSize

logger = logging.getLogger(__name__)


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Color в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except (AttributeError, KeyError):
        return "#333333"


# =============================================================================
# CONSTANTS
# =============================================================================

# Минимальные и максимальные значения для валидации
MIN_DIMENSION_MM: Final[float] = 1.0
MAX_DIMENSION_MM: Final[float] = 2000.0
MIN_MARGIN_MM: Final[float] = 0.0
MAX_MARGIN_MM: Final[float] = 500.0
MIN_CPI: Final[int] = 10
MAX_CPI: Final[int] = 20

# Regex для валидации числовых значений
NUMBER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[\d]+\.?\d*$")

# Отображаемые названия ориентаций
ORIENTATION_DISPLAY: Final[Dict[Orientation, str]] = {
    Orientation.PORTRAIT: "Portrait",
    Orientation.LANDSCAPE: "Landscape",
}

# Отображаемые названия типов источников бумаги
PAPER_SOURCE_DISPLAY: Final[Dict[str, str]] = {
    "tractor": "Tractor feed",
    "manual": "Manual feed",
    "auto": "Auto select",
}

# Отображаемые названия типов бумажных форм
PAPER_FORM_DISPLAY: Final[Dict[str, str]] = {
    "custom": "Custom",
    "tractor_full": "Tractor Full 210×305",
    "tractor_half": "Tractor Half 210×152.5",
    "tractor_triplet": "Tractor Triplet 210×101.6",
    "envelope_dl": "Envelope DL",
    "envelope_c5": "Envelope C5",
}

# =============================================================================
# Validation
# =============================================================================


def validate_positive_float(value: str, min_val: float, max_val: float) -> Optional[float]:
    """Валидирует положительное число с плавающей точкой.

    Args:
        value: Входная строка.
        min_val: Минимальное допустимое значение.
        max_val: Максимальное допустимое значение.

    Returns:
        Числовое значение или None если недопустимо.
    """
    if not value or not value.strip():
        return None

    if not NUMBER_PATTERN.match(value.strip()):
        return None

    try:
        num = float(value.strip())
        if num < min_val or num > max_val:
            return None
        return num
    except ValueError:
        return None


def validate_cpi(value: str) -> Optional[int]:
    """Валидирует значение CPI.

    Args:
        value: Входная строка.

    Returns:
        Целочисленное значение CPI или None если недопустимо.
    """
    if not value or not value.strip():
        return None

    try:
        cpi = int(value.strip())
        if cpi < MIN_CPI or cpi > MAX_CPI:
            return None
        return cpi
    except ValueError:
        return None


def sanitize_string(value: str, max_length: int = 100) -> str:
    """Санитизирует строковое значение.

    Args:
        value: Входная строка.
        max_length: Максимальная длина.

    Returns:
        Очищенная строка.
    """
    sanitized = re.sub(r"[<>&\"']", "", value)
    return sanitized[:max_length]


# =============================================================================
# PaperSetupDialog
# =============================================================================


class PaperSetupDialog(BaseDialog):
    """Диалог настройки параметров бумаги.

    Attributes:
        parent: Родительское окно.
        initial_config: Начальная конфигурация.
        on_apply: Callback при нажатии Apply с валидированным PaperConfig.
        result: Результат диалога (PaperConfig или None).

    Example:
        >>> dialog = PaperSetupDialog(
        ...     parent=root,
        ...     initial_config=PaperConfig(),
        ...     on_apply=lambda cfg: print(f"Config: {cfg}"),
        ... )
        >>> config = dialog.show()
        >>> if config:
        ...     print(f"Applied: {config}")
    """

    def __init__(
        self,
        parent: tk.Tk | tk.Widget,
        initial_config: Optional[PaperConfig] = None,
        on_apply: Optional[Callable[[PaperConfig], None]] = None,
        title: str = "Page Setup",
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительское окно.
            initial_config: Начальная конфигурация бумаги.
            on_apply: Callback при применении настроек.
            title: Заголовок диалога.
        """
        super().__init__(parent)
        self.title(title)
        self.transient(cast(tk.Wm, parent))

        self._initial_config = initial_config or PaperConfig()
        self._apply_callback: Optional[Callable[[PaperConfig], None]] = on_apply
        self._result: Optional[PaperConfig] = None

        # Текущие значения (могут быть изменены пользователем)
        self._current_config = PaperConfig(
            paper_size=self._initial_config.paper_size,
            cpi=self._initial_config.cpi,
            line_spacing=self._initial_config.line_spacing,
            paper_source=self._initial_config.paper_source,
            width_mm=self._initial_config.width_mm,
            height_mm=self._initial_config.height_mm,
            top_margin_mm=self._initial_config.top_margin_mm,
            bottom_margin_mm=self._initial_config.bottom_margin_mm,
            left_margin_mm=self._initial_config.left_margin_mm,
            right_margin_mm=self._initial_config.right_margin_mm,
            orientation=self._initial_config.orientation,
            skip_perforation=self._initial_config.skip_perforation,
            perforation_enabled=self._initial_config.perforation_enabled,
            perforation_margin_mm=self._initial_config.perforation_margin_mm,
            paper_form_type=self._initial_config.paper_form_type,
        )

        # Настройка окна
        self.resizable(False, False)

        # Переменные для форм
        self._vars: Dict[str, tk.StringVar] = {}
        self._error_labels: Dict[str, tk.Label] = {}
        self._notebook: ttk.Notebook
        self._preview_canvas: tk.Canvas

        # Создаём UI
        self._create_ui()
        if self._notebook is None:
            raise AssertionError("_notebook is not set")

        # Центрируем окно

        # Обработка закрытия окна

        # Обработка закрытия окна

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        width = 500
        height = 480

        parent = self.master
        if isinstance(parent, (tk.Tk, tk.Toplevel)):
            parent_x = parent.winfo_x()
            parent_y = parent.winfo_y()
            parent_width = parent.winfo_width()
            parent_height = parent.winfo_height()
        else:
            parent_x = parent.winfo_rootx() if hasattr(parent, "winfo_rootx") else 0
            parent_y = parent.winfo_rooty() if hasattr(parent, "winfo_rooty") else 0
            parent_width = 800
            parent_height = 600

        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        main_frame = tk.Frame(self, padx=PADDING_LARGE, pady=PADDING_LARGE)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Notebook с вкладками
        self._notebook = ttk.Notebook(main_frame)
        self._notebook.pack(fill=tk.BOTH, expand=True, pady=(0, PADDING_NORMAL))

        # Создаём вкладки
        self._create_margins_tab()
        self._create_paper_tab()
        self._create_layout_tab()

        # Canvas preview
        self._create_preview_canvas(main_frame)

        # Кнопки
        self._create_buttons(main_frame)

        # Подписка на изменения для обновления preview
        self._bind_preview_updates()

    def _create_margins_tab(self) -> None:
        """Создаёт вкладку 'Отступы' (Margins)."""
        tab = tk.Frame(self._notebook, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        self._notebook.add(tab, text="Margins")

        # Top margin
        self._create_validated_entry(
            tab,
            row=0,
            label="Top margin (mm):",
            var_name="top_margin",
            default=str(self._current_config.top_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        # Bottom margin
        self._create_validated_entry(
            tab,
            row=1,
            label="Bottom margin (mm):",
            var_name="bottom_margin",
            default=str(self._current_config.bottom_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        # Left margin
        self._create_validated_entry(
            tab,
            row=2,
            label="Left margin (mm):",
            var_name="left_margin",
            default=str(self._current_config.left_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        # Right margin
        self._create_validated_entry(
            tab,
            row=3,
            label="Right margin (mm):",
            var_name="right_margin",
            default=str(self._current_config.right_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        # Perforation margin
        self._create_validated_entry(
            tab,
            row=4,
            label="Perforation from top (mm):",
            var_name="perforation_margin",
            default=str(self._current_config.perforation_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        # Preset buttons
        preset_frame = tk.Frame(tab)
        preset_frame.grid(row=5, column=0, columnspan=3, pady=PADDING_LARGE)

        tk.Label(preset_frame, text="Presets:").pack(side=tk.LEFT, padx=(0, PADDING_NORMAL))

        presets = [
            ("Minimum", "2", "2", "2", "2"),
            ("Standard", "10", "10", "10", "10"),
            ("Wide", "20", "20", "20", "20"),
        ]

        def make_preset_handler(
            top_val: str, bottom_val: str, left_val: str, right_val: str
        ) -> Callable[[], None]:
            """Создаёт handler для пресета полей."""

            def handler() -> None:
                self._apply_margin_preset(top_val, bottom_val, left_val, right_val)

            return handler

        for name, top, bottom, left, right in presets:
            btn = tk.Button(
                preset_frame,
                text=name,
                command=make_preset_handler(top, bottom, left, right),
            )
            btn.pack(side=tk.LEFT, padx=PADDING_SMALL)

    def _create_paper_tab(self) -> None:
        """Создаёт вкладку 'Бумага' (Paper)."""
        tab = tk.Frame(self._notebook, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        self._notebook.add(tab, text="Paper")

        # Paper size
        self._create_labeled_dropdown(
            tab,
            row=0,
            label="Paper size:",
            var_name="paper_size",
            options=list(self._get_paper_size_options().keys()),
            default=self._paper_size_to_display(self._current_config.paper_size),
        )

        # Paper source
        self._create_labeled_dropdown(
            tab,
            row=1,
            label="Paper source:",
            var_name="paper_source",
            options=list(PAPER_SOURCE_DISPLAY.values()),
            default=PAPER_SOURCE_DISPLAY.get(self._current_config.paper_source, "Auto select"),
        )

        # Paper form type
        self._create_labeled_dropdown(
            tab,
            row=2,
            label="Paper type:",
            var_name="paper_form_type",
            options=list(PAPER_FORM_DISPLAY.values()),
            default=PAPER_FORM_DISPLAY.get(self._current_config.paper_form_type, "Custom"),
        )

        # Perforation enabled
        self._perforation_var = tk.BooleanVar(
            master=self, value=self._current_config.perforation_enabled
        )
        perf_frame = tk.Frame(tab)
        perf_frame.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=PADDING_SMALL)
        perf_check = tk.Checkbutton(
            perf_frame,
            text="Enable perforation",
            variable=self._perforation_var,
        )
        perf_check.pack(side=tk.LEFT)

        # Custom dimensions (только для CUSTOM)
        self._create_dimension_fields(tab, start_row=4)

    def _create_layout_tab(self) -> None:
        """Создаёт вкладку 'Макет' (Layout)."""
        tab = tk.Frame(self._notebook, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        self._notebook.add(tab, text="Layout")

        # Orientation
        self._create_labeled_dropdown(
            tab,
            row=0,
            label="Orientation:",
            var_name="orientation",
            options=[
                ORIENTATION_DISPLAY[Orientation.PORTRAIT],
                ORIENTATION_DISPLAY[Orientation.LANDSCAPE],
            ],
            default=ORIENTATION_DISPLAY.get(
                self._current_config.orientation, ORIENTATION_DISPLAY[Orientation.PORTRAIT]
            ),
        )

        # Line spacing
        self._create_labeled_dropdown(
            tab,
            row=1,
            label="Line spacing:",
            var_name="line_spacing",
            options=['1/6" (6 LPI)', '1/8" (8 LPI)', "Custom"],
            default=self._line_spacing_to_display(self._current_config.line_spacing),
        )

        # CPI
        self._create_labeled_dropdown(
            tab,
            row=2,
            label="CPI (characters per inch):",
            var_name="cpi",
            options=["10 (Pica)", "12 (Elite)", "15 (Condensed)", "17 (Compressed)", "20 (Ultra)"],
            default=self._cpi_to_display(self._current_config.cpi),
        )

        # Skip perforation
        self._skip_var = tk.BooleanVar(master=self, value=self._current_config.skip_perforation)
        skip_frame = tk.Frame(tab)
        skip_frame.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=PADDING_SMALL)
        skip_check = tk.Checkbutton(
            skip_frame,
            text="Skip perforation lines",
            variable=self._skip_var,
        )
        skip_check.pack(side=tk.LEFT)

    def _create_dimension_fields(self, parent: tk.Widget, start_row: int) -> None:
        """Создаёт поля для ввода размеров (для custom)."""
        self._create_validated_entry(
            parent,
            row=start_row,
            label="Width (mm):",
            var_name="custom_width",
            default=str(self._current_config.width_mm),
            validator=lambda v: validate_positive_float(v, MIN_DIMENSION_MM, MAX_DIMENSION_MM),
        )

        self._create_validated_entry(
            parent,
            row=start_row + 1,
            label="Height (mm):",
            var_name="custom_height",
            default=str(self._current_config.height_mm),
            validator=lambda v: validate_positive_float(v, MIN_DIMENSION_MM, MAX_DIMENSION_MM),
        )

    def _create_labeled_dropdown(
        self,
        parent: tk.Widget,
        row: int,
        label: str,
        var_name: str,
        options: List[str],
        default: str,
    ) -> ttk.Combobox:
        """Создаёт labeled dropdown.

        Args:
            parent: Родительский виджет.
            row: Номер строки в grid.
            label: Текст метки.
            var_name: Имя переменной.
            options: Список опций.
            default: Значение по умолчанию.

        Returns:
            Созданный Combobox виджет.
        """
        lbl = tk.Label(parent, text=label)
        lbl.grid(row=row, column=0, sticky=tk.W, pady=PADDING_SMALL)

        var = tk.StringVar(master=self, value=default)
        self._vars[var_name] = var

        combo = ttk.Combobox(
            parent,
            textvariable=var,
            values=options,
            state="readonly",
            width=30,
        )
        combo.grid(row=row, column=1, sticky=tk.W, pady=PADDING_SMALL, padx=(PADDING_NORMAL, 0))

        return combo

    def _create_validated_entry(
        self,
        parent: tk.Widget,
        row: int,
        label: str,
        var_name: str,
        default: str,
        validator: Callable[[str], Any],
    ) -> tk.Entry:
        """Создаёт labeled entry с валидацией.

        Args:
            parent: Родительский виджет.
            row: Номер строки в grid.
            label: Текст метки.
            var_name: Имя переменной.
            default: Значение по умолчанию.
            validator: Функция валидации.

        Returns:
            Созданный Entry виджет.
        """
        lbl = tk.Label(parent, text=label)
        lbl.grid(row=row, column=0, sticky=tk.W, pady=PADDING_SMALL)

        var = tk.StringVar(master=self, value=default)
        self._vars[var_name] = var

        entry = tk.Entry(parent, textvariable=var, width=15)
        entry.grid(row=row, column=1, sticky=tk.W, pady=PADDING_SMALL, padx=(PADDING_NORMAL, 0))

        # Error label
        error_lbl = tk.Label(parent, text="", fg=_theme_color("error"), font=("Arial", 8))
        error_lbl.grid(row=row, column=2, sticky=tk.W, pady=PADDING_SMALL)
        self._error_labels[var_name] = error_lbl
        return entry

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки OK, Cancel, Apply, Save as Preset.

        Args:
            parent: Родительский виджет.
        """
        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(PADDING_NORMAL, 0))

        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        ok_btn = tk.Button(btn_frame, text="OK", width=10, command=self._on_ok)
        ok_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        cancel_btn = tk.Button(btn_frame, text="Cancel", width=10, command=self._on_cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        save_preset_btn = tk.Button(
            btn_frame, text="Save as Preset", width=14, command=self._on_save_preset
        )
        save_preset_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        apply_btn = tk.Button(btn_frame, text="Apply", width=10, command=self._on_apply_clicked)
        apply_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

    def _create_preview_canvas(self, parent: tk.Widget) -> None:
        """Создаёт Canvas для визуального preview параметров бумаги.

        Args:
            parent: Родительский виджет.
        """
        frame = tk.LabelFrame(parent, text="Preview", padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        self._preview_canvas = tk.Canvas(bg=_theme_color("paper_preview_bg"), highlightthickness=0)
        self._preview_canvas.pack()

        self._update_preview()

    def _bind_preview_updates(self) -> None:
        """Подписывает переменные формы на обновление preview."""
        for var in self._vars.values():
            var.trace_add("write", lambda *_: self._update_preview())

    def _update_preview(self) -> None:
        """Перерисовывает preview canvas с учётом текущих значений."""
        if not hasattr(self, "_preview_canvas"):
            return
        try:
            self._preview_canvas.delete("all")
        except tk.TclError:
            return

        # Получаем размеры
        paper_size_display = self._vars.get("paper_size", tk.StringVar(master=self)).get()
        size_options = self._get_paper_size_options()
        paper_size = size_options.get(paper_size_display, PaperSize.A4)

        if paper_size == PaperSize.CUSTOM:
            width_val = self._vars.get("custom_width", tk.StringVar(master=self)).get()
            height_val = self._vars.get("custom_height", tk.StringVar(master=self)).get()
            width_mm = (
                validate_positive_float(width_val, MIN_DIMENSION_MM, MAX_DIMENSION_MM) or 210.0
            )
            height_mm = (
                validate_positive_float(height_val, MIN_DIMENSION_MM, MAX_DIMENSION_MM) or 297.0
            )
        else:
            width_mm = paper_size.width_mm
            height_mm = paper_size.height_mm

        # Ориентация
        orientation_display = self._vars.get("orientation", tk.StringVar(master=self)).get()
        if orientation_display == ORIENTATION_DISPLAY[Orientation.LANDSCAPE]:
            width_mm, height_mm = height_mm, width_mm

        # Масштаб: адаптивно вписываем в 440×180 с отступами 20px
        canvas_w = 440
        canvas_h = 180
        pad_x = 20
        pad_y = 20

        scale_w = (canvas_w - 2 * pad_x) / width_mm
        scale_h = (canvas_h - 2 * pad_y) / height_mm
        scale = min(scale_w, scale_h)
        scale = max(scale, 1.0)
        max_scale = min(
            (canvas_w - 2 * pad_x) / max(width_mm, 1.0),
            (canvas_h - 2 * pad_y) / max(height_mm, 1.0),
        )
        if max_scale > 0:
            scale = min(scale, max_scale)

        rect_w = width_mm * scale
        rect_h = height_mm * scale
        cx = (480 - rect_w) / 2
        cy = (220 - rect_h) / 2

        # Поля
        top_val = self._vars.get("top_margin", tk.StringVar(master=self)).get()
        bottom_val = self._vars.get("bottom_margin", tk.StringVar(master=self)).get()
        left_val = self._vars.get("left_margin", tk.StringVar(master=self)).get()
        right_val = self._vars.get("right_margin", tk.StringVar(master=self)).get()
        top_m = (validate_positive_float(top_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0) * scale
        bottom_m = (
            validate_positive_float(bottom_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0
        ) * scale
        left_m = (validate_positive_float(left_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0) * scale
        right_m = (validate_positive_float(right_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0) * scale

        # Перфорация
        perf_val = self._vars.get("perforation_margin", tk.StringVar(master=self)).get()
        perf_mm = validate_positive_float(perf_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0
        perf_y = perf_mm * scale

        # Рисуем прямоугольник страницы
        self._preview_canvas.create_rectangle(
            cx, cy, cx + rect_w, cy + rect_h, outline=_theme_color("tab_border"), width=2
        )

        # Поля — серые области
        if top_m > 0:
            self._preview_canvas.create_rectangle(
                cx, cy, cx + rect_w, cy + top_m, fill=_theme_color("margin_color"), outline=""
            )
        if bottom_m > 0:
            self._preview_canvas.create_rectangle(
                cx,
                cy + rect_h - bottom_m,
                cx + rect_w,
                cy + rect_h,
                fill=_theme_color("margin_color"),
                outline="",
            )
        if left_m > 0:
            self._preview_canvas.create_rectangle(
                cx,
                cy + top_m,
                cx + left_m,
                cy + rect_h - bottom_m,
                fill=_theme_color("margin_color"),
                outline="",
            )
        if right_m > 0:
            self._preview_canvas.create_rectangle(
                cx + rect_w - right_m,
                cy + top_m,
                cx + rect_w,
                cy + rect_h - bottom_m,
                fill=_theme_color("margin_color"),
                outline="",
            )

        # Перфорация — пунктирная линия
        if perf_y > 0 and perf_y < rect_h:
            dash_len = 6
            gap_len = 4
            y_line = cy + perf_y
            x_start = cx
            x_end = cx + rect_w
            while x_start < x_end:
                seg_end = min(x_start + dash_len, x_end)
                self._preview_canvas.create_line(
                    x_start,
                    y_line,
                    seg_end,
                    y_line,
                    fill=_theme_color("perforation_color"),
                    width=1,
                )
                x_start += dash_len + gap_len

        # Подписи
        self._preview_canvas.create_text(
            480 // 2,
            10,
            text=f"{paper_size.name}  {width_mm:.1f}×{height_mm:.1f} mm  (scale {scale:.1f}x)",
            fill=_theme_color("text_secondary"),
            font=("Arial", 9),
        )

    def _apply_margin_preset(self, top: str, bottom: str, left: str, right: str) -> None:
        """Применяет пресет полей.

        Args:
            top: Верхнее поле.
            bottom: Нижнее поле.
            left: Левое поле.
            right: Правое поле.
        """
        if "top_margin" in self._vars:
            self._vars["top_margin"].set(top)
        if "bottom_margin" in self._vars:
            self._vars["bottom_margin"].set(bottom)
        if "left_margin" in self._vars:
            self._vars["left_margin"].set(left)
        if "right_margin" in self._vars:
            self._vars["right_margin"].set(right)

        # Очищаем сообщения об ошибках
        for label in self._error_labels.values():
            label.config(text="")

    def _get_paper_size_options(self) -> Dict[str, PaperSize]:
        """Возвращает отображаемые названия размеров бумаги.

        Returns:
            Словарь отображаемое_название -> PaperSize.
        """
        return {
            "A4 (210×297 мм)": PaperSize.A4,
            "A5 (148×210 мм)": PaperSize.A5,
            'Letter (8.5×11")': PaperSize.LETTER,
            'Legal (8.5×14")': PaperSize.LEGAL,
            "A3 (297×420 мм)": PaperSize.A3,
            "Tractor Full (210×305 мм)": PaperSize.TRACTOR_FULL,
            "Tractor Half (210×152.5 мм)": PaperSize.TRACTOR_HALF,
            "Tractor Triplet (210×101.6 мм)": PaperSize.TRACTOR_TRIPLET,
            "Envelope DL (110×220 мм)": PaperSize.ENVELOPE_DL,
            "Envelope C5 (162×229 мм)": PaperSize.ENVELOPE_C5,
            "Custom": PaperSize.CUSTOM,
        }

    def _paper_size_to_display(self, size: PaperSize) -> str:
        """Конвертирует PaperSize в отображаемое название.

        Args:
            size: Размер бумаги.

        Returns:
            Отображаемое название.
        """
        mapping = {
            PaperSize.A4: "A4 (210×297 мм)",
            PaperSize.A5: "A5 (148×210 мм)",
            PaperSize.LETTER: 'Letter (8.5×11")',
            PaperSize.LEGAL: 'Legal (8.5×14")',
            PaperSize.A3: "A3 (297×420 мм)",
            PaperSize.TRACTOR_FULL: "Tractor Full (210×305 мм)",
            PaperSize.TRACTOR_HALF: "Tractor Half (210×152.5 мм)",
            PaperSize.TRACTOR_TRIPLET: "Tractor Triplet (210×101.6 мм)",
            PaperSize.ENVELOPE_DL: "Envelope DL (110×220 мм)",
            PaperSize.ENVELOPE_C5: "Envelope C5 (162×229 мм)",
            PaperSize.CUSTOM: "Custom",
        }
        return mapping.get(size, "A4 (210×297 мм)")

    def _extract_paper_source_from_display(self, display: str) -> str:
        """Извлекает ключ источника бумаги из отображаемого названия.

        Args:
            display: Отображаемое название.

        Returns:
            Ключ источника.
        """
        for key, val in PAPER_SOURCE_DISPLAY.items():
            if val == display:
                return key
        if "tractor" in display.lower():
            return "tractor"
        elif "manual" in display.lower():
            return "manual"
        return "auto"

    def _extract_paper_form_type_from_display(self, display: str) -> str:
        """Извлекает ключ типа бумажной формы из отображаемого названия.

        Args:
            display: Отображаемое название.

        Returns:
            Ключ типа формы.
        """
        for key, val in PAPER_FORM_DISPLAY.items():
            if val == display:
                return key
        return "custom"

    def _extract_orientation_from_display(self, display: str) -> Orientation:
        """Извлекает ориентацию из отображаемого названия.

        Args:
            display: Отображаемое название.

        Returns:
            Ориентация.
        """
        if "Альбомная" in display or "Landscape" in display:
            return Orientation.LANDSCAPE
        return Orientation.PORTRAIT

    def _cpi_to_display(self, cpi: int) -> str:
        """Конвертирует CPI в отображаемое название.

        Args:
            cpi: Значение CPI.

        Returns:
            Отображаемое название.
        """
        mapping = {
            10: "10 (Pica)",
            12: "12 (Elite)",
            15: "15 (Condensed)",
            17: "17 (Compressed)",
            20: "20 (Ultra)",
        }
        return mapping.get(cpi, "10 (Pica)")

    def _line_spacing_to_display(self, spacing: str) -> str:
        """Конвертирует межстрочный интервал в отображаемое название.

        Args:
            spacing: Ключ интервала.

        Returns:
            Отображаемое название.
        """
        mapping = {
            "1/6": '1/6" (6 LPI)',
            "1/8": '1/8" (8 LPI)',
            "custom": "Custom",
        }
        return mapping.get(spacing, '1/6" (6 LPI)')

    def _extract_cpi_from_display(self, display: str) -> int:
        """Извлекает CPI из отображаемого названия.

        Args:
            display: Отображаемое название.

        Returns:
            Числовое значение CPI.
        """
        match = re.match(r"(\d+)", display)
        if match:
            cpi = int(match.group(1))
            if MIN_CPI <= cpi <= MAX_CPI:
                return cpi
        return 10  # default

    def _extract_line_spacing_from_display(self, display: str) -> str:
        """Извлекает ключ межстрочного интервала из отображаемого названия.

        Args:
            display: Отображаемое название.

        Returns:
            Ключ интервала.
        """
        if "1/6" in display or "6 LPI" in display:
            return "1/6"
        elif "1/8" in display or "8 LPI" in display:
            return "1/8"
        return "custom"

    def _validate_all(self) -> Tuple[bool, List[str]]:
        """Валидирует все поля формы.

        Returns:
            Кортеж (успех, список_ошибок).
        """
        errors: List[str] = []
        is_valid = True

        margin_fields = [
            ("top_margin", "Top margin"),
            ("bottom_margin", "Bottom margin"),
            ("left_margin", "Left margin"),
            ("right_margin", "Right margin"),
            ("perforation_margin", "Perforation"),
        ]

        for var_name, label in margin_fields:
            if var_name in self._vars:
                value = self._vars[var_name].get()
                result = validate_positive_float(value, MIN_MARGIN_MM, MAX_MARGIN_MM)
                if result is None:
                    self._error_labels[var_name].config(text="Invalid value")
                    errors.append(f"{label}: invalid value")
                    is_valid = False
                else:
                    self._error_labels[var_name].config(text="")

        # Custom dimensions (если выбран custom)
        paper_size_display = self._vars.get("paper_size", tk.StringVar(master=self)).get()
        if "Custom" in paper_size_display:
            for var_name, label in [("custom_width", "Width"), ("custom_height", "Height")]:
                if var_name in self._vars:
                    value = self._vars[var_name].get()
                    result = validate_positive_float(value, MIN_DIMENSION_MM, MAX_DIMENSION_MM)
                    if result is None:
                        errors.append(f"{label}: invalid value")
                        is_valid = False

        return is_valid, errors

    def _build_config(self) -> PaperConfig:
        """Собирает PaperConfig из значений формы.

        Returns:
            Сконфигурированный PaperConfig.
        """
        # Paper size
        paper_size_display = self._vars.get("paper_size", tk.StringVar(master=self)).get()
        size_options = self._get_paper_size_options()
        paper_size = size_options.get(paper_size_display, PaperSize.A4)

        # CPI
        cpi_display = self._vars.get("cpi", tk.StringVar(master=self)).get()
        cpi = self._extract_cpi_from_display(cpi_display)

        # Line spacing
        spacing_display = self._vars.get("line_spacing", tk.StringVar(master=self)).get()
        line_spacing = self._extract_line_spacing_from_display(spacing_display)

        # Paper source
        source_display = self._vars.get("paper_source", tk.StringVar(master=self)).get()
        paper_source = self._extract_paper_source_from_display(source_display)

        # Paper form type
        form_display = self._vars.get("paper_form_type", tk.StringVar(master=self)).get()
        paper_form_type = self._extract_paper_form_type_from_display(form_display)

        # Orientation
        orientation_display = self._vars.get("orientation", tk.StringVar(master=self)).get()
        orientation = self._extract_orientation_from_display(orientation_display)

        # Margins
        def get_float(var_name: str, default: float) -> float:
            """Извлекает float значение из переменной."""
            if var_name in self._vars:
                result = validate_positive_float(
                    self._vars[var_name].get(), MIN_MARGIN_MM, MAX_MARGIN_MM
                )
                return result if result is not None else default
            return default

        top_margin = get_float("top_margin", self._current_config.top_margin_mm)
        bottom_margin = get_float("bottom_margin", self._current_config.bottom_margin_mm)
        left_margin = get_float("left_margin", self._current_config.left_margin_mm)
        right_margin = get_float("right_margin", self._current_config.right_margin_mm)
        perforation_margin = get_float(
            "perforation_margin", self._current_config.perforation_margin_mm
        )

        # Dimensions (для custom)
        width_mm = self._current_config.width_mm
        height_mm = self._current_config.height_mm
        if paper_size == PaperSize.CUSTOM:
            width_val = self._vars.get("custom_width", tk.StringVar(master=self)).get()
            height_val = self._vars.get("custom_height", tk.StringVar(master=self)).get()
            width_result = validate_positive_float(width_val, MIN_DIMENSION_MM, MAX_DIMENSION_MM)
            height_result = validate_positive_float(height_val, MIN_DIMENSION_MM, MAX_DIMENSION_MM)
            width_mm = width_result if width_result is not None else width_mm
            height_mm = height_result if height_result is not None else height_mm
        else:
            width_mm = paper_size.width_mm
            height_mm = paper_size.height_mm

        # Checkbox values
        perforation_enabled = getattr(self, "_perforation_var", tk.BooleanVar(master=self)).get()
        skip_perforation = getattr(self, "_skip_var", tk.BooleanVar(master=self)).get()

        return PaperConfig(
            paper_size=paper_size,
            cpi=cpi,
            line_spacing=line_spacing,
            paper_source=paper_source,
            width_mm=width_mm,
            height_mm=height_mm,
            top_margin_mm=top_margin,
            bottom_margin_mm=bottom_margin,
            left_margin_mm=left_margin,
            right_margin_mm=right_margin,
            orientation=orientation,
            skip_perforation=skip_perforation,
            perforation_enabled=perforation_enabled,
            perforation_margin_mm=perforation_margin,
            paper_form_type=paper_form_type,
        )

    def _on_ok(self) -> None:
        """Обрабатывает нажатие кнопки OK."""
        is_valid, errors = self._validate_all()
        if not is_valid:
            logger.warning("Валидация не пройдена: %s", errors)
            return

        self._current_config = self._build_config()
        self._result = self._current_config

        if self._apply_callback is not None:
            try:
                self._apply_callback(self._current_config)
            except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
                logger.error("Ошибка в callback on_apply: %s", exc)

        self.destroy()

    def _on_cancel(self) -> None:
        """Обрабатывает нажатие кнопки Cancel."""
        self._result = None
        self.destroy()

    def _on_apply_clicked(self) -> None:
        """Обрабатывает нажатие кнопки Apply."""
        is_valid, errors = self._validate_all()
        if not is_valid:
            logger.warning("Валидация не пройдена: %s", errors)
            return

        self._current_config = self._build_config()

        if self._apply_callback is not None:
            try:
                self._apply_callback(self._current_config)
            except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
                logger.error("Ошибка в callback on_apply: %s", exc)

    def _on_save_preset(self) -> None:
        """Обрабатывает нажатие кнопки Save as Preset."""
        from tkinter import simpledialog

        name = simpledialog.askstring(
            "Save Preset",
            "Enter preset name:",
            parent=self,
        )
        if not name:
            return

        is_valid, errors = self._validate_all()
        if not is_valid:
            messagebox.showwarning(
                "Invalid Values",
                f"Cannot save preset: {errors[0] if errors else 'Invalid values'}",
                parent=self,
            )
            return

        self._current_config = self._build_config()
        logger.info(
            "Preset saved: %s (paper=%s, orientation=%s)",
            name,
            self._current_config.paper_size,
            self._current_config.orientation,
        )
        messagebox.showinfo(
            "Preset Saved",
            f"Preset '{name}' saved successfully.",
            parent=self,
        )

    def show(self) -> Optional[PaperConfig]:
        """Показывает диалог и ожидает закрытия.

        Returns:
            PaperConfig если нажат OK, None если Cancel.
        """
        super().show()
        return self._result

    def get_result(self) -> Optional[PaperConfig]:
        """Возвращает результат диалога.

        Returns:
            PaperConfig если нажат OK, None если Cancel или окно закрыто.
        """
        return self._result


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "PaperSetupDialog",
    "validate_positive_float",
    "validate_cpi",
    "sanitize_string",
    "MIN_DIMENSION_MM",
    "MAX_DIMENSION_MM",
    "MIN_MARGIN_MM",
    "MAX_MARGIN_MM",
    "MIN_CPI",
    "MAX_CPI",
]
