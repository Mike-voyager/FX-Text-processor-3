"""Диалог настройки страницы.

Предоставляет единый диалог настройки страницы с тремя вкладками:
- Margins (Отступы): Top, Bottom, Left, Right в мм.
- Paper (Бумага): Orientation, Size presets.
- Layout (Макет): Line spacing, Skip perforation.

Security:
    - Строгая валидация числовых значений
    - Санитизация user input
    - Callback on_apply получает только валидированный PageSetupConfig

Example:
    >>> dialog = PageSetupDialog(
    ...     parent=root,
    ...     initial_config=PageSetupConfig(),
    ...     paper_format_service=service,
    ...     on_apply=lambda cfg: print(f"Applied: {cfg}"),
    ... )
    >>> dialog.show()

Version: 3.0
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, Final, List, Optional, Tuple

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.layout.layout_constants import PADDING_LARGE, PADDING_NORMAL, PADDING_SMALL
from src.gui.themes import ThemeRegistry
from src.services.paper_format_service import Orientation, PaperFormatService, PaperSize

logger = logging.getLogger(__name__)


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Цвет в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except (AttributeError, KeyError, RuntimeError):
        return "#333333"


# =============================================================================
# CONSTANTS
# =============================================================================

MIN_MARGIN_MM: Final[float] = 0.0
MAX_MARGIN_MM: Final[float] = 500.0

NUMBER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[\d]+\.?\d*$")

ORIENTATION_DISPLAY: Final[Dict[Orientation, str]] = {
    Orientation.PORTRAIT: "Книжная (Portrait)",
    Orientation.LANDSCAPE: "Альбомная (Landscape)",
}

PAPER_SIZE_DISPLAY: Final[Dict[PaperSize, str]] = {
    PaperSize.A4: "A4 (210×297 мм)",
    PaperSize.A3: "A3 (297×420 мм)",
    PaperSize.LETTER: "Letter (8.5×11 дюймов)",
    PaperSize.LEGAL: "Legal (8.5×14 дюймов)",
    PaperSize.TRACTOR_FULL: "Tractor Full (210×305 мм)",
    PaperSize.TRACTOR_HALF: "Tractor Half (210×152.5 мм)",
    PaperSize.TRACTOR_TRIPLET: "Tractor Triplet (210×101.6 мм)",
    PaperSize.ENVELOPE_DL: "Envelope DL (110×220 мм)",
    PaperSize.ENVELOPE_C5: "Envelope C5 (162×229 мм)",
}

LINE_SPACING_DISPLAY: Final[List[str]] = [
    '1/6" (6 LPI)',
    '1/8" (8 LPI)',
    '1/4" (4 LPI)',
]


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
# PageSetupConfig
# =============================================================================


class PageSetupConfig:
    """Конфигурация страницы для PageSetupDialog.

    Attributes:
        paper_size: Размер бумаги
        orientation: Ориентация страницы
        margins: Отступы (Top, Bottom, Left, Right)
        line_spacing_index: Индекс межстрочного интервала
        skip_perforation: Количество строк для пропуска перфорации
    """

    def __init__(
        self,
        paper_size: PaperSize = PaperSize.A4,
        orientation: Orientation = Orientation.PORTRAIT,
        top_margin_mm: float = 20.0,
        bottom_margin_mm: float = 20.0,
        left_margin_mm: float = 20.0,
        right_margin_mm: float = 20.0,
        line_spacing_index: int = 0,
        skip_perforation: int = 0,
    ) -> None:
        """Инициализирует конфигурацию страницы.

        Args:
            paper_size: Размер бумаги
            orientation: Ориентация страницы
            top_margin_mm: Верхний отступ в мм
            bottom_margin_mm: Нижний отступ в мм
            left_margin_mm: Левый отступ в мм
            right_margin_mm: Правый отступ в мм
            line_spacing_index: Индекс межстрочного интервала
            skip_perforation: Количество строк для пропуска перфорации
        """
        self.paper_size = paper_size
        self.orientation = orientation
        self.top_margin_mm = top_margin_mm
        self.bottom_margin_mm = bottom_margin_mm
        self.left_margin_mm = left_margin_mm
        self.right_margin_mm = right_margin_mm
        self.line_spacing_index = line_spacing_index
        self.skip_perforation = skip_perforation


# =============================================================================
# PageSetupDialog
# =============================================================================


class PageSetupDialog(BaseDialog):
    """Диалог настройки параметров страницы.

    Attributes:
        parent: Родительское окно.
        initial_config: Начальная конфигурация.
        paper_format_service: Сервис форматов бумаги.
        on_apply: Callback при нажатии Apply с PageSetupConfig.
        result: Результат диалога (PageSetupConfig или None).

    Example:
        >>> dialog = PageSetupDialog(
        ...     parent=root,
        ...     initial_config=PageSetupConfig(),
        ...     paper_format_service=service,
        ...     on_apply=lambda cfg: print(f"Applied: {cfg}"),
        ... )
        >>> config = dialog.show()
        >>> if config:
        ...     print(f"Applied: {config}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        initial_config: Optional[PageSetupConfig] = None,
        paper_format_service: Optional[PaperFormatService] = None,
        on_apply: Optional[Callable[[PageSetupConfig], None]] = None,
        title: str = "Настройка страницы",
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительское окно.
            initial_config: Начальная конфигурация страницы.
            paper_format_service: Сервис форматов бумаги.
            on_apply: Callback при применении настроек.
            title: Заголовок диалога.
        """
        super().__init__(parent, title=title, modal=True)

        self._initial_config = initial_config or PageSetupConfig()
        self._paper_format_service = paper_format_service or PaperFormatService()
        self._apply_callback: Optional[Callable[[PageSetupConfig], None]] = on_apply
        self._result: Optional[PageSetupConfig] = None

        self._current_config = PageSetupConfig(
            paper_size=self._initial_config.paper_size,
            orientation=self._initial_config.orientation,
            top_margin_mm=self._initial_config.top_margin_mm,
            bottom_margin_mm=self._initial_config.bottom_margin_mm,
            left_margin_mm=self._initial_config.left_margin_mm,
            right_margin_mm=self._initial_config.right_margin_mm,
            line_spacing_index=self._initial_config.line_spacing_index,
            skip_perforation=self._initial_config.skip_perforation,
        )

        self._vars: Dict[str, tk.StringVar] = {}
        self._error_labels: Dict[str, tk.Label] = {}
        self._notebook: ttk.Notebook
        self._preview_canvas: tk.Canvas

        self._create_ui()

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        main_frame = tk.Frame(self, padx=PADDING_LARGE, pady=PADDING_LARGE)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._notebook = ttk.Notebook(main_frame)
        self._notebook.pack(fill=tk.BOTH, expand=True, pady=(0, PADDING_NORMAL))

        self._create_margins_tab()
        self._create_paper_tab()
        self._create_layout_tab()

        self._create_preview_canvas(main_frame)
        self._create_buttons(main_frame)

    def _create_margins_tab(self) -> None:
        """Создаёт вкладку 'Отступы' (Margins)."""
        tab = tk.Frame(self._notebook, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        self._notebook.add(tab, text="Отступы")

        self._create_validated_entry(
            tab,
            row=0,
            label="Верхнее поле (мм):",
            var_name="top_margin",
            default=str(self._current_config.top_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        self._create_validated_entry(
            tab,
            row=1,
            label="Нижнее поле (мм):",
            var_name="bottom_margin",
            default=str(self._current_config.bottom_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        self._create_validated_entry(
            tab,
            row=2,
            label="Левое поле (мм):",
            var_name="left_margin",
            default=str(self._current_config.left_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        self._create_validated_entry(
            tab,
            row=3,
            label="Правое поле (мм):",
            var_name="right_margin",
            default=str(self._current_config.right_margin_mm),
            validator=lambda v: validate_positive_float(v, MIN_MARGIN_MM, MAX_MARGIN_MM),
        )

        preset_frame = tk.Frame(tab)
        preset_frame.grid(row=4, column=0, columnspan=3, pady=PADDING_LARGE)

        tk.Label(preset_frame, text="Пресеты:").pack(side=tk.LEFT, padx=(0, PADDING_NORMAL))

        presets = [
            ("Минимум", "2", "2", "2", "2"),
            ("Стандарт", "20", "20", "20", "20"),
            ("Широкие", "30", "30", "30", "30"),
        ]

        def make_preset_handler(
            top_val: str, bottom_val: str, left_val: str, right_val: str
        ) -> Callable[[], None]:
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
        self._notebook.add(tab, text="Бумага")

        self._create_labeled_dropdown(
            tab,
            row=0,
            label="Размер бумаги:",
            var_name="paper_size",
            options=list(PAPER_SIZE_DISPLAY.values()),
            default=PAPER_SIZE_DISPLAY.get(
                self._current_config.paper_size, PAPER_SIZE_DISPLAY[PaperSize.A4]
            ),
        )

        self._create_labeled_dropdown(
            tab,
            row=1,
            label="Ориентация:",
            var_name="orientation",
            options=list(ORIENTATION_DISPLAY.values()),
            default=ORIENTATION_DISPLAY.get(
                self._current_config.orientation, ORIENTATION_DISPLAY[Orientation.PORTRAIT]
            ),
        )

    def _create_layout_tab(self) -> None:
        """Создаёт вкладку 'Макет' (Layout)."""
        tab = tk.Frame(self._notebook, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        self._notebook.add(tab, text="Макет")

        self._create_labeled_dropdown(
            tab,
            row=0,
            label="Межстрочный интервал:",
            var_name="line_spacing",
            options=LINE_SPACING_DISPLAY,
            default=LINE_SPACING_DISPLAY[self._current_config.line_spacing_index]
            if self._current_config.line_spacing_index < len(LINE_SPACING_DISPLAY)
            else LINE_SPACING_DISPLAY[0],
        )

        self._create_validated_entry(
            tab,
            row=1,
            label="Пропуск перфорации (строк):",
            var_name="skip_perforation",
            default=str(self._current_config.skip_perforation),
            validator=self._validate_skip_perforation,
        )

    def _validate_skip_perforation(self, value: str) -> Optional[int]:
        """Валидирует значение пропуска перфорации.

        Args:
            value: Входная строка.

        Returns:
            Целочисленное значение или None если недопустимо.
        """
        if not value or not value.strip():
            return 0

        try:
            val = int(value.strip())
            if val < 0 or val > 100:
                return None
            return val
        except ValueError:
            return None

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

        error_lbl = tk.Label(parent, text="", fg=_theme_color("error"), font=("Arial", 8))
        error_lbl.grid(row=row, column=2, sticky=tk.W, pady=PADDING_SMALL)
        self._error_labels[var_name] = error_lbl
        return entry

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки OK, Cancel, Apply.

        Args:
            parent: Родительский виджет.
        """
        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(PADDING_NORMAL, 0))

        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        ok_btn = tk.Button(btn_frame, text="OK", width=10, command=self._on_ok)
        ok_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        cancel_btn = tk.Button(btn_frame, text="Отмена", width=10, command=self._on_cancel)
        cancel_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        apply_btn = tk.Button(btn_frame, text="Применить", width=10, command=self._on_apply_clicked)
        apply_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

    def _create_preview_canvas(self, parent: tk.Widget) -> None:
        """Создаёт Canvas для визуального preview параметров страницы.

        Args:
            parent: Родительский виджет.
        """
        frame = tk.LabelFrame(parent, text="Превью", padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        self._preview_canvas = tk.Canvas(
            bg=_theme_color("paper_preview_bg"), highlightthickness=0, width=440, height=180
        )
        self._preview_canvas.pack()

        self._update_preview()

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

        for label in self._error_labels.values():
            label.config(text="")

        self._update_preview()

    def _update_preview(self) -> None:
        """Перерисовывает preview canvas с учётом текущих значений."""
        if not hasattr(self, "_preview_canvas"):
            return
        self._preview_canvas.delete("all")

        width_mm = self._current_config.paper_size.width_mm
        height_mm = self._current_config.paper_size.height_mm

        orientation_display = self._vars.get("orientation", tk.StringVar()).get()
        if "Альбомная" in orientation_display or "Landscape" in orientation_display:
            width_mm, height_mm = height_mm, width_mm

        canvas_w = 440
        canvas_h = 180
        pad_x = 20
        pad_y = 20

        scale_w = (canvas_w - 2 * pad_x) / width_mm if width_mm > 0 else 1
        scale_h = (canvas_h - 2 * pad_y) / height_mm if height_mm > 0 else 1
        scale = min(scale_w, scale_h)
        scale = max(scale, 1.0)

        rect_w = width_mm * scale
        rect_h = height_mm * scale

        cx = (canvas_w - rect_w) / 2
        cy = (canvas_h - rect_h) / 2

        top_val = self._vars.get("top_margin", tk.StringVar()).get()
        bottom_val = self._vars.get("bottom_margin", tk.StringVar()).get()
        left_val = self._vars.get("left_margin", tk.StringVar()).get()
        right_val = self._vars.get("right_margin", tk.StringVar()).get()

        top_m = (
            validate_positive_float(top_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0
        ) * scale
        bottom_m = (
            validate_positive_float(bottom_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0
        ) * scale
        left_m = (
            validate_positive_float(left_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0
        ) * scale
        right_m = (
            validate_positive_float(right_val, MIN_MARGIN_MM, MAX_MARGIN_MM) or 0.0
        ) * scale

        self._preview_canvas.create_rectangle(
            cx, cy, cx + rect_w, cy + rect_h, outline=_theme_color("tab_border"), width=2
        )

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

    def _build_config(self) -> PageSetupConfig:
        """Собирает PageSetupConfig из значений формы.

        Returns:
            Сконфигурированный PageSetupConfig.
        """
        paper_size_display = self._vars.get("paper_size", tk.StringVar()).get()
        paper_size = next(
            (ps for ps, display in PAPER_SIZE_DISPLAY.items() if display == paper_size_display),
            PaperSize.A4,
        )

        orientation_display = self._vars.get("orientation", tk.StringVar()).get()
        orientation = (
            Orientation.LANDSCAPE
            if "Альбомная" in orientation_display or "Landscape" in orientation_display
            else Orientation.PORTRAIT
        )

        def get_float(var_name: str, default: float) -> float:
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

        line_spacing_display = self._vars.get("line_spacing", tk.StringVar()).get()
        try:
            line_spacing_index = LINE_SPACING_DISPLAY.index(line_spacing_display)
        except ValueError:
            line_spacing_index = 0

        skip_val = self._vars.get("skip_perforation", tk.StringVar()).get()
        skip_perforation = self._validate_skip_perforation(skip_val) or 0

        return PageSetupConfig(
            paper_size=paper_size,
            orientation=orientation,
            top_margin_mm=top_margin,
            bottom_margin_mm=bottom_margin,
            left_margin_mm=left_margin,
            right_margin_mm=right_margin,
            line_spacing_index=line_spacing_index,
            skip_perforation=skip_perforation,
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
            except Exception as exc:
                logger.error("Ошибка в callback on_apply: %s", exc)

        self.close(result=self._result)

    def _on_cancel(self) -> None:
        """Обрабатывает нажатие кнопки Cancel."""
        self.close(result=None)

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
            except Exception as exc:
                logger.error("Ошибка в callback on_apply: %s", exc)

    def _validate_all(self) -> Tuple[bool, List[str]]:
        """Валидирует все поля формы.

        Returns:
            Кортеж (успех, список_ошибок).
        """
        errors: List[str] = []
        is_valid = True

        margin_fields = [
            ("top_margin", "Верхнее поле"),
            ("bottom_margin", "Нижнее поле"),
            ("left_margin", "Левое поле"),
            ("right_margin", "Правое поле"),
        ]

        for var_name, label in margin_fields:
            if var_name in self._vars:
                value = self._vars[var_name].get()
                result = validate_positive_float(value, MIN_MARGIN_MM, MAX_MARGIN_MM)
                if result is None:
                    self._error_labels[var_name].config(text="Недопустимое значение")
                    errors.append(f"{label}: недопустимое значение")
                    is_valid = False
                else:
                    self._error_labels[var_name].config(text="")

        return is_valid, errors


__all__ = ["PageSetupDialog", "PageSetupConfig", "validate_positive_float", "sanitize_string"]
