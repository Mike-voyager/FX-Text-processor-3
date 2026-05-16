"""Панель форматирования текста.

Модуль предоставляет FormatToolbar — композитный виджет для управления
форматированием текста: CPI (characters per inch) и атрибуты шрифта
(bold, italic, underline, strikethrough).

Использует toggle-кнопки с визуальной индикацией состояния (RAISED/SUNKEN).

Example:
    >>> toolbar = FormatToolbar(
    ...     widget_id="format_toolbar",
    ...     on_cpi_change=lambda cpi: print(f"CPI: {cpi}"),
    ...     on_format_toggle=lambda fmt, active: print(f"{fmt}: {active}"),
    ... )
    >>> toolbar.mount(parent_frame).pack(fill=tk.X)
    >>> toolbar.set_cpi(12)
    >>> toolbar.set_format_active("bold", True)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.layout.layout_constants import PADDING_NORMAL, TOOLBAR_HEIGHT
from src.model.enums import Alignment, CodePage, FontFamily, PrintQuality


class FormatToolbar(BaseWidget):
    """Панель форматирования текста с CPI и toggle-кнопками.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _cpi_var: IntVar для отслеживания выбранного CPI.
        _format_buttons: Словарь кнопок форматирования.
        _format_states: Словарь состояний toggle-кнопок.
        _on_cpi_change: Callback при изменении CPI.
        _on_format_toggle: Callback при изменении форматирования.

    Example:
        >>> toolbar = FormatToolbar(
        ...     widget_id="fmt_toolbar",
        ...     on_cpi_change=handle_cpi,
        ...     on_format_toggle=handle_format,
        ... )
        >>> frame = toolbar.mount(parent)
        >>> toolbar.set_cpi(12)
        >>> toolbar.set_format_active("bold", True)
        >>> assert toolbar.is_format_active("bold") is True
    """

    # Допустимые значения CPI для Epson FX-890
    CPI_VALUES: Final[tuple[str, ...]] = ("10", "12", "15", "17", "20")

    # Типы форматирования и их метки
    FORMAT_LABELS: Final[dict[str, str]] = {
        "bold": "B",
        "italic": "I",
        "underline": "U",
        "strikethrough": "S",
        "subscript": "x₂",
        "superscript": "x²",
    }

    # Quality labels
    QUALITY_LABELS: Final[dict[PrintQuality, str]] = {
        PrintQuality.DRAFT: "Draft",
        PrintQuality.NLQ: "NLQ",
        PrintQuality.USD: "USD",
        PrintQuality.HSD: "HSD",
    }

    # Font labels
    FONT_LABELS: Final[dict[FontFamily, str]] = {
        FontFamily.DRAFT: "Draft",
        FontFamily.ROMAN: "Roman",
        FontFamily.SANS_SERIF: "Sans Serif",
        FontFamily.USD: "USD",
        FontFamily.HSD: "HSD",
    }

    # CodePage labels (common subset)
    CODEPAGE_LABELS: Final[dict[CodePage, str]] = {
        CodePage.PC437: "PC437",
        CodePage.PC850: "PC850",
        CodePage.PC852: "PC852",
        CodePage.PC855: "PC855",
        CodePage.PC866: "PC866",
        CodePage.PC1250: "PC1250",
        CodePage.PC1251: "PC1251",
    }

    # Alignment labels
    ALIGNMENT_LABELS: Final[dict[Alignment, str]] = {
        Alignment.LEFT: "◀",
        Alignment.CENTER: "◆",
        Alignment.RIGHT: "▶",
        Alignment.JUSTIFY: "≡",
    }

    def __init__(
        self,
        widget_id: str = "format_toolbar",
        on_cpi_change: Optional[Callable[[int], None]] = None,
        on_format_toggle: Optional[Callable[[str, bool], None]] = None,
        on_barcode: Optional[Callable[[], None]] = None,
        on_qr: Optional[Callable[[], None]] = None,
        on_script_toggle: Optional[Callable[[str, bool], None]] = None,
        on_fix_validation: Optional[Callable[[], None]] = None,
        on_quality_change: Optional[Callable[[PrintQuality], None]] = None,
        on_font_change: Optional[Callable[[FontFamily], None]] = None,
        on_codepage_change: Optional[Callable[[CodePage], None]] = None,
        on_alignment_change: Optional[Callable[[Alignment], None]] = None,
    ) -> None:
        """Инициализация панели форматирования.

        Args:
            widget_id: Уникальный идентификатор виджета.
            on_cpi_change: Callback при изменении CPI (int -> None).
            on_format_toggle: Callback при переключении формата (str, bool -> None).
            on_barcode: Callback при нажатии на кнопку Barcode (None -> None).
            on_qr: Callback при нажатии на кнопку QR (None -> None).
            on_script_toggle: Callback при переключении subscript/superscript.
            on_fix_validation: Callback при нажатии на кнопку исправления.
            on_quality_change: Callback при изменении качества печати.
            on_font_change: Callback при изменении шрифта.
            on_codepage_change: Callback при изменении кодовой страницы.
            on_alignment_change: Callback при изменении выравнивания.

        Example:
            >>> toolbar = FormatToolbar(
            ...     widget_id="fmt_bar",
            ...     on_cpi_change=lambda c: print(f"CPI={c}"),
            ... )
        """
        super().__init__(widget_id=widget_id)

        self._on_cpi_change: Optional[Callable[[int], None]] = on_cpi_change
        self._on_format_toggle: Optional[Callable[[str, bool], None]] = on_format_toggle
        self._on_barcode: Optional[Callable[[], None]] = on_barcode
        self._on_qr: Optional[Callable[[], None]] = on_qr
        self._on_script_toggle: Optional[Callable[[str, bool], None]] = on_script_toggle
        self._on_fix_validation: Optional[Callable[[], None]] = on_fix_validation
        self._on_quality_change: Optional[Callable[[PrintQuality], None]] = on_quality_change
        self._on_font_change: Optional[Callable[[FontFamily], None]] = on_font_change
        self._on_codepage_change: Optional[Callable[[CodePage], None]] = on_codepage_change
        self._on_alignment_change: Optional[Callable[[Alignment], None]] = on_alignment_change

        # Переменная для CPI dropdown (StringVar для совместимости с Combobox)
        self._cpi_var: tk.StringVar = tk.StringVar(value=self.CPI_VALUES[0])

        # Словарь кнопок форматирования
        self._format_buttons: dict[str, tk.Button] = {}

        # Состояния toggle-кнопок (False = RAISED, True = SUNKEN)
        self._format_states: dict[str, bool] = {
            "bold": False,
            "italic": False,
            "underline": False,
            "strikethrough": False,
            "subscript": False,
            "superscript": False,
        }

        # Состояние валидации
        self._validation_count: int = 0
        self._fix_button: Optional[tk.Button] = None
        self._validation_badge: Optional[tk.Label] = None

        # Ссылка на dropdown для обновления
        self._cpi_dropdown: Optional[ttk.Combobox] = None

        # Новые dropdown'ы
        self._quality_var: tk.StringVar = tk.StringVar(
            value=self.QUALITY_LABELS[PrintQuality.DRAFT]
        )
        self._quality_dropdown: Optional[ttk.Combobox] = None

        self._font_var: tk.StringVar = tk.StringVar(value=self.FONT_LABELS[FontFamily.DRAFT])
        self._font_dropdown: Optional[ttk.Combobox] = None

        self._codepage_var: tk.StringVar = tk.StringVar(value=self.CODEPAGE_LABELS[CodePage.PC866])
        self._codepage_dropdown: Optional[ttk.Combobox] = None

        # Alignment buttons (mutually exclusive)
        self._alignment_buttons: dict[Alignment, tk.Button] = {}
        self._current_alignment: Alignment = Alignment.LEFT

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт панель форматирования.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame с элементами панели.
        """
        # Основной контейнер
        frame = tk.Frame(
            parent,
            height=TOOLBAR_HEIGHT,
            relief=tk.FLAT,
            borderwidth=0,
        )
        frame.pack_propagate(False)

        # === Группа CPI ===
        cpi_label = tk.Label(frame, text="CPI:", padx=PADDING_NORMAL)
        cpi_label.pack(side=tk.LEFT)

        self._cpi_dropdown = ttk.Combobox(
            frame,
            textvariable=self._cpi_var,
            values=self.CPI_VALUES,
            width=5,
            state="readonly",
        )
        self._cpi_dropdown.pack(side=tk.LEFT, padx=(0, PADDING_NORMAL))
        self._cpi_dropdown.bind("<<ComboboxSelected>>", self._on_cpi_selected)

        # Разделитель
        separator1 = tk.Frame(frame, width=1, bg="gray60")
        separator1.pack(side=tk.LEFT, fill=tk.Y, padx=PADDING_NORMAL, pady=4)

        # === Группа форматирования ===
        def make_toggle_handler(fmt: str) -> Callable[[], None]:
            return lambda: self._toggle_format(fmt)

        for fmt_type in ("bold", "italic", "underline", "strikethrough"):
            btn = tk.Button(
                frame,
                text=self.FORMAT_LABELS[fmt_type],
                width=3,
                relief=tk.RAISED,
                command=make_toggle_handler(fmt_type),
                font=("TkDefaultFont", 9, "bold"),
            )
            btn.pack(side=tk.LEFT, padx=(0, 2))
            self._format_buttons[fmt_type] = btn

        # === Группа subscript/superscript ===
        for script_type in ("subscript", "superscript"):
            btn = tk.Button(
                frame,
                text=self.FORMAT_LABELS[script_type],
                width=4,
                relief=tk.RAISED,
                command=make_toggle_handler(script_type),
                font=("TkDefaultFont", 9, "bold"),
            )
            btn.pack(side=tk.LEFT, padx=(0, 2))
            self._format_buttons[script_type] = btn

        # Разделитель перед Quality/Font/CodePage
        separator_qfc = tk.Frame(frame, width=1, bg="gray60")
        separator_qfc.pack(side=tk.LEFT, fill=tk.Y, padx=PADDING_NORMAL, pady=4)

        # === Группа Quality ===
        tk.Label(frame, text="Q:").pack(side=tk.LEFT)
        self._quality_dropdown = ttk.Combobox(
            frame,
            textvariable=self._quality_var,
            values=list(self.QUALITY_LABELS.values()),
            width=6,
            state="readonly",
        )
        self._quality_dropdown.pack(side=tk.LEFT, padx=(0, 2))
        self._quality_dropdown.bind("<<ComboboxSelected>>", self._on_quality_selected)

        # === Группа Font ===
        tk.Label(frame, text="F:").pack(side=tk.LEFT)
        self._font_dropdown = ttk.Combobox(
            frame,
            textvariable=self._font_var,
            values=list(self.FONT_LABELS.values()),
            width=10,
            state="readonly",
        )
        self._font_dropdown.pack(side=tk.LEFT, padx=(0, 2))
        self._font_dropdown.bind("<<ComboboxSelected>>", self._on_font_selected)

        # === Группа CodePage ===
        tk.Label(frame, text="CP:").pack(side=tk.LEFT)
        self._codepage_dropdown = ttk.Combobox(
            frame,
            textvariable=self._codepage_var,
            values=list(self.CODEPAGE_LABELS.values()),
            width=7,
            state="readonly",
        )
        self._codepage_dropdown.pack(side=tk.LEFT, padx=(0, 2))
        self._codepage_dropdown.bind("<<ComboboxSelected>>", self._on_codepage_selected)

        # Разделитель перед Alignment
        separator_align = tk.Frame(frame, width=1, bg="gray60")
        separator_align.pack(side=tk.LEFT, fill=tk.Y, padx=PADDING_NORMAL, pady=4)

        # === Группа Alignment ===
        def make_alignment_handler(align: Alignment) -> Callable[[], None]:
            return lambda: self._set_alignment(align)

        for align in (Alignment.LEFT, Alignment.CENTER, Alignment.RIGHT, Alignment.JUSTIFY):
            btn = tk.Button(
                frame,
                text=self.ALIGNMENT_LABELS[align],
                width=3,
                relief=tk.SUNKEN if align == Alignment.LEFT else tk.RAISED,
                command=make_alignment_handler(align),
                font=("TkDefaultFont", 9, "bold"),
            )
            btn.pack(side=tk.LEFT, padx=(0, 2))
            self._alignment_buttons[align] = btn

        # Разделитель перед кнопками Barcode и QR
        separator2 = tk.Frame(frame, width=1, bg="gray60")
        separator2.pack(side=tk.LEFT, fill=tk.Y, padx=PADDING_NORMAL, pady=4)

        # === Кнопка Barcode ===
        barcode_btn = tk.Button(
            frame,
            text="📊 Barcode",
            relief=tk.RAISED,
            command=self._on_barcode_clicked,
        )
        barcode_btn.pack(side=tk.LEFT, padx=(0, 2))
        self._barcode_button: tk.Button = barcode_btn

        # === Кнопка QR ===
        qr_btn = tk.Button(
            frame,
            text="🔳 QR",
            relief=tk.RAISED,
            command=self._on_qr_clicked,
        )
        qr_btn.pack(side=tk.LEFT, padx=(0, 2))
        self._qr_button: tk.Button = qr_btn

        # Разделитель перед элементами валидации
        separator3 = tk.Frame(frame, width=1, bg="gray60")
        separator3.pack(side=tk.LEFT, fill=tk.Y, padx=PADDING_NORMAL, pady=4)

        # === Группа валидации ===
        # Бейдж с количеством невалидных символов
        self._validation_badge = tk.Label(
            frame,
            text="",
            fg="#f9ab00",  # Жёлтый цвет для предупреждения
            font=("TkDefaultFont", 9, "bold"),
            padx=4,
        )
        self._validation_badge.pack(side=tk.LEFT, padx=(0, 4))

        # Кнопка "Исправить"
        self._fix_button = tk.Button(
            frame,
            text="🔧 Fix",
            relief=tk.RAISED,
            command=self._on_fix_validation_clicked,
            state=tk.DISABLED,  # Изначально отключена
        )
        self._fix_button.pack(side=tk.LEFT, padx=(0, 2))

        return frame

    def _on_cpi_selected(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик выбора CPI из dropdown.

        Args:
            event: Событие ComboboxSelected (может быть None при прямом вызове).
        """
        cpi_str: str = self._cpi_var.get()
        cpi: int = int(cpi_str)
        if self._on_cpi_change is not None:
            self._on_cpi_change(cpi)

    def _on_quality_selected(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик выбора Quality из dropdown."""
        label = self._quality_var.get()
        quality = next(
            (q for q, lbl in self.QUALITY_LABELS.items() if lbl == label),
            PrintQuality.DRAFT,
        )
        if self._on_quality_change is not None:
            self._on_quality_change(quality)

    def _on_font_selected(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик выбора Font из dropdown."""
        label = self._font_var.get()
        font = next(
            (f for f, lbl in self.FONT_LABELS.items() if lbl == label),
            FontFamily.DRAFT,
        )
        if self._on_font_change is not None:
            self._on_font_change(font)

    def _on_codepage_selected(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик выбора CodePage из dropdown."""
        label = self._codepage_var.get()
        codepage = next(
            (cp for cp, lbl in self.CODEPAGE_LABELS.items() if lbl == label),
            CodePage.PC866,
        )
        if self._on_codepage_change is not None:
            self._on_codepage_change(codepage)

    def _set_alignment(self, align: Alignment) -> None:
        """Устанавливает выравнивание (взаимоисключение)."""
        self._current_alignment = align
        for a, btn in self._alignment_buttons.items():
            btn.config(relief=tk.SUNKEN if a == align else tk.RAISED)
        if self._on_alignment_change is not None:
            self._on_alignment_change(align)

    def _toggle_format(self, format_type: str) -> None:
        """Переключает состояние кнопки форматирования.

        Args:
            format_type: Тип форматирования (bold, italic, underline, strikethrough,
                                          subscript, superscript).
        """
        # Инвертируем состояние
        new_state: bool = not self._format_states[format_type]
        self._format_states[format_type] = new_state

        # Обновляем визуальное состояние кнопки
        button = self._format_buttons[format_type]
        button.config(relief=tk.SUNKEN if new_state else tk.RAISED)

        # Взаимоисключение для subscript/superscript
        if format_type == "subscript" and new_state:
            if self._format_states["superscript"]:
                self.set_format_active("superscript", False)
        elif format_type == "superscript" and new_state:
            if self._format_states["subscript"]:
                self.set_format_active("subscript", False)

        # Вызываем callback
        if self._on_format_toggle is not None:
            self._on_format_toggle(format_type, new_state)

        # Вызываем script callback для subscript/superscript
        if format_type in ("subscript", "superscript") and self._on_script_toggle is not None:
            self._on_script_toggle(format_type, new_state)

    def set_cpi(self, cpi: int) -> None:
        """Устанавливает значение CPI в dropdown.

        Args:
            cpi: Новое значение CPI (должно быть в CPI_VALUES).

        Raises:
            ValueError: Если cpi не входит в допустимые значения.

        Example:
            >>> toolbar.set_cpi(12)
            >>> assert toolbar._cpi_var.get() == "12"
        """
        cpi_str = str(cpi)
        if cpi_str not in self.CPI_VALUES:
            raise ValueError(f"Invalid CPI value: {cpi}. Allowed: {self.CPI_VALUES}")

        self._cpi_var.set(cpi_str)

    def set_format_active(self, format_type: str, active: bool) -> None:
        """Устанавливает состояние кнопки форматирования.

        Args:
            format_type: Тип форматирования (bold, italic, underline, strikethrough).
            active: True для SUNKEN (активно), False для RAISED (неактивно).

        Raises:
            ValueError: Если format_type неизвестен.

        Example:
            >>> toolbar.set_format_active("bold", True)
            >>> assert toolbar.is_format_active("bold") is True
        """
        if format_type not in self._format_states:
            raise ValueError(
                f"Unknown format type: {format_type}. Available: {list(self._format_states.keys())}"
            )

        # Обновляем внутреннее состояние
        self._format_states[format_type] = active

        # Обновляем визуальное состояние если виджет создан
        if self._is_mounted and format_type in self._format_buttons:
            button = self._format_buttons[format_type]
            button.config(relief=tk.SUNKEN if active else tk.RAISED)

    def is_format_active(self, format_type: str) -> bool:
        """Проверяет, активен ли указанный формат.

        Args:
            format_type: Тип форматирования (bold, italic, underline, strikethrough).

        Returns:
            True если формат активен (кнопка в SUNKEN).

        Raises:
            ValueError: Если format_type неизвестен.

        Example:
            >>> toolbar.set_format_active("italic", True)
            >>> assert toolbar.is_format_active("italic") is True
        """
        if format_type not in self._format_states:
            raise ValueError(
                f"Unknown format type: {format_type}. Available: {list(self._format_states.keys())}"
            )

        return self._format_states[format_type]

    def get_current_cpi(self) -> str:
        """Возвращает текущее значение CPI.

        Returns:
            Текущее выбранное значение CPI.

        Example:
            >>> toolbar.set_cpi(15)
            >>> assert toolbar.get_current_cpi() == "15"
        """
        return self._cpi_var.get()

    def reset_formats(self) -> None:
        """Сбрасывает все форматы в неактивное состояние.

        Example:
            >>> toolbar.set_format_active("bold", True)
            >>> toolbar.reset_formats()
            >>> assert toolbar.is_format_active("bold") is False
        """
        for format_type in self._format_states:
            self.set_format_active(format_type, False)

    def _on_barcode_clicked(self) -> None:
        """Обработчик нажатия на кнопку Barcode."""
        if self._on_barcode is not None:
            self._on_barcode()

    def _on_qr_clicked(self) -> None:
        """Обработчик нажатия на кнопку QR."""
        if self._on_qr is not None:
            self._on_qr()

    def _on_fix_validation_clicked(self) -> None:
        """Обработчик нажатия на кнопку исправления валидации."""
        if self._on_fix_validation is not None:
            self._on_fix_validation()

    def trigger_barcode(self) -> None:
        """Вызывает callback для Barcode программно.

        Example:
            >>> toolbar.trigger_barcode()
        """
        self._on_barcode_clicked()

    def trigger_qr(self) -> None:
        """Вызывает callback для QR программно.

        Example:
            >>> toolbar.trigger_qr()
        """
        self._on_qr_clicked()

    def set_subscript(self, active: bool) -> None:
        """Устанавливает состояние subscript.

        Args:
            active: True для включения, False для отключения.

        Example:
            >>> toolbar.set_subscript(True)
            >>> assert toolbar.is_script_active("subscript") is True
        """
        self.set_format_active("subscript", active)
        # Взаимоисключение: если включили subscript, отключаем superscript
        if active and self._format_states["superscript"]:
            self.set_format_active("superscript", False)

    def set_superscript(self, active: bool) -> None:
        """Устанавливает состояние superscript.

        Args:
            active: True для включения, False для отключения.

        Example:
            >>> toolbar.set_superscript(True)
            >>> assert toolbar.is_script_active("superscript") is True
        """
        self.set_format_active("superscript", active)
        # Взаимоисключение: если включили superscript, отключаем subscript
        if active and self._format_states["subscript"]:
            self.set_format_active("subscript", False)

    def is_script_active(self, script_type: str) -> bool:
        """Проверяет, активен ли указанный script-формат.

        Args:
            script_type: Тип script-форматирования ("subscript" или "superscript").

        Returns:
            True если script-формат активен.

        Raises:
            ValueError: Если script_type не "subscript" и не "superscript".

        Example:
            >>> toolbar.set_subscript(True)
            >>> assert toolbar.is_script_active("subscript") is True
        """
        if script_type not in ("subscript", "superscript"):
            raise ValueError(f"Invalid script formatting type: {script_type}")
        return self._format_states[script_type]

    def reset_scripts(self) -> None:
        """Сбрасывает subscript и superscript в неактивное состояние.

        Example:
            >>> toolbar.set_subscript(True)
            >>> toolbar.set_superscript(True)
            >>> toolbar.reset_scripts()
            >>> assert toolbar.is_script_active("subscript") is False
            >>> assert toolbar.is_script_active("superscript") is False
        """
        self.set_format_active("subscript", False)
        self.set_format_active("superscript", False)

    def _apply_script(self, script_type: str, active: bool) -> None:
        """Применяет ESC/P команду для subscript/superscript.

        Args:
            script_type: Тип script-форматирования ("subscript" или "superscript").
            active: True для включения, False для отключения.

        Note:
            Этот метод предназначен для использования с ESC/P командами.
            При active=True отправляется команда включения,
            при active=False - команда отключения.

        Example:
            >>> toolbar._apply_script("superscript", True)
            >>> toolbar._apply_script("superscript", False)
        """
        if script_type not in ("subscript", "superscript"):
            raise ValueError(f"Invalid script formatting type: {script_type}")
        if self._on_script_toggle is not None:
            self._on_script_toggle(script_type, active)

    def set_validation_badge(self, count: int) -> None:
        """Устанавливает значение бейджа с количеством невалидных символов.

        Args:
            count: Количество невалидных символов. 0 скрывает бейдж.

        Example:
            >>> toolbar.set_validation_badge(5)
            >>> toolbar.set_validation_badge(0)  # Скрыть бейдж
        """
        self._validation_count = count
        if self._validation_badge is not None:
            if count > 0:
                self._validation_badge.config(text=f"⚠️ {count}")
            else:
                self._validation_badge.config(text="")

    def set_fix_validation_enabled(self, enabled: bool) -> None:
        """Включает или отключает кнопку исправления.

        Args:
            enabled: True для включения кнопки, False для отключения.

        Example:
            >>> toolbar.set_fix_validation_enabled(True)
            >>> toolbar.set_fix_validation_enabled(False)
        """
        if self._fix_button is not None:
            from typing import Literal

            state: Literal["normal", "active", "disabled"] = "normal" if enabled else "disabled"
            self._fix_button.config(state=state)

    def set_on_fix_validation_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """Устанавливает callback для кнопки исправления валидации.

        Args:
            callback: Функция, вызываемая при нажатии на кнопку "Исправить".

        Example:
            >>> toolbar.set_on_fix_validation_callback(lambda: print("Fix clicked"))
        """
        self._on_fix_validation = callback

    def get_validation_count(self) -> int:
        """Возвращает текущее количество невалидных символов.

        Returns:
            Количество невалидных символов.

        Example:
            >>> toolbar.set_validation_badge(3)
            >>> assert toolbar.get_validation_count() == 3
        """
        return self._validation_count

    # === Quality ===
    def set_quality(self, quality: PrintQuality) -> None:
        """Устанавливает качество печати в dropdown.

        Args:
            quality: Новое качество печати.
        """
        label = self.QUALITY_LABELS.get(quality)
        if label is not None:
            self._quality_var.set(label)

    def get_current_quality(self) -> PrintQuality:
        """Возвращает текущее качество печати.

        Returns:
            Текущее качество печати.
        """
        label = self._quality_var.get()
        return next(
            (q for q, lbl in self.QUALITY_LABELS.items() if lbl == label),
            PrintQuality.DRAFT,
        )

    # === Font ===
    def set_font(self, font: FontFamily) -> None:
        """Устанавливает шрифт в dropdown.

        Args:
            font: Новый шрифт.
        """
        label = self.FONT_LABELS.get(font)
        if label is not None:
            self._font_var.set(label)

    def get_current_font(self) -> FontFamily:
        """Возвращает текущий шрифт.

        Returns:
            Текущий шрифт.
        """
        label = self._font_var.get()
        return next(
            (f for f, lbl in self.FONT_LABELS.items() if lbl == label),
            FontFamily.DRAFT,
        )

    # === CodePage ===
    def set_codepage(self, codepage: CodePage) -> None:
        """Устанавливает кодовую страницу в dropdown.

        Args:
            codepage: Новая кодовая страница.
        """
        label = self.CODEPAGE_LABELS.get(codepage)
        if label is not None:
            self._codepage_var.set(label)

    def get_current_codepage(self) -> CodePage:
        """Возвращает текущую кодовую страницу.

        Returns:
            Текущая кодовая страница.
        """
        label = self._codepage_var.get()
        return next(
            (cp for cp, lbl in self.CODEPAGE_LABELS.items() if lbl == label),
            CodePage.PC866,
        )

    # === Alignment ===
    def set_alignment(self, align: Alignment) -> None:
        """Устанавливает выравнивание.

        Args:
            align: Новое выравнивание.
        """
        self._set_alignment(align)

    def get_current_alignment(self) -> Alignment:
        """Возвращает текущее выравнивание.

        Returns:
            Текущее выравнивание.
        """
        return self._current_alignment


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "FormatToolbar",
]
