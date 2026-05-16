"""Диалог настройки шрифта для FX Text Processor 3.

Позволяет выбрать семейство шрифта (FontFamily), CPI, качество печати,
а также базовое форматирование текущего Run (bold, italic, underline).

Architecture:
    Dialog (View) → MainController (Controller) → FormatService/Run (Model)

Example:
    >>> from src.gui.dialogs.font_dialog import FontDialog
    >>> result = FontDialog.show_dialog(parent, current_run=run)
    >>> if result:
    ...     print(result.font_family, result.cpi)

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.model.enums import CharactersPerInch, FontFamily, PrintQuality

logger: Final = logging.getLogger(__name__)

DIALOG_WIDTH: Final[int] = 420
DIALOG_HEIGHT: Final[int] = 380


@dataclass(frozen=True)
class FontDialogResult:
    """Результат диалога настройки шрифта."""

    font_family: FontFamily
    cpi: CharactersPerInch
    quality: PrintQuality
    bold: bool
    italic: bool
    underline: bool


class FontDialog(BaseDialog):
    """Модальный диалог настройки шрифта FX-890.

    Attributes:
        _current_family: Текущее семейство шрифта.
        _current_cpi: Текущее CPI.
        _current_quality: Текущее качество.
        _bold_var: Флаг жирного текста.
        _italic_var: Флаг курсива.
        _underline_var: Флаг подчёркивания.
    """

    def __init__(
        self,
        parent: tk.Widget,
        current_family: FontFamily = FontFamily.ROMAN,
        current_cpi: CharactersPerInch = CharactersPerInch.CPI_12,
        current_quality: PrintQuality = PrintQuality.NLQ,
        current_bold: bool = False,
        current_italic: bool = False,
        current_underline: bool = False,
    ) -> None:
        """Инициализация диалога настройки шрифта.

        Args:
            parent: Родительский виджет.
            current_family: Текущий шрифт.
            current_cpi: Текущее CPI.
            current_quality: Текущее качество печати.
            current_bold: Жирный текст.
            current_italic: Курсив.
            current_underline: Подчёркивание.
        """
        super().__init__(parent, title="Font Settings", modal=True)

        self._current_family = current_family
        self._current_cpi = current_cpi
        self._current_quality = current_quality

        self._family_var = tk.StringVar(master=self, value=current_family.value)
        self._cpi_var = tk.StringVar(master=self, value=current_cpi.value)
        self._quality_var = tk.StringVar(master=self, value=current_quality.value)
        self._bold_var = tk.BooleanVar(master=self, value=current_bold)
        self._italic_var = tk.BooleanVar(master=self, value=current_italic)
        self._underline_var = tk.BooleanVar(master=self, value=current_underline)

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настройка геометрии окна."""
        self.resizable(False, False)
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self._center_window()

    def _create_ui(self) -> None:
        """Создаёт элементы интерфейса."""
        frame = ttk.Frame(self, padding=15)
        frame.pack(fill="both", expand=True)

        # Font Family
        ttk.Label(frame, text="Font Family:").grid(row=0, column=0, sticky="w", pady=5)
        family_combo = ttk.Combobox(
            frame,
            textvariable=self._family_var,
            values=[f.value for f in FontFamily],
            state="readonly",
            width=25,
        )
        family_combo.grid(row=0, column=1, sticky="ew", pady=5)

        # CPI
        ttk.Label(frame, text="CPI (chars/inch):").grid(row=1, column=0, sticky="w", pady=5)
        cpi_combo = ttk.Combobox(
            frame,
            textvariable=self._cpi_var,
            values=[c.value for c in CharactersPerInch],
            state="readonly",
            width=25,
        )
        cpi_combo.grid(row=1, column=1, sticky="ew", pady=5)

        # Quality
        ttk.Label(frame, text="Print Quality:").grid(row=2, column=0, sticky="w", pady=5)
        quality_combo = ttk.Combobox(
            frame,
            textvariable=self._quality_var,
            values=[q.value for q in PrintQuality],
            state="readonly",
            width=25,
        )
        quality_combo.grid(row=2, column=1, sticky="ew", pady=5)

        # Formatting
        fmt_frame = ttk.LabelFrame(frame, text="Formatting", padding=10)
        fmt_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)

        ttk.Checkbutton(fmt_frame, text="Bold", variable=self._bold_var).pack(side="left", padx=5)
        ttk.Checkbutton(fmt_frame, text="Italic", variable=self._italic_var).pack(
            side="left", padx=5
        )
        ttk.Checkbutton(fmt_frame, text="Underline", variable=self._underline_var).pack(
            side="left", padx=5
        )

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=15)

        ttk.Button(btn_frame, text="OK", command=self._on_ok, width=12).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel, width=12).pack(
            side="left", padx=5
        )

        frame.columnconfigure(1, weight=1)

    def _on_ok(self) -> None:
        """Применяет настройки и закрывает диалог."""
        family = FontFamily.from_string(self._family_var.get()) or FontFamily.ROMAN
        cpi = CharactersPerInch.from_string(self._cpi_var.get()) or CharactersPerInch.CPI_12
        quality = PrintQuality.from_string(self._quality_var.get()) or PrintQuality.NLQ

        result = FontDialogResult(
            font_family=family,
            cpi=cpi,
            quality=quality,
            bold=self._bold_var.get(),
            italic=self._italic_var.get(),
            underline=self._underline_var.get(),
        )
        self.close(result=result)

    def _on_cancel(self) -> None:
        """Отменяет изменения и закрывает диалог."""
        self.close(result=None)

    def get_result(self) -> Optional[FontDialogResult]:
        """Возвращает результат диалога.

        Returns:
            FontDialogResult или None если отменено.
        """
        result = super().get_result()
        if isinstance(result, FontDialogResult):
            return result
        return None

    @classmethod
    def show_dialog(
        cls,
        parent: tk.Widget,
        current_family: FontFamily = FontFamily.ROMAN,
        current_cpi: CharactersPerInch = CharactersPerInch.CPI_12,
        current_quality: PrintQuality = PrintQuality.NLQ,
        current_bold: bool = False,
        current_italic: bool = False,
        current_underline: bool = False,
    ) -> Optional[FontDialogResult]:
        """Показывает диалог и возвращает результат.

        Args:
            parent: Родительский виджет.
            current_family: Текущий шрифт.
            current_cpi: Текущее CPI.
            current_quality: Текущее качество.
            current_bold: Жирный текст.
            current_italic: Курсив.
            current_underline: Подчёркивание.

        Returns:
            FontDialogResult или None.
        """
        dialog = cls(
            parent=parent,
            current_family=current_family,
            current_cpi=current_cpi,
            current_quality=current_quality,
            current_bold=current_bold,
            current_italic=current_italic,
            current_underline=current_underline,
        )
        dialog.wait_window()
        return dialog.get_result()
