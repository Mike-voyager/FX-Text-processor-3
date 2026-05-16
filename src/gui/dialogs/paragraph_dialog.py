"""Диалог настройки абзаца для FX Text Processor 3.

Позволяет настроить выравнивание, отступы, межстрочный интервал
и пробелы между абзацами.

Architecture:
    Dialog (View) → MainController (Controller) → ParagraphFormat / Model

Example:
    >>> from src.gui.dialogs.paragraph_dialog import ParagraphDialog
    >>> result = ParagraphDialog.show_dialog(parent, alignment="left")
    >>> if result:
    ...     print(result.alignment, result.first_line_indent)

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog

logger: Final = logging.getLogger(__name__)

DIALOG_WIDTH: Final[int] = 400
DIALOG_HEIGHT: Final[int] = 340


@dataclass(frozen=True)
class ParagraphDialogResult:
    """Результат диалога настройки абзаца."""

    alignment: str
    first_line_indent: int
    left_indent: int
    right_indent: int
    line_spacing: str
    space_before: int
    space_after: int


class ParagraphDialog(BaseDialog):
    """Модальный диалог настройки абзаца.

    Attributes:
        _alignment_var: Текущее выравнивание.
        _first_indent_var: Отступ первой строки (chars).
        _left_indent_var: Левый отступ (chars).
        _right_indent_var: Правый отступ (chars).
        _line_spacing_var: Межстрочный интервал.
        _space_before_var: Пробел до (mm).
        _space_after_var: Пробел после (mm).
    """

    def __init__(
        self,
        parent: tk.Widget,
        current_alignment: str = "left",
        current_first_indent: int = 0,
        current_left_indent: int = 0,
        current_right_indent: int = 0,
        current_line_spacing: str = "1/6",
        current_space_before: int = 0,
        current_space_after: int = 0,
    ) -> None:
        """Инициализация диалога настройки абзаца.

        Args:
            parent: Родительский виджет.
            current_alignment: Текущее выравнивание (left, center, right, justify).
            current_first_indent: Отступ первой строки (chars).
            current_left_indent: Левый отступ (chars).
            current_right_indent: Правый отступ (chars).
            current_line_spacing: Межстрочный интервал (1/6 или 1/8).
            current_space_before: Пробел до абзаца (mm).
            current_space_after: Пробел после абзаца (mm).
        """
        super().__init__(parent, title="Paragraph Settings", modal=True)

        self._alignment_var = tk.StringVar(master=self, value=current_alignment)
        self._first_indent_var = tk.IntVar(master=self, value=current_first_indent)
        self._left_indent_var = tk.IntVar(master=self, value=current_left_indent)
        self._right_indent_var = tk.IntVar(master=self, value=current_right_indent)
        self._line_spacing_var = tk.StringVar(master=self, value=current_line_spacing)
        self._space_before_var = tk.IntVar(master=self, value=current_space_before)
        self._space_after_var = tk.IntVar(master=self, value=current_space_after)

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

        # Alignment
        ttk.Label(frame, text="Alignment:").grid(row=0, column=0, sticky="w", pady=5)
        align_combo = ttk.Combobox(
            frame,
            textvariable=self._alignment_var,
            values=["left", "center", "right", "justify"],
            state="readonly",
            width=20,
        )
        align_combo.grid(row=0, column=1, sticky="ew", pady=5)

        # Indents
        indent_frame = ttk.LabelFrame(frame, text="Indents", padding=10)
        indent_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=8)

        ttk.Label(indent_frame, text="First line (chars):").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(
            indent_frame, from_=0, to=20, textvariable=self._first_indent_var, width=8
        ).grid(row=0, column=1, padx=5)

        ttk.Label(indent_frame, text="Left (chars):").grid(row=1, column=0, sticky="w")
        ttk.Spinbox(indent_frame, from_=0, to=20, textvariable=self._left_indent_var, width=8).grid(
            row=1, column=1, padx=5
        )

        ttk.Label(indent_frame, text="Right (chars):").grid(row=2, column=0, sticky="w")
        ttk.Spinbox(
            indent_frame, from_=0, to=20, textvariable=self._right_indent_var, width=8
        ).grid(row=2, column=1, padx=5)

        # Line spacing
        ttk.Label(frame, text="Line spacing:").grid(row=2, column=0, sticky="w", pady=5)
        ls_combo = ttk.Combobox(
            frame,
            textvariable=self._line_spacing_var,
            values=["1/6", "1/8"],
            state="readonly",
            width=20,
        )
        ls_combo.grid(row=2, column=1, sticky="ew", pady=5)

        # Spacing
        space_frame = ttk.LabelFrame(frame, text="Spacing", padding=10)
        space_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)

        ttk.Label(space_frame, text="Before (mm):").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(space_frame, from_=0, to=50, textvariable=self._space_before_var, width=8).grid(
            row=0, column=1, padx=5
        )

        ttk.Label(space_frame, text="After (mm):").grid(row=1, column=0, sticky="w")
        ttk.Spinbox(space_frame, from_=0, to=50, textvariable=self._space_after_var, width=8).grid(
            row=1, column=1, padx=5
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
        result = ParagraphDialogResult(
            alignment=self._alignment_var.get(),
            first_line_indent=self._first_indent_var.get(),
            left_indent=self._left_indent_var.get(),
            right_indent=self._right_indent_var.get(),
            line_spacing=self._line_spacing_var.get(),
            space_before=self._space_before_var.get(),
            space_after=self._space_after_var.get(),
        )
        self.close(result=result)

    def _on_cancel(self) -> None:
        """Отменяет изменения и закрывает диалог."""
        self.close(result=None)

    def get_result(self) -> Optional[ParagraphDialogResult]:
        """Возвращает результат диалога.

        Returns:
            ParagraphDialogResult или None если отменено.
        """
        result = super().get_result()
        if isinstance(result, ParagraphDialogResult):
            return result
        return None

    @classmethod
    def show_dialog(
        cls,
        parent: tk.Widget,
        current_alignment: str = "left",
        current_first_indent: int = 0,
        current_left_indent: int = 0,
        current_right_indent: int = 0,
        current_line_spacing: str = "1/6",
        current_space_before: int = 0,
        current_space_after: int = 0,
    ) -> Optional[ParagraphDialogResult]:
        """Показывает диалог и возвращает результат.

        Args:
            parent: Родительский виджет.
            current_alignment: Текущее выравнивание.
            current_first_indent: Отступ первой строки.
            current_left_indent: Левый отступ.
            current_right_indent: Правый отступ.
            current_line_spacing: Межстрочный интервал.
            current_space_before: Пробел до.
            current_space_after: Пробел после.

        Returns:
            ParagraphDialogResult или None.
        """
        dialog = cls(
            parent=parent,
            current_alignment=current_alignment,
            current_first_indent=current_first_indent,
            current_left_indent=current_left_indent,
            current_right_indent=current_right_indent,
            current_line_spacing=current_line_spacing,
            current_space_before=current_space_before,
            current_space_after=current_space_after,
        )
        dialog.wait_window()
        return dialog.get_result()
