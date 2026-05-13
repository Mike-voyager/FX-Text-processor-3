"""Диалог предупреждения о конфликте типа штрих-кода.

Показывается при выборе штрих-кода, несовместимого с Hardware mode
(CODE128, PDF417 и др.). Предлагает пользователю:
- рендерить как изображение (Software mode),
- переключить тип на совместимый (CODE39),
- отменить операцию.

Example:
    >>> dialog = BarcodeTypeConflictWarning(
    ...     parent,
    ...     barcode_type="CODE128",
    ...     hardware_mode="FX-890 ESC/P",
    ... )
    >>> result = dialog.show()
    >>> assert result in ("software", "switch", "cancel")

Module: src/gui/dialogs/barcode_conflict_dialog.py
Version: 1.0
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Final

from src.gui.dialogs.base_dialog import BaseDialog

COLOR_BG: Final[str] = "#f8f9fa"
COLOR_WARNING: Final[str] = "#f39c12"
COLOR_TEXT_PRIMARY: Final[str] = "#212529"
COLOR_TEXT_SECONDARY: Final[str] = "#6c757d"
COLOR_SUCCESS: Final[str] = "#27ae60"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_INFO: Final[str] = "#17a2b8"

DIALOG_WIDTH: Final[int] = 520
DIALOG_HEIGHT: Final[int] = 380


class BarcodeTypeConflictWarning(BaseDialog):
    """Модальный диалог предупреждения о конфликте типа штрих-кода.

    Attributes:
        _barcode_type: Выбранный тип штрих-кода (например "CODE128").
        _hardware_mode: Название/описание аппаратного режима.
        _result: Результат выбора пользователя.

    Example:
        >>> dialog = BarcodeTypeConflictWarning(parent, "CODE128", "FX-890")
        >>> result = dialog.show()
        >>> if result == "software":
        ...     print("Продолжить с рендерингом изображения")
    """

    def __init__(
        self,
        parent: Any,
        barcode_type: str,
        hardware_mode: str = "FX-890 ESC/P",
    ) -> None:
        """Инициализация диалога конфликта.

        Args:
            parent: Родительский виджет.
            barcode_type: Тип штрих-кода с конфликтом.
            hardware_mode: Название аппаратного режима.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._barcode_type: str = barcode_type
        self._hardware_mode: str = hardware_mode
        self._result: str = "cancel"

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна диалога."""
        self.title("⚠️ Barcode Type Conflict")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(450, 340)
        self.resizable(False, False)

        # Центрируем окно
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (DIALOG_WIDTH // 2)
        y = (self.winfo_screenheight() // 2) - (DIALOG_HEIGHT // 2)
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        self.config(bg=COLOR_BG)

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Заголовок
        header = ttk.Label(
            main_frame,
            text="⚠️ Barcode Type Conflict",
            font=("Helvetica", 14, "bold"),
            foreground=COLOR_WARNING,
        )
        header.pack(anchor="w", pady=(0, 5))

        # Описание конфликта
        desc = ttk.Label(
            main_frame,
            text=(f"Selected: {self._barcode_type}, Hardware mode: Not supported"),
            font=("Helvetica", 10),
            foreground=COLOR_TEXT_PRIMARY,
        )
        desc.pack(anchor="w", pady=(0, 10))

        # Примечание
        note = ttk.Label(
            main_frame,
            text=(
                f"{self._barcode_type} will be exported as PNG and printed as graphics (slower)."
            ),
            font=("Helvetica", 9),
            foreground=COLOR_TEXT_SECONDARY,
            wraplength=DIALOG_WIDTH - 60,
        )
        note.pack(anchor="w", pady=(0, 15))

        # Радиокнопки
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 15))

        self._choice_var = tk.StringVar(master=self, value="software")

        ttk.Radiobutton(
            options_frame,
            text="Render as image (software)",
            variable=self._choice_var,
            value="software",
        ).pack(anchor="w", pady=4)

        ttk.Radiobutton(
            options_frame,
            text="Switch to CODE39 (hardware)",
            variable=self._choice_var,
            value="switch",
        ).pack(anchor="w", pady=4)

        ttk.Radiobutton(
            options_frame,
            text="Cancel",
            variable=self._choice_var,
            value="cancel",
        ).pack(anchor="w", pady=4)

        # Кнопки
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Button(
            btn_frame,
            text="OK",
            command=self._on_ok,
        ).pack(side=tk.RIGHT, padx=(10, 0))

        ttk.Button(
            btn_frame,
            text="Cancel",
            command=self._on_cancel,
        ).pack(side=tk.RIGHT)

    def _on_ok(self) -> None:
        """Обработчик нажатия OK."""
        self._result = self._choice_var.get()
        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик нажатия Cancel."""
        self._result = "cancel"
        self.destroy()

    def show(self) -> str:
        """Показывает диалог и возвращает выбор пользователя.

        Returns:
            "software" — продолжить с рендерингом изображения,
            "switch" — переключить тип на CODE39,
            "cancel" — отменить операцию.
        """
        self.wait_window()
        return self._result


__all__: list[str] = ["BarcodeTypeConflictWarning"]
