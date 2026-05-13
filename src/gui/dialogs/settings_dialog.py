"""Диалог общих настроек FX Text Processor 3.

Предоставляет простой интерфейс для настройки:
- Интервал авто-сохранения (минуты)
- Тема оформления
- Размер бумаги по умолчанию

Example:
    >>> from src.gui.dialogs.settings_dialog import SettingsDialog
    >>> dialog = SettingsDialog(parent=root, current_settings={"theme": "classic_green"})
    >>> result = dialog.show()
    >>> if result:
    ...     print(result["theme"])

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.themes import ThemeRegistry
from src.services.paper_format_service import PaperSize

logger: Final = logging.getLogger(__name__)

DEFAULT_AUTO_SAVE: Final[int] = 5
DEFAULT_THEME: Final[str] = "classic_green"
DEFAULT_PAPER_SIZE: Final[str] = "A4"


class SettingsDialog(BaseDialog):
    """Диалог общих настроек приложения.

    Attributes:
        _settings: Текущие настройки для редактирования.
    """

    def __init__(
        self,
        parent: tk.Widget,
        current_settings: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Инициализирует диалог настроек.

        Args:
            parent: Родительский виджет.
            current_settings: Текущие значения настроек.
        """
        super().__init__(parent, title="Настройки", modal=True, center_on_parent=True)
        self._settings: Dict[str, Any] = dict(current_settings) if current_settings else {}
        self._build_ui()

    def _build_ui(self) -> None:
        """Создаёт элементы диалога."""
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Auto-save interval
        ttk.Label(frame, text="Интервал авто-сохранения (мин, 0 = выкл):").grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        self._auto_save_var = tk.IntVar(
            value=self._settings.get("auto_save_interval", DEFAULT_AUTO_SAVE)
        )
        self._auto_save_spin = tk.Spinbox(
            frame, from_=0, to=60, textvariable=self._auto_save_var, width=10
        )
        self._auto_save_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        # Theme
        ttk.Label(frame, text="Тема оформления:").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        themes = ThemeRegistry.get_instance().list_themes()
        self._theme_var = tk.StringVar(master=self, value=self._settings.get("theme", DEFAULT_THEME))
        self._theme_combo = ttk.Combobox(
            frame, textvariable=self._theme_var, values=themes, state="readonly", width=20
        )
        self._theme_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        if themes and self._theme_var.get() not in themes:
            self._theme_var.set(themes[0])

        # Default paper size
        ttk.Label(frame, text="Размер бумаги по умолчанию:").grid(
            row=2, column=0, sticky=tk.W, pady=5
        )
        paper_sizes = [p.name for p in PaperSize]
        self._paper_var = tk.StringVar(
            value=self._settings.get("default_paper_size", DEFAULT_PAPER_SIZE)
        )
        self._paper_combo = ttk.Combobox(
            frame, textvariable=self._paper_var, values=paper_sizes, state="readonly", width=20
        )
        self._paper_combo.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=15)

        ttk.Button(btn_frame, text="Сохранить", command=self._on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=self._on_cancel).pack(side=tk.LEFT, padx=5)

    def _on_save(self) -> None:
        """Сохраняет настройки и закрывает диалог."""
        try:
            auto_save = int(self._auto_save_var.get())
        except ValueError:
            auto_save = DEFAULT_AUTO_SAVE

        result: Dict[str, Any] = {
            "auto_save_interval": max(0, min(60, auto_save)),
            "theme": self._theme_var.get(),
            "default_paper_size": self._paper_var.get(),
        }

        messagebox.showinfo("Настройки", "Настройки успешно сохранены.")
        logger.info("Настройки сохранены: %s", result)
        self.close(result)

    def _on_cancel(self) -> None:
        """Закрывает диалог без сохранения."""
        self.close(None)

    def show(self) -> Any:
        """Показывает диалог модально и возвращает результат.

        Returns:
            Словарь настроек или None при отмене.
        """
        return super().show()
