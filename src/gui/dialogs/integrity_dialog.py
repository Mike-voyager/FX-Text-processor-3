"""Диалог проверки целостности приложения и конфигурации.

Показывает прогресс выполнения проверок:
- Verifying binary...
- Verifying configuration...

Результаты отображаются в модальном окне с подробностями.

Example:
    >>> from src.gui.dialogs.integrity_dialog import IntegrityDialog
    >>> dialog = IntegrityDialog(parent)
    >>> dialog.show()

Module: src/gui/dialogs/integrity_dialog.py
Version: 2.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import ttk
from typing import Any, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.themes import ThemeNotFoundError, ThemeRegistry
from src.security.integrity import AppIntegrityChecker, ConfigIntegrityChecker
from src.security.integrity.models import ConfigSignatureResult, IntegrityCheckResult

logger: Final = logging.getLogger(__name__)


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Color в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except (AttributeError, KeyError, RuntimeError, ThemeNotFoundError):
        return "#333333"


DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 420


class IntegrityDialog(BaseDialog):
    """Диалог проверки целостности.

    Выполняет две проверки:
    1. Целостность бинарного файла (AppIntegrityChecker).
    2. Целостность конфигурации (ConfigIntegrityChecker).

    Attributes:
        _parent: Родительский виджет.
        _app_checker: Проверяющий бинарника.
        _config_checker: Проверяющий конфигурации.
        _app_result: Результат проверки бинарника.
        _config_result: Результат проверки конфигурации.

    Example:
        >>> dialog = IntegrityDialog(parent)
        >>> dialog.show()
    """

    def __init__(
        self,
        parent: Any,
        app_checker: Optional[AppIntegrityChecker] = None,
        config_checker: Optional[ConfigIntegrityChecker] = None,
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительский виджет.
            app_checker: Опциональный AppIntegrityChecker.
            config_checker: Опциональный ConfigIntegrityChecker.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._app_checker: Optional[AppIntegrityChecker] = app_checker
        self._config_checker: Optional[ConfigIntegrityChecker] = config_checker
        self._app_result: Optional[IntegrityCheckResult] = None
        self._config_result: Optional[ConfigSignatureResult] = None

        self._progress_var: tk.StringVar = tk.StringVar(master=self, value="Preparing checks...")
        self._status_var: tk.StringVar = tk.StringVar(master=self, value="")

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title("Integrity Check")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(400, 340)
        self.resizable(False, False)

        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (DIALOG_WIDTH // 2)
        y = (self.winfo_screenheight() // 2) - (DIALOG_HEIGHT // 2)
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI компоненты."""
        self.config(bg=_theme_color("dialog_bg"))

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Заголовок
        header = ttk.Label(
            main_frame,
            text="🔐 Integrity Check",
            font=("Helvetica", 14, "bold"),
        )
        header.pack(anchor="w", pady=(0, 10))

        # Прогресс
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=(0, 10))

        self._progress_label = ttk.Label(
            progress_frame,
            textvariable=self._progress_var,
            font=("Helvetica", 10),
            foreground=_theme_color("info"),
        )
        self._progress_label.pack(anchor="w")

        self._progress_bar = ttk.Progressbar(progress_frame, mode="determinate", maximum=2, value=0)
        self._progress_bar.pack(fill=tk.X, pady=(5, 0))

        # Статус результатов
        self._results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        self._results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self._status_label = ttk.Label(
            self._results_frame,
            textvariable=self._status_var,
            font=("Helvetica", 10),
            wraplength=DIALOG_WIDTH - 80,
            justify=tk.LEFT,
        )
        self._status_label.pack(anchor="nw")

        # Кнопка закрытия (изначально disabled)
        self._close_btn = ttk.Button(
            main_frame,
            text="Close",
            command=self.destroy,
            state=tk.DISABLED,
        )
        self._close_btn.pack(side=tk.RIGHT)

    def _update_progress(self, step: int, message: str) -> None:
        """Обновляет прогресс.

        Args:
            step: Номер шага (0..2).
            message: Сообщение о текущей операции.
        """
        self._progress_var.set(message)
        self._progress_bar["value"] = step
        self.update_idletasks()

    def _append_status(self, text: str, color: str = _theme_color("text_primary")) -> None:
        """Добавляет текст в область статуса.

        Args:
            text: Текст для добавления.
            color: Color текста.
        """
        current = self._status_var.get()
        if current:
            current += "\n"
        self._status_var.set(current + text)
        self.update_idletasks()

    def _run_checks(self) -> None:
        """Выполняет проверки целостности."""
        # Step 1: Verify binary
        self._update_progress(0, "Verifying binary...")
        if self._app_checker is not None:
            try:
                self._app_result = self._app_checker.verify()
            except (OSError, ValueError, RuntimeError) as exc:
                logger.exception("App integrity check error")
                self._app_result = IntegrityCheckResult(
                    valid=False,
                    reason="Integrity check error",
                    error_message=str(exc),
                )
        else:
            self._app_result = IntegrityCheckResult(
                valid=False,
                reason="AppIntegrityChecker not configured",
                error_message="Checker not provided",
            )

        if self._app_result is not None and self._app_result.valid:
            self._append_status(f"✅ Binary: {self._app_result.reason}", _theme_color("success"))
        else:
            error_msg = (
                self._app_result.error_message if self._app_result is not None else "Unknown error"
            )
            self._append_status(f"❌ Binary check failed: {error_msg}", _theme_color("error"))

        # Step 2: Verify configuration
        self._update_progress(1, "Verifying configuration...")
        if self._config_checker is not None:
            try:
                self._config_result = self._config_checker.verify_config()
            except (OSError, ValueError, RuntimeError) as exc:
                logger.exception("Config integrity check error")
                self._config_result = ConfigSignatureResult(
                    valid=False,
                    tampered=False,
                    details=f"Config check error: {exc}",
                )
        else:
            self._config_result = ConfigSignatureResult(
                valid=False,
                tampered=False,
                details="ConfigIntegrityChecker not configured",
            )

        if self._config_result is not None and self._config_result.valid:
            self._append_status(
                f"✅ Configuration: {self._config_result.details}",
                _theme_color("success"),
            )
        else:
            details = (
                self._config_result.details if self._config_result is not None else "Unknown error"
            )
            self._append_status(f"❌ Configuration check failed: {details}", _theme_color("error"))

        # Final step
        self._update_progress(2, "Checks completed")
        self._close_btn.config(state=tk.NORMAL)

    def show(self) -> None:
        """Показывает диалог и запускает проверки."""
        # Schedule checks after dialog is visible
        self._after_ids.append(self.after(100, self._run_checks))
        self.wait_window()

    def get_app_result(self) -> Optional[IntegrityCheckResult]:
        """Возвращает результат проверки бинарника.

        Returns:
            Результат или None.
        """
        return self._app_result

    def get_config_result(self) -> Optional[ConfigSignatureResult]:
        """Возвращает результат проверки конфигурации.

        Returns:
            Результат или None.
        """
        return self._config_result


__all__: list[str] = ["IntegrityDialog"]
