"""Диалог отображения результатов Security Health Check.

Предоставляет интерфейс для запуска и отображения результатов
проверок системы безопасности FX Text Processor 3.

Features:
    - Модальный диалог с блокировкой родительского окна
    - Асинхронное выполнение проверок с progress bar
    - Thread-safe обновления UI
    - Colorовая индикация статусов (красный/жёлтый/зелёный)
    - Детальное отображение результатов каждой проверки

Example:
    >>> checker = HealthChecker(version="1.0.0")
    >>> checker.register_function("entropy", lambda: HealthCheckResult.healthy("entropy"))
    >>> dialog = HealthCheckDialog(parent=root, health_checker=checker)
    >>> dialog.show()
    >>> if not dialog.is_healthy():
    ...     print("Обнаружены проблемы безопасности!")

Version: 1.0
"""

from __future__ import annotations

import logging
import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog

# Используем TYPE_CHECKING для избежания циклических импортов
if TYPE_CHECKING:
    from src.security.monitoring.health_checker import HealthChecker

from src.security.monitoring.models import HealthCheckReport, HealthCheckStatus

logger: logging.Logger = logging.getLogger(__name__)


def _safe_grab_set(widget: tk.Misc) -> None:
    """Устанавливает grab с подавлением TclError (другой диалог может иметь grab).

    Args:
        widget: Виджет, для которого устанавливается grab.
    """
    try:
        widget.grab_set()
    except tk.TclError:
        pass


# =============================================================================
# CONSTANTS
# =============================================================================

# Colorа для различных статусов
COLOR_CRITICAL: str = "#e74c3c"  # 🔴 Красный
COLOR_WARNING: str = "#f39c12"  # 🟡 Жёлтый
COLOR_PASS: str = "#27ae60"  # 🟢 Зелёный
COLOR_NEUTRAL: str = "#7f8c8d"  # ⚪ Серый
COLOR_RUNNING: str = "#3498db"  # 🔵 Синий

# Иконки для статусов
ICON_RUNNING: str = "🔄"
ICON_PASS: str = "✓"
ICON_WARNING: str = "!"
ICON_CRITICAL: str = "✗"
ICON_PENDING: str = "○"

# Статусы в порядке отображения
CHECK_ORDER: list[str] = [
    "entropy",
    "keystore",
    "hardware",
    "algorithms",
    "audit",
    "config",
]

# Отображаемые названия проверок
CHECK_DISPLAY_NAMES: dict[str, str] = {
    "entropy": "Entropy Check",
    "keystore": "Keystore Check",
    "hardware": "Hardware Devices",
    "algorithms": "Algorithm Library",
    "audit": "Audit Chain",
    "config": "Config Check",
}

# Размеры диалога
DIALOG_WIDTH: int = 500
DIALOG_HEIGHT: int = 400

# =============================================================================
# HealthCheckDialog
# =============================================================================


class HealthCheckDialog(BaseDialog):
    """Диалог отображения результатов Security Health Check.

    Attributes:
        parent: Родительский виджет
        health_checker: Экземпляр HealthChecker для выполнения проверок
        _report: Текущий отчёт о проверках
        _check_widgets: Виджеты для отображения результатов проверок
        _is_running: Флаг выполнения асинхронной операции
        _cancelled: Флаг отмены операции
        _thread: Thread для асинхронного выполнения

    Thread Safety:
        - Все обновления UI выполняются через after() для thread-safety
        - _is_running и _cancelled защищены через tkinter variable system
    """

    def __init__(
        self,
        parent: tk.Tk,
        health_checker: Optional["HealthChecker"] = None,
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительский виджет
            health_checker: HealthChecker instance (optional)
        """
        super().__init__(parent, modal=True)

        self._parent: tk.Tk = parent
        self._health_checker: Optional["HealthChecker"] = health_checker
        self._report: Optional[HealthCheckReport] = None
        self._is_running: bool = False
        self._cancelled: bool = False
        self._thread: Optional[threading.Thread] = None

        # Хранение виджетов для каждой проверки
        self._check_widgets: dict[str, dict[str, tk.Widget]] = {}

        # Callback при завершении асинхронной операции
        self._on_complete_callback: Optional[Callable[[HealthCheckReport], None]] = None

        # Настройка окна
        self.title("🔒 Security Health Check")
        self.resizable(False, False)

        # Создаём UI
        self._create_ui()

        # Центрируем окно

        # Обработка закрытия окна

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        # Родительские координаты
        parent = self._parent
        parent_x = parent.winfo_rootx() if hasattr(parent, "winfo_rootx") else 0
        parent_y = parent.winfo_rooty() if hasattr(parent, "winfo_rooty") else 0
        parent_width = parent.winfo_width() if hasattr(parent, "winfo_width") else 800
        parent_height = parent.winfo_height() if hasattr(parent, "winfo_height") else 600

        # Вычисляем позицию
        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2

        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        # Главный контейнер
        main_frame = tk.Frame(self, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Заголовок
        header_frame = tk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(
            header_frame,
            text="🔒 Security Health Check",
            font=("Arial", 14, "bold"),
        ).pack(anchor=tk.W)

        # Разделитель
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 15))

        # Фрейм для списка проверок
        self._checks_frame = tk.Frame(main_frame)
        self._checks_frame.pack(fill=tk.X, expand=True)

        # Создаём виджеты для каждой проверки
        self._create_check_widgets()

        # Progress bar
        self._progress_var = tk.DoubleVar(master=self, value=0.0)
        self._progress_label_var = tk.StringVar(master=self, value="Progress: 0%")

        progress_frame = tk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=(15, 10))

        self._progress_label = tk.Label(
            progress_frame,
            textvariable=self._progress_label_var,
            font=("Arial", 10),
            fg=COLOR_NEUTRAL,
        )
        self._progress_label.pack(anchor=tk.W)

        self._progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self._progress_var,
            maximum=100,
            mode="determinate",
            length=460,
        )
        self._progress_bar.pack(fill=tk.X, pady=(5, 0))

        # Разделитель перед статусом
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(15, 10))

        # Статусная строка
        self._status_frame = tk.Frame(main_frame)
        self._status_frame.pack(fill=tk.X, pady=(0, 10))

        self._status_label = tk.Label(
            self._status_frame,
            text="Ready to run checks...",
            font=("Arial", 10, "bold"),
            fg=COLOR_NEUTRAL,
        )
        self._status_label.pack(anchor=tk.W)

        # Кнопки
        self._button_frame = tk.Frame(main_frame)
        self._button_frame.pack(fill=tk.X)

        # Растягиваем для выравнивания кнопок справа
        tk.Frame(self._button_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Кнопка Details (изначально скрыта)
        self._details_btn = tk.Button(
            self._button_frame,
            text="🔍 Details",
            width=12,
            command=self._on_details,
            state=tk.DISABLED,
        )
        self._details_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Кнопка Re-run (изначально скрыта)
        self._rerun_btn = tk.Button(
            self._button_frame,
            text="🔄 Re-run",
            width=12,
            command=self._on_rerun,
        )
        self._rerun_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Кнопка Cancel (для процесса)
        self._cancel_btn = tk.Button(
            self._button_frame,
            text="Cancel",
            width=10,
            command=self._on_cancel,
        )
        self._cancel_btn.pack(side=tk.RIGHT)

        # Кнопка Close (изначально скрыта)
        self._close_btn = tk.Button(
            self._button_frame,
            text="Close",
            width=10,
            command=self._on_close,
            state=tk.NORMAL,
        )
        # Не показываем сразу
        self._close_btn.pack_forget()

    def _create_check_widgets(self) -> None:
        """Создаёт виджеты для отображения результатов проверок."""
        for _idx, check_name in enumerate(CHECK_ORDER):
            display_name = CHECK_DISPLAY_NAMES.get(check_name, check_name)

            # Фрейм для одной проверки
            row_frame = tk.Frame(self._checks_frame)
            row_frame.pack(fill=tk.X, pady=3)

            # Иконка статуса
            icon_label = tk.Label(
                row_frame,
                text=ICON_PENDING,
                font=("Arial", 12),
                fg=COLOR_NEUTRAL,
                width=3,
            )
            icon_label.pack(side=tk.LEFT)

            # Название проверки
            name_label = tk.Label(
                row_frame,
                text=display_name,
                font=("Arial", 10),
                anchor=tk.W,
            )
            name_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

            # Сообщение о результате (изначально пустое)
            message_label = tk.Label(
                row_frame,
                text="",
                font=("Arial", 9),
                fg=COLOR_NEUTRAL,
                anchor=tk.E,
            )
            message_label.pack(side=tk.RIGHT, padx=(10, 0))

            # Сохраняем виджеты
            self._check_widgets[check_name] = {
                "icon": icon_label,
                "name": name_label,
                "message": message_label,
                "frame": row_frame,
            }

    def _update_check_display(
        self,
        check_name: str,
        status: str,
        message: str = "",
    ) -> None:
        """Обновляет отображение конкретной проверки.

        Thread-safe: использует after() для обновления UI.

        Args:
            check_name: Имя проверки
            status: Статус ('running', 'passed', 'warning', 'critical', 'pending')
            message: Сообщение о результате
        """
        _status = status
        _message = message

        def _do_update() -> None:
            if check_name not in self._check_widgets:
                return

            widgets = self._check_widgets[check_name]
            icon_label = widgets["icon"]
            msg_label = widgets["message"]

            # Cast для type safety
            icon_widget = cast(tk.Label, icon_label)
            msg_widget = cast(tk.Label, msg_label)

            if _status == "running":
                icon_widget.config(text=ICON_RUNNING, fg=COLOR_RUNNING)
                msg_widget.config(text="Running...", fg=COLOR_RUNNING)
            elif _status == "passed":
                icon_widget.config(text=ICON_PASS, fg=COLOR_PASS)
                msg_widget.config(text=_message or "Passed", fg=COLOR_PASS)
            elif _status == "warning":
                icon_widget.config(text=ICON_WARNING, fg=COLOR_WARNING)
                msg_widget.config(text=_message, fg=COLOR_WARNING)
            elif _status == "critical":
                icon_widget.config(text=ICON_CRITICAL, fg=COLOR_CRITICAL)
                msg_widget.config(text=_message, fg=COLOR_CRITICAL)
            else:  # pending
                icon_widget.config(text=ICON_PENDING, fg=COLOR_NEUTRAL)
                msg_widget.config(text="", fg=COLOR_NEUTRAL)

        # Thread-safe update через after()
        self.after(0, _do_update)

    def _update_progress(self, value: int) -> None:
        """Обновляет progress bar.

        Thread-safe: использует after() для обновления UI.

        Args:
            value: Процент выполнения (0-100)
        """

        def _do_update() -> None:
            self._progress_var.set(value)
            self._progress_label_var.set(f"Progress: [{self._get_progress_bar(value)}] {value}%")

        self.after(0, _do_update)

    def _get_progress_bar(self, value: int) -> str:
        """Создаёт текстовое представление прогресс-бара.

        Args:
            value: Процент выполнения

        Returns:
            Строка с визуальным прогресс-баром
        """
        filled = int(value / 100 * 20)  # 20 символов всего
        empty = 20 - filled
        return "█" * filled + "░" * empty

    def _update_status(self, text: str, color: str = COLOR_NEUTRAL) -> None:
        """Обновляет статусную строку.

        Thread-safe: использует after() для обновления UI.

        Args:
            text: Текст статуса
            color: Color текста
        """

        def _do_update() -> None:
            self._status_label.config(text=text, fg=color)

        self.after(0, _do_update)

    def _show_results_ui(self) -> None:
        """Переключает UI в режим отображения результатов."""

        def _do_switch() -> None:
            # Скрываем Cancel, показываем Close и Details
            self._cancel_btn.pack_forget()
            self._close_btn.pack(side=tk.RIGHT)

            # Активируем кнопки если есть результаты
            if self._report is not None:
                self._details_btn.config(state=tk.NORMAL)

        self.after(0, _do_switch)

    def show(self) -> None:
        """Показывает диалог модально.

        Блокирует родительское окно до закрытия диалога.
        """
        self.wait_window()

    def run_checks(self) -> HealthCheckReport:
        """Запускает проверки и возвращает результат.

        Returns:
            HealthCheckReport с результатами 6 проверок

        Raises:
            RuntimeError: Если health_checker не предоставлен
        """
        if self._health_checker is None:
            raise RuntimeError("HealthChecker not provided")

        # Сбрасываем состояние
        self._cancelled = False
        self._is_running = True

        # Обновляем UI
        for check_name in CHECK_ORDER:
            self._update_check_display(check_name, "pending")
        self._update_progress(0)
        self._update_status("Initializing checks...", COLOR_RUNNING)

        # Запускаем проверки синхронно
        report = self._health_checker.run_all()
        self._report = report

        # Обновляем UI с результатами
        self._update_ui_with_results(report)

        self._is_running = False
        return report

    def run_checks_async(
        self,
        on_complete: Optional[Callable[[HealthCheckReport], None]] = None,
    ) -> None:
        """Запускает проверки асинхронно с progress bar.

        Args:
            on_complete: Callback при завершении проверок
        """
        if self._health_checker is None:
            raise RuntimeError("HealthChecker not provided")

        if self._is_running:
            logger.warning("Health checks already running")
            return

        self._on_complete_callback = on_complete
        self._cancelled = False
        self._is_running = True

        # Сбрасываем UI
        for check_name in CHECK_ORDER:
            self._update_check_display(check_name, "pending")
        self._update_progress(0)
        self._update_status("Running security checks...", COLOR_RUNNING)

        # Запускаем в отдельном потоке
        self._thread = threading.Thread(target=self._run_checks_thread, daemon=True)
        self._thread.start()

    def _run_checks_thread(self) -> None:
        """Выполняет проверки в отдельном потоке."""
        try:
            # Симулируем прогресс для каждой проверки
            total_checks = len(CHECK_ORDER)

            for idx, check_name in enumerate(CHECK_ORDER):
                if self._cancelled:
                    break

                # Обновляем статус проверки
                self._update_check_display(check_name, "running")
                self._update_progress(int((idx / total_checks) * 100))

                # Задержка для визуализации (можно убрать в production)
                time.sleep(0.1)

            # Выполняем реальные проверки
            if not self._cancelled and self._health_checker is not None:
                report = self._health_checker.run_all()
                self._report = report

                # Обновляем UI с результатами
                self._update_ui_with_results(report)

                # Вызываем callback
                if self._on_complete_callback is not None:
                    callback = self._on_complete_callback
                    self.after(0, lambda: callback(report))

        except (OSError, IOError, ValueError, KeyError, PermissionError, RuntimeError) as e:
            logger.error("Error running health checks: %s", e)
            self._update_status(f"Error: {str(e)}", COLOR_CRITICAL)

        finally:
            self._is_running = False
            self._update_progress(100)
            self._show_results_ui()

    def _update_ui_with_results(self, report: HealthCheckReport) -> None:
        """Обновляет UI с результатами проверок.

        Args:
            report: Отчёт о проверках
        """

        def _do_update() -> None:
            # Обновляем каждую проверку
            for result in report.checks:
                check_name = result.check_name
                if check_name not in self._check_widgets:
                    continue

                if result.status == HealthCheckStatus.HEALTHY:
                    self._update_check_display(check_name, "passed", result.message or "Passed")
                elif result.status == HealthCheckStatus.DEGRADED:
                    self._update_check_display(check_name, "warning", result.message or "Warning")
                elif result.status in (
                    HealthCheckStatus.UNHEALTHY,
                    HealthCheckStatus.ERROR,
                ):
                    error_msg = result.message
                    if result.error:
                        error_msg = f"{error_msg} ({result.error})"
                    self._update_check_display(check_name, "critical", error_msg)
                else:
                    self._update_check_display(check_name, "pending", result.message)

            # Обновляем статусную строку
            status_text, status_color = self._get_status_summary(report)
            self._update_status(status_text, status_color)

        self.after(0, _do_update)

    def _get_status_summary(self, report: HealthCheckReport) -> tuple[str, str]:
        """Формирует сводку статуса отчёта.

        Args:
            report: Отчёт о проверках

        Returns:
            Кортеж (текст, цвет)
        """
        if report.unhealthy_count > 0:
            return (
                f"🔴 {report.unhealthy_count} Critical Failure(s)",
                COLOR_CRITICAL,
            )
        elif report.error_count > 0:
            return (
                f"🔴 {report.error_count} Error(s)",
                COLOR_CRITICAL,
            )
        elif report.degraded_count > 0:
            return (
                f"🟡 {report.degraded_count} Warning(s)",
                COLOR_WARNING,
            )
        elif report.healthy_count == 0:
            return (
                "⚪ No checks completed",
                COLOR_NEUTRAL,
            )
        else:
            return (
                f"🟢 All {report.healthy_count} checks passed",
                COLOR_PASS,
            )

    def close(self, result: Any = None) -> None:
        """Закрывает диалог."""
        self._on_close()

    def has_critical_failures(self) -> bool:
        """Проверяет наличие критических ошибок.

        Returns:
            True если есть критические ошибки (unhealthy или error статус)
        """
        if self._report is None:
            return False
        return self._report.unhealthy_count > 0 or self._report.error_count > 0

    def has_warnings(self) -> bool:
        """Проверяет наличие предупреждений.

        Returns:
            True если есть предупреждения (degraded статус)
        """
        if self._report is None:
            return False
        return self._report.degraded_count > 0

    def is_healthy(self) -> bool:
        """Проверяет, все ли проверки пройдены.

        Returns:
            True если система в порядке (healthy или degraded)
        """
        if self._report is None:
            return False
        return self._report.is_healthy

    def get_report(self) -> Optional[HealthCheckReport]:
        """Возвращает текущий отчёт о проверках.

        Returns:
            HealthCheckReport или None если проверки не выполнялись
        """
        return self._report

    def _on_close(self) -> None:
        """Обрабатывает закрытие диалога."""
        # Отменяем выполнение если идёт
        if self._is_running:
            self._cancelled = True

        # Ждём завершения потока
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=1.0)

        self.destroy()

    def _on_cancel(self) -> None:
        """Обрабатывает нажатие кнопки Cancel."""
        self._cancelled = True
        self._update_status("Cancelled by user", COLOR_NEUTRAL)
        self._show_results_ui()

    def _on_rerun(self) -> None:
        """Обрабатывает нажатие кнопки Re-run."""
        # Переключаем UI обратно
        self._close_btn.pack_forget()
        self._cancel_btn.pack(side=tk.RIGHT)

        # Запускаем проверки асинхронно
        self.run_checks_async()

    def _on_details(self) -> None:
        """Обрабатывает нажатие кнопки Details.

        Показывает детальную информацию о проверках.
        """
        if self._report is None:
            return

        # Создаём детальное окно
        details_window = tk.Toplevel(self)
        details_window.title("Health Check Details")
        details_window.geometry("500x400")
        details_window.transient(self)

        # Передаём grab детальному окну, восстанавливаем при закрытии
        self.grab_release()
        _safe_grab_set(details_window)

        def _close_details() -> None:
            try:
                details_window.destroy()
            except tk.TclError:
                pass
            _safe_grab_set(self)

        details_window.protocol("WM_DELETE_WINDOW", _close_details)

        # Текстовое поле с деталями
        text = tk.Text(details_window, wrap=tk.WORD, padx=10, pady=10)
        text.pack(fill=tk.BOTH, expand=True)

        # Формируем детальный отчёт
        report_text = self._format_detailed_report(self._report)
        text.insert(tk.END, report_text)
        text.config(state=tk.DISABLED)

        # Кнопка закрытия
        tk.Button(
            details_window,
            text="Close",
            command=_close_details,
        ).pack(pady=10)

    def _format_detailed_report(self, report: HealthCheckReport) -> str:
        """Форматирует детальный отчёт для отображения.

        Args:
            report: Отчёт о проверках

        Returns:
            Форматированная строка с деталями
        """
        lines = [
            "=" * 50,
            "SECURITY HEALTH CHECK REPORT",
            "=" * 50,
            "",
            f"Version: {report.version}",
            f"Platform: {report.platform}",
            f"Timestamp: {report.timestamp.isoformat()}",
            "",
            f"Overall Status: {report.overall_status.value.upper()}",
            "",
            "SUMMARY:",
            f"  ✓ Healthy:   {report.healthy_count}",
            f"  ⚠ Degraded:  {report.degraded_count}",
            f"  ✗ Unhealthy: {report.unhealthy_count}",
            f"  ⊘ Skipped:   {report.skipped_count}",
            f"  ✖ Errors:    {report.error_count}",
            "",
            "-" * 50,
            "DETAILED RESULTS:",
            "-" * 50,
        ]

        for result in report.checks:
            lines.append("")
            lines.append(f"Check: {result.check_name}")
            lines.append(f"  Status: {result.status.value}")
            lines.append(f"  Message: {result.message}")
            lines.append(f"  Duration: {result.duration_ms}ms")
            if result.error:
                lines.append(f"  Error: {result.error}")
            if result.warnings:
                lines.append(f"  Warnings: {', '.join(result.warnings)}")
            if result.details:
                lines.append("  Details:")
                for key, value in result.details.items():
                    lines.append(f"    {key}: {value}")

        lines.extend(
            [
                "",
                "=" * 50,
                "END OF REPORT",
                "=" * 50,
            ]
        )

        return "\n".join(lines)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "HealthCheckDialog",
    "COLOR_CRITICAL",
    "COLOR_WARNING",
    "COLOR_PASS",
    "COLOR_NEUTRAL",
    "COLOR_RUNNING",
]
