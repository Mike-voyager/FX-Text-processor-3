"""Диалог настройки автоматической блокировки сессии для FX Text Processor 3.

Предоставляет интерфейс для настройки параметров автоблокировки:
- Включение/отключение автоблокировки
- Настройка таймаута бездействия (1-60 минут)
- Дополнительные параметры (MFA, очистка буфера, скрытие документов)
- Live-отображение времени бездействия

Интегрируется с AutoLockService и SessionLockManager.

Example:
    >>> from src.security.lock.session_lock_manager import LockConfig
    >>> from src.security.lock.auto_lock_service import AutoLockService
    >>> config = LockConfig(auto_lock_minutes=15, require_mfa_to_unlock=True)
    >>> dialog = AutoLockSettingsDialog(
    ...     parent=root,
    ...     current_config=config,
    ...     auto_lock_service=auto_lock_service,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Новый таймаут: {result.config.auto_lock_minutes} мин")

Version: 1.0
Security: CRITICAL-002
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk

# TYPE_CHECKING для избежания циклических импортов
from typing import TYPE_CHECKING, Callable, Final, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.themes import ThemeManager, get_theme_manager
from src.security.lock.session_lock_manager import LockConfig

if TYPE_CHECKING:
    from src.security.lock.auto_lock_service import AutoLockService

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 600

# Colors (fallback, если ThemeManager недоступен)
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_FG: Final[str] = "#2c3e50"
COLOR_ACCENT: Final[str] = "#3498db"
COLOR_WARNING: Final[str] = "#f39c12"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_SUCCESS: Final[str] = "#27ae60"
COLOR_BORDER: Final[str] = "#bdc3c7"

# Пресеты таймаута (в минутах)
TIMEOUT_PRESETS: Final[list[tuple[str, int]]] = [
    ("1 min", 1),
    ("5", 5),
    ("15", 15),
    ("30", 30),
    ("60", 60),
    ("Never", 0),
]

# Интервал обновления idle time (мс)
IDLE_UPDATE_INTERVAL: Final[int] = 1000


# =============================================================================
# RESULT DATA CLASS
# =============================================================================


@dataclass(frozen=True)
class AutoLockSettingsResult:
    """Результат настройки автоблокировки.

    Attributes:
        config: Новая конфигурация блокировки
        restart_service: Требуется ли перезапуск AutoLockService

    Example:
        >>> result = AutoLockSettingsResult(
        ...     config=LockConfig(auto_lock_minutes=30),
        ...     restart_service=True,
        ... )
    """

    config: LockConfig
    restart_service: bool


# =============================================================================
# DIALOG CLASS
# =============================================================================


class AutoLockSettingsDialog(BaseDialog):
    """Диалог настройки автоматической блокировки сессии.

    Attributes:
        _parent: Родительский виджет (обычно tk.Tk)
        _current_config: Текущая конфигурация блокировки
        _auto_lock_service: Сервис автоблокировки (опционально)
        _theme_manager: Менеджер тем для стилизации
        _result: Результат диалога
        _modified: Флаг изменения настроек

        # UI References
        _master_var: Variable для master switch
        _timeout_var: Variable для значения таймаута
        _timeout_scale: Slider таймаута
        _timeout_label: Метка текущего значения таймаута
        _preset_buttons: Список кнопок пресетов
        _checkboxes: Словарь чекбоксов опций
        _warning_label: Метка предупреждения о MFA
        _status_label: Метка статуса с idle time
        _idle_timer_id: ID таймера обновления idle

    Example:
        >>> dialog = AutoLockSettingsDialog(
        ...     parent=root,
        ...     current_config=LockConfig(),
        ... )
        >>> result = dialog.show()
    """

    def __init__(
        self,
        parent: tk.Tk,
        current_config: LockConfig,
        auto_lock_service: Optional["AutoLockService"] = None,
    ) -> None:
        """Инициализация диалога настройки автоблокировки.

        Args:
            parent: Родительское окно (обычно tk.Tk)
            current_config: Текущая конфигурация блокировки
            auto_lock_service: Сервис автоблокировки для live-обновлений
        """
        super().__init__(parent)

        self._parent: tk.Tk = parent
        self._current_config: LockConfig = current_config
        self._auto_lock_service: Optional["AutoLockService"] = auto_lock_service
        self._theme_manager: ThemeManager = get_theme_manager()

        # Result state
        self._result: Optional[AutoLockSettingsResult] = None
        self._modified: bool = False

        # UI Variables
        self._master_var: tk.BooleanVar = tk.BooleanVar(master=self, value=current_config.enabled)
        self._timeout_var: tk.IntVar = tk.IntVar(
            master=self, value=current_config.auto_lock_minutes
        )

        # Checkbox variables
        self._checkbox_vars: dict[str, tk.BooleanVar] = {
            "lock_on_sleep": tk.BooleanVar(master=self, value=current_config.lock_on_sleep),
            "lock_on_screensaver": tk.BooleanVar(
                master=self, value=current_config.lock_on_screensaver
            ),
            "require_mfa_to_unlock": tk.BooleanVar(
                master=self, value=current_config.require_mfa_to_unlock
            ),
            "clear_clipboard_on_lock": tk.BooleanVar(
                master=self, value=current_config.clear_clipboard_on_lock
            ),
            "hide_documents_on_lock": tk.BooleanVar(
                master=self, value=current_config.hide_documents_on_lock
            ),
        }

        # UI References (initialized in _create_ui)
        self._timeout_scale: Optional[tk.Scale] = None
        self._timeout_label: Optional[tk.Label] = None
        self._preset_buttons: list[tk.Button] = []
        self._master_checkbox: tk.Checkbutton = None  # type: ignore[assignment]
        self._options_frame: Optional[tk.LabelFrame] = None
        self._warning_label: Optional[tk.Label] = None
        self._status_label: Optional[tk.Label] = None
        self._idle_timer_id: Optional[str] = None
        self._save_btn: tk.Button = None  # type: ignore[assignment]

        # Configure window
        self._configure_window()

        # Create UI
        self._create_ui()

        # Apply theme
        self._apply_theme()

        # Center window

        # Bind events
        self._bind_events()

        # Initial UI update
        self._update_ui_state()

    def _configure_window(self) -> None:
        """Настраивает параметры окна диалога."""
        self.title("⏱️ Auto-Lock Settings")
        self.resizable(False, False)

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        parent_x = self._parent.winfo_rootx()
        parent_y = self._parent.winfo_rooty()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2

        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")

    def _bind_events(self) -> None:
        """Привязывает события клавиатуры и другие обработчики."""
        # ESC для закрытия

        # Обработка изменений переменных
        self._master_var.trace_add("write", lambda *_: self._on_master_changed())
        self._timeout_var.trace_add("write", lambda *_: self._on_timeout_var_changed())

        for var in self._checkbox_vars.values():
            var.trace_add("write", lambda *_: self._on_checkbox_changed())

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс диалога."""
        # Main container
        main_frame = tk.Frame(self, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self._create_header(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Master switch
        self._create_master_switch(main_frame)

        # Timeout slider
        self._create_timeout_slider(main_frame)

        # Preset buttons
        preset_frame = self._get_preset_buttons(main_frame)
        preset_frame.pack(fill=tk.X, pady=(0, 15))

        # Options checkboxes
        self._create_checkboxes(main_frame)

        # Separator before status
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Status bar with idle time
        self._create_status_bar(main_frame)

        # Separator before buttons
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Buttons
        self._create_buttons(main_frame)

    def _create_header(self, parent: tk.Widget) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский виджет.
        """
        header_frame = tk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 5))

        tk.Label(
            header_frame,
            text="⏱️ Auto-Lock Settings",
            font=("Arial", 14, "bold"),
            fg=COLOR_FG,
        ).pack(anchor=tk.W)

        tk.Label(
            header_frame,
            text="Configure automatic session lock settings",
            font=("Arial", 9),
            fg="#7f8c8d",
        ).pack(anchor=tk.W, pady=(5, 0))

    def _create_master_switch(self, parent: tk.Widget) -> None:
        """Создаёт master switch для включения автоблокировки.

        Args:
            parent: Родительский виджет.
        """
        switch_frame = tk.Frame(parent)
        switch_frame.pack(fill=tk.X, pady=(0, 15))

        self._master_checkbox = tk.Checkbutton(
            switch_frame,
            text="Enable auto-lock",
            variable=self._master_var,
            font=("Arial", 10, "bold"),
            fg=COLOR_FG,
        )
        self._master_checkbox.pack(anchor=tk.W)

        tk.Label(
            switch_frame,
            text="Session will be automatically locked after a period of inactivity",
            font=("Arial", 8),
            fg="#7f8c8d",
        ).pack(anchor=tk.W, padx=(20, 0))

    def _create_timeout_slider(self, parent: tk.Widget) -> None:
        """Создаёт слайдер для настройки таймаута.

        Args:
            parent: Родительский виджет.
        """
        timeout_frame = tk.LabelFrame(
            parent,
            text="Idle Timeout",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10,
        )
        timeout_frame.pack(fill=tk.X, pady=(0, 10))

        # Current value label
        self._timeout_label = tk.Label(
            timeout_frame,
            text=self._format_timeout(self._timeout_var.get()),
            font=("Arial", 11, "bold"),
            fg=COLOR_ACCENT,
        )
        self._timeout_label.pack(anchor=tk.W, pady=(0, 10))

        # Scale widget
        self._timeout_scale = tk.Scale(
            timeout_frame,
            from_=1,
            to=60,
            orient=tk.HORIZONTAL,
            variable=self._timeout_var,
            command=self._on_timeout_changed,
            showvalue=False,
            length=350,
        )
        self._timeout_scale.pack(fill=tk.X)

        # Scale labels
        scale_labels = tk.Frame(timeout_frame)
        scale_labels.pack(fill=tk.X)

        tk.Label(scale_labels, text="1 min", font=("Arial", 8), fg="#7f8c8d").pack(side=tk.LEFT)
        tk.Label(scale_labels, text="30 min", font=("Arial", 8), fg="#7f8c8d").pack(
            side=tk.LEFT, expand=True
        )
        tk.Label(scale_labels, text="60 min", font=("Arial", 8), fg="#7f8c8d").pack(side=tk.RIGHT)

    def _get_preset_buttons(self, parent: tk.Widget) -> tk.Frame:
        """Создаёт кнопки пресетов для быстрого выбора таймаута.

        Args:
            parent: Родительский виджет.

        Returns:
            Frame с кнопками пресетов.
        """
        preset_frame = tk.Frame(parent)

        tk.Label(preset_frame, text="Quick select:", font=("Arial", 9), fg="#7f8c8d").pack(
            side=tk.LEFT, padx=(0, 10)
        )

        for label_text, minutes in TIMEOUT_PRESETS:
            btn = tk.Button(
                preset_frame,
                text=label_text,
                font=("Arial", 8),
                width=8,
                command=cast(Callable[[], None], lambda m=minutes: self._apply_preset(m)),  # noqa: B023
            )
            btn.pack(side=tk.LEFT, padx=(0, 5))
            self._preset_buttons.append(btn)

        return preset_frame

    def _create_checkboxes(self, parent: tk.Widget) -> None:
        """Создаёт чекбоксы дополнительных параметров.

        Args:
            parent: Родительский виджет.
        """
        self._options_frame = tk.LabelFrame(
            parent,
            text="Additional Options",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10,
        )
        self._options_frame.pack(fill=tk.X, pady=(0, 10))

        options = [
            ("lock_on_sleep", "Lock on system sleep"),
            ("lock_on_screensaver", "Lock on screensaver"),
            ("require_mfa_to_unlock", "Require MFA to unlock"),
            ("clear_clipboard_on_lock", "Clear clipboard on lock"),
            ("hide_documents_on_lock", "Hide documents on lock"),
        ]

        for key, text in options:
            cb = tk.Checkbutton(
                self._options_frame,
                text=text,
                variable=self._checkbox_vars[key],
                font=("Arial", 9),
                fg=COLOR_FG,
            )
            cb.pack(anchor=tk.W, pady=2)

        # Warning label for MFA
        self._warning_label = tk.Label(
            self._options_frame,
            text="⚠️ Session is less protected without MFA",
            font=("Arial", 8, "italic"),
            fg=COLOR_WARNING,
        )
        self._warning_label.pack(anchor=tk.W, padx=(20, 0), pady=(0, 5))

        # Initial warning state
        self._update_warning()

    def _create_status_bar(self, parent: tk.Widget) -> None:
        """Создаёт статус-бар с отображением idle time.

        Args:
            parent: Родительский виджет.
        """
        status_frame = tk.Frame(parent)
        status_frame.pack(fill=tk.X)

        self._status_label = tk.Label(
            status_frame,
            text="Status: Waiting...",
            font=("Arial", 9),
            fg="#7f8c8d",
        )
        self._status_label.pack(side=tk.LEFT)

        # Start idle update timer
        self._update_idle_display()

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки диалога (Отмена, Сохранить).

        Args:
            parent: Родительский виджет.
        """
        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill=tk.X)

        # Spacer
        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Cancel button
        cancel_btn = tk.Button(
            btn_frame,
            text="❌ Cancel",
            width=12,
            command=self._on_cancel,
            font=("Arial", 9),
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Save button
        self._save_btn = tk.Button(
            btn_frame,
            text="✓ Save",
            width=12,
            command=self._save_settings,
            font=("Arial", 9, "bold"),
            bg=COLOR_ACCENT,
            fg="white",
        )
        self._save_btn.pack(side=tk.RIGHT)

    def _apply_theme(self) -> None:
        """Применяет текущую тему к виджетам диалога."""
        try:
            theme = self._theme_manager.get_current_theme()

            # Apply to main widgets
            for widget in [self]:
                try:
                    widget.configure(bg=theme.bg_color)
                except tk.TclError:
                    pass

            # Apply to frames
            for frame in self.winfo_children():
                if isinstance(frame, tk.Frame):
                    try:
                        frame.configure(bg=theme.bg_color)
                    except tk.TclError:
                        pass

                    # Apply to frame children
                    for child in frame.winfo_children():
                        self._theme_manager.apply_to_widget(child)

        except Exception as e:
            logger.warning("Failed to apply theme: %s", e)

    def _format_timeout(self, minutes: int) -> str:
        """Форматирует значение таймаута для отображения.

        Args:
            minutes: Количество минут.

        Returns:
            Отформатированная строка (например, "15 минут").
        """
        if minutes == 0:
            return "Never"
        if minutes == 1:
            return "1 minute"
        return f"{minutes} minutes"

    def _on_timeout_changed(self, value: str) -> None:
        """Обработчик изменения значения слайдера.

        Args:
            value: Новое значение (строка от tk.Scale).
        """
        try:
            minutes = int(float(value))
            self._timeout_var.set(minutes)

            if self._timeout_label is not None:
                self._timeout_label.config(text=self._format_timeout(minutes))

            self._modified = True

        except ValueError:
            pass

    def _on_timeout_var_changed(self) -> None:
        """Обработчик изменения переменной таймаута."""
        minutes = self._timeout_var.get()

        if self._timeout_label is not None:
            self._timeout_label.config(text=self._format_timeout(minutes))

        # Sync scale if needed
        if self._timeout_scale is not None:
            try:
                current_scale = int(self._timeout_scale.get())
                if current_scale != minutes:
                    self._timeout_scale.set(minutes)
            except tk.TclError:
                pass

    def _apply_preset(self, minutes: int) -> None:
        """Применяет пресет таймаута.

        Args:
            minutes: Значение таймаута в минутах (0 для "Никогда").
        """
        self._timeout_var.set(minutes if minutes > 0 else 1)

        if minutes == 0:
            # "Никогда" - отключаем автоблокировку
            self._master_var.set(False)

        self._modified = True
        self._update_ui_state()

    def _on_master_changed(self) -> None:
        """Обработчик изменения master switch."""
        self._update_ui_state()
        self._modified = True

    def _on_checkbox_changed(self) -> None:
        """Обработчик изменения чекбоксов."""
        self._update_warning()
        self._modified = True

    def _update_ui_state(self) -> None:
        """Обновляет состояние UI элементов в зависимости от master switch."""
        enabled = self._master_var.get()

        # Enable/disable timeout controls
        if self._timeout_scale is not None:
            if enabled:
                self._timeout_scale.configure(state="normal")
            else:
                self._timeout_scale.configure(state="disabled")

        if self._timeout_label is not None:
            self._timeout_label.config(fg=COLOR_ACCENT if enabled else "#bdc3c7")

        # Enable/disable preset buttons
        for btn in self._preset_buttons:
            btn.config(state=tk.NORMAL if enabled else tk.DISABLED)

        # Enable/disable options frame
        if self._options_frame is not None:
            for child in self._options_frame.winfo_children():
                if isinstance(child, tk.Checkbutton):
                    child.config(state=tk.NORMAL if enabled else tk.DISABLED)

        self._update_warning()

    def _update_warning(self) -> None:
        """Обновляет отображение предупреждения о MFA."""
        if self._warning_label is None:
            return

        enabled = self._master_var.get()
        require_mfa = self._checkbox_vars["require_mfa_to_unlock"].get()

        if not enabled:
            self._warning_label.config(text="", fg=COLOR_WARNING)
        elif not require_mfa:
            self._warning_label.config(
                text="⚠️ Session is less protected without MFA",
                fg=COLOR_WARNING,
            )
        else:
            self._warning_label.config(
                text="✓ MFA protection enabled",
                fg=COLOR_SUCCESS,
            )

    def _update_idle_display(self) -> None:
        """Обновляет отображение текущего idle time.

        Вызывается периодически для live-обновления статуса.
        """
        if self._status_label is None or not self.winfo_exists():
            return

        try:
            status_text = "Status: "

            # Get auto-lock service state
            if self._auto_lock_service is not None:
                from src.security.lock.auto_lock_service import AutoLockState

                state = self._auto_lock_service.get_state()
                idle_minutes = 0.0

                # Try to get idle time from lock manager
                try:
                    idle_minutes = self._auto_lock_service._lock_manager.get_idle_time_minutes()
                except Exception as e:
                    logging.getLogger(__name__).exception(
                        "Exception ignored during idle time retrieval: %s", e
                    )

                state_text = {
                    AutoLockState.STOPPED: "Stopped",
                    AutoLockState.RUNNING: "Active",
                    AutoLockState.PAUSED: "Paused",
                    AutoLockState.LOCKING: "Locking...",
                }.get(state, "Unknown")

                idle_str = f"{int(idle_minutes)} min {int((idle_minutes % 1) * 60)} sec"
                status_text += f"{state_text}, idle: {idle_str}"
            else:
                status_text += "Service unavailable"

            self._status_label.config(text=status_text)

        except Exception as e:
            logger.debug("Error updating idle display: %s", e)
            self._status_label.config(text="Status: Update error")

        # Schedule next update
        if self.winfo_exists():
            self._idle_timer_id = self.after(IDLE_UPDATE_INTERVAL, self._update_idle_display)
            if self._idle_timer_id is not None:
                self._after_ids.append(self._idle_timer_id)

    def _save_settings(self) -> None:
        """Сохраняет настройки и закрывает диалог."""
        # Create new config
        new_config = LockConfig(
            enabled=self._master_var.get(),
            auto_lock_minutes=self._timeout_var.get(),
            lock_on_sleep=self._checkbox_vars["lock_on_sleep"].get(),
            lock_on_screensaver=self._checkbox_vars["lock_on_screensaver"].get(),
            require_mfa_to_unlock=self._checkbox_vars["require_mfa_to_unlock"].get(),
            clear_clipboard_on_lock=self._checkbox_vars["clear_clipboard_on_lock"].get(),
            hide_documents_on_lock=self._checkbox_vars["hide_documents_on_lock"].get(),
        )

        # Determine if service restart needed
        restart_needed = self._check_restart_required(new_config)

        # Apply to auto-lock service if available
        if self._auto_lock_service is not None:
            try:
                self._auto_lock_service._lock_manager.update_config(new_config)

                # Handle enable/disable
                if new_config.enabled and not self._auto_lock_service.is_running():
                    self._auto_lock_service.start()
                elif not new_config.enabled and self._auto_lock_service.is_running():
                    self._auto_lock_service.stop()

            except Exception as e:
                logger.error("Failed to update auto-lock service: %s", e)

        self._result = AutoLockSettingsResult(
            config=new_config,
            restart_service=restart_needed,
        )

        # Cancel idle timer
        if self._idle_timer_id is not None:
            self.after_cancel(self._idle_timer_id)

        self.close(self._result)

    def _check_restart_required(self, new_config: LockConfig) -> bool:
        """Проверяет, требуется ли перезапуск сервиса.

        Args:
            new_config: Новая конфигурация.

        Returns:
            True если необходим перезапуск.
        """
        old = self._current_config

        # Restart needed if enabled state changed
        if old.enabled != new_config.enabled:
            return True

        # Restart needed if timeout changed significantly
        if old.auto_lock_minutes != new_config.auto_lock_minutes:
            return True

        return False

    def _on_cancel(self) -> None:
        """Обработчик отмены - закрывает диалог без сохранения."""
        # Cancel idle timer
        if self._idle_timer_id is not None:
            self.after_cancel(self._idle_timer_id)

        self.close(None)

    def show(self) -> Optional[AutoLockSettingsResult]:
        """Показывает диалог модально и возвращает результат.

        Returns:
            AutoLockSettingsResult с новой конфигурацией или None если отменено.
        """
        super().show()
        return self._result


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "AutoLockSettingsDialog",
    "AutoLockSettingsResult",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
]
