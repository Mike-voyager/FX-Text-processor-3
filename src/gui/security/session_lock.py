"""Полноэкранный UI блокировки сессии для FX Text Processor 3.

Компонент отображает экран блокировки с возможностью разблокировки
через пароль + MFA. Работает в полноэкранном режиме, блокирует
весь ввод до успешной аутентификации.

Architecture:
    - View Layer: наследуется от tk.Toplevel
    - Интеграция с SessionLockManager через callbacks
    - MFAGate для MFA challenge
    - ThemeManager для стилизации

Example:
    >>> from src.gui.security.session_lock import SessionLockScreen
    >>> lock_screen = SessionLockScreen(
    ...     parent=root,
    ...     lock_manager=session_lock_manager,
    ...     mfa_gate=mfa_gate,
    ... )
    >>> lock_screen.show()

Security:
    - Очищает поля ввода при неудачной попытке
    - Блокирует ESC пока сессия заблокирована
    - Не закрывается по Alt+F4 без авторизации

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from datetime import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from src.gui.security.mfa_gate import MFAGate
    from src.security.lock.session_lock_manager import (
        LockReason,
        SessionLockManager,
        UnlockResult,
    )

from src.gui.themes import get_theme_manager

logger = logging.getLogger(__name__)


class SessionLockScreen(tk.Toplevel):
    """Полноэкранный экран блокировки сессии.

    Отображает fullscreen overlay с формой разблокировки.
    Требует пароль + MFA для разблокировки сессии.

    Attributes:
        _parent: Родительское окно (tk.Tk).
        _lock_manager: Менеджер блокировки сессии.
        _mfa_gate: MFAGate для MFA верификации (опционально).
        _theme_manager: Менеджер тем для стилизации.
        _password_var: Переменная для поля пароля.
        _mfa_var: Переменная для поля MFA кода.
        _password_visible: Флаг видимости пароля.
        _is_unlocking: Флаг процесса разблокировки.
        _locked_at: Время блокировки для отображения.
        _lock_reason: Причина блокировки.
        _update_job_id: ID запланированного обновления idle time.

    Security:
        - Поля очищаются при каждой неудачной попытке.
        - ESC не закрывает окно пока сессия заблокирована.
        - Пароль скрыт по умолчанию (show="*").

    Example:
        >>> lock_screen = SessionLockScreen(root, lock_manager)
        >>> lock_screen.show()
        # Экран блокировки отображается fullscreen
    """

    def __init__(
        self,
        parent: tk.Tk,
        lock_manager: "SessionLockManager",
        mfa_gate: Optional["MFAGate"] = None,
    ) -> None:
        """Инициализация экрана блокировки сессии.

        Args:
            parent: Родительское окно (root).
            lock_manager: Менеджер блокировки сессии.
            mfa_gate: MFAGate для MFA верификации (опционально).

        Example:
            >>> lock_screen = SessionLockScreen(root, lock_manager, mfa_gate)
        """
        super().__init__(parent)

        self._parent: tk.Tk = parent
        self._lock_manager: "SessionLockManager" = lock_manager
        self._mfa_gate: Optional["MFAGate"] = mfa_gate
        self._theme_manager = get_theme_manager()

        # Переменные формы
        self._password_var = tk.StringVar()
        self._mfa_var = tk.StringVar()
        self._mfa_method_var = tk.StringVar(value="fido2")
        self._password_visible = False
        self._is_unlocking = False

        # Данные блокировки
        self._locked_at: Optional[datetime] = None
        self._lock_reason: Optional["LockReason"] = None

        # UI элементы
        self._password_entry: Optional[tk.Entry] = None
        self._mfa_entry: Optional[tk.Entry] = None
        self._toggle_btn: Optional[tk.Button] = None
        self._unlock_btn: Optional[tk.Button] = None
        self._error_label: Optional[tk.Label] = None
        self._reason_label: Optional[tk.Label] = None
        self._locked_time_label: Optional[tk.Label] = None
        self._idle_time_label: Optional[tk.Label] = None

        # Job ID для отмены обновления
        self._update_job_id: Optional[str] = None

        # Настройка окна
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает базовые параметры окна."""
        # Настройки fullscreen
        self.attributes("-fullscreen", True)
        self.attributes("-topmost", True)

        # Запрещаем закрытие стандартными средствами
        self.protocol("WM_DELETE_WINDOW", self._on_close_attempt)

        # Применяем тему к окну
        theme = self._theme_manager.get_current_theme()
        self.configure(bg=theme.bg_color)

    def _on_close_attempt(self) -> None:
        """Обработчик попытки закрытия окна.

        Security:
            Игнорирует попытку закрытия пока сессия заблокирована.
        """
        # Не закрываем, пока сессия заблокирована
        logger.debug("Close attempt blocked: session is locked")

    def show(self) -> None:
        """Показывает экран блокировки fullscreen.

        Создаёт UI элементы, устанавливает fullscreen режим
        и начинает отслеживание времени простоя.

        Example:
            >>> lock_screen.show()
            # Экран блокировки активен
        """
        # Получаем данные о блокировке
        self._locked_at = self._lock_manager.get_locked_at()
        self._lock_reason = self._lock_manager.get_lock_reason()

        # Создаём UI
        self._create_ui()

        # Захватываем фокус
        self.grab_set()
        self.focus_force()

        # Устанавливаем fullscreen
        self.attributes("-fullscreen", True)

        # Биндим ESC (не закрывает, только сообщает)
        self.bind("<Escape>", self._on_escape)

        # Биндим Enter на обеих полях
        if self._password_entry:
            self._password_entry.bind("<Return>", lambda e: self._focus_mfa())
        if self._mfa_entry:
            self._mfa_entry.bind("<Return>", lambda e: self._on_unlock())

        # Фокус на поле пароля
        if self._password_entry:
            self._password_entry.focus_set()

        # Начинаем обновление idle time
        self._schedule_idle_update()

        logger.info(
            "Session lock screen shown (reason=%s)",
            self._lock_reason.value if self._lock_reason else "unknown",
        )

    def hide(self) -> None:
        """Скрывает экран блокировки.

        Вызывается при успешной разблокировке.
        Очищает sensitive данные и уничтожает окно.

        Example:
            >>> lock_screen.hide()
            # Экран блокировки скрыт
        """
        # Отменяем обновление idle time
        if self._update_job_id:
            try:
                self.after_cancel(self._update_job_id)
            except (tk.TclError, ValueError) as e:
                logging.getLogger(__name__).debug("Exception ignored: %s", e)
            self._update_job_id = None

        # Очищаем поля
        self.wipe_credentials()

        # Снимаем fullscreen
        self.attributes("-fullscreen", False)
        self.attributes("-topmost", False)

        # Уничтожаем окно
        self.destroy()

        logger.info("Session lock screen hidden")

    def is_locked(self) -> bool:
        """Проверяет состояние блокировки.

        Returns:
            True если сессия заблокирована.

        Example:
            >>> if lock_screen.is_locked():
            ...     print("Сессия заблокирована")
        """
        return self._lock_manager.is_locked()

    def _create_ui(self) -> None:
        """Создаёт UI элементы экрана блокировки.

        Создаёт центрированную панель с:
        - Иконкой и заголовком
        - Информацией о блокировке
        - Полем пароля (скрытое + кнопка 👁)
        - Полем MFA кода
        - Кнопкой разблокировки
        - Областью ошибок
        """
        theme = self._theme_manager.get_current_theme()

        # Главный контейнер (центрируем содержимое)
        main_frame = tk.Frame(
            self,
            bg=theme.bg_color,
        )
        main_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Иконка замка и заголовок
        header_frame = tk.Frame(main_frame, bg=theme.bg_color)
        header_frame.pack(pady=(0, 30))

        lock_icon = tk.Label(
            header_frame,
            text="🔒 Session Locked",
            font=(theme.font_family, theme.font_size + 8, "bold"),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        lock_icon.pack()

        # Subtitle
        subtitle_label = tk.Label(
            header_frame,
            text="Document is protected and hidden.",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        subtitle_label.pack(pady=(5, 0))

        # Информация о блокировке
        info_frame = tk.Frame(main_frame, bg=theme.bg_color)
        info_frame.pack(pady=(0, 20))

        # Причина блокировки
        reason_text = self._get_lock_reason_text()
        self._reason_label = tk.Label(
            info_frame,
            text=f"Причина: {reason_text}",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        self._reason_label.pack(pady=2)

        # Время блокировки
        locked_time_text = self._get_locked_time_text()
        self._locked_time_label = tk.Label(
            info_frame,
            text=f"Заблокировано: {locked_time_text}",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        self._locked_time_label.pack(pady=2)

        # Время простоя (обновляется)
        self._idle_time_label = tk.Label(
            info_frame,
            text="Время простоя: 0 мин",
            font=(theme.font_family, theme.font_size - 1),
            bg=theme.bg_color,
            fg=theme.accent_color,
        )
        self._idle_time_label.pack(pady=2)

        # Разделительная линия (визуальная)
        separator = tk.Frame(
            main_frame,
            height=1,
            bg=theme.border_color,
        )
        separator.pack(fill=tk.X, pady=20)

        # Форма разблокировки
        form_frame = tk.Frame(main_frame, bg=theme.bg_color)
        form_frame.pack(fill=tk.X, padx=40)

        # Поле пароля
        password_frame = tk.Frame(form_frame, bg=theme.bg_color)
        password_frame.pack(fill=tk.X, pady=10)

        password_label = tk.Label(
            password_frame,
            text="Password:",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            width=12,
            anchor=tk.E,
        )
        password_label.pack(side=tk.LEFT, padx=(0, 10))

        self._password_entry = tk.Entry(
            password_frame,
            textvariable=self._password_var,
            show="*",
            font=(theme.font_family, theme.font_size + 2),
            bg=theme.bg_color,
            fg=theme.fg_color,
            insertbackground=theme.fg_color,
            selectbackground=theme.accent_color,
            selectforeground=theme.bg_color,
            width=30,
        )
        self._password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Кнопка показа/скрытия пароля
        self._toggle_btn = tk.Button(
            password_frame,
            text="👁",
            command=self._toggle_password_visibility,
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            padx=8,
        )
        self._toggle_btn.pack(side=tk.LEFT, padx=(5, 0))

        # Поле MFA кода с выбором метода
        mfa_frame = tk.Frame(form_frame, bg=theme.bg_color)
        mfa_frame.pack(fill=tk.X, pady=10)

        # Метка метода
        mfa_method_label = tk.Label(
            mfa_frame,
            text="Method:",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        mfa_method_label.pack(side=tk.LEFT, padx=(0, 5))

        # Выбор метода MFA
        self._mfa_method_var = tk.StringVar(value="fido2")
        
        fido2_radio = tk.Radiobutton(
            mfa_frame,
            text="🔐 FIDO2",
            variable=self._mfa_method_var,
            value="fido2",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            selectcolor=theme.accent_color,
        )
        fido2_radio.pack(side=tk.LEFT, padx=(5, 0))

        totp_radio = tk.Radiobutton(
            mfa_frame,
            text="⏱️ TOTP",
            variable=self._mfa_method_var,
            value="totp",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            selectcolor=theme.accent_color,
        )
        totp_radio.pack(side=tk.LEFT, padx=(5, 0))

        self._mfa_entry = tk.Entry(
            mfa_frame,
            textvariable=self._mfa_var,
            font=(theme.font_family, theme.font_size + 2),
            bg=theme.bg_color,
            fg=theme.fg_color,
            insertbackground=theme.fg_color,
            selectbackground=theme.accent_color,
            selectforeground=theme.bg_color,
            width=20,
        )
        self._mfa_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Подсказка для MFA
        mfa_hint = tk.Label(
            mfa_frame,
            text="(Touch key or enter 6-digit code)",
            font=(theme.font_family, theme.font_size - 2),
            bg=theme.bg_color,
            fg=theme.accent_color,
        )
        mfa_hint.pack(side=tk.LEFT, padx=(10, 0))

        # Область ошибок
        self._error_label = tk.Label(
            form_frame,
            text="",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.error_color,
        )
        self._error_label.pack(pady=(15, 0))

        # Кнопка разблокировки
        button_frame = tk.Frame(form_frame, bg=theme.bg_color)
        button_frame.pack(pady=30)

        self._unlock_btn = tk.Button(
            button_frame,
            text="🔓 Разблокировать",
            command=self._on_unlock,
            font=(theme.font_family, theme.font_size + 2, "bold"),
            bg=theme.accent_color,
            fg=theme.bg_color,
            padx=30,
            pady=10,
            cursor="hand2",
            relief=tk.RAISED,
            bd=2,
        )
        self._unlock_btn.pack()

    def _get_lock_reason_text(self) -> str:
        """Возвращает текстовое описание причины блокировки.

        Returns:
            Человекочитаемое описание причины.
        """
        if self._lock_reason is None:
            return "Неизвестно"

        reason_map = {
            "manual": "Ручная блокировка",
            "auto_lock": "Автоматическая блокировка",
            "system_sleep": "Блокировка при засыпании системы",
            "screensaver": "Блокировка при скринсейвере",
            "security_policy": "Блокировка по политике безопасности",
        }
        return reason_map.get(self._lock_reason.value, "Неизвестно")

    def _get_locked_time_text(self) -> str:
        """Возвращает время блокировки в читаемом формате.

        Returns:
            Время блокировки как строка (HH:MM:SS).
        """
        if self._locked_at is None:
            return "Неизвестно"

        # Конвертируем UTC в local time для отображения
        local_time = self._locked_at.astimezone()
        return local_time.strftime("%H:%M:%S")

    def _update_idle_time(self) -> None:
        """Обновляет отображение времени простоя.

        Вызывается периодически для обновления idle time label.
        """
        if not self._lock_manager.is_locked():
            return

        idle_minutes = self._lock_manager.get_idle_time_minutes()
        idle_text = f"Время простоя: {int(idle_minutes)} мин {int((idle_minutes % 1) * 60)} сек"

        if self._idle_time_label and self._idle_time_label.winfo_exists():
            self._idle_time_label.configure(text=idle_text)

        # Планируем следующее обновление через 1 секунду
        self._schedule_idle_update()

    def _schedule_idle_update(self) -> None:
        """Планирует следующее обновление idle time."""
        try:
            self._update_job_id = self.after(1000, self._update_idle_time)
        except Exception as e:
            logging.getLogger(__name__).debug("Exception ignored: %s", e)

    def _toggle_password_visibility(self) -> None:
        """Переключает видимость пароля.

        Переключает show/hide для поля пароля между "*" и "".

        Security:
            Обновляет кнопку эмодзи для визуальной обратной связи.
        """
        if self._password_entry is None:
            return

        self._password_visible = not self._password_visible
        show_char = "" if self._password_visible else "*"
        self._password_entry.configure(show=show_char)

        # Обновляем текст кнопки
        if self._toggle_btn is not None:
            btn_text = "🙈" if self._password_visible else "👁"
            self._toggle_btn.configure(text=btn_text)

    def _focus_mfa(self) -> None:
        """Переносит фокус на поле MFA кода."""
        if self._mfa_entry:
            self._mfa_entry.focus_set()

    def _on_unlock(self) -> None:
        """Обработчик нажатия кнопки разблокировки.

        Проверяет введённые данные, вызывает разблокировку
        через SessionLockManager, при неудаче очищает поля.

        Security:
            - Очищает поля при любой ошибке.
            - Блокирует повторные попытки во время обработки.
        """
        if self._is_unlocking:
            return

        self._clear_error()

        password = self._password_var.get()
        mfa_code = self._mfa_var.get()

        # Валидация ввода
        if not password:
            self._show_error("Введите пароль")
            if self._password_entry:
                self._password_entry.focus_set()
            return

        if not mfa_code:
            self._show_error("Введите MFA код")
            if self._mfa_entry:
                self._mfa_entry.focus_set()
            return

        self._is_unlocking = True
        if self._unlock_btn:
            self._unlock_btn.configure(state=tk.DISABLED, text="Проверка...")

        try:
            # Вызываем разблокировку
            result = self._lock_manager.unlock_session(password, mfa_code)

            if result.success:
                self._on_unlock_success()
            else:
                self._on_unlock_failure(result)

        except Exception as e:
            logger.error("Unlock error: %s", e)
            self._show_error("Ошибка разблокировки")
            self.wipe_credentials()
        finally:
            self._is_unlocking = False
            if self._unlock_btn and self._unlock_btn.winfo_exists():
                self._unlock_btn.configure(state=tk.NORMAL, text="🔓 Разблокировать")

    def _on_unlock_success(self) -> None:
        """Обработчик успешной разблокировки.

        Очищает данные и скрывает экран блокировки.
        """
        logger.info("Session unlocked successfully via lock screen")
        self.wipe_credentials()
        self.hide()

    def _on_unlock_failure(self, result: "UnlockResult") -> None:
        """Обработчик неудачной разблокировки.

        Args:
            result: Результат разблокировки с ошибкой.

        Security:
            Очищает ВСЕ поля ввода для предотвращения
            повторного использования введённых данных.
        """
        error_msg = result.error_message or "Ошибка аутентификации"
        self._show_error(error_msg)
        self.wipe_credentials()

        # Фокус на поле пароля
        if self._password_entry:
            self._password_entry.focus_set()

        logger.warning("Unlock failed: %s", result.error_code)

    def _on_escape(self, event: tk.Event) -> None:
        """Обработчик нажатия ESC.

        Args:
            event: Событие нажатия клавиши.

        Security:
            ESC не закрывает экран пока сессия заблокирована.
            Можно добавить вибрацию или звуковой сигнал.
        """
        if self._lock_manager.is_locked():
            # Показываем сообщение что нужно разблокировать
            self._show_error("Нажмите 🔓 Разблокировать для входа")
        else:
            # Если сессия уже разблокирована - можно закрыть
            self.hide()

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке.

        Args:
            message: Текст ошибки для отображения.
        """
        if self._error_label is not None:
            self._error_label.configure(text=message)

    def _clear_error(self) -> None:
        """Очищает сообщение об ошибке."""
        if self._error_label is not None:
            self._error_label.configure(text="")

    def wipe_credentials(self) -> None:
        """Очищает поля с учётными данными.

        Security:
            Очищает переменные пароля и MFA для предотвращения
            утечки в памяти. Вызывается при каждой неудачной попытке.

        Example:
            >>> lock_screen.wipe_credentials()
        """
        self._password_var.set("")
        self._mfa_var.set("")
        self._password_visible = False

        if self._password_entry:
            self._password_entry.configure(show="*")
        if self._toggle_btn:
            self._toggle_btn.configure(text="👁")


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "SessionLockScreen",
]
