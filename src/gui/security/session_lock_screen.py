"""Экран блокировки сессии FX Text Processor 3.

Реализует application-level overlay поверх главного окна с формой
разблокировки. Используется при блокировке сессии (ручной или автоматической).

Security:
    - Поля очищаются при неудачной попытке
    - ESC не закрывает окно
    - Нет логирования password/token

Example:
    >>> screen = SessionLockScreen(
    ...     parent=root,
    ...     on_unlock=my_unlock_callback,
    ...     locked_at=datetime.now(),
    ...     trigger="auto",
    ... )
    >>> screen.show()

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from datetime import datetime
from typing import Any, Callable, Optional

from src.gui.components.mfa_form import MFAForm
from src.security.crypto.core.exceptions import AuthError, CryptoError

# Callback type: password, mfa_token, method -> bool
UnlockCallback = Callable[[str, str, str], bool]


class SessionLockScreen(tk.Toplevel):
    """Экран блокировки сессии на уровне приложения.

    Отображает чёрный overlay поверх главного окна приложения
    с центрированной формой разблокировки. Требует пароль + MFA
    для разблокировки.

    Security:
        - НЕ захватывает весь экран ОС (application-level lock).
        - Привязывается к геометрии родительского окна.
        - Поля очищаются при каждой неудачной попытке.
        - ESC не закрывает окно пока сессия заблокирована.
        - Пароль скрыт (show='*').
        - НЕ логирует password/token.
    """

    def __init__(
        self,
        *,
        parent: tk.Tk,
        on_unlock: Optional[UnlockCallback] = None,
        locked_at: datetime,
        trigger: str = "manual",
        auto_lock_minutes: int = 0,
        password_service: Optional[Any] = None,
        mfa_manager: Optional[Any] = None,
    ) -> None:
        """Инициализация экрана блокировки сессии.

        Args:
            parent: Родительское окно (root).
            on_unlock: Callback для проверки credentials.
                Получает (password, mfa_token, method) -> bool.
            locked_at: Время блокировки для отображения.
            trigger: Причина блокировки ("manual", "auto", etc.).
            auto_lock_minutes: Минут до автоматической блокировки.
                Если > 0, отображается на экране.
            password_service: Сервис проверки пароля (опционально).
            mfa_manager: Менеджер второго фактора (опционально).
        """
        super().__init__(parent)
        self._parent: tk.Tk = parent
        self._on_unlock: Optional[UnlockCallback] = on_unlock
        self._locked_at: datetime = locked_at
        self._trigger: str = trigger
        self._auto_lock_minutes: int = auto_lock_minutes
        self._password_service: Optional[Any] = password_service
        self._mfa_manager: Optional[Any] = mfa_manager

        self._mfa_form: Optional[MFAForm] = None
        self._error_label: Optional[tk.Label] = None
        self._locked_info_label: Optional[tk.Label] = None
        self._trigger_info_label: Optional[tk.Label] = None
        self._auto_lock_label: Optional[tk.Label] = None

        self._bind_ids: dict[str, str] = {}
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна блокировки.

        Security:
            Блокировка выполняется на уровне приложения (overlay поверх root),
            а не всего рабочего стола (fullscreen).
            Это предотвращает случайное захвачивание Alt-Tab и удобнее
            в многомониторной конфигурации.
        """
        # Application-level overlay: follow parent size
        self.transient(self._parent)
        self.overrideredirect(True)
        # Do NOT use -fullscreen or -topmost

        self.configure(bg="black")
        self.protocol("WM_DELETE_WINDOW", self._on_close_attempt)
        self.bind("<Escape>", self._on_escape)
        self._sync_geometry()
        # Keep lock screen in sync with parent window geometry
        self._bind_ids["<Configure>"] = self._parent.bind("<Configure>", self._on_parent_configure)
        self._bind_ids["<Unmap>"] = self._parent.bind("<Unmap>", self._on_parent_unmap)
        self._bind_ids["<Map>"] = self._parent.bind("<Map>", self._on_parent_map)

    def _sync_geometry(self) -> None:
        """Синхронизирует размер и позицию lock screen с родительским окном."""
        self.geometry(f"{self._parent.winfo_width()}x{self._parent.winfo_height()}+{self._parent.winfo_x()}+{self._parent.winfo_y()}")

    def _on_parent_configure(self, _event: Any) -> None:
        """Обработчик изменения размера/позиции родительского окна."""
        self._sync_geometry()

    def _on_parent_unmap(self, _event: Any) -> None:
        """Скрывать lock screen когда родитель свёрнут."""
        self.withdraw()

    def _on_parent_map(self, _event: Any) -> None:
        """Показывать lock screen когда родитель восстановлен."""
        self.deiconify()
        self._sync_geometry()
        self.lift(self._parent)

    def _on_close_attempt(self) -> None:
        """Обработчик попытки закрытия окна.

        Security:
            Игнорирует попытку закрытия пока сессия заблокирована.
        """
        # Do nothing — window cannot be closed without authentication
        return

    def _on_escape(self, event: Any) -> str:
        """Обработчик нажатия ESC.

        Args:
            event: Событие нажатия клавиши.

        Returns:
            'break' чтобы предотвратить стандартное поведение.
        """
        # Prevent closing on Escape
        return "break"

    def show(self) -> None:
        """Показывает экран блокировки fullscreen.

        Создаёт UI элементы, устанавливает fullscreen режим
        и захватывает фокус.
        """
        self._create_ui()
        self.grab_set()
        self.focus_force()

    def hide(self) -> None:
        """Скрывает экран блокировки.

        Вызывается при успешной разблокировке.
        Очищает sensitive данные и уничтожает окно.
        """
        if self._mfa_form is not None:
            self._mfa_form.wipe_credentials()
        self.destroy()

    def _create_ui(self) -> None:
        """Создаёт UI элементы экрана блокировки.

        Создаёт центрированную панель с заголовком, подзаголовком,
        формой MFA и информацией о блокировке.
        """
        # Center frame
        center_frame = tk.Frame(self, bg="black")
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Title
        title_label = tk.Label(
            center_frame,
            text="Session Locked",
            font=("Courier New", 24),
            bg="black",
            fg="white",
        )
        title_label.pack(pady=(0, 10))

        # Subtitle
        subtitle_label = tk.Label(
            center_frame,
            text="Document is protected and hidden.",
            font=("Courier New", 12),
            bg="black",
            fg="#888888",
        )
        subtitle_label.pack(pady=(0, 30))

        # MFA form
        self._mfa_form = MFAForm(
            center_frame,
            on_submit=self._on_mfa_submit,
            on_cancel=None,
            show_username=False,
            show_cancel=False,
            submit_text="Unlock",
            bg_color="black",
            fg_color="#ecf0f1",
            error_color="#e74c3c",
            accent_color="#27ae60",
            font_family="Courier New",
            title_text="",
            title_font_size=18,
            label_font_size=12,
            entry_font_size=12,
            button_font_size=12,
        )
        self._mfa_form.pack(pady=(0, 20))

        # Custom error label (red, below form)
        self._error_label = tk.Label(
            center_frame,
            text="",
            font=("Courier New", 11, "bold"),
            bg="black",
            fg="#e74c3c",
        )
        self._error_label.pack(pady=(5, 10))

        # Locked info
        locked_time = self._locked_at.strftime("%H:%M:%S")
        self._locked_info_label = tk.Label(
            center_frame,
            text=f"Locked at: {locked_time}",
            font=("Courier New", 10),
            bg="black",
            fg="#888888",
        )
        self._locked_info_label.pack(pady=(5, 2))

        # Trigger info
        trigger_text = f"Trigger: {self._trigger}"
        self._trigger_info_label = tk.Label(
            center_frame,
            text=trigger_text,
            font=("Courier New", 10),
            bg="black",
            fg="#888888",
        )
        self._trigger_info_label.pack(pady=(2, 5))

        # Auto-lock info
        if self._auto_lock_minutes > 0:
            self._auto_lock_label = tk.Label(
                center_frame,
                text=f"Auto-lock in: {self._auto_lock_minutes} min",
                font=("Courier New", 10),
                bg="black",
                fg="#888888",
            )
            self._auto_lock_label.pack(pady=(2, 5))

        # Focus password
        self._mfa_form.focus_password()

    def _on_mfa_submit(self, _username: str, password: str, method: str, token: str) -> bool:
        """Обработчик отправки формы MFA.

        Вызывает on_unlock callback и обновляет UI.

        Args:
            _username: Username (не используется для session lock).
            password: Введённый пароль.
            method: Выбранный метод MFA.
            token: Введённый MFA токен.

        Returns:
            True если аутентификация успешна.
        """
        if self._on_unlock is None:
            self._show_error("Unlock handler not configured")
            return False

        try:
            result = self._on_unlock(password, token, method)
        except (AuthError, CryptoError) as e:
            logging.critical("Session unlock security error: %s", e, exc_info=True)
            result = False
        except Exception as e:
            logging.exception("Unexpected error during session unlock: %s", e)
            result = False

        if result:
            # Success: clear custom error and destroy
            self._show_error("")
            self.after(200, self.hide)
        else:
            # Failure: show error label
            self._show_error("Invalid credentials")
            # Wipe handled by MFAForm internally on failure

        return result

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке.

        Args:
            message: Текст ошибки для отображения.
        """
        if self._error_label is not None and self._error_label.winfo_exists():
            self._error_label.config(text=message)

    def wipe_credentials(self) -> None:
        """Security: очистить поля ввода.

        Очищает все поля ввода credentials для предотвращения
        утечки sensitive данных.
        """
        if self._mfa_form is not None:
            self._mfa_form.wipe_credentials()

    def destroy(self) -> None:
        """Переопределённый destroy для очистки credentials и отвязки событий."""
        self.wipe_credentials()
        # Unbind parent events to prevent zombies
        try:
            for event, bind_id in getattr(self, "_bind_ids", {}).items():
                self._parent.unbind(event, bind_id)
        except tk.TclError:
            pass
        self._bind_ids.clear()
        super().destroy()


# Module exports
__all__: list[str] = [
    "SessionLockScreen",
    "UnlockCallback",
]
