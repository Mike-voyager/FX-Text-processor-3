"""Окно аутентификации с поддержкой MFA.

Вход в систему через пароль + второй фактор (FIDO2/TOTP/Backup Codes).

Example:
    >>> import tkinter as tk
    >>> root = tk.Tk()
    >>> def on_success(user_id: str) -> None:
    ...     print(f"User {user_id} authenticated")
    >>> auth_window = AuthWindow(
    ...     parent=root,
    ...     on_auth_success=on_success,
    ... )
    >>> auth_window.show()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from enum import Enum
from typing import Any, Callable, Optional

from src.gui.security.components.secure_entry import SecureEntry
from src.gui.security.mfa_gate import MFAGate
from src.gui.themes import get_theme_manager
from src.security.crypto.core.exceptions import AuthError, CryptoError


class MFASelection(Enum):
    """Выбор метода MFA."""

    FIDO2 = "fido2"
    TOTP = "totp"
    BACKUP_CODES = "backup_code"


class AuthWindow:
    """Окно аутентификации с поддержкой MFA.

    Реализует модальное окно для входа в систему с поддержкой
    многофакторной аутентификации. Работает в двух режимах:
    - Полный режим: с auth_service для реальной верификации
    - Demo режим: без auth_service, принимает любой пароль

    Attributes:
        _parent: Родительское окно.
        _auth_service: Сервис аутентификации (None в demo режиме).
        _on_auth_success: Callback при успешной аутентификации.
        _on_cancel_callback: Callback при отмене.
        _window: Ссылка на Toplevel окно.
        _password_var: Переменная для поля пароля.
        _mfa_method: Текущий выбранный метод MFA.
        _error_label: Label для отображения ошибок.
        _password_visible: Флаг видимости пароля.
        _theme_manager: Менеджер тем для стилизации.
        _mfa_gate: MFAGate для MFA верификации.

    Example:
        >>> root = tk.Tk()
        >>> auth = AuthWindow(
        ...     parent=root,
        ...     on_auth_success=lambda uid: print(f"Success: {uid}"),
        ... )
        >>> auth.show()
    """

    def __init__(
        self,
        parent: tk.Tk,
        auth_service: Optional[Any] = None,
        on_auth_success: Optional[Callable[[str], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация окна аутентификации.

        Args:
            parent: Родительское окно (root).
            auth_service: Сервис аутентификации (опционально).
            on_auth_success: Callback при успешной аутентификации,
                получает user_id.
            on_cancel: Callback при отмене.

        Example:
            >>> root = tk.Tk()
            >>> window = AuthWindow(root, on_auth_success=lambda x: None)
        """
        self._parent: tk.Tk = parent
        self._auth_service: Optional[Any] = auth_service
        self._on_auth_success: Optional[Callable[[str], None]] = on_auth_success
        self._on_cancel_callback: Optional[Callable[[], None]] = on_cancel

        self._window: Optional[tk.Toplevel] = None
        self._password_var = tk.StringVar(master=self._parent)
        self._mfa_method = tk.StringVar(master=self._parent, value=MFASelection.FIDO2.value)
        self._password_visible = False
        self._theme_manager = get_theme_manager()
        self._mfa_gate: Optional[MFAGate] = None

        # UI элементы (инициализируются в _create_ui)
        self._username_entry: Optional[tk.Entry] = None
        self._password_entry: Optional[tk.Entry] = None
        self._error_label: Optional[tk.Label] = None
        self._toggle_btn: Optional[tk.Button] = None
        self._login_btn: Optional[tk.Button] = None
        self._cancel_btn: Optional[tk.Button] = None
        self._fido2_radio: Optional[tk.Radiobutton] = None
        self._totp_radio: Optional[tk.Radiobutton] = None
        self._backup_radio: Optional[tk.Radiobutton] = None
        self._fido2_touch_label: Optional[tk.Label] = None

        # Инициализация MFAGate если есть auth_service
        if auth_service is not None:
            self._mfa_gate = MFAGate(auth_service=auth_service)
            # Регистрация диалогов MFA (в demo режиме не нужно)
            self._register_mfa_dialogs()

    def _register_mfa_dialogs(self) -> None:
        """Регистрирует диалоги MFA для работы с MFAGate."""
        try:
            from src.gui.dialogs.mfa_method_selector_dialog import MFAMethodSelectorDialog

            # Регистрация диалогов для методов MFA
            # В реальной реализации здесь будут специализированные диалоги
            # Сейчас используем универсальный MFAMethodSelectorDialog
            if self._mfa_gate is not None:
                self._mfa_gate.register_dialog("totp", MFAMethodSelectorDialog)  # type: ignore[arg-type]
                self._mfa_gate.register_dialog("fido2", MFAMethodSelectorDialog)  # type: ignore[arg-type]
                self._mfa_gate.register_dialog("backup_code", MFAMethodSelectorDialog)  # type: ignore[arg-type]
        except ImportError:
            # Если диалог не найден, продолжаем без регистрации
            logging.getLogger(__name__).warning(
                "MFAMethodSelectorDialog not found for registration",
            )

    def show(self) -> None:
        """Показывает окно модально.

        Создаёт Toplevel окно, настраивает UI и блокирует
        родительское окно до закрытия.

        Example:
            >>> auth_window.show()
            # Окно отображается модально
        """
        if self._window is not None and self._window.winfo_exists():
            try:
                self._window.lift()
            except tk.TclError:
                pass
            return

        self._window = tk.Toplevel(self._parent)
        self._window.title("FX Text Processor 3 - Вход в систему")
        self._window.resizable(False, False)
        self._window.transient(self._parent)
        try:
            self._window.grab_set()
        except tk.TclError:
            pass

        # Применяем тему
        self._apply_theme_to_window()

        # Создаём UI
        self._create_ui()

        # Центрируем окно
        self._center_window()

        # Биндим ESC
        self._window.bind("<Escape>", lambda e: self._on_cancel())
        self._window.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def hide(self) -> None:
        """Скрывает окно.

        Скрывает окно без уничтожения. Можно снова
        показать через show().

        Example:
            >>> auth_window.hide()
            # Окно скрыто, но не уничтожено
        """
        if self._window is not None and self._window.winfo_exists():
            self._window.withdraw()

    def destroy(self) -> None:
        """Уничтожает окно и очищает ресурсы.

        Освобождает все ресурсы, уничтожает виджеты
        и очищает чувствительные данные.

        Security:
            Очищает поле пароля перед уничтожением.

        Example:
            >>> auth_window.destroy()
            # Окно уничтожено, ресурсы освобождены
        """
        self.wipe_credentials()

        if self._window is not None and self._window.winfo_exists():
            self._window.destroy()

        self._window = None
        self._password_entry = None
        self._error_label = None
        self._toggle_btn = None
        self._login_btn = None
        self._cancel_btn = None

    def _create_ui(self) -> None:
        """Создаёт UI элементы.

        Создаёт:
        - Заголовок "FX Text Processor 3 - Вход в систему"
        - Поле пароля (Entry с show="*")
        - Кнопку 👁 для toggle видимости пароля
        - Radio buttons для выбора MFA метода
        - Кнопки [Войти] [Отмена]
        """
        if self._window is None:
            return

        theme = self._theme_manager.get_current_theme()

        # Основной контейнер
        main_frame = tk.Frame(
            self._window,
            bg=theme.bg_color,
            padx=20,
            pady=20,
        )
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Заголовок
        header_label = tk.Label(
            main_frame,
            text="FX Text Processor 3",
            font=(theme.font_family, theme.font_size + 2, "bold"),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        header_label.pack(pady=(0, 10))

        # Подзаголовок
        subheader_label = tk.Label(
            main_frame,
            text="🔐 Authentication Required",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        subheader_label.pack(pady=(0, 20))

        # Имя пользователя (опционально)
        username_frame = tk.Frame(main_frame, bg=theme.bg_color)
        username_frame.pack(fill=tk.X, pady=2)

        username_label = tk.Label(
            username_frame,
            text="Username:",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        username_label.pack(side=tk.LEFT, padx=(0, 5))

        self._username_entry = tk.Entry(
            username_frame,
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            insertbackground=theme.fg_color,
            selectbackground=theme.accent_color,
            selectforeground=theme.bg_color,
            width=30,
        )
        self._username_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._username_entry.bind("<Return>", lambda e: self._on_login())

        # Фрейм для пароля
        password_frame = tk.Frame(main_frame, bg=theme.bg_color)
        password_frame.pack(fill=tk.X, pady=5)

        # Метка пароля
        password_label = tk.Label(
            password_frame,
            text="Password:",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        password_label.pack(side=tk.LEFT, padx=(0, 5))

        # Поле пароля
        self._password_entry = tk.Entry(
            password_frame,
            textvariable=self._password_var,
            show="*",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            insertbackground=theme.fg_color,
            selectbackground=theme.accent_color,
            selectforeground=theme.bg_color,
            width=30,
        )
        self._password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._password_entry.bind("<Return>", lambda e: self._on_login())

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
        )
        self._toggle_btn.pack(side=tk.LEFT, padx=(5, 0))

        # Выбор метода MFA (согласно спецификации)
        mfa_frame = tk.Frame(main_frame, bg=theme.bg_color)
        mfa_frame.pack(fill=tk.X, pady=15)

        # Метка метода
        method_label = tk.Label(
            mfa_frame,
            text="Method:",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        method_label.pack(anchor=tk.W, pady=(0, 5))

        # Фрейм для radio кнопок в виде спецификации
        methods_frame = tk.Frame(mfa_frame, bg=theme.bg_color)
        methods_frame.pack(fill=tk.X, pady=2)

        # FIDO2 опция
        fido2_frame = tk.Frame(methods_frame, bg=theme.bg_color)
        fido2_frame.pack(fill=tk.X, pady=2)

        self._fido2_radio = tk.Radiobutton(
            fido2_frame,
            text="Password + FIDO2",
            variable=self._mfa_method,
            value=MFASelection.FIDO2.value,
            bg=theme.bg_color,
            fg=theme.fg_color,
            selectcolor=theme.accent_color,
            font=(theme.font_family, theme.font_size),
        )
        self._fido2_radio.pack(side=tk.LEFT)

        # TOTP опция
        totp_frame = tk.Frame(methods_frame, bg=theme.bg_color)
        totp_frame.pack(fill=tk.X, pady=2)

        self._totp_radio = tk.Radiobutton(
            totp_frame,
            text="Password + TOTP",
            variable=self._mfa_method,
            value=MFASelection.TOTP.value,
            bg=theme.bg_color,
            fg=theme.fg_color,
            selectcolor=theme.accent_color,
            font=(theme.font_family, theme.font_size),
        )
        self._totp_radio.pack(side=tk.LEFT)

        # Backup Code опция
        backup_frame = tk.Frame(methods_frame, bg=theme.bg_color)
        backup_frame.pack(fill=tk.X, pady=2)

        self._backup_radio = tk.Radiobutton(
            backup_frame,
            text="Password + Backup Code",
            variable=self._mfa_method,
            value=MFASelection.BACKUP_CODES.value,
            bg=theme.bg_color,
            fg=theme.fg_color,
            selectcolor=theme.accent_color,
            font=(theme.font_family, theme.font_size),
        )
        self._backup_radio.pack(side=tk.LEFT)

        # Индикатор касания FIDO2 (скрыт по умолчанию)
        self._fido2_touch_label = tk.Label(
            mfa_frame,
            text="[FIDO2: Touch your key]",
            font=("Courier", theme.font_size),
            bg=theme.bg_color,
            fg=theme.accent_color,
        )
        self._fido2_touch_label.pack(anchor=tk.W, pady=(5, 0))
        self._fido2_touch_label.pack_forget()  # Скрыто по умолчанию

        # Привязка для показа индикатора касания при выборе FIDO2
        self._mfa_method.trace_add("write", self._on_mfa_method_changed)

        # Область ошибок
        self._error_label = tk.Label(
            main_frame,
            text="",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.error_color,
        )
        self._error_label.pack(pady=(10, 0))

        # Кнопки
        button_frame = tk.Frame(main_frame, bg=theme.bg_color)
        button_frame.pack(fill=tk.X, pady=(20, 0))

        # Кнопка Войти
        self._login_btn = tk.Button(
            button_frame,
            text="Login",
            command=self._on_login,
            font=(theme.font_family, theme.font_size, "bold"),
            bg=theme.accent_color,
            fg=theme.bg_color,
            padx=15,
            pady=5,
            cursor="hand2",
        )
        self._login_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Кнопка Отмена
        self._cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=self._on_cancel,
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            padx=15,
            pady=5,
            cursor="hand2",
        )
        self._cancel_btn.pack(side=tk.RIGHT)

    def _get_method_display_name(self, method: MFASelection) -> str:
        """Возвращает отображаемое имя метода MFA.

        Args:
            method: Метод MFA.

        Returns:
            Строка с отображаемым именем.
        """
        names = {
            MFASelection.FIDO2: "FIDO2 Security Key",
            MFASelection.TOTP: "TOTP (Google Authenticator)",
            MFASelection.BACKUP_CODES: "Backup Codes",
        }
        return names.get(method, method.value)

    def _on_mfa_method_changed(self, *args: Any) -> None:
        """Обработчик изменения метода MFA."""
        if self._mfa_method.get() == MFASelection.FIDO2.value:
            # Показываем индикатор касания для FIDO2
            if self._fido2_touch_label:
                self._fido2_touch_label.pack(fill=tk.X, pady=(5, 0))
        else:
            # Скрываем индикатор касания для других методов
            if self._fido2_touch_label:
                self._fido2_touch_label.pack_forget()

    def _apply_theme_to_window(self) -> None:
        """Применяет текущую тему к окну."""
        if self._window is None:
            return

        theme = self._theme_manager.get_current_theme()
        self._window.configure(bg=theme.bg_color)

    def _center_window(self) -> None:
        """Центрирует окно относительно родителя."""
        if self._window is None:
            return

        self._window.update_idletasks()

        # Получаем размеры
        width = self._window.winfo_width()
        height = self._window.winfo_height()
        parent_x = self._parent.winfo_x()
        parent_y = self._parent.winfo_y()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        # Вычисляем позицию
        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2

        self._window.geometry(f"+{x}+{y}")

    def _toggle_password_visibility(self) -> None:
        """Переключает видимость пароля.

        Переключает show/hide для поля пароля между "*" и "".

        Example:
            >>> auth_window._toggle_password_visibility()
            # Пароль теперь виден
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

    def _on_login(self) -> None:
        """Обработчик входа.

        Проверяет пароль через auth_service, показывает
        MFA диалог через MFAGate, при успехе вызывает
        on_auth_success callback.

        Example:
            >>> auth_window._on_login()
            # Начинается процесс аутентификации
        """
        self._clear_error()

        password = self._password_var.get()

        if not password:
            self._show_error("Введите пароль")
            return

        # Demo mode: всегда успешно
        if self._auth_service is None:
            self._handle_demo_login(password)
            return

        # Реальная аутентификация
        self._handle_real_login(password)

    def _handle_demo_login(self, password: str) -> None:
        """Обрабатывает вход в demo режиме.

        Args:
            password: Введённый пароль (игнорируется).
        """
        # Имитируем MFA flow (выбранный метод в demo режиме игнорируется)
        _ = self._mfa_method.get()  # Для совместимости с будущей реализацией

        # В demo режиме считаем что MFA прошёл успешно
        if self._on_auth_success is not None:
            self._on_auth_success("demo-user")

        self.destroy()

    def _handle_real_login(self, password: str) -> None:
        """Обрабатывает реальную аутентификацию.

        Args:
            password: Введённый пароль.
        """
        # Проверяем пароль
        try:
            if self._auth_service is None:
                self._show_error("Сервис аутентификации недоступен")
                return
            auth_result = self._auth_service.authenticate(password)
            if not auth_result.success:
                self._show_error("Неверный пароль")
                return

            user_id = auth_result.user_id

            # Получаем доступные MFA методы
            available_methods = self._get_available_mfa_methods(user_id)

            if not available_methods:
                # MFA не настроен, входим сразу
                if self._on_auth_success is not None:
                    self._on_auth_success(user_id)
                self.destroy()
                return

            # Показываем MFA диалог
            self._perform_mfa_challenge(user_id, available_methods)

        except (AuthError, CryptoError) as e:
            logging.critical("Authentication security error: %s", e, exc_info=True)
            self._show_error("Ошибка аутентификации")
        except (ValueError, TypeError, AttributeError, RuntimeError) as e:
            logging.exception("Unexpected authentication error: %s", e)
            self._show_error("Ошибка аутентификации. Обратитесь к администратору.")

    def _get_available_mfa_methods(self, user_id: str) -> list[str]:
        """Получает список доступных MFA методов для пользователя.

        Args:
            user_id: ID пользователя.

        Returns:
            Список доступных методов MFA.
        """
        methods: list[str] = []
        selected = self._mfa_method.get()

        # В demo режиме или если нет методов, возвращаем выбранный
        if self._auth_service is None:
            return [selected]

        # Проверяем доступность методов через auth_service
        try:
            if hasattr(self._auth_service, "has_fido2"):
                if self._auth_service.has_fido2(user_id):
                    methods.append("fido2")
            if hasattr(self._auth_service, "has_totp"):
                if self._auth_service.has_totp(user_id):
                    methods.append("totp")
            if hasattr(self._auth_service, "has_backup_codes"):
                if self._auth_service.has_backup_codes(user_id):
                    methods.append("backup_code")
        except (AttributeError, ValueError, TypeError, RuntimeError) as e:
            # Игнорируем ошибки при проверке доступных методов
            # Demo mode или отсутствие auth service
            logging.getLogger(__name__).debug("Exception ignored: %s", e)

        # Если ничего не доступно, используем выбранный
        if not methods:
            methods = [selected]

        return methods

    def _perform_mfa_challenge(self, user_id: str, methods: list[str]) -> None:
        """Выполняет MFA challenge.

        Args:
            user_id: ID пользователя.
            methods: Список методов MFA для попытки.
        """
        if self._mfa_gate is None or self._window is None:
            self._show_error("Ошибка инициализации MFA")
            return

        # Показываем MFA диалог
        result = self._mfa_gate.challenge(
            parent=self._window,  # type: ignore[arg-type]
            user_id=user_id,
            required_methods=methods,
            operation="login",
        )

        if result.verified:
            if self._on_auth_success is not None:
                self._on_auth_success(user_id)
            self.destroy()
        else:
            error_msg = result.error_message or "MFA верификация не пройдена"
            self._show_error(error_msg)

    def _on_cancel(self) -> None:
        """Обработчик отмены.

        Очищает поля, вызывает on_cancel callback
        и закрывает окно.

        Example:
            >>> auth_window._on_cancel()
            # Окно закрыто, вызван on_cancel callback
        """
        self.wipe_credentials()

        if self._on_cancel_callback is not None:
            self._on_cancel_callback()

        self.destroy()

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке.

        Args:
            message: Текст ошибки для отображения.

        Example:
            >>> auth_window._show_error("Неверный пароль")
        """
        if self._error_label is not None:
            self._error_label.configure(text=message)

    def _clear_error(self) -> None:
        """Очищает сообщение об ошибке.

        Example:
            >>> auth_window._clear_error()
        """
        if self._error_label is not None:
            self._error_label.configure(text="")

    def wipe_credentials(self) -> None:
        """Очищает поля с учётными данными.

        Security:
            Очищает переменную пароля для предотвращения
            утечки в памяти. Также вызывает wipe() на SecureEntry,
            если используется.

        Example:
            >>> auth_window.wipe_credentials()
        """
        self._password_var.set("")
        # Secure wipe если виджеты ещё существуют
        if self._password_entry is not None:
            try:
                if isinstance(self._password_entry, SecureEntry):
                    self._password_entry.wipe()
            except tk.TclError:
                pass  # виджет уже уничтожен


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "AuthWindow",
    "MFASelection",
]
