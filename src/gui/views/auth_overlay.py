"""AuthOverlay — тёмный overlay для аутентификации (вход в Special Mode).

Модуль реализует полноэкранный overlay с формой MFA-аутентификации:
- Поддержка методов: Password + FIDO2/TOTP/Backup Code
- Security: скрытие пароля, очистка полей
- Интеграция с AuthService для проверки credentials

Example:
    >>> from src.gui.views.auth_overlay import AuthOverlay
    >>> from src.security.auth.auth_service import AuthService
    >>> overlay = AuthOverlay(
    ...     parent=root,
    ...     widget_id="auth_overlay",
    ...     auth_service=auth_service,
    ...     on_auth_success=lambda: print("Authenticated!"),
    ...     on_cancel=lambda: print("Cancelled"),
    ... )
    >>> overlay.mount(parent)
    >>> overlay.show()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import Any, Callable, Final, Optional, Protocol, runtime_checkable

from src.gui.components.base.widget import BaseWidget
from src.gui.components.mfa_form import MFAForm
from src.gui.core.protocols import ControllerProtocol

logger: logging.Logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AuthResult — результат аутентификации (Protocol для GUI-слоя)
# ---------------------------------------------------------------------------


class AuthResult(Protocol):
    """Протокол результата аутентификации.

    Определяет минимальный контракт результата, используемый
    AuthOverlay: атрибуты ``success`` и ``failure_reason``.

    Note:
        Реальный :class:`src.security.auth.auth_service.AuthResult`
        (frozen dataclass) удовлетворяет этому протоколу структурно.
    """

    success: bool
    failure_reason: Optional[str]


# ---------------------------------------------------------------------------
# AuthServiceProtocol — контракт сервиса аутентификации для GUI-слоя
# ---------------------------------------------------------------------------


@runtime_checkable
class AuthServiceProtocol(Protocol):
    """Протокол сервиса аутентификации для использования в GUI-слое.

    Определяет минимальный контракт, необходимый AuthOverlay для
    взаимодействия с сервисом аутентификации без прямой зависимости
    от конкретной реализации (AuthService dataclass).

    Структурная типизация (Protocol) позволяет подставлять любой
    объект, реализующий метод ``authenticate`` с совместимой
    сигнатурой, включая моки в тестах.

    Example:
        >>> class FakeAuthService:
        ...     def authenticate(self, user_id: str, *, password: str,
        ...                        factor_type: Optional[str] = None,
        ...                        factor_credential: Any = None) -> AuthResult:
        ...         return AuthResult(success=True, user_id=user_id)
        >>> isinstance(FakeAuthService(), AuthServiceProtocol)
        True
    """

    def authenticate(
        self,
        user_id: str,
        *,
        password: str,
        factor_type: Optional[str] = ...,
        factor_credential: Any = ...,
    ) -> AuthResult:
        """Выполняет аутентификацию пользователя с MFA.

        Args:
            user_id: Идентификатор пользователя.
            password: Пароль в открытом виде.
            factor_type: Тип второго фактора (``"totp"``, ``"fido2"``,
                ``"backupcode"``).
            factor_credential: Учётные данные второго фактора.

        Returns:
            :class:`AuthResult` с результатом аутентификации.
        """
        ...


# Type alias для читаемости: реальный тип — AuthServiceProtocol
AuthService = AuthServiceProtocol


class AuthOverlay(BaseWidget):
    """Тёмный overlay для аутентификации (вход в Special Mode).

    Реализует полноэкранный overlay с формой MFA-аутентификации.
    Поддерживает три метода второго фактора: FIDO2, TOTP, Backup Code.

    Attributes:
        OVERLAY_BG: Color фона overlay (тёмно-синий).
        FORM_BG: Color фона формы (немного светлее).
        FG: Color текста (светлый).
        ERROR_FG: Color текста ошибки (красный).
        SUCCESS_FG: Color текста успеха (зелёный).

    Security:
        - Пароль скрывается (show="•")
        - Поля очищаются при hide()
        - Нет логирования sensitive данных
        - Валидация перед вызовом auth_service

    Example:
        >>> overlay = AuthOverlay(parent=root, widget_id="auth")
        >>> overlay.mount(root)
        >>> overlay.show()
    """

    # Colors
    OVERLAY_BG: Final[str] = "#2c3e50"  # Dark blue-gray
    FORM_BG: Final[str] = "#34495e"  # Slightly lighter
    FG: Final[str] = "#ecf0f1"  # Light text
    ERROR_FG: Final[str] = "#e74c3c"  # Red
    SUCCESS_FG: Final[str] = "#2ecc71"  # Green
    INFO_FG: Final[str] = "#3498db"  # Blue
    WARNING_FG: Final[str] = "#f39c12"  # Orange

    def __init__(
        self,
        parent: tk.Widget,
        widget_id: str = "auth_overlay",
        controller: Optional[ControllerProtocol] = None,
        auth_service: Optional[AuthService] = None,
        on_auth_success: Optional[Callable[[], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация AuthOverlay.

        Args:
            parent: Родительский виджет (MainWindow root).
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер для callbacks.
            auth_service: Сервис аутентификации.
            on_auth_success: Callback при успешной аутентификации.
            on_cancel: Callback при отмене.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._parent: tk.Widget = parent
        self._auth_service: Optional[AuthService] = auth_service
        self._auth_success_callback: Optional[Callable[[], None]] = on_auth_success
        self._cancel_callback: Optional[Callable[[], None]] = on_cancel

        # UI Components (created in _create_tk_widget)
        self._overlay_frame: tk.Frame
        self._form_frame: tk.Frame
        self._mfa_form: Optional[MFAForm] = None
        self._status_label: Optional[tk.Label] = None

        # State
        self._is_visible: bool = False

    # -------------------------------------------------------------------------
    # BaseWidget Implementation
    # -------------------------------------------------------------------------

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет (overlay frame).

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет (overlay frame).
        """
        self._overlay_frame = tk.Frame(
            parent,
            bg=self.OVERLAY_BG,
        )
        self._build_form()
        return self._overlay_frame

    def _build_form(self) -> None:
        """Создаёт форму аутентификации внутри overlay."""
        if self._overlay_frame is None:
            return

        self._form_frame = tk.Frame(
            self._overlay_frame,
            bg=self.FORM_BG,
            padx=40,
            pady=40,
        )
        self._form_frame.place(relx=0.5, rely=0.5, anchor="center")

        self._mfa_form = MFAForm(
            self._form_frame,
            on_submit=self._on_mfa_submit,
            on_fido2_request=self._on_fido2_request,
            on_cancel=self._on_cancel,
            show_username=True,
            show_cancel=True,
            submit_text="Authenticate",
            cancel_text="Cancel",
            bg_color=self.FORM_BG,
            fg_color=self.FG,
            error_color=self.ERROR_FG,
            accent_color="#27ae60",
            font_family="TkDefaultFont",
            title_text="🔐 Authentication Required",
            title_font_size=18,
            label_font_size=11,
            entry_font_size=11,
            button_font_size=11,
        )
        self._mfa_form.pack()

        self._status_label = tk.Label(
            self._form_frame,
            text="Status: Enter credentials",
            font=("TkDefaultFont", 10),
            bg=self.FORM_BG,
            fg=self.INFO_FG,
            anchor="w",
        )
        self._status_label.pack(fill=tk.X, pady=(15, 0))

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        if self._overlay_frame is not None:
            self._overlay_frame.bind("<Escape>", lambda e: self._on_cancel())

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self.wipe_credentials()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def show(self) -> None:
        """Показывает overlay поверх parent (place(relwidth=1, relheight=1)).

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if not self._is_mounted or self._overlay_frame is None:
            raise RuntimeError("AuthOverlay not mounted. Call mount() first.")

        if self._is_visible:
            return

        self._overlay_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        try:
            self._overlay_frame.lift()
        except tk.TclError:
            pass
        self._is_visible = True

        self.set_status("Enter credentials", "info")
        self.wipe_credentials()
        if self._mfa_form is not None:
            self._mfa_form.focus_password()

    def hide(self) -> None:
        """Скрывает overlay и очищает credentials."""
        if not self._is_visible or self._overlay_frame is None:
            return

        self._overlay_frame.place_forget()
        self.wipe_credentials()
        self._is_visible = False

    def is_visible(self) -> bool:
        """Виден ли overlay.

        Returns:
            True если overlay виден.
        """
        return self._is_visible

    def set_status(self, message: str, status_type: str = "info") -> None:
        """Устанавливает статусное сообщение.

        Args:
            message: Текст сообщения.
            status_type: Тип статуса — "info", "error", "success", "warning".
        """
        if self._status_label is None:
            return

        color_map = {
            "info": self.INFO_FG,
            "error": self.ERROR_FG,
            "success": self.SUCCESS_FG,
            "warning": self.WARNING_FG,
        }

        color = color_map.get(status_type, self.INFO_FG)
        self._status_label.config(text=f"Status: {message}", fg=color)

    def wipe_credentials(self) -> None:
        """Security: очистить поля ввода.

        Очищает все поля ввода credentials для предотвращения
        утечки sensitive данных.
        """
        if self._mfa_form is not None:
            self._mfa_form.wipe_credentials()

    # -------------------------------------------------------------------------
    # Event Handlers
    # -------------------------------------------------------------------------

    def _on_mfa_submit(self, username: str, password: str, method: str, token: str) -> bool:
        """Обработчик отправки формы MFA.

        Args:
            username: Введённый username.
            password: Введённый пароль.
            method: Выбранный метод MFA.
            token: Введённый MFA токен.

        Returns:
            True если аутентификация успешна.
        """
        if self._auth_service is None:
            self.set_status("Auth service not configured", "error")
            return False

        factor_type: Optional[str] = None
        factor_credential: Optional[str] = None

        if method == MFAForm.METHOD_TOTP:
            factor_type = "totp"
            factor_credential = token
        elif method == MFAForm.METHOD_BACKUP:
            factor_type = "backupcode"
            factor_credential = token
        elif method == MFAForm.METHOD_FIDO2:
            # FIDO2 обрабатывается через отдельный callback _on_fido2_request,
            # который вызывается из MFAForm._perform_fido2_authentication.
            # Если мы оказались здесь — значит callback не подключён.
            self.set_status(
                "FIDO2 requires hardware key setup. Use Security → FIDO2 Setup to register a key.",
                "warning",
            )
            return False

        self.set_status("Authenticating...", "info")

        try:
            result = self._auth_service.authenticate(
                user_id=username,
                password=password,
                factor_type=factor_type,
                factor_credential=factor_credential,
            )

            if result.success:
                self.set_status("Authentication successful!", "success")
                if self._auth_success_callback is not None:
                    self._auth_success_callback()
                self.hide()
                return True
            else:
                failure_msg = self._get_friendly_error(result.failure_reason)
                self.set_status(failure_msg, "error")
                return False

        except (OSError, ValueError, RuntimeError) as e:
            # Логирование ошибки аутентификации без раскрытия sensitive данных
            logger.error("Authentication failed: %s", e)
            self.set_status("Authentication failed", "error")
            return False

    def _on_fido2_request(self, username: str, password: str) -> bool:
        """Обработчик FIDO2-аутентификации.

        Args:
            username: Введённый username.
            password: Введённый пароль.

        Returns:
            True если аутентификация успешна.
        """
        if self._auth_service is None:
            self.set_status("Auth service not configured", "error")
            return False

        self.set_status("Authenticating FIDO2...", "info")

        try:
            result = self._auth_service.authenticate(
                user_id=username,
                password=password,
                factor_type="fido2",
                factor_credential=None,
            )

            if result.success:
                self.set_status("Authentication successful!", "success")
                if self._auth_success_callback is not None:
                    self._auth_success_callback()
                self.hide()
                return True
            else:
                failure_msg = self._get_friendly_error(result.failure_reason)
                self.set_status(failure_msg, "error")
                return False

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("FIDO2 authentication failed: %s", e)
            self.set_status("FIDO2 authentication failed", "error")
            return False

    def _on_cancel(self) -> None:
        """Обработчик кнопки Cancel.

        Очищает credentials, вызывает on_cancel callback и скрывает overlay.
        """
        self.wipe_credentials()

        if self._cancel_callback is not None:
            self._cancel_callback()

        self.hide()

    def _get_friendly_error(self, failure_reason: Optional[str]) -> str:
        """Преобразует техническую причину ошибки в user-friendly сообщение.

        Args:
            failure_reason: Техническая причина ошибки.

        Returns:
            User-friendly сообщение об ошибке.
        """
        error_map: dict[str, str] = {
            "invalid_password": "Invalid username or password",  # nosec: B105
            "password_error": "Authentication error",  # nosec: B105
            "mfa_missing": "Second factor required",
            "mfa_error": "Second factor error",
            "invalid_mfa": "Invalid second factor code",
        }

        if failure_reason is not None and failure_reason in error_map:
            return error_map[failure_reason]
        return "Authentication failed"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "AuthOverlay",
    "AuthServiceProtocol",
    "AuthResult",
]
