"""MFAGate — единая точка входа для MFA операций в FX Text Processor 3.

Модуль реализует паттерн Decorator для MFA-gated операций. Предоставляет:
- ``MFAGate.execute()`` — декоратор операций с автоматическим MFA challenge.
- ``MFAMethodSelectorDialog`` — модальный диалог выбора метода верификации.
- Обратную совместимость с ``challenge()`` и ``verify_transition()``.

Example:
    >>> from src.gui.security.mfa_gate import MFAGate
    >>> mfa_gate = MFAGate(auth_service)
    >>> result = mfa_gate.execute(
    ...     parent=window,
    ...     operation=lambda: approve_document(doc_id),
    ...     operation_name="Согласование документа",
    ...     requires_mfa=True,
    ... )
    >>> if result is not None:
    ...     print("Операция выполнена")

Version: 2.0 (MFAGate Decorator Pattern)
Date: May 2026
Security: CRITICAL-001
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional, Protocol, Type, TypeVar, cast

from src.security.crypto.core.exceptions import AuthError, CryptoError
from src.security.audit import AuditEventType, AuditLog

logger: logging.Logger = logging.getLogger(__name__)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Константы UI
# ---------------------------------------------------------------------------

DIALOG_WIDTH: int = 420
DIALOG_HEIGHT: int = 380
COLOR_BG: str = "#f8f9fa"
COLOR_SUCCESS: str = "#27ae60"
COLOR_ERROR: str = "#e74c3c"
COLOR_INFO: str = "#3498db"
COLOR_WARNING: str = "#f39c12"
COLOR_DISABLED: str = "#7f8c8d"


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


class AuthServiceProtocol(Protocol):
    """Протокол сервиса аутентификации для MFAGate.

    Совместим с :class:`~src.controller.auth_controller.AuthController`
    и :class:`~src.security.auth.auth_service.AuthService` через
    structural subtyping.
    """

    def is_mfa_verified(self) -> bool:
        """True если MFA пройдена в текущей сессии."""
        ...

    def mark_mfa_satisfied(self) -> bool:
        """Помечает MFA как пройденную."""
        ...

    def get_current_user(self) -> Optional[str]:
        """Возвращает ID текущего пользователя."""
        ...

    def verify_totp(self, user_id: str, code: str) -> bool:
        """Верифицирует TOTP код."""
        ...

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Верифицирует резервный код."""
        ...


class MFADialog(Protocol):
    """Протокол для MFA диалогов (legacy)."""

    def show(self, parent: tk.Widget) -> Optional["MFAResult"]:
        """Показывает диалог и возвращает результат."""
        ...

    def get_method(self) -> str:
        """Возвращает метод MFA."""
        ...


# ---------------------------------------------------------------------------
# Enums / Data classes
# ---------------------------------------------------------------------------


class MFAMethod(str, Enum):
    """Доступные методы MFA."""

    PASSWORD = "password"  # noqa: S105
    TOTP = "totp"
    FIDO2 = "fido2"
    BACKUP_CODE = "backup_code"


@dataclass(frozen=True)
class MFAResult:
    """Результат MFA верификации.

    Attributes:
        verified: True если верификация успешна.
        method: Метод, которым прошла верификация.
        timestamp: Время верификации.
        audit_token: Токен для записи в AuditService.
        user_id: ID пользователя.
        error_message: Сообщение об ошибке (если failed).
    """

    verified: bool
    method: str
    timestamp: datetime
    audit_token: str
    user_id: str
    error_message: Optional[str] = None

    @classmethod
    def success(
        cls,
        method: str,
        user_id: str,
        audit_token: str,
    ) -> "MFAResult":
        """Создаёт успешный результат."""
        return cls(
            verified=True,
            method=method,
            timestamp=datetime.now(),
            audit_token=audit_token,
            user_id=user_id,
        )

    @classmethod
    def failure(
        cls,
        method: str,
        user_id: str,
        error_message: str,
    ) -> "MFAResult":
        """Создаёт неуспешный результат."""
        return cls(
            verified=False,
            method=method,
            timestamp=datetime.now(),
            audit_token="",  # nosec: B105,B106
            user_id=user_id,
            error_message=error_message,
        )


# ---------------------------------------------------------------------------
# MFAMethodSelectorDialog
# ---------------------------------------------------------------------------


class MFAMethodSelectorDialog(tk.Toplevel):
    """Модальный диалог выбора метода MFA верификации.

    Поддерживает методы:
    - TOTP (6-значный код)
    - Backup Code (XXXX-XXXX)
    - FIDO2 (disabled, placeholder)

    Интегрируется с сервисом аутентификации через ``AuthServiceProtocol``.

    Attributes:
        _auth_service: Сервис аутентификации.
        _operation_name: Название операции для отображения.
        _user_id: ID пользователя (определяется автоматически).
        _result: Результат диалога (MFAResult или None).
    """

    def __init__(
        self,
        parent: tk.Widget,
        auth_service: AuthServiceProtocol,
        operation_name: str,
        user_id: Optional[str] = None,
    ) -> None:
        """Инициализация диалога MFA.

        Args:
            parent: Родительский виджет для модальности.
            auth_service: Сервис аутентификации.
            operation_name: Название операции (отображается в заголовке).
            user_id: ID пользователя (если None — определяется из auth_service).
        """
        super().__init__(cast(Any, parent))

        self._auth_service: AuthServiceProtocol = auth_service
        self._operation_name: str = operation_name
        self._user_id: str = user_id or auth_service.get_current_user() or "operator"
        self._result: Optional[MFAResult] = None
        self._current_method: str = MFAMethod.TOTP.value

        # UI refs
        self._code_entry: Optional[tk.Entry] = None
        self._code_label: Optional[tk.Label] = None
        self._status_label: Optional[tk.Label] = None
        self._method_var: tk.StringVar = tk.StringVar(value=MFAMethod.TOTP.value)
        self._verify_btn: Optional[tk.Button] = None

        self._setup_window(parent)
        self._create_ui()
        self._center_window(parent)

    # ------------------------------------------------------------------
    # Window setup
    # ------------------------------------------------------------------

    def _setup_window(self, parent: tk.Widget) -> None:
        """Настраивает параметры окна."""
        self.title("MFA Verification Required")
        self.transient(cast(tk.Wm, parent))
        self.resizable(False, False)
        self.configure(bg=COLOR_BG)
        self.grab_set()

    def _center_window(self, parent: tk.Widget) -> None:
        """Центрирует окно относительно родителя."""
        self.update_idletasks()
        try:
            toplevel = cast(tk.Tk, parent.winfo_toplevel())
            px = toplevel.winfo_x()
            py = toplevel.winfo_y()
            pw = toplevel.winfo_width()
            ph = toplevel.winfo_height()
            x = px + (pw - DIALOG_WIDTH) // 2
            y = py + (ph - DIALOG_HEIGHT) // 2
            self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")
        except (tk.TclError, AttributeError, RuntimeError):
            self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _create_ui(self) -> None:
        """Создаёт UI компоненты."""
        main_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Operation name
        op_label = tk.Label(
            main_frame,
            text=self._operation_name,
            font=("Arial", 12, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
            wraplength=DIALOG_WIDTH - 60,
        )
        op_label.pack(pady=(0, 5))

        # Description
        desc = tk.Label(
            main_frame,
            text="Для выполнения операции требуется MFA верификация.",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#666666",
            wraplength=DIALOG_WIDTH - 60,
        )
        desc.pack(pady=(0, 15))

        # Method selector
        self._create_method_selector(main_frame)

        # Code entry
        self._create_code_entry(main_frame)

        # Status
        self._status_label = tk.Label(
            main_frame,
            text="",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg=COLOR_ERROR,
        )
        self._status_label.pack(pady=(10, 0))

        # Buttons
        self._create_buttons(main_frame)

        # Bindings
        self.bind("<Return>", lambda _: self._on_verify())
        self.bind("<Escape>", lambda _: self._on_cancel())

    def _create_method_selector(self, parent: tk.Frame) -> None:
        """Создаёт селектор метода MFA."""
        method_frame = tk.LabelFrame(
            parent,
            text=" Метод верификации ",
            bg=COLOR_BG,
            fg="#333333",
            font=("Arial", 9, "bold"),
            padx=10,
            pady=10,
        )
        method_frame.pack(fill=tk.X, pady=(0, 15))

        # FIDO2 (disabled)
        fido2_frame = tk.Frame(method_frame, bg=COLOR_BG)
        fido2_frame.pack(fill=tk.X, pady=(0, 5))

        fido2_radio = tk.Radiobutton(
            fido2_frame,
            variable=self._method_var,
            value=MFAMethod.FIDO2.value,
            font=("Arial", 9),
            bg=COLOR_BG,
            state="disabled",
        )
        fido2_radio.pack(side=tk.LEFT)

        fido2_label = tk.Label(
            fido2_frame,
            text="FIDO2 Security Key",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg=COLOR_DISABLED,
        )
        fido2_label.pack(side=tk.LEFT)

        fido2_hint = tk.Label(
            fido2_frame,
            text="(требуется устройство)",
            font=("Arial", 8, "italic"),
            bg=COLOR_BG,
            fg=COLOR_DISABLED,
        )
        fido2_hint.pack(side=tk.LEFT, padx=(5, 0))

        # TOTP
        totp_frame = tk.Frame(method_frame, bg=COLOR_BG)
        totp_frame.pack(fill=tk.X, pady=(0, 5))

        totp_radio = tk.Radiobutton(
            totp_frame,
            variable=self._method_var,
            value=MFAMethod.TOTP.value,
            font=("Arial", 9),
            bg=COLOR_BG,
            command=self._on_method_changed,
        )
        totp_radio.pack(side=tk.LEFT)

        totp_label = tk.Label(
            totp_frame,
            text="TOTP (6-значный код)",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#333333",
        )
        totp_label.pack(side=tk.LEFT)

        # Backup Code
        backup_frame = tk.Frame(method_frame, bg=COLOR_BG)
        backup_frame.pack(fill=tk.X)

        backup_radio = tk.Radiobutton(
            backup_frame,
            variable=self._method_var,
            value=MFAMethod.BACKUP_CODE.value,
            font=("Arial", 9),
            bg=COLOR_BG,
            command=self._on_method_changed,
        )
        backup_radio.pack(side=tk.LEFT)

        backup_label = tk.Label(
            backup_frame,
            text="Резервный код",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#333333",
        )
        backup_label.pack(side=tk.LEFT)

    def _create_code_entry(self, parent: tk.Frame) -> None:
        """Создаёт поле ввода кода."""
        entry_frame = tk.Frame(parent, bg=COLOR_BG)
        entry_frame.pack(fill=tk.X, pady=(0, 10))

        self._code_label = tk.Label(
            entry_frame,
            text="Введите 6-значный код:",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#333333",
        )
        self._code_label.pack(anchor=tk.W, pady=(0, 5))

        self._code_entry = tk.Entry(
            entry_frame,
            font=("Courier", 16, "bold"),
            justify=tk.CENTER,
            width=20,
            relief=tk.SOLID,
            bd=2,
        )
        self._code_entry.pack(fill=tk.X)
        self._code_entry.focus_set()

    def _create_buttons(self, parent: tk.Frame) -> None:
        """Создаёт кнопки Cancel и Verify."""
        btn_frame = tk.Frame(parent, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X, pady=(20, 0))

        tk.Frame(btn_frame, bg=COLOR_BG).pack(side=tk.LEFT, fill=tk.X, expand=True)

        cancel_btn = tk.Button(
            btn_frame,
            text="Отмена",
            width=12,
            command=self._on_cancel,
            font=("Arial", 9),
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))

        self._verify_btn = tk.Button(
            btn_frame,
            text="Подтвердить",
            width=12,
            command=self._on_verify,
            font=("Arial", 9, "bold"),
            bg=COLOR_INFO,
            fg="white",
        )
        self._verify_btn.pack(side=tk.RIGHT)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_method_changed(self) -> None:
        """Обработчик смены метода MFA."""
        method = self._method_var.get()
        self._current_method = method

        if self._code_label is not None:
            if method == MFAMethod.TOTP.value:
                self._code_label.config(text="Введите 6-значный код:")
            else:
                self._code_label.config(text="Введите резервный код (XXXX-XXXX):")

        if self._status_label is not None:
            self._status_label.config(text="")

        if self._code_entry is not None:
            self._code_entry.delete(0, tk.END)
            self._code_entry.focus_set()

    def _on_verify(self) -> None:
        """Обработчик нажатия кнопки Verify."""
        if self._code_entry is None:
            return

        code = self._code_entry.get().strip()

        # Валидация формата
        if self._current_method == MFAMethod.TOTP.value:
            if len(code) != 6 or not code.isdigit():
                self._show_error("Введите 6-значный код")
                return
        else:  # backup_code
            normalized = code.upper().replace("-", "")
            if len(normalized) != 8 or not normalized.isalnum():
                self._show_error("Неверный формат (XXXX-XXXX)")
                return

        # Верификация через auth_service
        try:
            if self._current_method == MFAMethod.TOTP.value:
                verified = self._auth_service.verify_totp(self._user_id, code)
            else:
                verified = self._auth_service.verify_backup_code(self._user_id, code)

            if verified:
                self._on_verification_success()
            else:
                self._show_error("Неверный код. Попробуйте снова.")

        except (AuthError, CryptoError) as e:
            # Security: CRITICAL logging and generic UI alert
            logger.critical("MFA authentication failed: %s", e, exc_info=True)
            self._show_error("Ошибка верификации")
        except Exception as e:
            logger.error("Unexpected MFA verification error: %s", e, exc_info=True)
            self._show_error("Произошла непредвиденная ошибка")

    def _on_verification_success(self) -> None:
        """Обработчик успешной верификации."""
        self._result = MFAResult.success(
            method=self._current_method,
            user_id=self._user_id,
            audit_token=f"{self._user_id}:mfa:{self._current_method}",
        )

        # Отметить MFA как пройденную
        try:
            self._auth_service.mark_mfa_satisfied()
        except (AttributeError, ValueError, TypeError, RuntimeError) as e:
            logger.warning("Failed to mark MFA satisfied: %s", e)

        self._show_success("Верификация успешна!")
        self.after(500, self.destroy)

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        self._result = MFAResult.failure(
            method=self._current_method,
            user_id=self._user_id,
            error_message="MFA verification cancelled",
        )
        self.destroy()

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке."""
        if self._status_label is not None:
            self._status_label.config(text=f"✗ {message}", fg=COLOR_ERROR)

    def _show_success(self, message: str) -> None:
        """Показывает сообщение об успехе."""
        if self._status_label is not None:
            self._status_label.config(text=f"✓ {message}", fg=COLOR_SUCCESS)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show(self) -> Optional[MFAResult]:
        """Показывает диалог модально и возвращает результат.

        Returns:
            MFAResult при успехе, None при отмене.
        """
        self.wait_window()
        if self._result is not None and self._result.verified:
            return self._result
        return None


# ---------------------------------------------------------------------------
# MFAGate
# ---------------------------------------------------------------------------


class MFAGate:
    """Единая точка входа для MFA операций.

    Реализует паттерн Decorator: оборачивает операцию в MFA challenge.
    Интегрируется с AuthService для проверки credentials
    и с AuditService для логирования.

    Attributes:
        _auth_service: Сервис аутентификации.
        _audit_log: Опциональный AuditLog.
        _dialogs: Реестр legacy MFA диалогов.

    Example:
        >>> mfa_gate = MFAGate(auth_service, audit_log)
        >>> result = mfa_gate.execute(
        ...     parent=window,
        ...     operation=lambda: do_sensitive_op(),
        ...     operation_name="Подписание документа",
        ...     requires_mfa=True,
        ... )
    """

    def __init__(
        self,
        auth_service: AuthServiceProtocol,
        audit_log: Optional[AuditLog] = None,
    ) -> None:
        """Инициализация MFAGate.

        Args:
            auth_service: Сервис аутентификации (AuthController или AuthService).
            audit_log: Опциональный AuditLog.
        """
        self._auth_service = auth_service
        self._audit_log = audit_log
        self._dialogs: dict[str, Type[MFADialog]] = {}

    # ------------------------------------------------------------------
    # Decorator API (новый)
    # ------------------------------------------------------------------

    def execute(
        self,
        parent: tk.Widget,
        operation: Callable[[], T],
        operation_name: str,
        requires_mfa: bool = True,
    ) -> Optional[T]:
        """Выполняет операцию с автоматическим MFA challenge.

        Паттерн Decorator: если MFA требуется и не пройдена,
        показывает ``MFAMethodSelectorDialog`` перед выполнением.

        Args:
            parent: Родительский виджет для модального диалога.
            operation: Операция для выполнения (без аргументов).
            operation_name: Название операции (отображается в диалоге).
            requires_mfa: Если False — операция выполняется без MFA.

        Returns:
            Результат operation() или None если MFA отменена / не пройдена.

        Example:
            >>> result = mfa_gate.execute(
            ...     parent=root,
            ...     operation=lambda: transition(doc_id, target),
            ...     operation_name="Согласование документа",
            ... )
            >>> if result is None:
            ...     print("Операция отменена")
        """
        if not requires_mfa:
            return operation()

        if self._auth_service.is_mfa_verified():
            return operation()

        # MFA требуется — показываем диалог
        dialog = MFAMethodSelectorDialog(
            parent=parent,
            auth_service=self._auth_service,
            operation_name=operation_name,
        )
        mfa_result = dialog.show()

        if mfa_result is not None and mfa_result.verified:
            try:
                self._auth_service.mark_mfa_satisfied()
            except (AuthError, CryptoError) as e:
                logger.critical("Failed to mark MFA satisfied (security error): %s", e, exc_info=True)
            except Exception as e:
                logger.warning("Failed to mark MFA satisfied: %s", e, exc_info=True)
            self._log_mfa_success(
                user_id=mfa_result.user_id,
                method=mfa_result.method,
                operation=operation_name,
                audit_token=mfa_result.audit_token,
            )
            return operation()

        # Отмена или неудача
        self._log_mfa_failure(
            user_id=getattr(mfa_result, "user_id", "unknown"),
            method=getattr(mfa_result, "method", "unknown"),
            operation=operation_name,
        )
        return None

    # ------------------------------------------------------------------
    # Legacy API (сохраняется для обратной совместимости)
    # ------------------------------------------------------------------

    def register_dialog(
        self,
        method: str,
        dialog_class: Type[MFADialog],
    ) -> None:
        """Регистрирует диалог для метода MFA (legacy).

        Args:
            method: Метод MFA.
            dialog_class: Класс диалога.
        """
        self._dialogs[method] = dialog_class

    def challenge(
        self,
        parent: tk.Widget,
        user_id: str,
        required_methods: list[str],
        operation: str,
        **kwargs: Any,
    ) -> MFAResult:
        """Legacy: вызывает MFA диалог для верификации.

        Args:
            parent: Родительский виджет.
            user_id: ID пользователя.
            required_methods: Список допустимых методов.
            operation: Описание операции для audit log.
            **kwargs: Дополнительные параметры.

        Returns:
            MFAResult с результатом верификации.
        """
        audit_token = self._generate_audit_token(user_id, operation)

        for method in required_methods:
            dialog_class = self._dialogs.get(method)
            if dialog_class is None:
                continue

            try:
                dialog = dialog_class()
                result = dialog.show(parent)

                if result is not None and result.verified:
                    self._log_mfa_success(
                        user_id=user_id,
                        method=method,
                        operation=operation,
                        audit_token=audit_token,
                    )
                    return MFAResult.success(
                        method=method,
                        user_id=user_id,
                        audit_token=audit_token,
                    )

            except Exception as e:
                self._log_mfa_error(
                    user_id=user_id,
                    method=method,
                    operation=operation,
                    error=str(e),
                )
                continue

        return MFAResult.failure(
            method=",".join(required_methods),
            user_id=user_id,
            error_message="MFA verification failed for all methods",
        )

    def verify_transition(
        self,
        from_status: Any,
        to_status: Any,
        user_id: str,
    ) -> tuple[bool, Optional[MFAResult]]:
        """Legacy: проверяет необходимость MFA для workflow transition.

        Args:
            from_status: Исходный статус.
            to_status: Целевой статус.
            user_id: ID пользователя.

        Returns:
            Кортеж (requires_mfa, mfa_result).
        """
        from src.documents.constructor.form_status import FormStatus

        mfa_required_transitions: set[tuple[Any, Any]] = {
            (FormStatus.DRAFT, getattr(FormStatus, "APPROVED", None)),
            (FormStatus.DRAFT, getattr(FormStatus, "REJECTED", None)),
            (FormStatus.DRAFT, FormStatus.SIGNED),
            (FormStatus.VALIDATED, getattr(FormStatus, "APPROVED", None)),
            (FormStatus.VALIDATED, getattr(FormStatus, "REJECTED", None)),
        }
        mfa_required_transitions = {t for t in mfa_required_transitions if t[1] is not None}

        try:
            current = (
                FormStatus(from_status) if not isinstance(from_status, FormStatus) else from_status
            )
            target = FormStatus(to_status) if not isinstance(to_status, FormStatus) else to_status
        except (ValueError, TypeError):
            return False, None

        requires_mfa = (current, target) in mfa_required_transitions

        if not requires_mfa:
            return False, None

        return True, None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_audit_token(self, user_id: str, operation: str) -> str:
        """Генерирует токен для audit log."""
        import uuid

        return f"{user_id}:{operation}:{uuid.uuid4().hex[:16]}"

    def _log_mfa_success(
        self,
        user_id: str,
        method: str,
        operation: str,
        audit_token: str,
    ) -> None:
        """Логирует успешную MFA верификацию."""
        logger.info("MFA success for user %s via %s", user_id, method)

        if self._audit_log:
            try:
                self._audit_log.log_event(
                    AuditEventType.AUTH_MFA_SUCCESS,
                    details={
                        "user_id": user_id,
                        "method": method,
                        "operation": operation,
                        "audit_token": audit_token,
                    },
                )
            except Exception as e:
                logger.error("Failed to log MFA success to audit: %s", e)

    def _log_mfa_error(
        self,
        user_id: str,
        method: str,
        operation: str,
        error: str,
    ) -> None:
        """Логирует ошибку MFA в audit."""
        logger.warning("MFA failed for user %s: %s", user_id, error)

        if self._audit_log:
            try:
                self._audit_log.log_event(
                    AuditEventType.AUTH_MFA_FAILED,
                    details={
                        "user_id": user_id,
                        "method": method,
                        "operation": operation,
                        "error": error,
                    },
                )
            except Exception as e:
                logger.error("Failed to log MFA error to audit: %s", e)

    def _log_mfa_failure(
        self,
        user_id: str,
        method: str,
        operation: str,
    ) -> None:
        """Логирует отмену MFA."""
        logger.info("MFA cancelled for user %s (operation: %s)", user_id, operation)

        if self._audit_log:
            try:
                self._audit_log.log_event(
                    AuditEventType.AUTH_MFA_FAILED,
                    details={
                        "user_id": user_id,
                        "method": method,
                        "operation": operation,
                        "reason": "cancelled",
                    },
                )
            except Exception as e:
                logger.error("Failed to log MFA cancellation to audit: %s", e)


# =============================================================================
# Module exports
# =============================================================================

__all__: list[str] = [
    "MFAGate",
    "MFAResult",
    "MFAMethod",
    "MFADialog",
    "MFAMethodSelectorDialog",
    "AuthServiceProtocol",
]
