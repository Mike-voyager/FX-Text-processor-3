"""Контроллер аутентификации FX Text Processor 3.

Управляет жизненным циклом аутентификации и сессии:
- Вход/выход в систему
- MFA верификация
- Блокировка/разблокировка сессии
- Переключение ролей workflow

Интегрируется с AuthWindow и security services.

Example:
    >>> controller = AuthController(
    ...     password_service=password_service,
    ...     session_manager=session_manager,
    ...     mfa_manager=mfa_manager,
    ... )
    >>> if controller.authenticate("user", "password", mfa_code="123456"):
    ...     print("Вход выполнен")
    ...     print(f"Токен: {controller.get_session_token()}")
"""

from __future__ import annotations

import enum
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Final, FrozenSet, List, Optional, Set

from src.security.auth.code_service import validate_backup_code_for_user
from src.security.auth.fido2_service import (
    get_fido2_status,
    validate_fido2_response,
)
from src.security.auth.password_service import (
    AccountLockedError,
    PasswordExpiredError,
    PasswordService,
)
from src.security.auth.second_factor import SecondFactorManager
from src.security.auth.session import (
    InvalidToken,
    SessionManager,
    TokenExpired,
    TokenRevoked,
)
from src.security.auth.totp_service import (
    TotpInvalidCode,
    TotpLockedOut,
    TotpNotConfigured,
    validate_totp_code,
)

logger = logging.getLogger(__name__)


class WorkflowRole(enum.Enum):
    """Роли внутри single-operator workflow.

    Это не разные пользователи, а режимы работы
    одного оператора с разными правами.
    """

    OPERATOR = "operator"  # Заполнение формы
    EDITOR = "editor"  # Редактирование/проверка
    SUPERVISOR = "supervisor"  # Согласование
    SIGNATORY = "signatory"  # Подписание


class AuthState(enum.Enum):
    """Состояние аутентификации."""

    UNAUTHENTICATED = "unauthenticated"  # Не аутентифицирован
    AUTHENTICATED = "authenticated"  # Аутентифицирован
    LOCKED = "locked"  # Заблокирован (без logout)


class FactorType(enum.Enum):
    """Типы факторов MFA."""

    PASSWORD = "password"
    TOTP = "totp"
    FIDO2 = "fido2"
    BACKUP_CODE = "backup_code"


class AuthErrorCode(enum.Enum):
    """Коды ошибок аутентификации."""

    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    PASSWORD_EXPIRED = "password_expired"
    MFA_REQUIRED = "mfa_required"
    MFA_INVALID = "mfa_invalid"
    MFA_LOCKED = "mfa_locked"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    SESSION_LOCKED = "session_locked"
    INSUFFICIENT_PRIVILEGES = "insufficient_privileges"
    UNKNOWN_ERROR = "unknown_error"


class AuthContext:
    """Контекст аутентификации для операций.

    Attributes:
        user_id: Идентификатор пользователя
        session_token: Токен доступа
        role: Текущая роль workflow
        mfa_verified: MFA пройдена
        scopes: Разрешённые scope
        issued_at: Время выдачи сессии
    """

    user_id: str
    session_token: str
    role: WorkflowRole
    mfa_verified: bool
    scopes: FrozenSet[str]
    issued_at: datetime


@dataclass(frozen=True)
class RoleTransitionRule:
    """Правило перехода между ролями."""

    from_role: WorkflowRole
    to_role: WorkflowRole
    requires_mfa: bool


@dataclass
class AuthResult:
    """Результат операции аутентификации.

    Attributes:
        success: Успешность операции
        error_code: Код ошибки (если неудача)
        error_message: Сообщение об ошибке
        context: Контекст аутентификации (при успехе)
    """

    success: bool
    error_code: str = ""
    error_message: str = ""
    context: Optional[AuthContext] = None


class AuthError(Exception):
    """Базовое исключение для ошибок аутентификации."""

    pass


class AuthenticationRequiredError(AuthError):
    """Требуется аутентификация."""

    pass


class MFAVerificationError(AuthError):
    """Ошибка MFA верификации."""

    pass


class SessionLockedError(AuthError):
    """Сессия заблокирована."""

    pass


class AuthController:
    """Контроллер аутентификации и управления сессией.

    Координирует работу с сервисами безопасности:
    - PasswordService — верификация пароля
    - SessionManager — управление токенами
    - SecondFactorManager — MFA
    - FIDO2Service — аппаратные ключи
    - TOTPService — TOTP коды
    - CodeService — резервные коды

    Attributes:
        _password_service: Сервис паролей
        _session_manager: Менеджер сессий
        _mfa_manager: Менеджер второго фактора
        _state: Текущее состояние аутентификации
        _current_user_id: Текущий пользователь
        _current_role: Текущая роль
        _session_token: Токен сессии
        _refresh_token: Refresh токен
        _session_id: ID сессии
        _mfa_verified: Флаг MFA верификации
        _lock: Блокировка для потокобезопасности
        _state_listeners: Подписчики на изменения состояния
    """

    # Правила перехода между ролями: (from, to) -> требуется MFA
    ROLE_TRANSITIONS: Final[Dict[tuple[WorkflowRole, WorkflowRole], bool]] = {
        # OPERATOR может переключаться
        (WorkflowRole.OPERATOR, WorkflowRole.EDITOR): False,
        (WorkflowRole.OPERATOR, WorkflowRole.SUPERVISOR): True,
        (WorkflowRole.OPERATOR, WorkflowRole.SIGNATORY): True,
        # EDITOR может переключаться
        (WorkflowRole.EDITOR, WorkflowRole.OPERATOR): False,
        (WorkflowRole.EDITOR, WorkflowRole.SUPERVISOR): True,
        (WorkflowRole.EDITOR, WorkflowRole.SIGNATORY): True,
        # SUPERVISOR может переключаться
        (WorkflowRole.SUPERVISOR, WorkflowRole.OPERATOR): True,
        (WorkflowRole.SUPERVISOR, WorkflowRole.EDITOR): True,
        (WorkflowRole.SUPERVISOR, WorkflowRole.SIGNATORY): False,
        # SIGNATORY может переключаться
        (WorkflowRole.SIGNATORY, WorkflowRole.OPERATOR): True,
        (WorkflowRole.SIGNATORY, WorkflowRole.EDITOR): True,
        (WorkflowRole.SIGNATORY, WorkflowRole.SUPERVISOR): False,
    }

    # Роли, требующие MFA для любых операций
    PRIVILEGED_ROLES: Final[Set[WorkflowRole]] = {
        WorkflowRole.SUPERVISOR,
        WorkflowRole.SIGNATORY,
    }

    def __init__(
        self,
        password_service: PasswordService,
        session_manager: SessionManager,
        mfa_manager: SecondFactorManager,
        default_role: WorkflowRole = WorkflowRole.OPERATOR,
    ) -> None:
        """Инициализация контроллера аутентификации.

        Args:
            password_service: Сервис управления паролями
            session_manager: Менеджер сессий
            mfa_manager: Менеджер второго фактора
            default_role: Роль по умолчанию после входа
        """
        self._password_service = password_service
        self._session_manager = session_manager
        self._mfa_manager = mfa_manager
        self._default_role = default_role

        self._state = AuthState.UNAUTHENTICATED
        self._current_user_id: Optional[str] = None
        self._current_role: Optional[WorkflowRole] = None
        self._session_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._session_id: Optional[str] = None
        self._mfa_verified = False
        self._scopes: FrozenSet[str] = frozenset()
        self._locked_at: Optional[datetime] = None

        self._lock = threading.RLock()
        self._state_listeners: List[Callable[[AuthState, AuthState], None]] = []

        logger.debug("AuthController initialized")

    # === Управление подписчиками ===

    def add_state_listener(self, callback: Callable[[AuthState, AuthState], None]) -> None:
        """Добавить подписчика на изменения состояния.

        Args:
            callback: Функция (old_state, new_state) -> None
        """
        with self._lock:
            self._state_listeners.append(callback)

    def remove_state_listener(self, callback: Callable[[AuthState, AuthState], None]) -> None:
        """Удалить подписчика."""
        with self._lock:
            if callback in self._state_listeners:
                self._state_listeners.remove(callback)

    def _notify_state_change(self, old_state: AuthState, new_state: AuthState) -> None:
        """Уведомить подписчиков об изменении состояния."""
        for listener in self._state_listeners:
            try:
                listener(old_state, new_state)
            except Exception as e:
                logger.warning("State listener failed: %s", e)

    def _set_state(self, new_state: AuthState) -> None:
        """Изменить состояние с уведомлением."""
        with self._lock:
            old_state = self._state
            if old_state != new_state:
                self._state = new_state
                self._notify_state_change(old_state, new_state)
                logger.debug("Auth state changed: %s -> %s", old_state.value, new_state.value)

    # === Основные методы аутентификации ===

    def authenticate(
        self,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> AuthResult:
        """Аутентификация пользователя.

        Выполняет двухфакторную аутентификацию:
        1. Верификация пароля через PasswordService
        2. MFA верификация (если настроена)

        Args:
            username: Идентификатор пользователя
            password: Пароль
            mfa_code: MFA код (TOTP/Backup) или None
            device_fingerprint: Отпечаток устройства
            ip: IP адрес

        Returns:
            Результат аутентификации

        Example:
            >>> result = controller.authenticate("user", "password", mfa_code="123456")
            >>> if result.success:
            ...     print("Вход выполнен")
            ... else:
            ...     print(f"Ошибка: {result.error_message}")
        """
        with self._lock:
            # Сброс текущего состояния
            self._clear_session()

            # Шаг 1: Верификация пароля
            try:
                password_valid = self._password_service.verify_password(username, password)
            except AccountLockedError:
                return AuthResult(
                    success=False,
                    error_code="ACCOUNT_LOCKED",
                    error_message="Аккаунт заблокирован. Обратитесь к администратору.",
                )
            except PasswordExpiredError:
                return AuthResult(
                    success=False,
                    error_code="PASSWORD_EXPIRED",
                    error_message="Срок действия пароля истёк. Требуется смена пароля.",
                )
            except Exception as e:
                logger.error("Password verification error: %s", e)
                return AuthResult(
                    success=False,
                    error_code="PASSWORD_ERROR",
                    error_message="Ошибка проверки пароля. Попробуйте позже.",
                )

            if not password_valid:
                return AuthResult(
                    success=False,
                    error_code="INVALID_CREDENTIALS",
                    error_message="Неверный пароль.",
                )

            # Шаг 2: Проверка MFA (если настроено)
            requires_mfa = self._check_mfa_required(username)
            if requires_mfa:
                if not mfa_code:
                    return AuthResult(
                        success=False,
                        error_code="MFA_REQUIRED",
                        error_message="Требуется двухфакторная аутентификация.",
                    )

                mfa_valid = self._verify_mfa_code(username, mfa_code)
                if not mfa_valid:
                    return AuthResult(
                        success=False,
                        error_code="INVALID_MFA",
                        error_message="Неверный MFA код.",
                    )
                self._mfa_verified = True
            else:
                self._mfa_verified = False

            # Шаг 3: Создание сессии
            scopes = self._determine_scopes(self._default_role)
            try:
                bundle = self._session_manager.issue(
                    user_id=username,
                    scopes=scopes,
                    mfa_required=requires_mfa,
                    device_fingerprint=device_fingerprint,
                    ip=ip,
                )
            except Exception as e:
                logger.error("Session creation error: %s", e)
                return AuthResult(
                    success=False,
                    error_code="SESSION_ERROR",
                    error_message="Ошибка создания сессии. Попробуйте позже.",
                )

            # Сохранение состояния сессии
            self._current_user_id = username
            self._current_role = self._default_role
            self._session_token = bundle.access_token
            self._refresh_token = bundle.refresh_token
            self._session_id = bundle.session_id
            self._scopes = scopes

            # Пометка MFA как пройденной в сессии
            if self._mfa_verified:
                try:
                    self._session_manager.mark_mfa_satisfied(bundle.session_id)
                except Exception as e:
                    logger.warning("Failed to mark MFA satisfied: %s", e)

            self._set_state(AuthState.AUTHENTICATED)

            logger.info("User authenticated: %s, role: %s", username, self._default_role.value)

            context = AuthContext(
                user_id=username,
                session_token=bundle.access_token,
                role=self._default_role,
                mfa_verified=self._mfa_verified,
                scopes=scopes,
                issued_at=datetime.now(timezone.utc),
            )

            return AuthResult(success=True, context=context)

    def logout(self) -> None:
        """Выход из системы.

        Отзывает сессию и очищает все токены.
        """
        with self._lock:
            if self._session_id:
                try:
                    self._session_manager.revoke_by_session_id(self._session_id)
                    logger.info("Session revoked: %s", self._session_id)
                except Exception as e:
                    logger.warning("Failed to revoke session: %s", e)

            self._clear_session()
            self._set_state(AuthState.UNAUTHENTICATED)

    def _clear_session(self) -> None:
        """Очистка данных сессии (внутренний метод)."""
        self._current_user_id = None
        self._current_role = None
        self._session_token = None
        self._refresh_token = None
        self._session_id = None
        self._mfa_verified = False
        self._scopes = frozenset()
        self._locked_at = None

    # === MFA методы ===

    def requires_mfa(self, user_id: Optional[str] = None) -> bool:
        """Проверяет, требуется ли MFA для пользователя.

        Args:
            user_id: Идентификатор пользователя (если None — текущий)

        Returns:
            True если MFA настроена
        """
        with self._lock:
            uid = user_id or self._current_user_id
            if not uid:
                return False
            return self._check_mfa_required(uid)

    def _check_mfa_required(self, user_id: str) -> bool:
        """Внутренняя проверка MFA."""
        try:
            # Проверяем наличие настроенных факторов
            for factor_type in ["totp", "fido2", "backupcode"]:
                status = self._mfa_manager.get_status(user_id, factor_type)
                if status and status.get("state"):
                    return True
        except Exception as e:
            logger.warning("MFA check error: %s", e)
        return False

    def _verify_mfa_code(self, user_id: str, code: str) -> bool:
        """Верификация MFA кода."""
        # Нормализация кода
        normalized_code = code.strip().replace("-", "").upper()

        # Пробуем TOTP (6 цифр)
        if len(normalized_code) == 6 and normalized_code.isdigit():
            try:
                if validate_totp_code(user_id, normalized_code):
                    return True
            except TotpLockedOut:
                raise MFAVerificationError("MFA заблокировано на время")
            except (TotpNotConfigured, TotpInvalidCode):
                pass

        # Пробуем backup code (формат XXXX-XXXX)
        if len(normalized_code) == 8 and "-" not in code:
            # Формат без дефиса — добавляем
            formatted = f"{normalized_code[:4]}-{normalized_code[4:]}"
            if validate_backup_code_for_user(user_id, formatted):
                return True

        # Пробуем FIDO2 (код не требуется, но нужен ответ от authenticator)
        # FIDO2 требует отдельного вызова verify_fido2_response
        # Это обрабатывается на уровне AuthWindow

        return False

    def verify_totp(self, user_id: str, code: str) -> bool:
        """Верификация TOTP кода.

        Args:
            user_id: Идентификатор пользователя
            code: TOTP код (6 цифр)

        Returns:
            True если код верный

        Raises:
            MFAVerificationError: При ошибке верификации
        """
        try:
            return validate_totp_code(user_id, code)
        except TotpLockedOut as e:
            raise MFAVerificationError(f"MFA заблокировано на {e.remaining_seconds} сек")
        except TotpNotConfigured:
            raise MFAVerificationError("TOTP не настроен")
        except TotpInvalidCode:
            return False

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Верификация резервного кода.

        Args:
            user_id: Идентификатор пользователя
            code: Резервный код (XXXX-XXXX или XXXXXXXX)

        Returns:
            True если код верный
        """
        normalized = code.strip().upper()
        if "-" not in normalized and len(normalized) == 8:
            normalized = f"{normalized[:4]}-{normalized[4:]}"
        return validate_backup_code_for_user(user_id, normalized)

    def verify_fido2(self, user_id: str, response: Dict[str, Any]) -> bool:
        """Верификация FIDO2 ответа.

        Args:
            user_id: Идентификатор пользователя
            response: Ответ от FIDO2 authenticator

        Returns:
            True если верификация успешна
        """
        return validate_fido2_response(user_id, response)

    def is_mfa_verified(self) -> bool:
        """Проверяет, пройдена ли MFA в текущей сессии.

        Returns:
            True если MFA пройдена.
        """
        with self._lock:
            return self._mfa_verified

    def mark_mfa_satisfied(self) -> bool:
        """Пометить MFA как пройденную для текущей сессии.

        Returns:
            True если успешно
        """
        with self._lock:
            if not self._session_id:
                return False
            try:
                self._session_manager.mark_mfa_satisfied(self._session_id)
                self._mfa_verified = True
                return True
            except Exception as e:
                logger.warning("Failed to mark MFA satisfied: %s", e)
                return False

    # === Блокировка сессии ===

    def lock_session(self) -> None:
        """Блокировка сессии без logout.

        Требует повторного ввода пароля для разблокировки.
        Сессия остаётся активной на сервере.
        """
        with self._lock:
            if self._state != AuthState.AUTHENTICATED:
                return
            self._locked_at = datetime.now(timezone.utc)
            self._set_state(AuthState.LOCKED)
            logger.info("Session locked for user: %s", self._current_user_id)

    def unlock_session(self, password: str) -> AuthResult:
        """Разблокировка сессии.

        Args:
            password: Пароль пользователя

        Returns:
            Результат разблокировки
        """
        with self._lock:
            if self._state != AuthState.LOCKED:
                return AuthResult(
                    success=False,
                    error_code="NOT_LOCKED",
                    error_message="Сессия не заблокирована.",
                )

            if not self._current_user_id:
                return AuthResult(
                    success=False,
                    error_code="NO_SESSION",
                    error_message="Нет активной сессии.",
                )

            # Верификация пароля
            try:
                valid = self._password_service.verify_password(self._current_user_id, password)
            except Exception as e:
                logger.error("Unlock password verification error: %s", e)
                return AuthResult(
                    success=False,
                    error_code="VERIFICATION_ERROR",
                    error_message="Ошибка проверки пароля.",
                )

            if not valid:
                return AuthResult(
                    success=False,
                    error_code="INVALID_PASSWORD",
                    error_message="Неверный пароль.",
                )

            self._locked_at = None
            self._set_state(AuthState.AUTHENTICATED)
            logger.info("Session unlocked for user: %s", self._current_user_id)

            context = AuthContext(
                user_id=self._current_user_id,
                session_token=self._session_token or "",
                role=self._current_role or self._default_role,
                mfa_verified=self._mfa_verified,
                scopes=self._scopes,
                issued_at=datetime.now(timezone.utc),
            )

            return AuthResult(success=True, context=context)

    def is_locked(self) -> bool:
        """Проверяет, заблокирована ли сессия."""
        with self._lock:
            return self._state == AuthState.LOCKED

    # === Управление ролями ===

    def get_current_role(self) -> Optional[WorkflowRole]:
        """Возвращает текущую активную роль.

        Returns:
            Текущая роль или None если не аутентифицирован
        """
        with self._lock:
            if self._state not in (AuthState.AUTHENTICATED, AuthState.LOCKED):
                return None
            return self._current_role

    def switch_role(
        self,
        new_role: WorkflowRole,
        mfa_code: Optional[str] = None,
    ) -> AuthResult:
        """Переключение роли workflow.

        Некоторые переходы требуют MFA верификации.

        Args:
            new_role: Новая роль
            mfa_code: MFA код для привилегированных переходов

        Returns:
            Результат переключения

        Raises:
            AuthenticationRequiredError: Если не аутентифицирован
            MFAVerificationError: Если требуется MFA
        """
        with self._lock:
            if self._state not in (AuthState.AUTHENTICATED, AuthState.LOCKED):
                raise AuthenticationRequiredError("Требуется аутентификация")

            if self._state == AuthState.LOCKED:
                return AuthResult(
                    success=False,
                    error_code="SESSION_LOCKED",
                    error_message="Сессия заблокирована. Разблокируйте сначала.",
                )

            if not self._current_role:
                return AuthResult(
                    success=False,
                    error_code="NO_ROLE",
                    error_message="Текущая роль не установлена.",
                )

            if self._current_role == new_role:
                # Уже в этой роли
                context = self._create_auth_context()
                return AuthResult(success=True, context=context)

            # Проверка правила перехода
            transition_key = (self._current_role, new_role)
            requires_mfa = self.ROLE_TRANSITIONS.get(transition_key, False)

            # Привилегированные роли всегда требуют MFA
            if new_role in self.PRIVILEGED_ROLES:
                requires_mfa = True

            if requires_mfa:
                if not mfa_code:
                    return AuthResult(
                        success=False,
                        error_code="MFA_REQUIRED",
                        error_message=f"Переход в роль {new_role.value} требует MFA.",
                    )

                if not self._current_user_id:
                    return AuthResult(
                        success=False,
                        error_code="NO_USER",
                        error_message="Неизвестный пользователь.",
                    )

                mfa_valid = self._verify_mfa_code(self._current_user_id, mfa_code)
                if not mfa_valid:
                    return AuthResult(
                        success=False,
                        error_code="INVALID_MFA",
                        error_message="Неверный MFA код.",
                    )

            # Обновление scopes при смене роли
            new_scopes = self._determine_scopes(new_role)

            # Обновление сессии в менеджере
            if self._session_id:
                try:
                    self._session_manager.update_scopes(
                        self._session_id,
                        new_scopes,
                        require_fresh_mfa=requires_mfa,
                    )
                except Exception as e:
                    logger.warning("Failed to update session scopes: %s", e)

            old_role = self._current_role
            self._current_role = new_role
            self._scopes = new_scopes

            logger.info(
                "Role switched: %s -> %s (user: %s)",
                old_role.value if old_role else "None",
                new_role.value,
                self._current_user_id,
            )

            context = self._create_auth_context()
            return AuthResult(success=True, context=context)

    def can_switch_to(self, role: WorkflowRole) -> tuple[bool, bool]:
        """Проверяет, можно ли переключиться в роль.

        Args:
            role: Целевая роль

        Returns:
            Кортеж (возможно, требуется_mfa)
        """
        with self._lock:
            if not self._current_role:
                return False, False

            if self._current_role == role:
                return True, False

            transition_key = (self._current_role, role)
            requires_mfa = self.ROLE_TRANSITIONS.get(transition_key, False)

            if role in self.PRIVILEGED_ROLES:
                requires_mfa = True

            return True, requires_mfa

    def _determine_scopes(self, role: WorkflowRole) -> FrozenSet[str]:
        """Определяет scopes для роли."""
        base_scopes: Set[str] = {"read", "write"}

        if role == WorkflowRole.OPERATOR:
            base_scopes.add("print")
        elif role == WorkflowRole.EDITOR:
            base_scopes.update(["edit", "validate", "print"])
        elif role == WorkflowRole.SUPERVISOR:
            base_scopes.update(["edit", "validate", "approve", "reject", "print"])
        elif role == WorkflowRole.SIGNATORY:
            base_scopes.update(["sign", "approve", "reject", "admin", "print"])

        return frozenset(base_scopes)

    def _create_auth_context(self) -> AuthContext:
        """Создаёт контекст аутентификации из текущего состояния."""
        return AuthContext(
            user_id=self._current_user_id or "",
            session_token=self._session_token or "",
            role=self._current_role or self._default_role,
            mfa_verified=self._mfa_verified,
            scopes=self._scopes,
            issued_at=datetime.now(timezone.utc),
        )

    # === Проверки состояния ===

    def is_authenticated(self) -> bool:
        """Проверяет, аутентифицирован ли пользователь.

        Returns:
            True если есть активная сессия
        """
        with self._lock:
            return self._state in (AuthState.AUTHENTICATED, AuthState.LOCKED)

    def is_fully_authenticated(self) -> bool:
        """Проверяет полную аутентификацию (не заблокирован).

        Returns:
            True если аутентифицирован и не заблокирован
        """
        with self._lock:
            return self._state == AuthState.AUTHENTICATED

    def get_session_token(self) -> Optional[str]:
        """Возвращает токен сессии для API вызовов.

        Returns:
            Access token или None
        """
        with self._lock:
            return self._session_token

    def get_refresh_token(self) -> Optional[str]:
        """Возвращает refresh токен.

        Returns:
            Refresh token или None
        """
        with self._lock:
            return self._refresh_token

    def get_session_id(self) -> Optional[str]:
        """Возвращает ID сессии.

        Returns:
            Session ID или None
        """
        with self._lock:
            return self._session_id

    def get_current_user(self) -> Optional[str]:
        """Возвращает ID текущего пользователя.

        Returns:
            User ID или None
        """
        with self._lock:
            return self._current_user_id

    def get_auth_context(self) -> Optional[AuthContext]:
        """Возвращает полный контекст аутентификации.

        Returns:
            AuthContext или None если не аутентифицирован
        """
        with self._lock:
            if self._state not in (AuthState.AUTHENTICATED, AuthState.LOCKED):
                return None
            return self._create_auth_context()

    # === Валидация токена ===

    def validate_token(
        self,
        token: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> bool:
        """Валидирует токен через SessionManager.

        Args:
            token: Токен для валидации (если None — текущий)
            device_fingerprint: Отпечаток устройства
            ip: IP адрес

        Returns:
            True если токен валиден
        """
        with self._lock:
            check_token = token or self._session_token
            if not check_token:
                return False

            try:
                result = self._session_manager.validate_access(
                    check_token,
                    device_fingerprint=device_fingerprint,
                    ip=ip,
                )
                return result.valid
            except (InvalidToken, TokenExpired, TokenRevoked):
                return False
            except Exception as e:
                logger.warning("Token validation error: %s", e)
                return False

    def refresh_session(
        self,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> bool:
        """Обновляет сессию через refresh token.

        Args:
            device_fingerprint: Отпечаток устройства
            ip: IP адрес

        Returns:
            True если обновление успешно
        """
        with self._lock:
            if not self._refresh_token:
                return False

            try:
                bundle = self._session_manager.refresh(
                    self._refresh_token,
                    device_fingerprint=device_fingerprint,
                    ip=ip,
                )
                self._session_token = bundle.access_token
                self._refresh_token = bundle.refresh_token
                self._session_id = bundle.session_id
                return True
            except Exception as e:
                logger.warning("Session refresh failed: %s", e)
                return False

    # === Информация о факторах ===

    def get_mfa_status(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Возвращает статус MFA для пользователя.

        Args:
            user_id: Идентификатор пользователя (если None — текущий)

        Returns:
            Словарь с информацией о факторах
        """
        with self._lock:
            uid = user_id or self._current_user_id
            if not uid:
                return {}

            result: Dict[str, Any] = {
                "totp": False,
                "fido2": False,
                "backup_code": False,
            }

            try:
                for factor_type in ["totp", "fido2", "backupcode"]:
                    status = self._mfa_manager.get_status(uid, factor_type)
                    key = factor_type.replace("code", "_code")
                    result[key] = bool(status and status.get("state"))
            except Exception as e:
                logger.warning("MFA status check error: %s", e)

            # FIDO2 status с деталями
            try:
                fido2_status = get_fido2_status(uid)
                result["fido2_devices"] = fido2_status.get("devices", [])
            except Exception as e:
                logger.debug("FIDO2 status error: %s", e)

            return result

    # === Контекстный менеджер ===

    def __enter__(self) -> "AuthController":
        """Вход в контекст."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Выход из контекста — logout."""
        self.logout()

    # === Служебные методы ===

    def __repr__(self) -> str:
        """Строковое представление."""
        with self._lock:
            return (
                f"AuthController("
                f"state={self._state.value}, "
                f"user={self._current_user_id or 'None'}, "
                f"role={self._current_role.value if self._current_role else 'None'})"
            )
