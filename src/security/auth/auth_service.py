# -*- coding: utf-8 -*-
"""
AuthService — единая точка входа для полного MFA-аутентификационного flow.

Оркестрирует последовательность:
    1. Проверка мастер-пароля (:class:`~src.security.auth.password_service.PasswordService`)
    2. Проверка второго фактора (:class:`~src.security.auth.second_factor.SecondFactorManager`)
    3. Создание сессии с выдачей токенов
    (:class:`~src.security.auth.session_service.SessionService`)
    4. Применение политики разрешений
    (:class:`~src.security.auth.permissions_service.PermissionsService`)
    5. Запись всех шагов в аудит-журнал

Архитектурный принцип Zero Trust: каждый шаг обязателен, пропуск любого
шага делает сессию невалидной. Критические операции требуют повторного
MFA независимо от возраста сессии.

Примеры:
    >>> from src.security.auth.auth_service import AuthService
    >>> from src.security.auth.password_service import PasswordService, InMemoryUserStorage
    >>> from src.security.auth.second_factor import SecondFactorManager
    >>> from src.security.crypto.utilities.secure_storage import SecureStorage
    >>> # ... инициализация зависимостей ...
    >>> svc = AuthService(password_service=pw_svc, mfa_manager=mfa_mgr,
    ...                    session_service=sess_svc, permissions_service=perm_svc)
    >>> result = svc.authenticate("operator", password="secret", factor_type="totp",
    ...                            factor_credential="123456")
    >>> result.success
    True
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, FrozenSet, Optional

from .permissions import OPERATOR_SCOPES, Permission
from .permissions_service import PermissionsService
from .session import TokenBundle, ValidationResult
from .session_service import SessionService

__all__ = [
    "AuthService",
    "AuthResult",
    "AuthError",
    "PasswordError",
    "SecondFactorError",
]

LOG = logging.getLogger("security.auth.auth_service")

AuditCallback = Callable[[str, dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Базовое исключение аутентификационного слоя."""


class PasswordError(AuthError):
    """Ошибка проверки мастер-пароля."""


class SecondFactorError(AuthError):
    """Ошибка проверки второго фактора."""


# ---------------------------------------------------------------------------
# AuthResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthResult:
    """Результат попытки аутентификации.

    Attrs:
        success: True при полной успешной аутентификации.
        session_id: Идентификатор сессии (None при неудаче).
        token_bundle: Токены доступа (None при неудаче).
        user_id: Идентификатор пользователя.
        failure_reason: Описание причины неудачи (None при success=True).
        mfa_required: True, если сессия требует MFA для критических операций.
    """

    success: bool
    user_id: str
    session_id: Optional[str] = None
    token_bundle: Optional[TokenBundle] = None
    failure_reason: Optional[str] = None
    mfa_required: bool = True


# ---------------------------------------------------------------------------
# AuthService
# ---------------------------------------------------------------------------


@dataclass
class AuthService:
    """Оркестратор полного MFA-аутентификационного flow.

    Единственная точка входа для аутентификации оператора. Все зависимости
    передаются через конструктор (DI через конструктор), без глобального
    состояния.

    Attrs:
        password_service: Сервис проверки мастер-пароля.
        mfa_manager: Менеджер второго фактора (TOTP/FIDO2/BackupCode).
        session_service: Сервис управления сессиями.
        permissions_service: Сервис проверки прав доступа.
        audit_callback: Callback для записи событий аудита.
            Сигнатура: ``(event_name: str, details: dict) -> None``.
        require_second_factor: Если False, второй фактор пропускается.
            **Только для тестов** — в production всегда True.
    """

    password_service: Any  # PasswordService (избегаем циклического импорта)
    mfa_manager: Any  # SecondFactorManager
    session_service: SessionService
    permissions_service: PermissionsService = field(default_factory=PermissionsService)
    audit_callback: Optional[AuditCallback] = field(default=None)
    require_second_factor: bool = field(default=True)

    # ---------- Основной метод аутентификации ----------

    def authenticate(
        self,
        user_id: str,
        *,
        password: str,
        factor_type: Optional[str] = None,
        factor_credential: Any = None,
        factor_state: Optional[dict[str, Any]] = None,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
        remember: bool = False,
        scopes: Optional[FrozenSet[str]] = None,
    ) -> AuthResult:
        """Выполняет полный двухфакторный аутентификационный flow.

        Шаги:
            1. Проверка мастер-пароля через PasswordService.
            2. Проверка второго фактора через SecondFactorManager
               (если ``require_second_factor=True``).
            3. Создание сессии через SessionService.
            4. Установка флага MFA-satisfied.

        Args:
            user_id: Идентификатор пользователя (оператора).
            password: Мастер-пароль в открытом виде.
            factor_type: Тип второго фактора: ``"totp"``, ``"fido2"``,
                ``"backupcode"``. Обязателен при ``require_second_factor=True``.
            factor_credential: Учётные данные фактора (код TOTP, assertion FIDO2 и т.д.).
            factor_state: Состояние фактора из хранилища (для некоторых
                реализаций факторов).
            device_fingerprint: Отпечаток устройства для привязки сессии.
            ip: IP-адрес для привязки сессии.
            remember: Расширенный TTL refresh-токена.
            scopes: Scope сессии. По умолчанию OPERATOR_SCOPES.

        Returns:
            :class:`AuthResult` с ``success=True`` и токенами при успехе,
            либо с ``failure_reason`` при отказе.
        """
        LOG.info("Попытка аутентификации user=%s", user_id)

        # --- Шаг 1: Проверка мастер-пароля ---
        try:
            password_ok: bool = self.password_service.verify_password(user_id, password)
        except Exception as exc:
            LOG.warning("Ошибка проверки пароля user=%s: %s", user_id, exc)
            self._audit(
                "auth.failed",
                {"user_id": user_id, "reason": "password_error"},
            )
            return AuthResult(
                success=False,
                user_id=user_id,
                failure_reason="password_error",
            )

        if not password_ok:
            LOG.warning("Неверный пароль user=%s", user_id)
            self._audit(
                "auth.failed",
                {"user_id": user_id, "reason": "invalid_password"},
            )
            return AuthResult(
                success=False,
                user_id=user_id,
                failure_reason="invalid_password",
            )

        # --- Шаг 2: Проверка второго фактора ---
        if self.require_second_factor:
            if not factor_type or factor_credential is None:
                LOG.warning("Второй фактор не предоставлен user=%s", user_id)
                self._audit(
                    "auth.failed",
                    {"user_id": user_id, "reason": "mfa_missing"},
                )
                return AuthResult(
                    success=False,
                    user_id=user_id,
                    failure_reason="mfa_missing",
                )

            try:
                mfa_ok: bool = bool(
                    self.mfa_manager.verify_factor(
                        user_id,
                        factor_type,
                        factor_credential,
                        state=factor_state or {},
                    )
                )
            except Exception as exc:
                LOG.warning(
                    "Ошибка проверки второго фактора user=%s type=%s: %s",
                    user_id,
                    factor_type,
                    exc,
                )
                self._audit(
                    "auth.failed",
                    {
                        "user_id": user_id,
                        "reason": "mfa_error",
                        "factor_type": factor_type,
                    },
                )
                return AuthResult(
                    success=False,
                    user_id=user_id,
                    failure_reason="mfa_error",
                )

            if not mfa_ok:
                LOG.warning(
                    "Неверный второй фактор user=%s type=%s",
                    user_id,
                    factor_type,
                )
                self._audit(
                    "auth.failed",
                    {
                        "user_id": user_id,
                        "reason": "invalid_mfa",
                        "factor_type": factor_type,
                    },
                )
                return AuthResult(
                    success=False,
                    user_id=user_id,
                    failure_reason="invalid_mfa",
                )

        # --- Шаг 3: Создание сессии ---
        effective_scopes: FrozenSet[str] = scopes if scopes is not None else OPERATOR_SCOPES
        bundle = self.session_service.create_session(
            user_id=user_id,
            mfa_required=True,
            scopes=effective_scopes,
            device_fingerprint=device_fingerprint,
            ip=ip,
            remember=remember,
        )

        # --- Шаг 4: Отметить MFA как пройденный ---
        if self.require_second_factor:
            self.session_service.mark_mfa_satisfied(bundle.session_id)

        LOG.info(
            "Аутентификация успешна user=%s sid=%s",
            user_id,
            bundle.session_id,
        )
        self._audit(
            "auth.success",
            {
                "user_id": user_id,
                "session_id": bundle.session_id,
                "factor_type": factor_type,
                "scopes": sorted(effective_scopes),
            },
        )
        return AuthResult(
            success=True,
            user_id=user_id,
            session_id=bundle.session_id,
            token_bundle=bundle,
            mfa_required=True,
        )

    # ---------- Проверка токена (для защищённых операций) ----------

    def validate_access(
        self,
        access_token: str,
        *,
        required_permission: Optional[Permission] = None,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> ValidationResult:
        """Валидирует access-токен и опционально проверяет разрешение.

        Args:
            access_token: Bearer-токен из запроса.
            required_permission: Если указано, проверяет наличие разрешения
                и свежесть MFA для MFA-gated операций.
            device_fingerprint: Отпечаток устройства.
            ip: IP-адрес.

        Returns:
            :class:`~src.security.auth.session.ValidationResult`.

        Raises:
            InvalidToken: Токен неизвестен.
            TokenExpired: TTL или idle timeout истёк.
            ScopeError: Разрешение не предоставлено scope сессии.
            MFARequiredError: Требуется свежее MFA для данной операции.
        """
        result = self.session_service.validate(
            access_token=access_token,
            device_fingerprint=device_fingerprint,
            ip=ip,
        )

        if required_permission is not None:
            self.permissions_service.assert_access(
                scopes=result.scopes,
                permission=required_permission,
                mfa_satisfied=result.mfa_ok,
            )

        return result

    # ---------- Завершение сессии ----------

    def logout(self, session_id: str, *, user_id: str = "") -> None:
        """Завершает сессию оператора.

        Отзывает сессию через SessionService и фиксирует событие
        ``app.locked`` в аудит-журнале.

        Args:
            session_id: Идентификатор текущей сессии.
            user_id: Идентификатор пользователя (для аудита).
        """
        self.session_service.lock(session_id, user_id=user_id)
        LOG.info("Выход выполнен sid=%s user=%s", session_id, user_id)

    def logout_all(self, user_id: str) -> int:
        """Завершает все сессии пользователя.

        Используется при подозрении на компрометацию.

        Args:
            user_id: Идентификатор пользователя.

        Returns:
            Количество отозванных сессий.
        """
        count = self.session_service.revoke_all(user_id)
        self._audit(
            "auth.failed",
            {"user_id": user_id, "reason": "force_logout_all", "count": count},
        )
        return count

    # ---------- Смена пароля ----------

    def change_password(
        self,
        user_id: str,
        *,
        current_password: str,
        new_password: str,
        session_id: str,
    ) -> bool:
        """Меняет мастер-пароль при наличии активной MFA-сессии.

        Требует подтверждённого MFA в текущей сессии. После успешной смены
        все остальные сессии пользователя отзываются.

        Args:
            user_id: Идентификатор пользователя.
            current_password: Текущий пароль для верификации.
            new_password: Новый пароль.
            session_id: Идентификатор текущей сессии (должна иметь MFA).

        Returns:
            True при успешной смене пароля.

        Raises:
            PasswordError: Текущий пароль неверен или новый нарушает политику.
            PermissionError: MFA не подтверждён или его свежесть истекла.
        """
        # Проверяем свежесть MFA
        self.session_service.require_mfa(session_id)

        try:
            changed: bool = self.password_service.change_password(
                user_id,
                current_password=current_password,
                new_password=new_password,
            )
        except Exception as exc:
            LOG.warning("Ошибка смены пароля user=%s: %s", user_id, exc)
            raise PasswordError(str(exc)) from exc

        if changed:
            LOG.info("Пароль изменён user=%s", user_id)
            self._audit("config.modified", {"user_id": user_id, "field": "password"})
            # Отзываем остальные сессии — пароль изменён
            self.session_service.revoke_all(user_id)

        return changed

    # ---------- Внутренние ----------

    def _audit(self, event: str, details: dict[str, Any]) -> None:
        """Вызывает audit_callback без проброса исключений.

        Args:
            event: Имя события аудита.
            details: Детали события.
        """
        if self.audit_callback is not None:
            try:
                self.audit_callback(event, details)
            except Exception as exc:  # noqa: BLE001
                LOG.error("audit_callback raised: %s", exc)
