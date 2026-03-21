# -*- coding: utf-8 -*-
"""
SessionService — управление сессиями с аудит-логированием.

Обёртка над :class:`~src.security.auth.session.SessionManager`, добавляющая:
- Запись событий сессии в аудит-журнал (AUTH_SUCCESS, APP_LOCKED и т.д.)
- Метод завершения сессии с фиксацией в аудите (``lock``)
- Контекстный менеджер для auto-lock при выходе из блока
- Единый интерфейс для :class:`~src.security.auth.auth_service.AuthService`

Зависимости:
    - :mod:`src.security.auth.session` — SessionManager, TokenBundle
    - :mod:`src.security.auth.permissions` — OPERATOR_SCOPES

Примеры:
    >>> from src.security.auth.session import SessionManager
    >>> from src.security.auth.session_service import SessionService
    >>> mgr = SessionManager()
    >>> svc = SessionService(session_manager=mgr)
    >>> bundle = svc.create_session("operator", mfa_required=True)
    >>> svc.mark_mfa_satisfied(bundle.session_id)
    >>> svc.revoke(bundle.session_id)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, FrozenSet, Mapping, Optional, Tuple

from .permissions import OPERATOR_SCOPES
from .session import (
    SessionManager,
    TokenBundle,
    ValidationResult,
)

__all__ = [
    "SessionService",
    "SessionInfo",
]

LOG = logging.getLogger("security.auth.session_service")

# Тип audit-callback, совместимый с PermissionsService и auth слоем.
AuditCallback = Callable[[str, dict[str, Any]], None]


@dataclass(frozen=True)
class SessionInfo:
    """Краткая информация о сессии для отображения в UI/логах.

    Attrs:
        session_id: Идентификатор сессии.
        user_id: Идентификатор пользователя.
        active: True, если сессия не отозвана.
        mfa_satisfied: True, если второй фактор подтверждён.
        scopes: Scope токена.
    """

    session_id: str
    user_id: str
    active: bool
    mfa_satisfied: bool
    scopes: Tuple[str, ...]


@dataclass
class SessionService:
    """Сервис управления сессиями с интеграцией аудит-журнала.

    Инкапсулирует :class:`~src.security.auth.session.SessionManager`
    и добавляет audit-callback для фиксации событий жизненного цикла
    сессии (создание, MFA, блокировка, отзыв).

    Attrs:
        session_manager: Нижележащий менеджер сессий.
        audit_callback: Опциональный callback для записи событий.
            Сигнатура: ``(event_name: str, details: dict) -> None``.
        default_user_id: Идентификатор единственного оператора.
            По умолчанию ``"operator"``.

    Примеры:
        >>> svc = SessionService()
        >>> bundle = svc.create_session("operator", mfa_required=True)
        >>> svc.validate(bundle.access_token)
        ValidationResult(valid=True, ...)
    """

    session_manager: SessionManager = field(default_factory=SessionManager)
    audit_callback: Optional[AuditCallback] = field(default=None)
    default_user_id: str = field(default="operator")

    # ---------- Создание сессии ----------

    def create_session(
        self,
        user_id: str,
        *,
        mfa_required: bool = True,
        scopes: Optional[FrozenSet[str]] = None,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
        remember: bool = False,
    ) -> TokenBundle:
        """Создаёт новую аутентифицированную сессию.

        Выпускает пару access/refresh токенов через SessionManager и
        фиксирует событие ``auth.success`` в аудит-журнале.

        Args:
            user_id: Идентификатор пользователя.
            mfa_required: Требовать ли свежего MFA перед критическими
                операциями (рекомендуется True).
            scopes: Набор scope токена. По умолчанию OPERATOR_SCOPES.
            device_fingerprint: Опциональный отпечаток устройства для
                привязки сессии.
            ip: Опциональный IP-адрес для привязки сессии.
            remember: Расширенный refresh TTL (если разрешён в менеджере).

        Returns:
            :class:`~src.security.auth.session.TokenBundle` с токенами.
        """
        effective_scopes: FrozenSet[str] = scopes if scopes is not None else OPERATOR_SCOPES
        bundle = self.session_manager.issue(
            user_id=user_id,
            scopes=effective_scopes,
            mfa_required=mfa_required,
            device_fingerprint=device_fingerprint,
            ip=ip,
            remember=remember,
        )
        LOG.info(
            "Сессия создана user=%s sid=%s mfa_required=%s",
            user_id,
            bundle.session_id,
            mfa_required,
        )
        self._audit(
            "auth.success",
            {
                "user_id": user_id,
                "session_id": bundle.session_id,
                "mfa_required": mfa_required,
                "scopes": sorted(effective_scopes),
            },
        )
        return bundle

    # ---------- Валидация ----------

    def validate(
        self,
        access_token: str,
        *,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> ValidationResult:
        """Валидирует access-токен и возвращает результат проверки.

        Args:
            access_token: Bearer-токен из текущего запроса.
            device_fingerprint: Отпечаток устройства (если сессия привязана).
            ip: IP-адрес (если сессия привязана).

        Returns:
            :class:`~src.security.auth.session.ValidationResult`.

        Raises:
            InvalidToken: Токен неизвестен.
            TokenExpired: Истёк TTL или idle timeout.
            TokenRevoked: Сессия отозвана.
            DeviceMismatch: Несоответствие привязки устройства/IP.
        """
        return self.session_manager.validate_access(
            token=access_token,
            device_fingerprint=device_fingerprint,
            ip=ip,
        )

    # ---------- MFA ----------

    def mark_mfa_satisfied(self, session_id: str) -> None:
        """Помечает сессию как прошедшую MFA-верификацию.

        Вызывается :class:`~src.security.auth.auth_service.AuthService`
        после успешной проверки второго фактора.

        Args:
            session_id: Идентификатор сессии.
        """
        self.session_manager.mark_mfa_satisfied(session_id)
        LOG.info("MFA подтверждён для сессии sid=%s", session_id)
        self._audit(
            "auth.mfa_challenged",
            {"session_id": session_id, "result": "success"},
        )

    def require_mfa(
        self,
        session_id: str,
        freshness_seconds: Optional[int] = None,
    ) -> None:
        """Проверяет свежесть MFA, выбрасывает исключение при нарушении.

        Args:
            session_id: Идентификатор сессии.
            freshness_seconds: Окно свежести в секундах (None = из конфига).

        Raises:
            PermissionError: MFA не подтверждён или окно свежести истекло.
        """
        self.session_manager.require_mfa(session_id, freshness_seconds=freshness_seconds)

    # ---------- Обновление токена ----------

    def refresh(
        self,
        refresh_token: str,
        *,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> TokenBundle:
        """Обновляет пару токенов по refresh-токену.

        Args:
            refresh_token: Текущий refresh-токен (одноразовый).
            device_fingerprint: Отпечаток устройства.
            ip: IP-адрес.

        Returns:
            Новый :class:`~src.security.auth.session.TokenBundle`.

        Raises:
            InvalidToken: refresh-токен неизвестен или уже использован.
            TokenExpired: Истёк TTL или idle timeout.
            TokenRevoked: Сессия отозвана.
        """
        bundle = self.session_manager.refresh(
            refresh_token=refresh_token,
            device_fingerprint=device_fingerprint,
            ip=ip,
        )
        LOG.debug("Токены обновлены sid=%s", bundle.session_id)
        return bundle

    # ---------- Блокировка / отзыв ----------

    def lock(self, session_id: str, *, user_id: str = "") -> None:
        """Отзывает сессию (мгновенная блокировка приложения).

        Фиксирует событие ``app.locked`` в аудит-журнале.

        Args:
            session_id: Идентификатор сессии.
            user_id: Идентификатор пользователя для записи в аудит.
        """
        revoked = self.session_manager.revoke_by_session_id(session_id)
        LOG.info("Сессия заблокирована sid=%s revoked=%s", session_id, revoked)
        self._audit(
            "app.locked",
            {"session_id": session_id, "user_id": user_id},
        )

    def revoke(self, session_id: str) -> bool:
        """Отзывает конкретную сессию.

        Args:
            session_id: Идентификатор сессии.

        Returns:
            True, если сессия была найдена и отозвана.
        """
        result = self.session_manager.revoke_by_session_id(session_id)
        if result:
            LOG.info("Сессия отозвана sid=%s", session_id)
            self._audit(
                "session.revoke",
                {"session_id": session_id},
            )
        return result

    def revoke_all(self, user_id: str) -> int:
        """Отзывает все активные сессии пользователя.

        Используется при компрометации учётных данных.

        Args:
            user_id: Идентификатор пользователя.

        Returns:
            Количество отозванных сессий.
        """
        count = self.session_manager.revoke_all_user_sessions(user_id)
        LOG.warning(
            "Все сессии пользователя отозваны user=%s count=%d",
            user_id,
            count,
        )
        self._audit(
            "session.revoke_all",
            {"user_id": user_id, "count": count},
        )
        return count

    # ---------- Информация ----------

    def list_active(self, user_id: str) -> Tuple[int, Tuple[str, ...]]:
        """Возвращает активные сессии пользователя.

        Args:
            user_id: Идентификатор пользователя.

        Returns:
            Кортеж (количество, tuple идентификаторов сессий).
        """
        return self.session_manager.list_active_sessions(user_id)

    def get_snapshot(self, session_id: str) -> Mapping[str, object]:
        """Возвращает диагностический снимок состояния сессии.

        Args:
            session_id: Идентификатор сессии.

        Returns:
            Словарь с полями сессии (без токенов).
        """
        return self.session_manager.get_snapshot(session_id)

    def purge_expired(self) -> int:
        """Удаляет истёкшие и отозванные сессии из памяти.

        Returns:
            Количество удалённых сессий.
        """
        return self.session_manager.purge_expired()

    # ---------- Внутренние ----------

    def _audit(self, event: str, details: dict[str, Any]) -> None:
        """Вызывает audit_callback без проброса исключений.

        Args:
            event: Имя события (например, ``auth.success``).
            details: Детали события.
        """
        if self.audit_callback is not None:
            try:
                self.audit_callback(event, details)
            except Exception as exc:  # noqa: BLE001
                LOG.error("audit_callback raised: %s", exc)
