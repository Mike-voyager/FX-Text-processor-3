# -*- coding: utf-8 -*-
"""
PermissionsService — проверка прав доступа с аудитом событий ACCESS_DENIED.

Сервис предоставляет единый guard-метод для защищённых операций:
проверяет scope текущей сессии, свежесть MFA и логирует отказы
в аудит-журнал через опциональный callback.

Зависимости:
    - :mod:`src.security.auth.permissions` — модели разрешений
    - :mod:`src.security.auth.session` — SessionManager, ValidationResult

Примеры:
    >>> from src.security.auth.permissions_service import PermissionsService
    >>> from src.security.auth.permissions import Permission, OPERATOR_SCOPES
    >>> svc = PermissionsService()
    >>> svc.check(OPERATOR_SCOPES, Permission.DOCUMENT_READ, mfa_satisfied=False)
    True
    >>> svc.check(OPERATOR_SCOPES, Permission.DEVICE_PROVISION, mfa_satisfied=False)
    False
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Final, FrozenSet, Optional

from .permissions import (
    MFARequiredError,
    Permission,
    PermissionChecker,
    ScopeError,
    requires_mfa,
    scopes_to_permissions,
)

__all__ = [
    "PermissionsService",
    "AccessDecision",
    "DenialReason",
]

LOG = logging.getLogger("security.auth.permissions_service")


# ---------------------------------------------------------------------------
# Вспомогательные типы
# ---------------------------------------------------------------------------


class DenialReason(str):
    """Причина отказа в доступе (строка-константа для аудита)."""

    SCOPE_MISSING: Final[str] = "scope_missing"
    MFA_REQUIRED: Final[str] = "mfa_required"


@dataclass(frozen=True)
class AccessDecision:
    """Решение о допуске к операции.

    Attrs:
        granted: True, если доступ разрешён.
        permission: Запрошенное разрешение.
        reason: Причина отказа (None при granted=True).
        mfa_required: Требуется ли MFA для данной операции.
    """

    granted: bool
    permission: Permission
    reason: Optional[str] = None
    mfa_required: bool = False


# ---------------------------------------------------------------------------
# PermissionsService
# ---------------------------------------------------------------------------

# Тип callback-функции для записи событий в аудит-журнал.
# Принимает имя события и детали.
AuditCallback = Callable[[str, dict[str, Any]], None]


@dataclass
class PermissionsService:
    """Сервис проверки прав доступа с интеграцией аудит-лога.

    Инкапсулирует :class:`~src.security.auth.permissions.PermissionChecker`
    и добавляет:
    - Аудит-callback для события ``access.denied``
    - Удобные методы ``check`` / ``assert_access`` для сервисного слоя
    - Статистику отказов (in-memory, сбрасывается при перезапуске)

    Attrs:
        checker: Внутренний объект проверки прав.
        audit_callback: Опциональный callback для записи в аудит-журнал.
            Сигнатура: ``(event_name: str, details: dict) -> None``.
            Вызывается синхронно при каждом отказе ACCESS_DENIED.

    Примеры:
        >>> svc = PermissionsService()
        >>> decision = svc.decide(frozenset({"full"}), Permission.BLANK_ISSUE,
        ...                       mfa_satisfied=False)
        >>> decision.granted
        True
    """

    checker: PermissionChecker = field(default_factory=PermissionChecker)
    audit_callback: Optional[AuditCallback] = field(default=None)

    # In-memory статистика (не персистируется)
    _denial_count: int = field(default=0, init=False, repr=False)

    def decide(
        self,
        scopes: FrozenSet[str],
        permission: Permission,
        *,
        mfa_satisfied: bool = False,
    ) -> AccessDecision:
        """Возвращает решение о допуске без выброса исключений.

        Метод никогда не бросает исключений — результат всегда
        ``AccessDecision``. Используйте :meth:`assert_access`, если
        требуется исключение при отказе.

        Args:
            scopes: Активные scope текущей сессии.
            permission: Запрошенное разрешение.
            mfa_satisfied: True, если MFA подтверждён в текущем контексте.

        Returns:
            :class:`AccessDecision` с полем ``granted``.
        """
        try:
            self.checker.assert_permission(scopes, permission, mfa_satisfied=mfa_satisfied)
        except ScopeError:
            self._record_denial(permission, DenialReason.SCOPE_MISSING, scopes)
            return AccessDecision(
                granted=False,
                permission=permission,
                reason=DenialReason.SCOPE_MISSING,
                mfa_required=requires_mfa(permission),
            )
        except MFARequiredError:
            self._record_denial(permission, DenialReason.MFA_REQUIRED, scopes)
            return AccessDecision(
                granted=False,
                permission=permission,
                reason=DenialReason.MFA_REQUIRED,
                mfa_required=True,
            )
        return AccessDecision(
            granted=True,
            permission=permission,
            mfa_required=requires_mfa(permission),
        )

    def check(
        self,
        scopes: FrozenSet[str],
        permission: Permission,
        *,
        mfa_satisfied: bool = False,
    ) -> bool:
        """Возвращает True, если доступ разрешён.

        Упрощённая обёртка над :meth:`decide` для быстрых проверок.

        Args:
            scopes: Активные scope текущей сессии.
            permission: Запрошенное разрешение.
            mfa_satisfied: True, если MFA подтверждён.

        Returns:
            True при granted, False при любом отказе.
        """
        return self.decide(scopes, permission, mfa_satisfied=mfa_satisfied).granted

    def assert_access(
        self,
        scopes: FrozenSet[str],
        permission: Permission,
        *,
        mfa_satisfied: bool = False,
    ) -> None:
        """Проверяет доступ и выбрасывает исключение при отказе.

        Предназначен для использования в начале каждого защищённого
        метода сервисного слоя в качестве guard-условия.

        Args:
            scopes: Активные scope текущей сессии.
            permission: Требуемое разрешение.
            mfa_satisfied: True, если MFA подтверждён.

        Raises:
            ScopeError: Разрешение не входит в активные scope.
            MFARequiredError: Операция требует MFA, которое не пройдено.
        """
        self.checker.assert_permission(scopes, permission, mfa_satisfied=mfa_satisfied)

    def mfa_required_for(self, permission: Permission) -> bool:
        """Возвращает True, если операция требует свежего MFA.

        Args:
            permission: Проверяемое разрешение.

        Returns:
            True для MFA-gated операций.
        """
        return requires_mfa(permission)

    def effective_permissions(self, scopes: FrozenSet[str]) -> FrozenSet[Permission]:
        """Возвращает полный набор разрешений для заданных scope.

        Args:
            scopes: Набор scope-строк.

        Returns:
            Объединённый набор разрешений.
        """
        return scopes_to_permissions(scopes)

    def mfa_gated_permissions(self, scopes: FrozenSet[str]) -> FrozenSet[Permission]:
        """Возвращает MFA-gated разрешения, доступные через данные scope.

        Используется в UI для отображения списка операций,
        требующих повторного MFA-подтверждения.

        Args:
            scopes: Набор scope-строк активной сессии.

        Returns:
            Подмножество доступных разрешений с обязательным MFA.
        """
        return self.checker.mfa_required_permissions(scopes)

    @property
    def denial_count(self) -> int:
        """Количество отказов ACCESS_DENIED с момента запуска.

        In-memory счётчик, сбрасывается при перезапуске приложения.
        """
        return self._denial_count

    def _record_denial(
        self,
        permission: Permission,
        reason: str,
        scopes: FrozenSet[str],
    ) -> None:
        """Логирует отказ и вызывает audit_callback.

        Args:
            permission: Отклонённое разрешение.
            reason: Причина отказа (DenialReason константа).
            scopes: Активные scope сессии.
        """
        self._denial_count += 1
        LOG.warning(
            "ACCESS_DENIED permission='%s' reason='%s' scopes=%s",
            permission.value,
            reason,
            sorted(scopes),
        )
        if self.audit_callback is not None:
            try:
                self.audit_callback(
                    "access.denied",
                    {
                        "permission": permission.value,
                        "reason": reason,
                        "scopes": sorted(scopes),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                LOG.error("audit_callback raised: %s", exc)
