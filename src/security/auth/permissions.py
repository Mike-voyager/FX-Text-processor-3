# -*- coding: utf-8 -*-
"""
Модели разрешений и scope-based access control для FX Text Processor 3.

Система разрешений реализует Zero Trust принцип: каждая операция явно
авторизована, набор операций требует свежего MFA-подтверждения независимо
от активной сессии.

Приложение рассчитано на единственного оператора, однако разграничение
прав оформлено через перечисление `Permission`, группировку по `Scope` и
`PermissionPolicy`, что позволяет проверять авторизацию унифицировано
по всей кодовой базе.

MFA-gated операции (из SECURITY_ARCHITECTURE.md §Authentication System):
- Провизионирование аппаратного устройства (`DEVICE_PROVISION`)
- Отзыв устройства (`DEVICE_REVOKE`)
- Экспорт/бэкап мастер-ключа (`KEY_EXPORT`)
- Импорт ключа на устройство (`KEY_IMPORT_DEVICE`)
- Понижение пресета безопасности (`SECURITY_DOWNGRADE`)

Примеры:
    >>> from src.security.auth.permissions import Permission, requires_mfa
    >>> requires_mfa(Permission.DEVICE_PROVISION)
    True
    >>> requires_mfa(Permission.DOCUMENT_READ)
    False
    >>> from src.security.auth.permissions import PermissionChecker, OPERATOR_SCOPES
    >>> checker = PermissionChecker()
    >>> checker.has_permission(OPERATOR_SCOPES, Permission.BLANK_SIGN)
    True
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, FrozenSet

__all__ = [
    # Перечисления
    "Permission",
    "Scope",
    # Константы
    "MFA_REQUIRED_PERMISSIONS",
    "OPERATOR_PERMISSIONS",
    "OPERATOR_SCOPES",
    "SCOPE_PERMISSIONS",
    # Модели
    "OperatorRole",
    "PermissionPolicy",
    # Утилиты
    "PermissionChecker",
    "requires_mfa",
    # Исключения
    "PermissionError",
    "MFARequiredError",
    "ScopeError",
]

LOG = logging.getLogger("security.auth.permissions")


# ---------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------


class PermissionError(Exception):
    """Базовое исключение подсистемы разрешений."""


class MFARequiredError(PermissionError):
    """Операция требует свежего MFA-подтверждения.

    Attrs:
        permission: Разрешение, которое было запрошено.
    """

    def __init__(self, permission: "Permission") -> None:
        self.permission = permission
        super().__init__(f"Операция '{permission.value}' требует подтверждения MFA")


class ScopeError(PermissionError):
    """Запрошенное разрешение не входит в активные scope сессии.

    Attrs:
        required: Требуемое разрешение.
        active_scopes: Набор scope, предоставленных текущей сессией.
    """

    def __init__(self, required: "Permission", active_scopes: FrozenSet[str]) -> None:
        self.required = required
        self.active_scopes = active_scopes
        super().__init__(
            f"Разрешение '{required.value}' недоступно для scope: {sorted(active_scopes)}"
        )


# ---------------------------------------------------------------------------
# Permission — перечисление всех операций
# ---------------------------------------------------------------------------


class Permission(str, Enum):
    """Перечисление всех операций, требующих явной авторизации.

    Значения представлены строками формата ``<ресурс>:<действие>``
    для совместимости с JWT scope и SessionManager.scopes.

    Группы операций:
        - ``document:*``  — работа с документами
        - ``blank:*``     — жизненный цикл защищённых бланков
        - ``key:*``       — операции с ключевым материалом (MFA-gated)
        - ``device:*``    — управление аппаратными устройствами (MFA-gated)
        - ``security:*``  — настройки безопасности (MFA-gated)
        - ``audit:*``     — журнал аудита
        - ``backup:*``    — резервное копирование
        - ``config:*``    — конфигурация приложения
        - ``session:*``   — управление сессиями
    """

    # ---- Документы ----
    DOCUMENT_READ = "document:read"
    """Чтение/открытие документов."""

    DOCUMENT_WRITE = "document:write"
    """Создание и редактирование документов."""

    DOCUMENT_DELETE = "document:delete"
    """Удаление документов."""

    DOCUMENT_SIGN = "document:sign"
    """Цифровая подпись документа."""

    DOCUMENT_ENCRYPT = "document:encrypt"
    """Шифрование документа."""

    DOCUMENT_EXPORT = "document:export"
    """Экспорт документа в файл."""

    # ---- Защищённые бланки ----
    BLANK_READ = "blank:read"
    """Просмотр бланков и их статусов."""

    BLANK_ISSUE = "blank:issue"
    """Выпуск новой серии бланков."""

    BLANK_SIGN = "blank:sign"
    """Подпись документа на бланке."""

    BLANK_VOID = "blank:void"
    """Аннулирование бланка."""

    BLANK_VERIFY = "blank:verify"
    """Верификация подлинности бланка."""

    # ---- Ключевой материал (MFA-gated) ----
    KEY_EXPORT = "key:export"
    """Экспорт/бэкап мастер-ключа. Требует MFA."""

    KEY_IMPORT_DEVICE = "key:import_device"
    """Импорт ключа на аппаратное устройство (Mode B). Требует MFA."""

    KEY_ROTATE = "key:rotate"
    """Ротация ключей шифрования."""

    # ---- Аппаратные устройства (MFA-gated) ----
    DEVICE_LIST = "device:list"
    """Просмотр реестра доверенных устройств."""

    DEVICE_PROVISION = "device:provision"
    """Провизионирование аппаратного устройства. Требует MFA."""

    DEVICE_REVOKE = "device:revoke"
    """Отзыв (revocation) доверенного устройства. Требует MFA."""

    # ---- Настройки безопасности (MFA-gated) ----
    SECURITY_DOWNGRADE = "security:downgrade"
    """Понижение пресета безопасности (напр., Paranoid→Standard). Требует MFA."""

    SECURITY_CONFIG_READ = "security:config_read"
    """Чтение текущих настроек безопасности."""

    # ---- Аудит ----
    AUDIT_READ = "audit:read"
    """Чтение журнала аудита."""

    AUDIT_VERIFY = "audit:verify"
    """Проверка целостности цепочки аудита."""

    # ---- Резервное копирование ----
    BACKUP_CREATE = "backup:create"
    """Создание резервной копии ключевого хранилища."""

    BACKUP_RESTORE = "backup:restore"
    """Восстановление из резервной копии."""

    # ---- Конфигурация ----
    CONFIG_READ = "config:read"
    """Чтение конфигурации приложения."""

    CONFIG_MODIFY = "config:modify"
    """Изменение конфигурации приложения."""

    # ---- Сессии ----
    SESSION_LIST = "session:list"
    """Просмотр активных сессий."""

    SESSION_REVOKE = "session:revoke"
    """Принудительный отзыв сессии."""


# ---------------------------------------------------------------------------
# MFA_REQUIRED_PERMISSIONS — операции, требующие свежего MFA
# ---------------------------------------------------------------------------

MFA_REQUIRED_PERMISSIONS: Final[FrozenSet[Permission]] = frozenset(
    {
        # Ключевой материал
        Permission.KEY_EXPORT,
        Permission.KEY_IMPORT_DEVICE,
        # Аппаратные устройства
        Permission.DEVICE_PROVISION,
        Permission.DEVICE_REVOKE,
        # Безопасность
        Permission.SECURITY_DOWNGRADE,
        # Восстановление из бэкапа
        Permission.BACKUP_RESTORE,
    }
)
"""Операции, требующие подтверждения MFA при каждом вызове.

Соответствует разделу «MFA-Gated Critical Operations» документа
SECURITY_ARCHITECTURE.md. Свежесть MFA определяется полем
``mfa_freshness_seconds`` в :class:`~src.security.auth.session.SessionManager`.
"""


# ---------------------------------------------------------------------------
# Scope — логические группы разрешений
# ---------------------------------------------------------------------------


class Scope(str, Enum):
    """Именованные группы разрешений (scope) для сессионных токенов.

    Scope используются в :class:`~src.security.auth.session.SessionManager`
    при выпуске токенов и проверке доступа.
    """

    DOCUMENTS = "documents"
    """Полный доступ к документам."""

    BLANKS = "blanks"
    """Полный доступ к защищённым бланкам."""

    KEYS = "keys"
    """Операции с ключевым материалом (MFA-gated)."""

    DEVICES = "devices"
    """Управление аппаратными устройствами (MFA-gated)."""

    SECURITY = "security"
    """Управление настройками безопасности (MFA-gated)."""

    AUDIT = "audit"
    """Доступ к журналу аудита."""

    BACKUP = "backup"
    """Операции резервного копирования."""

    CONFIG = "config"
    """Управление конфигурацией."""

    SESSIONS = "sessions"
    """Управление сессиями."""

    FULL = "full"
    """Полный доступ оператора ко всем операциям."""


# ---------------------------------------------------------------------------
# Маппинг Scope → набор Permission
# ---------------------------------------------------------------------------

SCOPE_PERMISSIONS: Final[dict[Scope, FrozenSet[Permission]]] = {
    Scope.DOCUMENTS: frozenset(
        {
            Permission.DOCUMENT_READ,
            Permission.DOCUMENT_WRITE,
            Permission.DOCUMENT_DELETE,
            Permission.DOCUMENT_SIGN,
            Permission.DOCUMENT_ENCRYPT,
            Permission.DOCUMENT_EXPORT,
        }
    ),
    Scope.BLANKS: frozenset(
        {
            Permission.BLANK_READ,
            Permission.BLANK_ISSUE,
            Permission.BLANK_SIGN,
            Permission.BLANK_VOID,
            Permission.BLANK_VERIFY,
        }
    ),
    Scope.KEYS: frozenset(
        {
            Permission.KEY_EXPORT,
            Permission.KEY_IMPORT_DEVICE,
            Permission.KEY_ROTATE,
        }
    ),
    Scope.DEVICES: frozenset(
        {
            Permission.DEVICE_LIST,
            Permission.DEVICE_PROVISION,
            Permission.DEVICE_REVOKE,
        }
    ),
    Scope.SECURITY: frozenset(
        {
            Permission.SECURITY_DOWNGRADE,
            Permission.SECURITY_CONFIG_READ,
        }
    ),
    Scope.AUDIT: frozenset(
        {
            Permission.AUDIT_READ,
            Permission.AUDIT_VERIFY,
        }
    ),
    Scope.BACKUP: frozenset(
        {
            Permission.BACKUP_CREATE,
            Permission.BACKUP_RESTORE,
        }
    ),
    Scope.CONFIG: frozenset(
        {
            Permission.CONFIG_READ,
            Permission.CONFIG_MODIFY,
        }
    ),
    Scope.SESSIONS: frozenset(
        {
            Permission.SESSION_LIST,
            Permission.SESSION_REVOKE,
        }
    ),
}
"""Сопоставление каждого Scope множеству Permission.

``Scope.FULL`` вычисляется динамически как объединение всех прочих scope.
"""

# Scope.FULL — объединение всех остальных scope
_ALL_PERMISSIONS: FrozenSet[Permission] = frozenset(
    p for perms in SCOPE_PERMISSIONS.values() for p in perms
)
SCOPE_PERMISSIONS[Scope.FULL] = _ALL_PERMISSIONS


# ---------------------------------------------------------------------------
# Набор разрешений оператора по умолчанию
# ---------------------------------------------------------------------------

OPERATOR_PERMISSIONS: Final[FrozenSet[Permission]] = _ALL_PERMISSIONS
"""Полный набор разрешений единственного оператора системы."""

OPERATOR_SCOPES: Final[FrozenSet[str]] = frozenset({Scope.FULL.value})
"""Scope-строки, выдаваемые оператору при успешной аутентификации.

Совместимы с ``scopes`` параметром
:meth:`~src.security.auth.session.SessionManager.issue`.
"""


# ---------------------------------------------------------------------------
# OperatorRole — модель роли оператора
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OperatorRole:
    """Роль единственного оператора системы.

    В текущей архитектуре (single operator) используется одна роль с
    полным набором разрешений. Структура оставлена расширяемой на случай
    добавления read-only ролей (верификатор, аудитор).

    Attrs:
        name: Идентификатор роли.
        display_name: Отображаемое имя роли (русский).
        permissions: Разрешённые операции.
        scopes: Scope-строки для сессионных токенов.
        description: Описание назначения роли.
    """

    name: str
    display_name: str
    permissions: FrozenSet[Permission]
    scopes: FrozenSet[str]
    description: str = ""

    def has_permission(self, permission: Permission) -> bool:
        """Проверяет, входит ли операция в набор разрешений роли.

        Args:
            permission: Проверяемое разрешение.

        Returns:
            True, если разрешение предоставлено.
        """
        return permission in self.permissions

    def can_access_scope(self, scope: str) -> bool:
        """Проверяет, содержит ли роль указанный scope.

        Args:
            scope: Строковый идентификатор scope.

        Returns:
            True, если scope предоставлен.
        """
        return scope in self.scopes


# Предопределённая роль единственного оператора
OPERATOR_ROLE: Final[OperatorRole] = OperatorRole(
    name="operator",
    display_name="Оператор",
    permissions=OPERATOR_PERMISSIONS,
    scopes=OPERATOR_SCOPES,
    description=(
        "Единственный оператор системы FX Text Processor 3. Имеет полный доступ ко всем операциям."
    ),
)
"""Единственная роль в системе — оператор с полным доступом."""


# ---------------------------------------------------------------------------
# PermissionPolicy — политика авторизации для операции
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionPolicy:
    """Политика авторизации для конкретной операции.

    Описывает, какие разрешения необходимы и требует ли операция
    свежего MFA-подтверждения.

    Attrs:
        permission: Основное разрешение, предоставляющее доступ.
        mfa_required: Требуется ли свежее MFA для данной операции.
        description: Описание операции (русский).
        audit_required: Должно ли выполнение фиксироваться в аудит-лог.
    """

    permission: Permission
    mfa_required: bool
    description: str = ""
    audit_required: bool = True

    @classmethod
    def for_permission(cls, permission: Permission) -> "PermissionPolicy":
        """Создаёт политику для разрешения с автоматическим определением MFA.

        Args:
            permission: Разрешение, для которого строится политика.

        Returns:
            Экземпляр PermissionPolicy.
        """
        return cls(
            permission=permission,
            mfa_required=permission in MFA_REQUIRED_PERMISSIONS,
            description=permission.value,
        )


# Предвычисленные политики для всех разрешений
PERMISSION_POLICIES: Final[dict[Permission, PermissionPolicy]] = {
    p: PermissionPolicy.for_permission(p) for p in Permission
}
"""Политики авторизации для каждого разрешения."""


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------


def requires_mfa(permission: Permission) -> bool:
    """Возвращает True, если операция требует свежего MFA-подтверждения.

    Args:
        permission: Проверяемое разрешение.

    Returns:
        True для MFA-gated операций (см. ``MFA_REQUIRED_PERMISSIONS``).

    Examples:
        >>> requires_mfa(Permission.DEVICE_PROVISION)
        True
        >>> requires_mfa(Permission.DOCUMENT_READ)
        False
    """
    return permission in MFA_REQUIRED_PERMISSIONS


def scopes_to_permissions(scopes: FrozenSet[str]) -> FrozenSet[Permission]:
    """Разворачивает набор scope-строк в набор разрешений.

    Args:
        scopes: Набор строковых идентификаторов scope (из JWT / SessionManager).

    Returns:
        Объединённый набор разрешений всех переданных scope.
        Неизвестные scope игнорируются с предупреждением.
    """
    result: set[Permission] = set()
    for scope_str in scopes:
        try:
            scope_enum = Scope(scope_str)
        except ValueError:
            LOG.warning("Неизвестный scope: '%s' — игнорируется", scope_str)
            continue
        perms = SCOPE_PERMISSIONS.get(scope_enum, frozenset())
        result.update(perms)
    return frozenset(result)


# ---------------------------------------------------------------------------
# PermissionChecker
# ---------------------------------------------------------------------------


@dataclass
class PermissionChecker:
    """Проверяет наличие разрешений и соответствие требованиям MFA.

    Предназначен для использования в сервисном слое при каждой
    защищённой операции. Не зависит от конкретной реализации сессии —
    принимает scope как frozenset строк.

    Attrs:
        strict: При True неизвестные scope вызывают исключение.
            При False неизвестные scope игнорируются (логируется warning).

    Examples:
        >>> checker = PermissionChecker()
        >>> checker.has_permission(OPERATOR_SCOPES, Permission.KEY_EXPORT)
        True
        >>> checker.is_mfa_required(Permission.DEVICE_PROVISION)
        True
    """

    strict: bool = False

    def has_permission(self, scopes: FrozenSet[str], permission: Permission) -> bool:
        """Проверяет, предоставляет ли набор scope указанное разрешение.

        Args:
            scopes: Активные scope текущей сессии.
            permission: Проверяемое разрешение.

        Returns:
            True, если разрешение доступно через один из scope.

        Raises:
            ScopeError: Если ``strict=True`` и разрешение недоступно.
        """
        available = scopes_to_permissions(scopes)
        if permission in available:
            return True
        if self.strict:
            raise ScopeError(permission, scopes)
        return False

    def is_mfa_required(self, permission: Permission) -> bool:
        """Проверяет, требует ли операция свежего MFA.

        Args:
            permission: Проверяемое разрешение.

        Returns:
            True для MFA-gated операций.
        """
        return requires_mfa(permission)

    def assert_permission(
        self,
        scopes: FrozenSet[str],
        permission: Permission,
        *,
        mfa_satisfied: bool = False,
    ) -> None:
        """Проверяет разрешение и выбрасывает исключение при нарушении политики.

        Используется как защитный предусловный контроль в начале
        каждого защищённого метода сервисного слоя.

        Args:
            scopes: Активные scope текущей сессии.
            permission: Требуемое разрешение.
            mfa_satisfied: True, если MFA было успешно подтверждено
                в текущем контексте (свежесть проверяется SessionManager).

        Raises:
            ScopeError: Разрешение не входит в активные scope.
            MFARequiredError: Операция требует MFA, которое не пройдено.
        """
        # 1. Проверка scope
        available = scopes_to_permissions(scopes)
        if permission not in available:
            LOG.warning(
                "Доступ запрещён: разрешение '%s' не найдено в scope %s",
                permission.value,
                sorted(scopes),
            )
            raise ScopeError(permission, scopes)

        # 2. Проверка MFA для критических операций
        if requires_mfa(permission) and not mfa_satisfied:
            LOG.warning("Требуется MFA для операции '%s'", permission.value)
            raise MFARequiredError(permission)

    def effective_permissions(self, scopes: FrozenSet[str]) -> FrozenSet[Permission]:
        """Возвращает все разрешения, доступные через переданные scope.

        Args:
            scopes: Набор scope-строк активной сессии.

        Returns:
            Объединённый набор разрешений всех scope.
        """
        return scopes_to_permissions(scopes)

    def mfa_required_permissions(self, scopes: FrozenSet[str]) -> FrozenSet[Permission]:
        """Возвращает MFA-gated разрешения, доступные через переданные scope.

        Удобно для отображения в UI списка операций, требующих MFA.

        Args:
            scopes: Набор scope-строк активной сессии.

        Returns:
            Подмножество доступных разрешений, требующих MFA.
        """
        effective = self.effective_permissions(scopes)
        return effective & MFA_REQUIRED_PERMISSIONS
