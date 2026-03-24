"""
Типы событий аудита.

Определяет все типы событий для аудита в системе FX Text Processor.
Каждое событие имеет уникальный строковый идентификатор и категорию.

Categories:
    - Application: Запуск, блокировка, проверка целостности
    - Authentication: Успех/провал входа, MFA, резервные коды
    - Hardware: Устройства, ключи, операции
    - Blanks: Жизненный цикл защищённых бланков
    - FormHistory: История форм
    - Template: Импорт/экспорт шаблонов
    - Workflow: Согласование документов

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from enum import Enum
from typing import Final


class AuditEventType(Enum):
    """
    Перечисление типов событий аудита.

    Все события разделены на категории по префиксу:
    - app.* — Application events
    - auth.* — Authentication events
    - device.* — Hardware device events
    - blank.* — Protected blank events
    - form_history.* — Form history events
    - template.* — Template library events
    - workflow.* — Approval workflow events
    - crypto.* — Cryptographic operation events
    - keystore.* — Key management events
    - session.* — Session events
    - integrity.* — Integrity check events
    """

    # =========================================================================
    # Application Events
    # =========================================================================

    APP_STARTED = "app.started"
    """Приложение запущено."""

    APP_LOCKED = "app.locked"
    """Приложение заблокировано."""

    APP_UNLOCKED = "app.unlocked"
    """Приложение разблокировано."""

    APP_CLOSED = "app.closed"
    """Приложение закрыто."""

    APP_CRASH = "app.crash"
    """Аварийное завершение приложения."""

    INTEGRITY_CHECK_PASSED = "integrity.passed"
    """Проверка целостности пройдена успешно."""

    INTEGRITY_CHECK_FAILED = "integrity.failed"
    """Проверка целостности обнаружила нарушения."""

    # =========================================================================
    # Authentication Events
    # =========================================================================

    AUTH_SUCCESS = "auth.success"
    """Успешная аутентификация."""

    AUTH_FAILED = "auth.failed"
    """Неудачная аутентификация."""

    AUTH_MFA_CHALLENGED = "auth.mfa_challenged"
    """MFA запрос."""

    AUTH_MFA_SUCCESS = "auth.mfa_success"
    """MFA успешно пройден."""

    AUTH_MFA_FAILED = "auth.mfa_failed"
    """MFA не пройден."""

    SECOND_FACTOR_ADDED = "auth.2fa_added"
    """Второй фактор добавлен."""

    SECOND_FACTOR_REMOVED = "auth.2fa_removed"
    """Второй фактор удалён."""

    BACKUP_CODE_USED = "auth.backup_code_used"
    """Использован резервный код."""

    BACKUP_CODE_REGENERATED = "auth.backup_code_regenerated"
    """Резервные коды перегенерированы."""

    PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105
    """Пароль изменён."""

    PASSWORD_RESET = "auth.password_reset"  # noqa: S105
    """Пароль сброшен."""

    # =========================================================================
    # Hardware Device Events
    # =========================================================================

    DEVICE_PROVISIONED = "device.provisioned"
    """Устройство провизировано."""

    DEVICE_REVOKED = "device.revoked"
    """Устройство отозвано."""

    DEVICE_KEY_IMPORTED = "device.key_imported"
    """Ключ импортирован на устройство (⚠️ logged with warning)."""

    DEVICE_OPERATION = "device.operation"
    """Операция на устройстве."""

    DEVICE_PIN_CHANGED = "device.pin_changed"
    """PIN устройства изменён."""

    DEVICE_LOCKOUT = "device.lockout"
    """Устройство заблокировано (превышено количество попыток PIN)."""

    # =========================================================================
    # Protected Blank Events
    # =========================================================================

    BLANK_ISSUED = "blank.issued"
    """Бланк выдан."""

    BLANK_SIGNED = "blank.signed"
    """Бланк подписан."""

    BLANK_VERIFIED = "blank.verified"
    """Бланк верифицирован."""

    BLANK_VERIFY_FAILED = "blank.verify_failed"
    """Верификация бланка не удалась."""

    BLANK_VOIDED = "blank.voided"
    """Бланк аннулирован."""

    BLANK_SPOILED = "blank.spoiled"
    """Бланк испорчен."""

    BLANK_ARCHIVED = "blank.archived"
    """Бланк архивирован."""

    BLANK_SIGNING_BLOCKED = "blank.signing_blocked"
    """Подпись бланка заблокирована (ошибки валидации)."""

    # =========================================================================
    # Form History Events
    # =========================================================================

    FORM_HISTORY_ENTRY_ADDED = "form_history.entry_added"
    """Запись добавлена в историю."""

    FORM_HISTORY_RETENTION_ENFORCED = "form_history.retention_enforced"
    """Применена политика хранения."""

    FORM_HISTORY_CLEARED = "form_history.cleared"
    """История очищена."""

    FORM_HISTORY_INTEGRITY_FAILED = "form_history.integrity_failed"
    """Нарушение целостности истории."""

    # =========================================================================
    # Template Library Events
    # =========================================================================

    TEMPLATE_IMPORTED = "template.imported"
    """Шаблон импортирован."""

    TEMPLATE_EXPORTED = "template.exported"
    """Шаблон экспортирован."""

    TEMPLATE_SIGNATURE_INVALID = "template.signature_invalid"
    """Подпись шаблона недействительна."""

    TEMPLATE_TRUST_CHAIN_FAILED = "template.trust_chain_failed"
    """Цепочка доверия шаблона не прошла проверку."""

    TEMPLATE_CREATED = "template.created"
    """Шаблон создан."""

    TEMPLATE_UPDATED = "template.updated"
    """Шаблон обновлён."""

    TEMPLATE_DELETED = "template.deleted"
    """Шаблон удалён."""

    # =========================================================================
    # Approval Workflow Events
    # =========================================================================

    WORKFLOW_ROLE_SWITCHED = "workflow.role_switched"
    """Роль переключена."""

    WORKFLOW_TRANSITION = "workflow.transition"
    """Переход между статусами."""

    WORKFLOW_COMMENT_ADDED = "workflow.comment_added"
    """Комментарий добавлен."""

    WORKFLOW_COMMENT_RESOLVED = "workflow.comment_resolved"
    """Комментарий разрешён."""

    WORKFLOW_REJECTED = "workflow.rejected"
    """Документ отклонён."""

    WORKFLOW_SKIP_ATTEMPTED = "workflow.skip_attempted"
    """Попытка обхода workflow."""

    WORKFLOW_APPROVED = "workflow.approved"
    """Документ согласован."""

    # =========================================================================
    # Cryptographic Events
    # =========================================================================

    CRYPTO_KEY_GENERATED = "crypto.key_generated"
    """Ключ сгенерирован."""

    CRYPTO_KEY_ROTATED = "crypto.key_rotated"
    """Ключ ротирован."""

    CRYPTO_KEY_DESTROYED = "crypto.key_destroyed"
    """Ключ уничтожен."""

    CRYPTO_ENCRYPTION = "crypto.encryption"
    """Операция шифрования."""

    CRYPTO_DECRYPTION = "crypto.decryption"
    """Операция расшифровки."""

    CRYPTO_SIGNING = "crypto.signing"
    """Операция подписи."""

    CRYPTO_VERIFICATION = "crypto.verification"
    """Операция верификации подписи."""

    CRYPTO_PRESET_CHANGED = "crypto.preset_changed"
    """Пресет безопасности изменён."""

    # =========================================================================
    # Keystore Events
    # =========================================================================

    KEYSTORE_OPENED = "keystore.opened"
    """Хранилище ключей открыто."""

    KEYSTORE_CLOSED = "keystore.closed"
    """Хранилище ключей закрыто."""

    KEYSTORE_BACKUP_CREATED = "keystore.backup_created"
    """Резервная копия создана."""

    KEYSTORE_RESTORED = "keystore.restored"
    """Хранилище восстановлено из резервной копии."""

    KEYSTORE_MIGRATED = "keystore.migrated"
    """Хранилище мигрировано."""

    # =========================================================================
    # Session Events
    # =========================================================================

    SESSION_CREATED = "session.created"
    """Сессия создана."""

    SESSION_EXTENDED = "session.extended"
    """Сессия продлена."""

    SESSION_TERMINATED = "session.terminated"
    """Сессия завершена."""

    SESSION_TIMEOUT = "session.timeout"
    """Сессия истекла по таймауту."""

    SESSION_LOCKED = "session.locked"
    """Сессия заблокирована."""

    # =========================================================================
    # Print Events
    # =========================================================================

    PRINT_STARTED = "print.started"
    """Печать начата."""

    PRINT_COMPLETED = "print.completed"
    """Печать завершена."""

    PRINT_FAILED = "print.failed"
    """Ошибка печати."""

    PRINT_CANCELLED = "print.cancelled"
    """Печать отменена."""

    @property
    def category(self) -> str:
        """
        Категория события.

        Returns:
            Категория (префикс до первой точки)
        """
        return self.value.split(".", maxsplit=1)[0]

    @property
    def severity(self) -> str:
        """
        Серьёзность события.

        Returns:
            'info' | 'warning' | 'critical' | 'error'
        """
        # Critical events
        critical_events: Final[set[AuditEventType]] = {
            AuditEventType.INTEGRITY_CHECK_FAILED,
            AuditEventType.AUTH_MFA_FAILED,
            AuditEventType.DEVICE_LOCKOUT,
            AuditEventType.BLANK_VERIFY_FAILED,
            AuditEventType.FORM_HISTORY_INTEGRITY_FAILED,
            AuditEventType.TEMPLATE_SIGNATURE_INVALID,
            AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
            AuditEventType.WORKFLOW_SKIP_ATTEMPTED,
            AuditEventType.APP_CRASH,
        }

        # Warning events
        warning_events: Final[set[AuditEventType]] = {
            AuditEventType.AUTH_FAILED,
            AuditEventType.DEVICE_KEY_IMPORTED,
            AuditEventType.BLANK_SIGNING_BLOCKED,
            AuditEventType.WORKFLOW_REJECTED,
            AuditEventType.CRYPTO_PRESET_CHANGED,
            AuditEventType.SESSION_TIMEOUT,
            AuditEventType.PRINT_FAILED,
        }

        # Error events
        error_events: Final[set[AuditEventType]] = {
            AuditEventType.PRINT_FAILED,
            AuditEventType.PRINT_CANCELLED,
        }

        if self in critical_events:
            return "critical"
        if self in warning_events:
            return "warning"
        if self in error_events:
            return "error"
        return "info"


# Категории событий для удобной фильтрации
CATEGORY_APPLICATION: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.APP_STARTED,
        AuditEventType.APP_LOCKED,
        AuditEventType.APP_UNLOCKED,
        AuditEventType.APP_CLOSED,
        AuditEventType.APP_CRASH,
        AuditEventType.INTEGRITY_CHECK_PASSED,
        AuditEventType.INTEGRITY_CHECK_FAILED,
    }
)

CATEGORY_AUTHENTICATION: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.AUTH_SUCCESS,
        AuditEventType.AUTH_FAILED,
        AuditEventType.AUTH_MFA_CHALLENGED,
        AuditEventType.AUTH_MFA_SUCCESS,
        AuditEventType.AUTH_MFA_FAILED,
        AuditEventType.SECOND_FACTOR_ADDED,
        AuditEventType.SECOND_FACTOR_REMOVED,
        AuditEventType.BACKUP_CODE_USED,
        AuditEventType.BACKUP_CODE_REGENERATED,
        AuditEventType.PASSWORD_CHANGED,
        AuditEventType.PASSWORD_RESET,
    }
)

CATEGORY_HARDWARE: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.DEVICE_PROVISIONED,
        AuditEventType.DEVICE_REVOKED,
        AuditEventType.DEVICE_KEY_IMPORTED,
        AuditEventType.DEVICE_OPERATION,
        AuditEventType.DEVICE_PIN_CHANGED,
        AuditEventType.DEVICE_LOCKOUT,
    }
)

CATEGORY_BLANKS: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.BLANK_ISSUED,
        AuditEventType.BLANK_SIGNED,
        AuditEventType.BLANK_VERIFIED,
        AuditEventType.BLANK_VERIFY_FAILED,
        AuditEventType.BLANK_VOIDED,
        AuditEventType.BLANK_SPOILED,
        AuditEventType.BLANK_ARCHIVED,
        AuditEventType.BLANK_SIGNING_BLOCKED,
    }
)

CATEGORY_FORM_HISTORY: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.FORM_HISTORY_ENTRY_ADDED,
        AuditEventType.FORM_HISTORY_RETENTION_ENFORCED,
        AuditEventType.FORM_HISTORY_CLEARED,
        AuditEventType.FORM_HISTORY_INTEGRITY_FAILED,
    }
)

CATEGORY_TEMPLATE: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.TEMPLATE_IMPORTED,
        AuditEventType.TEMPLATE_EXPORTED,
        AuditEventType.TEMPLATE_SIGNATURE_INVALID,
        AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
        AuditEventType.TEMPLATE_CREATED,
        AuditEventType.TEMPLATE_UPDATED,
        AuditEventType.TEMPLATE_DELETED,
    }
)

CATEGORY_WORKFLOW: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.WORKFLOW_ROLE_SWITCHED,
        AuditEventType.WORKFLOW_TRANSITION,
        AuditEventType.WORKFLOW_COMMENT_ADDED,
        AuditEventType.WORKFLOW_COMMENT_RESOLVED,
        AuditEventType.WORKFLOW_REJECTED,
        AuditEventType.WORKFLOW_SKIP_ATTEMPTED,
        AuditEventType.WORKFLOW_APPROVED,
    }
)

CATEGORY_CRYPTO: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.CRYPTO_KEY_GENERATED,
        AuditEventType.CRYPTO_KEY_ROTATED,
        AuditEventType.CRYPTO_KEY_DESTROYED,
        AuditEventType.CRYPTO_ENCRYPTION,
        AuditEventType.CRYPTO_DECRYPTION,
        AuditEventType.CRYPTO_SIGNING,
        AuditEventType.CRYPTO_VERIFICATION,
        AuditEventType.CRYPTO_PRESET_CHANGED,
    }
)

CATEGORY_KEYSTORE: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.KEYSTORE_OPENED,
        AuditEventType.KEYSTORE_CLOSED,
        AuditEventType.KEYSTORE_BACKUP_CREATED,
        AuditEventType.KEYSTORE_RESTORED,
        AuditEventType.KEYSTORE_MIGRATED,
    }
)

CATEGORY_SESSION: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.SESSION_CREATED,
        AuditEventType.SESSION_EXTENDED,
        AuditEventType.SESSION_TERMINATED,
        AuditEventType.SESSION_TIMEOUT,
        AuditEventType.SESSION_LOCKED,
    }
)

CATEGORY_PRINT: Final[frozenset[AuditEventType]] = frozenset(
    {
        AuditEventType.PRINT_STARTED,
        AuditEventType.PRINT_COMPLETED,
        AuditEventType.PRINT_FAILED,
        AuditEventType.PRINT_CANCELLED,
    }
)


__all__: list[str] = [
    "AuditEventType",
    "CATEGORY_APPLICATION",
    "CATEGORY_AUTHENTICATION",
    "CATEGORY_HARDWARE",
    "CATEGORY_BLANKS",
    "CATEGORY_FORM_HISTORY",
    "CATEGORY_TEMPLATE",
    "CATEGORY_WORKFLOW",
    "CATEGORY_CRYPTO",
    "CATEGORY_KEYSTORE",
    "CATEGORY_SESSION",
    "CATEGORY_PRINT",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
