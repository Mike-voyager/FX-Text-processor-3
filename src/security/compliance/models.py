"""
Модели данных для модуля compliance.

Определяет:
- DataCategory: Категории данных (PII, sensitive, etc.)
- RetentionRule: Правила хранения данных
- RetentionPolicy: Политика хранения
- PIIField: Определение PII полей
- DataSubjectRecord: Запись о субъекте данных

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class DataCategory(Enum):
    """
    Категории данных по GDPR.

    Categories:
        PUBLIC: Публичные данные (имя, фото профиля)
        INTERNAL: Внутренние данные (логи, метрики)
        PII: Персональные данные (email, телефон)
        SENSITIVE: Чувствительные данные (health, biometrics)
        FINANCIAL: Финансовые данные
        CREDENTIALS: Учётные данные (пароли, ключи)
    """

    PUBLIC = "public"
    """Публичные данные."""

    INTERNAL = "internal"
    """Внутренние данные."""

    PII = "pii"
    """Персональные данные."""

    SENSITIVE = "sensitive"
    """Чувствительные данные (GDPR Art. 9)."""

    FINANCIAL = "financial"
    """Финансовые данные."""

    CREDENTIALS = "credentials"
    """Учётные данные (особая категория)."""

    @property
    def requires_anonymization(self) -> bool:
        """Требует анонимизации при экспорте."""
        return self in (DataCategory.PII, DataCategory.SENSITIVE, DataCategory.FINANCIAL)

    @property
    def requires_encryption(self) -> bool:
        """Требует шифрования при хранении."""
        return self in (DataCategory.SENSITIVE, DataCategory.FINANCIAL, DataCategory.CREDENTIALS)

    @property
    def max_retention_days(self) -> int:
        """Максимальный срок хранения (дни)."""
        retention_map = {
            DataCategory.PUBLIC: 3650,  # 10 лет
            DataCategory.INTERNAL: 365,  # 1 год
            DataCategory.PII: 365,  # 1 год (по умолчанию)
            DataCategory.SENSITIVE: 90,  # 90 дней
            DataCategory.FINANCIAL: 2555,  # 7 лет (legal requirement)
            DataCategory.CREDENTIALS: 365,  # 1 год
        }
        return retention_map[self]


class RetentionAction(Enum):
    """
    Действия при истечении срока хранения.

    Actions:
        DELETE: Удалить данные
        ANONYMIZE: Анонимизировать данные
        ARCHIVE: Архивировать данные
        REVIEW: Отправить на ручную проверку
    """

    DELETE = "delete"
    """Удалить данные."""

    ANONYMIZE = "anonymize"
    """Анонимизировать данные."""

    ARCHIVE = "archive"
    """Аривировать данные."""

    REVIEW = "review"
    """Отправить на ручную проверку."""


@dataclass(frozen=True)
class RetentionRule:
    """
    Правило хранения данных.

    Attributes:
        name: Имя правила
        data_category: Категория данных
        retention_days: Срок хранения (дни)
        action: Действие при истечении срока
        legal_basis: Правовое основание (GDPR Art. 6)
        description: Описание
    """

    name: str
    data_category: DataCategory
    retention_days: int
    action: RetentionAction = RetentionAction.DELETE
    legal_basis: str = ""
    description: str = ""

    @property
    def retention_delta(self) -> timedelta:
        """Срок хранения как timedelta."""
        return timedelta(days=self.retention_days)

    def is_expired(self, created_at: datetime) -> bool:
        """
        Проверить, истёк ли срок хранения.

        Args:
            created_at: Дата создания данных

        Returns:
            True если срок истёк
        """
        expiration = created_at + self.retention_delta
        return datetime.now(timezone.utc) > expiration

    def expiration_date(self, created_at: datetime) -> datetime:
        """
        Вычислить дату истечения.

        Args:
            created_at: Дата создания данных

        Returns:
            Дата истечения срока хранения
        """
        return created_at + self.retention_delta


@dataclass(frozen=True)
class RetentionPolicy:
    """
    Политика хранения данных.

    Содержит набор правил для разных категорий данных.

    Attributes:
        name: Имя политики
        version: Версия
        rules: Список правил хранения
        default_rule: Правило по умолчанию
        created_at: Дата создания политики
    """

    name: str
    version: str = "1.0"
    rules: List[RetentionRule] = field(default_factory=list)
    default_rule: Optional[RetentionRule] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_rule(self, data_category: DataCategory) -> RetentionRule:
        """
        Получить правило для категории данных.

        Args:
            data_category: Категория данных

        Returns:
            Правило хранения (или default_rule)
        """
        for rule in self.rules:
            if rule.data_category == data_category:
                return rule

        if self.default_rule:
            return self.default_rule

        # Fallback: правило по умолчанию для категории
        return RetentionRule(
            name=f"default_{data_category.value}",
            data_category=data_category,
            retention_days=data_category.max_retention_days,
            action=RetentionAction.DELETE,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "name": self.name,
            "version": self.version,
            "rules": [
                {
                    "name": r.name,
                    "data_category": r.data_category.value,
                    "retention_days": r.retention_days,
                    "action": r.action.value,
                    "legal_basis": r.legal_basis,
                    "description": r.description,
                }
                for r in self.rules
            ],
            "default_rule": {
                "name": self.default_rule.name,
                "data_category": self.default_rule.data_category.value,
                "retention_days": self.default_rule.retention_days,
                "action": self.default_rule.action.value,
            } if self.default_rule else None,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class PIIField:
    """
    Определение PII поля.

    Attributes:
        name: Имя поля
        field_type: Тип PII (email, phone, name, etc.)
        category: Категория данных
        anonymizable: Можно ли анонимизировать
        anonymization_method: Метод анонимизации (hash, mask, redact, fake)
    """

    name: str
    field_type: str  # email, phone, name, address, ssn, etc.
    category: DataCategory = DataCategory.PII
    anonymizable: bool = True
    anonymization_method: str = "hash"  # hash, mask, redact, fake

    def anonymize_value(self, value: str) -> str:
        """
        Анонимизировать значение.

        Args:
            value: Исходное значение

        Returns:
            Анонимизированное значение
        """
        if not self.anonymizable or not value:
            return "[REDACTED]"

        if self.anonymization_method == "redact":
            return "[REDACTED]"

        if self.anonymization_method == "mask":
            return self._mask_value(value)

        if self.anonymization_method == "fake":
            return self._fake_value()

        # Default: hash
        import hashlib

        return hashlib.sha256(value.encode()).hexdigest()[:16]

    def _mask_value(self, value: str) -> str:
        """Маскирование значения."""
        if len(value) <= 4:
            return "*" * len(value)

        # Показываем первые 2 и последние 2 символа
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    def _fake_value(self) -> str:
        """Генерация фейкового значения."""
        import random
        import string

        fake_map = {
            "email": "user@example.com",
            "phone": "+1-555-000-0000",
            "name": "John Doe",
            "address": "123 Main St",
            "ssn": "000-00-0000",
        }

        if self.field_type in fake_map:
            return fake_map[self.field_type]

        # Случайная строка
        return "".join(random.choices(string.ascii_lowercase, k=8))


@dataclass(frozen=True)
class DataSubjectRecord:
    """
    Запись о субъекте данных (data subject).

    Attributes:
        subject_id: Уникальный идентификатор субъекта
        identifier_type: Тип идентификатора (user_id, email, etc.)
        data_categories: Категории данных субъекта
        created_at: Дата создания записи
        last_updated: Дата последнего обновления
        consent_given: Согласие дано
        consent_date: Дата согласия
        retention_policy: Применённая политика
    """

    subject_id: str
    identifier_type: str = "user_id"
    data_categories: List[DataCategory] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    consent_given: bool = False
    consent_date: Optional[datetime] = None
    retention_policy: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "subject_id": self.subject_id,
            "identifier_type": self.identifier_type,
            "data_categories": [c.value for c in self.data_categories],
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "consent_given": self.consent_given,
            "consent_date": self.consent_date.isoformat() if self.consent_date else None,
            "retention_policy": self.retention_policy,
        }


@dataclass(frozen=True)
class DataExportRequest:
    """
    Запрос на экспорт данных (GDPR Art. 20).

    Attributes:
        request_id: Идентификатор запроса
        subject_id: Идентификатор субъекта данных
        export_format: Формат экспорта (json, xml, csv)
        include_metadata: Включить метаданные
        anonymize_pii: Анонимизировать PII
        requested_at: Дата запроса
        status: Статус запроса
    """

    request_id: str
    subject_id: str
    export_format: str = "json"
    include_metadata: bool = True
    anonymize_pii: bool = True
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "pending"  # pending, processing, completed, failed


@dataclass(frozen=True)
class ErasureRequest:
    """
    Запрос на удаление данных (GDPR Art. 17).

    Attributes:
        request_id: Идентификатор запроса
        subject_id: Идентификатор субъекта данных
        reason: Причина удаления
        data_types: Типы данных для удаления
        requested_at: Дата запроса
        status: Статус запроса
        completed_at: Дата завершения
        notes: Заметки
    """

    request_id: str
    subject_id: str
    reason: str = "Data subject request"
    data_types: List[str] = field(default_factory=list)
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "pending"  # pending, processing, completed, failed, denied
    completed_at: Optional[datetime] = None
    notes: List[str] = field(default_factory=list)


__all__: list[str] = [
    "DataCategory",
    "RetentionAction",
    "RetentionRule",
    "RetentionPolicy",
    "PIIField",
    "DataSubjectRecord",
    "DataExportRequest",
    "ErasureRequest",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"