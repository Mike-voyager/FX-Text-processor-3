"""
Анонимизация PII данных.

PIIAnonymizer предоставляет методы для анонимизации
персональных данных в соответствии с GDPR.

Methods:
    - Hash: SHA-256 хеш с солью
    - Mask: Частичное маскирование
    - Redact: Полное удаление
    - Fake: Замена на фейковые данные
    - Generalize: Обобщение данных

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from src.security.compliance.exceptions import AnonymizationError
from src.security.compliance.models import DataCategory, PIIField

LOG = logging.getLogger(__name__)

# Предопределённые PII поля
DEFAULT_PII_FIELDS: List[PIIField] = [
    PIIField(name="email", field_type="email", anonymization_method="hash"),
    PIIField(name="phone", field_type="phone", anonymization_method="mask"),
    PIIField(name="first_name", field_type="name", anonymization_method="fake"),
    PIIField(name="last_name", field_type="name", anonymization_method="fake"),
    PIIField(name="full_name", field_type="name", anonymization_method="fake"),
    PIIField(name="address", field_type="address", anonymization_method="mask"),
    PIIField(name="city", field_type="city", anonymization_method="generalize"),
    PIIField(name="postal_code", field_type="postal_code", anonymization_method="mask"),
    PIIField(name="country", field_type="country", anonymization_method="keep"),  # Страна обычно не PII
    PIIField(name="date_of_birth", field_type="date", anonymization_method="generalize"),
    PIIField(name="ssn", field_type="ssn", category=DataCategory.SENSITIVE, anonymization_method="redact"),
    PIIField(name="passport", field_type="passport", category=DataCategory.SENSITIVE, anonymization_method="redact"),
    PIIField(name="ip_address", field_type="ip", anonymization_method="mask"),
    PIIField(name="user_agent", field_type="user_agent", anonymization_method="redact"),
]


@dataclass
class PIIAnonymizer:
    """
    Анонимизатор PII данных.

    Предоставляет методы для анонимизации персональных данных.

    Attributes:
        fields: Список PII полей
        salt: Соль для хеширования (генерируется если не задана)
        audit_log: Опциональный AuditLog для логирования

    Example:
        >>> anonymizer = PIIAnonymizer()
        >>> data = {"email": "user@example.com", "name": "John Doe"}
        >>> anonymized = anonymizer.anonymize(data)
        >>> print(anonymized["email"])  # хеш вместо email
    """

    fields: List[PIIField] = field(default_factory=lambda: list(DEFAULT_PII_FIELDS))
    salt: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    audit_log: Optional[Any] = None  # AuditLog

    # Кэш для хешей (ускоряет повторную анонимизацию)
    _hash_cache: Dict[str, str] = field(default_factory=dict, init=False)

    # Паттерны для автоопределения PII
    _patterns: Dict[str, re.Pattern[str]] = field(
        default_factory=lambda: {
            "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
            "phone": re.compile(r"^\+?[\d\s\-\(\)]{7,15}$"),
            "ssn": re.compile(r"^\d{3}-\d{2}-\d{4}$"),
            "postal_code": re.compile(r"^\d{5}(-\d{4})?$"),
            "ip_v4": re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
        },
        init=False,
    )

    def anonymize(
        self,
        data: Dict[str, Any],
        *,
        fields_to_anonymize: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """
        Анонимизировать данные.

        Args:
            data: Словарь с данными
            fields_to_anonymize: Опционально, список полей для анонимизации

        Returns:
            Анонимизированный словарь

        Raises:
            AnonymizationError: Ошибка анонимизации
        """
        result: Dict[str, Any] = {}

        for key, value in data.items():
            # Пропускаем None
            if value is None:
                result[key] = None
                continue

            # Проверяем, нужно ли анонимизировать
            if fields_to_anonymize and key not in fields_to_anonymize:
                result[key] = value
                continue

            # Ищем поле в списке PII
            pii_field = self._find_field(key)

            if pii_field:
                result[key] = self._anonymize_value(str(value), pii_field)
            else:
                # Автоопределение PII
                if self._is_pii(key, value):
                    result[key] = self._auto_anonymize(key, str(value))
                else:
                    result[key] = value

        self._log_anonymization(data, result)

        return result

    def anonymize_list(
        self,
        records: List[Dict[str, Any]],
        *,
        fields_to_anonymize: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Анонимизировать список записей.

        Args:
            records: Список записей
            fields_to_anonymize: Опционально, список полей

        Returns:
            Список анонимизированных записей
        """
        return [self.anonymize(record, fields_to_anonymize=fields_to_anonymize) for record in records]

    def _find_field(self, name: str) -> Optional[PIIField]:
        """Найти PII поле по имени."""
        for field in self.fields:
            if field.name == name:
                return field
        return None

    def _anonymize_value(self, value: str, pii_field: PIIField) -> str:
        """Анонимизировать значение по методу поля."""
        method = pii_field.anonymization_method

        if method == "hash":
            return self._hash_value(value)
        elif method == "mask":
            return self._mask_value(value)
        elif method == "redact":
            return "[REDACTED]"
        elif method == "fake":
            return self._fake_value(pii_field.field_type)
        elif method == "generalize":
            return self._generalize_value(value, pii_field.field_type)
        elif method == "keep":
            return value
        else:
            LOG.warning("Unknown anonymization method: %s, using redact", method)
            return "[REDACTED]"

    def _hash_value(self, value: str) -> str:
        """Хешировать значение с солью."""
        # Проверяем кэш
        cache_key = f"{value}:{self.salt.hex()[:8]}"
        if cache_key in self._hash_cache:
            return self._hash_cache[cache_key]

        # Вычисляем хеш
        hash_value = hashlib.sha256(self.salt + value.encode()).hexdigest()[:16]
        self._hash_cache[cache_key] = hash_value

        return hash_value

    def _mask_value(self, value: str) -> str:
        """Маскировать значение (показать часть)."""
        if len(value) <= 4:
            return "*" * len(value)

        # Показываем первые 2 и последние 2 символа
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    def _fake_value(self, field_type: str) -> str:
        """Генерировать фейковое значение."""
        fake_values = {
            "email": "anon@example.com",
            "phone": "+1-555-000-0000",
            "name": "Anonymous User",
            "address": "123 Anonymous St",
            "city": "Anonymous City",
            "country": "Country",
            "ssn": "000-00-0000",
            "passport": "ANON000000",
            "ip": "0.0.0.0",
            "user_agent": "Anonymous/1.0",
            "date": "1900-01-01",
            "postal_code": "00000",
        }

        return fake_values.get(field_type, "[ANONYMIZED]")

    def _generalize_value(self, value: str, field_type: str) -> str:
        """Обобщить значение."""
        if field_type == "date":
            # Обобщаем дату до года
            try:
                dt = datetime.fromisoformat(value)
                return str(dt.year)
            except ValueError:
                return "[YEAR]"
        elif field_type == "city":
            # Обобщаем город до региона
            return f"Region of {value[:3]}..." if len(value) > 3 else "[Region]"
        elif field_type == "age":
            # Обобщаем возраст до диапазона
            try:
                age = int(value)
                if age < 18:
                    return "under-18"
                elif age < 25:
                    return "18-24"
                elif age < 35:
                    return "25-34"
                elif age < 45:
                    return "35-44"
                elif age < 55:
                    return "45-54"
                elif age < 65:
                    return "55-64"
                else:
                    return "65+"
            except ValueError:
                return "[AGE RANGE]"
        else:
            return self._mask_value(value)

    def _is_pii(self, key: str, value: Any) -> bool:
        """Автоопределение PII по имени поля и значению."""
        # Проверяем имя поля
        key_lower = key.lower()
        pii_keywords = {
            "email", "phone", "ssn", "passport", "name", "address",
            "postal", "zip", "birth", "ip", "user_agent",
        }

        if any(kw in key_lower for kw in pii_keywords):
            return True

        # Проверяем значение по паттернам
        if isinstance(value, str):
            for pattern_name, pattern in self._patterns.items():
                if pattern.match(value):
                    return True

        return False

    def _auto_anonymize(self, key: str, value: str) -> str:
        """Автоматическая анонимизация по типу значения."""
        # Email
        if self._patterns["email"].match(value):
            return self._hash_value(value)

        # Phone
        if self._patterns["phone"].match(value):
            return self._mask_value(value)

        # SSN
        if self._patterns["ssn"].match(value):
            return "[REDACTED]"

        # IP
        if self._patterns["ip_v4"].match(value):
            return self._mask_value(value)

        # По умолчанию - маскирование
        return self._mask_value(value)

    def _log_anonymization(self, original: Dict[str, Any], anonymized: Dict[str, Any]) -> None:
        """Логировать анонимизацию в audit."""
        if not self.audit_log:
            return

        try:
            from src.security.audit import AuditEventType

            # Определяем какие поля были анонимизированы
            anonymized_fields = [
                key for key in original
                if original.get(key) != anonymized.get(key) and original.get(key) is not None
            ]

            self.audit_log.log_event(
                AuditEventType.FORM_HISTORY_ENTRY_ADDED,  # Используем доступный тип
                details={
                    "action": "pii_anonymization",
                    "fields_anonymized": anonymized_fields,
                    "field_count": len(anonymized_fields),
                },
            )

        except Exception as e:
            LOG.warning("Failed to log anonymization: %s", e)

    def add_field(self, field: PIIField) -> None:
        """Добавить PII поле."""
        self.fields.append(field)

    def remove_field(self, name: str) -> bool:
        """Удалить PII поле по имени."""
        for i, field in enumerate(self.fields):
            if field.name == name:
                self.fields.pop(i)
                return True
        return False

    def clear_cache(self) -> None:
        """Очистить кэш хешей."""
        self._hash_cache.clear()


__all__: list[str] = [
    "PIIAnonymizer",
    "DEFAULT_PII_FIELDS",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"