"""
Тесты для модуля compliance (GDPR).

Tests:
    - DataCategory: категории данных
    - RetentionRule: правила хранения
    - RetentionPolicy: политика хранения
    - PIIField: определение PII полей
    - RetentionPolicyManager: менеджер политик
    - PIIAnonymizer: анонимизатор
    - DataExportService: сервис экспорта
    - RightToErasureHandler: обработчик удаления

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List
from unittest.mock import MagicMock

import pytest

from src.security.compliance import (
    AnonymizationError,
    ComplianceError,
    DataCategory,
    DataExportError,
    DataExportRequest,
    DataExportService,
    DataSubjectRecord,
    DEFAULT_PII_FIELDS,
    DEFAULT_RULES,
    DENIAL_REASONS,
    ErasureError,
    ErasureRequest,
    ErasureResult,
    PIIAnonymizer,
    PIIField,
    RetentionAction,
    RetentionError,
    RetentionPolicy,
    RetentionPolicyManager,
    RetentionRule,
    RightToErasureHandler,
)


# =============================================================================
# Tests for DataCategory
# =============================================================================


class TestDataCategory:
    """Тесты для DataCategory."""

    def test_category_values(self) -> None:
        """Проверка значений категорий."""
        assert DataCategory.PUBLIC.value == "public"
        assert DataCategory.INTERNAL.value == "internal"
        assert DataCategory.PII.value == "pii"
        assert DataCategory.SENSITIVE.value == "sensitive"
        assert DataCategory.FINANCIAL.value == "financial"
        assert DataCategory.CREDENTIALS.value == "credentials"

    def test_requires_anonymization(self) -> None:
        """Проверка requires_anonymization."""
        assert DataCategory.PII.requires_anonymization is True
        assert DataCategory.SENSITIVE.requires_anonymization is True
        assert DataCategory.FINANCIAL.requires_anonymization is True
        assert DataCategory.PUBLIC.requires_anonymization is False
        assert DataCategory.INTERNAL.requires_anonymization is False

    def test_requires_encryption(self) -> None:
        """Проверка requires_encryption."""
        assert DataCategory.SENSITIVE.requires_encryption is True
        assert DataCategory.FINANCIAL.requires_encryption is True
        assert DataCategory.CREDENTIALS.requires_encryption is True
        assert DataCategory.PII.requires_encryption is False

    def test_max_retention_days(self) -> None:
        """Проверка max_retention_days."""
        assert DataCategory.PUBLIC.max_retention_days == 3650  # 10 лет
        assert DataCategory.INTERNAL.max_retention_days == 365
        assert DataCategory.SENSITIVE.max_retention_days == 90


# =============================================================================
# Tests for RetentionRule
# =============================================================================


class TestRetentionRule:
    """Тесты для RetentionRule."""

    def test_rule_creation(self) -> None:
        """Создание правила."""
        rule = RetentionRule(
            name="test_rule",
            data_category=DataCategory.PII,
            retention_days=365,
            action=RetentionAction.DELETE,
        )

        assert rule.name == "test_rule"
        assert rule.data_category == DataCategory.PII
        assert rule.retention_days == 365
        assert rule.action == RetentionAction.DELETE

    def test_retention_delta(self) -> None:
        """Проверка retention_delta."""
        rule = RetentionRule(
            name="test",
            data_category=DataCategory.PII,
            retention_days=30,
        )

        assert rule.retention_delta == timedelta(days=30)

    def test_is_expired(self) -> None:
        """Проверка is_expired."""
        rule = RetentionRule(
            name="test",
            data_category=DataCategory.PII,
            retention_days=30,
        )

        # Запись 31 день назад — истёк
        old_date = datetime.now(timezone.utc) - timedelta(days=31)
        assert rule.is_expired(old_date) is True

        # Запись 10 дней назад — не истёк
        recent_date = datetime.now(timezone.utc) - timedelta(days=10)
        assert rule.is_expired(recent_date) is False

    def test_expiration_date(self) -> None:
        """Проверка expiration_date."""
        rule = RetentionRule(
            name="test",
            data_category=DataCategory.PII,
            retention_days=30,
        )

        created = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiration = rule.expiration_date(created)

        assert expiration == datetime(2026, 1, 31, tzinfo=timezone.utc)


# =============================================================================
# Tests for RetentionPolicy
# =============================================================================


class TestRetentionPolicy:
    """Тесты для RetentionPolicy."""

    def test_policy_creation(self) -> None:
        """Создание политики."""
        policy = RetentionPolicy(
            name="test_policy",
            version="1.0",
            rules=[
                RetentionRule(
                    name="pii",
                    data_category=DataCategory.PII,
                    retention_days=365,
                ),
            ],
        )

        assert policy.name == "test_policy"
        assert len(policy.rules) == 1

    def test_get_rule(self) -> None:
        """Получение правила для категории."""
        policy = RetentionPolicy(
            name="test",
            rules=[
                RetentionRule(
                    name="pii",
                    data_category=DataCategory.PII,
                    retention_days=365,
                ),
            ],
        )

        rule = policy.get_rule(DataCategory.PII)
        assert rule.name == "pii"
        assert rule.retention_days == 365

    def test_get_rule_fallback(self) -> None:
        """Получение правила fallback."""
        policy = RetentionPolicy(name="test")

        rule = policy.get_rule(DataCategory.PII)
        assert rule.data_category == DataCategory.PII
        # Должно вернуть правило с max_retention_days из категории
        assert rule.retention_days == DataCategory.PII.max_retention_days

    def test_to_dict(self) -> None:
        """Сериализация политики."""
        policy = RetentionPolicy(
            name="test",
            version="2.0",
            rules=[
                RetentionRule(
                    name="pii",
                    data_category=DataCategory.PII,
                    retention_days=365,
                ),
            ],
        )

        data = policy.to_dict()

        assert data["name"] == "test"
        assert data["version"] == "2.0"
        assert len(data["rules"]) == 1
        assert data["rules"][0]["data_category"] == "pii"


# =============================================================================
# Tests for PIIField
# =============================================================================


class TestPIIField:
    """Тесты для PIIField."""

    def test_field_creation(self) -> None:
        """Создание PII поля."""
        field = PIIField(
            name="email",
            field_type="email",
            category=DataCategory.PII,
            anonymization_method="hash",
        )

        assert field.name == "email"
        assert field.field_type == "email"
        assert field.anonymization_method == "hash"

    def test_anonymize_hash(self) -> None:
        """Анонимизация хешем."""
        field = PIIField(name="email", field_type="email", anonymization_method="hash")

        result = field.anonymize_value("user@example.com")

        # Хеш — 16 символов
        assert len(result) == 16
        assert result != "user@example.com"

    def test_anonymize_mask(self) -> None:
        """Анонимизация маскированием."""
        field = PIIField(name="phone", field_type="phone", anonymization_method="mask")

        result = field.anonymize_value("+12345678901")

        # Первые 2 и последние 2 символа видны
        assert result.startswith("+1")
        assert result.endswith("01")
        assert "*" in result

    def test_anonymize_redact(self) -> None:
        """Анонимизация удалением."""
        field = PIIField(name="ssn", field_type="ssn", anonymization_method="redact")

        result = field.anonymize_value("123-45-6789")

        assert result == "[REDACTED]"

    def test_anonymize_fake(self) -> None:
        """Анонимизация фейковыми данными."""
        field = PIIField(name="email", field_type="email", anonymization_method="fake")

        result = field.anonymize_value("real@example.com")

        # Фейковое значение из fake_map
        assert result == "user@example.com"

    def test_anonymize_empty_value(self) -> None:
        """Анонимизация пустого значения."""
        field = PIIField(name="email", field_type="email")

        result = field.anonymize_value("")

        # Пустое значение не анонимизируется
        assert result == "[REDACTED]"


# =============================================================================
# Tests for RetentionPolicyManager
# =============================================================================


class TestRetentionPolicyManager:
    """Тесты для RetentionPolicyManager."""

    def test_manager_creation(self) -> None:
        """Создание менеджера."""
        manager = RetentionPolicyManager()

        assert manager.policy is not None
        assert len(manager.policy.rules) > 0

    def test_get_rule(self) -> None:
        """Получение правила."""
        manager = RetentionPolicyManager()

        rule = manager.get_rule(DataCategory.PII)

        assert rule.data_category == DataCategory.PII

    def test_find_expired_records(self) -> None:
        """Поиск истёкших записей."""
        manager = RetentionPolicyManager()

        records: List[Dict[str, str]] = [
            {
                "id": "1",
                "category": "pii",
                "created_at": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
            },
            {
                "id": "2",
                "category": "pii",
                "created_at": (datetime.now(timezone.utc) - timedelta(days=100)).isoformat(),
            },
        ]

        expired = manager.find_expired_records(records)  # type: ignore[arg-type]

        # Только первая запись истекла
        assert len(expired) == 1
        assert expired[0]["id"] == "1"

    def test_get_action(self) -> None:
        """Получение действия."""
        manager = RetentionPolicyManager()

        record = {"id": "1", "category": "pii"}
        action = manager.get_action(record)  # type: ignore[arg-type]

        assert action == RetentionAction.ANONYMIZE

    def test_apply_retention_dry_run(self) -> None:
        """Применение политики (dry run)."""
        manager = RetentionPolicyManager()

        records: List[Dict[str, str]] = [
            {
                "id": "1",
                "category": "pii",
                "created_at": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
            },
        ]

        result = manager.apply_retention(records, dry_run=True)  # type: ignore[arg-type]

        assert result["dry_run"] is True
        assert result["expired_count"] == 1


# =============================================================================
# Tests for PIIAnonymizer
# =============================================================================


class TestPIIAnonymizer:
    """Тесты для PIIAnonymizer."""

    def test_anonymizer_creation(self) -> None:
        """Создание анонимизатора."""
        anonymizer = PIIAnonymizer()

        assert len(anonymizer.fields) > 0
        assert len(anonymizer.salt) == 32

    def test_anonymize_email(self) -> None:
        """Анонимизация email."""
        anonymizer = PIIAnonymizer()

        data = {"email": "user@example.com", "name": "John"}
        result = anonymizer.anonymize(data)

        # email должен быть анонимизирован (поле есть в DEFAULT_PII_FIELDS)
        assert result["email"] != "user@example.com"
        # name также анонимизирован (fake значение)
        assert result["name"] != "John"

    def test_anonymize_list(self) -> None:
        """Анонимизация списка."""
        anonymizer = PIIAnonymizer()

        records = [
            {"email": "user1@example.com"},
            {"email": "user2@example.com"},
        ]

        result = anonymizer.anonymize_list(records)

        assert len(result) == 2
        assert result[0]["email"] != "user1@example.com"
        assert result[1]["email"] != "user2@example.com"

    def test_anonymize_selective(self) -> None:
        """Выборочная анонимизация."""
        anonymizer = PIIAnonymizer()

        data = {"email": "user@example.com", "public_field": "public_value"}

        result = anonymizer.anonymize(data, fields_to_anonymize={"email"})

        assert result["email"] != "user@example.com"
        assert result["public_field"] == "public_value"

    def test_add_field(self) -> None:
        """Добавление PII поля."""
        anonymizer = PIIAnonymizer()

        anonymizer.add_field(PIIField(name="custom_field", field_type="text"))

        assert any(f.name == "custom_field" for f in anonymizer.fields)

    def test_remove_field(self) -> None:
        """Удаление PII поля."""
        anonymizer = PIIAnonymizer()

        result = anonymizer.remove_field("email")

        assert result is True
        assert not any(f.name == "email" for f in anonymizer.fields)


# =============================================================================
# Tests for DataExportService
# =============================================================================


class TestDataExportService:
    """Тесты для DataExportService."""

    def test_service_creation(self) -> None:
        """Создание сервиса."""
        service = DataExportService()

        assert service.anonymizer is not None
        assert "json" in service.SUPPORTED_FORMATS

    def test_export_unsupported_format(self) -> None:
        """Экспорт в неподдерживаемом формате."""
        service = DataExportService(data_provider=lambda x: [])

        with pytest.raises(DataExportError, match="Unsupported format"):
            service.export_data("user1", format="pdf")

    def test_export_no_provider(self) -> None:
        """Экспорт без провайдера данных."""
        service = DataExportService()

        with pytest.raises(DataExportError, match="Data provider not configured"):
            service.export_data("user1")

    def test_export_json(self) -> None:
        """Экспорт в JSON."""
        def provider(subject_id: str) -> List[Dict[str, str]]:
            return [{"id": "1", "name": "Test", "email": "test@example.com"}]

        service = DataExportService(data_provider=provider)
        result = service.export_data("user1", format="json")

        assert result["export_format"] == "json"
        assert result["record_count"] == 1
        assert "serialized" in result

    def test_export_with_anonymization(self) -> None:
        """Экспорт с анонимизацией."""
        def provider(subject_id: str) -> List[Dict[str, str]]:
            return [{"id": "1", "email": "secret@example.com"}]

        service = DataExportService(data_provider=provider)
        result = service.export_data("user1", format="json", anonymize_pii=True)

        # email должен быть анонимизирован
        assert result["data"][0]["email"] != "secret@example.com"

    def test_export_without_anonymization(self) -> None:
        """Экспорт без анонимизации."""
        def provider(subject_id: str) -> List[Dict[str, str]]:
            return [{"id": "1", "email": "test@example.com"}]

        service = DataExportService(data_provider=provider)
        result = service.export_data("user1", format="json", anonymize_pii=False)

        # email не должен измениться
        assert result["data"][0]["email"] == "test@example.com"

    def test_create_export_request(self) -> None:
        """Создание запроса на экспорт."""
        service = DataExportService()

        request = service.create_export_request("user1", format="json")

        assert request.subject_id == "user1"
        assert request.export_format == "json"
        assert request.anonymize_pii is True
        assert request.status == "pending"


# =============================================================================
# Tests for RightToErasureHandler
# =============================================================================


class TestRightToErasureHandler:
    """Тесты для RightToErasureHandler."""

    def test_handler_creation(self) -> None:
        """Создание обработчика."""
        handler = RightToErasureHandler()

        assert handler.data_locator is None
        assert handler.data_deleter is None

    def test_process_request_no_data(self) -> None:
        """Обработка запроса без данных."""
        handler = RightToErasureHandler(
            data_locator=lambda x: [],
        )

        result = handler.process_request("user1")

        assert result.status == "completed"
        assert result.deleted_count == 0

    def test_process_request_success(self) -> None:
        """Успешная обработка запроса."""
        def locator(subject_id: str) -> List[Dict[str, str]]:
            return [{"id": "1", "category": "pii", "data_type": "profile"}]

        def deleter(ids: List[str]) -> int:
            return len(ids)

        handler = RightToErasureHandler(
            data_locator=locator,
            data_deleter=deleter,
        )

        result = handler.process_request("user1")

        assert result.is_success()
        assert result.deleted_count == 1

    def test_process_request_partial(self) -> None:
        """Частичное удаление."""
        def locator(subject_id: str) -> List[Dict[str, str]]:
            return [
                {"id": "1", "category": "pii"},
                {"id": "2", "category": "pii"},
            ]

        def deleter(ids: List[str]) -> int:
            raise RuntimeError("Partial deletion error")

        handler = RightToErasureHandler(
            data_locator=locator,
            data_deleter=deleter,
        )

        result = handler.process_request("user1")

        # При ошибке удаления статус "failed" (0 удалено, есть ошибки)
        assert result.status == "failed"
        assert len(result.errors) > 0

    def test_verify_erasure(self) -> None:
        """Верификация удаления."""
        handler = RightToErasureHandler(
            data_locator=lambda x: [],
        )

        verification = handler.verify_erasure("user1")

        assert verification["subject_id"] == "user1"
        assert verification["is_complete"] is True
        assert verification["remaining_records"] == 0


# =============================================================================
# Tests for Exceptions
# =============================================================================


class TestComplianceExceptions:
    """Тесты для иерархии исключений."""

    def test_compliance_error(self) -> None:
        """Тест ComplianceError."""
        error = ComplianceError("Test error", details={"key": "value"})

        assert error.message == "Test error"
        assert error.details == {"key": "value"}
        assert "key=value" in str(error)

    def test_retention_error(self) -> None:
        """Тест RetentionError."""
        error = RetentionError(
            "Retention failed",
            policy_name="test_policy",
            data_category="pii",
        )

        assert error.policy_name == "test_policy"
        assert error.data_category == "pii"

    def test_anonymization_error(self) -> None:
        """Тест AnonymizationError."""
        error = AnonymizationError(
            "Anonymization failed",
            field_name="email",
            field_type="pii",
        )

        assert error.field_name == "email"
        assert error.field_type == "pii"

    def test_data_export_error(self) -> None:
        """Тест DataExportError."""
        error = DataExportError(
            "Export failed",
            export_format="json",
            record_count=10,
        )

        assert error.export_format == "json"
        assert error.record_count == 10

    def test_erasure_error(self) -> None:
        """Тест ErasureError."""
        error = ErasureError(
            "Erasure failed",
            data_type="pii",
            reason="legal_hold",
        )

        assert error.data_type == "pii"
        assert error.reason == "legal_hold"

    def test_exception_hierarchy(self) -> None:
        """Все исключения наследуются от ComplianceError."""
        exceptions = [
            ComplianceError("Test"),
            RetentionError("Test"),
            AnonymizationError("Test"),
            DataExportError("Test"),
            ErasureError("Test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, ComplianceError)
            assert isinstance(exc, Exception)


# =============================================================================
# Tests for Constants
# =============================================================================


class TestConstants:
    """Тесты для констант."""

    def test_default_rules(self) -> None:
        """Проверка DEFAULT_RULES."""
        assert len(DEFAULT_RULES) >= 6

        pii_rule = next((r for r in DEFAULT_RULES if r.data_category == DataCategory.PII), None)
        assert pii_rule is not None
        assert pii_rule.retention_days == 365

    def test_default_pii_fields(self) -> None:
        """Проверка DEFAULT_PII_FIELDS."""
        assert len(DEFAULT_PII_FIELDS) >= 10

        email_field = next((f for f in DEFAULT_PII_FIELDS if f.name == "email"), None)
        assert email_field is not None
        assert email_field.anonymization_method == "hash"

    def test_denial_reasons(self) -> None:
        """Проверка DENIAL_REASONS."""
        assert "legal_obligation" in DENIAL_REASONS
        assert "public_interest" in DENIAL_REASONS