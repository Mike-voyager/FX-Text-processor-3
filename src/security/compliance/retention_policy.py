"""
Управление политиками хранения данных.

RetentionPolicyManager управляет жизненным циклом данных:
- Применение правил хранения
- Выявление истёкших данных
- Планирование действий по удалению/анонимизации

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from src.security.compliance.exceptions import RetentionError
from src.security.compliance.models import (
    DataCategory,
    RetentionAction,
    RetentionPolicy,
    RetentionRule,
)

if TYPE_CHECKING:
    from src.security.audit import AuditLog, AuditEventType

LOG = logging.getLogger(__name__)


# Предопределённые правила хранения
DEFAULT_RULES: List[RetentionRule] = [
    RetentionRule(
        name="pii_standard",
        data_category=DataCategory.PII,
        retention_days=365,
        action=RetentionAction.ANONYMIZE,
        legal_basis="GDPR Art. 6(1)(b) - Contract performance",
        description="Personal data retained for 1 year",
    ),
    RetentionRule(
        name="sensitive_limited",
        data_category=DataCategory.SENSITIVE,
        retention_days=90,
        action=RetentionAction.DELETE,
        legal_basis="GDPR Art. 9(2)(a) - Explicit consent",
        description="Sensitive data deleted after 90 days",
    ),
    RetentionRule(
        name="financial_legal",
        data_category=DataCategory.FINANCIAL,
        retention_days=2555,  # 7 лет
        action=RetentionAction.ARCHIVE,
        legal_basis="Legal requirement - Tax records",
        description="Financial data archived after 7 years",
    ),
    RetentionRule(
        name="credentials_security",
        data_category=DataCategory.CREDENTIALS,
        retention_days=365,
        action=RetentionAction.DELETE,
        legal_basis="Security best practice",
        description="Credentials retained for 1 year then deleted",
    ),
    RetentionRule(
        name="internal_logs",
        data_category=DataCategory.INTERNAL,
        retention_days=90,
        action=RetentionAction.DELETE,
        legal_basis="GDPR Art. 6(1)(f) - Legitimate interest",
        description="Internal logs deleted after 90 days",
    ),
    RetentionRule(
        name="public_unlimited",
        data_category=DataCategory.PUBLIC,
        retention_days=3650,  # 10 лет
        action=RetentionAction.REVIEW,
        legal_basis="N/A - Public data",
        description="Public data reviewed after 10 years",
    ),
]


@dataclass
class RetentionPolicyManager:
    """
    Менеджер политик хранения данных.

    Управляет жизненным циклом данных в соответствии с GDPR.

    Attributes:
        policy: Активная политика хранения
        audit_log: Опциональный AuditLog для логирования
        storage_path: Путь к хранилищу данных (для persistence)

    Example:
        >>> manager = RetentionPolicyManager()
        >>> expired = manager.find_expired_records(records)
        >>> for record in expired:
        ...     action = manager.get_action(record)
        ...     print(f"{record.id}: {action}")
    """

    policy: RetentionPolicy = field(default_factory=lambda: RetentionPolicy(name="default", rules=DEFAULT_RULES))
    audit_log: Optional["AuditLog"] = None
    storage_path: Optional[Path] = None

    def get_rule(self, data_category: DataCategory) -> RetentionRule:
        """
        Получить правило хранения для категории данных.

        Args:
            data_category: Категория данных

        Returns:
            Применимое правило хранения
        """
        return self.policy.get_rule(data_category)

    def find_expired_records(
        self,
        records: List[Dict[str, Any]],
        category_field: str = "category",
        created_field: str = "created_at",
    ) -> List[Dict[str, Any]]:
        """
        Найти записи с истёкшим сроком хранения.

        Args:
            records: Список записей
            category_field: Поле с категорией данных
            created_field: Поле с датой создания

        Returns:
            Список истёкших записей
        """
        expired: List[Dict[str, Any]] = []

        for record in records:
            try:
                category_value = record.get(category_field)
                if not category_value:
                    continue

                category = DataCategory(category_value)
                rule = self.get_rule(category)

                created_at_str = record.get(created_field)
                if not created_at_str:
                    continue

                created_at = self._parse_datetime(created_at_str)

                if rule.is_expired(created_at):
                    expired.append(record)

            except (ValueError, KeyError):
                LOG.debug("Skipping record with invalid category: %s", record.get("id"))
                continue

        return expired

    def get_action(self, record: Dict[str, Any]) -> RetentionAction:
        """
        Получить действие для записи.

        Args:
            record: Запись данных

        Returns:
            Действие при истечении срока
        """
        category_value = record.get("category")
        if not category_value:
            return RetentionAction.DELETE

        try:
            category = DataCategory(category_value)
            rule = self.get_rule(category)
            return rule.action
        except ValueError:
            return RetentionAction.DELETE

    def apply_retention(
        self,
        records: List[Dict[str, Any]],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Применить политику хранения к записям.

        Args:
            records: Список записей
            dry_run: Только симуляция (без реальных действий)

        Returns:
            Отчёт о применённой политике
        """
        result: Dict[str, Any] = {
            "total_records": len(records),
            "expired_count": 0,
            "actions": {
                "deleted": 0,
                "anonymized": 0,
                "archived": 0,
                "reviewed": 0,
            },
            "errors": [],
            "dry_run": dry_run,
        }

        expired = self.find_expired_records(records)
        result["expired_count"] = len(expired)

        for record in expired:
            action = self.get_action(record)
            record_id = record.get("id", "unknown")

            try:
                if dry_run:
                    LOG.info("[DRY RUN] Would apply %s to record %s", action.value, record_id)
                else:
                    self._apply_action(record, action)

                result["actions"][action.value] += 1

            except Exception as e:
                LOG.error("Failed to apply %s to record %s: %s", action.value, record_id, e)
                result["errors"].append({
                    "record_id": record_id,
                    "action": action.value,
                    "error": str(e),
                })

        # Логируем в audit
        self._log_retention_action(result)

        return result

    def _apply_action(self, record: Dict[str, Any], action: RetentionAction) -> None:
        """
        Применить действие к записи.

        Args:
            record: Запись данных
            action: Действие

        Raises:
            RetentionError: Ошибка применения действия
        """
        record_id = record.get("id", "unknown")

        if action == RetentionAction.DELETE:
            LOG.info("Deleting record: %s", record_id)
            # Реальное удаление выполняется вызывающим кодом
            # Здесь только логирование

        elif action == RetentionAction.ANONYMIZE:
            LOG.info("Anonymizing record: %s", record_id)
            # Анонимизация выполняется PIIAnonymizer

        elif action == RetentionAction.ARCHIVE:
            LOG.info("Archiving record: %s", record_id)
            # Архивация выполняется вызывающим кодом

        elif action == RetentionAction.REVIEW:
            LOG.info("Marking record for review: %s", record_id)
            # Отметка для ручной проверки

    def _parse_datetime(self, value: str) -> datetime:
        """Парсинг даты/времени."""
        if isinstance(value, datetime):
            return value

        # ISO format
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass

        # Fallback: текущее время
        LOG.warning("Could not parse datetime: %s", value)
        return datetime.now(timezone.utc)

    def _log_retention_action(self, result: Dict[str, Any]) -> None:
        """Логировать действие хранения в audit."""
        if not self.audit_log:
            return

        try:
            from src.security.audit import AuditEventType

            # Определяем тип события
            event_type = AuditEventType.FORM_HISTORY_RETENTION_ENFORCED

            self.audit_log.log_event(
                event_type,
                details={
                    "total_records": result["total_records"],
                    "expired_count": result["expired_count"],
                    "actions": result["actions"],
                    "dry_run": result["dry_run"],
                    "errors_count": len(result["errors"]),
                },
            )

        except Exception as e:
            LOG.warning("Failed to log retention action: %s", e)

    def save_policy(self, path: Path) -> None:
        """
        Сохранить политику в файл.

        Args:
            path: Путь к файлу
        """
        try:
            data = self.policy.to_dict()
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            LOG.info("Policy saved to: %s", path)
        except Exception as e:
            raise RetentionError(
                f"Failed to save policy: {e}",
                policy_name=self.policy.name,
            ) from e

    def load_policy(self, path: Path) -> None:
        """
        Загрузить политику из файла.

        Args:
            path: Путь к файлу
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))

            rules = []
            for rule_data in data.get("rules", []):
                rule = RetentionRule(
                    name=rule_data["name"],
                    data_category=DataCategory(rule_data["data_category"]),
                    retention_days=rule_data["retention_days"],
                    action=RetentionAction(rule_data.get("action", "delete")),
                    legal_basis=rule_data.get("legal_basis", ""),
                    description=rule_data.get("description", ""),
                )
                rules.append(rule)

            default_rule = None
            if data.get("default_rule"):
                dr = data["default_rule"]
                default_rule = RetentionRule(
                    name=dr["name"],
                    data_category=DataCategory(dr["data_category"]),
                    retention_days=dr["retention_days"],
                    action=RetentionAction(dr.get("action", "delete")),
                )

            created_at: datetime
            if data.get("created_at"):
                created_at = datetime.fromisoformat(data["created_at"])
            else:
                created_at = datetime.now(timezone.utc)

            self.policy = RetentionPolicy(
                name=data["name"],
                version=data.get("version", "1.0"),
                rules=rules,
                default_rule=default_rule,
                created_at=created_at,
            )

            LOG.info("Policy loaded from: %s", path)

        except Exception as e:
            raise RetentionError(
                f"Failed to load policy: {e}",
                policy_name=path.stem,
            ) from e


__all__: list[str] = [
    "RetentionPolicyManager",
    "DEFAULT_RULES",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"