"""
Обработчик запросов на удаление данных (GDPR Art. 17 - Right to erasure).

RightToErasureHandler управляет процессом удаления данных:
- Проверка права на удаление
- Идентификация данных для удаления
- Безопасное удаление с аудитом

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from src.security.compliance.exceptions import ErasureError
from src.security.compliance.models import DataCategory, ErasureRequest

if TYPE_CHECKING:
    from src.security.audit import AuditLog

LOG = logging.getLogger(__name__)

# Причины для отказа в удалении (GDPR Art. 17(3))
DENIAL_REASONS: Dict[str, str] = {
    "legal_obligation": "Data required for legal obligation",
    "public_interest": "Data required for public interest",
    "legal_claim": "Data required for legal claim defense",
    "contract": "Data required for contract performance",
    "consent_revoked": "Consent was not the basis for processing",
}


@dataclass
class ErasureResult:
    """
    Результат операции удаления.

    Attributes:
        request_id: ID запроса на удаление
        subject_id: ID субъекта данных
        status: Статус (completed, partial, denied, failed)
        deleted_count: Количество удалённых записей
        denied_reasons: Причины отказа
        errors: Ошибки при удалении
        completed_at: Время завершения
    """

    request_id: str
    subject_id: str
    status: str  # completed, partial, denied, failed
    deleted_count: int = 0
    denied_reasons: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_success(self) -> bool:
        """Успешное удаление."""
        return self.status in ("completed", "partial")


@dataclass
class RightToErasureHandler:
    """
    Обработчик запросов на удаление данных (GDPR Art. 17).

    Управляет процессом удаления персональных данных.

    Attributes:
        data_locator: Функция для поиска данных субъекта
        data_deleter: Функция для удаления данных
        secure_eraser: Опциональный SecureEraser для безопасного удаления
        audit_log: Опциональный AuditLog для логирования
        allowed_categories: Категории данных, которые можно удалять
        protected_data: Типы данных, защищённые от удаления

    Example:
        >>> def find_data(user_id: str) -> List[Dict]:
        ...     return db.query("SELECT * FROM data WHERE user_id = ?", user_id)
        >>>
        >>> def delete_data(data_ids: List[str]) -> int:
        ...     return db.execute("DELETE FROM data WHERE id IN (?)", data_ids)
        >>>
        >>> handler = RightToErasureHandler(
        ...     data_locator=find_data,
        ...     data_deleter=delete_data,
        ... )
        >>> result = handler.process_request(user_id, reason="User request")
    """

    data_locator: Optional[Callable[[str], List[Dict[str, Any]]]] = None
    data_deleter: Optional[Callable[[List[str]], int]] = None
    audit_log: Optional["AuditLog"] = None

    # Категории, которые можно удалять без проверки
    allowed_categories: List[DataCategory] = field(
        default_factory=lambda: [
            DataCategory.PII,
            DataCategory.INTERNAL,
        ]
    )

    # Категории, требующие особой проверки
    protected_categories: List[DataCategory] = field(
        default_factory=lambda: [
            DataCategory.FINANCIAL,
            DataCategory.CREDENTIALS,
        ]
    )

    # Типы данных, которые нельзя удалять
    protected_data_types: List[str] = field(
        default_factory=lambda: [
            "audit_log",
            "legal_records",
            "financial_records",
        ]
    )

    def process_request(
        self,
        subject_id: str,
        reason: str = "Data subject request",
        *,
        data_types: Optional[List[str]] = None,
        force: bool = False,
    ) -> ErasureResult:
        """
        Обработать запрос на удаление данных.

        Args:
            subject_id: Идентификатор субъекта данных
            reason: Причина удаления
            data_types: Типы данных для удаления (опционально)
            force: Принудительное удаление (игнорировать проверки)

        Returns:
            ErasureResult с результатом операции

        Raises:
            ErasureError: Критическая ошибка удаления
        """
        # Создаём запрос
        request = self._create_request(subject_id, reason, data_types)

        # Логируем начало обработки
        self._log_request_start(request)

        try:
            # 1. Находим данные субъекта
            data_records = self._locate_data(subject_id)

            if not data_records:
                return ErasureResult(
                    request_id=request.request_id,
                    subject_id=subject_id,
                    status="completed",
                    deleted_count=0,
                    denied_reasons=["No data found for subject"],
                )

            # 2. Фильтруем по типам данных если указано
            if data_types:
                data_records = [
                    r for r in data_records
                    if r.get("data_type") in data_types
                ]

            # 3. Проверяем возможность удаления
            if not force:
                can_delete, denied_reasons = self._check_deletion_allowed(data_records)
                if not can_delete:
                    return ErasureResult(
                        request_id=request.request_id,
                        subject_id=subject_id,
                        status="denied",
                        denied_reasons=denied_reasons,
                    )

            # 4. Удаляем данные
            deleted_count, errors = self._delete_data(data_records)

            # 5. Определяем статус
            if errors:
                status = "partial" if deleted_count > 0 else "failed"
            else:
                status = "completed"

            result = ErasureResult(
                request_id=request.request_id,
                subject_id=subject_id,
                status=status,
                deleted_count=deleted_count,
                errors=errors,
            )

            # 6. Логируем завершение
            self._log_request_complete(request, result)

            return result

        except Exception as e:
            LOG.error("Erasure request failed: %s", e)
            self._log_request_error(request, str(e))

            return ErasureResult(
                request_id=request.request_id,
                subject_id=subject_id,
                status="failed",
                errors=[str(e)],
            )

    def _create_request(
        self,
        subject_id: str,
        reason: str,
        data_types: Optional[List[str]],
    ) -> ErasureRequest:
        """Создать запрос на удаление."""
        return ErasureRequest(
            request_id=str(uuid.uuid4()),
            subject_id=subject_id,
            reason=reason,
            data_types=data_types or [],
            status="processing",
        )

    def _locate_data(self, subject_id: str) -> List[Dict[str, Any]]:
        """Найти данные субъекта."""
        if not self.data_locator:
            raise ErasureError("Data locator not configured")

        return self.data_locator(subject_id)

    def _check_deletion_allowed(
        self,
        data_records: List[Dict[str, Any]],
    ) -> tuple[bool, List[str]]:
        """
        Проверить возможность удаления данных.

        Returns:
            (allowed, reasons) - можно ли удалять и причины отказа
        """
        denied_reasons: List[str] = []

        for record in data_records:
            # Проверяем тип данных
            data_type = record.get("data_type", "")
            if data_type in self.protected_data_types:
                denied_reasons.append(f"Protected data type: {data_type}")

            # Проверяем категорию
            category_str = record.get("category", "internal")
            try:
                category = DataCategory(category_str)
                if category in self.protected_categories:
                    # Для защищённых категорий нужна дополнительная проверка
                    legal_hold = record.get("legal_hold", False)
                    if legal_hold:
                        denied_reasons.append(f"Legal hold on {category.value} data")
            except ValueError:
                pass

        return len(denied_reasons) == 0, denied_reasons

    def _delete_data(
        self,
        data_records: List[Dict[str, Any]],
    ) -> tuple[int, List[str]]:
        """
        Удалить данные.

        Returns:
            (deleted_count, errors) - количество удалённых и список ошибок
        """
        if not self.data_deleter:
            raise ErasureError("Data deleter not configured")

        errors: List[str] = []
        deleted_count = 0

        # Извлекаем ID записей
        record_ids: List[str] = [
            str(r.get("id")) for r in data_records if r.get("id") is not None
        ]

        if not record_ids:
            return 0, ["No record IDs found"]

        try:
            deleted_count = self.data_deleter(record_ids)
            LOG.info("Deleted %d records", deleted_count)

        except Exception as e:
            errors.append(f"Deletion failed: {e}")
            LOG.error("Failed to delete records: %s", e)

        # Выполняем безопасное удаление файлов
        for record in data_records:
            file_path = record.get("file_path")
            if file_path:
                try:
                    from src.security.erasure import wipe_file
                    wipe_file(Path(file_path))
                except Exception as e:
                    errors.append(f"Failed to wipe {file_path}: {e}")

        return deleted_count, errors

    def _log_request_start(self, request: ErasureRequest) -> None:
        """Логировать начало обработки запроса."""
        if not self.audit_log:
            return

        try:
            from src.security.audit import AuditEventType

            self.audit_log.log_event(
                AuditEventType.FORM_HISTORY_ENTRY_ADDED,
                details={
                    "action": "erasure_request_started",
                    "request_id": request.request_id,
                    "subject_id": request.subject_id,
                    "reason": request.reason,
                },
            )

        except Exception as e:
            LOG.warning("Failed to log erasure request start: %s", e)

    def _log_request_complete(
        self,
        request: ErasureRequest,
        result: ErasureResult,
    ) -> None:
        """Логировать завершение обработки запроса."""
        if not self.audit_log:
            return

        try:
            from src.security.audit import AuditEventType

            self.audit_log.log_event(
                AuditEventType.FORM_HISTORY_CLEARED,
                details={
                    "action": "erasure_request_completed",
                    "request_id": request.request_id,
                    "subject_id": request.subject_id,
                    "status": result.status,
                    "deleted_count": result.deleted_count,
                },
            )

        except Exception as e:
            LOG.warning("Failed to log erasure request completion: %s", e)

    def _log_request_error(self, request: ErasureRequest, error: str) -> None:
        """Логировать ошибку обработки запроса."""
        if not self.audit_log:
            return

        try:
            from src.security.audit import AuditEventType

            self.audit_log.log_event(
                AuditEventType.FORM_HISTORY_INTEGRITY_FAILED,
                details={
                    "action": "erasure_request_failed",
                    "request_id": request.request_id,
                    "subject_id": request.subject_id,
                    "error": error,
                },
            )

        except Exception as e:
            LOG.warning("Failed to log erasure request error: %s", e)

    def verify_erasure(self, subject_id: str) -> Dict[str, Any]:
        """
        Верифицировать удаление данных.

        Args:
            subject_id: Идентификатор субъекта

        Returns:
            Словарь с результатами верификации
        """
        result: Dict[str, Any] = {
            "subject_id": subject_id,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "remaining_records": 0,
            "remaining_categories": [],
            "is_complete": True,
        }

        if self.data_locator:
            remaining = self.data_locator(subject_id)
            result["remaining_records"] = len(remaining)

            if remaining:
                result["is_complete"] = False
                result["remaining_categories"] = list(set(
                    r.get("category", "unknown") for r in remaining
                ))

        return result


__all__: list[str] = [
    "RightToErasureHandler",
    "ErasureResult",
    "DENIAL_REASONS",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"