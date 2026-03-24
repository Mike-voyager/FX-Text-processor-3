"""
Исключения модуля compliance.

Иерархия:
    ComplianceError (базовое)
    ├── RetentionError
    ├── AnonymizationError
    ├── DataExportError
    └── ErasureError

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class ComplianceError(Exception):
    """
    Базовое исключение для ошибок compliance.

    Attributes:
        message: Описание ошибки
        details: Дополнительные детали
    """

    def __init__(
        self,
        message: str,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        parts = [self.message]
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            parts.append(f" ({detail_str})")
        return "".join(parts)


class RetentionError(ComplianceError):
    """Ошибка при применении политики хранения."""

    def __init__(
        self,
        message: str = "Retention policy error",
        *,
        policy_name: Optional[str] = None,
        data_category: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if policy_name:
            det["policy_name"] = policy_name
        if data_category:
            det["data_category"] = data_category
        super().__init__(message, details=det)
        self.policy_name = policy_name
        self.data_category = data_category


class AnonymizationError(ComplianceError):
    """Ошибка при анонимизации PII."""

    def __init__(
        self,
        message: str = "Anonymization error",
        *,
        field_name: Optional[str] = None,
        field_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if field_name:
            det["field_name"] = field_name
        if field_type:
            det["field_type"] = field_type
        super().__init__(message, details=det)
        self.field_name = field_name
        self.field_type = field_type


class DataExportError(ComplianceError):
    """Ошибка при экспорте данных."""

    def __init__(
        self,
        message: str = "Data export error",
        *,
        export_format: Optional[str] = None,
        record_count: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if export_format:
            det["export_format"] = export_format
        if record_count is not None:
            det["record_count"] = record_count
        super().__init__(message, details=det)
        self.export_format = export_format
        self.record_count = record_count


class ErasureError(ComplianceError):
    """Ошибка при удалении данных (right to erasure)."""

    def __init__(
        self,
        message: str = "Erasure error",
        *,
        data_type: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if data_type:
            det["data_type"] = data_type
        if reason:
            det["reason"] = reason
        super().__init__(message, details=det)
        self.data_type = data_type
        self.reason = reason


__all__: list[str] = [
    "ComplianceError",
    "RetentionError",
    "AnonymizationError",
    "DataExportError",
    "ErasureError",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"