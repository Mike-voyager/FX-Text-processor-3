"""
Модуль compliance (GDPR).

Обеспечивает соответствие требованиям GDPR:
- Управление политиками хранения данных
- Анонимизация PII
- Экспорт данных (Right to data portability)
- Удаление данных (Right to erasure)

Components:
    - RetentionPolicyManager: Управление политиками хранения
    - PIIAnonymizer: Анонимизация персональных данных
    - DataExportService: Экспорт данных субъекта
    - RightToErasureHandler: Обработка запросов на удаление

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from src.security.compliance.anonymization import DEFAULT_PII_FIELDS, PIIAnonymizer
from src.security.compliance.data_export import DataExportService
from src.security.compliance.erasure_handler import (
    DENIAL_REASONS,
    ErasureResult,
    RightToErasureHandler,
)
from src.security.compliance.exceptions import (
    AnonymizationError,
    ComplianceError,
    DataExportError,
    ErasureError,
    RetentionError,
)
from src.security.compliance.models import (
    DataCategory,
    DataExportRequest,
    DataSubjectRecord,
    ErasureRequest,
    PIIField,
    RetentionAction,
    RetentionPolicy,
    RetentionRule,
)
from src.security.compliance.retention_policy import (
    DEFAULT_RULES,
    RetentionPolicyManager,
)

__all__: list[str] = [
    # Exceptions
    "ComplianceError",
    "RetentionError",
    "AnonymizationError",
    "DataExportError",
    "ErasureError",
    # Models
    "DataCategory",
    "RetentionAction",
    "RetentionRule",
    "RetentionPolicy",
    "PIIField",
    "DataSubjectRecord",
    "DataExportRequest",
    "ErasureRequest",
    # Services
    "RetentionPolicyManager",
    "PIIAnonymizer",
    "DataExportService",
    "RightToErasureHandler",
    "ErasureResult",
    # Constants
    "DEFAULT_RULES",
    "DEFAULT_PII_FIELDS",
    "DENIAL_REASONS",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"