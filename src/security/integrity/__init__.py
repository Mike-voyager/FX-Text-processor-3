"""
Модуль проверки целостности приложения.

Обеспечивает Zero Trust проверку целостности:
- AppIntegrityChecker: проверка хеша бинарника приложения
- ConfigIntegrityChecker: проверка подписи конфигурации

Security:
    - SHA3-256 для хеширования
    - Ed25519 для подписи конфигурации
    - Только чтение, никаких модификаций

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from src.security.integrity.app_integrity import AppIntegrityChecker
from src.security.integrity.config_integrity import ConfigIntegrityChecker
from src.security.integrity.exceptions import (
    ConfigSignatureError,
    IntegrityCheckError,
    IntegrityError,
)
from src.security.integrity.models import (
    ConfigSignatureResult,
    IntegrityCheckResult,
)

__all__: list[str] = [
    # Exceptions
    "IntegrityError",
    "IntegrityCheckError",
    "ConfigSignatureError",
    # Models
    "IntegrityCheckResult",
    "ConfigSignatureResult",
    # Checkers
    "AppIntegrityChecker",
    "ConfigIntegrityChecker",
]

__version__ = "1.0.0"
__author__ = "FX Text Processor Team"
__date__ = "2026-03-23"
