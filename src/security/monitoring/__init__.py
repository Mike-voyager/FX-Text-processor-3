"""
Модуль мониторинга и health checks.

Обеспечивает проверку состояния системы при запуске:
- Проверка энтропии /dev/random
- Проверка keystore
- Проверка аппаратных устройств
- Проверка криптографических алгоритмов
- Проверка целостности audit log
- Проверка подписи конфигурации

Security:
    - Все проверки выполняются без раскрытия секретов
    - Результаты логируются в audit
    - Критические ошибки блокируют запуск

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from src.security.monitoring.checks import (
    AlgorithmCheck,
    AuditChainCheck,
    ConfigCheck,
    DeviceCheck,
    EntropyCheck,
    KeystoreCheck,
)
from src.security.monitoring.exceptions import (
    AlgorithmCheckError,
    AuditChainCheckError,
    ConfigCheckError,
    DeviceCheckError,
    EntropyCheckError,
    HealthCheckError,
    KeystoreCheckError,
)
from src.security.monitoring.health_checker import HealthChecker, HealthCheck
from src.security.monitoring.models import (
    HealthCheckReport,
    HealthCheckResult,
    HealthCheckStatus,
)

__all__: list[str] = [
    # Exceptions
    "HealthCheckError",
    "EntropyCheckError",
    "KeystoreCheckError",
    "DeviceCheckError",
    "AlgorithmCheckError",
    "AuditChainCheckError",
    "ConfigCheckError",
    # Models
    "HealthCheckStatus",
    "HealthCheckResult",
    "HealthCheckReport",
    # Checker
    "HealthChecker",
    "HealthCheck",
    # Checks
    "EntropyCheck",
    "KeystoreCheck",
    "DeviceCheck",
    "AlgorithmCheck",
    "AuditChainCheck",
    "ConfigCheck",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"