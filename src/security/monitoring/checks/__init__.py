"""
Модуль индивидуальных health checks.

Каждая проверка реализует протокол HealthCheck.

Checks:
    - EntropyCheck: Проверка доступности энтропии /dev/random
    - KeystoreCheck: Проверка состояния keystore
    - DeviceCheck: Проверка аппаратных устройств
    - AlgorithmCheck: Проверка криптографических алгоритмов
    - AuditChainCheck: Проверка целостности audit log
    - ConfigCheck: Проверка подписи конфигурации

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from src.security.monitoring.checks.algorithm_check import AlgorithmCheck
from src.security.monitoring.checks.audit_chain_check import AuditChainCheck
from src.security.monitoring.checks.config_check import ConfigCheck
from src.security.monitoring.checks.device_check import DeviceCheck
from src.security.monitoring.checks.entropy_check import EntropyCheck
from src.security.monitoring.checks.keystore_check import KeystoreCheck

__all__: list[str] = [
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