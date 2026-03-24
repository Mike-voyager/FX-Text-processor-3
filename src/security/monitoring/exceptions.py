"""
Исключения модуля мониторинга.

Иерархия:
    HealthCheckError (базовое)
    ├── EntropyCheckError
    ├── KeystoreCheckError
    ├── DeviceCheckError
    ├── AlgorithmCheckError
    └── AuditChainCheckError

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class HealthCheckError(Exception):
    """
    Базовое исключение для ошибок health check.

    Attributes:
        check_name: Имя проверки
        message: Описание ошибки
        details: Дополнительные детали
    """

    def __init__(
        self,
        check_name: str,
        message: str,
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.check_name = check_name
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        parts = [f"[{self.check_name}] ", self.message]
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            parts.append(f" ({detail_str})")
        return "".join(parts)


class EntropyCheckError(HealthCheckError):
    """Ошибка проверки энтропии."""

    def __init__(
        self,
        message: str = "Entropy check failed",
        *,
        available_bits: Optional[int] = None,
        required_bits: int = 256,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if available_bits is not None:
            det["available_bits"] = available_bits
        det["required_bits"] = required_bits
        super().__init__("entropy", message, details=det)
        self.available_bits = available_bits
        self.required_bits = required_bits


class KeystoreCheckError(HealthCheckError):
    """Ошибка проверки keystore."""

    def __init__(
        self,
        message: str = "Keystore check failed",
        *,
        keystore_path: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if keystore_path:
            det["keystore_path"] = keystore_path
        super().__init__("keystore", message, details=det)
        self.keystore_path = keystore_path


class DeviceCheckError(HealthCheckError):
    """Ошибка проверки аппаратного устройства."""

    def __init__(
        self,
        message: str = "Device check failed",
        *,
        device_type: Optional[str] = None,
        device_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if device_type:
            det["device_type"] = device_type
        if device_id:
            det["device_id"] = device_id
        super().__init__("device", message, details=det)
        self.device_type = device_type
        self.device_id = device_id


class AlgorithmCheckError(HealthCheckError):
    """Ошибка проверки криптографического алгоритма."""

    def __init__(
        self,
        message: str = "Algorithm check failed",
        *,
        algorithm: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if algorithm:
            det["algorithm"] = algorithm
        if reason:
            det["reason"] = reason
        super().__init__("algorithm", message, details=det)
        self.algorithm = algorithm
        self.reason = reason


class AuditChainCheckError(HealthCheckError):
    """Ошибка проверки целостности audit log."""

    def __init__(
        self,
        message: str = "Audit chain check failed",
        *,
        event_count: Optional[int] = None,
        failed_at_event: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if event_count is not None:
            det["event_count"] = event_count
        if failed_at_event:
            det["failed_at_event"] = failed_at_event
        super().__init__("audit_chain", message, details=det)
        self.event_count = event_count
        self.failed_at_event = failed_at_event


class ConfigCheckError(HealthCheckError):
    """Ошибка проверки конфигурации."""

    def __init__(
        self,
        message: str = "Config check failed",
        *,
        config_path: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        det = details or {}
        if config_path:
            det["config_path"] = config_path
        super().__init__("config", message, details=det)
        self.config_path = config_path


__all__: list[str] = [
    "HealthCheckError",
    "EntropyCheckError",
    "KeystoreCheckError",
    "DeviceCheckError",
    "AlgorithmCheckError",
    "AuditChainCheckError",
    "ConfigCheckError",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"