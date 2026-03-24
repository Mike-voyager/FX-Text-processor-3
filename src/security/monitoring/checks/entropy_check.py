"""
Entropy Check — проверка доступности энтропии системы.

Проверяет:
- Доступность /dev/random (Linux)
- Доступность CryptGenRandom (Windows)
- Уровень энтропии (если доступен)

Security:
- Не раскрывает содержимое энтропии
- Логирует только метрики

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import os
import platform
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.security.monitoring.exceptions import EntropyCheckError
from src.security.monitoring.models import HealthCheckResult, HealthCheckStatus

LOG = logging.getLogger(__name__)

# Минимальный уровень энтропии (биты) для HEALTHY
MIN_ENTROPY_BITS = 256

# Минимальный уровень энтропии (биты) для DEGRADED
MIN_ENTROPY_BITS_DEGRADED = 128


@dataclass
class EntropyCheck:
    """
    Проверка доступности системной энтропии.

    Критическая проверка для криптографических операций.

    Attributes:
        name: Имя проверки (фиксированное: "entropy")
        description: Описание проверки
        critical: Всегда True (критическая проверка)
        min_bits: Минимальный уровень энтропии для HEALTHY

    Platform Support:
        - Linux: /dev/random, /proc/sys/kernel/random/entropy_avail
        - Windows: CryptGenRandom (всегда доступен)
        - macOS: /dev/random (всегда доступен)

    Example:
        >>> check = EntropyCheck()
        >>> result = check.check()
        >>> if result.is_healthy:
        ...     print("Entropy OK")
    """

    name: str = "entropy"
    description: str = "System entropy availability check"
    critical: bool = True
    min_bits: int = MIN_ENTROPY_BITS

    def check(self) -> HealthCheckResult:
        """
        Выполнить проверку энтропии.

        Returns:
            HealthCheckResult с результатом проверки
        """
        start_ms = time.monotonic()

        try:
            system = platform.system()

            if system == "Linux":
                result = self._check_linux_entropy()
            elif system == "Windows":
                result = self._check_windows_entropy()
            elif system == "Darwin":
                result = self._check_macos_entropy()
            else:
                result = self._check_generic_entropy()

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            # Обновляем duration
            details = result.details.copy()
            details["duration_ms"] = elapsed_ms

            return HealthCheckResult(
                check_name=result.check_name,
                status=result.status,
                message=result.message,
                duration_ms=elapsed_ms,
                details=details,
                warnings=result.warnings,
                error=result.error,
            )

        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Entropy check failed: %s", e)
            return HealthCheckResult.error_result(
                check_name=self.name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _check_linux_entropy(self) -> HealthCheckResult:
        """
        Проверка энтропии на Linux.

        Проверяет:
        1. Доступность /dev/random
        2. Уровень энтропии из /proc/sys/kernel/random/entropy_avail

        Returns:
            Результат проверки
        """
        details: Dict[str, Any] = {
            "platform": "Linux",
            "device": "/dev/random",
        }

        # Проверяем доступность /dev/random
        random_path = "/dev/random"
        if not os.path.exists(random_path):
            raise EntropyCheckError(
                message="/dev/random not found",
                available_bits=0,
                required_bits=self.min_bits,
            )

        if not os.access(random_path, os.R_OK):
            raise EntropyCheckError(
                message="/dev/random not readable",
                available_bits=0,
                required_bits=self.min_bits,
            )

        details["device_accessible"] = True

        # Пытаемся получить уровень энтропии
        entropy_avail_path = "/proc/sys/kernel/random/entropy_avail"
        entropy_bits = 0

        try:
            with open(entropy_avail_path, "r") as f:
                entropy_bits = int(f.read().strip())
            details["entropy_bits"] = entropy_bits
            details["entropy_source"] = "proc"
        except (FileNotFoundError, PermissionError, ValueError) as e:
            LOG.debug("Could not read entropy_avail: %s", e)
            details["entropy_source"] = "unavailable"

        # Определяем статус
        if entropy_bits >= self.min_bits:
            status = HealthCheckStatus.HEALTHY
            message = f"Entropy available: {entropy_bits} bits"
        elif entropy_bits >= MIN_ENTROPY_BITS_DEGRADED:
            status = HealthCheckStatus.DEGRADED
            message = f"Entropy low: {entropy_bits} bits (minimum: {self.min_bits})"
        elif entropy_bits > 0:
            status = HealthCheckStatus.UNHEALTHY
            message = f"Entropy critical: {entropy_bits} bits"
        else:
            # Если не удалось прочитать entropy_avail, но /dev/random доступен
            # Считаем что энтропия есть (современные ядра гарантируют это)
            status = HealthCheckStatus.DEGRADED
            message = "/dev/random accessible, entropy level unknown"
            details["entropy_bits"] = None

        return HealthCheckResult(
            check_name=self.name,
            status=status,
            message=message,
            details=details,
        )

    def _check_windows_entropy(self) -> HealthCheckResult:
        """
        Проверка энтропии на Windows.

        Windows использует CryptGenRandom / BCryptGenRandom,
        который всегда доступен на современных системах.

        Returns:
            Результат проверки (всегда HEALTHY на Windows)
        """
        details: Dict[str, Any] = {
            "platform": "Windows",
            "provider": "CryptGenRandom/BCryptGenRandom",
            "entropy_source": "system_csp",
        }

        # На Windows криптографически стойкий CSP всегда доступен
        # Проверяем только что система поддерживает криптографию
        try:
            import secrets

            # Пробуем получить случайные байты
            _ = secrets.token_bytes(32)
            details["test_passed"] = True

            return HealthCheckResult(
                check_name=self.name,
                status=HealthCheckStatus.HEALTHY,
                message="Windows CSP entropy available",
                details=details,
            )

        except Exception as e:
            LOG.warning("Windows entropy check failed: %s", e)
            details["test_passed"] = False

            return HealthCheckResult(
                check_name=self.name,
                status=HealthCheckStatus.UNHEALTHY,
                message=f"Windows CSP unavailable: {e}",
                details=details,
            )

    def _check_macos_entropy(self) -> HealthCheckResult:
        """
        Проверка энтропии на macOS.

        macOS использует /dev/random, который всегда доступен.

        Returns:
            Результат проверки (всегда HEALTHY на macOS)
        """
        details: Dict[str, Any] = {
            "platform": "Darwin",
            "device": "/dev/random",
            "entropy_source": "kernel",
        }

        random_path = "/dev/random"

        if not os.path.exists(random_path):
            raise EntropyCheckError(
                message="/dev/random not found",
                available_bits=0,
                required_bits=self.min_bits,
            )

        if not os.access(random_path, os.R_OK):
            raise EntropyCheckError(
                message="/dev/random not readable",
                available_bits=0,
                required_bits=self.min_bits,
            )

        details["device_accessible"] = True

        return HealthCheckResult(
            check_name=self.name,
            status=HealthCheckStatus.HEALTHY,
            message="macOS /dev/random available",
            details=details,
        )

    def _check_generic_entropy(self) -> HealthCheckResult:
        """
        Проверка энтропии на неизвестной платформе.

        Пытается использовать secrets.token_bytes.

        Returns:
            Результат проверки
        """
        details: Dict[str, Any] = {
            "platform": platform.system(),
        }

        try:
            import secrets

            _ = secrets.token_bytes(32)
            details["test_passed"] = True

            return HealthCheckResult(
                check_name=self.name,
                status=HealthCheckStatus.DEGRADED,
                message="Unknown platform, secrets module available",
                details=details,
            )

        except Exception as e:
            LOG.error("Generic entropy check failed: %s", e)
            details["test_passed"] = False

            return HealthCheckResult(
                check_name=self.name,
                status=HealthCheckStatus.UNHEALTHY,
                message=f"No entropy source available: {e}",
                details=details,
            )


__all__: list[str] = [
    "EntropyCheck",
    "MIN_ENTROPY_BITS",
    "MIN_ENTROPY_BITS_DEGRADED",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"