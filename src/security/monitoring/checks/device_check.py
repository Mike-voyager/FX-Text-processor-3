"""
Device Check — проверка аппаратных устройств.

Проверяет:
- Смарт-карты (PIV, OpenPGP)
- FIDO2 токены
- Hardware Security Modules (HSM)

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.security.monitoring.exceptions import DeviceCheckError
from src.security.monitoring.models import HealthCheckResult, HealthCheckStatus

LOG = logging.getLogger(__name__)


@dataclass
class DeviceCheck:
    """
    Проверка аппаратных устройств.

    Некритическая проверка (устройства опциональны).

    Attributes:
        name: Имя проверки (фиксированное: "device")
        description: Описание проверки
        critical: False (устройства опциональны)
        device_types: Типы устройств для проверки (['smartcard', 'fido2', 'hsm'])
        device_registry: Опциональный DeviceRegistry для проверки

    Example:
        >>> check = DeviceCheck(device_types=['smartcard', 'fido2'])
        >>> result = check.check()
        >>> if result.is_healthy:
        ...     print("Devices OK")
    """

    name: str = "device"
    description: str = "Hardware device availability check"
    critical: bool = False
    device_types: List[str] = None  # type: ignore[assignment]
    device_registry: Optional[Any] = None  # DeviceRegistry if available

    def __post_init__(self) -> None:
        """Инициализация после создания."""
        if self.device_types is None:
            self.device_types = ["smartcard", "fido2"]

    def check(self) -> HealthCheckResult:
        """
        Выполнить проверку устройств.

        Returns:
            HealthCheckResult с результатом проверки
        """
        start_ms = time.monotonic()

        try:
            details: Dict[str, Any] = {
                "device_types": list(self.device_types),
                "devices_found": [],
                "devices_checked": 0,
            }

            warnings: List[str] = []
            devices_healthy = 0
            devices_total = 0

            # Проверяем каждый тип устройства
            for device_type in self.device_types:
                try:
                    device_result = self._check_device_type(device_type)
                    details["devices_found"].extend(device_result.get("devices", []))
                    devices_total += device_result.get("count", 0)
                    devices_healthy += device_result.get("healthy", 0)

                    if device_result.get("warning"):
                        warnings.append(device_result["warning"])

                except Exception as e:
                    LOG.debug("Device type %s check failed: %s", device_type, e)
                    warnings.append(f"{device_type}: {e}")

            details["devices_total"] = devices_total
            details["devices_healthy"] = devices_healthy

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            # Определяем статус
            if devices_healthy == devices_total and devices_total > 0:
                status = HealthCheckStatus.HEALTHY
                message = f"All {devices_total} device(s) healthy"
            elif devices_healthy > 0:
                status = HealthCheckStatus.DEGRADED
                message = f"{devices_healthy}/{devices_total} device(s) healthy"
            elif devices_total == 0:
                # Нет устройств — OK для некритической проверки
                status = HealthCheckStatus.HEALTHY
                message = "No hardware devices configured (optional)"
            else:
                status = HealthCheckStatus.UNHEALTHY
                message = "All devices unhealthy"

            return HealthCheckResult(
                check_name=self.name,
                status=status,
                message=message,
                duration_ms=elapsed_ms,
                details=details,
                warnings=warnings,
            )

        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Device check failed: %s", e)
            return HealthCheckResult.error_result(
                check_name=self.name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _check_device_type(self, device_type: str) -> Dict[str, Any]:
        """
        Проверить тип устройства.

        Args:
            device_type: Тип устройства ('smartcard', 'fido2', 'hsm')

        Returns:
            Словарь с результатом проверки
        """
        result: Dict[str, Any] = {
            "type": device_type,
            "devices": [],
            "count": 0,
            "healthy": 0,
            "warning": None,
        }

        if device_type == "smartcard":
            result = self._check_smartcard()
        elif device_type == "fido2":
            result = self._check_fido2()
        elif device_type == "hsm":
            result = self._check_hsm()
        else:
            result["warning"] = f"Unknown device type: {device_type}"

        return result

    def _check_smartcard(self) -> Dict[str, Any]:
        """Проверка смарт-карт."""
        result: Dict[str, Any] = {
            "type": "smartcard",
            "devices": [],
            "count": 0,
            "healthy": 0,
            "warning": None,
        }

        try:
            # Пытаемся импортировать pyscard
            from smartcard.System import readers

            reader_list = readers()
            result["count"] = len(reader_list)

            for reader in reader_list:
                device_info = {
                    "type": "smartcard",
                    "name": str(reader),
                    "healthy": True,  # Базовая проверка прошла
                }
                result["devices"].append(device_info)
                result["healthy"] += 1

        except ImportError:
            # pyscard не установлен — OK для некритической проверки
            result["warning"] = "pyscard not installed"

        except Exception as e:
            # Ошибка доступа к смарт-картам
            LOG.debug("Smartcard check failed: %s", e)
            result["warning"] = f"Smartcard access error: {e}"

        return result

    def _check_fido2(self) -> Dict[str, Any]:
        """Проверка FIDO2 токенов."""
        result: Dict[str, Any] = {
            "type": "fido2",
            "devices": [],
            "count": 0,
            "healthy": 0,
            "warning": None,
        }

        try:
            # Пытаемся импортировать fido2
            from fido2.hid import CtapHidDevice
            from fido2.client import Fido2Client

            devices = list(CtapHidDevice.list_devices())
            result["count"] = len(devices)

            for device in devices:
                device_info = {
                    "type": "fido2",
                    "name": device.descriptor.product_name or "Unknown FIDO2 device",
                    "healthy": True,
                }
                result["devices"].append(device_info)
                result["healthy"] += 1

        except ImportError:
            # fido2 не установлен — OK для некритической проверки
            result["warning"] = "fido2 library not installed"

        except Exception as e:
            LOG.debug("FIDO2 check failed: %s", e)
            result["warning"] = f"FIDO2 access error: {e}"

        return result

    def _check_hsm(self) -> Dict[str, Any]:
        """Проверка HSM (Hardware Security Module)."""
        result: Dict[str, Any] = {
            "type": "hsm",
            "devices": [],
            "count": 0,
            "healthy": 0,
            "warning": None,
        }

        # HSM проверка требует специфичных библиотек (PKCS#11, etc.)
        # Для базовой проверки просто отмечаем, что HSM не сконфигурирован
        if self.device_registry and hasattr(self.device_registry, "list_hsm"):
            try:
                devices = self.device_registry.list_hsm()
                result["count"] = len(devices)

                for device in devices:
                    device_info = {
                        "type": "hsm",
                        "name": device.get("name", "Unknown HSM"),
                        "healthy": device.get("healthy", True),
                    }
                    result["devices"].append(device_info)
                    if device_info["healthy"]:
                        result["healthy"] += 1

            except Exception as e:
                LOG.debug("HSM check failed: %s", e)
                result["warning"] = f"HSM access error: {e}"
        else:
            result["warning"] = "HSM not configured"

        return result


__all__: list[str] = [
    "DeviceCheck",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"