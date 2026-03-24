"""
Тесты для проверки устройств.

Tests:
    - DeviceCheck: проверка аппаратных устройств (smartcard, fido2, hsm)

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.security.monitoring.checks.device_check import DeviceCheck
from src.security.monitoring.models import HealthCheckStatus


class TestDeviceCheck:
    """Тесты для DeviceCheck."""

    def test_check_name(self) -> None:
        """Проверка имени проверки."""
        check = DeviceCheck()
        assert check.name == "device"
        assert check.critical is False  # Non-critical check

    def test_check_description(self) -> None:
        """Проверка описания."""
        check = DeviceCheck()
        assert "device" in check.description.lower()

    def test_default_device_types(self) -> None:
        """Проверка типов устройств по умолчанию."""
        check = DeviceCheck()
        assert "smartcard" in check.device_types
        assert "fido2" in check.device_types

    def test_custom_device_types(self) -> None:
        """Проверка кастомных типов устройств."""
        check = DeviceCheck(device_types=["hsm"])
        assert check.device_types == ["hsm"]

    def test_check_healthy_no_devices(self) -> None:
        """Проверка HEALTHY, когда устройства не найдены (некритично)."""
        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.return_value = {"devices": [], "count": 0, "healthy": 0, "warning": None}

            check = DeviceCheck(device_types=["smartcard"])
            result = check.check()

            assert result.status == HealthCheckStatus.HEALTHY
            assert "no hardware devices" in result.message.lower()

    def test_check_healthy_with_devices(self) -> None:
        """Проверка HEALTHY, когда устройства найдены и здоровы."""
        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.return_value = {
                "devices": [{"type": "smartcard", "name": "Reader1", "healthy": True}],
                "count": 1,
                "healthy": 1,
                "warning": None,
            }

            check = DeviceCheck(device_types=["smartcard"])
            result = check.check()

            assert result.status == HealthCheckStatus.HEALTHY
            assert result.details.get("devices_healthy") == 1
            assert result.details.get("devices_total") == 1

    def test_check_degraded_partial_devices(self) -> None:
        """Проверка DEGRADED, когда часть устройств недоступна."""
        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.return_value = {
                "devices": [
                    {"type": "smartcard", "name": "Reader1", "healthy": True},
                    {"type": "smartcard", "name": "Reader2", "healthy": False},
                ],
                "count": 2,
                "healthy": 1,
                "warning": None,
            }

            check = DeviceCheck(device_types=["smartcard"])
            result = check.check()

            assert result.status == HealthCheckStatus.DEGRADED
            assert "1/2" in result.message

    def test_check_unhealthy_all_failed(self) -> None:
        """Проверка UNHEALTHY, когда все устройства недоступны."""
        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.return_value = {
                "devices": [{"type": "smartcard", "name": "Reader1", "healthy": False}],
                "count": 1,
                "healthy": 0,
                "warning": "Device not responding",
            }

            check = DeviceCheck(device_types=["smartcard"])
            result = check.check()

            assert result.status == HealthCheckStatus.UNHEALTHY

    def test_check_smartcard_not_installed(self) -> None:
        """Проверка smartcard, когда pyscard не установлен."""
        check = DeviceCheck(device_types=["smartcard"])

        with patch.dict("sys.modules", {"smartcard": None, "smartcard.System": None}):
            # ImportError обрабатывается
            result = check._check_smartcard()

            assert result["warning"] == "pyscard not installed"

    def test_check_fido2_not_installed(self) -> None:
        """Проверка FIDO2, когда библиотека не установлена."""
        check = DeviceCheck(device_types=["fido2"])

        with patch.dict("sys.modules", {"fido2": None, "fido2.hid": None}):
            result = check._check_fido2()

            assert result["warning"] == "fido2 library not installed"

    def test_check_hsm_not_configured(self) -> None:
        """Проверка HSM, когда не сконфигурирован."""
        check = DeviceCheck(device_types=["hsm"])
        result = check._check_hsm()

        assert result["warning"] == "HSM not configured"

    def test_check_hsm_with_registry(self) -> None:
        """Проверка HSM с DeviceRegistry."""
        mock_registry = MagicMock()
        mock_registry.list_hsm.return_value = [
            {"name": "HSM1", "healthy": True},
            {"name": "HSM2", "healthy": False},
        ]

        check = DeviceCheck(device_types=["hsm"], device_registry=mock_registry)
        result = check._check_hsm()

        assert result["count"] == 2
        assert result["healthy"] == 1

    def test_check_unknown_device_type(self) -> None:
        """Проверка неизвестного типа устройства."""
        check = DeviceCheck(device_types=["unknown"])
        result = check._check_device_type("unknown")

        assert "unknown" in result["warning"].lower()

    def test_result_has_duration(self) -> None:
        """Результат содержит duration_ms."""
        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.return_value = {"devices": [], "count": 0, "healthy": 0, "warning": None}

            check = DeviceCheck(device_types=["smartcard"])
            result = check.check()

            assert result.duration_ms >= 0

    def test_result_has_details(self) -> None:
        """Результат содержит details."""
        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.return_value = {"devices": [], "count": 0, "healthy": 0, "warning": None}

            check = DeviceCheck(device_types=["smartcard"])
            result = check.check()

            assert "device_types" in result.details
            assert "devices_found" in result.details

    def test_check_multiple_device_types(self) -> None:
        """Проверка нескольких типов устройств."""
        check = DeviceCheck(device_types=["smartcard", "fido2"])

        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.return_value = {"devices": [], "count": 1, "healthy": 1, "warning": None}

            result = check.check()

            # Должен быть вызван дважды (для каждого типа)
            assert mock_check.call_count == 2

    def test_check_handles_exception(self) -> None:
        """Проверка обрабатывает исключения."""
        with patch.object(DeviceCheck, "_check_device_type") as mock_check:
            mock_check.side_effect = RuntimeError("Device error")

            check = DeviceCheck(device_types=["smartcard"])
            result = check.check()

            # Исключение обрабатывается, добавляется в warnings
            assert len(result.warnings) > 0