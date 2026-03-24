"""
Тесты для проверки энтропии.

Tests:
    - EntropyCheck: проверка доступности системной энтропии

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import platform
from unittest.mock import MagicMock, patch

import pytest

from src.security.monitoring.checks.entropy_check import (
    EntropyCheck,
    MIN_ENTROPY_BITS,
    MIN_ENTROPY_BITS_DEGRADED,
)
from src.security.monitoring.models import HealthCheckStatus


class TestEntropyCheck:
    """Тесты для EntropyCheck."""

    def test_check_name(self) -> None:
        """Проверка имени проверки."""
        check = EntropyCheck()
        assert check.name == "entropy"
        assert check.critical is True

    def test_check_description(self) -> None:
        """Проверка описания."""
        check = EntropyCheck()
        assert "entropy" in check.description.lower()

    @patch("platform.system")
    def test_check_linux_healthy(self, mock_system: MagicMock) -> None:
        """Проверка на Linux с достаточной энтропией."""
        mock_system.return_value = "Linux"

        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True), \
             patch("builtins.open", MagicMock()), \
             patch("builtins.open.read", return_value="512\n"):
            check = EntropyCheck()
            # Мокаем чтение entropy_avail
            with patch("builtins.open") as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = "512\n"
                mock_file.__enter__.return_value = mock_file
                mock_open.return_value = mock_file

                result = check.check()

            assert result.status == HealthCheckStatus.HEALTHY
            assert result.check_name == "entropy"
            assert "512" in result.message or "healthy" in result.message.lower()

    @patch("platform.system")
    def test_check_linux_degraded(self, mock_system: MagicMock) -> None:
        """Проверка на Linux с низкой энтропией."""
        mock_system.return_value = "Linux"

        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True):
            check = EntropyCheck()

            with patch("builtins.open") as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = "150\n"  # Ниже MIN_ENTROPY_BITS (256)
                mock_file.__enter__.return_value = mock_file
                mock_open.return_value = mock_file

                result = check.check()

            assert result.status == HealthCheckStatus.DEGRADED

    @patch("platform.system")
    def test_check_linux_critical(self, mock_system: MagicMock) -> None:
        """Проверка на Linux с критически низкой энтропией."""
        mock_system.return_value = "Linux"

        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True):
            check = EntropyCheck()

            with patch("builtins.open") as mock_open:
                mock_file = MagicMock()
                mock_file.read.return_value = "50\n"  # Критически низко
                mock_file.__enter__.return_value = mock_file
                mock_open.return_value = mock_file

                result = check.check()

            assert result.status == HealthCheckStatus.UNHEALTHY

    @patch("platform.system")
    def test_check_linux_not_found(self, mock_system: MagicMock) -> None:
        """Проверка на Linux без /dev/random."""
        mock_system.return_value = "Linux"

        with patch("os.path.exists", return_value=False):
            check = EntropyCheck()
            result = check.check()

            # Должен быть ERROR (EntropyCheckError обрабатывается)
            assert result.status == HealthCheckStatus.ERROR
            assert "random" in result.error.lower() or "not found" in result.error.lower()

    @patch("platform.system")
    def test_check_windows(self, mock_system: MagicMock) -> None:
        """Проверка на Windows (CSP всегда доступен)."""
        mock_system.return_value = "Windows"

        check = EntropyCheck()
        result = check.check()

        # На Windows должен быть HEALTHY (secrets всегда доступен)
        assert result.status == HealthCheckStatus.HEALTHY

    @patch("platform.system")
    def test_check_macos(self, mock_system: MagicMock) -> None:
        """Проверка на macOS."""
        mock_system.return_value = "Darwin"

        with patch("os.path.exists", return_value=True), \
             patch("os.access", return_value=True):
            check = EntropyCheck()
            result = check.check()

            # На macOS должен быть HEALTHY
            assert result.status == HealthCheckStatus.HEALTHY

    @patch("platform.system")
    def test_check_generic(self, mock_system: MagicMock) -> None:
        """Проверка на неизвестной платформе."""
        mock_system.return_value = "UnknownOS"

        check = EntropyCheck()
        result = check.check()

        # На неизвестной платформе должен быть DEGRADED или ERROR
        assert result.status in (HealthCheckStatus.DEGRADED, HealthCheckStatus.HEALTHY, HealthCheckStatus.ERROR)

    def test_custom_min_bits(self) -> None:
        """Проверка с кастомным min_bits."""
        check = EntropyCheck(min_bits=512)

        assert check.min_bits == 512

    def test_result_has_duration(self) -> None:
        """Результат содержит duration_ms."""
        check = EntropyCheck()
        result = check.check()

        assert result.duration_ms >= 0

    def test_result_has_details(self) -> None:
        """Результат содержит details."""
        with patch("platform.system") as mock_system:
            mock_system.return_value = "Windows"

            check = EntropyCheck()
            result = check.check()

            assert "platform" in result.details