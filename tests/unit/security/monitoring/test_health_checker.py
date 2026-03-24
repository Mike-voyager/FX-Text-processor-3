"""
Тесты для модуля мониторинга.

Tests:
    - HealthCheckStatus: перечисление статусов
    - HealthCheckResult: результат проверки
    - HealthCheckReport: комплексный отчёт
    - HealthChecker: реестр и исполнитель проверок
    - HealthCheckError: иерархия исключений

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from src.security.monitoring import (
    HealthChecker,
    HealthCheck,
    HealthCheckError,
    HealthCheckReport,
    HealthCheckResult,
    HealthCheckStatus,
)
from src.security.monitoring.exceptions import (
    AlgorithmCheckError,
    AuditChainCheckError,
    ConfigCheckError,
    DeviceCheckError,
    EntropyCheckError,
    KeystoreCheckError,
)


# =============================================================================
# Tests for HealthCheckStatus
# =============================================================================


class TestHealthCheckStatus:
    """Тесты для HealthCheckStatus."""

    def test_status_values(self) -> None:
        """Проверка значений статусов."""
        assert HealthCheckStatus.HEALTHY.value == "healthy"
        assert HealthCheckStatus.DEGRADED.value == "degraded"
        assert HealthCheckStatus.UNHEALTHY.value == "unhealthy"
        assert HealthCheckStatus.SKIPPED.value == "skipped"
        assert HealthCheckStatus.ERROR.value == "error"

    def test_is_ok_property(self) -> None:
        """Проверка свойства is_ok."""
        assert HealthCheckStatus.HEALTHY.is_ok is True
        assert HealthCheckStatus.DEGRADED.is_ok is True
        assert HealthCheckStatus.UNHEALTHY.is_ok is False
        assert HealthCheckStatus.SKIPPED.is_ok is False
        assert HealthCheckStatus.ERROR.is_ok is False

    def test_is_critical_property(self) -> None:
        """Проверка свойства is_critical."""
        assert HealthCheckStatus.HEALTHY.is_critical is False
        assert HealthCheckStatus.DEGRADED.is_critical is False
        assert HealthCheckStatus.UNHEALTHY.is_critical is True
        assert HealthCheckStatus.SKIPPED.is_critical is False
        assert HealthCheckStatus.ERROR.is_critical is True

    def test_severity_property(self) -> None:
        """Проверка свойства severity."""
        assert HealthCheckStatus.HEALTHY.severity == 0
        assert HealthCheckStatus.DEGRADED.severity == 1
        assert HealthCheckStatus.SKIPPED.severity == 2
        assert HealthCheckStatus.UNHEALTHY.severity == 3
        assert HealthCheckStatus.ERROR.severity == 4


# =============================================================================
# Tests for HealthCheckResult
# =============================================================================


class TestHealthCheckResult:
    """Тесты для HealthCheckResult."""

    def test_healthy_factory(self) -> None:
        """Создание успешного результата."""
        result = HealthCheckResult.healthy(
            check_name="test",
            message="All good",
            duration_ms=100,
            details={"key": "value"},
        )

        assert result.check_name == "test"
        assert result.status == HealthCheckStatus.HEALTHY
        assert result.message == "All good"
        assert result.duration_ms == 100
        assert result.details == {"key": "value"}
        assert result.is_healthy is True
        assert result.needs_attention is False

    def test_degraded_factory(self) -> None:
        """Создание результата с предупреждениями."""
        result = HealthCheckResult.degraded(
            check_name="test",
            message="Some warnings",
            warnings=["Warning 1", "Warning 2"],
        )

        assert result.status == HealthCheckStatus.DEGRADED
        assert result.warnings == ["Warning 1", "Warning 2"]
        assert result.is_healthy is False
        assert result.needs_attention is False

    def test_unhealthy_factory(self) -> None:
        """Создание неуспешного результата."""
        result = HealthCheckResult.unhealthy(
            check_name="test",
            message="Check failed",
            error="Connection refused",
        )

        assert result.status == HealthCheckStatus.UNHEALTHY
        assert result.error == "Connection refused"
        assert result.is_healthy is False
        assert result.needs_attention is True

    def test_skipped_factory(self) -> None:
        """Создание результата пропущенной проверки."""
        result = HealthCheckResult.skipped(
            check_name="test",
            message="Skipped",
            reason="Not applicable",
        )

        assert result.status == HealthCheckStatus.SKIPPED
        assert result.details.get("reason") == "Not applicable"
        assert result.is_healthy is False

    def test_error_result_factory(self) -> None:
        """Создание результата ошибки выполнения."""
        result = HealthCheckResult.error_result(
            check_name="test",
            error="Exception occurred",
            exception="ValueError",
        )

        assert result.status == HealthCheckStatus.ERROR
        assert result.error == "Exception occurred"
        assert result.details.get("exception") == "ValueError"
        assert result.needs_attention is True

    def test_to_dict(self) -> None:
        """Сериализация в словарь."""
        result = HealthCheckResult.healthy(
            check_name="test",
            message="OK",
            details={"key": "value", "long_key": "x" * 200},
        )

        data = result.to_dict()

        assert data["check_name"] == "test"
        assert data["status"] == "healthy"
        assert data["message"] == "OK"
        # Длинные значения обрезаются
        assert len(data["details"]["long_key"]) <= 103  # str[:100] + "..."

    def test_frozen(self) -> None:
        """Проверка immutability."""
        result = HealthCheckResult.healthy(check_name="test")

        with pytest.raises(AttributeError):
            result.status = HealthCheckStatus.UNHEALTHY  # type: ignore[misc]


# =============================================================================
# Tests for HealthCheckReport
# =============================================================================


class TestHealthCheckReport:
    """Тесты для HealthCheckReport."""

    def test_report_creation(self) -> None:
        """Создание отчёта."""
        checks = [
            HealthCheckResult.healthy("check1"),
            HealthCheckResult.degraded("check2", message="Warning"),
            HealthCheckResult.unhealthy("check3", message="Failed", error="Error"),
        ]

        report = HealthCheckReport(
            checks=checks,
            overall_status=HealthCheckStatus.DEGRADED,
            version="1.0.0",
            platform="linux",
        )

        assert len(report.checks) == 3
        assert report.healthy_count == 1
        assert report.degraded_count == 1
        assert report.unhealthy_count == 1
        assert report.skipped_count == 0
        assert report.error_count == 0
        assert len(report.critical_checks) == 1
        assert report.is_healthy is True  # DEGRADED is still OK

    def test_calculate_overall_status(self) -> None:
        """Вычисление общего статуса."""
        # Пустой список
        assert HealthCheckReport.calculate_overall_status([]) == HealthCheckStatus.SKIPPED

        # Все здоровы
        checks = [
            HealthCheckResult.healthy("check1"),
            HealthCheckResult.healthy("check2"),
        ]
        assert HealthCheckReport.calculate_overall_status(checks) == HealthCheckStatus.HEALTHY

        # Есть degraded
        checks = [
            HealthCheckResult.healthy("check1"),
            HealthCheckResult.degraded("check2", message="Warning"),
        ]
        assert HealthCheckReport.calculate_overall_status(checks) == HealthCheckStatus.DEGRADED

        # Есть unhealthy
        checks = [
            HealthCheckResult.healthy("check1"),
            HealthCheckResult.unhealthy("check2", message="Failed", error="Error"),
        ]
        assert HealthCheckReport.calculate_overall_status(checks) == HealthCheckStatus.UNHEALTHY

        # Есть error
        checks = [
            HealthCheckResult.healthy("check1"),
            HealthCheckResult.error_result("check2", error="Exception"),
        ]
        assert HealthCheckReport.calculate_overall_status(checks) == HealthCheckStatus.ERROR

    def test_to_dict(self) -> None:
        """Сериализация отчёта."""
        checks = [
            HealthCheckResult.healthy("check1"),
        ]

        report = HealthCheckReport(
            checks=checks,
            overall_status=HealthCheckStatus.HEALTHY,
            version="1.0.0",
            platform="linux",
        )

        data = report.to_dict()

        assert "checks" in data
        assert data["overall_status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert data["platform"] == "linux"
        assert "summary" in data
        assert data["summary"]["healthy"] == 1


# =============================================================================
# Tests for HealthChecker
# =============================================================================


class TestHealthChecker:
    """Тесты для HealthChecker."""

    def test_register_check(self) -> None:
        """Регистрация проверки-экземпляра."""
        checker = HealthChecker()

        class MockCheck:
            name = "mock"
            description = "Mock check"
            critical = False

            def check(self) -> HealthCheckResult:
                return HealthCheckResult.healthy("mock")

        check = MockCheck()
        checker.register_check(check)

        assert checker.check_count == 1
        assert "mock" in checker.check_names

    def test_register_function(self) -> None:
        """Регистрация проверки-функции."""
        checker = HealthChecker()

        def mock_check() -> HealthCheckResult:
            return HealthCheckResult.healthy("mock_func")

        checker.register_function("mock_func", mock_check, description="Mock function check")

        assert checker.check_count == 1
        assert "mock_func" in checker.check_names

    def test_register_duplicate_raises(self) -> None:
        """Регистрация дубликата выбрасывает исключение."""
        checker = HealthChecker()

        def mock_check() -> HealthCheckResult:
            return HealthCheckResult.healthy("mock")

        checker.register_function("mock", mock_check)

        with pytest.raises(ValueError, match="already registered"):
            checker.register_function("mock", mock_check)

    def test_unregister(self) -> None:
        """Удаление проверки."""
        checker = HealthChecker()

        def mock_check() -> HealthCheckResult:
            return HealthCheckResult.healthy("mock")

        checker.register_function("mock", mock_check)
        assert checker.check_count == 1

        result = checker.unregister("mock")
        assert result is True
        assert checker.check_count == 0

        # Удаление несуществующей проверки
        result = checker.unregister("nonexistent")
        assert result is False

    def test_run_check(self) -> None:
        """Выполнение одной проверки."""
        checker = HealthChecker()

        def mock_check() -> HealthCheckResult:
            return HealthCheckResult.healthy("mock", message="OK")

        checker.register_function("mock", mock_check)

        result = checker.run_check("mock")

        assert result.check_name == "mock"
        assert result.status == HealthCheckStatus.HEALTHY
        assert result.message == "OK"

    def test_run_check_not_found(self) -> None:
        """Выполнение несуществующей проверки."""
        checker = HealthChecker()

        with pytest.raises(KeyError, match="not found"):
            checker.run_check("nonexistent")

    def test_run_all(self) -> None:
        """Выполнение всех проверок."""
        checker = HealthChecker(version="2.0.0")

        def check1() -> HealthCheckResult:
            return HealthCheckResult.healthy("check1")

        def check2() -> HealthCheckResult:
            return HealthCheckResult.degraded("check2", message="Warning", warnings=["w1"])

        checker.register_function("check1", check1)
        checker.register_function("check2", check2)

        report = checker.run_all()

        assert report.version == "2.0.0"
        assert len(report.checks) == 2
        assert report.overall_status == HealthCheckStatus.DEGRADED
        assert report.healthy_count == 1
        assert report.degraded_count == 1

    def test_run_all_with_error(self) -> None:
        """Выполнение с ошибкой в проверке."""
        checker = HealthChecker()

        def failing_check() -> HealthCheckResult:
            raise RuntimeError("Check failed")

        checker.register_function("failing", failing_check)

        report = checker.run_all()

        assert len(report.checks) == 1
        assert report.checks[0].status == HealthCheckStatus.ERROR
        assert report.checks[0].details.get("exception") == "RuntimeError"

    def test_run_critical(self) -> None:
        """Выполнение только критических проверок."""
        checker = HealthChecker()

        def critical_check() -> HealthCheckResult:
            return HealthCheckResult.healthy("critical")

        def non_critical_check() -> HealthCheckResult:
            return HealthCheckResult.healthy("non_critical")

        checker.register_function("critical", critical_check, critical=True)
        checker.register_function("non_critical", non_critical_check, critical=False)

        # Добавляем проверку-экземпляр
        class CriticalInstanceCheck:
            name = "critical_instance"
            description = "Critical instance check"
            critical = True

            def check(self) -> HealthCheckResult:
                return HealthCheckResult.healthy("critical_instance")

        checker.register_check(CriticalInstanceCheck())

        report = checker.run_critical()

        assert len(report.checks) == 2
        assert all(c.check_name.startswith("critical") for c in report.checks)

    def test_health_check_error_wrapped(self) -> None:
        """Ошибки HealthCheckError оборачиваются."""
        checker = HealthChecker()

        def failing_check() -> HealthCheckResult:
            raise EntropyCheckError(
                message="Entropy too low",
                available_bits=128,
                required_bits=256,
            )

        checker.register_function("entropy", failing_check)

        report = checker.run_all()

        assert len(report.checks) == 1
        assert report.checks[0].status == HealthCheckStatus.ERROR
        assert report.checks[0].details.get("exception") == "EntropyCheckError"


# =============================================================================
# Tests for Exceptions
# =============================================================================


class TestHealthCheckExceptions:
    """Тесты для иерархии исключений."""

    def test_entropy_check_error(self) -> None:
        """Тест EntropyCheckError."""
        error = EntropyCheckError(
            message="Entropy check failed",
            available_bits=128,
            required_bits=256,
        )

        assert error.check_name == "entropy"
        assert error.available_bits == 128
        assert error.required_bits == 256
        assert "Entropy check failed" in str(error)
        assert "available_bits=128" in str(error)

    def test_keystore_check_error(self) -> None:
        """Тест KeystoreCheckError."""
        error = KeystoreCheckError(
            message="Keystore not found",
            keystore_path="/path/to/keystore",
        )

        assert error.check_name == "keystore"
        assert error.keystore_path == "/path/to/keystore"

    def test_device_check_error(self) -> None:
        """Тест DeviceCheckError."""
        error = DeviceCheckError(
            message="Device not found",
            device_type="smartcard",
            device_id="reader-0",
        )

        assert error.check_name == "device"
        assert error.device_type == "smartcard"
        assert error.device_id == "reader-0"

    def test_algorithm_check_error(self) -> None:
        """Тест AlgorithmCheckError."""
        error = AlgorithmCheckError(
            message="Algorithm not available",
            algorithm="ML-DSA-65",
            reason="liboqs not installed",
        )

        assert error.check_name == "algorithm"
        assert error.algorithm == "ML-DSA-65"
        assert error.reason == "liboqs not installed"

    def test_audit_chain_check_error(self) -> None:
        """Тест AuditChainCheckError."""
        error = AuditChainCheckError(
            message="Chain broken",
            event_count=100,
            failed_at_event="event-50",
        )

        assert error.check_name == "audit_chain"
        assert error.event_count == 100
        assert error.failed_at_event == "event-50"

    def test_config_check_error(self) -> None:
        """Тест ConfigCheckError."""
        error = ConfigCheckError(
            message="Config signature invalid",
            config_path="/path/to/config",
        )

        assert error.check_name == "config"
        assert error.config_path == "/path/to/config"

    def test_exception_hierarchy(self) -> None:
        """Все исключения наследуются от HealthCheckError."""
        exceptions = [
            EntropyCheckError("Test"),
            KeystoreCheckError("Test"),
            DeviceCheckError("Test"),
            AlgorithmCheckError("Test"),
            AuditChainCheckError("Test"),
            ConfigCheckError("Test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, HealthCheckError)
            assert isinstance(exc, Exception)