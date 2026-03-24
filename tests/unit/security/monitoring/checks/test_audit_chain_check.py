"""
Тесты для проверки audit chain.

Tests:
    - AuditChainCheck: проверка целостности hash-chain в audit log

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.security.monitoring.checks.audit_chain_check import AuditChainCheck
from src.security.monitoring.models import HealthCheckStatus


class TestAuditChainCheck:
    """Тесты для AuditChainCheck."""

    def test_check_name(self) -> None:
        """Проверка имени проверки."""
        check = AuditChainCheck()
        assert check.name == "audit_chain"
        assert check.critical is True

    def test_check_description(self) -> None:
        """Проверка описания."""
        check = AuditChainCheck()
        assert "audit" in check.description.lower()

    def test_check_skipped_when_no_audit_log(self) -> None:
        """Проверка пропускается, когда AuditLog не задан."""
        check = AuditChainCheck(audit_log=None)
        result = check.check()

        assert result.status == HealthCheckStatus.SKIPPED
        assert "not configured" in result.message.lower()

    def test_check_healthy_empty_log(self) -> None:
        """Проверка HEALTHY для пустого audit log."""
        mock_audit = MagicMock()
        mock_audit.event_count = 0

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        assert "empty" in result.message.lower()

    def test_check_healthy_valid_chain(self) -> None:
        """Проверка HEALTHY для валидной цепочки."""
        mock_audit = MagicMock()
        mock_audit.event_count = 100
        mock_audit.verify_chain.return_value = True

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        assert result.details.get("valid") is True
        assert result.details.get("verified_count") == 100

    def test_check_unhealthy_broken_chain(self) -> None:
        """Проверка UNHEALTHY для сломанной цепочки."""
        mock_audit = MagicMock()
        mock_audit.event_count = 50
        mock_audit.verify_chain.return_value = False

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert result.status == HealthCheckStatus.UNHEALTHY
        assert result.details.get("valid") is False

    def test_check_handles_verify_exception(self) -> None:
        """Проверка обрабатывает исключения при верификации."""
        mock_audit = MagicMock()
        mock_audit.event_count = 10
        mock_audit.verify_chain.side_effect = RuntimeError("Chain broken")

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert result.status == HealthCheckStatus.UNHEALTHY
        assert "Chain broken" in result.error

    def test_check_uses_count_events_method(self) -> None:
        """Проверка использует метод count_events."""
        mock_audit = MagicMock()
        # Удаляем event_count чтобы использовать count_events
        del mock_audit.event_count
        mock_audit.count_events.return_value = 25
        mock_audit.verify_chain.return_value = True

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        # count_events вызывается дважды: в _get_event_count и в _verify_chain
        assert mock_audit.count_events.call_count >= 1

    def test_check_handles_missing_methods(self) -> None:
        """Проверка обрабатывает отсутствие методов."""
        mock_audit = MagicMock(spec=[])  # Empty spec = no methods

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        # Должен вернуть HEALTHY с пустым event_count=0
        # т.к. _get_event_count возвращает 0 если нет методов
        assert result.status == HealthCheckStatus.HEALTHY

    def test_max_events_parameter(self) -> None:
        """Проверка параметра max_events."""
        check = AuditChainCheck(max_events=500)
        assert check.max_events == 500

    def test_result_has_duration(self) -> None:
        """Результат содержит duration_ms."""
        mock_audit = MagicMock()
        mock_audit.event_count = 0

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert result.duration_ms >= 0

    def test_result_has_details(self) -> None:
        """Результат содержит details."""
        mock_audit = MagicMock()
        mock_audit.event_count = 10
        mock_audit.verify_chain.return_value = True

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert "event_count" in result.details
        assert "verified_count" in result.details

    def test_check_error_result_format(self) -> None:
        """Проверка формата ERROR результата."""
        mock_audit = MagicMock()
        mock_audit.event_count = 10
        mock_audit.verify_chain.side_effect = Exception("Test error")

        check = AuditChainCheck(audit_log=mock_audit)
        result = check.check()

        assert result.status == HealthCheckStatus.UNHEALTHY
        assert result.error is not None