"""
Тесты для проверки конфигурации.

Tests:
    - ConfigCheck: проверка целостности конфигурационного файла

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.security.monitoring.checks.config_check import ConfigCheck
from src.security.monitoring.models import HealthCheckStatus


class TestConfigCheck:
    """Тесты для ConfigCheck."""

    def test_check_name(self) -> None:
        """Проверка имени проверки."""
        check = ConfigCheck()
        assert check.name == "config"
        assert check.critical is False  # Non-critical check

    def test_check_description(self) -> None:
        """Проверка описания."""
        check = ConfigCheck()
        assert "config" in check.description.lower()

    def test_check_skipped_when_no_path(self) -> None:
        """Проверка пропускается, когда путь не задан."""
        check = ConfigCheck(config_path=None)
        result = check.check()

        assert result.status == HealthCheckStatus.SKIPPED
        assert "not configured" in result.message.lower()

    def test_check_skipped_when_file_not_found(self, tmp_path: Path) -> None:
        """Проверка пропускается, когда файл не найден."""
        nonexistent = tmp_path / "nonexistent.fxsconfig"
        check = ConfigCheck(config_path=nonexistent)
        result = check.check()

        assert result.status == HealthCheckStatus.SKIPPED
        assert "not found" in result.message.lower()

    def test_check_healthy_valid_json(self, tmp_path: Path) -> None:
        """Проверка HEALTHY для валидного JSON."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"key": "value", "number": 42}))

        check = ConfigCheck(config_path=config_path)
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        assert result.details.get("config_valid_json") is True
        assert "key" in result.details.get("config_keys", [])

    def test_check_unhealthy_invalid_json(self, tmp_path: Path) -> None:
        """Проверка UNHEALTHY для невалидного JSON."""
        config_path = tmp_path / "config.json"
        config_path.write_text("{invalid json}")

        check = ConfigCheck(config_path=config_path)
        result = check.check()

        assert result.status == HealthCheckStatus.UNHEALTHY
        assert "parse error" in result.message.lower()

    def test_check_error_not_a_file(self, tmp_path: Path) -> None:
        """Проверка бросает исключение, когда путь указывает не на файл."""
        directory = tmp_path / "config_dir"
        directory.mkdir()

        check = ConfigCheck(config_path=directory)
        with pytest.raises(Exception):  # ConfigCheckError
            check.check()

    def test_check_error_not_readable(self, tmp_path: Path) -> None:
        """Проверка бросает исключение, когда файл не читается."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"key": "value"}))

        with patch("os.access", return_value=False):
            check = ConfigCheck(config_path=config_path)
            with pytest.raises(Exception):  # ConfigCheckError
                check.check()

    def test_check_with_integrity_checker_valid(self, tmp_path: Path) -> None:
        """Проверка с ConfigIntegrityChecker (валидная подпись)."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"key": "value"}))

        mock_checker = MagicMock()
        mock_result = MagicMock()
        mock_result.passed = True
        mock_result.actual_hash = "abcd1234efgh5678"
        mock_result.error_message = None
        mock_checker.check_config.return_value = mock_result

        check = ConfigCheck(config_path=config_path, integrity_checker=mock_checker)
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        assert result.details.get("signature_verified") is True
        mock_checker.check_config.assert_called_once()

    def test_check_with_integrity_checker_invalid(self, tmp_path: Path) -> None:
        """Проверка с ConfigIntegrityChecker (невалидная подпись)."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"key": "value"}))

        mock_checker = MagicMock()
        mock_result = MagicMock()
        mock_result.passed = False
        mock_result.error_message = "Signature mismatch"
        mock_checker.check_config.return_value = mock_result

        check = ConfigCheck(config_path=config_path, integrity_checker=mock_checker)
        result = check.check()

        assert result.status == HealthCheckStatus.UNHEALTHY
        assert result.details.get("signature_verified") is False

    def test_check_warning_unsigned_with_signature_file(self, tmp_path: Path) -> None:
        """Проверка с предупреждением о неподписанной конфигурации."""
        config_path = tmp_path / "config.json"
        signature_path = tmp_path / "config.json.sig"
        config_path.write_text(json.dumps({"key": "value"}))
        signature_path.write_bytes(b"signature")

        check = ConfigCheck(
            config_path=config_path,
            signature_path=signature_path,
            integrity_checker=None,  # No integrity checker
        )
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        assert len(result.warnings) > 0
        assert "integrity checker" in result.warnings[0].lower()

    def test_result_has_duration(self, tmp_path: Path) -> None:
        """Результат содержит duration_ms."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"key": "value"}))

        check = ConfigCheck(config_path=config_path)
        result = check.check()

        assert result.duration_ms >= 0

    def test_result_has_details(self, tmp_path: Path) -> None:
        """Результат содержит details."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"key": "value"}))

        check = ConfigCheck(config_path=config_path)
        result = check.check()

        assert "config_path" in result.details
        assert "file_size" in result.details

    def test_check_handles_exception(self, tmp_path: Path) -> None:
        """Проверка обрабатывает исключения."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"key": "value"}))

        mock_checker = MagicMock()
        mock_checker.check_config.side_effect = RuntimeError("Checker error")

        check = ConfigCheck(config_path=config_path, integrity_checker=mock_checker)
        result = check.check()

        # Исключение должно быть обработано
        assert result.status == HealthCheckStatus.UNHEALTHY
        assert result.details.get("signature_verified") is False

    def test_check_truncates_config_keys(self, tmp_path: Path) -> None:
        """Проверка обрезает список ключей до 10."""
        config_path = tmp_path / "config.json"
        # 15 ключей
        config_data = {f"key{i}": f"value{i}" for i in range(15)}
        config_path.write_text(json.dumps(config_data))

        check = ConfigCheck(config_path=config_path)
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        assert len(result.details.get("config_keys", [])) == 10