"""
Тесты для проверки keystore.

Tests:
    - KeystoreCheck: проверка состояния keystore

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.security.monitoring.checks.keystore_check import KeystoreCheck
from src.security.monitoring.models import HealthCheckStatus


class TestKeystoreCheck:
    """Тесты для KeystoreCheck."""

    def test_check_name(self) -> None:
        """Проверка имени проверки."""
        check = KeystoreCheck()
        assert check.name == "keystore"
        assert check.critical is True

    def test_check_description(self) -> None:
        """Проверка описания."""
        check = KeystoreCheck()
        assert "keystore" in check.description.lower()

    def test_check_skipped_when_no_path(self) -> None:
        """Проверка пропускается, когда путь не задан."""
        check = KeystoreCheck(keystore_path=None)
        result = check.check()

        assert result.status == HealthCheckStatus.SKIPPED
        assert "not configured" in result.message.lower()

    def test_check_error_when_file_not_found(self, tmp_path: Path) -> None:
        """Проверка бросает исключение, когда файл не найден."""
        nonexistent = tmp_path / "nonexistent.fxskeystore.enc"
        check = KeystoreCheck(keystore_path=nonexistent)

        with pytest.raises(Exception):  # KeystoreCheckError
            check.check()

    def test_check_degraded_unencrypted_keystore(self, tmp_path: Path) -> None:
        """Проверка DEGRADED для незашифрованного keystore."""
        keystore_path = tmp_path / "test.fxskeystore"
        keystore_path.write_bytes(b"plain content")

        check = KeystoreCheck(keystore_path=keystore_path)
        result = check.check()

        assert result.status == HealthCheckStatus.DEGRADED
        assert "not encrypted" in result.message.lower()

    def test_check_error_not_a_file(self, tmp_path: Path) -> None:
        """Проверка бросает исключение, когда путь указывает не на файл."""
        directory = tmp_path / "keystore_dir"
        directory.mkdir()

        check = KeystoreCheck(keystore_path=directory)
        with pytest.raises(Exception):  # KeystoreCheckError
            check.check()

    def test_check_error_not_readable(self, tmp_path: Path) -> None:
        """Проверка бросает исключение, когда файл не читается."""
        import os

        keystore_path = tmp_path / "test.fxskeystore.enc"
        keystore_path.write_bytes(b"content")

        # Мокаем os.access чтобы вернуть False
        with patch("os.access", return_value=False):
            check = KeystoreCheck(keystore_path=keystore_path)
            with pytest.raises(Exception):  # KeystoreCheckError
                check.check()

    def test_check_with_crypto_service(self, tmp_path: Path) -> None:
        """Проверка с CryptoService."""
        keystore_path = tmp_path / "test.fxskeystore.enc"
        keystore_path.write_bytes(b"encrypted content")

        mock_crypto = MagicMock()
        mock_crypto.list_keys.return_value = [
            {"id": "key1", "expires_at": "2099-01-01T00:00:00+00:00"}
        ]

        check = KeystoreCheck(keystore_path=keystore_path, crypto_service=mock_crypto)
        result = check.check()

        assert result.status == HealthCheckStatus.HEALTHY
        assert result.details.get("keys_checked") is True
        assert result.details.get("key_count") == 1

    def test_check_expiring_keys(self, tmp_path: Path) -> None:
        """Проверка DEGRADED при истекающих ключах."""
        from datetime import datetime, timedelta, timezone

        keystore_path = tmp_path / "test.fxskeystore.enc"
        keystore_path.write_bytes(b"encrypted content")

        # Ключ, который истекает через 15 дней
        expires_soon = datetime.now(timezone.utc) + timedelta(days=15)

        mock_crypto = MagicMock()
        mock_crypto.list_keys.return_value = [
            {"id": "key1", "expires_at": expires_soon.isoformat()}
        ]

        check = KeystoreCheck(keystore_path=keystore_path, crypto_service=mock_crypto)
        result = check.check()

        assert result.status == HealthCheckStatus.DEGRADED
        assert result.details.get("keys_expiring") is True

    def test_result_has_duration(self, tmp_path: Path) -> None:
        """Результат содержит duration_ms."""
        keystore_path = tmp_path / "test.fxskeystore.enc"
        keystore_path.write_bytes(b"content")

        check = KeystoreCheck(keystore_path=keystore_path)
        result = check.check()

        assert result.duration_ms >= 0

    def test_result_has_details(self, tmp_path: Path) -> None:
        """Результат содержит details."""
        keystore_path = tmp_path / "test.fxskeystore.enc"
        keystore_path.write_bytes(b"content")

        check = KeystoreCheck(keystore_path=keystore_path)
        result = check.check()

        assert "keystore_path" in result.details
        assert "file_size" in result.details

    def test_check_handles_crypto_service_error(self, tmp_path: Path) -> None:
        """Проверка обрабатывает ошибки от CryptoService."""
        keystore_path = tmp_path / "test.fxskeystore.enc"
        keystore_path.write_bytes(b"encrypted content")

        mock_crypto = MagicMock()
        mock_crypto.list_keys.side_effect = RuntimeError("Key error")

        check = KeystoreCheck(keystore_path=keystore_path, crypto_service=mock_crypto)
        result = check.check()

        # Файл существует, но ключи не проверены
        assert result.status == HealthCheckStatus.HEALTHY
        assert result.details.get("keys_checked") is False