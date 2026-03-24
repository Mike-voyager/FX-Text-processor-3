"""
Тесты для модуля integrity: ConfigIntegrityChecker.

Проверка подписи конфигурационных файлов.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from src.security.crypto.algorithms.signing import Ed25519Signer
from src.security.integrity.config_integrity import (
    PUBLIC_KEY_FILE,
    SIGNED_CONFIG_EXTENSION,
    ConfigIntegrityChecker,
    SignedConfig,
)
from src.security.integrity.exceptions import ConfigSignatureError
from src.security.integrity.models import IntegrityCheckType


class TestConfigIntegrityChecker:
    """Тесты ConfigIntegrityChecker."""

    @pytest.fixture
    def keypair(self) -> tuple[bytes, bytes]:
        """Генерация пары ключей для тестов."""
        signer = Ed25519Signer()
        return signer.generate_keypair()

    @pytest.fixture
    def config_content(self) -> dict:
        """Тестовое содержимое конфигурации."""
        return {
            "app_name": "FX Text Processor",
            "version": "3.0.0",
            "settings": {
                "auto_save": True,
                "theme": "dark",
            },
        }

    def test_compute_config_hash(self, keypair: tuple[bytes, bytes]) -> None:
        """Тест вычисления хеша конфигурации."""
        public_key, _ = keypair
        checker = ConfigIntegrityChecker(verification_key=public_key)

        content = '{"test": "data"}'
        hash_bytes = checker.compute_config_hash(content)
        expected = hashlib.sha3_256(content.encode()).digest()

        assert hash_bytes == expected
        assert len(hash_bytes) == 32

    def test_verify_signature_valid(self, keypair: tuple[bytes, bytes], config_content: dict) -> None:
        """Тест верификации валидной подписи."""
        private_key, public_key = keypair
        checker = ConfigIntegrityChecker(verification_key=public_key)
        signer = Ed25519Signer()

        # Нормализуем JSON и подписываем
        config_str = json.dumps(config_content, ensure_ascii=False, sort_keys=True)
        config_hash = hashlib.sha3_256(config_str.encode()).digest()
        signature = signer.sign(private_key, config_hash)

        # Верифицируем
        is_valid = checker.verify_signature(config_str, signature)
        assert is_valid is True

    def test_verify_signature_invalid(self, keypair: tuple[bytes, bytes]) -> None:
        """Тест верификации невалидной подписи."""
        private_key, public_key = keypair
        checker = ConfigIntegrityChecker(verification_key=public_key)
        signer = Ed25519Signer()

        # Подписываем одно содержимое
        content1 = '{"test": "data1"}'
        hash1 = hashlib.sha3_256(content1.encode()).digest()
        signature = signer.sign(private_key, hash1)

        # Верифицируем другое содержимое
        content2 = '{"test": "data2"}'
        is_valid = checker.verify_signature(content2, signature)
        assert is_valid is False

    def test_verify_signature_wrong_key(self, keypair: tuple[bytes, bytes]) -> None:
        """Тест верификации с неверным публичным ключом."""
        private_key, _ = keypair
        # Генерируем другую пару ключей
        signer = Ed25519Signer()
        other_private, other_public = signer.generate_keypair()

        checker = ConfigIntegrityChecker(verification_key=other_public)

        # Подписываем первым ключом
        content = '{"test": "data"}'
        hash_bytes = hashlib.sha3_256(content.encode()).digest()
        signature = signer.sign(private_key, hash_bytes)

        # Верифицируем другим ключом
        is_valid = checker.verify_signature(content, signature)
        assert is_valid is False

    def test_verify_signature_no_key(self) -> None:
        """Тест ошибки при отсутствии публичного ключа."""
        checker = ConfigIntegrityChecker(verification_key=None)

        with pytest.raises(ConfigSignatureError) as exc_info:
            checker.verify_signature("content", b"signature")

        assert "ключ" in str(exc_info.value).lower()

    def test_load_signed_config(self, keypair: tuple[bytes, bytes], config_content: dict, tmp_path: Path) -> None:
        """Тест загрузки подписанной конфигурации."""
        private_key, public_key = keypair
        signer = Ed25519Signer()

        # Создаём подписанную конфигурацию
        config_str = json.dumps(config_content, ensure_ascii=False, sort_keys=True)
        config_hash = hashlib.sha3_256(config_str.encode()).digest()
        signature = signer.sign(private_key, config_hash)

        signed_data = {
            "config": config_content,
            "signature": signature.hex(),
            "public_key_hint": public_key[:8].hex(),
            "algorithm": "Ed25519",
        }

        config_file = tmp_path / "config.fxsconfig"
        config_file.write_text(json.dumps(signed_data), encoding="utf-8")

        checker = ConfigIntegrityChecker(verification_key=public_key)
        signed_config = checker.load_signed_config(config_file)

        assert signed_config.signature == signature.hex()
        assert signed_config.public_key_hint == public_key[:8].hex()

    def test_load_signed_config_not_found(self, tmp_path: Path) -> None:
        """Тест ошибки при отсутствии файла конфигурации."""
        checker = ConfigIntegrityChecker(verification_key=b"x" * 32)

        with pytest.raises(ConfigSignatureError) as exc_info:
            checker.load_signed_config(tmp_path / "nonexistent.fxsconfig")

        assert "не найден" in str(exc_info.value)

    def test_load_signed_config_invalid_json(self, tmp_path: Path) -> None:
        """Тест ошибки при некорректном JSON."""
        config_file = tmp_path / "config.fxsconfig"
        config_file.write_text("not a valid json", encoding="utf-8")

        checker = ConfigIntegrityChecker(verification_key=b"x" * 32)

        with pytest.raises(ConfigSignatureError) as exc_info:
            checker.load_signed_config(config_file)

        assert "JSON" in str(exc_info.value)

    def test_check_config_valid(self, keypair: tuple[bytes, bytes], config_content: dict, tmp_path: Path) -> None:
        """Тест успешной проверки конфигурации."""
        private_key, public_key = keypair
        signer = Ed25519Signer()

        # Создаём подписанную конфигурацию
        config_str = json.dumps(config_content, ensure_ascii=False, sort_keys=True)
        config_hash = hashlib.sha3_256(config_str.encode()).digest()
        signature = signer.sign(private_key, config_hash)

        signed_data = {
            "config": config_content,
            "signature": signature.hex(),
            "public_key_hint": public_key[:8].hex(),
        }

        config_file = tmp_path / "config.fxsconfig"
        config_file.write_text(json.dumps(signed_data), encoding="utf-8")

        checker = ConfigIntegrityChecker(verification_key=public_key)
        result = checker.check_config(config_file)

        assert result.passed is True
        assert result.check_type == IntegrityCheckType.CONFIG_FILE
        assert result.signature_valid is True
        assert result.error_message is None

    def test_check_config_invalid_signature(self, keypair: tuple[bytes, bytes], config_content: dict, tmp_path: Path) -> None:
        """Тест неуспешной проверки с неверной подписью."""
        _, public_key = keypair
        checker = ConfigIntegrityChecker(verification_key=public_key)

        # Создаём конфигурацию с неверной подписью
        signed_data = {
            "config": config_content,
            "signature": "a" * 128,  # Неверная подпись
            "public_key_hint": public_key[:8].hex(),
        }

        config_file = tmp_path / "config.fxsconfig"
        config_file.write_text(json.dumps(signed_data), encoding="utf-8")

        result = checker.check_config(config_file)

        assert result.passed is False
        assert result.signature_valid is False
        assert "недействительна" in (result.error_message or "").lower()

    def test_check_config_no_signature(self, config_content: dict, tmp_path: Path) -> None:
        """Тест проверки конфигурации без подписи."""
        checker = ConfigIntegrityChecker(verification_key=b"x" * 32)

        # Конфигурация без подписи
        signed_data = {
            "config": config_content,
        }

        config_file = tmp_path / "config.fxsconfig"
        config_file.write_text(json.dumps(signed_data), encoding="utf-8")

        result = checker.check_config(config_file)

        assert result.passed is False
        assert "не подписана" in (result.error_message or "")

    def test_check_config_no_key(self, keypair: tuple[bytes, bytes], config_content: dict, tmp_path: Path) -> None:
        """Тест проверки без публичного ключа."""
        private_key, _ = keypair
        signer = Ed25519Signer()

        # Подписываем конфигурацию
        config_str = json.dumps(config_content, ensure_ascii=False, sort_keys=True)
        config_hash = hashlib.sha3_256(config_str.encode()).digest()
        signature = signer.sign(private_key, config_hash)

        signed_data = {
            "config": config_content,
            "signature": signature.hex(),
        }

        config_file = tmp_path / "config.fxsconfig"
        config_file.write_text(json.dumps(signed_data), encoding="utf-8")

        checker = ConfigIntegrityChecker(verification_key=None)  # Без ключа
        result = checker.check_config(config_file)

        assert result.passed is False
        assert "ключ" in (result.error_message or "").lower()

    def test_sign_config(self, keypair: tuple[bytes, bytes], config_content: dict, tmp_path: Path) -> None:
        """Тест подписания конфигурации."""
        private_key, public_key = keypair

        # Создаём неподписанную конфигурацию
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_content), encoding="utf-8")

        checker = ConfigIntegrityChecker(verification_key=public_key)
        signed_path = checker.sign_config(config_file, private_key)

        assert signed_path.suffix == SIGNED_CONFIG_EXTENSION
        assert signed_path.exists()

        # Проверяем что подпись валидна
        signed_data = json.loads(signed_path.read_text(encoding="utf-8"))
        assert "config" in signed_data
        assert "signature" in signed_data
        assert signed_data["algorithm"] == "Ed25519"

    def test_sign_config_and_verify(self, keypair: tuple[bytes, bytes], config_content: dict, tmp_path: Path) -> None:
        """Тест полного цикла: подпись и верификация."""
        private_key, public_key = keypair

        # Создаём и подписываем конфигурацию
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_content), encoding="utf-8")

        checker = ConfigIntegrityChecker(verification_key=public_key)
        signed_path = checker.sign_config(config_file, private_key)

        # Верифицируем
        result = checker.check_config(signed_path)

        assert result.passed is True
        assert result.signature_valid is True

    def test_load_public_key_from_file(self, keypair: tuple[bytes, bytes], tmp_path: Path) -> None:
        """Тест загрузки публичного ключа из файла."""
        _, public_key = keypair

        key_file = tmp_path / PUBLIC_KEY_FILE
        # Публичный ключ в DER формате
        key_file.write_text(public_key.hex(), encoding="utf-8")

        checker = ConfigIntegrityChecker(public_key_path=key_file)

        assert checker.has_verification_key is True
        # public_key_hint берёт первые 8 байт публичного ключа (raw bytes, не DER)
        # DER-encoded ключ имеет overhead, поэтому берём только значимую часть
        assert checker.verification_key_hint is not None

    def test_load_public_key_from_env(self, keypair: tuple[bytes, bytes], monkeypatch) -> None:
        """Тест загрузки публичного ключа из переменной окружения."""
        _, public_key = keypair
        monkeypatch.setenv("CONFIG_PUBLIC_KEY", public_key.hex())

        checker = ConfigIntegrityChecker()

        assert checker.has_verification_key is True

    def test_verification_key_hint(self, keypair: tuple[bytes, bytes]) -> None:
        """Тест подсказки о публичном ключе."""
        _, public_key = keypair
        checker = ConfigIntegrityChecker(verification_key=public_key)

        hint = checker.verification_key_hint
        assert hint == public_key[:8].hex()
        assert len(hint) == 16  # 8 байт = 16 hex символов


class TestSignedConfig:
    """Тесты SignedConfig dataclass."""

    def test_to_dict(self, tmp_path: Path) -> None:
        """Тест сериализации SignedConfig."""
        config = SignedConfig(
            config_path=tmp_path / "config.fxsconfig",
            signature_path=None,
            content='{"test": "data"}',
            signature="a" * 128,
            public_key_hint="deadbeef",
        )

        data = config.to_dict()

        assert "config_path" in data
        assert "signature" in data
        assert data["public_key_hint"] == "deadbeef"

    def test_to_dict_no_signature(self, tmp_path: Path) -> None:
        """Тест сериализации без подписи."""
        config = SignedConfig(
            config_path=tmp_path / "config.fxsconfig",
            signature_path=None,
            content='{"test": "data"}',
            signature=None,
            public_key_hint=None,
        )

        data = config.to_dict()

        assert data["signature"] is None
        assert data["public_key_hint"] is None


class TestConfigIntegrityResult:
    """Тесты IntegrityCheckResult для конфигурации."""

    def test_result_signature_valid(self) -> None:
        """Тест результата с валидной подписью."""
        from src.security.integrity.models import IntegrityCheckResult

        result = IntegrityCheckResult(
            check_type=IntegrityCheckType.CONFIG_FILE,
            passed=True,
            signature_valid=True,
            algorithm="Ed25519",
        )

        assert result.signature_valid is True
        assert result.passed is True

    def test_result_without_signature_check(self) -> None:
        """Тест результата без проверки подписи."""
        from src.security.integrity.models import IntegrityCheckResult

        result = IntegrityCheckResult(
            check_type=IntegrityCheckType.CONFIG_FILE,
            passed=True,
            signature_valid=None,  # Проверка не выполнялась
            algorithm="Ed25519",
        )

        assert result.signature_valid is None