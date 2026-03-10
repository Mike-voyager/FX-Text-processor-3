"""
Тесты для модуля управления ключами (KeyManager).

Покрытие:
- import_key: все форматы (RAW/PEM/DER/COMPACT/JWK/PKCS8), пустые данные
- export_key: все форматы, пустой ключ
- import_key/export_key: roundtrip для всех форматов
- wrap_key: нормальный сценарий, пустой key_to_wrap, неверный размер wrapping_key,
  AlgorithmNotSupportedError пробрасывается, общее исключение оборачивается
- unwrap_key: нормальный сценарий, пустой wrapped, неверный размер wrapping_key,
  слишком короткие данные, AlgorithmNotSupportedError пробрасывается,
  общее исключение оборачивается
- wrap→unwrap roundtrip через мок
- generate_wrapping_key: длина, уникальность, логирование
- Логирование DEBUG/INFO для import/export/wrap/unwrap/generate

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 10, 2026
"""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import logging
import os
from unittest.mock import MagicMock, patch

import pytest
from src.security.crypto.core.exceptions import (
    AlgorithmNotSupportedError,
    DecryptionFailedError,
    EncryptionFailedError,
    InvalidParameterError,
)
from src.security.crypto.utilities.key_management import (
    _DEFAULT_WRAP_ALGORITHM,  # noqa: PLC2701
    _WRAPPING_KEY_SIZE,  # noqa: PLC2701
    KeyManager,
)
from src.security.crypto.utilities.serialization import KeyFormat

# ==============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================================================

_ALGO = "aes-256-gcm"
_KEY_32 = b"\xab" * 32
_KEY_16 = b"\xcd" * 16
_NONCE_12 = b"\x00" * 12


def _make_registry(
    nonce: bytes = _NONCE_12,
    ciphertext: bytes = b"\xff" * 32,
    plaintext: bytes = _KEY_32,
) -> MagicMock:
    """Создаёт mock AlgorithmRegistry с настроенным cipher."""
    cipher = MagicMock()
    cipher.nonce_size = len(nonce)
    cipher.encrypt.return_value = (nonce, ciphertext)
    cipher.decrypt.return_value = plaintext

    registry = MagicMock()
    registry.create.return_value = cipher
    return registry


def _manager_with_mock_registry(**kwargs: object) -> tuple[KeyManager, MagicMock]:
    registry = _make_registry(**kwargs)  # type: ignore[arg-type]
    return KeyManager(registry), registry  # type: ignore[arg-type]


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def registry() -> MagicMock:
    return _make_registry()


@pytest.fixture
def manager(registry: MagicMock) -> KeyManager:
    return KeyManager(registry)  # type: ignore[arg-type]


# ==============================================================================
# KeyManager.__init__
# ==============================================================================


class TestInit:
    def test_stores_registry(self, registry: MagicMock) -> None:
        mgr = KeyManager(registry)  # type: ignore[arg-type]
        assert mgr._registry is registry

    def test_logs_debug_on_init(
        self, registry: MagicMock, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.DEBUG, logger="src.security.crypto.utilities.key_management"):
            KeyManager(registry)  # type: ignore[arg-type]

        assert any("KeyManager" in r.message for r in caplog.records)


# ==============================================================================
# import_key
# ==============================================================================


class TestImportKey:
    def test_raw_returns_same_bytes(self, manager: KeyManager) -> None:
        result = manager.import_key(_KEY_32, KeyFormat.RAW, _ALGO)
        assert result == _KEY_32

    def test_pem_roundtrip(self, manager: KeyManager) -> None:
        from src.security.crypto.utilities.serialization import serialize_key

        pem = serialize_key(_KEY_32, KeyFormat.PEM, _ALGO)
        result = manager.import_key(pem, KeyFormat.PEM, _ALGO)
        assert result == _KEY_32

    def test_der_roundtrip(self, manager: KeyManager) -> None:
        from src.security.crypto.utilities.serialization import serialize_key

        der = serialize_key(_KEY_32, KeyFormat.DER, _ALGO)
        result = manager.import_key(der, KeyFormat.DER, _ALGO)
        assert result == _KEY_32

    def test_compact_roundtrip(self, manager: KeyManager) -> None:
        from src.security.crypto.utilities.serialization import serialize_key

        compact = serialize_key(_KEY_32, KeyFormat.COMPACT, _ALGO)
        result = manager.import_key(compact, KeyFormat.COMPACT, _ALGO)
        assert result == _KEY_32

    def test_jwk_roundtrip(self, manager: KeyManager) -> None:
        from src.security.crypto.utilities.serialization import serialize_key

        jwk = serialize_key(_KEY_32, KeyFormat.JWK, _ALGO)
        result = manager.import_key(jwk, KeyFormat.JWK, _ALGO)
        assert result == _KEY_32

    def test_pkcs8_roundtrip(self, manager: KeyManager) -> None:
        from src.security.crypto.utilities.serialization import serialize_key

        pkcs8 = serialize_key(_KEY_32, KeyFormat.PKCS8, _ALGO)
        result = manager.import_key(pkcs8, KeyFormat.PKCS8, _ALGO)
        assert result == _KEY_32

    def test_empty_data_raises(self, manager: KeyManager) -> None:
        with pytest.raises(InvalidParameterError, match="data"):
            manager.import_key(b"", KeyFormat.RAW, _ALGO)

    def test_logs_debug_on_success(
        self, manager: KeyManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.DEBUG, logger="src.security.crypto.utilities.key_management"):
            manager.import_key(_KEY_32, KeyFormat.RAW, _ALGO)

        assert any("imported" in r.message.lower() for r in caplog.records)


# ==============================================================================
# export_key
# ==============================================================================


class TestExportKey:
    def test_raw_returns_same_bytes(self, manager: KeyManager) -> None:
        result = manager.export_key(_KEY_32, KeyFormat.RAW, _ALGO)
        assert result == _KEY_32

    @pytest.mark.parametrize(
        "fmt",
        [KeyFormat.PEM, KeyFormat.DER, KeyFormat.COMPACT, KeyFormat.JWK, KeyFormat.PKCS8],
        ids=["pem", "der", "compact", "jwk", "pkcs8"],
    )
    def test_export_produces_bytes(self, manager: KeyManager, fmt: KeyFormat) -> None:
        result = manager.export_key(_KEY_32, fmt, _ALGO)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_empty_key_raises(self, manager: KeyManager) -> None:
        with pytest.raises(InvalidParameterError, match="key"):
            manager.export_key(b"", KeyFormat.RAW, _ALGO)

    def test_logs_debug_on_success(
        self, manager: KeyManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.DEBUG, logger="src.security.crypto.utilities.key_management"):
            manager.export_key(_KEY_32, KeyFormat.RAW, _ALGO)

        assert any("exported" in r.message.lower() for r in caplog.records)


# ==============================================================================
# export_key / import_key roundtrip (все форматы)
# ==============================================================================


class TestImportExportRoundtrip:
    @pytest.mark.parametrize(
        "fmt",
        [KeyFormat.RAW, KeyFormat.PEM, KeyFormat.DER, KeyFormat.COMPACT, KeyFormat.JWK],
        ids=["raw", "pem", "der", "compact", "jwk"],
    )
    def test_roundtrip(self, manager: KeyManager, fmt: KeyFormat) -> None:
        exported = manager.export_key(_KEY_32, fmt, _ALGO)
        imported = manager.import_key(exported, fmt, _ALGO)
        assert imported == _KEY_32

    @pytest.mark.parametrize(
        "key_size",
        [16, 24, 32],
        ids=["128bit", "192bit", "256bit"],
    )
    def test_different_key_sizes_raw(self, manager: KeyManager, key_size: int) -> None:
        key = os.urandom(key_size)
        exported = manager.export_key(key, KeyFormat.RAW, _ALGO)
        imported = manager.import_key(exported, KeyFormat.RAW, _ALGO)
        assert imported == key


# ==============================================================================
# wrap_key
# ==============================================================================


class TestWrapKey:
    def test_normal_returns_nonce_plus_ciphertext(self) -> None:
        nonce = b"\x01" * 12
        ciphertext = b"\xff" * 32
        mgr, reg = _manager_with_mock_registry(nonce=nonce, ciphertext=ciphertext)

        result = mgr.wrap_key(_KEY_32, _KEY_32)

        assert result == nonce + ciphertext
        reg.create.assert_called_once_with(_DEFAULT_WRAP_ALGORITHM)
        reg.create.return_value.encrypt.assert_called_once_with(_KEY_32, _KEY_32)

    def test_custom_algorithm_passed_to_registry(self) -> None:
        mgr, reg = _manager_with_mock_registry()

        mgr.wrap_key(_KEY_32, _KEY_32, algorithm="chacha20-poly1305")

        reg.create.assert_called_once_with("chacha20-poly1305")

    def test_empty_key_to_wrap_raises(self, manager: KeyManager) -> None:
        with pytest.raises(EncryptionFailedError, match="key_to_wrap"):
            manager.wrap_key(b"", _KEY_32)

    def test_wrong_wrapping_key_size_raises(self, manager: KeyManager) -> None:
        with pytest.raises(EncryptionFailedError, match="wrapping_key"):
            manager.wrap_key(_KEY_32, b"\x00" * 16)

    def test_algorithm_not_supported_propagates(self) -> None:
        registry = MagicMock()
        registry.create.side_effect = AlgorithmNotSupportedError("unknown-algo", "not installed")
        mgr = KeyManager(registry)  # type: ignore[arg-type]

        with pytest.raises(AlgorithmNotSupportedError):
            mgr.wrap_key(_KEY_32, _KEY_32)

    def test_generic_exception_wrapped_as_encryption_error(self) -> None:
        registry = MagicMock()
        registry.create.side_effect = RuntimeError("cipher failed")
        mgr = KeyManager(registry)  # type: ignore[arg-type]

        with pytest.raises(EncryptionFailedError, match="cipher failed"):
            mgr.wrap_key(_KEY_32, _KEY_32)

    def test_logs_info_on_success(
        self, manager: KeyManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger="src.security.crypto.utilities.key_management"):
            manager.wrap_key(_KEY_32, _KEY_32)

        assert any("wrapped" in r.message.lower() for r in caplog.records)


# ==============================================================================
# unwrap_key
# ==============================================================================


class TestUnwrapKey:
    def test_normal_splits_nonce_and_calls_decrypt(self) -> None:
        nonce = b"\x01" * 12
        ciphertext = b"\xff" * 32
        wrapped = nonce + ciphertext
        expected_plaintext = _KEY_32
        mgr, reg = _manager_with_mock_registry(nonce=nonce, plaintext=expected_plaintext)

        result = mgr.unwrap_key(wrapped, _KEY_32)

        assert result == expected_plaintext
        cipher = reg.create.return_value
        cipher.decrypt.assert_called_once_with(_KEY_32, nonce, ciphertext)

    def test_custom_algorithm_passed_to_registry(self) -> None:
        nonce = b"\x00" * 12
        wrapped = nonce + b"\xff" * 32
        mgr, reg = _manager_with_mock_registry(nonce=nonce)

        mgr.unwrap_key(wrapped, _KEY_32, algorithm="chacha20-poly1305")

        reg.create.assert_called_once_with("chacha20-poly1305")

    def test_empty_wrapped_raises(self, manager: KeyManager) -> None:
        with pytest.raises(DecryptionFailedError, match="wrapped"):
            manager.unwrap_key(b"", _KEY_32)

    def test_wrong_wrapping_key_size_raises(self, manager: KeyManager) -> None:
        with pytest.raises(DecryptionFailedError, match="wrapping_key"):
            manager.unwrap_key(b"\x00" * 50, b"\x00" * 16)

    def test_too_short_data_raises(self) -> None:
        """Данные короче nonce_size + AEAD_TAG_SIZE вызывают ошибку."""
        # cipher.nonce_size=12, AEAD_TAG_SIZE=16 → min=28
        registry = MagicMock()
        cipher = MagicMock()
        cipher.nonce_size = 12
        registry.create.return_value = cipher
        mgr = KeyManager(registry)  # type: ignore[arg-type]

        # 27 байт < 28 — слишком коротко
        with pytest.raises(DecryptionFailedError, match="коротк"):
            mgr.unwrap_key(b"\x00" * 27, _KEY_32)

    def test_exactly_min_size_does_not_raise_length_check(self) -> None:
        """Ровно min_size байт проходит проверку длины (cipher.decrypt может выбросить)."""
        nonce = b"\x00" * 12
        tag = b"\x00" * 16
        wrapped = nonce + tag  # 12 + 16 = 28 = min_size

        registry = MagicMock()
        cipher = MagicMock()
        cipher.nonce_size = 12
        cipher.decrypt.return_value = b"\xaa" * 16
        registry.create.return_value = cipher
        mgr = KeyManager(registry)  # type: ignore[arg-type]

        result = mgr.unwrap_key(wrapped, _KEY_32)

        assert result == b"\xaa" * 16

    def test_algorithm_not_supported_propagates(self) -> None:
        registry = MagicMock()
        registry.create.side_effect = AlgorithmNotSupportedError("no-algo", "not installed")
        mgr = KeyManager(registry)  # type: ignore[arg-type]

        with pytest.raises(AlgorithmNotSupportedError):
            mgr.unwrap_key(b"\x00" * 50, _KEY_32)

    def test_generic_exception_wrapped_as_decryption_error(self) -> None:
        registry = MagicMock()
        registry.create.side_effect = ValueError("bad data")
        mgr = KeyManager(registry)  # type: ignore[arg-type]

        with pytest.raises(DecryptionFailedError, match="bad data"):
            mgr.unwrap_key(b"\x00" * 50, _KEY_32)

    def test_logs_info_on_success(
        self, manager: KeyManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        nonce = b"\x00" * 12
        wrapped = nonce + b"\xff" * 32
        with caplog.at_level(logging.INFO, logger="src.security.crypto.utilities.key_management"):
            manager.unwrap_key(wrapped, _KEY_32)

        assert any("unwrapped" in r.message.lower() for r in caplog.records)


# ==============================================================================
# wrap → unwrap roundtrip через мок
# ==============================================================================


class TestWrapUnwrapRoundtrip:
    def test_roundtrip_preserves_key(self) -> None:
        """wrap→unwrap возвращает исходный ключ."""
        original_key = b"\xde\xad\xbe\xef" * 8  # 32 байта
        nonce = os.urandom(12)

        # Настраиваем мок: encrypt возвращает (nonce, "зашифрованные" данные),
        # decrypt возвращает исходный ключ.
        fake_ciphertext = b"\x11" * 32
        registry = MagicMock()
        cipher = MagicMock()
        cipher.nonce_size = 12
        cipher.encrypt.return_value = (nonce, fake_ciphertext)
        cipher.decrypt.return_value = original_key
        registry.create.return_value = cipher

        mgr = KeyManager(registry)  # type: ignore[arg-type]
        wrapped = mgr.wrap_key(original_key, _KEY_32)
        unwrapped = mgr.unwrap_key(wrapped, _KEY_32)

        assert unwrapped == original_key

    def test_wrapped_contains_nonce_prefix(self) -> None:
        """Первые nonce_size байт результата wrap — это nonce."""
        nonce = b"\xaa" * 12
        ciphertext = b"\xbb" * 32
        mgr, _ = _manager_with_mock_registry(nonce=nonce, ciphertext=ciphertext)

        wrapped = mgr.wrap_key(_KEY_32, _KEY_32)

        assert wrapped[:12] == nonce
        assert wrapped[12:] == ciphertext


# ==============================================================================
# generate_wrapping_key
# ==============================================================================


class TestGenerateWrappingKey:
    def test_returns_32_bytes(self, manager: KeyManager) -> None:
        key = manager.generate_wrapping_key()
        assert len(key) == _WRAPPING_KEY_SIZE

    def test_returns_bytes(self, manager: KeyManager) -> None:
        assert isinstance(manager.generate_wrapping_key(), bytes)

    def test_keys_are_unique(self, manager: KeyManager) -> None:
        keys = {manager.generate_wrapping_key() for _ in range(10)}
        assert len(keys) == 10

    def test_uses_os_urandom(self, manager: KeyManager) -> None:
        with patch("os.urandom", return_value=b"\xab" * 32) as mock_urandom:
            key = manager.generate_wrapping_key()

        mock_urandom.assert_called_once_with(_WRAPPING_KEY_SIZE)
        assert key == b"\xab" * 32

    def test_logs_info(self, manager: KeyManager, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger="src.security.crypto.utilities.key_management"):
            manager.generate_wrapping_key()

        assert any("wrapping key" in r.message.lower() for r in caplog.records)


# ==============================================================================
# Интеграционные тесты с реальным AlgorithmRegistry (без моков)
# ==============================================================================


@pytest.mark.integration
class TestWrapUnwrapIntegration:
    """
    Тесты с реальным AES-256-GCM через AlgorithmRegistry.
    Проверяют, что wrap→unwrap реально шифрует и расшифровывает.
    """

    @pytest.fixture
    def real_manager(self) -> KeyManager:
        from src.security.crypto.core.registry import AlgorithmRegistry, register_all_algorithms

        register_all_algorithms()
        return KeyManager(AlgorithmRegistry.get_instance())

    def test_real_wrap_unwrap_roundtrip(self, real_manager: KeyManager) -> None:
        """Реальное шифрование: unwrap возвращает исходный ключ."""
        data_key = os.urandom(32)
        wrapping_key = real_manager.generate_wrapping_key()

        wrapped = real_manager.wrap_key(data_key, wrapping_key)
        unwrapped = real_manager.unwrap_key(wrapped, wrapping_key)

        assert unwrapped == data_key

    def test_wrong_wrapping_key_fails_decryption(self, real_manager: KeyManager) -> None:
        """Неверный KEK приводит к ошибке расшифровки."""
        data_key = os.urandom(32)
        correct_kek = real_manager.generate_wrapping_key()
        wrong_kek = real_manager.generate_wrapping_key()

        wrapped = real_manager.wrap_key(data_key, correct_kek)

        with pytest.raises(DecryptionFailedError):
            real_manager.unwrap_key(wrapped, wrong_kek)

    def test_wrapped_output_differs_each_time(self, real_manager: KeyManager) -> None:
        """Каждый wrap даёт разный nonce → разные байты."""
        data_key = os.urandom(32)
        kek = real_manager.generate_wrapping_key()

        wrapped1 = real_manager.wrap_key(data_key, kek)
        wrapped2 = real_manager.wrap_key(data_key, kek)

        assert wrapped1 != wrapped2  # разные nonce

    def test_tampered_ciphertext_fails(self, real_manager: KeyManager) -> None:
        """Повреждение шифртекста вызывает ошибку (AEAD integrity)."""
        data_key = os.urandom(32)
        kek = real_manager.generate_wrapping_key()

        wrapped = real_manager.wrap_key(data_key, kek)
        # Портим последний байт
        tampered = wrapped[:-1] + bytes([wrapped[-1] ^ 0xFF])

        with pytest.raises(DecryptionFailedError):
            real_manager.unwrap_key(tampered, kek)
