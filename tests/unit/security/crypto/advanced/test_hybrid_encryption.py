"""
Тесты для модуля гибридного шифрования.

Тестирует hybrid_encryption.py: KEX + Symmetric cipher паттерн.
Покрывает все 4 preset конфигурации (classical + PQC).

Test Coverage:
- All 4 presets (classical_standard, classical_paranoid, pqc_standard, pqc_paranoid)
- Round-trip encryption/decryption
- Large data encryption (no size limits)
- Error handling (invalid keys, missing fields, wrong keys)
- Security properties (ephemeral keys, Perfect Forward Secrecy)
- Edge cases (empty data, corrupted ciphertext)

Version: 1.0
Date: February 10, 2026
"""

from __future__ import annotations

import pytest
import logging
from typing import Any, Dict, Iterator

from src.security.crypto.advanced.hybrid_encryption import (
    HybridEncryption,
    HybridConfig,
    PRESETS,
    create_hybrid_cipher,
)
from src.security.crypto.core.exceptions import (
    AlgorithmNotSupportedError,
    DecryptionFailedError,
    EncryptionError,
    InvalidKeyError,
)

from src.security.crypto.core.registry import AlgorithmRegistry, register_all_algorithms

# Настройка логирования для тестов
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture(scope="session", autouse=True)
def setup_crypto_registry() -> Iterator[AlgorithmRegistry]:
    """Регистрация алгоритмов перед тестами."""
    from src.security.crypto.core.registry import register_all_algorithms

    registry = AlgorithmRegistry.get_instance()

    if len(registry.list_algorithms()) == 0:
        print("\n🔧 Registering cryptographic algorithms...")
        register_all_algorithms()

        total = len(registry.list_algorithms())
        print(f"✅ Registered {total} algorithms")

    yield registry


@pytest.fixture
def plaintext() -> bytes:
    """Sample plaintext для тестов."""
    return b"Secret message for hybrid encryption testing"


@pytest.fixture
def large_plaintext() -> bytes:
    """Large plaintext для проверки отсутствия size limits."""
    return b"X" * (10 * 1024 * 1024)  # 10 MB


@pytest.fixture(
    params=[
        "classical_standard",
        "classical_paranoid",
        "pqc_standard",  # Uncomment if liboqs-python available
        "pqc_paranoid",  # Uncomment if liboqs-python available
    ]
)
def cipher_preset(request: pytest.FixtureRequest) -> str:
    """Параметризованный preset для тестирования всех конфигураций."""
    return str(request.param)


@pytest.fixture
def cipher(cipher_preset: str) -> HybridEncryption:
    """Создать cipher для заданного preset."""
    return create_hybrid_cipher(cipher_preset)


@pytest.fixture
def recipient_keypair(cipher: HybridEncryption) -> tuple[bytes, bytes]:
    """Генерация keypair для получателя."""
    return cipher.generate_recipient_keypair()


# ==============================================================================
# TEST: CONFIGURATION
# ==============================================================================


class TestConfiguration:
    """Тесты конфигурации и presets."""

    def test_all_presets_exist(self) -> None:
        """Проверка наличия всех 4 presets."""
        expected_presets = {
            "classical_standard",
            "classical_paranoid",
            "pqc_standard",
            "pqc_paranoid",
        }
        assert set(PRESETS.keys()) == expected_presets

    def test_preset_structure(self) -> None:
        """Проверка структуры каждого preset."""
        for name, config in PRESETS.items():
            assert isinstance(config, HybridConfig)
            assert config.kex_algorithm in [
                "x25519",
                "x448",
                "ml-kem-768",
                "ml-kem-1024",
            ]
            assert config.symmetric_algorithm in ["aes-256-gcm", "chacha20-poly1305"]
            assert config.name
            assert config.description

    def test_classical_standard_config(self) -> None:
        """Проверка classical_standard конфигурации."""
        config = PRESETS["classical_standard"]
        assert config.kex_algorithm == "x25519"
        assert config.symmetric_algorithm == "aes-256-gcm"
        assert "X25519" in config.name or "Classical" in config.name

    def test_classical_paranoid_config(self) -> None:
        """Проверка classical_paranoid конфигурации."""
        config = PRESETS["classical_paranoid"]
        assert config.kex_algorithm == "x448"
        assert config.symmetric_algorithm == "chacha20-poly1305"
        assert "X448" in config.name or "Paranoid" in config.name

    def test_pqc_standard_config(self) -> None:
        """Проверка pqc_standard конфигурации."""
        config = PRESETS["pqc_standard"]
        assert config.kex_algorithm == "ml-kem-768"
        assert config.symmetric_algorithm == "aes-256-gcm"
        assert "Kyber" in config.name or "Quantum" in config.name

    def test_pqc_paranoid_config(self) -> None:
        """Проверка pqc_paranoid конфигурации."""
        config = PRESETS["pqc_paranoid"]
        assert config.kex_algorithm == "ml-kem-1024"
        assert config.symmetric_algorithm == "chacha20-poly1305"


# ==============================================================================
# TEST: FACTORY FUNCTION
# ==============================================================================


class TestFactory:
    """Тесты factory function create_hybrid_cipher()."""

    def test_create_default_cipher(self) -> None:
        """Создание cipher с default preset."""
        cipher = create_hybrid_cipher()
        assert isinstance(cipher, HybridEncryption)

    def test_create_with_preset(self) -> None:
        """Создание cipher с явным preset."""
        cipher = create_hybrid_cipher("classical_standard")
        assert isinstance(cipher, HybridEncryption)

    def test_create_unknown_preset(self) -> None:
        """Ошибка при неизвестном preset."""
        with pytest.raises(ValueError, match="Unknown preset"):
            create_hybrid_cipher("unknown_preset")

    @pytest.mark.parametrize(
        "preset",
        ["classical_standard", "classical_paranoid"],
    )
    def test_create_all_classical_presets(self, preset: str) -> None:
        """Создание всех classical presets."""
        cipher = create_hybrid_cipher(preset)
        assert isinstance(cipher, HybridEncryption)

    @pytest.mark.skipif(
        True,  # Change to False if liboqs-python available
        reason="Requires liboqs-python for PQC algorithms",
    )
    @pytest.mark.parametrize(
        "preset",
        ["pqc_standard", "pqc_paranoid"],
    )
    def test_create_all_pqc_presets(self, preset: str) -> None:
        """Создание всех PQC presets (requires liboqs-python)."""
        cipher = create_hybrid_cipher(preset)
        assert isinstance(cipher, HybridEncryption)


# ==============================================================================
# TEST: KEYPAIR GENERATION
# ==============================================================================


class TestKeypairGeneration:
    """Тесты генерации keypair для получателя."""

    def test_generate_keypair(self, cipher: HybridEncryption) -> None:
        """Генерация keypair."""
        private_key, public_key = cipher.generate_recipient_keypair()

        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert len(private_key) > 0
        assert len(public_key) > 0

    def test_keypair_uniqueness(self, cipher: HybridEncryption) -> None:
        """Каждый keypair должен быть уникальным."""
        priv1, pub1 = cipher.generate_recipient_keypair()
        priv2, pub2 = cipher.generate_recipient_keypair()

        assert priv1 != priv2
        assert pub1 != pub2

    def test_keypair_format(self, cipher: HybridEncryption) -> None:
        """Проверка формата keypair."""
        private_key, public_key = cipher.generate_recipient_keypair()

        # Keys должны быть bytes (raw format, не PEM)
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)

        # Public key должен быть меньше или равен private key
        # (для most KEX algorithms)
        assert len(public_key) <= len(private_key) * 2


# ==============================================================================
# TEST: ENCRYPTION
# ==============================================================================


class TestEncryption:
    """Тесты шифрования."""

    def test_encrypt_basic(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Базовое шифрование."""
        _, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        assert isinstance(encrypted, dict)
        assert "ephemeral_public_key" in encrypted
        assert "nonce" in encrypted
        assert "ciphertext" in encrypted

        assert isinstance(encrypted["ephemeral_public_key"], bytes)
        assert isinstance(encrypted["nonce"], bytes)
        assert isinstance(encrypted["ciphertext"], bytes)

    def test_encrypt_output_structure(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Проверка структуры encrypted output."""
        _, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        # Должны быть ровно 3 поля
        assert len(encrypted) == 3

        # Ephemeral public key должен быть non-empty
        assert len(encrypted["ephemeral_public_key"]) > 0

        # Nonce должен быть 12 bytes (GCM) или 24 bytes (XChaCha20)
        assert len(encrypted["nonce"]) in [12, 24]

        # Ciphertext должен быть больше plaintext (AEAD tag added)
        assert len(encrypted["ciphertext"]) >= len(plaintext)

    def test_encrypt_empty_plaintext(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
    ) -> None:
        """Ошибка при пустом plaintext."""
        _, public_key = recipient_keypair

        with pytest.raises(ValueError, match="empty plaintext"):
            cipher.encrypt_for_recipient(public_key, b"")

    def test_encrypt_empty_public_key(
        self,
        cipher: HybridEncryption,
        plaintext: bytes,
    ) -> None:
        """Ошибка при пустом public key."""
        with pytest.raises(ValueError, match="empty"):
            cipher.encrypt_for_recipient(b"", plaintext)

    def test_encrypt_invalid_public_key(
        self,
        cipher: HybridEncryption,
        plaintext: bytes,
    ) -> None:
        """Ошибка при некорректном public key."""
        invalid_key = b"invalid_key_too_short"

        with pytest.raises((InvalidKeyError, EncryptionError)):
            cipher.encrypt_for_recipient(invalid_key, plaintext)

    def test_encrypt_large_data(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        large_plaintext: bytes,
    ) -> None:
        """Шифрование больших данных (no size limits)."""
        _, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, large_plaintext)

        assert isinstance(encrypted, dict)
        # Ciphertext должен быть примерно равен plaintext + AEAD tag
        assert len(encrypted["ciphertext"]) >= len(large_plaintext)

    def test_encrypt_ephemeral_key_uniqueness(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ephemeral key должен быть уникальным для каждого сообщения."""
        _, public_key = recipient_keypair

        encrypted1 = cipher.encrypt_for_recipient(public_key, plaintext)
        encrypted2 = cipher.encrypt_for_recipient(public_key, plaintext)

        # Ephemeral keys должны отличаться (Perfect Forward Secrecy!)
        assert encrypted1["ephemeral_public_key"] != encrypted2["ephemeral_public_key"]

        # Nonces тоже должны отличаться
        assert encrypted1["nonce"] != encrypted2["nonce"]

        # Ciphertexts должны отличаться
        assert encrypted1["ciphertext"] != encrypted2["ciphertext"]


# ==============================================================================
# TEST: DECRYPTION
# ==============================================================================


class TestDecryption:
    """Тесты расшифровки."""

    def test_decrypt_basic(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Базовая расшифровка."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)
        decrypted = cipher.decrypt_from_sender(private_key, encrypted)

        assert decrypted == plaintext

    def test_decrypt_empty_private_key(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ошибка при пустом private key."""
        _, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        with pytest.raises(ValueError, match="empty"):
            cipher.decrypt_from_sender(b"", encrypted)

    def test_decrypt_invalid_private_key(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ошибка при некорректном private key."""
        _, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)
        invalid_key = b"invalid_key_too_short"

        with pytest.raises((InvalidKeyError, DecryptionFailedError)):
            cipher.decrypt_from_sender(invalid_key, encrypted)

    def test_decrypt_wrong_private_key(
        self,
        cipher: HybridEncryption,
        plaintext: bytes,
    ) -> None:
        """Ошибка при использовании wrong private key."""
        # Generate two keypairs
        priv1, pub1 = cipher.generate_recipient_keypair()
        priv2, pub2 = cipher.generate_recipient_keypair()

        # Encrypt for recipient 1
        encrypted = cipher.encrypt_for_recipient(pub1, plaintext)

        # Try to decrypt with recipient 2's private key
        with pytest.raises((InvalidKeyError, DecryptionFailedError)):
            cipher.decrypt_from_sender(priv2, encrypted)

    def test_decrypt_missing_field(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ошибка при отсутствующем поле в encrypted_data."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        # Remove required field
        del encrypted["nonce"]

        with pytest.raises(ValueError, match="Missing required fields"):
            cipher.decrypt_from_sender(private_key, encrypted)

    def test_decrypt_empty_field(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ошибка при пустом поле в encrypted_data."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        # Set field to empty
        encrypted["ciphertext"] = b""

        with pytest.raises(ValueError, match="cannot be empty"):
            cipher.decrypt_from_sender(private_key, encrypted)

    def test_decrypt_corrupted_ciphertext(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ошибка при испорченном ciphertext (AEAD tag fail)."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        # Corrupt ciphertext
        ciphertext = bytearray(encrypted["ciphertext"])
        ciphertext[0] ^= 0xFF  # Flip first byte
        encrypted["ciphertext"] = bytes(ciphertext)

        with pytest.raises(DecryptionFailedError):
            cipher.decrypt_from_sender(private_key, encrypted)

    def test_decrypt_corrupted_ephemeral_key(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ошибка при испорченном ephemeral public key."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        # Corrupt ephemeral key
        eph_key = bytearray(encrypted["ephemeral_public_key"])
        eph_key[0] ^= 0xFF
        encrypted["ephemeral_public_key"] = bytes(eph_key)

        with pytest.raises((InvalidKeyError, DecryptionFailedError)):
            cipher.decrypt_from_sender(private_key, encrypted)


# ==============================================================================
# TEST: ROUND-TRIP
# ==============================================================================


class TestRoundTrip:
    """Тесты полного цикла encrypt → decrypt."""

    def test_roundtrip_basic(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Round-trip: encrypt → decrypt."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)
        decrypted = cipher.decrypt_from_sender(private_key, encrypted)

        assert decrypted == plaintext

    def test_roundtrip_large_data(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        large_plaintext: bytes,
    ) -> None:
        """Round-trip с большими данными."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, large_plaintext)
        decrypted = cipher.decrypt_from_sender(private_key, encrypted)

        assert decrypted == large_plaintext

    @pytest.mark.parametrize(
        "data",
        [
            b"a",  # 1 byte
            b"Short",  # Few bytes
            b"X" * 1024,  # 1 KB
            b"Y" * 1024 * 1024,  # 1 MB
        ],
    )
    def test_roundtrip_various_sizes(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        data: bytes,
    ) -> None:
        """Round-trip с различными размерами данных."""
        private_key, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, data)
        decrypted = cipher.decrypt_from_sender(private_key, encrypted)

        assert decrypted == data

    def test_roundtrip_multiple_messages(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
    ) -> None:
        """Round-trip для множественных сообщений."""
        private_key, public_key = recipient_keypair

        messages = [
            b"Message 1",
            b"Message 2",
            b"Message 3",
        ]

        for msg in messages:
            encrypted = cipher.encrypt_for_recipient(public_key, msg)
            decrypted = cipher.decrypt_from_sender(private_key, encrypted)
            assert decrypted == msg

    def test_roundtrip_binary_data(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
    ) -> None:
        """Round-trip с бинарными данными."""
        private_key, public_key = recipient_keypair

        # Binary data with all byte values
        binary_data = bytes(range(256))

        encrypted = cipher.encrypt_for_recipient(public_key, binary_data)
        decrypted = cipher.decrypt_from_sender(private_key, encrypted)

        assert decrypted == binary_data


# ==============================================================================
# TEST: SECURITY PROPERTIES
# ==============================================================================


class TestSecurity:
    """Тесты security свойств."""

    def test_perfect_forward_secrecy(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Perfect Forward Secrecy: каждое сообщение с уникальным ephemeral key."""
        _, public_key = recipient_keypair

        encrypted1 = cipher.encrypt_for_recipient(public_key, plaintext)
        encrypted2 = cipher.encrypt_for_recipient(public_key, plaintext)

        # Ephemeral keys MUST differ
        assert encrypted1["ephemeral_public_key"] != encrypted2["ephemeral_public_key"]

    def test_ciphertext_differs_for_same_plaintext(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Один и тот же plaintext шифруется по-разному каждый раз."""
        _, public_key = recipient_keypair

        encrypted1 = cipher.encrypt_for_recipient(public_key, plaintext)
        encrypted2 = cipher.encrypt_for_recipient(public_key, plaintext)

        # Ciphertexts должны отличаться (разные ephemeral keys + nonces)
        assert encrypted1["ciphertext"] != encrypted2["ciphertext"]

    def test_ciphertext_not_equal_plaintext(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Ciphertext не должен содержать plaintext в явном виде."""
        _, public_key = recipient_keypair

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)

        # Plaintext не должен быть в ciphertext
        assert plaintext not in encrypted["ciphertext"]
        assert plaintext not in encrypted["ephemeral_public_key"]
        assert plaintext not in encrypted["nonce"]

    def test_different_recipients(
        self,
        cipher: HybridEncryption,
        plaintext: bytes,
    ) -> None:
        """Шифрование для разных получателей дает разные ciphertexts."""
        # Generate keypairs for two recipients
        priv1, pub1 = cipher.generate_recipient_keypair()
        priv2, pub2 = cipher.generate_recipient_keypair()

        # Encrypt same plaintext for both
        encrypted1 = cipher.encrypt_for_recipient(pub1, plaintext)
        encrypted2 = cipher.encrypt_for_recipient(pub2, plaintext)

        # Ciphertexts должны отличаться
        assert encrypted1["ciphertext"] != encrypted2["ciphertext"]

        # Both can decrypt correctly
        decrypted1 = cipher.decrypt_from_sender(priv1, encrypted1)
        decrypted2 = cipher.decrypt_from_sender(priv2, encrypted2)

        assert decrypted1 == plaintext
        assert decrypted2 == plaintext


# ==============================================================================
# TEST: EDGE CASES
# ==============================================================================


class TestEdgeCases:
    """Тесты edge cases."""

    def test_single_byte_plaintext(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
    ) -> None:
        """Шифрование 1 байта."""
        private_key, public_key = recipient_keypair
        plaintext = b"X"

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)
        decrypted = cipher.decrypt_from_sender(private_key, encrypted)

        assert decrypted == plaintext

    def test_maximum_plaintext_size(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
    ) -> None:
        """Проверка отсутствия size limits (в отличие от RSA)."""
        private_key, public_key = recipient_keypair

        # 100 MB plaintext (RSA-OAEP would fail at ~190 bytes!)
        huge_plaintext = b"Z" * (100 * 1024 * 1024)

        encrypted = cipher.encrypt_for_recipient(public_key, huge_plaintext)
        # Don't decrypt (too slow), just check encryption succeeded
        assert isinstance(encrypted, dict)
        assert len(encrypted["ciphertext"]) >= len(huge_plaintext)

    def test_unicode_plaintext_encoded(
        self,
        cipher: HybridEncryption,
        recipient_keypair: tuple[bytes, bytes],
    ) -> None:
        """Шифрование Unicode текста (encoded to bytes)."""
        private_key, public_key = recipient_keypair

        # Unicode string → bytes
        unicode_text = "Hello 世界 🌍"
        plaintext = unicode_text.encode("utf-8")

        encrypted = cipher.encrypt_for_recipient(public_key, plaintext)
        decrypted = cipher.decrypt_from_sender(private_key, encrypted)

        assert decrypted == plaintext
        assert decrypted.decode("utf-8") == unicode_text


# ==============================================================================
# TEST: MULTIPLE PRESETS
# ==============================================================================


class TestMultiplePresets:
    """Тесты совместимости разных presets."""

    @pytest.mark.parametrize(
        "preset1,preset2",
        [
            ("classical_standard", "classical_paranoid"),
        ],
    )
    def test_different_presets_incompatible(
        self,
        preset1: str,
        preset2: str,
        plaintext: bytes,
    ) -> None:
        """Encrypted data от одного preset не может быть расшифрован другим."""
        cipher1 = create_hybrid_cipher(preset1)
        cipher2 = create_hybrid_cipher(preset2)

        # Generate keypair with cipher1
        priv1, pub1 = cipher1.generate_recipient_keypair()

        # Encrypt with cipher1
        encrypted = cipher1.encrypt_for_recipient(pub1, plaintext)

        # Try to decrypt with cipher2 (wrong KEX/Symmetric combination)
        # This SHOULD fail because algorithms don't match
        with pytest.raises((InvalidKeyError, DecryptionFailedError, ValueError)):
            cipher2.decrypt_from_sender(priv1, encrypted)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
