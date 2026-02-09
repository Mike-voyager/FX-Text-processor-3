"""
Тесты для модуля asymmetric.py (RSA-OAEP варианты).

Тестируемые алгоритмы:
- RSA-OAEP-2048 (минимальный размер)
- RSA-OAEP-3072 (рекомендуемый)
- RSA-OAEP-4096 (максимальная защита)

Покрытие:
- Генерация ключей
- Шифрование/расшифровка
- Валидация размера plaintext
- Обработка ошибок (invalid keys, corrupted ciphertext)
- Metadata и registry
- Edge cases

Author: Mike Voyager
Date: February 10, 2026
"""

from __future__ import annotations

import pytest
from typing import Type, Any

from src.security.crypto.algorithms.asymmetric import (
    RSAOAEP2048,
    RSAOAEP3072,
    RSAOAEP4096,
    get_asymmetric_algorithm,
    ASYMMETRIC_ALGORITHMS,
    ALL_METADATA,
    MAX_PLAINTEXT_SIZE_2048,
    MAX_PLAINTEXT_SIZE_3072,
    MAX_PLAINTEXT_SIZE_4096,
    RSA_PUBLIC_EXPONENT,
)
from src.security.crypto.core.protocols import AsymmetricEncryptionProtocol
from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    SecurityLevel,
    FloppyFriendly,
    ImplementationStatus,
)
from src.security.crypto.core.exceptions import (
    KeyGenerationError,
    EncryptionFailedError,
    DecryptionFailedError,
    InvalidKeyError,
    PlaintextTooLargeError,
)

# Parametrize data: (class, name, key_size, max_plaintext)
RSA_OAEP_VARIANTS = [
    (RSAOAEP2048, "RSA-OAEP-2048", 2048, MAX_PLAINTEXT_SIZE_2048),
    (RSAOAEP3072, "RSA-OAEP-3072", 3072, MAX_PLAINTEXT_SIZE_3072),
    (RSAOAEP4096, "RSA-OAEP-4096", 4096, MAX_PLAINTEXT_SIZE_4096),
]


# ==============================================================================
# TEST: BASIC FUNCTIONALITY
# ==============================================================================


class TestRSAOAEPBasics:
    """Базовые тесты RSA-OAEP шифрования."""

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_keypair_generation(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест генерации keypair для всех RSA-OAEP вариантов."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        # Validate types
        assert isinstance(private_key, bytes), f"{name}: private_key должен быть bytes"
        assert isinstance(public_key, bytes), f"{name}: public_key должен быть bytes"

        # Validate sizes (approximate, DER encoding varies slightly)
        assert len(private_key) > 100, f"{name}: private_key слишком короткий"
        assert len(public_key) > 100, f"{name}: public_key слишком короткий"

        # RSA-2048: ~1217 bytes private, ~294 bytes public
        # RSA-3072: ~1793 bytes private, ~422 bytes public
        # RSA-4096: ~2374 bytes private, ~550 bytes public
        if key_size == 2048:
            assert (
                1150 < len(private_key) < 1300
            ), f"{name}: private_key size = {len(private_key)}"
            assert (
                250 < len(public_key) < 350
            ), f"{name}: public_key size = {len(public_key)}"
        elif key_size == 3072:
            assert (
                1700 < len(private_key) < 1900
            ), f"{name}: private_key size = {len(private_key)}"
            assert (
                380 < len(public_key) < 480
            ), f"{name}: public_key size = {len(public_key)}"
        elif key_size == 4096:
            assert (
                2300 < len(private_key) < 2500
            ), f"{name}: private_key size = {len(private_key)}"
            assert (
                500 < len(public_key) < 650
            ), f"{name}: public_key size = {len(public_key)}"

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_encrypt_decrypt_basic(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест базового encrypt/decrypt цикла."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        plaintext = b"Hello, RSA-OAEP!"
        ciphertext = cipher.encrypt(public_key, plaintext)
        decrypted = cipher.decrypt(private_key, ciphertext)

        assert decrypted == plaintext, f"{name}: расшифровка не совпала"

        # Ciphertext size = key_size / 8
        expected_ct_size = key_size // 8
        assert len(ciphertext) == expected_ct_size, (
            f"{name}: ciphertext должен быть {expected_ct_size} байт, "
            f"получено {len(ciphertext)}"
        )

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_encrypt_decrypt_empty_message(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест шифрования пустого сообщения."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        plaintext = b""
        ciphertext = cipher.encrypt(public_key, plaintext)
        decrypted = cipher.decrypt(private_key, ciphertext)

        assert decrypted == plaintext, f"{name}: пустое сообщение не расшифровалось"

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_encrypt_decrypt_max_size_plaintext(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест шифрования plaintext максимального размера."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        # Max plaintext size
        plaintext = b"X" * max_plaintext
        ciphertext = cipher.encrypt(public_key, plaintext)
        decrypted = cipher.decrypt(private_key, ciphertext)

        assert decrypted == plaintext, f"{name}: max size plaintext не расшифровался"
        assert len(plaintext) == max_plaintext


# ==============================================================================
# TEST: RANDOMIZED ENCRYPTION
# ==============================================================================


class TestRSAOAEPRandomization:
    """Тесты randomized encryption (OAEP feature)."""

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_oaep_randomized_encryption(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что OAEP даёт разные ciphertext для одного plaintext."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        plaintext = b"Same message"
        ciphertext1 = cipher.encrypt(public_key, plaintext)
        ciphertext2 = cipher.encrypt(public_key, plaintext)

        # OAEP padding должен давать разные ciphertext
        assert ciphertext1 != ciphertext2, f"{name}: OAEP должен быть randomized"

        # Но оба должны расшифроваться в один plaintext
        assert cipher.decrypt(private_key, ciphertext1) == plaintext
        assert cipher.decrypt(private_key, ciphertext2) == plaintext

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_multiple_encryptions(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест множественных шифрований разных сообщений."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        messages = [
            b"First message",
            b"Second message",
            b"Third message with more data",
            b"",
            b"X" * 50,
        ]

        for msg in messages:
            ct = cipher.encrypt(public_key, msg)
            pt = cipher.decrypt(private_key, ct)
            assert pt == msg, f"{name}: failed for message: {msg[:20]!r}"


# ==============================================================================
# TEST: ERROR HANDLING
# ==============================================================================


class TestRSAOAEPErrors:
    """Тесты обработки ошибок."""

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_plaintext_too_large(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что слишком большой plaintext вызывает PlaintextTooLargeError."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        # Plaintext на 1 байт больше максимума
        oversized_plaintext = b"X" * (max_plaintext + 1)

        with pytest.raises(PlaintextTooLargeError) as exc_info:
            cipher.encrypt(public_key, oversized_plaintext)

        # Validate error message contains useful info
        error_msg = str(exc_info.value)
        assert str(max_plaintext) in error_msg or name in error_msg

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_invalid_public_key_type(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что не-bytes public_key вызывает TypeError."""
        cipher = cipher_class()

        with pytest.raises(TypeError) as exc_info:
            cipher.encrypt("not bytes", b"message")  # type: ignore[arg-type]

        assert "public_key" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_invalid_private_key_type(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что не-bytes private_key вызывает TypeError."""
        cipher = cipher_class()

        with pytest.raises(TypeError) as exc_info:
            cipher.decrypt("not bytes", b"ciphertext")  # type: ignore[arg-type]

        assert "private_key" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_invalid_plaintext_type(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что не-bytes plaintext вызывает TypeError."""
        cipher = cipher_class()
        _, public_key = cipher.generate_keypair()

        with pytest.raises(TypeError) as exc_info:
            cipher.encrypt(public_key, "not bytes")  # type: ignore[arg-type]

        assert "plaintext" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_corrupted_public_key(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что испорченный public_key вызывает InvalidKeyError или EncryptionFailedError."""
        cipher = cipher_class()

        corrupted_key = b"corrupted_key_data_not_valid_DER"

        with pytest.raises((InvalidKeyError, EncryptionFailedError)):
            cipher.encrypt(corrupted_key, b"message")

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_corrupted_private_key(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что испорченный private_key вызывает InvalidKeyError или DecryptionFailedError."""
        cipher = cipher_class()
        _, public_key = cipher.generate_keypair()

        ciphertext = cipher.encrypt(public_key, b"message")
        corrupted_key = b"corrupted_private_key_data"

        with pytest.raises((InvalidKeyError, DecryptionFailedError)):
            cipher.decrypt(corrupted_key, ciphertext)

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_corrupted_ciphertext(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что испорченный ciphertext вызывает DecryptionFailedError."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        valid_ciphertext = cipher.encrypt(public_key, b"message")

        # Corrupt first byte
        corrupted = bytearray(valid_ciphertext)
        corrupted[0] ^= 0xFF
        corrupted_ciphertext = bytes(corrupted)

        with pytest.raises(DecryptionFailedError):
            cipher.decrypt(private_key, corrupted_ciphertext)

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_wrong_key_decryption(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что расшифровка с неверным ключом вызывает DecryptionFailedError."""
        cipher = cipher_class()
        private_key1, public_key1 = cipher.generate_keypair()
        private_key2, public_key2 = cipher.generate_keypair()

        ciphertext = cipher.encrypt(public_key1, b"message")

        # Попытка расшифровать с другим ключом
        with pytest.raises(DecryptionFailedError):
            cipher.decrypt(private_key2, ciphertext)

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_public_key_as_private_key(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что использование public_key вместо private_key вызывает ошибку."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()

        ciphertext = cipher.encrypt(public_key, b"message")

        # Попытка расшифровать с public key вместо private
        with pytest.raises((InvalidKeyError, DecryptionFailedError)):
            cipher.decrypt(public_key, ciphertext)


# ==============================================================================
# TEST: CROSS-KEY COMPATIBILITY
# ==============================================================================


class TestRSAOAEPCrossKeyCompatibility:
    """Тесты совместимости ключей."""

    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_different_instances_same_keys(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
    ) -> None:
        """Тест что разные экземпляры cipher могут использовать одни ключи."""
        cipher1 = cipher_class()
        cipher2 = cipher_class()

        private_key, public_key = cipher1.generate_keypair()

        # Шифруем в cipher1, расшифровываем в cipher2
        plaintext = b"Cross-instance test"
        ciphertext = cipher1.encrypt(public_key, plaintext)
        decrypted = cipher2.decrypt(private_key, ciphertext)

        assert decrypted == plaintext

    def test_different_key_sizes_incompatible(self) -> None:
        """Тест что ключи разных размеров несовместимы."""
        cipher2048 = RSAOAEP2048()
        cipher3072 = RSAOAEP3072()

        priv2048, pub2048 = cipher2048.generate_keypair()
        priv3072, pub3072 = cipher3072.generate_keypair()

        # Зашифровать с RSA-2048 ключом
        ct2048 = cipher2048.encrypt(pub2048, b"test")

        # Попытка расшифровать с RSA-3072 ключом (должно fail)
        with pytest.raises(DecryptionFailedError):
            cipher3072.decrypt(priv3072, ct2048)


# ==============================================================================
# TEST: REGISTRY & METADATA
# ==============================================================================


class TestRSAOAEPRegistry:
    """Тесты registry и metadata."""

    def test_all_algorithms_registered(self) -> None:
        """Тест что все 3 алгоритма зарегистрированы."""
        assert len(ASYMMETRIC_ALGORITHMS) == 3, "Должно быть 3 RSA-OAEP варианта"

        expected_names = {"RSA-OAEP-2048", "RSA-OAEP-3072", "RSA-OAEP-4096"}
        actual_names = set(ASYMMETRIC_ALGORITHMS.keys())

        assert (
            actual_names == expected_names
        ), f"Неверные имена алгоритмов: {actual_names}"

    def test_get_asymmetric_algorithm(self) -> None:
        """Тест фабричной функции get_asymmetric_algorithm."""
        for name in ["RSA-OAEP-2048", "RSA-OAEP-3072", "RSA-OAEP-4096"]:
            cipher = get_asymmetric_algorithm(name)
            assert cipher is not None
            assert hasattr(cipher, "encrypt")
            assert hasattr(cipher, "decrypt")
            assert hasattr(cipher, "generate_keypair")

    def test_get_asymmetric_algorithm_invalid(self) -> None:
        """Тест что несуществующий алгоритм вызывает KeyError."""
        with pytest.raises(KeyError) as exc_info:
            get_asymmetric_algorithm("RSA-OAEP-99999")

        assert "not found" in str(exc_info.value).lower()
        assert "RSA-OAEP-99999" in str(exc_info.value)

    def test_metadata_count(self) -> None:
        """Тест что метаданные для всех 3 алгоритмов присутствуют."""
        assert len(ALL_METADATA) == 3, "Должно быть 3 metadata объекта"

    @pytest.mark.parametrize(
        "name", ["RSA-OAEP-2048", "RSA-OAEP-3072", "RSA-OAEP-4096"]
    )
    def test_metadata_structure(self, name: str) -> None:
        """Тест структуры metadata для каждого алгоритма."""
        _, metadata = ASYMMETRIC_ALGORITHMS[name]

        assert metadata.name == name
        assert metadata.category == AlgorithmCategory.ASYMMETRIC_ENCRYPTION
        assert metadata.status == ImplementationStatus.STABLE
        assert metadata.library == "cryptography"
        assert metadata.key_size is not None
        assert metadata.max_plaintext_size is not None
        assert len(metadata.description_ru) > 0
        assert len(metadata.description_en) > 0

    def test_metadata_security_levels(self) -> None:
        """Тест что security levels корректны."""
        _, meta2048 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-2048"]
        _, meta3072 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-3072"]
        _, meta4096 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-4096"]

        assert meta2048.security_level == SecurityLevel.STANDARD
        assert meta3072.security_level == SecurityLevel.HIGH  # Recommended
        assert meta4096.security_level == SecurityLevel.HIGH  # Maximum security

    def test_metadata_floppy_friendly(self) -> None:
        """Тест что floppy_friendly флаги корректны."""
        _, meta2048 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-2048"]
        _, meta3072 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-3072"]
        _, meta4096 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-4096"]

        assert meta2048.floppy_friendly == FloppyFriendly.ACCEPTABLE
        assert meta3072.floppy_friendly == FloppyFriendly.ACCEPTABLE
        assert meta4096.floppy_friendly == FloppyFriendly.POOR  # > 1KB

    def test_metadata_key_sizes(self) -> None:
        """Тест что размеры ключей в metadata корректны."""
        _, meta2048 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-2048"]
        _, meta3072 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-3072"]
        _, meta4096 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-4096"]

        assert meta2048.key_size == 2048
        assert meta3072.key_size == 3072
        assert meta4096.key_size == 4096

    def test_metadata_max_plaintext_sizes(self) -> None:
        """Тест что max_plaintext_size в metadata корректен."""
        _, meta2048 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-2048"]
        _, meta3072 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-3072"]
        _, meta4096 = ASYMMETRIC_ALGORITHMS["RSA-OAEP-4096"]

        assert meta2048.max_plaintext_size == MAX_PLAINTEXT_SIZE_2048
        assert meta3072.max_plaintext_size == MAX_PLAINTEXT_SIZE_3072
        assert meta4096.max_plaintext_size == MAX_PLAINTEXT_SIZE_4096


# ==============================================================================
# TEST: CONSTANTS
# ==============================================================================


class TestRSAOAEPConstants:
    """Тесты констант модуля."""

    def test_public_exponent(self) -> None:
        """Тест что public exponent = 65537 (F4)."""
        assert RSA_PUBLIC_EXPONENT == 65537

    def test_max_plaintext_sizes_formula(self) -> None:
        """Тест что max plaintext sizes соответствуют формуле."""
        # Formula: (key_size_bytes - 2*hash_size - 2)
        # For SHA-256: hash_size = 32 bytes

        assert MAX_PLAINTEXT_SIZE_2048 == 256 - 2 * 32 - 2  # 190
        assert MAX_PLAINTEXT_SIZE_3072 == 384 - 2 * 32 - 2  # 318
        assert MAX_PLAINTEXT_SIZE_4096 == 512 - 2 * 32 - 2  # 446


# ==============================================================================
# TEST: PERFORMANCE (OPTIONAL BENCHMARKS)
# ==============================================================================


class TestRSAOAEPPerformance:
    """Performance benchmarks (optional, может быть медленным)."""

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_keygen_performance(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
        benchmark: Any,  # pytest-benchmark fixture
    ) -> None:
        """Benchmark генерации ключей (требует pytest-benchmark)."""
        cipher = cipher_class()

        def keygen() -> tuple[bytes, bytes]:
            return cipher.generate_keypair()

        result = benchmark(keygen)
        assert len(result) == 2  # (private, public)

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_encrypt_performance(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
        benchmark: Any,  # pytest-benchmark fixture
    ) -> None:
        """Benchmark шифрования (требует pytest-benchmark)."""
        cipher = cipher_class()
        _, public_key = cipher.generate_keypair()
        plaintext = b"Performance test message"

        result = benchmark(cipher.encrypt, public_key, plaintext)
        assert len(result) == key_size // 8

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "cipher_class,name,key_size,max_plaintext", RSA_OAEP_VARIANTS
    )
    def test_decrypt_performance(
        self,
        cipher_class: Type[AsymmetricEncryptionProtocol],
        name: str,
        key_size: int,
        max_plaintext: int,
        benchmark: Any,  # pytest-benchmark fixture
    ) -> None:
        """Benchmark расшифровки (требует pytest-benchmark)."""
        cipher = cipher_class()
        private_key, public_key = cipher.generate_keypair()
        plaintext = b"Performance test message"
        ciphertext = cipher.encrypt(public_key, plaintext)

        result = benchmark(cipher.decrypt, private_key, ciphertext)
        assert result == plaintext


# ==============================================================================
# TEST: EDGE CASES
# ==============================================================================


class TestRSAOAEPEdgeCases:
    """Тесты edge cases."""

    def test_multiple_sequential_keypairs(self) -> None:
        """Тест генерации нескольких keypair подряд (не должно быть collisions)."""
        cipher = RSAOAEP3072()

        keypairs = [cipher.generate_keypair() for _ in range(5)]

        # All private keys должны быть уникальны
        private_keys = [kp[0] for kp in keypairs]
        assert len(set(private_keys)) == 5, "Private keys должны быть уникальны"

        # All public keys должны быть уникальны
        public_keys = [kp[1] for kp in keypairs]
        assert len(set(public_keys)) == 5, "Public keys должны быть уникальны"

    def test_binary_data_encryption(self) -> None:
        """Тест шифрования бинарных данных (все байты 0x00-0xFF)."""
        cipher = RSAOAEP3072()
        private_key, public_key = cipher.generate_keypair()

        # Binary data with all byte values
        binary_data = bytes(range(256))[:100]  # First 100 bytes

        ciphertext = cipher.encrypt(public_key, binary_data)
        decrypted = cipher.decrypt(private_key, ciphertext)

        assert decrypted == binary_data

    def test_unicode_strings_as_bytes(self) -> None:
        """Тест шифрования unicode строк (как UTF-8 bytes)."""
        cipher = RSAOAEP3072()
        private_key, public_key = cipher.generate_keypair()

        unicode_text = "Привет, мир! 🚀 Hello, world!"
        plaintext = unicode_text.encode("utf-8")

        ciphertext = cipher.encrypt(public_key, plaintext)
        decrypted = cipher.decrypt(private_key, ciphertext)

        assert decrypted.decode("utf-8") == unicode_text

    @pytest.mark.parametrize("size", [1, 10, 50, 100, 150])
    def test_various_plaintext_sizes(self, size: int) -> None:
        """Тест различных размеров plaintext."""
        cipher = RSAOAEP3072()
        private_key, public_key = cipher.generate_keypair()

        plaintext = b"X" * size
        ciphertext = cipher.encrypt(public_key, plaintext)
        decrypted = cipher.decrypt(private_key, ciphertext)

        assert decrypted == plaintext
        assert len(decrypted) == size


# ==============================================================================
# PYTEST CONFIGURATION
# ==============================================================================


def pytest_configure(config: Any) -> None:  # pytest.Config не всегда импортируется
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
