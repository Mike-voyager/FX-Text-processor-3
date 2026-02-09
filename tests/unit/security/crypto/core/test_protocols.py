"""
Unit-тесты для протокольных интерфейсов криптографической подсистемы.

Проверяет:
- Runtime checking с @runtime_checkable
- Корректность определения Protocol атрибутов
- Корректность определения Protocol методов
- isinstance() проверки с mock объектами

Coverage target: ≥95%
"""

import pytest
from typing import Iterable, Optional, Tuple

from src.security.crypto.core.protocols import (
    AsymmetricEncryptionProtocol,
    HashProtocol,
    KDFProtocol,
    KeyExchangeProtocol,
    NonceManagerProtocol,
    SecureMemoryProtocol,
    SignatureProtocol,
    SymmetricCipherProtocol,
)


# ==============================================================================
# TEST: SymmetricCipherProtocol
# ==============================================================================


class TestSymmetricCipherProtocol:
    """Тесты для SymmetricCipherProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """SymmetricCipherProtocol корректно проверяется в runtime."""

        class MockCipher:
            algorithm_name = "AES-256-GCM"
            key_size = 32
            nonce_size = 12
            is_aead = True

            def encrypt(
                self,
                key: bytes,
                plaintext: bytes,
                *,
                nonce: Optional[bytes] = None,
                associated_data: Optional[bytes] = None,
            ) -> Tuple[bytes, bytes]:
                return b"ciphertext", b"tag"

            def decrypt(
                self,
                key: bytes,
                ciphertext: bytes,
                nonce_or_tag: bytes,
                *,
                associated_data: Optional[bytes] = None,
            ) -> bytes:
                return b"plaintext"

            def generate_key(self) -> bytes:
                return b"0" * 32

        cipher = MockCipher()
        assert isinstance(cipher, SymmetricCipherProtocol)

    def test_protocol_requires_attributes(self) -> None:
        """SymmetricCipherProtocol требует обязательные атрибуты."""

        class IncompleteCipher:
            # Отсутствуют атрибуты algorithm_name, key_size, etc.
            def encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
                return b"", b""

            def decrypt(self, key: bytes, ciphertext: bytes, tag: bytes) -> bytes:
                return b""

            def generate_key(self) -> bytes:
                return b""

        cipher = IncompleteCipher()
        assert not isinstance(cipher, SymmetricCipherProtocol)

    def test_protocol_requires_encrypt_method(self) -> None:
        """SymmetricCipherProtocol требует метод encrypt."""

        class NoEncryptCipher:
            algorithm_name = "TEST"
            key_size = 32
            nonce_size = 12
            is_aead = True

            # Отсутствует encrypt
            def decrypt(self, key: bytes, ciphertext: bytes, tag: bytes) -> bytes:
                return b""

            def generate_key(self) -> bytes:
                return b""

        cipher = NoEncryptCipher()
        assert not isinstance(cipher, SymmetricCipherProtocol)

    def test_protocol_requires_decrypt_method(self) -> None:
        """SymmetricCipherProtocol требует метод decrypt."""

        class NoDecryptCipher:
            algorithm_name = "TEST"
            key_size = 32
            nonce_size = 12
            is_aead = True

            def encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
                return b"", b""

            # Отсутствует decrypt
            def generate_key(self) -> bytes:
                return b""

        cipher = NoDecryptCipher()
        assert not isinstance(cipher, SymmetricCipherProtocol)

    def test_protocol_requires_generate_key_method(self) -> None:
        """SymmetricCipherProtocol требует метод generate_key."""

        class NoGenerateKeyCipher:
            algorithm_name = "TEST"
            key_size = 32
            nonce_size = 12
            is_aead = True

            def encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
                return b"", b""

            def decrypt(self, key: bytes, ciphertext: bytes, tag: bytes) -> bytes:
                return b""

            # Отсутствует generate_key

        cipher = NoGenerateKeyCipher()
        assert not isinstance(cipher, SymmetricCipherProtocol)


# ==============================================================================
# TEST: SignatureProtocol
# ==============================================================================


class TestSignatureProtocol:
    """Тесты для SignatureProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """SignatureProtocol корректно проверяется в runtime."""

        class MockSigner:
            algorithm_name = "Ed25519"
            signature_size = 64
            public_key_size = 32
            private_key_size = 32
            is_post_quantum = False

            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"0" * 32, b"1" * 32

            def sign(self, private_key: bytes, message: bytes) -> bytes:
                return b"signature"

            def verify(
                self, public_key: bytes, message: bytes, signature: bytes
            ) -> bool:
                return True

        signer = MockSigner()
        assert isinstance(signer, SignatureProtocol)

    def test_protocol_requires_attributes(self) -> None:
        """SignatureProtocol требует обязательные атрибуты."""

        class IncompleteSigner:
            # Отсутствуют атрибуты
            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"", b""

            def sign(self, private_key: bytes, message: bytes) -> bytes:
                return b""

            def verify(
                self, public_key: bytes, message: bytes, signature: bytes
            ) -> bool:
                return False

        signer = IncompleteSigner()
        assert not isinstance(signer, SignatureProtocol)

    def test_protocol_requires_all_methods(self) -> None:
        """SignatureProtocol требует все 3 метода."""

        class NoSignMethod:
            algorithm_name = "TEST"
            signature_size = 64
            public_key_size = 32
            private_key_size = 32
            is_post_quantum = False

            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"", b""

            # Отсутствует sign
            def verify(
                self, public_key: bytes, message: bytes, signature: bytes
            ) -> bool:
                return False

        signer = NoSignMethod()
        assert not isinstance(signer, SignatureProtocol)


# ==============================================================================
# TEST: AsymmetricEncryptionProtocol
# ==============================================================================


class TestAsymmetricEncryptionProtocol:
    """Тесты для AsymmetricEncryptionProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """AsymmetricEncryptionProtocol корректно проверяется в runtime."""

        class MockRSA:
            algorithm_name = "RSA-OAEP-2048"
            key_size = 2048
            max_plaintext_size = 190

            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"private", b"public"

            def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
                return b"ciphertext"

            def decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
                return b"plaintext"

        rsa = MockRSA()
        assert isinstance(rsa, AsymmetricEncryptionProtocol)

    def test_protocol_requires_attributes(self) -> None:
        """AsymmetricEncryptionProtocol требует обязательные атрибуты."""

        class IncompleteRSA:
            # Отсутствуют атрибуты
            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"", b""

            def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
                return b""

            def decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
                return b""

        rsa = IncompleteRSA()
        assert not isinstance(rsa, AsymmetricEncryptionProtocol)


# ==============================================================================
# TEST: KeyExchangeProtocol
# ==============================================================================


class TestKeyExchangeProtocol:
    """Тесты для KeyExchangeProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """KeyExchangeProtocol корректно проверяется в runtime."""

        class MockKEX:
            algorithm_name = "X25519"
            shared_secret_size = 32
            is_post_quantum = False

            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"private", b"public"

            def derive_shared_secret(
                self, private_key: bytes, peer_public_key: bytes
            ) -> bytes:
                return b"shared_secret"

        kex = MockKEX()
        assert isinstance(kex, KeyExchangeProtocol)

    def test_protocol_requires_attributes(self) -> None:
        """KeyExchangeProtocol требует обязательные атрибуты."""

        class IncompleteKEX:
            # Отсутствуют атрибуты
            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"", b""

            def derive_shared_secret(
                self, private_key: bytes, peer_public_key: bytes
            ) -> bytes:
                return b""

        kex = IncompleteKEX()
        assert not isinstance(kex, KeyExchangeProtocol)

    def test_protocol_requires_derive_shared_secret(self) -> None:
        """KeyExchangeProtocol требует метод derive_shared_secret."""

        class NoDerive:
            algorithm_name = "X25519"
            shared_secret_size = 32
            is_post_quantum = False

            def generate_keypair(self) -> Tuple[bytes, bytes]:
                return b"", b""

            # Отсутствует derive_shared_secret

        kex = NoDerive()
        assert not isinstance(kex, KeyExchangeProtocol)


# ==============================================================================
# TEST: HashProtocol
# ==============================================================================


class TestHashProtocol:
    """Тесты для HashProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """HashProtocol корректно проверяется в runtime."""

        class MockHash:
            algorithm_name = "SHA-256"
            digest_size = 32

            def hash(self, data: bytes) -> bytes:
                return b"0" * 32

            def hash_stream(self, stream: Iterable[bytes]) -> bytes:
                return b"0" * 32

        hasher = MockHash()
        assert isinstance(hasher, HashProtocol)

    def test_protocol_requires_hash_method(self) -> None:
        """HashProtocol требует метод hash."""

        class NoHashMethod:
            algorithm_name = "SHA-256"
            digest_size = 32

            # Отсутствует hash
            def hash_stream(self, stream: Iterable[bytes]) -> bytes:
                return b""

        hasher = NoHashMethod()
        assert not isinstance(hasher, HashProtocol)

    def test_protocol_requires_hash_stream_method(self) -> None:
        """HashProtocol требует метод hash_stream."""

        class NoHashStream:
            algorithm_name = "SHA-256"
            digest_size = 32

            def hash(self, data: bytes) -> bytes:
                return b""

            # Отсутствует hash_stream

        hasher = NoHashStream()
        assert not isinstance(hasher, HashProtocol)


# ==============================================================================
# TEST: KDFProtocol
# ==============================================================================


class TestKDFProtocol:
    """Тесты для KDFProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """KDFProtocol корректно проверяется в runtime."""

        class MockKDF:
            algorithm_name = "Argon2id"
            recommended_iterations = 3
            recommended_memory_cost = 65536

            def derive_key(
                self,
                password: bytes,
                salt: bytes,
                length: int,
                *,
                iterations: Optional[int] = None,
                memory_cost: Optional[int] = None,
                parallelism: Optional[int] = None,
            ) -> bytes:
                return b"0" * length

        kdf = MockKDF()
        assert isinstance(kdf, KDFProtocol)

    def test_protocol_requires_attributes(self) -> None:
        """KDFProtocol требует обязательные атрибуты."""

        class IncompleteKDF:
            # Отсутствуют атрибуты
            def derive_key(self, password: bytes, salt: bytes, length: int) -> bytes:
                return b""

        kdf = IncompleteKDF()
        assert not isinstance(kdf, KDFProtocol)

    def test_protocol_allows_optional_memory_cost(self) -> None:
        """KDFProtocol позволяет Optional[int] для recommended_memory_cost."""

        class KDFWithoutMemoryCost:
            algorithm_name = "PBKDF2"
            recommended_iterations = 100000
            recommended_memory_cost = None  # Optional

            def derive_key(
                self,
                password: bytes,
                salt: bytes,
                length: int,
                *,
                iterations: Optional[int] = None,
                memory_cost: Optional[int] = None,
                parallelism: Optional[int] = None,
            ) -> bytes:
                return b"0" * length

        kdf = KDFWithoutMemoryCost()
        assert isinstance(kdf, KDFProtocol)


# ==============================================================================
# TEST: NonceManagerProtocol
# ==============================================================================


class TestNonceManagerProtocol:
    """Тесты для NonceManagerProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """NonceManagerProtocol корректно проверяется в runtime."""

        class MockNonceManager:
            def generate_nonce(self, size: int) -> bytes:
                return b"0" * size

            def track_nonce(self, key_id: str, nonce: bytes) -> None:
                pass

        manager = MockNonceManager()
        assert isinstance(manager, NonceManagerProtocol)

    def test_protocol_requires_generate_nonce(self) -> None:
        """NonceManagerProtocol требует метод generate_nonce."""

        class NoGenerate:
            # Отсутствует generate_nonce
            def track_nonce(self, key_id: str, nonce: bytes) -> None:
                pass

        manager = NoGenerate()
        assert not isinstance(manager, NonceManagerProtocol)

    def test_protocol_requires_track_nonce(self) -> None:
        """NonceManagerProtocol требует метод track_nonce."""

        class NoTrack:
            def generate_nonce(self, size: int) -> bytes:
                return b""

            # Отсутствует track_nonce

        manager = NoTrack()
        assert not isinstance(manager, NonceManagerProtocol)


# ==============================================================================
# TEST: SecureMemoryProtocol
# ==============================================================================


class TestSecureMemoryProtocol:
    """Тесты для SecureMemoryProtocol."""

    def test_protocol_runtime_checkable(self) -> None:
        """SecureMemoryProtocol корректно проверяется в runtime."""

        class MockSecureMemory:
            def secure_zero(self, data: bytearray) -> None:
                for i in range(len(data)):
                    data[i] = 0

            def constant_time_compare(self, a: bytes, b: bytes) -> bool:
                return a == b

        memory = MockSecureMemory()
        assert isinstance(memory, SecureMemoryProtocol)

    def test_protocol_requires_secure_zero(self) -> None:
        """SecureMemoryProtocol требует метод secure_zero."""

        class NoSecureZero:
            # Отсутствует secure_zero
            def constant_time_compare(self, a: bytes, b: bytes) -> bool:
                return False

        memory = NoSecureZero()
        assert not isinstance(memory, SecureMemoryProtocol)

    def test_protocol_requires_constant_time_compare(self) -> None:
        """SecureMemoryProtocol требует метод constant_time_compare."""

        class NoConstantTime:
            def secure_zero(self, data: bytearray) -> None:
                pass

            # Отсутствует constant_time_compare

        memory = NoConstantTime()
        assert not isinstance(memory, SecureMemoryProtocol)


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты для exports модуля."""

    def test_all_protocols_exported(self) -> None:
        """Все 8 Protocol классов экспортированы."""
        from src.security.crypto.core import protocols

        assert hasattr(protocols, "SymmetricCipherProtocol")
        assert hasattr(protocols, "SignatureProtocol")
        assert hasattr(protocols, "AsymmetricEncryptionProtocol")
        assert hasattr(protocols, "KeyExchangeProtocol")
        assert hasattr(protocols, "HashProtocol")
        assert hasattr(protocols, "KDFProtocol")
        assert hasattr(protocols, "NonceManagerProtocol")
        assert hasattr(protocols, "SecureMemoryProtocol")

    def test_module_has_all_attribute(self) -> None:
        """Модуль имеет __all__ с 8 протоколами."""
        from src.security.crypto.core import protocols

        assert hasattr(protocols, "__all__")
        assert len(protocols.__all__) == 8
        assert "SymmetricCipherProtocol" in protocols.__all__
        assert "SignatureProtocol" in protocols.__all__
        assert "AsymmetricEncryptionProtocol" in protocols.__all__
        assert "KeyExchangeProtocol" in protocols.__all__
        assert "HashProtocol" in protocols.__all__
        assert "KDFProtocol" in protocols.__all__
        assert "NonceManagerProtocol" in protocols.__all__
        assert "SecureMemoryProtocol" in protocols.__all__

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.security.crypto.core import protocols

        assert hasattr(protocols, "__version__")
        assert hasattr(protocols, "__author__")
        assert hasattr(protocols, "__date__")


# ==============================================================================
# TEST: Complex Scenarios
# ==============================================================================


class TestComplexScenarios:
    """Тесты сложных сценариев использования."""

    def test_multiple_protocol_implementation(self) -> None:
        """Один класс может реализовать несколько Protocol."""

        class HybridCryptoTool:
            # SymmetricCipherProtocol
            algorithm_name = "Hybrid"
            key_size = 32
            nonce_size = 12
            is_aead = True

            # HashProtocol
            digest_size = 32

            def encrypt(
                self, key: bytes, plaintext: bytes, **kwargs: object
            ) -> Tuple[bytes, bytes]:
                return b"", b""

            def decrypt(
                self, key: bytes, ciphertext: bytes, tag: bytes, **kwargs: object
            ) -> bytes:
                return b""

            def generate_key(self) -> bytes:
                return b""

            def hash(self, data: bytes) -> bytes:
                return b""

            def hash_stream(self, stream: Iterable[bytes]) -> bytes:
                return b""

        tool = HybridCryptoTool()
        assert isinstance(tool, SymmetricCipherProtocol)
        assert isinstance(tool, HashProtocol)

    def test_partial_implementation_fails(self) -> None:
        """Частичная реализация Protocol не проходит isinstance()."""

        class PartialCipher:
            algorithm_name = "Partial"
            key_size = 32
            # Отсутствуют nonce_size, is_aead

            def encrypt(
                self, key: bytes, plaintext: bytes, **kwargs: object
            ) -> Tuple[bytes, bytes]:
                return b"", b""

            def decrypt(
                self, key: bytes, ciphertext: bytes, tag: bytes, **kwargs: object
            ) -> bytes:
                return b""

            def generate_key(self) -> bytes:
                return b""

        cipher = PartialCipher()
        assert not isinstance(cipher, SymmetricCipherProtocol)


# ==============================================================================
# TEST: Type Safety
# ==============================================================================


class TestTypeSafety:
    """Тесты типобезопасности Protocol."""

    def test_protocol_with_correct_return_types(self) -> None:
        """Protocol проверяет только наличие методов, не return типы."""

        class WrongReturnTypes:
            algorithm_name = "TEST"
            key_size = 32
            nonce_size = 12
            is_aead = True

            def encrypt(
                self, key: bytes, plaintext: bytes, **kwargs: object
            ) -> str:  # ✅ Добавлен return type
                # Неправильный return тип (str вместо Tuple[bytes, bytes])
                return "wrong"

            def decrypt(
                self, key: bytes, ciphertext: bytes, tag: bytes, **kwargs: object
            ) -> int:  # ✅ Добавлен return type
                # Неправильный return тип (int вместо bytes)
                return 0

            def generate_key(self) -> list:  # ✅ Добавлен return type
                # Неправильный return тип (list вместо bytes)
                return []

        # Protocol НЕ проверяет типы в runtime, только структуру
        cipher = WrongReturnTypes()
        assert isinstance(cipher, SymmetricCipherProtocol)
        # Это валидно для Protocol, но mypy --strict поймает ошибку!


# ==============================================================================
# COVERAGE: Edge Cases
# ==============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_empty_class_not_protocol(self) -> None:
        """Пустой класс не соответствует Protocol."""

        class EmptyClass:
            pass

        obj = EmptyClass()
        assert not isinstance(obj, SymmetricCipherProtocol)
        assert not isinstance(obj, SignatureProtocol)
        assert not isinstance(obj, HashProtocol)
        assert not isinstance(obj, KDFProtocol)

    def test_protocol_with_extra_methods(self) -> None:
        """Класс с дополнительными методами проходит Protocol."""

        class ExtendedCipher:
            algorithm_name = "Extended"
            key_size = 32
            nonce_size = 12
            is_aead = True

            def encrypt(
                self, key: bytes, plaintext: bytes, **kwargs: object
            ) -> Tuple[bytes, bytes]:  # ✅ Добавлен return type
                return b"", b""

            def decrypt(
                self, key: bytes, ciphertext: bytes, tag: bytes, **kwargs: object
            ) -> bytes:  # ✅ Добавлен return type
                return b""

            def generate_key(self) -> bytes:  # ✅ Добавлен return type
                return b""

            # Дополнительные методы
            def extra_method(self) -> str:  # ✅ Добавлен return type
                return "extra"

            def another_method(self, x: int) -> int:  # ✅ Добавлен return type
                return x * 2

        cipher = ExtendedCipher()
        assert isinstance(cipher, SymmetricCipherProtocol)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.security.crypto.core.protocols"])
