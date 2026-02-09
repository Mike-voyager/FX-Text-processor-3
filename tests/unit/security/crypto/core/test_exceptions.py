"""
Unit-тесты для модуля exceptions.py.

Проверяет корректность всех исключений криптографического модуля,
включая иерархию наследования, форматирование сообщений, и безопасность
(NO раскрытия секретов).

Coverage target: ≥98%
Version: 1.0
Date: February 9, 2026
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from src.security.crypto.core.exceptions import (
    # Base
    CryptoError,
    # Algorithm errors
    AlgorithmError,
    AlgorithmInitializationError,
    AlgorithmNotFoundError,
    AlgorithmNotSupportedError,
    # Encryption errors
    DecryptionFailedError,
    EncryptionError,
    EncryptionFailedError,
    InvalidNonceError,
    InvalidTagError,
    PlaintextTooLargeError,
    # Hash errors
    HashError,
    HashingFailedError,
    InvalidDigestError,
    # Key errors
    CryptoKeyError,
    InvalidKeyError,
    InvalidKeySizeError,
    KeyDerivationError,
    KeyGenerationError,
    # Protocol errors
    ProtocolError,
    ProtocolMismatchError,
    ProtocolViolationError,
    # Registry errors
    AlgorithmNotRegisteredError,
    DuplicateRegistrationError,
    RegistryError,
    # Signature errors
    InvalidSignatureError,
    SignatureError,
    SigningFailedError,
    VerificationFailedError,
    # Validation errors
    InvalidInputError,
    InvalidOutputError,
    InvalidParameterError,
    ValidationError,
)


# ==============================================================================
# BASE EXCEPTION TESTS
# ==============================================================================


class TestCryptoError:
    """Тесты базового исключения CryptoError."""

    def test_basic_initialization(self) -> None:
        """Тест базовой инициализации."""
        error = CryptoError("Test error message")

        assert error.message == "Test error message"
        assert error.algorithm is None
        assert error.context == {}

    def test_initialization_with_algorithm(self) -> None:
        """Тест инициализации с алгоритмом."""
        error = CryptoError("Test error", algorithm="AES-256-GCM")

        assert error.message == "Test error"
        assert error.algorithm == "AES-256-GCM"
        assert error.context == {}

    def test_initialization_with_context(self) -> None:
        """Тест инициализации с контекстом."""
        context = {"operation": "encrypt", "reason": "invalid_input"}
        error = CryptoError("Test error", context=context)

        assert error.message == "Test error"
        assert error.algorithm is None
        assert error.context == context

    def test_initialization_with_all_params(self) -> None:
        """Тест инициализации со всеми параметрами."""
        context = {"operation": "encrypt", "size": 32}
        error = CryptoError(
            "Test error",
            algorithm="AES-256-GCM",
            context=context,
        )

        assert error.message == "Test error"
        assert error.algorithm == "AES-256-GCM"
        assert error.context == context

    def test_str_without_algorithm_and_context(self) -> None:
        """Тест __str__() без алгоритма и контекста."""
        error = CryptoError("Simple error")
        result = str(error)

        assert result == "CryptoError: Simple error"

    def test_str_with_algorithm(self) -> None:
        """Тест __str__() с алгоритмом."""
        error = CryptoError("Test error", algorithm="Ed25519")
        result = str(error)

        assert result == "CryptoError: Test error [algorithm=Ed25519]"

    def test_str_with_context(self) -> None:
        """Тест __str__() с контекстом."""
        error = CryptoError(
            "Test error",
            context={"key": "value", "num": 42},
        )
        result = str(error)

        assert "CryptoError: Test error" in result
        assert "key=value" in result
        assert "num=42" in result

    def test_str_with_algorithm_and_context(self) -> None:
        """Тест __str__() с алгоритмом и контекстом."""
        error = CryptoError(
            "Test error",
            algorithm="SHA-256",
            context={"operation": "hash"},
        )
        result = str(error)

        assert "CryptoError: Test error" in result
        assert "[algorithm=SHA-256]" in result
        assert "operation=hash" in result

    def test_repr(self) -> None:
        """Тест __repr__()."""
        error = CryptoError(
            "Test error",
            algorithm="AES-256-GCM",
            context={"op": "enc"},
        )
        result = repr(error)

        assert "CryptoError(" in result
        assert "message='Test error'" in result
        assert "algorithm='AES-256-GCM'" in result
        assert "context={'op': 'enc'}" in result

    def test_inheritance_from_exception(self) -> None:
        """Тест наследования от Exception."""
        error = CryptoError("Test")
        assert isinstance(error, Exception)

    def test_can_be_caught_as_exception(self) -> None:
        """Тест перехвата как Exception."""
        with pytest.raises(Exception):
            raise CryptoError("Test error")

    def test_can_be_caught_as_cryptoerror(self) -> None:
        """Тест перехвата как CryptoError."""
        with pytest.raises(CryptoError) as exc_info:
            raise CryptoError("Test error")

        assert exc_info.value.message == "Test error"


# ==============================================================================
# ALGORITHM ERRORS TESTS
# ==============================================================================


class TestAlgorithmError:
    """Тесты AlgorithmError."""

    def test_inheritance(self) -> None:
        """Тест наследования от CryptoError."""
        error = AlgorithmError("Test")
        assert isinstance(error, CryptoError)
        assert isinstance(error, Exception)

    def test_basic_usage(self) -> None:
        """Тест базового использования."""
        error = AlgorithmError("Algorithm failed", algorithm="Test-Algo")
        assert error.message == "Algorithm failed"
        assert error.algorithm == "Test-Algo"


class TestAlgorithmNotFoundError:
    """Тесты AlgorithmNotFoundError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = AlgorithmNotFoundError("Test-Algo")
        assert isinstance(error, AlgorithmError)
        assert isinstance(error, CryptoError)

    def test_without_available_list(self) -> None:
        """Тест без списка доступных алгоритмов."""
        error = AlgorithmNotFoundError("NonExistent-Algo")

        assert error.algorithm_name == "NonExistent-Algo"
        assert error.available == []
        assert "NonExistent-Algo" in error.message
        assert "not found in registry" in error.message

    def test_with_available_list_short(self) -> None:
        """Тест с коротким списком доступных (≤5)."""
        available = ["AES-256-GCM", "Ed25519", "SHA-256"]
        error = AlgorithmNotFoundError("Test", available=available)

        assert error.algorithm_name == "Test"
        assert error.available == available
        assert "AES-256-GCM" in error.message
        assert "Ed25519" in error.message
        assert "SHA-256" in error.message

    def test_with_available_list_long(self) -> None:
        """Тест с длинным списком доступных (>5)."""
        available = [f"Algo-{i}" for i in range(10)]
        error = AlgorithmNotFoundError("Test", available=available)

        assert error.available == available
        assert "Algo-0" in error.message
        assert "Algo-4" in error.message
        assert "... (10 total)" in error.message
        # Не должны показываться все 10
        assert "Algo-9" not in error.message

    def test_context_contains_available_count(self) -> None:
        """Тест что контекст содержит количество доступных."""
        available = ["A", "B", "C"]
        error = AlgorithmNotFoundError("Test", available=available)

        assert error.context["available_count"] == 3


class TestAlgorithmNotSupportedError:
    """Тесты AlgorithmNotSupportedError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = AlgorithmNotSupportedError("Test", "reason")
        assert isinstance(error, AlgorithmError)

    def test_without_required_library(self) -> None:
        """Тест без указания требуемой библиотеки."""
        error = AlgorithmNotSupportedError("Kyber768", "Platform not supported")

        assert error.reason == "Platform not supported"
        assert error.required_library is None
        assert "Kyber768" in error.message
        assert "not supported" in error.message
        assert "Platform not supported" in error.message

    def test_with_required_library(self) -> None:
        """Тест с указанием требуемой библиотеки."""
        error = AlgorithmNotSupportedError(
            "Dilithium3",
            "Library missing",
            required_library="liboqs-python",
        )

        assert error.reason == "Library missing"
        assert error.required_library == "liboqs-python"
        assert error.context["required_library"] == "liboqs-python"

    def test_context_contains_reason(self) -> None:
        """Тест что контекст содержит причину."""
        error = AlgorithmNotSupportedError("Test", "No hardware acceleration")
        assert error.context["reason"] == "No hardware acceleration"


class TestAlgorithmInitializationError:
    """Тесты AlgorithmInitializationError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = AlgorithmInitializationError("Init failed")
        assert isinstance(error, AlgorithmError)

    def test_basic_usage(self) -> None:
        """Тест базового использования."""
        error = AlgorithmInitializationError(
            "Failed to initialize",
            algorithm="AES-256-GCM",
        )
        assert error.message == "Failed to initialize"
        assert error.algorithm == "AES-256-GCM"


# ==============================================================================
# KEY ERRORS TESTS
# ==============================================================================


class TestCryptoKeyError:
    """Тесты CryptoKeyError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = CryptoKeyError("Key error")
        assert isinstance(error, CryptoError)

    def test_does_not_conflict_with_builtin(self) -> None:
        """Тест что не конфликтует с builtin KeyError."""
        # Должны быть разные типы
        crypto_error = CryptoKeyError("test")
        builtin_error = KeyError("test")

        assert type(crypto_error) != type(builtin_error)
        assert not isinstance(crypto_error, KeyError)
        assert not isinstance(builtin_error, CryptoKeyError)


class TestInvalidKeyError:
    """Тесты InvalidKeyError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidKeyError("Invalid key")
        assert isinstance(error, CryptoKeyError)

    def test_without_sizes(self) -> None:
        """Тест без указания размеров."""
        error = InvalidKeyError("Key is corrupted", algorithm="AES-256-GCM")

        assert error.expected_size is None
        assert error.actual_size is None
        assert error.context == {}

    def test_with_sizes(self) -> None:
        """Тест с указанием размеров."""
        error = InvalidKeyError(
            "Wrong size",
            algorithm="AES-256-GCM",
            expected_size=32,
            actual_size=16,
        )

        assert error.expected_size == 32
        assert error.actual_size == 16
        assert error.context["expected_size"] == 32
        assert error.context["actual_size"] == 16


class TestInvalidKeySizeError:
    """Тесты InvalidKeySizeError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidKeySizeError("AES-256-GCM", 32, 16)
        assert isinstance(error, InvalidKeyError)
        assert isinstance(error, CryptoKeyError)

    def test_message_format(self) -> None:
        """Тест формата сообщения."""
        error = InvalidKeySizeError("AES-256-GCM", 32, 16)

        assert "Invalid key size" in error.message
        assert "AES-256-GCM" in error.message
        assert "expected 32 bytes" in error.message
        assert "got 16 bytes" in error.message

    def test_attributes(self) -> None:
        """Тест атрибутов."""
        error = InvalidKeySizeError("Ed25519", 32, 64)

        assert error.algorithm == "Ed25519"
        assert error.expected_size == 32
        assert error.actual_size == 64


class TestKeyGenerationError:
    """Тесты KeyGenerationError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = KeyGenerationError("Generation failed")
        assert isinstance(error, CryptoKeyError)


class TestKeyDerivationError:
    """Тесты KeyDerivationError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = KeyDerivationError("Derivation failed")
        assert isinstance(error, CryptoKeyError)


# ==============================================================================
# ENCRYPTION ERRORS TESTS
# ==============================================================================


class TestEncryptionError:
    """Тесты EncryptionError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = EncryptionError("Encryption failed")
        assert isinstance(error, CryptoError)


class TestEncryptionFailedError:
    """Тесты EncryptionFailedError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = EncryptionFailedError("Failed")
        assert isinstance(error, EncryptionError)


class TestDecryptionFailedError:
    """Тесты DecryptionFailedError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = DecryptionFailedError("Failed")
        assert isinstance(error, EncryptionError)


class TestInvalidNonceError:
    """Тесты InvalidNonceError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidNonceError("Invalid nonce")
        assert isinstance(error, EncryptionError)

    def test_without_sizes(self) -> None:
        """Тест без указания размеров."""
        error = InvalidNonceError("Nonce reused", algorithm="AES-256-GCM")

        assert error.expected_size is None
        assert error.actual_size is None
        assert error.context == {}

    def test_with_sizes(self) -> None:
        """Тест с указанием размеров."""
        error = InvalidNonceError(
            "Wrong nonce size",
            algorithm="ChaCha20-Poly1305",
            expected_size=12,
            actual_size=8,
        )

        assert error.expected_size == 12
        assert error.actual_size == 8
        assert error.context["expected_nonce_size"] == 12
        assert error.context["actual_nonce_size"] == 8


class TestInvalidTagError:
    """Тесты InvalidTagError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidTagError("Invalid tag")
        assert isinstance(error, EncryptionError)


class TestPlaintextTooLargeError:
    """Тесты PlaintextTooLargeError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = PlaintextTooLargeError("RSA-OAEP-2048", 190, 500)
        assert isinstance(error, EncryptionError)

    def test_message_format(self) -> None:
        """Тест формата сообщения."""
        error = PlaintextTooLargeError("RSA-OAEP-2048", 190, 500)

        assert "Plaintext too large" in error.message
        assert "RSA-OAEP-2048" in error.message
        assert "max 190 bytes" in error.message
        assert "got 500 bytes" in error.message

    def test_attributes(self) -> None:
        """Тест атрибутов."""
        error = PlaintextTooLargeError("Test-Algo", 100, 200)

        assert error.algorithm == "Test-Algo"
        assert error.max_size == 100
        assert error.actual_size == 200
        assert error.context["max_size"] == 100
        assert error.context["actual_size"] == 200


# ==============================================================================
# SIGNATURE ERRORS TESTS
# ==============================================================================


class TestSignatureError:
    """Тесты SignatureError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = SignatureError("Signature failed")
        assert isinstance(error, CryptoError)


class TestSigningFailedError:
    """Тесты SigningFailedError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = SigningFailedError("Signing failed")
        assert isinstance(error, SignatureError)


class TestVerificationFailedError:
    """Тесты VerificationFailedError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = VerificationFailedError("Verification failed")
        assert isinstance(error, SignatureError)


class TestInvalidSignatureError:
    """Тесты InvalidSignatureError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidSignatureError("Invalid signature")
        assert isinstance(error, SignatureError)

    def test_without_sizes(self) -> None:
        """Тест без указания размеров."""
        error = InvalidSignatureError("Corrupted", algorithm="Ed25519")

        assert error.expected_size is None
        assert error.actual_size is None
        assert error.context == {}

    def test_with_sizes(self) -> None:
        """Тест с указанием размеров."""
        error = InvalidSignatureError(
            "Wrong size",
            algorithm="Ed25519",
            expected_size=64,
            actual_size=32,
        )

        assert error.expected_size == 64
        assert error.actual_size == 32
        assert error.context["expected_signature_size"] == 64
        assert error.context["actual_signature_size"] == 32


# ==============================================================================
# HASH ERRORS TESTS
# ==============================================================================


class TestHashError:
    """Тесты HashError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = HashError("Hash failed")
        assert isinstance(error, CryptoError)


class TestHashingFailedError:
    """Тесты HashingFailedError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = HashingFailedError("Hashing failed")
        assert isinstance(error, HashError)


class TestInvalidDigestError:
    """Тесты InvalidDigestError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidDigestError("Invalid digest")
        assert isinstance(error, HashError)


# ==============================================================================
# PROTOCOL ERRORS TESTS
# ==============================================================================


class TestProtocolError:
    """Тесты ProtocolError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = ProtocolError("Protocol error")
        assert isinstance(error, CryptoError)


class TestProtocolMismatchError:
    """Тесты ProtocolMismatchError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = ProtocolMismatchError("TestAlgo", "TestProtocol")
        assert isinstance(error, ProtocolError)

    def test_without_missing_methods(self) -> None:
        """Тест без списка отсутствующих методов."""
        error = ProtocolMismatchError("CustomAlgo", "SymmetricCipherProtocol")

        assert error.protocol_name == "SymmetricCipherProtocol"
        assert error.missing_methods == []
        assert "CustomAlgo" in error.message
        assert "does not implement" in error.message
        assert "SymmetricCipherProtocol" in error.message

    def test_with_missing_methods(self) -> None:
        """Тест со списком отсутствующих методов."""
        missing = ["encrypt", "decrypt", "generate_key"]
        error = ProtocolMismatchError(
            "CustomAlgo",
            "SymmetricCipherProtocol",
            missing_methods=missing,
        )

        assert error.missing_methods == missing
        assert "Missing methods:" in error.message
        assert "encrypt" in error.message
        assert "decrypt" in error.message
        assert "generate_key" in error.message

    def test_context_contains_protocol_and_missing(self) -> None:
        """Тест что контекст содержит protocol и missing."""
        missing = ["method1", "method2"]
        error = ProtocolMismatchError("Algo", "Protocol", missing_methods=missing)

        assert error.context["protocol"] == "Protocol"
        assert error.context["missing"] == missing


class TestProtocolViolationError:
    """Тесты ProtocolViolationError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = ProtocolViolationError("Violation")
        assert isinstance(error, ProtocolError)


# ==============================================================================
# REGISTRY ERRORS TESTS
# ==============================================================================


class TestRegistryError:
    """Тесты RegistryError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = RegistryError("Registry error")
        assert isinstance(error, CryptoError)


class TestAlgorithmNotRegisteredError:
    """Тесты AlgorithmNotRegisteredError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = AlgorithmNotRegisteredError("Not registered")
        assert isinstance(error, RegistryError)


class TestDuplicateRegistrationError:
    """Тесты DuplicateRegistrationError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = DuplicateRegistrationError("AES-256-GCM")
        assert isinstance(error, RegistryError)

    def test_message_format(self) -> None:
        """Тест формата сообщения."""
        error = DuplicateRegistrationError("AES-256-GCM")

        assert "AES-256-GCM" in error.message
        assert "already registered" in error.message

    def test_attributes(self) -> None:
        """Тест атрибутов."""
        error = DuplicateRegistrationError("Ed25519")

        assert error.algorithm_name == "Ed25519"
        assert error.algorithm == "Ed25519"


# ==============================================================================
# VALIDATION ERRORS TESTS
# ==============================================================================


class TestValidationError:
    """Тесты ValidationError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = ValidationError("Validation failed")
        assert isinstance(error, CryptoError)


class TestInvalidParameterError:
    """Тесты InvalidParameterError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidParameterError("rounds", "must be positive")
        assert isinstance(error, ValidationError)

    def test_without_value(self) -> None:
        """Тест без значения параметра."""
        error = InvalidParameterError("iterations", "out of range")

        assert error.parameter_name == "iterations"
        assert error.reason == "out of range"
        assert "Invalid parameter 'iterations'" in error.message
        assert "out of range" in error.message
        assert "value" not in error.context

    def test_with_value(self) -> None:
        """Тест со значением параметра."""
        error = InvalidParameterError("rounds", "must be positive", value=-5)

        assert error.parameter_name == "rounds"
        assert error.reason == "must be positive"
        assert error.context["value"] == "-5"

    def test_value_truncation_for_safety(self) -> None:
        """Тест усечения длинного значения для безопасности."""
        long_value = "x" * 100
        error = InvalidParameterError("param", "invalid", value=long_value)

        # Должно быть усечено до 50 символов
        assert len(error.context["value"]) == 50
        assert error.context["value"] == "x" * 50


class TestInvalidInputError:
    """Тесты InvalidInputError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidInputError("Invalid input")
        assert isinstance(error, ValidationError)


class TestInvalidOutputError:
    """Тесты InvalidOutputError."""

    def test_inheritance(self) -> None:
        """Тест наследования."""
        error = InvalidOutputError("Invalid output")
        assert isinstance(error, ValidationError)


# ==============================================================================
# INTEGRATION & EDGE CASES
# ==============================================================================


class TestExceptionHierarchy:
    """Тесты иерархии исключений."""

    def test_all_inherit_from_cryptoerror(self) -> None:
        """Тест что все исключения наследуют от CryptoError."""
        exceptions = [
            AlgorithmError("test"),
            CryptoKeyError("test"),
            EncryptionError("test"),
            SignatureError("test"),
            HashError("test"),
            ProtocolError("test"),
            RegistryError("test"),
            ValidationError("test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, CryptoError)
            assert isinstance(exc, Exception)

    def test_can_catch_all_as_cryptoerror(self) -> None:
        """Тест что можно перехватить все через CryptoError."""
        exceptions = [
            InvalidKeyError("test"),
            EncryptionFailedError("test"),
            SigningFailedError("test"),
            HashingFailedError("test"),
        ]

        for exc_class in [type(e) for e in exceptions]:
            with pytest.raises(CryptoError):
                raise exc_class("test error")

    def test_specific_exception_catching(self) -> None:
        """Тест перехвата специфичных исключений."""
        # Более специфичное должно перехватываться первым
        try:
            raise InvalidKeySizeError("AES-256-GCM", 32, 16)
        except InvalidKeySizeError as e:
            assert isinstance(e, InvalidKeyError)
            assert isinstance(e, CryptoKeyError)
            assert isinstance(e, CryptoError)
        except (InvalidKeyError, CryptoKeyError, CryptoError):
            pytest.fail("Should have caught InvalidKeySizeError specifically")


class TestExceptionSecurity:
    """Тесты безопасности исключений."""

    def test_no_secret_in_message(self) -> None:
        """Тест что секреты не попадают в сообщения."""
        # Это пример правильного использования - размеры ОК, сами значения НЕТ
        error = InvalidKeySizeError("AES-256-GCM", 32, 16)

        message = str(error)
        # Должны быть размеры
        assert "32" in message
        assert "16" in message
        # Не должно быть самого ключа
        assert b"\x00" not in message.encode()

    def test_context_should_not_contain_secrets(self) -> None:
        """Тест что контекст не должен содержать секреты."""
        # Это правило для разработчиков - не передавать секреты в context
        safe_context = {"operation": "encrypt", "size": 32}
        error = CryptoError("Test", context=safe_context)

        # Context виден в __repr__
        repr_str = repr(error)
        assert "operation" in repr_str
        assert "encrypt" in repr_str

    def test_parameter_value_truncation(self) -> None:
        """Тест усечения значений параметров."""
        # Защита от случайной утечки длинных значений
        long_value = "secret" * 100
        error = InvalidParameterError("key", "invalid", value=long_value)

        # Значение должно быть усечено
        assert len(error.context["value"]) <= 50


class TestExceptionEdgeCases:
    """Тесты edge cases."""

    def test_empty_message(self) -> None:
        """Тест пустого сообщения."""
        error = CryptoError("")
        assert error.message == ""
        assert str(error) == "CryptoError: "

    def test_none_algorithm(self) -> None:
        """Тест явно переданного None для algorithm."""
        error = CryptoError("Test", algorithm=None)
        assert error.algorithm is None
        assert "[algorithm=" not in str(error)

    def test_empty_context(self) -> None:
        """Тест пустого контекста."""
        error = CryptoError("Test", context={})
        assert error.context == {}
        str_repr = str(error)
        assert "CryptoError: Test" in str_repr

    def test_unicode_in_messages(self) -> None:
        """Тест Unicode в сообщениях."""
        error = CryptoError("Ошибка шифрования 🔐", algorithm="AES-256-GCM")
        assert "Ошибка шифрования 🔐" in str(error)
        assert "AES-256-GCM" in str(error)

    def test_special_characters_in_algorithm_name(self) -> None:
        """Тест спецсимволов в имени алгоритма."""
        error = CryptoError("Test", algorithm="AES-256-GCM/CTR")
        assert "AES-256-GCM/CTR" in str(error)

    def test_large_context(self) -> None:
        """Тест большого контекста."""
        large_context = {f"key_{i}": f"value_{i}" for i in range(100)}
        error = CryptoError("Test", context=large_context)

        # Должен создаться без ошибок
        assert error.context == large_context
        # __str__() должен работать
        str_repr = str(error)
        assert "CryptoError: Test" in str_repr


class TestExceptionChaining:
    """Тесты цепочек исключений (exception chaining)."""

    def test_exception_chaining_with_from(self) -> None:
        """Тест цепочки исключений через 'from'."""
        original = ValueError("Original error")

        try:
            raise EncryptionFailedError("Encryption failed") from original
        except EncryptionFailedError as e:
            assert e.__cause__ is original
            assert isinstance(e.__cause__, ValueError)

    def test_exception_context_preservation(self) -> None:
        """Тест сохранения контекста исключения."""
        try:
            try:
                raise ValueError("Inner error")
            except ValueError:
                raise CryptoError("Outer error")
        except CryptoError as e:
            # __context__ автоматически устанавливается Python
            assert e.__context__ is not None
            assert isinstance(e.__context__, ValueError)


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================


class TestModuleExports:
    """Тесты экспортов модуля."""

    def test_all_exceptions_in_all(self) -> None:
        """Тест что все исключения в __all__."""
        from src.security.crypto.core import exceptions

        expected_exceptions = [
            "CryptoError",
            # Algorithm
            "AlgorithmError",
            "AlgorithmNotFoundError",
            "AlgorithmNotSupportedError",
            "AlgorithmInitializationError",
            # Key
            "CryptoKeyError",
            "InvalidKeyError",
            "InvalidKeySizeError",
            "KeyGenerationError",
            "KeyDerivationError",
            # Encryption
            "EncryptionError",
            "EncryptionFailedError",
            "DecryptionFailedError",
            "InvalidNonceError",
            "InvalidTagError",
            "PlaintextTooLargeError",
            # Signature
            "SignatureError",
            "SigningFailedError",
            "VerificationFailedError",
            "InvalidSignatureError",
            # Hash
            "HashError",
            "HashingFailedError",
            "InvalidDigestError",
            # Protocol
            "ProtocolError",
            "ProtocolMismatchError",
            "ProtocolViolationError",
            # Registry
            "RegistryError",
            "AlgorithmNotRegisteredError",
            "DuplicateRegistrationError",
            # Validation
            "ValidationError",
            "InvalidParameterError",
            "InvalidInputError",
            "InvalidOutputError",
        ]

        for exc_name in expected_exceptions:
            assert exc_name in exceptions.__all__
            assert hasattr(exceptions, exc_name)

    def test_all_is_list_of_strings(self) -> None:
        """Тест что __all__ это список строк."""
        from src.security.crypto.core import exceptions

        assert isinstance(exceptions.__all__, list)
        assert all(isinstance(item, str) for item in exceptions.__all__)
