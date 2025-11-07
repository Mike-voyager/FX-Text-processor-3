# -*- coding: utf-8 -*-
"""
RU: Централизованная иерархия исключений криптоподсистемы без конфликтов с built-in и с узкими подклассами
для fail-secure обработки ошибок (без утечек секретов в тексты сообщений).

EN: Centralized exception hierarchy for the crypto subsystem that avoids conflicts with Python built-ins
and provides narrow subclasses to enable fail-secure error handling (no leakage of secrets in messages).

Guidelines:
- Do not log secrets (keys, nonces, tags, plaintexts, salts) inside exception messages.
- Use specific subclasses at call sites for precise handling and better auditability.
- Keep messages concise and operational (what failed), not forensic (no sensitive data).
"""

from __future__ import annotations

from typing import Optional


class CryptoError(Exception):
    """Base exception for all crypto-related failures."""

    def __init__(
        self, message: str = "", *, cause: Optional[BaseException] = None
    ) -> None:
        super().__init__(message)
        self.__cause__ = cause


# Symmetric/asymmetric encryption
class EncryptionError(CryptoError):
    """Raised on encryption failures (e.g., invalid parameters, provider errors)."""


class DecryptionError(CryptoError):
    """Raised on decryption failures (e.g., invalid tag, corrupted payload)."""


# Signatures
class SignatureError(CryptoError):
    """Base class for signature errors."""


class SignatureGenerationError(SignatureError):
    """Raised when signing fails (e.g., missing private key or provider error)."""


class SignatureVerificationError(SignatureError):
    """Raised when verification fails structurally (bad key, bad length, provider error)."""


class InvalidSignatureError(SignatureVerificationError):
    """Raised when a signature does not validate for given data and key."""


# Keys (avoid shadowing built-in KeyError)
class CryptoKeyError(CryptoError):
    """Base class for key management errors (generation/import/rotation)."""


class KeyNotFoundError(CryptoKeyError):
    """Raised when a requested key is not found in a keystore/provider."""


class KeyGenerationError(CryptoKeyError):
    """Raised on key generation failures."""


class InvalidKeyError(CryptoKeyError):
    """Raised when a key has invalid size/format/algorithm for the requested operation."""


class KeyRotationError(CryptoKeyError):
    """Raised on failures related to key rotation procedures."""


# KDF
class KdfError(CryptoError):
    """Base class for key-derivation failures."""


class KDFParameterError(KdfError):
    """Raised on invalid KDF parameters (e.g., salt length, time/memory/parallelism)."""


class KDFAlgorithmError(KdfError):
    """Raised when the requested KDF algorithm is unsupported or fails internally."""


# Hashing
class HashingError(CryptoError):
    """Base class for hashing subsystem errors."""


class HashSchemeError(HashingError):
    """Raised on unsupported/invalid hash scheme (e.g., bad header/parameters)."""


# Storage
class StorageError(CryptoError):
    """Base class for secure storage (keystore) failures."""


class StorageReadError(StorageError):
    """Raised when reading or parsing the storage backend fails."""


class StorageWriteError(StorageError):
    """Raised when persisting changes to the storage backend fails."""


__all__ = [
    "CryptoError",
    "EncryptionError",
    "DecryptionError",
    "SignatureError",
    "SignatureGenerationError",
    "SignatureVerificationError",
    "InvalidSignatureError",
    "CryptoKeyError",
    "KeyNotFoundError",
    "KeyGenerationError",
    "InvalidKeyError",
    "KeyRotationError",
    "KdfError",
    "KDFParameterError",
    "KDFAlgorithmError",
    "HashingError",
    "HashSchemeError",
    "StorageError",
    "StorageReadError",
    "StorageWriteError",
]
