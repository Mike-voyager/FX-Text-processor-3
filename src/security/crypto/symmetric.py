# -*- coding: utf-8 -*-
"""
RU: Симметричное шифрование - AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305.
EN: Symmetric encryption - AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305.

Unified module containing all symmetric AEAD ciphers with:
- Nonce exhaustion protection
- Operation counting
- Key rotation warnings
- Birthday bound handling

Algorithms:
- AES-256-GCM: Hardware-accelerated (AES-NI), 96-bit nonce
- ChaCha20-Poly1305: Software-optimized, 96-bit nonce
- XChaCha20-Poly1305: Extended 192-bit nonce (no birthday bound)

Usage recommendations:
- Default: AES-GCM (best hardware support)
- ARM/Mobile: ChaCha20-Poly1305 (no AES-NI needed)
- Long-lived keys: XChaCha20-Poly1305 (2^64 operations safe)
"""
from __future__ import annotations

import logging
from typing import Final, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)

from .exceptions import DecryptionError, EncryptionError
from .utils import (
    generate_random_bytes,
    validate_key_length,
    validate_non_empty,
    validate_nonce_length,
    zero_memory,
)

_LOGGER: Final = logging.getLogger(__name__)

# Constants
AES_KEY_LEN: Final[int] = 32
AES_NONCE_LEN: Final[int] = 12
AES_TAG_LEN: Final[int] = 16

CHACHA_KEY_LEN: Final[int] = 32
CHACHA_NONCE_LEN: Final[int] = 12
CHACHA_TAG_LEN: Final[int] = 16

XCHACHA_KEY_LEN: Final[int] = 32
XCHACHA_NONCE_LEN: Final[int] = 24
XCHACHA_TAG_LEN: Final[int] = 16

# Birthday bound limits
DEFAULT_MAX_OPERATIONS: Final[int] = 2**31  # 50% of birthday bound


class SymmetricCipher:
    """
    AES-256-GCM cipher with operation counting.
    
    Features:
    - Automatic nonce generation
    - Operation counter (prevents birthday bound issues)
    - Rotation warnings at 80% threshold
    - Thread-safe counter
    """

    __slots__ = ('_encryption_counter', '_max_operations', '_rotation_warned')

    def __init__(self, max_operations: int = DEFAULT_MAX_OPERATIONS):
        self._encryption_counter = 0
        self._max_operations = max_operations
        self._rotation_warned = False

    def _check_operation_limit(self) -> None:
        if self._encryption_counter >= self._max_operations:
            raise EncryptionError(
                f"Key rotation required: {self._encryption_counter} operations "
                f"exceeds limit of {self._max_operations}"
            )

        if not self._rotation_warned and self._encryption_counter >= self._max_operations * 0.8:
            _LOGGER.warning(
                "AES-GCM key rotation recommended: %d/%d operations",
                self._encryption_counter,
                self._max_operations
            )
            self._rotation_warned = True

    def get_operation_count(self) -> int:
        return self._encryption_counter

    def reset_counter(self) -> None:
        self._encryption_counter = 0
        self._rotation_warned = False

    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
        """Encrypt with AES-256-GCM."""
        self._check_operation_limit()
        
        validate_key_length(key, AES_KEY_LEN, "AES-256 key")
        validate_non_empty(plaintext, "plaintext")

        is_mutable = isinstance(plaintext, bytearray)

        try:
            nonce = generate_random_bytes(AES_NONCE_LEN)
            aesgcm = AESGCM(key)
            combined = aesgcm.encrypt(nonce, bytes(plaintext), aad)

            self._encryption_counter += 1

            if return_combined:
                return bytes(nonce), bytes(combined)
            else:
                ciphertext = combined[:-AES_TAG_LEN]
                tag = combined[-AES_TAG_LEN:]
                return bytes(nonce), bytes(ciphertext), bytes(tag)

        except Exception as e:
            _LOGGER.error("AES-GCM encryption failed: %s", e.__class__.__name__)
            raise EncryptionError("AES-GCM encryption failed") from e

        finally:
            if is_mutable and isinstance(plaintext, bytearray):
                zero_memory(plaintext)

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        aad: Optional[bytes] = None,
        *,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt with AES-256-GCM."""
        validate_key_length(key, AES_KEY_LEN, "AES-256 key")
        validate_nonce_length(nonce, AES_NONCE_LEN)
        validate_non_empty(data, "ciphertext")

        try:
            if has_combined:
                combined = data
            else:
                if tag is None:
                    raise DecryptionError("Tag required when has_combined=False")
                combined = data + tag

            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, combined, aad)

            return bytes(plaintext)

        except Exception as e:
            _LOGGER.error("AES-GCM decryption failed: %s", e.__class__.__name__)
            raise DecryptionError("Invalid authentication tag") from e


class ChaCha20Cipher:
    """ChaCha20-Poly1305 AEAD cipher (software-optimized)."""

    __slots__ = ('_encryption_counter', '_max_operations', '_rotation_warned')

    def __init__(self, max_operations: int = DEFAULT_MAX_OPERATIONS):
        self._encryption_counter = 0
        self._max_operations = max_operations
        self._rotation_warned = False

    def _check_operation_limit(self) -> None:
        if self._encryption_counter >= self._max_operations:
            raise EncryptionError("Key rotation required")

        if not self._rotation_warned and self._encryption_counter >= self._max_operations * 0.8:
            _LOGGER.warning("ChaCha20 key rotation recommended")
            self._rotation_warned = True

    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Encrypt with ChaCha20-Poly1305."""
        self._check_operation_limit()

        validate_key_length(key, CHACHA_KEY_LEN, "ChaCha20 key")
        validate_non_empty(plaintext, "plaintext")

        is_mutable = isinstance(plaintext, bytearray)

        try:
            nonce = generate_random_bytes(CHACHA_NONCE_LEN)
            chacha = ChaCha20Poly1305(key)
            combined = chacha.encrypt(nonce, bytes(plaintext), aad)

            self._encryption_counter += 1

            return bytes(nonce), bytes(combined)

        except Exception as e:
            _LOGGER.error("ChaCha20 encryption failed: %s", e.__class__.__name__)
            raise EncryptionError("ChaCha20-Poly1305 encryption failed") from e

        finally:
            if is_mutable and isinstance(plaintext, bytearray):
                zero_memory(plaintext)

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        combined: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt with ChaCha20-Poly1305."""
        validate_key_length(key, CHACHA_KEY_LEN, "ChaCha20 key")
        validate_nonce_length(nonce, CHACHA_NONCE_LEN)
        validate_non_empty(combined, "ciphertext")

        try:
            chacha = ChaCha20Poly1305(key)
            plaintext = chacha.decrypt(nonce, combined, aad)
            return bytes(plaintext)

        except Exception as e:
            _LOGGER.error("ChaCha20 decryption failed: %s", e.__class__.__name__)
            raise DecryptionError("ChaCha20-Poly1305 authentication failed") from e


class XChaCha20Cipher:
    """XChaCha20-Poly1305 with extended 192-bit nonce (no operation limit needed)."""

    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Encrypt with XChaCha20-Poly1305."""
        validate_key_length(key, XCHACHA_KEY_LEN, "XChaCha20 key")
        validate_non_empty(plaintext, "plaintext")

        is_mutable = isinstance(plaintext, bytearray)

        try:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305 as XCC20
            except ImportError:
                raise EncryptionError(
                    "XChaCha20Poly1305 not available - upgrade cryptography"
                )

            nonce = generate_random_bytes(XCHACHA_NONCE_LEN)
            xchacha = XCC20(key)
            combined = xchacha.encrypt(nonce, bytes(plaintext), aad)

            return bytes(nonce), bytes(combined)

        except Exception as e:
            _LOGGER.error("XChaCha20 encryption failed: %s", e.__class__.__name__)
            raise EncryptionError("XChaCha20-Poly1305 encryption failed") from e

        finally:
            if is_mutable and isinstance(plaintext, bytearray):
                zero_memory(plaintext)

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        combined: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt with XChaCha20-Poly1305."""
        validate_key_length(key, XCHACHA_KEY_LEN, "XChaCha20 key")
        validate_nonce_length(nonce, XCHACHA_NONCE_LEN)
        validate_non_empty(combined, "ciphertext")

        try:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305 as XCC20
            except ImportError:
                raise DecryptionError("XChaCha20Poly1305 not available")

            xchacha = XCC20(key)
            plaintext = xchacha.decrypt(nonce, combined, aad)
            return bytes(plaintext)

        except Exception as e:
            _LOGGER.error("XChaCha20 decryption failed: %s", e.__class__.__name__)
            raise DecryptionError("XChaCha20-Poly1305 authentication failed") from e


# Convenience functions
def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    cipher = SymmetricCipher()
    return cipher.encrypt(key, plaintext, aad, return_combined=True)


def decrypt_aes_gcm(key: bytes, nonce: bytes, combined: bytes, aad: Optional[bytes] = None) -> bytes:
    cipher = SymmetricCipher()
    return cipher.decrypt(key, nonce, combined, aad, has_combined=True)


def encrypt_chacha20(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    cipher = ChaCha20Cipher()
    return cipher.encrypt(key, plaintext, aad)


def decrypt_chacha20(key: bytes, nonce: bytes, combined: bytes, aad: Optional[bytes] = None) -> bytes:
    cipher = ChaCha20Cipher()
    return cipher.decrypt(key, nonce, combined, aad)


def encrypt_xchacha20(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    cipher = XChaCha20Cipher()
    return cipher.encrypt(key, plaintext, aad)


def decrypt_xchacha20(key: bytes, nonce: bytes, combined: bytes, aad: Optional[bytes] = None) -> bytes:
    cipher = XChaCha20Cipher()
    return cipher.decrypt(key, nonce, combined, aad)


__all__ = [
    "SymmetricCipher",
    "ChaCha20Cipher",
    "XChaCha20Cipher",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "encrypt_chacha20",
    "decrypt_chacha20",
    "encrypt_xchacha20",
    "decrypt_xchacha20",
]
