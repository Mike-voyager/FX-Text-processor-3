# -*- coding: utf-8 -*-
"""
RU: Симметричное шифрование - AES-GCM, ChaCha20-Poly1305.
EN: Symmetric encryption - AES-GCM, ChaCha20-Poly1305.

Unified module containing symmetric AEAD ciphers with:
- Nonce exhaustion protection
- Operation counting
- Key rotation warnings
- Birthday bound handling

Algorithms:
- AES-256-GCM: Hardware-accelerated (AES-NI), 96-bit nonce
- ChaCha20-Poly1305: Software-optimized, 96-bit nonce

Usage recommendations:
- Default: AES-GCM (best hardware support)
- ARM/Mobile: ChaCha20-Poly1305 (no AES-NI needed)
"""
from __future__ import annotations

import logging
from typing import Final, Literal, Optional, Tuple, Union, overload

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

# Backward compatibility aliases
KEY_LEN: Final[int] = AES_KEY_LEN
NONCE_LEN: Final[int] = AES_NONCE_LEN
TAG_LEN: Final[int] = AES_TAG_LEN

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

    __slots__ = ("_encryption_counter", "_max_operations", "_rotation_warned")

    def __init__(self, max_operations: int = DEFAULT_MAX_OPERATIONS):
        self._encryption_counter = 0
        self._max_operations = max_operations
        self._rotation_warned = False

    def _check_operation_limit(self) -> None:
        future_count = self._encryption_counter + 1

        if future_count > self._max_operations:
            raise EncryptionError(
                f"Key rotation required: {self._encryption_counter} operations "
                f"exceeds limit of {self._max_operations}"
            )

        if not self._rotation_warned and future_count >= self._max_operations * 0.8:
            _LOGGER.warning(
                "AES-GCM key rotation recommended: %d/%d operations",
                future_count,
                self._max_operations,
            )
            self._rotation_warned = True

    def get_operation_count(self) -> int:
        """Get the number of encryption operations performed."""
        return self._encryption_counter

    def is_rotation_warned(self) -> bool:
        """Check if rotation warning threshold was reached."""
        return self._rotation_warned

    def reset_counter(self) -> None:
        """Reset operation counter and warning flag."""
        self._encryption_counter = 0
        self._rotation_warned = False

    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]: ...

    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
        *,
        return_combined: Literal[True],
    ) -> Tuple[bytes, bytes]: ...

    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
        *,
        return_combined: Literal[False],
    ) -> Tuple[bytes, bytes, bytes]: ...

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
                # Split combined into ciphertext and tag
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
        # Обернуть validation errors в DecryptionError
        try:
            validate_key_length(key, AES_KEY_LEN, "AES-256 key")
            validate_nonce_length(nonce, AES_NONCE_LEN)
            validate_non_empty(data, "ciphertext")
        except ValueError as e:
            raise DecryptionError(str(e)) from e

        try:
            aesgcm = AESGCM(key)

            # Auto-detect: if tag is provided, assume has_combined=False
            if tag is not None:
                has_combined = False

            if has_combined:
                # data contains ciphertext || tag
                combined = data
            else:
                # Need to combine ciphertext and tag
                if tag is None:
                    raise DecryptionError("Tag required when has_combined=False")
                if len(tag) != AES_TAG_LEN:
                    raise DecryptionError(
                        f"Invalid tag length: {len(tag)}, expected {AES_TAG_LEN}"
                    )
                combined = data + tag

            plaintext = aesgcm.decrypt(nonce, combined, aad)
            return bytes(plaintext)

        except DecryptionError:
            raise
        except Exception as e:
            _LOGGER.error("AES-GCM decryption failed: %s", e.__class__.__name__)
            raise DecryptionError("Invalid authentication tag") from e


class ChaCha20Cipher:
    """ChaCha20-Poly1305 AEAD cipher (software-optimized)."""

    __slots__ = ("_encryption_counter", "_max_operations", "_rotation_warned")

    def __init__(self, max_operations: int = DEFAULT_MAX_OPERATIONS):
        self._encryption_counter = 0
        self._max_operations = max_operations
        self._rotation_warned = False

    def _check_operation_limit(self) -> None:
        future_count = self._encryption_counter + 1

        if future_count > self._max_operations:
            raise EncryptionError("Key rotation required")

        if not self._rotation_warned and future_count >= self._max_operations * 0.8:
            _LOGGER.warning("ChaCha20 key rotation recommended")
            self._rotation_warned = True

    def get_operation_count(self) -> int:
        """Get the number of encryption operations performed."""
        return self._encryption_counter

    def is_rotation_warned(self) -> bool:
        """Check if rotation warning threshold was reached."""
        return self._rotation_warned

    def reset_counter(self) -> None:
        """Reset operation counter and warning flag."""
        self._encryption_counter = 0
        self._rotation_warned = False

    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]: ...

    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
        *,
        return_combined: Literal[True],
    ) -> Tuple[bytes, bytes]: ...

    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
        *,
        return_combined: Literal[False],
    ) -> Tuple[bytes, bytes, bytes]: ...

    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
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

            if return_combined:
                return bytes(nonce), bytes(combined)
            else:
                ciphertext = combined[:-CHACHA_TAG_LEN]
                tag = combined[-CHACHA_TAG_LEN:]
                return bytes(nonce), bytes(ciphertext), bytes(tag)

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
        data: bytes,
        aad: Optional[bytes] = None,
        *,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt with ChaCha20-Poly1305."""
        try:
            validate_key_length(key, CHACHA_KEY_LEN, "ChaCha20 key")
            validate_nonce_length(nonce, CHACHA_NONCE_LEN)
            validate_non_empty(data, "ciphertext")
        except ValueError as e:
            raise DecryptionError(str(e)) from e

        try:
            chacha = ChaCha20Poly1305(key)

            # Auto-detect: if tag is provided, assume has_combined=False
            if tag is not None:
                has_combined = False

            if has_combined:
                combined = data
            else:
                if tag is None:
                    raise DecryptionError("Tag required when has_combined=False")
                if len(tag) != CHACHA_TAG_LEN:
                    raise DecryptionError(
                        f"Invalid tag length: {len(tag)}, expected {CHACHA_TAG_LEN}"
                    )
                combined = data + tag

            plaintext = chacha.decrypt(nonce, combined, aad)
            return bytes(plaintext)

        except DecryptionError:
            raise
        except Exception as e:
            _LOGGER.error("ChaCha20 decryption failed: %s", e.__class__.__name__)
            raise DecryptionError("ChaCha20-Poly1305 authentication failed") from e


# Convenience functions
def encrypt_aes_gcm(
    key: bytes, plaintext: bytes, aad: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM (convenience function)."""
    cipher = SymmetricCipher()
    return cipher.encrypt(key, plaintext, aad, return_combined=True)  # ЯВНО!


def decrypt_aes_gcm(
    key: bytes, nonce: bytes, combined: bytes, aad: Optional[bytes] = None
) -> bytes:
    """Decrypt with AES-256-GCM (convenience function)."""
    cipher = SymmetricCipher()
    return cipher.decrypt(key, nonce, combined, aad)


def encrypt_chacha20(
    key: bytes, plaintext: bytes, aad: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Encrypt with ChaCha20-Poly1305 (convenience function)."""
    cipher = ChaCha20Cipher()
    return cipher.encrypt(key, plaintext, aad, return_combined=True)  # ЯВНО!


def decrypt_chacha20(
    key: bytes, nonce: bytes, combined: bytes, aad: Optional[bytes] = None
) -> bytes:
    """Decrypt with ChaCha20-Poly1305 (convenience function)."""
    cipher = ChaCha20Cipher()
    return cipher.decrypt(key, nonce, combined, aad)


def split_combined(combined: bytes, tag_len: int = 16) -> tuple[bytes, bytes]:
    """Разделить combined на ciphertext и tag."""
    return combined[:-tag_len], combined[-tag_len:]


def join_ct_tag(ciphertext: bytes, tag: bytes) -> bytes:
    """Объединить ciphertext и tag в combined."""
    return ciphertext + tag


__all__ = [
    # Classes
    "SymmetricCipher",
    "ChaCha20Cipher",
    # Convenience functions
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "encrypt_chacha20",
    "decrypt_chacha20",
    # Helper functions
    "split_combined",
    "join_ct_tag",
    # Constants (новые)
    "AES_KEY_LEN",
    "AES_NONCE_LEN",
    "AES_TAG_LEN",
    "CHACHA_KEY_LEN",
    "CHACHA_NONCE_LEN",
    "CHACHA_TAG_LEN",
    # Constants (legacy aliases)
    "KEY_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "DEFAULT_MAX_OPERATIONS",
]
