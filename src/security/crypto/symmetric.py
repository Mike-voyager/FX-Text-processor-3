# -*- coding: utf-8 -*-
"""
RU: Симметричное шифрование AES‑256‑GCM с fully random nonce generation,
унифицированным RNG из utils и best‑effort zeroization.

EN: AES-256-GCM symmetric cipher with fully random nonce generation,
unified RNG from utils, and best-effort zeroization.

⚠️ SECURITY NOTE: Nonce generation strategy (v2.0 breaking change).
- Old (v1.x): 32-bit prefix + 64-bit counter per key (risky on restart).
- New (v2.0): Full 96-bit random nonce (safe for < 2^32 messages per key).

This module provides:
- Fully random 96-bit nonces per encryption (NIST SP 800-38D compliant).
- Unified entropy source via security.crypto.utils.generate_random_bytes to centralize
  RNG policy and audits.
- Best-effort zeroization for in-memory mutable buffers (bytearray) using utils.zero_memory.
- Fail-secure exceptions (no silent fallbacks) and log messages without secrets.

Public API remains compatible by exposing both a class (DI-friendly) and plain helpers:
- SymmetricCipher.encrypt/decrypt with flexible combined/separate tag handling.
- encrypt_aes_gcm/decrypt_aes_gcm helpers returning (nonce, ciphertext||tag) and plaintext.

Thread-safety:
- No shared state; each SymmetricCipher instance is independent.
- Nonce generation uses cryptographically secure RNG (no coordination needed).

Security notes:
- Keys are 32 bytes (AES-256). Nonce is 12 bytes (GCM standard). Tag length is 16 bytes.
- No secrets, keys, nonces, tags, or plaintext fragments are logged.
- Zeroization only applies to mutable bytearray inputs; Python bytes cannot be wiped.
- Birthday bound: safe for up to ~2^32 encryptions per key (4 billion messages).
"""

from __future__ import annotations

import logging
from typing import Final, Literal, Optional, Tuple, Union, overload

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from security.crypto.exceptions import DecryptionError, EncryptionError
from security.crypto.utils import generate_random_bytes, zero_memory

_LOGGER: Final = logging.getLogger(__name__)

KEY_LEN: Final[int] = 32
NONCE_LEN: Final[int] = 12
TAG_LEN: Final[int] = 16

BytesLike = Union[bytes, bytearray]


class SymmetricCipher:
    """
    AES-256-GCM encryption/decryption with fully random nonce generation.

    Methods:
        encrypt(key, plaintext, aad, return_combined) -> (nonce, combined) or (nonce, ct, tag)
        decrypt(key, nonce, data, aad, has_combined, tag) -> plaintext

    Nonce Strategy (v2.0):
        - Fully random 96-bit nonce per encryption
        - Safe for < 2^32 messages per key (birthday bound ~2^48)
        - NIST SP 800-38D compliant
        - No state management or persistence required

    Examples:
        >>> cipher = SymmetricCipher()
        >>> nonce, combined = cipher.encrypt(key=b"0"*32, plaintext=b"hello")
        >>> plain = cipher.decrypt(key=b"0"*32, nonce=nonce, data=combined)
        >>> assert plain == b"hello"
    """

    __slots__ = ()

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
            raise EncryptionError("AES-256-GCM key must be 32 bytes")

    @staticmethod
    def _validate_nonce(nonce: bytes) -> None:
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
            raise DecryptionError("GCM nonce must be 12 bytes")

    # Overloads for precise return typing
    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: BytesLike,
        aad: Optional[bytes] = ...,
        *,
        return_combined: Literal[True] = True,
    ) -> Tuple[bytes, bytes]: ...

    @overload
    def encrypt(
        self,
        key: bytes,
        plaintext: BytesLike,
        aad: Optional[bytes] = ...,
        *,
        return_combined: Literal[False],
    ) -> Tuple[bytes, bytes, bytes]: ...

    def encrypt(
        self,
        key: bytes,
        plaintext: BytesLike,
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
        """
        Encrypt with AES-256-GCM.

        Args:
            key: 32-byte AES key.
            plaintext: message to encrypt; bytearray will be wiped best-effort after use.
            aad: additional authenticated data (not encrypted).
            return_combined: if True, returns (nonce, ciphertext||tag); else returns (nonce, ciphertext, tag).

        Returns:
            Either (nonce, combined) or (nonce, ciphertext, tag).

        Raises:
            EncryptionError: on invalid inputs or crypto failure.
        """
        self._validate_key(key)

        # Validate AAD if provided
        if aad is not None:
            if not isinstance(aad, (bytes, bytearray)) or len(aad) == 0:
                raise EncryptionError("AAD must be non-empty bytes when provided")

        # Generate fully random 96-bit nonce (v2.0 strategy)
        nonce = generate_random_bytes(NONCE_LEN)

        pt_is_mutable = isinstance(plaintext, bytearray)
        try:
            pt_bytes = bytes(plaintext)
            cipher = Cipher(algorithms.AES(bytes(key)), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            if aad:
                encryptor.authenticate_additional_data(aad)
            ciphertext = encryptor.update(pt_bytes) + encryptor.finalize()
            tag = encryptor.tag
        except Exception as exc:
            _LOGGER.error("AES-GCM encryption failed: %s", exc.__class__.__name__)
            raise EncryptionError("AES-GCM encryption failed") from exc
        finally:
            if pt_is_mutable:
                # best-effort wipe for bytearray inputs
                if isinstance(plaintext, bytearray):
                    zero_memory(plaintext)

        if return_combined:
            combined = ciphertext + tag
            return nonce, combined
        return nonce, ciphertext, tag

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
        """
        Decrypt with AES-256-GCM.

        Args:
            key: 32-byte AES key.
            nonce: 12-byte GCM nonce.
            data: ciphertext||tag if has_combined=True, else ciphertext.
            aad: additional authenticated data (must match encryption AAD).
            has_combined: indicates that `data` includes tag at the end.
            tag: optional explicit 16-byte GCM tag; if provided, overrides has_combined.

        Returns:
            Plaintext bytes.

        Raises:
            DecryptionError: on invalid inputs, mismatched tag, or crypto failure.
        """
        self._validate_key(key)
        self._validate_nonce(nonce)

        # Validate AAD if provided
        if aad is not None:
            if not isinstance(aad, (bytes, bytearray)) or len(aad) == 0:
                raise DecryptionError("AAD must be non-empty bytes when provided")

        if tag is not None:
            if not isinstance(tag, (bytes, bytearray)) or len(tag) != TAG_LEN:
                raise DecryptionError("GCM tag must be 16 bytes")
            ct = data
            tg = bytes(tag)
        else:
            if not has_combined or len(data) < TAG_LEN:
                raise DecryptionError("Combined ciphertext must include 16-byte tag")
            ct = data[:-TAG_LEN]
            tg = data[-TAG_LEN:]

        try:
            cipher = Cipher(algorithms.AES(bytes(key)), modes.GCM(nonce, tg))
            decryptor = cipher.decryptor()
            if aad:
                decryptor.authenticate_additional_data(aad)
            plaintext = decryptor.update(ct) + decryptor.finalize()
            return plaintext
        except InvalidTag as exc:
            _LOGGER.warning("AES-GCM tag verification failed")
            raise DecryptionError("Invalid authentication tag") from exc
        except Exception as exc:
            _LOGGER.error("AES-GCM decryption failed: %s", exc.__class__.__name__)
            raise DecryptionError("AES-GCM decryption failed") from exc


def encrypt_aes_gcm(
    key: bytes,
    plaintext: BytesLike,
    aad: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """
    Functional helper that returns (nonce, ciphertext||tag).

    Example:
        >>> nonce, combined = encrypt_aes_gcm(key=b"0"*32, plaintext=b"hi")
        >>> decrypt_aes_gcm(b"0"*32, nonce, combined) == b"hi"
        True
    """
    # Overload with default Literal[True] ensures precise return type
    return SymmetricCipher().encrypt(key, plaintext, aad, return_combined=True)


def decrypt_aes_gcm(
    key: bytes,
    nonce: bytes,
    combined: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """
    Functional helper for (nonce, ciphertext||tag) tuple.

    Example:
        >>> nonce, combined = encrypt_aes_gcm(key=b"0"*32, plaintext=b"hello")
        >>> decrypt_aes_gcm(b"0"*32, nonce, combined)
        b'hello'
    """
    return SymmetricCipher().decrypt(key, nonce, combined, aad, has_combined=True)
