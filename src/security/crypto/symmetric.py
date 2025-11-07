# -*- coding: utf-8 -*-
"""
RU: Симметричное шифрование AES‑256‑GCM с потокобезопасным менеджером nonce-per-key,
унифицированным RNG из utils и best‑effort zeroization.

EN: AES-256-GCM symmetric cipher with thread-safe per-key nonce manager,
unified RNG from utils, and best-effort zeroization.

This module provides:
- Strict nonce-per-key policy using a 96-bit nonce composed of a random 32-bit prefix and
  a 64-bit monotonic counter protected by a lock (per instance). This prevents catastrophic
  nonce reuse under the same key.
- Unified entropy source via security.crypto.utils.generate_random_bytes to centralize
  RNG policy and audits.
- Best-effort zeroization for in-memory mutable buffers (bytearray) using utils.zero_memory.
- Fail-secure exceptions (no silent fallbacks) and log messages without secrets.

Public API remains compatible by exposing both a class (DI-friendly) and plain helpers:
- SymmetricCipher.encrypt/decrypt with flexible combined/separate tag handling.
- encrypt_aes_gcm/decrypt_aes_gcm helpers returning (nonce, ciphertext||tag) and plaintext.

Thread-safety:
- Nonce generation is thread-safe within a SymmetricCipher instance.
- No global state is used; for cross-instance nonce coordination, keep a long-lived DI instance.

Security notes:
- Keys are 32 bytes (AES-256). Nonce is 12 bytes (GCM standard). Tag length is 16 bytes.
- No secrets, keys, nonces, tags, or plaintext fragments are logged.
- Zeroization only applies to mutable bytearray inputs; Python bytes cannot be wiped.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass
from typing import Dict, Final, Literal, Optional, Tuple, Union, overload

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from security.crypto.exceptions import DecryptionError, EncryptionError
from security.crypto.utils import generate_random_bytes, zero_memory

_LOGGER: Final = logging.getLogger(__name__)

KEY_LEN: Final[int] = 32
NONCE_LEN: Final[int] = 12
TAG_LEN: Final[int] = 16

BytesLike = Union[bytes, bytearray]


@dataclass(frozen=True)
class _KeyId:
    """Immutable identifier for a key derived from SHA-256 digest."""

    value: bytes


class _NonceState:
    """
    Per-key nonce state with a 96-bit nonce structure:
    - 32-bit random prefix (stable for the key within this instance)
    - 64-bit big-endian counter (monotonic)
    """

    __slots__ = ("prefix", "counter")

    def __init__(self, prefix: bytes) -> None:
        if len(prefix) != 4:
            raise ValueError("Prefix must be 4 bytes")
        self.prefix: bytes = prefix
        self.counter: int = 0

    def next(self) -> bytes:
        self.counter += 1
        # 64-bit counter, wraps after 2^64 - practically unreachable
        return self.prefix + self.counter.to_bytes(8, "big", signed=False)


class _NonceManager:
    """Thread-safe per-key nonce manager."""

    __slots__ = ("_lock", "_states")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: Dict[bytes, _NonceState] = {}

    def _key_id(self, key: bytes) -> _KeyId:
        h = hashlib.sha256(key).digest()
        return _KeyId(h)

    def next_nonce(self, key: bytes) -> bytes:
        """Return a fresh 12-byte nonce for the given key with per-key monotonicity."""
        kid = self._key_id(key).value
        with self._lock:
            st = self._states.get(kid)
            if st is None:
                prefix = generate_random_bytes(4)
                st = _NonceState(prefix)
                self._states[kid] = st
            return st.next()


class SymmetricCipher:
    """
    AES-256-GCM encryption/decryption with per-key nonce manager.

    Methods:
        encrypt(key, plaintext, aad, return_combined) -> (nonce, combined) or (nonce, ct, tag)
        decrypt(key, nonce, data, aad, has_combined, tag) -> plaintext

    Examples:
        >>> cipher = SymmetricCipher()
        >>> nonce, combined = cipher.encrypt(key=b"0"*32, plaintext=b"hello")
        >>> plain = cipher.decrypt(key=b"0"*32, nonce=nonce, data=combined)
        >>> assert plain == b"hello"
    """

    __slots__ = ("_nonce_mgr",)

    def __init__(self) -> None:
        self._nonce_mgr = _NonceManager()

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
        nonce = self._nonce_mgr.next_nonce(bytes(key))

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
                zero_memory(plaintext)  # type: ignore[arg-type]

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
