# -*- coding: utf-8 -*-
"""
RU: Криптографические утилиты: RNG через HKDF‑микширование, проверки энтропии,
best‑effort зануление буферов, сравнение в константное время, кодеки Base64/Hex,
валидации длины ключей/nonce и установка строгих прав на файлы.
"""
from __future__ import annotations

import base64
import hmac
import logging
import math
import os
import secrets
from collections import Counter
from typing import Final, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_LOGGER: Final = logging.getLogger(__name__)

_MAX_RANDOM_BYTES: Final[int] = 10 * 1024 * 1024
_MIN_SALT: Final[int] = 8
_MAX_SALT: Final[int] = 64
_ENTROPY_SAMPLE_THRESHOLD: Final[int] = 256
_MIN_SHANNON_PER_BYTE: Final[float] = 7.20
_SMALL_APT_MIN_N: Final[int] = 32


def generate_random_bytes(n: int) -> bytes:
    """
    Generate cryptographically secure random bytes with entropy checks.

    Uses dual-source XOR (os.urandom + secrets.token_bytes) mixed via HKDF-SHA256
    for defense-in-depth against RNG failures.

    Args:
        n: number of bytes to generate (1..10MiB).

    Returns:
        Random bytes of requested length.

    Raises:
        ValueError: if n is out of range or entropy checks fail.
    """
    if not isinstance(n, int) or n <= 0 or n > _MAX_RANDOM_BYTES:
        raise ValueError("Requested random size must be in 1..10MiB")

    src1 = os.urandom(n)
    src2 = secrets.token_bytes(n)
    ikm = bytes(a ^ b for a, b in zip(src1, src2))
    salt = src2[:16] if len(src2) >= 16 else src2
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=n, salt=salt, info=b"FXTP3-UTILS-RNG-v1"
    )
    out = hkdf.derive(ikm)

    # Entropy quality checks
    _rct_apt_checks(out)
    if n >= _ENTROPY_SAMPLE_THRESHOLD:
        h = _shannon_entropy(out)
        if h < _MIN_SHANNON_PER_BYTE:
            _LOGGER.warning(
                "Entropy check low (%.2f bits/byte) on %d-byte sample; continuing", h, n
            )

    _LOGGER.debug(
        "Generated %d random bytes (entropy: %.2f bits/byte)", n, _shannon_entropy(out)
    )
    return out


def _rct_apt_checks(data: bytes) -> None:
    """
    Repetition Count Test (RCT) and Adaptive Proportion Test (APT) sanity checks.

    Args:
        data: random bytes to check.

    Raises:
        ValueError: if data fails basic entropy sanity checks.
    """
    if not data:
        raise ValueError("Empty data for entropy checks")
    if all(b == data[0] for b in data):
        raise ValueError("Degenerate RNG output (all bytes equal)")
    if len(data) >= _SMALL_APT_MIN_N:
        freq: Counter[int] = Counter(data)
        max_prop = max(freq.values()) / float(len(data))
        if max_prop > 0.80:
            raise ValueError("RNG output fails adaptive proportion sanity check")


def _shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy in bits per byte.

    Args:
        data: bytes to analyze.

    Returns:
        Entropy value (0.0 to 8.0 bits/byte).
    """
    if not data:
        return 0.0
    freq: Counter[int] = Counter(data)
    n = len(data)
    ent: float = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def generate_salt(length: int) -> bytes:
    """
    Generate cryptographic salt.

    Args:
        length: salt length in bytes (8..64).

    Returns:
        Random salt bytes.

    Raises:
        ValueError: if length out of valid range.
    """
    if not isinstance(length, int) or length < _MIN_SALT or length > _MAX_SALT:
        raise ValueError("Salt length must be between 8 and 64 bytes")
    return generate_random_bytes(length)


def zero_memory(buf: Optional[bytearray]) -> None:
    """
    Best-effort zeroization of mutable buffer.

    Args:
        buf: bytearray to wipe (None is silently ignored).

    Notes:
        - Only works on bytearray (mutable); bytes cannot be wiped.
        - Ограничения Python: сборщик мусора, string interning, swap-файлы
        и оптимизации компилятора означают, что истинное криптографическое стирание
        недостижимо на чистом Python.
        - Для высокозащищённого ключевого материала используйте: HSM, TPM, secure enclave (SGX),
        или предоставляемые ОС API безопасной памяти через C-расширения (например, libsodium).
        - Эта функция обеспечивает эшелонированную защиту от случайных дампов памяти.
    """
    if buf is None:
        return
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except (TypeError, AttributeError) as e:
        # Expected for immutable types
        _LOGGER.debug("zero_memory skip (immutable): %s", e.__class__.__name__)
    except Exception as e:
        # Unexpected errors should be logged (not secrets, just error type)
        _LOGGER.warning("zero_memory failed: %s", e.__class__.__name__)


def secure_compare(a: Union[bytes, bytearray], b: Union[bytes, bytearray]) -> bool:
    """
    Constant-time bytes comparison.

    Args:
        a: first bytes sequence.
        b: second bytes sequence.

    Returns:
        True if sequences are equal, False otherwise.
    """
    return hmac.compare_digest(bytes(a), bytes(b))


def b64_encode(data: bytes) -> str:
    """
    Encode bytes to base64 ASCII string.

    Args:
        data: bytes to encode.

    Returns:
        Base64 string (no newlines).
    """
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: str) -> bytes:
    """
    Decode base64 ASCII string to bytes.

    Args:
        text: base64 string.

    Returns:
        Decoded bytes.

    Raises:
        ValueError: on invalid base64.
    """
    return base64.b64decode(text.encode("ascii"), validate=True)


def hex_encode(data: bytes) -> str:
    """
    Encode bytes to hexadecimal string.

    Args:
        data: bytes to encode.

    Returns:
        Lowercase hex string.
    """
    return data.hex()


def hex_decode(text: str) -> bytes:
    """
    Decode hexadecimal string to bytes.

    Args:
        text: hex string (case-insensitive).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: on invalid hex.
    """
    return bytes.fromhex(text)


def validate_key_length(
    key: Union[bytes, bytearray], expected_length: int, name: str = "key"
) -> None:
    """
    Validate key length.

    Args:
        key: key material to validate.
        expected_length: expected length in bytes.
        name: key name for error messages.

    Raises:
        ValueError: if length mismatch.
    """
    if len(key) != expected_length:
        raise ValueError(
            f"Invalid {name} length: {len(key)} bytes, expected {expected_length}"
        )


def validate_nonce_length(nonce: Union[bytes, bytearray], expected_length: int) -> None:
    """
    Validate nonce length.

    Args:
        nonce: nonce to validate.
        expected_length: expected length in bytes.

    Raises:
        ValueError: if length mismatch.
    """
    if len(nonce) != expected_length:
        raise ValueError(
            f"Invalid nonce length: {len(nonce)} bytes, expected {expected_length}"
        )


def validate_non_empty(data: Union[bytes, bytearray], name: str = "data") -> None:
    """
    Validate data is non-empty.

    Args:
        data: bytes to validate.
        name: data name for error messages.

    Raises:
        ValueError: if data is empty.
    """
    if not data:
        raise ValueError(f"{name} cannot be empty")


def set_secure_file_permissions(filepath: str) -> None:
    """
    Set strict file permissions (0600 on POSIX, equivalent on Windows).

    Args:
        filepath: path to file.

    Notes:
        - POSIX: chmod 0600 (owner read/write only)
        - Windows: best-effort via os.chmod (limited effect)
        - Logs warning on failure (non-fatal)
    """
    try:
        import stat

        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
        _LOGGER.debug("Applied 0600 permissions to %s", filepath)
    except Exception as e:
        _LOGGER.warning("Could not set strict permissions for %s: %s", filepath, e)


__all__ = [
    "generate_random_bytes",
    "generate_salt",
    "zero_memory",
    "secure_compare",
    "b64_encode",
    "b64_decode",
    "hex_encode",
    "hex_decode",
    "validate_key_length",
    "validate_nonce_length",
    "validate_non_empty",
    "set_secure_file_permissions",
]
