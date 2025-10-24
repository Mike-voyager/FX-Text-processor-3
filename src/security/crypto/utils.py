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
    _rct_apt_checks(out)
    if n >= _ENTROPY_SAMPLE_THRESHOLD:
        h = _shannon_entropy(out)
        if h < _MIN_SHANNON_PER_BYTE:
            _LOGGER.warning(
                "Entropy check low (%.2f bits/byte) on %d-byte sample; continuing", h, n
            )
    return out


def _rct_apt_checks(data: bytes) -> None:
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
    if not isinstance(length, int) or length < _MIN_SALT or length > _MAX_SALT:
        raise ValueError("Salt length must be between 8 and 64 bytes")
    return generate_random_bytes(length)


def zero_memory(buf: Optional[bytearray]) -> None:
    if buf is None:
        return
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except Exception:
        pass


def secure_compare(a: Union[bytes, bytearray], b: Union[bytes, bytearray]) -> bool:
    return hmac.compare_digest(bytes(a), bytes(b))


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(text: str) -> bytes:
    return bytes.fromhex(text)


def validate_key_length(
    key: Union[bytes, bytearray], expected_length: int, name: str = "key"
) -> None:
    if len(key) != expected_length:
        raise ValueError(
            f"Invalid {name} length: {len(key)} bytes, expected {expected_length}"
        )


def validate_nonce_length(nonce: Union[bytes, bytearray], expected_length: int) -> None:
    if len(nonce) != expected_length:
        raise ValueError(
            f"Invalid nonce length: {len(nonce)} bytes, expected {expected_length}"
        )


def validate_non_empty(data: Union[bytes, bytearray], name: str = "data") -> None:
    if not data:
        raise ValueError(f"{name} cannot be empty")


def set_secure_file_permissions(filepath: str) -> None:
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
