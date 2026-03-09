"""
Сериализация и десериализация криптографических ключей.

Поддерживает форматы RAW, PEM, DER, PKCS8, JWK, COMPACT.
Включает автоопределение формата и компактную сериализацию для floppy.

Example:
    >>> from src.security.crypto.utilities.serialization import (
    ...     serialize_key, deserialize_key, KeyFormat
    ... )
    >>> raw_key = b"\\x00" * 32
    >>> pem = serialize_key(raw_key, KeyFormat.PEM, "aes-256-gcm")
    >>> restored = deserialize_key(pem, KeyFormat.PEM, "aes-256-gcm")

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import base64
import json
import struct
from enum import Enum

from src.security.crypto.core.exceptions import (
    InvalidParameterError,
)

__all__: list[str] = [
    "KeyFormat",
    "serialize_key",
    "deserialize_key",
    "to_pem",
    "from_pem",
    "to_compact",
    "from_compact",
    "detect_format",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"


# ==============================================================================
# KEY FORMAT
# ==============================================================================


class KeyFormat(Enum):
    """Формат сериализации ключа."""

    RAW = "raw"
    PEM = "pem"
    DER = "der"
    PKCS8 = "pkcs8"
    JWK = "jwk"
    COMPACT = "compact"


# ==============================================================================
# PEM ENCODING
# ==============================================================================

_PEM_HEADER_TEMPLATE = "-----BEGIN {key_type} KEY-----"
_PEM_FOOTER_TEMPLATE = "-----END {key_type} KEY-----"


def to_pem(key: bytes, key_type: str = "SYMMETRIC") -> str:
    """
    PEM-кодирование ключа.

    Args:
        key: Данные ключа.
        key_type: Тип ключа ('SYMMETRIC', 'PUBLIC', 'PRIVATE').

    Returns:
        PEM-закодированная строка.

    Example:
        >>> pem = to_pem(b"\\x00" * 32, "SYMMETRIC")
        >>> pem.startswith("-----BEGIN SYMMETRIC KEY-----")
        True
    """
    b64 = base64.b64encode(key).decode("ascii")
    # Разбиваем на строки по 64 символа
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    header = _PEM_HEADER_TEMPLATE.format(key_type=key_type.upper())
    footer = _PEM_FOOTER_TEMPLATE.format(key_type=key_type.upper())
    return header + "\n" + "\n".join(lines) + "\n" + footer


def from_pem(pem_data: str) -> bytes:
    """
    Декодирование PEM-данных.

    Args:
        pem_data: PEM-закодированная строка.

    Returns:
        Декодированные байты ключа.

    Raises:
        InvalidParameterError: Если данные не в формате PEM.
    """
    lines = pem_data.strip().splitlines()
    if len(lines) < 3:
        raise InvalidParameterError(
            parameter_name="pem_data",
            reason="Некорректный PEM: слишком мало строк",
        )
    if not lines[0].startswith("-----BEGIN") or not lines[-1].startswith("-----END"):
        raise InvalidParameterError(
            parameter_name="pem_data",
            reason="Некорректный PEM: отсутствуют BEGIN/END маркеры",
        )

    b64_data = "".join(lines[1:-1])
    try:
        return base64.b64decode(b64_data)
    except Exception as e:
        raise InvalidParameterError(
            parameter_name="pem_data",
            reason=f"Некорректный PEM: ошибка Base64: {e}",
        ) from e


# ==============================================================================
# COMPACT FORMAT (для floppy)
# ==============================================================================

# Формат: [1 байт длина имени алгоритма][имя][данные ключа]
_COMPACT_MAGIC = b"\xcf"  # Compact Format magic byte


def to_compact(key: bytes) -> bytes:
    """
    Минимальный формат сериализации для floppy.

    Формат: magic(1) + length(2, big-endian) + key_data.

    Args:
        key: Данные ключа.

    Returns:
        Компактно сериализованные данные.
    """
    length = len(key)
    return _COMPACT_MAGIC + struct.pack(">H", length) + key


def from_compact(data: bytes) -> bytes:
    """
    Декодирование компактного формата.

    Args:
        data: Компактно сериализованные данные.

    Returns:
        Данные ключа.

    Raises:
        InvalidParameterError: Если данные некорректны.
    """
    if len(data) < 3:
        raise InvalidParameterError(
            parameter_name="data",
            reason="Compact format: данные слишком короткие",
        )
    if data[0:1] != _COMPACT_MAGIC:
        raise InvalidParameterError(
            parameter_name="data",
            reason="Compact format: неверный magic byte",
        )

    length = struct.unpack(">H", data[1:3])[0]
    key_data = data[3:]
    if len(key_data) != length:
        raise InvalidParameterError(
            parameter_name="data",
            reason=f"Compact format: ожидалось {length} байт, получено {len(key_data)}",
        )
    return key_data


# ==============================================================================
# FORMAT DETECTION
# ==============================================================================


def detect_format(data: bytes) -> KeyFormat:
    """
    Автоопределение формата ключа.

    Args:
        data: Данные для анализа.

    Returns:
        Определённый формат ключа.
    """
    # PEM
    try:
        text = data.decode("ascii", errors="strict")
        if text.strip().startswith("-----BEGIN"):
            return KeyFormat.PEM
    except (UnicodeDecodeError, ValueError):
        pass

    # JWK (JSON)
    try:
        text = data.decode("utf-8", errors="strict")
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "kty" in parsed:
            return KeyFormat.JWK
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        pass

    # Compact
    if len(data) >= 3 and data[0:1] == _COMPACT_MAGIC:
        return KeyFormat.COMPACT

    # DER (ASN.1 SEQUENCE tag = 0x30)
    if len(data) > 2 and data[0] == 0x30:
        return KeyFormat.DER

    return KeyFormat.RAW


# ==============================================================================
# SERIALIZE / DESERIALIZE
# ==============================================================================


def serialize_key(
    key: bytes,
    fmt: KeyFormat,
    algorithm: str,
) -> bytes:
    """
    Сериализация ключа в указанный формат.

    Args:
        key: Данные ключа.
        fmt: Целевой формат.
        algorithm: Имя алгоритма (для метаданных).

    Returns:
        Сериализованные данные.

    Raises:
        InvalidParameterError: Если формат не поддерживается.
    """
    if fmt == KeyFormat.RAW:
        return key

    if fmt == KeyFormat.PEM:
        return to_pem(key, _algorithm_to_key_type(algorithm)).encode("ascii")

    if fmt == KeyFormat.COMPACT:
        return to_compact(key)

    if fmt == KeyFormat.JWK:
        jwk = {
            "kty": "oct",
            "k": base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii"),
            "alg": algorithm,
        }
        return json.dumps(jwk, separators=(",", ":")).encode("utf-8")

    if fmt == KeyFormat.DER:
        # Простая DER-обёртка: OCTET STRING
        length = len(key)
        if length < 128:
            header = bytes([0x04, length])
        else:
            # Длинная форма
            len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
            header = bytes([0x04, 0x80 | len(len_bytes)]) + len_bytes
        return header + key

    if fmt == KeyFormat.PKCS8:
        # Упрощённая PKCS8 обёртка для симметричных ключей
        return serialize_key(key, KeyFormat.DER, algorithm)

    raise InvalidParameterError(
        parameter_name="fmt",
        reason=f"Формат не поддерживается: {fmt.value}",
    )


def deserialize_key(
    data: bytes,
    fmt: KeyFormat,
    algorithm: str,
) -> bytes:
    """
    Десериализация ключа из указанного формата.

    Args:
        data: Сериализованные данные.
        fmt: Формат данных.
        algorithm: Имя алгоритма.

    Returns:
        Данные ключа.

    Raises:
        InvalidParameterError: Если формат не поддерживается.
    """
    if fmt == KeyFormat.RAW:
        return data

    if fmt == KeyFormat.PEM:
        return from_pem(data.decode("ascii"))

    if fmt == KeyFormat.COMPACT:
        return from_compact(data)

    if fmt == KeyFormat.JWK:
        try:
            jwk = json.loads(data.decode("utf-8"))
            k = jwk["k"]
            # Добавляем padding
            padding = 4 - len(k) % 4
            if padding != 4:
                k += "=" * padding
            return base64.urlsafe_b64decode(k)
        except (json.JSONDecodeError, KeyError, Exception) as e:
            raise InvalidParameterError(
                parameter_name="data",
                reason=f"Некорректный JWK: {e}",
            ) from e

    if fmt == KeyFormat.DER:
        # Разбор DER OCTET STRING
        if len(data) < 2 or data[0] != 0x04:
            raise InvalidParameterError(
                parameter_name="data",
                reason="Некорректный DER: ожидался OCTET STRING (0x04)",
            )
        if data[1] < 128:
            return data[2 : 2 + data[1]]
        else:
            num_len_bytes = data[1] & 0x7F
            length = int.from_bytes(data[2 : 2 + num_len_bytes], "big")
            offset = 2 + num_len_bytes
            return data[offset : offset + length]

    if fmt == KeyFormat.PKCS8:
        return deserialize_key(data, KeyFormat.DER, algorithm)

    raise InvalidParameterError(
        parameter_name="fmt",
        reason=f"Формат не поддерживается: {fmt.value}",
    )


# ==============================================================================
# HELPERS
# ==============================================================================


def _algorithm_to_key_type(algorithm: str) -> str:
    """Определение типа ключа по алгоритму."""
    algo = algorithm.lower()
    if any(k in algo for k in ("rsa", "ec", "ed25519", "ed448")):
        return "PRIVATE"
    return "SYMMETRIC"
