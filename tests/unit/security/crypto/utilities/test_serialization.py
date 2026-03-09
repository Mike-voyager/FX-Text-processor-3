"""
Тесты для модуля сериализации криптографических ключей.

Покрытие:
- KeyFormat: все значения enum
- to_pem / from_pem: roundtrip, плохой PEM (мало строк, нет маркеров, битый base64)
- to_compact / from_compact: roundtrip, слишком короткие данные, неверный magic,
  несовпадение длины
- detect_format: PEM, JWK, COMPACT, DER, RAW
- serialize_key / deserialize_key: roundtrip для всех форматов
- DER: короткая (<128) и длинная (>=128) формы
- PKCS8: делегирует в DER
- _algorithm_to_key_type: symmetric vs asymmetric

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 10, 2026
"""

from __future__ import annotations

import json

import pytest
from src.security.crypto.core.exceptions import InvalidParameterError
from src.security.crypto.utilities.serialization import (
    KeyFormat,
    deserialize_key,
    detect_format,
    from_compact,
    from_pem,
    serialize_key,
    to_compact,
    to_pem,
)

# ==============================================================================
# KeyFormat
# ==============================================================================


class TestKeyFormat:
    def test_all_values(self) -> None:
        values = {f.value for f in KeyFormat}
        assert values == {"raw", "pem", "der", "pkcs8", "jwk", "compact"}

    def test_enum_members(self) -> None:
        assert KeyFormat.RAW.value == "raw"
        assert KeyFormat.PEM.value == "pem"
        assert KeyFormat.DER.value == "der"
        assert KeyFormat.PKCS8.value == "pkcs8"
        assert KeyFormat.JWK.value == "jwk"
        assert KeyFormat.COMPACT.value == "compact"


# ==============================================================================
# to_pem / from_pem
# ==============================================================================


class TestPem:
    def test_roundtrip_symmetric(self) -> None:
        key = b"\x42" * 32
        pem = to_pem(key, "SYMMETRIC")
        assert from_pem(pem) == key

    def test_roundtrip_private(self) -> None:
        key = b"\xab" * 48
        pem = to_pem(key, "PRIVATE")
        assert from_pem(pem) == key

    def test_pem_has_begin_end_markers(self) -> None:
        pem = to_pem(b"\x00" * 32)
        assert pem.startswith("-----BEGIN SYMMETRIC KEY-----")
        assert pem.endswith("-----END SYMMETRIC KEY-----")

    def test_pem_key_type_uppercase(self) -> None:
        pem = to_pem(b"\x00" * 16, "private")
        assert "-----BEGIN PRIVATE KEY-----" in pem

    def test_pem_line_wrap_64(self) -> None:
        key = b"\xff" * 64  # 64 bytes → 88 base64 chars → 2 lines
        pem = to_pem(key)
        lines = pem.splitlines()
        body_lines = lines[1:-1]
        for line in body_lines:
            assert len(line) <= 64

    def test_from_pem_too_few_lines_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            from_pem("-----BEGIN KEY-----\n-----END KEY-----")

    def test_from_pem_missing_begin_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            from_pem("not a begin\nYWJj\n-----END KEY-----")

    def test_from_pem_missing_end_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            from_pem("-----BEGIN KEY-----\nYWJj\nnot an end")

    def test_from_pem_bad_base64_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            from_pem("-----BEGIN KEY-----\n!!!invalid_base64!!!\n-----END KEY-----")


# ==============================================================================
# to_compact / from_compact
# ==============================================================================


class TestCompact:
    def test_roundtrip(self) -> None:
        key = b"\xde\xad\xbe\xef" * 8
        data = to_compact(key)
        assert from_compact(data) == key

    def test_compact_magic_byte(self) -> None:
        data = to_compact(b"\x00" * 16)
        assert data[0:1] == b"\xcf"

    def test_compact_length_encoded(self) -> None:
        key = b"\x00" * 32
        data = to_compact(key)
        # bytes 1-2 = big-endian length = 32 = 0x0020
        assert data[1] == 0x00
        assert data[2] == 32

    def test_from_compact_too_short_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            from_compact(b"\xcf\x00")

    def test_from_compact_bad_magic_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            from_compact(b"\xde\x00\x05hello")

    def test_from_compact_length_mismatch_raises(self) -> None:
        # Объявляем length=10, но данных только 5
        import struct

        bad = b"\xcf" + struct.pack(">H", 10) + b"hello"
        with pytest.raises(InvalidParameterError):
            from_compact(bad)

    def test_roundtrip_empty_key(self) -> None:
        data = to_compact(b"")
        assert from_compact(data) == b""


# ==============================================================================
# detect_format
# ==============================================================================


class TestDetectFormat:
    def test_detect_pem(self) -> None:
        pem = to_pem(b"\x00" * 32).encode("ascii")
        assert detect_format(pem) == KeyFormat.PEM

    def test_detect_jwk(self) -> None:
        jwk = json.dumps({"kty": "oct", "k": "abc", "alg": "AES"}).encode("utf-8")
        assert detect_format(jwk) == KeyFormat.JWK

    def test_detect_compact(self) -> None:
        data = to_compact(b"\x00" * 16)
        assert detect_format(data) == KeyFormat.COMPACT

    def test_detect_der(self) -> None:
        # DER распознаётся по ASN.1 SEQUENCE tag = 0x30
        data = bytes([0x30, 0x10]) + b"\x00" * 16
        assert detect_format(data) == KeyFormat.DER

    def test_detect_raw(self) -> None:
        # Случайные байты без специальных маркеров
        data = b"\xab\xcd" * 16
        assert detect_format(data) == KeyFormat.RAW

    def test_detect_json_without_kty_is_raw(self) -> None:
        # JSON, но без поля "kty"
        data = json.dumps({"key": "value"}).encode("utf-8")
        # Нет kty → не JWK → RAW (начинается с {)
        result = detect_format(data)
        assert result in (KeyFormat.RAW, KeyFormat.DER)


# ==============================================================================
# serialize_key / deserialize_key roundtrip
# ==============================================================================


class TestSerializeDeserializeRoundtrip:
    KEY_32 = b"\x11" * 32

    def test_raw_roundtrip(self) -> None:
        data = serialize_key(self.KEY_32, KeyFormat.RAW, "aes-256-gcm")
        assert deserialize_key(data, KeyFormat.RAW, "aes-256-gcm") == self.KEY_32

    def test_pem_roundtrip(self) -> None:
        data = serialize_key(self.KEY_32, KeyFormat.PEM, "aes-256-gcm")
        assert deserialize_key(data, KeyFormat.PEM, "aes-256-gcm") == self.KEY_32

    def test_compact_roundtrip(self) -> None:
        data = serialize_key(self.KEY_32, KeyFormat.COMPACT, "aes-256-gcm")
        assert deserialize_key(data, KeyFormat.COMPACT, "aes-256-gcm") == self.KEY_32

    def test_jwk_roundtrip(self) -> None:
        data = serialize_key(self.KEY_32, KeyFormat.JWK, "aes-256-gcm")
        assert deserialize_key(data, KeyFormat.JWK, "aes-256-gcm") == self.KEY_32

    def test_der_roundtrip_short_key(self) -> None:
        key = b"\xaa" * 16  # < 128 bytes
        data = serialize_key(key, KeyFormat.DER, "aes-128-gcm")
        assert deserialize_key(data, KeyFormat.DER, "aes-128-gcm") == key

    def test_der_roundtrip_long_key(self) -> None:
        key = b"\xbb" * 200  # > 128 bytes → длинная форма
        data = serialize_key(key, KeyFormat.DER, "aes-256-gcm")
        assert deserialize_key(data, KeyFormat.DER, "aes-256-gcm") == key

    def test_pkcs8_roundtrip(self) -> None:
        data = serialize_key(self.KEY_32, KeyFormat.PKCS8, "aes-256-gcm")
        assert deserialize_key(data, KeyFormat.PKCS8, "aes-256-gcm") == self.KEY_32

    def test_pem_algorithm_private_key(self) -> None:
        key = b"\xcc" * 32
        data = serialize_key(key, KeyFormat.PEM, "rsa-2048")
        pem_str = data.decode("ascii")
        assert "PRIVATE" in pem_str
        assert deserialize_key(data, KeyFormat.PEM, "rsa-2048") == key

    def test_pem_algorithm_symmetric_key(self) -> None:
        key = b"\xdd" * 32
        data = serialize_key(key, KeyFormat.PEM, "aes-256-gcm")
        pem_str = data.decode("ascii")
        assert "SYMMETRIC" in pem_str


# ==============================================================================
# serialize_key edge cases
# ==============================================================================


class TestSerializeKeyEdgeCases:
    def test_jwk_contains_kty_oct(self) -> None:
        data = serialize_key(b"\x00" * 32, KeyFormat.JWK, "aes-256-gcm")
        jwk = json.loads(data.decode("utf-8"))
        assert jwk["kty"] == "oct"
        assert "k" in jwk
        assert "alg" in jwk

    def test_der_short_form_header(self) -> None:
        key = b"\xaa" * 16
        data = serialize_key(key, KeyFormat.DER, "aes-128-gcm")
        assert data[0] == 0x04  # OCTET STRING tag
        assert data[1] == 16  # length

    def test_der_long_form_header(self) -> None:
        key = b"\xbb" * 200
        data = serialize_key(key, KeyFormat.DER, "aes-256-gcm")
        assert data[0] == 0x04
        assert data[1] & 0x80  # длинная форма


# ==============================================================================
# deserialize_key edge cases
# ==============================================================================


class TestDeserializeKeyEdgeCases:
    def test_jwk_missing_k_raises(self) -> None:
        bad_jwk = json.dumps({"kty": "oct"}).encode("utf-8")
        with pytest.raises(InvalidParameterError):
            deserialize_key(bad_jwk, KeyFormat.JWK, "aes-256-gcm")

    def test_der_bad_tag_raises(self) -> None:
        data = bytes([0x30, 0x10]) + b"\x00" * 16  # SEQUENCE, not OCTET STRING
        with pytest.raises(InvalidParameterError):
            deserialize_key(data, KeyFormat.DER, "aes-256-gcm")

    def test_der_too_short_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            deserialize_key(bytes([0x04]), KeyFormat.DER, "aes-256-gcm")

    def test_compact_bad_magic_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            deserialize_key(b"\xff\x00\x05hello", KeyFormat.COMPACT, "aes-256-gcm")
