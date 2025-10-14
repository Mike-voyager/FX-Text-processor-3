# tests/unit/crypto/test_kdf.py

"""
Extended unit tests for security.crypto.kdf.
Goal: raise branch and line coverage >97% (edge diagnostics, exceptions, serialization branches).
"""

import pytest
import secrets
from typing import Any, Dict

from src.security.crypto.kdf import (
    derive_key,
    validate_parameters,
    generate_salt,
    recommend_entropy_warning,
    KDFAlgorithm,
    KDFParameterError,
    KDFAlgorithmError,
    KDFEntropyWarning,
)


def test_generate_salt_len() -> None:
    for length in (8, 16, 24, 32, 48, 64):
        salt = generate_salt(length)
        assert isinstance(salt, bytes)
        assert len(salt) == length


def test_generate_salt_errors() -> None:
    with pytest.raises(KDFParameterError):
        generate_salt(7)
    with pytest.raises(KDFParameterError):
        generate_salt(100)


def test_entropy_warning_low_password(monkeypatch: Any) -> None:
    pw = b"aaaaaaaab"
    salt = generate_salt(16)
    with pytest.raises(KDFEntropyWarning):
        derive_key(
            algorithm=KDFAlgorithm.ARGON2ID,
            password=pw,
            salt=salt,
            length=32,
            time_cost=2,
            memory_cost=65536,
            parallelism=2,
        )


def test_entropy_warning_low_salt() -> None:
    pw = b"supersafepassword"
    salt = b"bbbbbbbbb"
    recommend_entropy_warning(pw, salt)  # warning only, no raise


def test_entropy_warning_good_entropy() -> None:
    pw = b"good_pw_long_and_unique"
    salt = generate_salt(16)
    recommend_entropy_warning(pw, salt)  # should NOT raise or warn


def test_argon2id_returns_bytes_and_hex_and_b64() -> None:
    pw = b"securelongenough"
    salt = generate_salt(16)
    key_bytes = derive_key(
        algorithm=KDFAlgorithm.ARGON2ID,
        password=pw,
        salt=salt,
        length=32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
    )
    assert isinstance(key_bytes, bytes)
    key_hex = derive_key(
        algorithm=KDFAlgorithm.ARGON2ID,
        password=pw,
        salt=salt,
        length=32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        to_hex=True,
    )
    assert isinstance(key_hex, str)
    assert len(key_hex) == 64
    key_b64 = derive_key(
        algorithm=KDFAlgorithm.ARGON2ID,
        password=pw,
        salt=salt,
        length=32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        to_b64=True,
    )
    assert isinstance(key_b64, str)
    assert len(key_b64) >= 43


def test_pbkdf2_bytes_hex_b64() -> None:
    pw = b"legacy-best"
    salt = generate_salt(16)
    key_bytes = derive_key(
        algorithm=KDFAlgorithm.PBKDF2_HMAC_SHA256,
        password=pw,
        salt=salt,
        length=24,
        iterations=120_000,
    )
    assert isinstance(key_bytes, bytes)
    key_hex = derive_key(
        algorithm=KDFAlgorithm.PBKDF2_HMAC_SHA256,
        password=pw,
        salt=salt,
        length=24,
        iterations=120_000,
        to_hex=True,
    )
    assert isinstance(key_hex, str)
    assert len(key_hex) == 48
    key_b64 = derive_key(
        algorithm=KDFAlgorithm.PBKDF2_HMAC_SHA256,
        password=pw,
        salt=salt,
        length=24,
        iterations=120_000,
        to_b64=True,
    )
    assert isinstance(key_b64, str)
    assert len(key_b64) >= 31


def test_argon2id_fails_for_param_errors() -> None:
    pw = b"securelongenough"
    salt = generate_salt(16)
    with pytest.raises(KDFParameterError):
        derive_key(
            algorithm=KDFAlgorithm.ARGON2ID,
            password=pw,
            salt=salt,
            length=8,  # too short
            time_cost=0,  # too small
            memory_cost=2**13,  # too small
            parallelism=0,  # too small
        )
    with pytest.raises(KDFParameterError):
        derive_key(
            algorithm=KDFAlgorithm.ARGON2ID,
            password=b"short",  # too short password
            salt=salt,
            length=32,
            time_cost=2,
            memory_cost=65536,
            parallelism=2,
        )
    with pytest.raises(KDFParameterError):
        derive_key(
            algorithm=KDFAlgorithm.ARGON2ID,
            password=pw,
            salt=b"tiny",  # too short salt
            length=32,
            time_cost=2,
            memory_cost=65536,
            parallelism=2,
        )


def test_pbkdf2_fails_for_param_errors() -> None:
    pw = b"legacy-good"
    salt = generate_salt(16)
    with pytest.raises(KDFParameterError):
        derive_key(
            algorithm=KDFAlgorithm.PBKDF2_HMAC_SHA256,
            password=pw,
            salt=salt,
            length=8,
            iterations=100_000,
        )
    with pytest.raises(KDFParameterError):
        derive_key(
            algorithm=KDFAlgorithm.PBKDF2_HMAC_SHA256,
            password=pw,
            salt=b"short",
            length=32,
            iterations=100_000,
        )
    with pytest.raises(KDFParameterError):
        derive_key(
            algorithm=KDFAlgorithm.PBKDF2_HMAC_SHA256,
            password=pw,
            salt=salt,
            length=32,
            iterations=5,
        )


def test_derive_key_auto_salt() -> None:
    pw = b"autosaltpassword"
    key = derive_key(
        algorithm=KDFAlgorithm.ARGON2ID,
        password=pw,
        salt=None,
        length=32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
    )
    assert isinstance(key, bytes) and len(key) == 32


def test_argon2id_determinism() -> None:
    pw = b"deterministic"
    salt = generate_salt(32)
    k1 = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
    )
    k2 = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
    )
    assert k1 == k2
    k3 = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        32,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
    )
    assert k1 != k3


def test_pbkdf2_determinism() -> None:
    pw = b"pbkdf2_x"
    salt = generate_salt(32)
    k1 = derive_key(KDFAlgorithm.PBKDF2_HMAC_SHA256, pw, salt, 32, iterations=100_000)
    k2 = derive_key(KDFAlgorithm.PBKDF2_HMAC_SHA256, pw, salt, 32, iterations=100_000)
    assert k1 == k2
    k3 = derive_key(KDFAlgorithm.PBKDF2_HMAC_SHA256, pw, salt, 32, iterations=120_000)
    assert k1 != k3


def test_derive_key_hex_and_b64_are_distinct() -> None:
    pw = b"distinct-pw"
    salt = generate_salt(32)
    bx = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
    )
    hx = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        to_hex=True,
    )
    b64x = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        to_b64=True,
    )
    assert isinstance(bx, bytes)
    assert isinstance(hx, str)
    assert isinstance(b64x, str)
    assert bx != hx.encode()
    assert bx != b64x.encode()
    assert hx != b64x


def test_key_length_edge_cases() -> None:
    pw = b"edgekeypw"
    salt = generate_salt(32)
    key16 = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        16,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
    )
    key64 = derive_key(
        KDFAlgorithm.ARGON2ID,
        pw,
        salt,
        64,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
    )
    assert len(key16) == 16
    assert len(key64) == 64
