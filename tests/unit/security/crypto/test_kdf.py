from __future__ import annotations

import builtins
import sys
import types
from typing import Any, Sequence, cast

import pytest

from security.crypto.kdf import (
    DefaultKdfProvider,
    generate_salt,
    KDFParameterError,
    KDFAlgorithmError,
)
from security.crypto.protocols import PBKDF2Params, Argon2idParams

# --- generate_salt ---


def test_generate_salt_ok_default() -> None:
    s = generate_salt()
    assert isinstance(s, bytes)
    assert 8 <= len(s) <= 64


@pytest.mark.parametrize("n", [7, 65])
def test_generate_salt_invalid_length(n: int) -> None:
    with pytest.raises(KDFParameterError):
        _ = generate_salt(n)


# --- PBKDF2 path ---


def test_pbkdf2_success_and_length_bounds() -> None:
    kdf = DefaultKdfProvider()
    salt = b"SALT0123"
    pb: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }
    # minimal valid length
    key16 = kdf.derive_key("pw", salt, 16, params=pb)
    assert isinstance(key16, (bytes, bytearray)) and len(key16) == 16
    # maximal valid length
    key64 = kdf.derive_key(b"pw", salt, 64, params=pb)
    assert isinstance(key64, (bytes, bytearray)) and len(key64) == 64


@pytest.mark.parametrize(
    "params",
    [
        cast(
            PBKDF2Params,
            {
                "version": "pbkdf2",
                "iterations": 99_999,
                "hash_name": "sha256",
                "salt_len": 16,
            },
        ),
        cast(
            PBKDF2Params,
            {
                "version": "pbkdf2",
                "iterations": 100_000,
                "hash_name": "sha1",
                "salt_len": 16,
            },
        ),
    ],
)
def test_pbkdf2_invalid_params_raise(params: PBKDF2Params) -> None:
    kdf = DefaultKdfProvider()
    with pytest.raises(KDFParameterError):
        _ = kdf.derive_key("pw", b"SALT0123", 32, params=params)


@pytest.mark.parametrize("length", [15, 65])
def test_pbkdf2_invalid_output_length(length: int) -> None:
    kdf = DefaultKdfProvider()
    pb: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }
    with pytest.raises(KDFParameterError):
        _ = kdf.derive_key("pw", b"SALT0123", length, params=pb)


@pytest.mark.parametrize("salt", [b"short", b"x" * 65])
def test_pbkdf2_invalid_salt_bounds(salt: bytes) -> None:
    kdf = DefaultKdfProvider()
    pb: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }
    with pytest.raises(KDFParameterError):
        _ = kdf.derive_key("pw", salt, 32, params=pb)


def test_pbkdf2_password_types_and_zeroization() -> None:
    kdf = DefaultKdfProvider()
    salt = b"SALT0123"
    pb: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }
    # str password
    k1 = kdf.derive_key("pw", salt, 32, params=pb)
    # bytes password
    k2 = kdf.derive_key(b"pw", salt, 32, params=pb)
    # bytearray password with zeroization best‑effort
    ba = bytearray(b"secretpw")
    k3 = kdf.derive_key(ba, salt, 32, params=pb)
    assert len(k1) == len(k2) == len(k3) == 32
    assert all(b == 0 for b in ba)


def test_pbkdf2_unsupported_version_raises() -> None:
    kdf = DefaultKdfProvider()
    with pytest.raises(KDFAlgorithmError):
        _ = kdf.derive_key(
            "pw", b"SALT0123", 32, params=cast(Any, {"version": "scrypt"})
        )


# --- Argon2id path ---


def test_argon2id_unavailable_maps_to_algorithm_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # подменим импорт так, чтобы он падал
    original_import = builtins.__import__

    def fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> Any:
        if name == "argon2.low_level":
            raise ImportError("no module")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    kdf = DefaultKdfProvider()
    ap: Argon2idParams = {
        "version": "argon2id",
        "time_cost": 2,
        "memory_cost": 65536,
        "parallelism": 1,
        "salt_len": 16,
    }
    with pytest.raises(KDFAlgorithmError):
        _ = kdf.derive_key("pw", b"SALT0123", 32, params=ap)


def test_argon2id_invalid_params_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    # эмулируем наличие argon2.low_level и валидный hash_secret_raw, проверяем валидацию
    def hash_secret_raw(**kwargs: Any) -> bytes:
        return b"x" * int(kwargs["hash_len"])

    class TypeNS:
        ID = 1

    fake = types.SimpleNamespace(hash_secret_raw=hash_secret_raw, Type=TypeNS)
    monkeypatch.setitem(sys.modules, "argon2.low_level", fake)

    kdf = DefaultKdfProvider()

    with pytest.raises(KDFParameterError):
        ap_bad: Argon2idParams = {
            "version": "argon2id",
            "time_cost": 1,
            "memory_cost": 65536,
            "parallelism": 1,
            "salt_len": 16,
        }
        _ = kdf.derive_key("pw", b"SALT0123", 32, params=ap_bad)

    with pytest.raises(KDFParameterError):
        ap_bad2: Argon2idParams = {
            "version": "argon2id",
            "time_cost": 2,
            "memory_cost": 65535,
            "parallelism": 1,
            "salt_len": 16,
        }
        _ = kdf.derive_key("pw", b"SALT0123", 32, params=ap_bad2)

    with pytest.raises(KDFParameterError):
        ap_bad3: Argon2idParams = {
            "version": "argon2id",
            "time_cost": 2,
            "memory_cost": 65536,
            "parallelism": 0,
            "salt_len": 16,
        }
        _ = kdf.derive_key("pw", b"SALT0123", 32, params=ap_bad3)


def test_argon2id_success_and_fixed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def hash_secret_raw(**kwargs: Any) -> bytes:
        captured.update(kwargs)
        return b"Y" * int(kwargs["hash_len"])

    class TypeNS:
        ID = 1

    fake = types.SimpleNamespace(hash_secret_raw=hash_secret_raw, Type=TypeNS)
    monkeypatch.setitem(sys.modules, "argon2.low_level", fake)

    kdf = DefaultKdfProvider()
    ap: Argon2idParams = {
        "version": "argon2id",
        "time_cost": 2,
        "memory_cost": 65536,
        "parallelism": 1,
        "salt_len": 16,
    }
    key = kdf.derive_key("pw", b"SALT0123", 32, params=ap)
    assert isinstance(key, (bytes, bytearray)) and len(key) == 32
    assert captured.get("version") == 19
    assert captured.get("type") == TypeNS.ID


# --- Generic input validation ---


def test_invalid_password_type_raises() -> None:
    kdf = DefaultKdfProvider()
    pb: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }
    with pytest.raises(KDFParameterError):
        _ = kdf.derive_key(cast(object, 123), b"SALT0123", 32, params=pb)  # type: ignore


def test_invalid_salt_type_raises() -> None:
    kdf = DefaultKdfProvider()
    pb: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }
    with pytest.raises(KDFParameterError):
        _ = kdf.derive_key("pw", cast(bytes, "SALTSTR"), 32, params=pb)


def test_generate_salt_maps_valueerror(monkeypatch: pytest.MonkeyPatch) -> None:
    # Подменяем utils.generate_salt, чтобы он бросил ValueError
    from security.crypto import kdf as kdf_mod

    def boom(length: int) -> bytes:
        raise ValueError("rng failure")

    monkeypatch.setattr(kdf_mod, "_utils_generate_salt", boom)
    with pytest.raises(KDFParameterError):
        _ = kdf_mod.generate_salt(16)


def test_pbkdf2_internal_failure_maps_to_algorithm_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kdf = DefaultKdfProvider()
    pb: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }

    def pbkdf2_fail(name: str, pw: bytes, salt: bytes, iters: int, dklen: int) -> bytes:
        raise RuntimeError("engine fail")

    monkeypatch.setattr("hashlib.pbkdf2_hmac", pbkdf2_fail)
    with pytest.raises(KDFAlgorithmError):
        _ = kdf.derive_key("pw", b"SALT0123", 32, params=pb)


def test_argon2id_internal_failure_maps_to_algorithm_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def hash_secret_raw(**kwargs: Any) -> bytes:
        raise RuntimeError("argon2 core fail")

    class TypeNS:
        ID = 1

    fake = types.SimpleNamespace(hash_secret_raw=hash_secret_raw, Type=TypeNS)
    monkeypatch.setitem(sys.modules, "argon2.low_level", fake)
    kdf = DefaultKdfProvider()
    ap: Argon2idParams = {
        "version": "argon2id",
        "time_cost": 2,
        "memory_cost": 65536,
        "parallelism": 1,
        "salt_len": 16,
    }
    with pytest.raises(KDFAlgorithmError):
        _ = kdf.derive_key("pw", b"SALT0123", 32, params=ap)
