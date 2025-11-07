from __future__ import annotations

import concurrent.futures
import os
from typing import Callable, Dict, Tuple, cast  # NEW

import pytest

from security.crypto import utils as utils_mod
from security.crypto.exceptions import DecryptionError, EncryptionError
from security.crypto.symmetric import (
    KEY_LEN,
    NONCE_LEN,
    TAG_LEN,
    SymmetricCipher,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
)


def test_roundtrip_basic() -> None:
    key = b"\x01" * KEY_LEN
    cipher = SymmetricCipher()
    nonce, combined = cast(
        Tuple[bytes, bytes], cipher.encrypt(key, b"hello", aad=b"hdr")
    )  # NEW
    assert isinstance(nonce, bytes) and len(nonce) == NONCE_LEN
    pt = cipher.decrypt(key, nonce, combined, aad=b"hdr")
    assert pt == b"hello"


def test_roundtrip_with_separate_tag() -> None:
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher()
    nonce, ct, tag = cast(
        Tuple[bytes, bytes, bytes],
        cipher.encrypt(key, b"payload", return_combined=False),
    )  # NEW
    assert len(tag) == TAG_LEN and len(nonce) == NONCE_LEN
    pt = cipher.decrypt(key, nonce, ct, tag=tag)
    assert pt == b"payload"


def test_encrypt_uses_utils_rng_for_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    called: Dict[str, int] = {"n": 0}

    def fake_rng(n: int) -> bytes:
        called["n"] += 1
        assert n == 4
        return b"\x00\x00\x00\x01"

    monkeypatch.setattr(
        "security.crypto.symmetric.generate_random_bytes", fake_rng, raising=True
    )

    key = b"\x02" * KEY_LEN
    cipher = SymmetricCipher()
    nonce1, combined1 = cast(
        Tuple[bytes, bytes], cipher.encrypt(key, b"a")
    )  # NEW (avoid assigning to "_")
    nonce2, combined2 = cast(Tuple[bytes, bytes], cipher.encrypt(key, b"b"))  # NEW
    assert nonce1[:4] == nonce2[:4] == b"\x00\x00\x00\x01"
    assert int.from_bytes(nonce2[4:], "big") == int.from_bytes(nonce1[4:], "big") + 1
    assert called["n"] == 1


def test_nonce_uniqueness_parallel() -> None:
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher()

    def one(i: int) -> bytes:  # rename parameter to avoid "_" reuse
        nonce, combined = cast(Tuple[bytes, bytes], cipher.encrypt(key, b"x"))  # NEW
        return nonce

    N = 1000
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        nonces = list(ex.map(one, range(N)))
    assert len(set(nonces)) == N
    assert all(len(n) == NONCE_LEN for n in nonces)


def test_decrypt_invalid_params_raise() -> None:
    cipher = SymmetricCipher()
    key = os.urandom(KEY_LEN)
    nonce, combined = encrypt_aes_gcm(key, b"p")
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, b"\x00", combined)  # bad nonce
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, nonce, b"x" * 15, has_combined=True)  # < TAG_LEN
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, nonce, b"ct", has_combined=False)  # no tag provided
    with pytest.raises(DecryptionError):
        cipher.decrypt(
            key, nonce, b"ct", has_combined=False, tag=b"short"
        )  # bad tag size


def test_invalid_tag_raises() -> None:
    key = os.urandom(KEY_LEN)
    nonce, combined = encrypt_aes_gcm(key, b"secret")
    tampered = combined[:-1] + bytes([combined[-1] ^ 0xFF])
    with pytest.raises(DecryptionError):
        decrypt_aes_gcm(key, nonce, tampered)


def test_encrypt_internal_failure_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher()

    class Boom(Exception):
        pass

    # Патчим конструктор Cipher, чтобы он падал
    monkeypatch.setattr(
        "security.crypto.symmetric.Cipher",
        lambda *a, **k: (_ for _ in ()).throw(Boom()),
    )
    with pytest.raises(EncryptionError):
        cipher.encrypt(key, b"data")
