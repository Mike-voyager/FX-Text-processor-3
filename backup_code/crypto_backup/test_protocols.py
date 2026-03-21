from __future__ import annotations

from typing import Callable, Literal, Optional, Tuple, Union

import pytest

from src.security.crypto.protocols import (
    Argon2idParams,
    BytesLike,
    CryptoServiceProtocol,
    HashingProtocol,
    KdfParams,
    KdfProtocol,
    KeyStoreProtocol,
    PBKDF2Params,
    SigningProtocol,
    SymmetricCipherProtocol,
)

# --- Basic presence and nominal typing ---


def test_byteslike_union_contains_bytes_and_bytearray() -> None:
    b: BytesLike = b"ok"
    ba: BytesLike = bytearray(b"ok")
    assert isinstance(b, (bytes, bytearray))
    assert isinstance(ba, (bytes, bytearray))


def test_kdf_params_typed_dicts_shape() -> None:
    a: Argon2idParams = {
        "version": "argon2id",
        "time_cost": 2,
        "memory_cost": 1024,
        "parallelism": 1,
        "salt_len": 16,
    }
    p: PBKDF2Params = {
        "version": "pbkdf2",
        "iterations": 100_000,
        "hash_name": "sha256",
        "salt_len": 16,
    }

    def accepts(params: KdfParams) -> Literal[True]:
        assert params["salt_len"] > 0
        return True

    assert accepts(a)
    assert accepts(p)


# --- SymmetricCipherProtocol conformance ---


class _GoodCipher:
    def encrypt(
        self,
        key: bytes,
        plaintext: BytesLike,
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
        nonce = b"N" * 12
        ct = bytes(plaintext)[::-1]
        if return_combined:
            return nonce, ct  # combined
        return nonce, ct, b"T" * 16  # split: (ct, tag)

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
        if has_combined:
            return data[::-1]
        assert tag is not None
        # демонстрационная логика: реверс (ct + tag)
        return (data + tag)[::-1]


class _BadCipherMissingKwOnly:
    # добавлены лишние обязательные positional параметры extra/more → несовместимо
    def encrypt(self, key: bytes, data: bytes, extra: int) -> Tuple[bytes, bytes]:
        return b"N" * 12, data

    def decrypt(self, key: bytes, nonce: bytes, data: bytes, more: int) -> bytes:
        return data


def test_symmetric_cipher_runtime_check() -> None:
    good = _GoodCipher()
    assert isinstance(good, SymmetricCipherProtocol)

    # combined path
    enc = good.encrypt(b"K" * 32, b"abc", None, return_combined=True)
    assert len(enc) == 2
    nonce = enc[0]
    combined = enc[1]
    pt = good.decrypt(b"K" * 32, nonce, combined, None, has_combined=True)
    assert pt == b"abc"

    # split path
    enc2 = good.encrypt(b"K" * 32, b"xyz", None, return_combined=False)
    assert len(enc2) == 3
    nonce2, ct2, tag2 = enc2
    pt2 = good.decrypt(b"K" * 32, nonce2, ct2, None, has_combined=False, tag=tag2)
    assert pt2 == (ct2 + tag2)[::-1]


def test_symmetric_cipher_rejects_incompatible_shape() -> None:
    bad = _BadCipherMissingKwOnly()
    # encrypt по протоколу — должен упасть из-за unexpected kw-only/арности
    with pytest.raises(TypeError):
        _ = bad.encrypt(b"K" * 32, b"abc", None, return_combined=True)  # type: ignore
    # decrypt по протоколу — тоже должен упасть
    with pytest.raises(TypeError):
        _ = bad.decrypt(b"K" * 32, b"N" * 12, b"ct", None, has_combined=False, tag=b"T" * 16)  # type: ignore


# --- SigningProtocol conformance ---


class _GoodSigner:
    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        return (context or b"") + data[::-1]

    def verify(
        self, data: bytes, signature: bytes, *, context: Optional[bytes] = None
    ) -> bool:
        return signature == (context or b"") + data[::-1]

    def public_key(
        self, fmt: Literal["raw", "hex", "pem"] = "raw"
    ) -> Union[bytes, str]:
        if fmt == "raw":
            return b"P" * 32
        if fmt == "hex":
            return "50" * 32
        if fmt == "pem":
            return "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
        raise ValueError("fmt")

    def get_fingerprint(self) -> str:
        return "f" * 64


class _BadSigner:
    # нет kw-only параметра context
    def sign(self, data: bytes) -> bytes:
        return data

    def verify(self, data: bytes, signature: bytes) -> bool:
        return True


def test_signing_protocol_runtime_check() -> None:
    s = _GoodSigner()
    assert isinstance(s, SigningProtocol)
    sig = s.sign(b"hello", context=b"X")
    assert s.verify(b"hello", sig, context=b"X") is True
    assert isinstance(s.public_key("hex"), str)
    assert len(s.get_fingerprint()) == 64


def test_signing_protocol_rejects_incompatible_shape() -> None:
    bad = _BadSigner()
    assert not isinstance(bad, SigningProtocol)


# --- KdfProtocol conformance ---


class _GoodKdf:
    def derive_key(
        self,
        password: Union[str, bytes, bytearray],
        salt: bytes,
        length: int,
        *,
        params: KdfParams,
    ) -> bytes:
        base = password.encode() if isinstance(password, str) else bytes(password)
        return (base + salt)[:length].ljust(length, b"\x00")


# Несовместимый: отсутствует параметр params вовсе (арность меньше)
class _BadKdf:
    # лишний обязательный аргумент extra ломает совместимость
    def derive_key(
        self,
        password: Union[str, bytes, bytearray],
        salt: bytes,
        length: int,
        extra: int,
    ) -> bytes:
        return b"\x00" * length


def test_kdf_protocol_runtime_check() -> None:
    kdf = _GoodKdf()
    assert isinstance(kdf, KdfProtocol)
    key = kdf.derive_key(
        "pw",
        b"SALT",
        16,
        params={
            "version": "pbkdf2",
            "iterations": 1,
            "hash_name": "sha256",
            "salt_len": 16,
        },
    )
    assert isinstance(key, (bytes, bytearray)) and len(key) == 16


def test_kdf_protocol_rejects_incompatible_shape() -> None:
    bad = _BadKdf()
    with pytest.raises(TypeError):
        _ = bad.derive_key(
            "pw",
            b"SALT",
            16,
            params={"version": "pbkdf2", "iterations": 1, "hash_name": "sha256", "salt_len": 16},  # type: ignore
        )  # type: ignore


# --- KeyStoreProtocol and CryptoServiceProtocol conformance ---


class _GoodKeystore:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def save(self, name: str, data: bytes) -> None:
        assert isinstance(name, str) and isinstance(data, (bytes, bytearray))
        self.store[name] = bytes(data)

    def load(self, name: str) -> bytes:
        return self.store[name]

    def delete(self, name: str) -> None:
        self.store.pop(name, None)


class _BadKeystore:
    # неверный тип второго аргумента
    def save(self, name: str, data: str) -> None:
        pass


class _GoodCryptoService:
    def __init__(self) -> None:
        self.instances: list[_GoodKeystore] = []

    def create_encrypted_keystore(
        self,
        filepath: str,
        *,
        password_provider: Callable[[], Union[str, bytes, bytearray]],
        salt_path: str,
        key_len: int = 32,
    ) -> _GoodKeystore:
        _ = password_provider()
        ks = _GoodKeystore()
        self.instances.append(ks)
        return ks


# Несовместимый: 2 позиционных параметра, нет kw-only, отсутствуют требуемые именованные аргументы
class _BadCryptoService:
    def create_encrypted_keystore(
        self, path: str, password: str, extra: int
    ) -> _GoodKeystore:
        return _GoodKeystore()


def test_keystore_and_crypto_service_runtime_check() -> None:
    ks = _GoodKeystore()
    cs = _GoodCryptoService()
    assert isinstance(ks, KeyStoreProtocol)
    assert isinstance(cs, CryptoServiceProtocol)
    ks.save("a", b"v")
    assert ks.load("a") == b"v"
    ks.delete("a")
    with pytest.raises(KeyError):
        ks.load("a")


def test_keystore_and_crypto_service_reject_bad_shapes() -> None:
    bad_ks = _BadKeystore()
    assert not isinstance(bad_ks, KeyStoreProtocol)  # оставить можно
    bad_cs = _BadCryptoService()
    with pytest.raises(TypeError):
        _ = bad_cs.create_encrypted_keystore(
            "ks.json",
            password_provider=lambda: b"K" * 32,  # type: ignore
            salt_path="salt.bin",  # type: ignore
            key_len=32,  # type: ignore
        )  # type: ignore


# --- HashingProtocol conformance ---


class _GoodHasher:
    def hash_password(self, password: str) -> str:
        return "hash:" + password

    def verify_password(self, password: str, hashed: str) -> bool:
        return hashed == "hash:" + password

    def needs_rehash(self, hashed: str) -> bool:
        return not hashed.startswith("hash:")


class _BadHasher:
    # неверные типы/сигнатуры
    def hash_password(self, password: bytes) -> str:
        return "x"

    def verify_password(self, password: str) -> bool:
        return True


def test_hashing_protocol_runtime_check() -> None:
    h = _GoodHasher()
    assert isinstance(h, HashingProtocol)
    hashed = h.hash_password("pw")
    assert h.verify_password("pw", hashed) is True
    assert h.needs_rehash(hashed) is False


def test_hashing_protocol_rejects_incompatible_shape() -> None:
    bad = _BadHasher()
    assert not isinstance(bad, HashingProtocol)


# --- __all__ exports ---


def test_all_exports_present() -> None:
    import src.security.crypto.protocols as pr

    names = {
        "BytesLike",
        "Argon2idParams",
        "PBKDF2Params",
        "KdfParams",
        "SymmetricCipherProtocol",
        "SigningProtocol",
        "KdfProtocol",
        "KeyStoreProtocol",
        "CryptoServiceProtocol",
        "HashingProtocol",
    }
    assert names.issubset(set(pr.__all__))
