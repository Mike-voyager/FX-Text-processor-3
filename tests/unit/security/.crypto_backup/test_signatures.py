import concurrent.futures
import hashlib
import os
from pathlib import Path
from typing import Any, Callable, Dict, Union

import pytest

from src.security.crypto.exceptions import (
    SignatureError,
    SignatureGenerationError,
    SignatureVerificationError,
)
from src.security.crypto.signatures import (  # импортируй протокол из production!
    Ed25519Signer,
    SignatureError,
    SignatureGenerationError,
    SignatureVerificationError,
    _KeystoreProto,
)

# ---------------------------
# Basic API Coverage
# ---------------------------


def test_generate_and_sign_verify() -> None:
    signer: Ed25519Signer = Ed25519Signer.generate()
    message: bytes = b"message"
    sig: bytes = signer.sign(message)
    assert signer.verify(message, sig) is True
    assert signer.verify(b"wrong", sig) is False
    with pytest.raises(SignatureVerificationError):
        signer.verify(message, b"\x00" * 32)
    with pytest.raises(SignatureVerificationError):
        signer.verify(message, b"\x00" * 128)


def test_from_private_and_public_bytes() -> None:
    signer_priv: Ed25519Signer = Ed25519Signer.generate()
    pub_raw = signer_priv.public_key("raw")
    assert isinstance(pub_raw, (bytes, bytearray)) and len(pub_raw) == 32
    signer_pub: Ed25519Signer = Ed25519Signer.from_public_bytes(bytes(pub_raw))
    msg = b"hello"
    sig = signer_priv.sign(msg)
    assert signer_pub.verify(msg, sig) is True


def test_public_key_formats_raw() -> None:
    signer = Ed25519Signer.generate()
    raw = signer.public_key("raw")
    assert isinstance(raw, (bytes, bytearray)) and len(raw) == 32


def test_public_key_formats_hex() -> None:
    signer = Ed25519Signer.generate()
    val = signer.public_key("hex")
    assert isinstance(val, str) and len(val) >= 64


def test_public_key_formats_pem() -> None:
    signer = Ed25519Signer.generate()
    val = signer.public_key("pem")
    assert isinstance(val, str) and len(val) >= 64


def test_public_key_bad_format() -> None:
    signer = Ed25519Signer.generate()
    with pytest.raises(ValueError):
        signer.public_key("bad")  # type: ignore


def test_fingerprint_sha256() -> None:
    signer = Ed25519Signer.generate()
    pk_raw = signer.public_key("raw")
    fp = signer.get_fingerprint()
    assert isinstance(fp, str) and len(fp) == 64
    raw_bytes = pk_raw.encode() if isinstance(pk_raw, str) else pk_raw
    assert fp == hashlib.sha256(raw_bytes).hexdigest()


def test_context_domain_separation() -> None:
    signer = Ed25519Signer.generate()
    msg = b"test"
    sig_a = signer.sign(msg, context=b"A")
    sig_b = signer.sign(msg, context=b"B")
    assert sig_a != sig_b
    assert signer.verify(msg, sig_a, context=b"A") is True
    assert signer.verify(msg, sig_a, context=b"B") is False


def test_init_with_invalid_seed() -> None:
    with pytest.raises(SignatureError):
        Ed25519Signer(b"shortseed")
    with pytest.raises(SignatureError):
        Ed25519Signer(os.urandom(64))
    with pytest.raises(SignatureError):
        Ed25519Signer.from_private_bytes(b"\x00")


def test_public_key_with_missing_priv_or_pub() -> None:
    s = Ed25519Signer()
    with pytest.raises(SignatureError):
        s.public_key("raw")


def test_sign_without_private_key() -> None:
    s = Ed25519Signer()
    with pytest.raises(SignatureGenerationError):
        s.sign(b"msg")


def test_verify_without_public_key() -> None:
    s = Ed25519Signer()
    with pytest.raises(SignatureVerificationError):
        s.verify(b"x", b"\x00" * 64)


def test_parallel_sign_and_verify() -> None:
    signer = Ed25519Signer.generate()
    data = [os.urandom(80) for _ in range(100)]

    def worker(m: bytes) -> bool:
        sig = signer.sign(m)
        return signer.verify(m, sig)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(worker, data))
    assert all(results)


def test_zeroization_on_bytearray_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: Dict[str, int] = {"zero": 0}
    from src.security.crypto.utils import zero_memory

    real_zero = zero_memory

    def fake_zero(buf: bytearray) -> None:
        calls["zero"] += 1
        real_zero(buf)

    monkeypatch.setattr("src.security.crypto.signatures.zero_memory", fake_zero)
    seed = bytearray(os.urandom(32))
    _ = Ed25519Signer(seed)
    assert calls["zero"] == 1


# ---------------------------
# Keystore encrypted seed I/O
# ---------------------------


def test_saveseedencrypted_and_loadseedencrypted(tmp_path: Path) -> None:
    keystore_path = str(tmp_path / "keystore-test.bin")
    salt_path = str(tmp_path / "salt.bin")
    password = "testpass"
    seed = os.urandom(32)

    class FakeKeystore(_KeystoreProto):
        def __init__(self) -> None:
            self.store: Dict[str, bytes] = {}

        def save(self, name: str, data: bytes) -> None:
            self.store[name] = bytes(data)

        def load(self, name: str) -> bytes:
            return self.store[name]

        def delete(self, name: str) -> None:
            if name in self.store:
                del self.store[name]

    shared_keystore = FakeKeystore()

    class FakeCryptoServiceProto:
        def create_encrypted_keystore(
            self,
            filepath: str,
            *,
            password_provider: Callable[[], Union[str, bytes, bytearray]],
            salt_path: str,
            key_len: int = 32,
        ) -> _KeystoreProto:
            pw = password_provider()
            pw_bytes = pw.encode() if isinstance(pw, str) else pw
            assert pw_bytes == password.encode()
            return shared_keystore  # <-- используем один и тот же объект!

    def pass_provider() -> str:
        return password

    factory: Callable[[], FakeCryptoServiceProto] = lambda: FakeCryptoServiceProto()

    Ed25519Signer.save_seed_encrypted(
        keystore_path,
        salt_path,
        pass_provider,
        seed,
        crypto_service_factory=factory,
        item_name="ed25519seed",
    )
    loaded = Ed25519Signer.load_seed_encrypted(
        keystore_path,
        salt_path,
        pass_provider,
        crypto_service_factory=factory,
        item_name="ed25519seed",
    )
    assert isinstance(loaded, (bytes, bytearray)) and loaded == seed


# ---------------------------
# Edge Cases / Defensive
# ---------------------------


def test_signature_verification_edge() -> None:
    s = Ed25519Signer.generate()
    msg = b"test"
    sig = s.sign(msg)
    forged = bytearray(sig)
    forged[0] ^= 0xFF
    assert s.verify(msg, bytes(forged)) is False
    with pytest.raises(SignatureVerificationError):
        s.verify(msg, b"\x01" * 8)
    empty_s = Ed25519Signer()
    with pytest.raises(SignatureVerificationError):
        empty_s.verify(msg, sig)


def test_invalid_signature_length_raises_error() -> None:
    signer = Ed25519Signer.generate()
    sig = signer.sign(b"msg")
    # Более 64 байт
    with pytest.raises(SignatureVerificationError):
        signer.verify(b"msg", sig + b"x" * 10)
    # Меньше 64 байт
    with pytest.raises(SignatureVerificationError):
        signer.verify(b"msg", sig[:10])


def test_public_key_invalid_format_raises() -> None:
    signer = Ed25519Signer.generate()
    with pytest.raises(ValueError):
        signer.public_key("invalid")  # type: ignore


def test_init_with_wrong_length_seed_raises() -> None:
    with pytest.raises(SignatureError):
        Ed25519Signer(b"short" * 3)  # 15 bytes, not 32


def test_from_public_bytes_with_invalid_input() -> None:
    with pytest.raises(SignatureError):
        Ed25519Signer.from_public_bytes(b"x" * 16)
    # not bytes
    with pytest.raises(SignatureError):
        Ed25519Signer.from_public_bytes("notbytes")  # type: ignore


def test_private_zeroization_called(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: Dict[str, int] = {}

    def fake_zero(buf: bytearray) -> None:
        calls["zero"] = 1

    monkeypatch.setattr("src.security.crypto.signatures.zero_memory", fake_zero)
    Ed25519Signer(bytearray(os.urandom(32)))
    assert calls.get("zero") == 1


def test_save_seed_encrypted_argument_errors() -> None:
    # Некорректная фабрика или не-байтовый seed
    with pytest.raises(Exception):
        Ed25519Signer.save_seed_encrypted(
            "path",
            "salt",
            lambda: "pw",
            b"x" * 30,  # неправильная длина
            crypto_service_factory=lambda: None,  # type: ignore
        )


def test_load_seed_encrypted_missing_key() -> None:
    class DummyKs(_KeystoreProto):
        def save(self, n: str, d: bytes) -> None:
            pass

        def load(self, n: str) -> bytes:
            raise KeyError("missing")

        def delete(self, n: str) -> None:
            pass

    class DummyService:
        def create_encrypted_keystore(
            self,
            filepath: str,
            *,
            password_provider: Callable[[], Union[str, bytes, bytearray]],
            salt_path: str,
            key_len: int = 32,
        ) -> _KeystoreProto:
            return DummyKs()

    with pytest.raises(KeyError):
        Ed25519Signer.load_seed_encrypted(
            "a", "b", lambda: "pw", crypto_service_factory=lambda: DummyService()
        )


def test_verify_with_invalid_pub(monkeypatch: pytest.MonkeyPatch) -> None:
    # покроет ветку except в verify, где pub invalid
    signer = Ed25519Signer.generate()
    signer._pub = None
    signer._priv = None  # форсируем отсутствие ключа
    with pytest.raises(SignatureVerificationError):
        signer.verify(b"x", b"y" * 64)


def test_sign_fails_on_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = Ed25519Signer.generate()
    monkeypatch.setattr(
        "src.security.crypto.signatures._prehash_with_context", lambda *_: 123
    )  # не bytes
    with pytest.raises(SignatureGenerationError):
        signer.sign(b"x")


def test_public_key_pem_encoding_error(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = Ed25519Signer.generate()

    # ломаем сериализацию через raw
    class BadPubView:
        raw: bytes = b"x" * 32

    signer._pub = BadPubView()  # type: ignore
    # monkeypatch "from_public_bytes" чтобы подложить ошибку во время pem сериализации
    monkeypatch.setattr(
        "src.security.crypto.signatures.Ed25519PublicKey.from_public_bytes",
        lambda *_: (_ for _ in ()).throw(ValueError("pem dead")),
    )
    with pytest.raises(Exception):
        signer.public_key("pem")  # type: ignore


def test_ctor_zeroization_finally(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, bool] = {}

    def fail_zero_memory(x: Any) -> None:
        calls["call"] = True
        raise Exception("fail")

    monkeypatch.setattr("src.security.crypto.signatures.zero_memory", fail_zero_memory)
    with pytest.raises(SignatureError):
        Ed25519Signer(bytearray(b"x" * 31))
    assert calls.get("call") is True


def test_invalid_pubkey_length_from_public_bytes() -> None:
    # untyped, but will fail coverage branch
    with pytest.raises(SignatureError):
        Ed25519Signer.from_public_bytes(b"x")
    with pytest.raises(SignatureError):
        Ed25519Signer.from_public_bytes(b"x" * 40)
