# tests/unit/crypto/test_signatures.py
from typing import Tuple, List, Any
import pytest
import builtins
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.crypto.signatures import Ed25519Signer, Ed25519Verifier, SignatureError, logger


def gen_keypair() -> Tuple[bytes, bytes]:
    """Generate random Ed25519 keypair for tests."""
    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes_raw()
    pk_bytes = sk.public_key().public_bytes_raw()
    return sk_bytes, pk_bytes


@pytest.fixture
def keypair() -> Tuple[bytes, bytes]:
    return gen_keypair()


def test_sign_and_verify(keypair: Tuple[bytes, bytes]) -> None:
    sk, pk = keypair
    signer = Ed25519Signer(sk, alias="userX")
    verifier = Ed25519Verifier(pk, alias="userX")
    msg = b"data"
    sig = signer.sign(msg)
    assert verifier.verify(msg, sig)
    assert not verifier.verify(msg, b"00" * 32)


def test_batch_verification(keypair: Tuple[bytes, bytes]) -> None:
    sk, pk = keypair
    signer = Ed25519Signer(sk)
    verifier = Ed25519Verifier(pk)
    msg = b"dataBatch"
    sig_good = signer.sign(msg)
    sig_bad = signer.sign(b"different")
    results = verifier.verify_batch(msg, [sig_good, b"short", sig_bad])
    assert results == [True, False, False]


def test_public_key_export_formats(keypair: Tuple[bytes, bytes]) -> None:
    sk, _ = keypair
    signer = Ed25519Signer(sk)
    raw = signer.public_key("raw")
    hex_ = signer.public_key("hex")
    assert isinstance(raw, bytes)
    assert isinstance(hex_, str)
    assert raw.hex() == hex_


def test_get_fingerprint_consistency(keypair: Tuple[bytes, bytes]) -> None:
    sk, pk = keypair
    signer = Ed25519Signer(sk)
    verifier = Ed25519Verifier(pk)
    assert signer.get_fingerprint() == verifier.get_fingerprint()


def test_save_and_load_key(tmp_path: Any, keypair: Tuple[bytes, bytes]) -> None:
    sk, pk = keypair
    path_sk = tmp_path / "private.key"
    path_pk = tmp_path / "public.key"
    Ed25519Signer.save_key_bytes(str(path_sk), sk)
    Ed25519Verifier.save_key_bytes(str(path_pk), pk)
    loaded_sk = Ed25519Signer.load_key_bytes(str(path_sk))
    loaded_pk = Ed25519Verifier.load_key_bytes(str(path_pk))
    assert sk == loaded_sk
    assert pk == loaded_pk


def test_invalid_key_lengths() -> None:
    with pytest.raises(SignatureError):
        Ed25519Signer(b"short")
    with pytest.raises(SignatureError):
        Ed25519Verifier(b"short")


def test_invalid_signature_length(keypair: Tuple[bytes, bytes]) -> None:
    _, pk = keypair
    verifier = Ed25519Verifier(pk)
    msg = b"abc"
    assert not verifier.verify(msg, b"12345")
    assert not verifier.verify(msg, b"x" * 100)
    assert not verifier.verify(msg, b"\x00" * 64)


def test_load_key_bytes_invalid(tmp_path: Any) -> None:
    path = tmp_path / "bad.key"
    with open(path, "wb") as f:
        f.write(b"xx")
    with pytest.raises(SignatureError):
        Ed25519Signer.load_key_bytes(str(path))
    with pytest.raises(SignatureError):
        Ed25519Verifier.load_key_bytes(str(path))


def test_verify_wrong_public_key(keypair: Tuple[bytes, bytes]) -> None:
    sk1, pk1 = keypair
    sk2, pk2 = gen_keypair()
    signer = Ed25519Signer(sk1)
    verifier = Ed25519Verifier(pk2)
    sig = signer.sign(b"zz")
    assert not verifier.verify(b"zz", sig)


def test_alias_affects_logging(monkeypatch: Any, keypair: Tuple[bytes, bytes]) -> None:
    sk, pk = keypair
    logs: List[str] = []

    # Захватываем все .debug() вызовы и собираем args
    def fake_debug(msg: str, *args: Any, **kwargs: Any) -> None:
        logs.append(msg)
        logs.extend(str(a) for a in args)

    monkeypatch.setattr(logger, "debug", fake_debug)
    signer = Ed25519Signer(sk, alias="LogUser")
    verifier = Ed25519Verifier(pk, alias="LogUser")
    signer.public_key()
    signer.get_fingerprint()
    verifier.get_fingerprint()
    assert any("LogUser" in l for l in logs)


def test_exception_path_on_verifier(keypair: Tuple[bytes, bytes]) -> None:
    sk, pk = keypair
    signer = Ed25519Signer(sk)
    verifier = Ed25519Verifier(pk)
    sig = signer.sign(b"exc")
    verifier._pk = None  # type: ignore
    with pytest.raises(SignatureError):
        verifier.verify(b"exc", sig)


def test_public_key_invalid_encoding(keypair: Tuple[bytes, bytes]) -> None:
    sk, _ = keypair
    signer = Ed25519Signer(sk)
    with pytest.raises(ValueError):
        signer.public_key(encoding="pem")  # type: ignore


def test_save_key_bytes_io_error(monkeypatch: Any, keypair: Tuple[bytes, bytes]) -> None:
    sk, _ = keypair

    def raise_ioerror(*args: Any, **kwargs: Any) -> None:
        raise OSError("Fake IO error")

    monkeypatch.setattr(builtins, "open", raise_ioerror)
    with pytest.raises(OSError):
        Ed25519Signer.save_key_bytes("fail.key", sk)


def test_load_key_bytes_io_error(monkeypatch: Any) -> None:

    def raise_ioerror(*args: Any, **kwargs: Any) -> None:
        raise OSError("Fake IO error")

    import builtins

    monkeypatch.setattr(builtins, "open", raise_ioerror)
    with pytest.raises(OSError):
        Ed25519Signer.load_key_bytes("fail.key")


def test_verify_batch_empty(keypair: Tuple[bytes, bytes]) -> None:
    _, pk = keypair
    verifier = Ed25519Verifier(pk)
    # Должен просто вернуть пустой список, не падать
    assert verifier.verify_batch(b"msg", []) == []


def test_signer_sign_internal_failure(keypair: Tuple[bytes, bytes]) -> None:
    sk, _ = keypair
    signer = Ed25519Signer(sk)
    signer._sk = None  # type: ignore
    with pytest.raises(SignatureError):
        signer.sign(b"data")


def test_sign_verify_empty_message(keypair: Tuple[bytes, bytes]) -> None:
    sk, pk = keypair
    signer = Ed25519Signer(sk)
    verifier = Ed25519Verifier(pk)
    sig = signer.sign(b"")
    assert verifier.verify(b"", sig)


def test_signer_with_non_bytes_key() -> None:
    with pytest.raises(Exception):
        Ed25519Signer("not_bytes")  # type: ignore
    with pytest.raises(Exception):
        Ed25519Verifier("not_bytes")  # type: ignore


def test_load_key_bytes_wrong_type() -> None:
    with pytest.raises(TypeError):
        Ed25519Signer.load_key_bytes(None)  # type: ignore


def test_public_key_unknown_encoding(keypair: Tuple[bytes, bytes]) -> None:
    sk, _ = keypair
    signer = Ed25519Signer(sk)
    with pytest.raises(ValueError):
        signer.public_key("pem")  # type: ignore
    # covers the unreachable branch


def test_batch_verify_non_bytes_entry(keypair: Tuple[bytes, bytes]) -> None:
    _, pk = keypair
    verifier = Ed25519Verifier(pk)
    with pytest.raises(TypeError):
        verifier.verify_batch(b"msg", [b"good" * 16, None])  # type: ignore
