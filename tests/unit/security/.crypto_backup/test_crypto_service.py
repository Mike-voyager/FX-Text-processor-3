from __future__ import annotations

import base64
import os
import sys
import types
from pathlib import Path
from typing import Any, Callable, Optional, Tuple, Union, cast

import pytest

import src.security.crypto.crypto_service as cs_mod
from src.security.crypto.crypto_service import (
    CryptoService,
    HashingPolicy,
    KdfPolicy,
    ServiceConfig,
    _load_or_create_salt,
)
from src.security.crypto.exceptions import HashSchemeError, KDFAlgorithmError

# --- Fakes implementing protocol-compliant surfaces ---


class FakeSymmetric:
    def __init__(self) -> None:
        self.enc_calls: list[tuple] = []
        self.dec_calls: list[tuple] = []

    # Match SymmetricCipherProtocol: aad positional-or-keyword, return union
    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> tuple[bytes, bytes] | tuple[bytes, bytes, bytes]:
        self.enc_calls.append((key, bytes(plaintext), aad, return_combined))
        nonce = b"\x00" * 12
        if return_combined:
            # combined → exactly two values
            return (nonce, b"CTAG")
        # split → exactly three values
        return (nonce, b"CIPH", b"TAG")

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
        self.dec_calls.append((key, nonce, data, aad, has_combined, tag))
        return b"PLAINTEXT"


class FakeSignerWithCtx:
    def __init__(self) -> None:
        self.sigs: list[tuple[bytes, Optional[bytes]]] = []
        self.verifs: list[tuple[bytes, bytes, Optional[bytes]]] = []

    # Match SigningProtocol; keep context optional
    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        self.sigs.append((data, context))
        return b"SIGN"

    def verify(
        self, data: bytes, signature: bytes, *, context: Optional[bytes] = None
    ) -> bool:
        self.verifs.append((data, signature, context))
        return signature == b"SIGN"

    def public_key(self, fmt: str = "raw") -> bytes | str:
        return b"PK"

    def get_fingerprint(self) -> str:
        return "fp"


class FakeSignerTypeError:
    """
    Conforms to SigningProtocol but raises TypeError when context is provided
    to exercise CryptoService fallback path.
    """

    def __init__(self) -> None:
        self.sigs: list[tuple[bytes, Optional[bytes]]] = []
        self.verifs: list[tuple[bytes, bytes, Optional[bytes]]] = []

    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        if context is not None:
            raise TypeError("no context")
        self.sigs.append((data, None))
        return b"SIGN-NOCTX"

    def verify(
        self, data: bytes, signature: bytes, *, context: Optional[bytes] = None
    ) -> bool:
        if context is not None:
            raise TypeError("no context")
        self.verifs.append((data, signature, None))
        return signature == b"SIGN-NOCTX"

    def public_key(self, fmt: str = "raw") -> bytes | str:
        return b"PK"

    def get_fingerprint(self) -> str:
        return "fp-noctx"


class FakeHasher:
    """Fake hasher for DI testing."""

    def hash_password(self, password: str) -> str:
        return "hok"

    def verify_password(
        self, password: str, hashed: str, identifier: str | None = None
    ) -> bool:
        return hashed == "hok" and password == "pw"

    def needs_rehash(self, hashed: str) -> bool:
        return False


class FakeKdf:
    def __init__(self) -> None:
        self.last_args: tuple[Union[str, bytes, bytearray], bytes, int, Any] | None = (
            None
        )

    # Match KdfProtocol signature
    def derive_key(
        self,
        password: Union[str, bytes, bytearray],
        salt: bytes,
        length: int,
        *,
        params: Any,  # keep Any in tests; structure is validated by CryptoService
    ) -> bytes:
        self.last_args = (password, salt, length, params)
        return b"K" * length


class DummyBackend:
    def __init__(
        self, path: str, symmetric: Any, key_provider: Callable[[], bytes]
    ) -> None:
        self.path = path
        self.symmetric = symmetric
        self._key_provider = key_provider

    def get_derived_key(self) -> bytes:
        return self._key_provider()


# --- Fixtures ---


@pytest.fixture
def fake_service() -> CryptoService:
    sym = FakeSymmetric()
    signer = FakeSignerWithCtx()
    kdf = FakeKdf()
    hasher = FakeHasher()
    return CryptoService(sym, signer, kdf, hasher, config=ServiceConfig())


# --- Tests: façades delegate correctly ---


def test_hashing_facade_delegates(fake_service: CryptoService) -> None:
    h = fake_service.hash_password("pw")
    assert h == "hok"
    assert fake_service.verify_password("pw", h, identifier=None) is True


def test_sign_verify_with_and_without_context() -> None:
    # With context-capable signer
    svc1 = CryptoService(
        FakeSymmetric(),
        FakeSignerWithCtx(),
        FakeKdf(),
        FakeHasher(),
        config=ServiceConfig(),
    )
    sig1 = svc1.sign(b"data", context=b"ctx")
    assert sig1 == b"SIGN"
    assert svc1.verify(b"data", sig1, context=b"ctx") is True
    # Without context-capable signer (fallback path via TypeError)
    svc2 = CryptoService(
        FakeSymmetric(),
        FakeSignerTypeError(),
        FakeKdf(),
        FakeHasher(),
        config=ServiceConfig(),
    )
    sig2 = svc2.sign(b"data", context=b"ctx")  # context triggers TypeError → fallback
    assert sig2 == b"SIGN-NOCTX"
    assert svc2.verify(b"data", sig2, context=b"ctx") is True


def test_symmetric_facade_encrypt_decrypt(fake_service: CryptoService) -> None:
    # combined → 2 values
    out = fake_service.encrypt(b"K" * 32, b"X", aad=b"A", return_combined=True)
    assert isinstance(out, tuple) and len(out) == 2
    nonce, ct = out
    assert nonce == b"\x00" * 12 and ct == b"CTAG"
    pt = fake_service.decrypt(b"K" * 32, nonce, ct, aad=b"A", has_combined=True)
    assert pt == b"PLAINTEXT"

    # split → 3 values
    out2 = fake_service.encrypt(b"K" * 32, b"X", aad=b"A", return_combined=False)
    assert isinstance(out2, tuple) and len(out2) == 3
    nonce2, ciph2, tag2 = out2
    assert nonce2 == b"\x00" * 12 and ciph2 == b"CIPH" and tag2 == b"TAG"
    pt2 = fake_service.decrypt(
        b"K" * 32, nonce2, ciph2, aad=b"A", has_combined=False, tag=tag2
    )
    assert pt2 == b"PLAINTEXT"


# --- Tests: new_default construction paths ---


def test_new_default_ed25519_uses_configured_signer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Monkeypatch Ed25519Signer.generate to return a sentinel (used as-is by CryptoService)
    sentinel = object()

    class FakeEd:
        @staticmethod
        def generate() -> object:
            return sentinel

    monkeypatch.setattr(cs_mod, "Ed25519Signer", FakeEd)
    svc = CryptoService.new_default()
    assert svc.signer is sentinel


def test_new_default_rsa_and_ecdsa_selects_asymmetric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Provide a minimal AsymmetricKeyPair with required methods
    class FakeAKP:
        @staticmethod
        def generate(algo: str, key_size: int | None = None) -> object:
            class _Obj:
                def sign(self, data: bytes) -> bytes:
                    return b"S"

                def verify(self, data: bytes, signature: bytes) -> bool:
                    return signature == b"S"

                def public_key(self, fmt: str = "raw") -> bytes | str:
                    return b"PK"

                def get_fingerprint(self) -> str:
                    return "fp"

            return _Obj()

    fake_asym = types.SimpleNamespace(AsymmetricKeyPair=FakeAKP)
    monkeypatch.setitem(sys.modules, "src.security.crypto.asymmetric", fake_asym)

    cfg_rsa = ServiceConfig(
        signing_algorithm="rsa4096", hashing=HashingPolicy(scheme="pbkdf2")
    )
    svc_rsa = CryptoService.new_default(cfg_rsa)
    # AsymmetricSignerAdapter is used — verify basic capabilities
    assert hasattr(svc_rsa.signer, "sign") and hasattr(svc_rsa.signer, "verify")

    cfg_ecdsa = ServiceConfig(
        signing_algorithm="ecdsa_p256", hashing=HashingPolicy(scheme="pbkdf2")
    )
    svc_ecdsa = CryptoService.new_default(cfg_ecdsa)
    assert svc_ecdsa.signer.verify(b"d", svc_ecdsa.signer.sign(b"d")) is True  # type: ignore[attr-defined]


def test_new_default_hashing_argon2_strict_missing_module_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Ensure importing "argon2" raises ImportError
    def fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "argon2":
            raise ImportError("no module")
        return __import__(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", fake_import)
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="argon2id"))
    with pytest.raises(HashSchemeError):
        _ = CryptoService.new_default(cfg)


def test_new_default_hashing_pbkdf2_path_ok() -> None:
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="pbkdf2"))
    svc = CryptoService.new_default(cfg)
    assert hasattr(svc, "hasher")


def test_select_kdf_params_strict_argon2_missing_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="pbkdf2"))
    svc = CryptoService.new_default(cfg)

    # Force ImportError on "argon2" during KDF selection
    def fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "argon2":
            raise ImportError("no module")
        return __import__(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", fake_import)
    with pytest.raises(KDFAlgorithmError):
        _ = svc._select_kdf_params_strict()  # type: ignore[attr-defined]


def test_select_kdf_params_strict_argon2_present_returns_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="pbkdf2"))
    svc = CryptoService.new_default(cfg)
    # Simulate argon2 presence
    monkeypatch.setitem(sys.modules, "argon2", types.SimpleNamespace())
    params = svc._select_kdf_params_strict()  # type: ignore[attr-defined]
    # TypedDict keys (not attributes)
    assert all(
        k in params
        for k in ("version", "time_cost", "memory_cost", "parallelism", "salt_len")
    )


# --- Tests: encrypted keystore factory and salt handling ---


def test_create_encrypted_keystore_creates_and_uses_salt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Prepare fake modules and functions
    sym = FakeSymmetric()
    signer = FakeSignerWithCtx()
    kdf = FakeKdf()
    hasher = FakeHasher()
    cfg = ServiceConfig()
    svc = CryptoService(sym, signer, kdf, hasher, config=cfg)

    salt_file = tmp_path / "salt.bin"

    # Intercept backend construction
    constructed: dict[str, Any] = {}

    def fake_backend(
        path: str, symmetric: Any, key_provider: Callable[[], bytes]
    ) -> Any:
        constructed["path"] = path
        constructed["symmetric"] = symmetric
        constructed["key"] = key_provider()
        return DummyBackend(path, symmetric, key_provider)

    monkeypatch.setattr(cs_mod, "FileEncryptedStorageBackend", fake_backend)
    # Avoid platform-specific permission ops
    monkeypatch.setattr(cs_mod, "set_secure_file_permissions", lambda p: None)

    # Provide password and optional pepper
    cfg.pepper_provider = lambda: b"pep"

    backend = svc.create_encrypted_keystore(
        filepath=str(tmp_path / "store.json"),
        password_provider=lambda: "pass",
        salt_path=str(salt_file),
        key_len=32,
    )
    # File created and key derived via KDF
    assert salt_file.exists()
    assert isinstance(backend, DummyBackend)
    assert constructed["path"].endswith("store.json")
    # Key length respected
    assert constructed["key"] == b"K" * 32
    # KDF was called with peppered password (HMAC-SHA256 over original)
    assert kdf.last_args is not None
    pw_used = kdf.last_args[0]
    # digest is 32 bytes for HMAC-SHA256
    assert isinstance(pw_used, (bytes, bytearray)) and len(pw_used) == 32


def test_load_or_create_salt_reads_base64_and_raw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "salt2.bin"
    raw = b"\x01" * 16
    with open(path, "wb") as f:
        f.write(base64.b64encode(raw))
    monkeypatch.setattr(cs_mod, "set_secure_file_permissions", lambda p: None)
    out1 = cs_mod._load_or_create_salt(str(path), 16)
    assert out1 == raw

    with open(path, "wb") as f:
        f.write(raw)
    out2 = cs_mod._load_or_create_salt(str(path), 16)
    assert out2 == raw


def test_load_or_create_salt_invalid_format_creates_new(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Invalid salt format triggers new salt generation with integrity."""
    path = tmp_path / "bad_salt.bin"
    with open(path, "wb") as f:
        f.write(b"\x02\x03")  # Invalid format (не base64, не нужной длины)

    with caplog.at_level("INFO"):
        salt = _load_or_create_salt(str(path), 16)

    assert len(salt) == 16
    assert "Generating new salt" in caplog.text

    integrity_path = Path(str(path) + ".integrity")
    assert integrity_path.exists()


def test_unsupported_signing_algorithm_raises() -> None:
    cfg = ServiceConfig(
        signing_algorithm="unknown", hashing=HashingPolicy(scheme="pbkdf2")
    )
    with pytest.raises(ValueError):
        _ = CryptoService.new_default(cfg)


def test_asymmetric_adapter_ignores_context(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeAKP:
        @staticmethod
        def generate(algo: str, key_size: int | None = None) -> object:
            class _Obj:
                def __init__(self) -> None:
                    self.last_signed: bytes | None = None

                def sign(self, data: bytes) -> bytes:
                    self.last_signed = data
                    return b"S"

                def verify(self, data: bytes, signature: bytes) -> bool:
                    return signature == b"S" and self.last_signed == data

                def public_key(self, fmt: str = "raw") -> bytes:
                    return b"PK"

                def get_fingerprint(self) -> str:
                    return "fp"

            return _Obj()

    fake_asym = types.SimpleNamespace(AsymmetricKeyPair=FakeAKP)
    monkeypatch.setitem(sys.modules, "src.security.crypto.asymmetric", fake_asym)

    cfg = ServiceConfig(
        signing_algorithm="rsa4096", hashing=HashingPolicy(scheme="pbkdf2")
    )
    svc = CryptoService.new_default(cfg)
    sig = svc.sign(b"data", context=b"ctx")  # контекст будет проигнорирован адаптером
    assert svc.verify(b"data", sig, context=b"ctx") is True


class FailingSymmetric(FakeSymmetric):
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
        if not has_combined and tag != b"TAG":
            raise ValueError("auth tag mismatch")
        return super().decrypt(
            key, nonce, data, aad=aad, has_combined=has_combined, tag=tag
        )


def test_symmetric_split_invalid_tag_raises() -> None:
    svc = CryptoService(
        FailingSymmetric(),
        FakeSignerWithCtx(),
        FakeKdf(),
        FakeHasher(),
        config=ServiceConfig(),
    )
    # получаем split-вывод
    nonce, ciph, tag = svc.encrypt(b"K" * 32, b"X", aad=b"A", return_combined=False)  # type: ignore[misc]
    # портим тег
    with pytest.raises(ValueError):
        _ = svc.decrypt(
            b"K" * 32, nonce, ciph, aad=b"A", has_combined=False, tag=b"BAD"
        )


def test_kdf_params_structure_literals(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="pbkdf2"))
    svc = CryptoService.new_default(cfg)
    # Эмулируем наличие argon2
    monkeypatch.setitem(sys.modules, "argon2", types.SimpleNamespace())
    # Argon2id
    cfg.kdf.use_argon2id = True
    p1 = svc._select_kdf_params_strict()  # type: ignore[attr-defined]
    assert (
        p1["version"] == "argon2id"
        and isinstance(p1["time_cost"], int)
        and isinstance(p1["memory_cost"], int)
    )
    # PBKDF2
    cfg.kdf.use_argon2id = False
    p2 = svc._select_kdf_params_strict()  # type: ignore[attr-defined]
    assert (
        p2["version"] == "pbkdf2"
        and p2["hash_name"] == "sha256"
        and isinstance(p2["iterations"], int)
    )


def test_keystore_same_salt_and_password_produce_same_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sym = FakeSymmetric()
    signer = FakeSignerWithCtx()
    kdf = FakeKdf()
    hasher = FakeHasher()
    cfg = ServiceConfig()
    svc = CryptoService(sym, signer, kdf, hasher, config=cfg)

    salt_file = tmp_path / "salt.bin"
    # Фиксируем соль
    with open(salt_file, "wb") as f:
        f.write(base64.b64encode(b"\x11" * cfg.kdf.salt_len))

    # Перехватываем backend
    keys: list[bytes] = []

    def fake_backend(
        path: str, symmetric: Any, key_provider: Callable[[], bytes]
    ) -> Any:
        k = key_provider()
        keys.append(k)
        return DummyBackend(path, symmetric, key_provider)

    monkeypatch.setattr(cs_mod, "FileEncryptedStorageBackend", fake_backend)
    monkeypatch.setattr(cs_mod, "set_secure_file_permissions", lambda p: None)
    cfg.pepper_provider = lambda: b"pep"

    svc.create_encrypted_keystore(
        filepath=str(tmp_path / "store.json"),
        password_provider=lambda: "pass",
        salt_path=str(salt_file),
        key_len=32,
    )
    svc.create_encrypted_keystore(
        filepath=str(tmp_path / "store2.json"),
        password_provider=lambda: "pass",
        salt_path=str(salt_file),
        key_len=32,
    )

    assert len(keys) == 2 and keys[0] == keys[1]


def test_new_default_hashing_unknown_scheme_raises() -> None:
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="unknown"))
    with pytest.raises(HashSchemeError):
        _ = CryptoService.new_default(cfg)


def test_ed25519_sign_verify_context_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeEd:
        @staticmethod
        def generate() -> Any:
            class _S:
                def sign(self, data: bytes, *, context: bytes | None = None) -> bytes:
                    return b"E"

                def verify(
                    self, data: bytes, signature: bytes, *, context: bytes | None = None
                ) -> bool:
                    return signature == b"E"

                def public_key(self, fmt: str = "raw") -> bytes:
                    return b"PK"

                def get_fingerprint(self) -> str:
                    return "fp"

            return _S()

    monkeypatch.setattr(cs_mod, "Ed25519Signer", FakeEd)
    svc = CryptoService.new_default()
    assert svc.verify(b"d", svc.sign(b"d", context=None), context=None) is True
    assert (
        svc.verify(b"d", svc.sign(b"d", context=b"\x00\x01"), context=b"\x00\x01")
        is True
    )


def test_load_or_create_salt_wrong_length_generates_new(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that wrong-length salt triggers regeneration."""
    p = tmp_path / "test.salt"
    p_int = tmp_path / "test.salt.integrity"

    # Create salt with wrong length (15 instead of 16)
    wrong_salt = b"A" * 15
    tag = cs_mod._compute_salt_integrity(wrong_salt)
    p.write_bytes(base64.b64encode(wrong_salt))
    p_int.write_bytes(tag)

    # Load should regenerate due to wrong length
    result = cs_mod._load_or_create_salt(str(p), 16)

    # Verify new salt has correct length
    assert len(result) == 16
    assert result != wrong_salt

    # Verify file was updated (salt changed)
    new_encoded = p.read_bytes()
    assert new_encoded != base64.b64encode(wrong_salt)


def test_keystore_calls_set_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sym, signer, kdf, hasher = (
        FakeSymmetric(),
        FakeSignerWithCtx(),
        FakeKdf(),
        FakeHasher(),
    )
    cfg = ServiceConfig()
    svc = CryptoService(sym, signer, kdf, hasher, config=cfg)

    called: dict[str, int] = {"count": 0, "last": 0}

    def sp(path: str) -> None:
        called["count"] += 1
        called["last"] = len(path)

    monkeypatch.setattr(cs_mod, "set_secure_file_permissions", sp)
    monkeypatch.setattr(
        cs_mod,
        "FileEncryptedStorageBackend",
        lambda p, s, kp: DummyBackend(p, s, kp),
    )

    svc.create_encrypted_keystore(
        filepath=str(tmp_path / "store.json"),
        password_provider=lambda: "pass",
        salt_path=str(tmp_path / "salt.bin"),
        key_len=32,
    )
    assert called["count"] >= 2


def test_hashing_pbkdf2_does_not_import_argon2(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = __import__  # сохранить оригинал

    def fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "argon2":
            raise ImportError("should not import")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", fake_import)
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="pbkdf2"))
    svc = CryptoService.new_default(cfg)
    assert hasattr(svc, "hasher")


def test_ed25519_public_key_and_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeEd:
        @staticmethod
        def generate() -> Any:
            class _S:
                def sign(self, data: bytes, *, context: bytes | None = None) -> bytes:
                    return b"E"

                def verify(
                    self, data: bytes, signature: bytes, *, context: bytes | None = None
                ) -> bool:
                    return signature == b"E"

                def public_key(self, fmt: str = "raw") -> bytes:
                    return b"PK"

                def get_fingerprint(self) -> str:
                    return "fp"

            return _S()

    monkeypatch.setattr(cs_mod, "Ed25519Signer", FakeEd)
    svc = CryptoService.new_default()
    assert (
        svc.signer.public_key() == b"PK"  # type: ignore[attr-defined]
        and svc.signer.get_fingerprint() == "fp"  # type: ignore[attr-defined]
    )


def test_keystore_argon2_required_for_kdf(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = ServiceConfig(hashing=HashingPolicy(scheme="pbkdf2"))
    svc = CryptoService.new_default(cfg)

    real_import = __import__

    def fake_import(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "argon2":
            raise ImportError("no module")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", fake_import)
    monkeypatch.setattr(
        cs_mod, "FileEncryptedStorageBackend", lambda p, s, kp: DummyBackend(p, s, kp)
    )
    monkeypatch.setattr(cs_mod, "set_secure_file_permissions", lambda p: None)

    with pytest.raises(KDFAlgorithmError):
        _ = svc.create_encrypted_keystore(
            filepath=str(tmp_path / "store.json"),
            password_provider=lambda: "pass",
            salt_path=str(tmp_path / "salt.bin"),
            key_len=32,
        )
