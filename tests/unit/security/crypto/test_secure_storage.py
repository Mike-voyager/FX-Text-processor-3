"""Unit tests for src/security/crypto/secure_storage.py.

RU: Тесты для защищённого хранилища с поддержкой MFA, ротацией соли, batch-операциями и логированием событий.
EN: Test coverage for SecureStorage (MFA, salt rotation, batch, error handling, audit logging).
"""

import pytest
import pickle
import time
from typing import Any, Dict, List, Optional, cast
from pathlib import Path
from pytest import MonkeyPatch
from types import ModuleType
import sys
import types
from security.crypto.secure_storage import (
    SecureStorage,
    StorageBackend,
    InMemoryEncryptedStorageBackend,
    MFAFactor,
)

from pytest import MonkeyPatch


class DummyBackend(InMemoryEncryptedStorageBackend):
    """Dummy backend for SecureStorage tests."""


@pytest.fixture
def backend() -> InMemoryEncryptedStorageBackend:
    return DummyBackend()


@pytest.fixture
def storage(backend: InMemoryEncryptedStorageBackend) -> SecureStorage:
    return SecureStorage(backend=backend, lock_timeout=2)


def dummy_derive_key(*args: Any, **kwargs: Any) -> bytes:
    # Simulate a constant session key for tests
    return b"X" * 32


def dummy_encrypt_aes_gcm(data: bytes, key: bytes, context: bytes) -> bytes:
    # Simulate encryption—return as is with context header
    return b"ENC:" + context + b":" + data


def dummy_decrypt_aes_gcm(data: bytes, key: bytes, context: bytes) -> bytes:
    # Simulate decryption—parse format
    if not data.startswith(b"ENC:" + context + b":"):
        raise ValueError("Invalid context or data")
    return data[len(b"ENC:" + context + b":") :]


@pytest.fixture(autouse=True)
def monkeypatch_crypto(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("security.crypto.secure_storage.derive_key_argon2id", dummy_derive_key)
    monkeypatch.setattr("security.crypto.secure_storage.encrypt_aes_gcm", dummy_encrypt_aes_gcm)
    monkeypatch.setattr("security.crypto.secure_storage.decrypt_aes_gcm", dummy_decrypt_aes_gcm)


def dummy_mfa_auth(self: SecureStorage, factor: MFAFactor, user_id: str, value: str) -> bytes:
    # Always return fixed key for tests
    return b"Y" * 32


@pytest.fixture(autouse=True)
def monkeypatch_mfa(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(SecureStorage, "_mfa_auth", dummy_mfa_auth)


def test_unlock_lock(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.TOTP, user_id="test", value="123456")
    assert storage.is_unlocked() is True
    storage.lock()
    assert storage.is_unlocked() is False


def test_store_and_retrieve(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.FIDO2, user_id="user", value="valid")
    obj: Dict[str, Any] = {"a": 1, "b": "foo"}
    storage.store("testkey", obj, context="ctx1")
    result = storage.retrieve("testkey", context="ctx1")
    assert result == obj


def test_retrieve_not_found(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.FIDO2, user_id="user", value="valid")
    with pytest.raises(KeyError):
        storage.retrieve("no_such_key", context="ctx1")


def test_delete(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.TOTP, user_id="user", value="123456")
    storage.store("delkey", {"x": "y"}, context="ctx2")
    storage.delete("delkey")
    with pytest.raises(KeyError):
        storage.retrieve("delkey", context="ctx2")


def test_auto_lock(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.TOTP, user_id="user", value="123456")
    time.sleep(3)
    with pytest.raises(PermissionError):
        storage.store("auto", {"a": 5}, context="foo")


def test_batch_store_and_keys(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.FIDO2, user_id="u", value="v")
    items: Dict[str, int] = {f"key{i}": i for i in range(5)}
    storage.batch_store(items, context="batchctx")
    keys = set(storage.keys())
    assert {f"key{i}" for i in range(5)}.issubset(keys)
    for i in range(5):
        assert storage.retrieve(f"key{i}", context="batchctx") == i


def test_batch_rotate_salt(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.TOTP, user_id="test", value="code")
    storage.batch_store({"k1": "A", "k2": "B"}, context="oldctx")
    storage.batch_rotate_salt(["k1", "k2"], old_context="oldctx", new_context="newctx")
    # still accessible via new context
    assert storage.retrieve("k1", context="newctx") == "A"
    assert storage.retrieve("k2", context="newctx") == "B"
    # fails for old context (raises PermissionError)
    with pytest.raises(PermissionError):
        storage.retrieve("k1", context="oldctx")


def test_high_security_op(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.TOTP, user_id="who", value="code")
    storage.store("secure", 42, context="verysec")
    # can retrieve even if locked via high_security_op
    storage.lock()
    result = storage.high_security_op(
        MFAFactor.FIDO2, user_id="who", value="code", key="secure", context="verysec"
    )
    assert result == 42


def test_rotate_salt(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.FIDO2, user_id="user", value="xxx")
    storage.store("rotatekey", {"v": 100}, context="ctx_old")
    storage.rotate_salt("rotatekey", old_context="ctx_old", new_context="ctx_new")
    assert storage.retrieve("rotatekey", context="ctx_new") == {"v": 100}


def test_emergency_recover(storage: SecureStorage, monkeypatch: MonkeyPatch) -> None:
    # Patch во внешний модуль, который реально импортируется внутрь метода
    monkeypatch.setattr(
        "security.auth.code_service.get_backup_code_secret_for_storage",
        lambda user, code: b"Q" * 32,
    )
    storage.lock()
    storage.emergency_recover("deadbeef")
    assert storage.is_unlocked() is True


def test_save_load_mfa_state(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.TOTP, user_id="test", value="x")
    mfa_state: Dict[str, Any] = {"step": 2, "user": "test"}
    storage.save(mfa_state)
    loaded = storage.load()
    assert loaded == mfa_state


def test_access_denied(storage: SecureStorage) -> None:
    with pytest.raises(PermissionError):
        storage.store("should_fail", 1, context="noaccess")


def test_invalid_mfa(monkeypatch: MonkeyPatch, storage: SecureStorage) -> None:
    # Patch MFA auth to raise error
    def raise_perm(*args: Any, **kwargs: Any) -> bytes:
        raise PermissionError("fail")

    monkeypatch.setattr(SecureStorage, "_mfa_auth", raise_perm)
    with pytest.raises(PermissionError):
        storage.unlock(MFAFactor.BACKUP_CODE, user_id="nobody", value="err")


def test_backend_delete_not_found(storage: SecureStorage) -> None:
    # Удаление несуществующего ключа: проходит без исключения, покрывает if not in db
    storage.unlock(MFAFactor.TOTP, "del", "x")
    storage.delete("absent")


def test_filebackend_setperms(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    from security.crypto.secure_storage import FileEncryptedStorageBackend

    path: str = str(tmp_path / "permtest.bin")
    with open(path, "wb") as f:
        pickle.dump({}, f)
    backend = FileEncryptedStorageBackend(path)
    called: dict[str, bool] = {}
    monkeypatch.setattr("os.chmod", lambda *a, **k: (_ for _ in ()).throw(PermissionError("fail")))
    backend._set_file_perms()  # покрывает выдачу warning


def test_store_pickle_fail(storage: SecureStorage, monkeypatch: MonkeyPatch) -> None:
    storage.unlock(MFAFactor.FIDO2, "p", "q")
    monkeypatch.setattr(
        "pickle.dumps", lambda *_: (_ for _ in ()).throw(pickle.PickleError("failed"))
    )
    with pytest.raises(pickle.PickleError):
        storage.store("k", {"x": 1}, context="c")


def test_retrieve_decrypt_error(storage: SecureStorage, monkeypatch: MonkeyPatch) -> None:
    storage.unlock(MFAFactor.TOTP, "user", "x")
    storage.store("errkey", 123, context="ctx")
    monkeypatch.setattr(
        "security.crypto.secure_storage.decrypt_aes_gcm",
        lambda *_: (_ for _ in ()).throw(ValueError("fail")),
    )
    with pytest.raises(PermissionError):
        storage.retrieve("errkey", context="ctx")


def test_rotate_salt_key_error(storage: SecureStorage) -> None:
    storage.unlock(MFAFactor.TOTP, "ro", "r")
    with pytest.raises(KeyError):
        storage.rotate_salt("not_found", "a", "b")


def test_high_security_op_decrypt_fail(storage: SecureStorage, monkeypatch: MonkeyPatch) -> None:
    storage.unlock(MFAFactor.TOTP, "who", "123")
    storage.store("secure", 42, context="x")
    monkeypatch.setattr(
        "security.crypto.secure_storage.decrypt_aes_gcm",
        lambda *_: (_ for _ in ()).throw(Exception("fail")),
    )
    with pytest.raises(PermissionError):
        storage.high_security_op(MFAFactor.FIDO2, "who", "z", "secure", context="x")


def test_high_security_op_pickle_error(storage: SecureStorage, monkeypatch: MonkeyPatch) -> None:
    storage.unlock(MFAFactor.TOTP, "wz", "pass")
    storage.store("p", {"x": 1}, context="ct")
    monkeypatch.setattr(
        "pickle.loads", lambda *_: (_ for _ in ()).throw(pickle.PickleError("fail"))
    )
    with pytest.raises(pickle.PickleError):
        storage.high_security_op(MFAFactor.FIDO2, "wz", "pass", "p", "ct")


def test_batch_zeroize(storage: SecureStorage, monkeypatch: MonkeyPatch) -> None:
    storage.unlock(MFAFactor.FIDO2, "b", "c")

    class DummyByte(bytearray):
        pass

    monkeypatch.setattr("pickle.dumps", lambda obj: DummyByte([1, 2, 3]))
    storage.batch_store({"k": "v"}, context="q")


def test_mfa_auth_unsupported(storage: SecureStorage) -> None:
    # Попытка создать недопустимый Enum вызовет ValueError сразу
    with pytest.raises(ValueError):
        storage._mfa_auth(MFAFactor("bad_value"), "uid", "val")
