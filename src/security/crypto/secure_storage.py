"""
RU: Защищённое шифрованное хранилище с Strategy backend, MFA, timeout, audit logging, zeroization, salt rotation, emergency recovery.
EN: Secure encrypted storage with Strategy backend, MFA unlock (session + selective high-security), timeout lock, audit log, zeroization, salt rotation, emergency recovery.

Типобезопасный API, интеграция с FIDO2, TOTP, Backup Code, файловый/in-memory/расширяемый backend, заводские и аварийные сценарии.
"""

import logging
import time
from typing import Any, Optional, Dict, List, Callable
from abc import ABC, abstractmethod
from enum import Enum
import pickle

from security.crypto.symmetric import encrypt_aes_gcm, decrypt_aes_gcm
from security.crypto.kdf import derive_key_argon2id

from security.auth.second_method.fido2 import Fido2Authenticator
from security.auth.second_method.totp import TOTPAuthenticator
from security.auth.second_method.code import BackupCodeAuthenticator

try:
    from security.audit.logger import audit_log
except ImportError:
    audit_log = logging.getLogger("secure_storage").info


class MFAFactor(Enum):
    FIDO2 = "fido2"
    TOTP = "totp"
    BACKUP_CODE = "backup_code"


class StorageBackend(ABC):
    @abstractmethod
    def save(self, key: str, encrypted_data: bytes) -> None: ...
    @abstractmethod
    def load(self, key: str) -> Optional[bytes]: ...
    @abstractmethod
    def delete(self, key: str) -> None: ...
    @abstractmethod
    def list_keys(self) -> List[str]: ...


class FileEncryptedStorageBackend(StorageBackend):
    def __init__(self, filepath: str):
        self._filepath = filepath
        try:
            with open(self._filepath, "rb") as f:
                self._db: Dict[str, bytes] = pickle.load(f)
        except (FileNotFoundError, EOFError):
            self._db = {}

    def save(self, key: str, encrypted_data: bytes) -> None:
        self._db[key] = encrypted_data
        with open(self._filepath, "wb") as f:
            pickle.dump(self._db, f)

    def load(self, key: str) -> Optional[bytes]:
        return self._db.get(key)

    def delete(self, key: str) -> None:
        if key in self._db:
            del self._db[key]
            with open(self._filepath, "wb") as f:
                pickle.dump(self._db, f)

    def list_keys(self) -> List[str]:
        return list(self._db.keys())


class InMemoryEncryptedStorageBackend(StorageBackend):
    def __init__(self):
        self._db: Dict[str, bytes] = {}

    def save(self, key: str, encrypted_data: bytes) -> None:
        self._db[key] = encrypted_data

    def load(self, key: str) -> Optional[bytes]:
        return self._db.get(key)

    def delete(self, key: str) -> None:
        self._db.pop(key, None)

    def list_keys(self) -> List[str]:
        return list(self._db.keys())


def _zeroize(data: Optional[bytearray]):
    if data is not None:
        for i in range(len(data)):
            data[i] = 0


class SecureStorage:
    """
    Secure encrypted storage for sensitive records with session unlock and selective high-security operations.
    - MFA unlock (FIDO2/TOTP/Backup)
    - Timeout auto-lock, manual lock/unlock
    - Audit log for all operations
    - Zeroization of key buffer (session key)
    - Salt/context rotation for records (auto-reencrypt)
    - Emergency recovery for backup codes
    """

    DEFAULT_LOCK_TIMEOUT = 600

    def __init__(self, backend: StorageBackend, lock_timeout: int = DEFAULT_LOCK_TIMEOUT):
        self._backend = backend
        self._session_key: Optional[bytearray] = None
        self._is_unlocked: bool = False
        self._last_access: float = 0.0
        self._lock_timeout: int = lock_timeout
        self._recovery_callback: Optional[Callable[[], None]] = None

    def unlock(self, factor: MFAFactor, value: Any) -> None:
        audit_log(f"Unlock attempt using {factor.name}")
        key = self._mfa_auth(factor, value)
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._session_key = bytearray(
            derive_key_argon2id(key, salt=factor.value.encode(), length=32)
        )
        self._is_unlocked = True
        self._last_access = time.time()
        audit_log("SecureStorage unlocked")

    def lock(self) -> None:
        if self._session_key:
            _zeroize(self._session_key)
        self._session_key = None
        self._is_unlocked = False
        audit_log("SecureStorage locked by user")

    def _auto_lock_check(self):
        if self._is_unlocked and (time.time() - self._last_access > self._lock_timeout):
            audit_log("SecureStorage auto-locked by timeout")
            self.lock()

    def is_unlocked(self) -> bool:
        self._auto_lock_check()
        return self._is_unlocked

    def _op_access(self):
        self._auto_lock_check()
        if not self._is_unlocked or self._session_key is None:
            audit_log("Storage locked; access denied")
            raise PermissionError("Storage not unlocked")
        self._last_access = time.time()

    def store(self, key: str, obj: Any, context: str) -> None:
        self._op_access()
        raw = pickle.dumps(obj)
        enc = encrypt_aes_gcm(raw, bytes(self._session_key), context.encode())
        self._backend.save(key, enc)
        audit_log(f"Stored encrypted record: {key}")

    def retrieve(self, key: str, context: str) -> Any:
        self._op_access()
        enc = self._backend.load(key)
        if enc is None:
            audit_log(f"Key not found: {key}")
            raise KeyError(f"{key} not found")
        try:
            raw = decrypt_aes_gcm(enc, bytes(self._session_key), context.encode())
        except Exception as ex:
            audit_log(f"Decryption failed ({key}): {str(ex)}")
            raise PermissionError("Decryption failed: missing or invalid context/key")
        obj = pickle.loads(raw)
        return obj

    def delete(self, key: str) -> None:
        self._op_access()
        self._backend.delete(key)
        audit_log(f"Deleted key: {key}")

    def high_security_op(self, factor: MFAFactor, value: Any, key: str, context: str) -> Any:
        audit_log("High-security operation requested")
        key_material = self._mfa_auth(factor, value)
        if isinstance(key_material, str):
            key_material = key_material.encode("utf-8")
        session_key = derive_key_argon2id(key_material, salt=factor.value.encode(), length=32)
        enc = self._backend.load(key)
        if enc is None:
            audit_log(f"Key not found: {key}")
            raise KeyError(f"{key} not found")
        try:
            raw = decrypt_aes_gcm(enc, session_key, context.encode())
        except Exception as ex:
            audit_log(f"Decryption failed ({key}): {str(ex)}")
            raise PermissionError("Decryption failed: missing or invalid context/key")
        obj = pickle.loads(raw)
        audit_log("High-security operation completed")
        return obj

    def rotate_salt(self, key: str, old_context: str, new_context: str) -> None:
        self._op_access()
        enc = self._backend.load(key)
        if enc is None:
            audit_log(f"Rotate salt failed: key not found {key}")
            raise KeyError(f"{key} not found")
        raw = decrypt_aes_gcm(enc, bytes(self._session_key), old_context.encode())
        obj = pickle.loads(raw)
        new_enc = encrypt_aes_gcm(pickle.dumps(obj), bytes(self._session_key), new_context.encode())
        self._backend.save(key, new_enc)
        audit_log(f"Salt rotated for key: {key}")

    def emergency_recover(self, backup_code: str) -> None:
        audit_log("Emergency recovery triggered")
        key_material = BackupCodeAuthenticator.authenticate(backup_code)
        if isinstance(key_material, str):
            key_material = key_material.encode("utf-8")
        self._session_key = bytearray(
            derive_key_argon2id(key_material, salt=MFAFactor.BACKUP_CODE.value.encode(), length=32)
        )
        self._is_unlocked = True
        self._last_access = time.time()
        audit_log("Emergency recovery: storage unlocked by backup code")
        if self._recovery_callback:
            self._recovery_callback()

    def keys(self) -> List[str]:
        return self._backend.list_keys()

    def batch_store(self, items: Dict[str, Any], context: str) -> None:
        self._op_access()
        for key, obj in items.items():
            raw = pickle.dumps(obj)
            enc = encrypt_aes_gcm(raw, bytes(self._session_key), context.encode())
            self._backend.save(key, enc)
            audit_log(f"Stored key in batch: {key}")

    def batch_rotate_salt(self, keys: List[str], old_context: str, new_context: str) -> None:
        self._op_access()
        for key in keys:
            self.rotate_salt(key, old_context, new_context)

    def set_recovery_callback(self, cb: Callable[[], None]) -> None:
        self._recovery_callback = cb

    def _mfa_auth(self, factor: MFAFactor, value: Any) -> bytes:
        """Uniform MFA authenticator with error-type invariance."""
        try:
            if factor == MFAFactor.FIDO2:
                result = Fido2Authenticator.authenticate(value)
            elif factor == MFAFactor.TOTP:
                result = TOTPAuthenticator.authenticate(value)
            elif factor == MFAFactor.BACKUP_CODE:
                result = BackupCodeAuthenticator.authenticate(value)
            else:
                raise ValueError("Unsupported MFA factor")
            if isinstance(result, str):
                return result.encode("utf-8")
            return result
        except Exception:
            time.sleep(0.1)
            audit_log("MFA authenticate failed/invariant error")
            raise PermissionError("MFA authentication failed")
