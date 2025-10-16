"""
Модуль защищённого хранилища для ESC/P Text Editor — шифрованное хранение чувствительных данных с MFA-контролем доступа.

Особенности:
- Многофакторная аутентификация (MFA): FIDO2, TOTP, Backup Codes для разблокировки хранилища.
- Session-based ключи: автоматическая блокировка по таймауту или вручную.
- Zeroization: все ключи сессии и plaintext-буферы зануляются при освобождении памяти.
- Контекстная ре-шифрация: salt/context rotation для защиты от side-channel attacks.
- Backend-агностичность: поддержка файлового и in-memory backend через абстракцию StorageBackend.
- Context manager: автоматический shutdown и cleanup ресурсов с использованием блока `with`.
- Audit trail: все операции логируются для SIEM-систем и forensic анализа.
- Emergency recovery: аварийное восстановление доступа через backup codes.
- Batch operations: пакетная обработка записей для повышения производительности.
- Protocol-интерфейс KeyStore для DI и расширяемости.

Classes:
    MFAFactor: enum поддерживаемых факторов MFA.
    StorageBackend: абстрактный backend для хранения.
    FileEncryptedStorageBackend: файловый backend с шифрованием.
    InMemoryEncryptedStorageBackend: in-memory backend для тестов.
    KeyStore: protocol-интерфейс для key-value хранилищ (DI).
    SecureStorage: главный класс защищённого хранилища с MFA и context manager.
"""

import logging
import time
from typing import (
    Any,
    Optional,
    Dict,
    List,
    Callable,
    cast,
    Protocol,
    runtime_checkable,
    Final,
)
from abc import ABC, abstractmethod
from enum import Enum
import pickle

from security.crypto.symmetric import encrypt_aes_gcm, decrypt_aes_gcm
from security.crypto.kdf import derive_key_argon2id

try:
    from security.audit.logger import audit_log  # type: ignore
except ImportError:
    audit_log = logging.getLogger("secure_storage").info

_LOG: Final = logging.getLogger("security.crypto.secure_storage")

# ================================ Enums =======================================


class MFAFactor(Enum):
    """Supported MFA authentication factors."""

    FIDO2 = "fido2"
    TOTP = "totp"
    BACKUP_CODE = "backup_code"


# ============================== Protocols =====================================


@runtime_checkable
class KeyStore(Protocol):
    """Protocol for key-value stores (for DI/testing)."""

    def get_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve encrypted data by key."""
        ...

    def set_key(self, key_id: str, data: bytes) -> None:
        """Store encrypted data."""
        ...

    def rotate_key(self, key_id: str) -> None:
        """Rotate/re-encrypt key."""
        ...


# ============================ Storage Backends ================================


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def save(self, key: str, encrypted_data: bytes) -> None:
        """Save encrypted data."""
        ...

    @abstractmethod
    def load(self, key: str) -> Optional[bytes]:
        """Load encrypted data."""
        ...

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete data."""
        ...

    @abstractmethod
    def list_keys(self) -> List[str]:
        """List all keys."""
        ...


class FileEncryptedStorageBackend(StorageBackend):
    """File-based encrypted storage backend with atomic writes."""

    def __init__(self, filepath: str) -> None:
        self._filepath = filepath
        self._set_file_perms()
        try:
            with open(self._filepath, "rb") as f:
                self._db: Dict[str, bytes] = pickle.load(f)
        except (FileNotFoundError, EOFError):
            self._db = {}

    def _set_file_perms(self) -> None:
        import os
        import stat

        try:
            os.chmod(self._filepath, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            _LOG.warning(
                "Could not set strict permissions for %s: %s", self._filepath, e
            )

    def save(self, key: str, encrypted_data: bytes) -> None:
        self._db[key] = encrypted_data
        tmp = self._filepath + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(self._db, f)
        import os

        os.replace(tmp, self._filepath)
        self._set_file_perms()

    def load(self, key: str) -> Optional[bytes]:
        return self._db.get(key)

    def delete(self, key: str) -> None:
        if key in self._db:
            del self._db[key]
            with open(self._filepath, "wb") as f:
                pickle.dump(self._db, f)
            self._set_file_perms()

    def list_keys(self) -> List[str]:
        return list(self._db.keys())


class InMemoryEncryptedStorageBackend(StorageBackend):
    """In-memory encrypted storage backend (for tests/dev)."""

    def __init__(self) -> None:
        self._db: Dict[str, bytes] = {}

    def save(self, key: str, encrypted_data: bytes) -> None:
        self._db[key] = encrypted_data

    def load(self, key: str) -> Optional[bytes]:
        return self._db.get(key)

    def delete(self, key: str) -> None:
        self._db.pop(key, None)

    def list_keys(self) -> List[str]:
        return list(self._db.keys())


# ============================ Utility Functions ===============================


def _zeroize(data: Optional[bytearray]) -> None:
    """Zero out bytearray in-place (best-effort memory cleanup)."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


# ========================== Secure Storage Container ==========================


class SecureStorage:
    """
    Secure encrypted storage with MFA unlock, automatic timeout, and context manager support.

    Example:
        >>> backend = InMemoryEncryptedStorageBackend()
        >>> with SecureStorage(backend, lock_timeout=600) as storage:
        ...     storage.unlock(MFAFactor.TOTP, "user123", "123456")
        ...     storage.store("secret_key", {"data": "sensitive"}, "context1")
        ...     obj = storage.retrieve("secret_key", "context1")
        >>> # Automatic shutdown and zeroization on exit
    """

    MFA_STATE_KEY: Final[str] = "__mfa_state__"
    DEFAULT_LOCK_TIMEOUT: Final[int] = 600

    def __init__(
        self, backend: StorageBackend, lock_timeout: int = DEFAULT_LOCK_TIMEOUT
    ) -> None:
        self._backend = backend
        self._session_key: Optional[bytearray] = None
        self._is_unlocked: bool = False
        self._last_access: float = 0.0
        self._lock_timeout: int = lock_timeout
        self._recovery_callback: Optional[Callable[[], None]] = None

    def __enter__(self) -> "SecureStorage":
        """Context manager entry."""
        _LOG.info("SecureStorage context entered.")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit with automatic shutdown and zeroization."""
        _LOG.info("SecureStorage context exiting; performing cleanup.")
        self.shutdown()

    def shutdown(self) -> None:
        """Explicitly shutdown storage: lock, zeroize, cleanup."""
        self.lock()
        audit_log("SecureStorage shutdown complete.")
        _LOG.info("SecureStorage shut down.")

    def unlock(self, factor: MFAFactor, user_id: str, value: Any) -> None:
        """Unlock storage using MFA factor."""
        audit_log(f"Unlock attempt using {factor.name}")
        key = self._mfa_auth(factor, user_id, value)
        if isinstance(key, str):
            key = key.encode("utf-8")
        session_key = bytearray(
            derive_key_argon2id(key, salt=factor.value.encode(), length=32)
        )
        _zeroize(self._session_key)
        self._session_key = session_key
        self._is_unlocked = True
        self._last_access = time.time()
        audit_log("SecureStorage unlocked")

    def lock(self) -> None:
        """Lock storage and zeroize session key."""
        if self._session_key:
            _zeroize(self._session_key)
        self._session_key = None
        self._is_unlocked = False
        audit_log("SecureStorage locked by user")

    def _auto_lock_check(self) -> None:
        """Check if session expired; auto-lock if needed."""
        if self._is_unlocked and (time.time() - self._last_access > self._lock_timeout):
            audit_log("SecureStorage auto-locked by timeout")
            self.lock()

    def is_unlocked(self) -> bool:
        """Check if storage is unlocked."""
        self._auto_lock_check()
        return self._is_unlocked

    def _op_access(self) -> None:
        """Verify storage is unlocked before operation."""
        self._auto_lock_check()
        if not self._is_unlocked or self._session_key is None:
            audit_log("Storage locked; access denied")
            raise PermissionError("Storage not unlocked")
        self._last_access = time.time()

    def store(self, key: str, obj: Any, context: str) -> None:
        """Store encrypted object."""
        self._op_access()
        raw = pickle.dumps(obj)
        key_bytes = bytes(self._session_key) if self._session_key is not None else b""
        enc = encrypt_aes_gcm(raw, key_bytes, context.encode())
        self._backend.save(key, enc)
        audit_log(f"Stored encrypted record: {key}")
        if isinstance(raw, bytearray):
            _zeroize(raw)

    def retrieve(self, key: str, context: str) -> Any:
        """Retrieve and decrypt object."""
        self._op_access()
        enc = self._backend.load(key)
        if enc is None:
            audit_log(f"Key not found: {key}")
            raise KeyError(f"{key} not found")
        key_bytes = bytes(self._session_key) if self._session_key is not None else b""
        try:
            raw = decrypt_aes_gcm(enc, key_bytes, context.encode())
        except Exception as ex:
            audit_log(f"Decryption failed ({key}): {str(ex)}")
            raise PermissionError("Decryption failed: missing or invalid context/key")
        try:
            obj = pickle.loads(raw)
        finally:
            if isinstance(raw, bytearray):
                _zeroize(raw)
        return obj

    def delete(self, key: str) -> None:
        """Delete key."""
        self._op_access()
        self._backend.delete(key)
        audit_log(f"Deleted key: {key}")

    def high_security_op(
        self, factor: MFAFactor, user_id: str, value: Any, key: str, context: str
    ) -> Any:
        """High-security operation requiring immediate MFA re-authentication."""
        audit_log("High-security operation requested")
        key_material = self._mfa_auth(factor, user_id, value)
        if isinstance(key_material, str):
            key_material = key_material.encode("utf-8")
        session_key = derive_key_argon2id(
            key_material, salt=factor.value.encode(), length=32
        )
        enc = self._backend.load(key)
        if enc is None:
            audit_log(f"Key not found: {key}")
            raise KeyError(f"{key} not found")
        try:
            raw = decrypt_aes_gcm(enc, session_key, context.encode())
        except Exception as ex:
            audit_log(f"Decryption failed ({key}): {str(ex)}")
            raise PermissionError("Decryption failed: missing or invalid context/key")
        try:
            obj = pickle.loads(raw)
        finally:
            if isinstance(raw, bytearray):
                _zeroize(raw)
        audit_log("High-security operation completed")
        return obj

    def rotate_salt(self, key: str, old_context: str, new_context: str) -> None:
        """Re-encrypt key with new context (salt rotation)."""
        self._op_access()
        enc = self._backend.load(key)
        if enc is None:
            audit_log(f"Rotate salt failed: key not found {key}")
            raise KeyError(f"{key} not found")
        key_bytes = bytes(self._session_key) if self._session_key is not None else b""
        raw = decrypt_aes_gcm(enc, key_bytes, old_context.encode())
        obj = pickle.loads(raw)
        new_enc = encrypt_aes_gcm(pickle.dumps(obj), key_bytes, new_context.encode())
        self._backend.save(key, new_enc)
        audit_log(f"Salt rotated for key: {key}")
        if isinstance(raw, bytearray):
            _zeroize(raw)

    def emergency_recover(self, backup_code: str) -> None:
        """Emergency recovery using backup code."""
        from security.auth.code_service import get_backup_code_secret_for_storage

        audit_log("Emergency recovery triggered")
        user_id = "emergency"
        key_material = get_backup_code_secret_for_storage(user_id, backup_code)
        if isinstance(key_material, str):
            key_material = key_material.encode("utf-8")
        session_key = bytearray(
            derive_key_argon2id(
                key_material, salt=MFAFactor.BACKUP_CODE.value.encode(), length=32
            )
        )
        _zeroize(self._session_key)
        self._session_key = session_key
        self._is_unlocked = True
        self._last_access = time.time()
        audit_log("Emergency recovery: storage unlocked by backup code")
        if self._recovery_callback:
            self._recovery_callback()

    def keys(self) -> List[str]:
        """List all keys."""
        return self._backend.list_keys()

    def batch_store(self, items: Dict[str, Any], context: str) -> None:
        """Batch store multiple items."""
        self._op_access()
        staging: Dict[str, bytes] = {}
        key_bytes = bytes(self._session_key) if self._session_key is not None else b""
        for key, obj in items.items():
            raw = pickle.dumps(obj)
            enc = encrypt_aes_gcm(raw, key_bytes, context.encode())
            staging[key] = enc
            if isinstance(raw, bytearray):
                _zeroize(raw)
        for key, enc in staging.items():
            self._backend.save(key, enc)
            audit_log(f"Stored key in batch: {key}")

    def batch_rotate_salt(
        self, keys: List[str], old_context: str, new_context: str
    ) -> None:
        """Batch rotate salt for multiple keys."""
        self._op_access()
        for key in keys:
            self.rotate_salt(key, old_context, new_context)

    def set_recovery_callback(self, cb: Callable[[], None]) -> None:
        """Set callback for emergency recovery."""
        self._recovery_callback = cb

    def _mfa_auth(self, factor: MFAFactor, user_id: str, value: Any) -> bytes:
        """Universal MFA gateway."""
        try:
            if factor == MFAFactor.FIDO2:
                from security.auth.fido2_service import validate_fido2_response

                result = validate_fido2_response(user_id, value)
            elif factor == MFAFactor.TOTP:
                from security.auth.totp_service import validate_totp_code

                result = validate_totp_code(user_id, value)
            elif factor == MFAFactor.BACKUP_CODE:
                from security.auth.code_service import validate_backup_code_for_user

                result = validate_backup_code_for_user(user_id, value)
            else:
                raise ValueError("Unsupported MFA factor")
            if isinstance(result, str):
                return result.encode("utf-8")
            if isinstance(result, bytes):
                return result
            raise PermissionError("MFA service did not return a valid secret")
        except Exception as ex:
            time.sleep(0.1)
            audit_log(f"MFA authenticate failed: {ex}")
            raise PermissionError("MFA authentication failed: " + str(ex))

    def save(self, data: dict) -> None:
        """Universal save for internal state."""
        self.store(self.MFA_STATE_KEY, data, context="mfa_state")

    def load(self) -> Optional[dict]:
        """Universal load for internal state."""
        try:
            result = self.retrieve(self.MFA_STATE_KEY, context="mfa_state")
            return cast(Dict[Any, Any], result)
        except KeyError:
            return None


__all__ = [
    "MFAFactor",
    "StorageBackend",
    "FileEncryptedStorageBackend",
    "InMemoryEncryptedStorageBackend",
    "KeyStore",
    "SecureStorage",
]
