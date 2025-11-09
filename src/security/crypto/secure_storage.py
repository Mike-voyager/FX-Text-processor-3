# security/crypto/secure_storage.py
# -*- coding: utf-8 -*-
"""
RU: Потокобезопасный зашифрованный файловый backend хранилища (AES‑256‑GCM) с атомарной записью,
едиными правами доступа к файлу, best‑effort zeroization и DI‑совместимостью.

EN: Thread-safe encrypted file keystore backend (AES-256-GCM) with atomic writes,
uniform file permission hardening, best-effort zeroization, and DI compatibility.

Design:
- Implements KeyStoreProtocol (save/load/delete) for use by higher-level secure storage.
- Encryption via SymmetricCipherProtocol; key provided by a user-supplied callable.
- On-disk format: JSON mapping name -> { "v": version, "n": base64(nonce), "c": base64(ciphertext||tag) }.
- Atomic writes using a temp file + os.replace under a process-wide compatible lock.
- Strict file permission application via utils.set_secure_file_permissions after each write.
- No secrets are logged; only structural events and item names.
- Key rotation support via version field and reencrypt methods.

Thread-safety:
- A re-entrant lock (RLock) guards read-modify-write.
- No global state; each instance isolates its own file.

Zeroization:
- Python cannot wipe immutable bytes; wiping applies only to mutable bytearray where used.
- This backend keeps secrets ephemeral in local variables; no secret content is logged.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Final, Optional

from security.crypto.exceptions import (
    StorageError,
    StorageReadError,
    StorageWriteError,
)
from security.crypto.protocols import SymmetricCipherProtocol
from security.crypto.utils import set_secure_file_permissions, zero_memory

_LOGGER: Final = logging.getLogger(__name__)

# Current key version for rotation support
_CURRENT_KEY_VERSION: Final[int] = 1

# Platform-specific file locking
if sys.platform == "win32":
    import msvcrt

    def _lock_file(fd: int) -> None:
        """Acquire exclusive lock on Windows."""
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

else:
    import fcntl

    def _lock_file(fd: int) -> None:
        """Acquire exclusive lock on POSIX."""
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _b64e(data: bytes) -> str:
    """Encode bytes to base64 ASCII string (no newlines)."""
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    """Decode base64 ASCII string to bytes."""
    return base64.b64decode(text.encode("ascii"), validate=True)


# Type alias for JSON record structure
_RecordDict = Dict[str, Any]  # {"v": int, "n": str, "c": str}


class FileEncryptedStorageBackend:
    """
    Encrypted file keystore with AES-256-GCM.

    The file contains a JSON object mapping item names to objects:
      { "<name>": { "v": 1, "n": "<base64-12b-nonce>", "c": "<base64-ciphertext||tag>" }, ... }

    Implements KeyStoreProtocol interface (duck-typed Protocol):
      - save(name: str, data: bytes) -> None
      - load(name: str) -> bytes
      - delete(name: str) -> None

    Args:
        filepath: path to keystore file (created on first save).
        cipher: symmetric cipher provider (AES-256-GCM).
        key_provider: callable returning a 32-byte AES key (kept outside this object).

    Raises:
        StorageError: on invalid initialization parameters.
    """

    __slots__ = ("_filepath", "_filepath_str", "_cipher", "_key_provider", "_lock")

    def __init__(
        self,
        filepath: str,
        cipher: SymmetricCipherProtocol,
        key_provider: Callable[[], bytes],
    ) -> None:
        if not isinstance(filepath, str) or not filepath:
            raise StorageError("Invalid keystore path")

        # Convert to Path for proper Unicode/long path handling (Windows support)
        self._filepath: Path = Path(filepath).resolve()
        # Keep string version for compatibility
        self._filepath_str: str = str(self._filepath)

        self._cipher: SymmetricCipherProtocol = cipher
        self._key_provider: Callable[[], bytes] = key_provider
        self._lock = threading.RLock()

    # KeyStoreProtocol API

    def save(self, name: str, data: bytes) -> None:
        """
        Save or replace an item.

        Args:
            name: item name.
            data: plaintext bytes to encrypt and persist.

        Raises:
            StorageWriteError: when write fails.
        """
        if not isinstance(name, str) or not name:
            raise StorageWriteError("Invalid item name")
        if not isinstance(data, (bytes, bytearray)):
            raise StorageWriteError("Data must be bytes-like")

        with self._lock:
            db = self._read_db_checked()
            key: bytes = self._key_provider()
            is_mutable_input: bool = isinstance(data, bytearray)

            try:
                enc_res = self._cipher.encrypt(key, data)
                # Support both (nonce, combined) and (nonce, ct, tag)
                nonce: bytes
                combined: bytes
                if len(enc_res) == 2:
                    nonce, combined = enc_res[0], enc_res[1]
                else:
                    n, ct, tag = enc_res[0], enc_res[1], enc_res[2]
                    nonce, combined = n, ct + tag

                # Store with version for key rotation support
                db[name] = {
                    "v": _CURRENT_KEY_VERSION,
                    "n": _b64e(nonce),
                    "c": _b64e(combined),
                }
                self._atomically_write_db(db)

            except Exception as exc:
                _LOGGER.error(
                    "Keystore save failed for '%s': %s", name, exc.__class__.__name__
                )
                raise StorageWriteError("Save operation failed") from exc

            finally:
                if is_mutable_input and isinstance(data, bytearray):
                    try:
                        # best-effort wipe of caller-provided bytearray
                        zero_memory(data)
                    except Exception:
                        pass

            _LOGGER.info("Keystore item '%s' saved.", name)

    def load(self, name: str) -> bytes:
        """
        Load an item by name.

        Args:
            name: item name.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            KeyError: if item not found.
            StorageReadError: on read/decryption errors.
        """
        if not isinstance(name, str) or not name:
            raise StorageReadError("Invalid item name")

        with self._lock:
            db = self._read_db_checked()
            if name not in db:
                raise KeyError(name)

            rec = db[name]
            try:
                # Check key version for rotation support
                key_ver_raw = rec.get("v", 0)  # default to 0 for legacy records

                # Ensure version is int
                if not isinstance(key_ver_raw, int):
                    raise StorageReadError(f"Invalid version type: {type(key_ver_raw)}")

                key_ver: int = key_ver_raw

                if key_ver > _CURRENT_KEY_VERSION:
                    _LOGGER.error(
                        "Unsupported key version %d for item '%s' (current: %d)",
                        key_ver,
                        name,
                        _CURRENT_KEY_VERSION,
                    )
                    raise StorageReadError(f"Unsupported key version: {key_ver}")

                # Extract nonce and ciphertext (must be strings)
                nonce_str = rec["n"]
                combined_str = rec["c"]

                if not isinstance(nonce_str, str):
                    raise StorageReadError(f"Invalid nonce type: {type(nonce_str)}")
                if not isinstance(combined_str, str):
                    raise StorageReadError(
                        f"Invalid ciphertext type: {type(combined_str)}"
                    )

                nonce_b = _b64d(nonce_str)
                combined_b = _b64d(combined_str)
                key = self._key_provider()

                # Explicit type assertion for decrypt return value
                plaintext: bytes = self._cipher.decrypt(key, nonce_b, combined_b)
                return plaintext

            except KeyError as exc:
                _LOGGER.warning(
                    "Malformed keystore record for '%s': missing %s", name, exc
                )
                raise StorageReadError("Malformed keystore record") from exc
            except Exception as exc:
                _LOGGER.error(
                    "Keystore load failed for '%s': %s", name, exc.__class__.__name__
                )
                raise StorageReadError("Load operation failed") from exc

    def delete(self, name: str) -> None:
        """
        Delete an item by name.

        Args:
            name: item name.

        Raises:
            KeyError: if item not found.
            StorageWriteError: on write errors.
        """
        if not isinstance(name, str) or not name:
            raise StorageWriteError("Invalid item name")

        with self._lock:
            db = self._read_db_checked()
            if name not in db:
                raise KeyError(name)
            del db[name]
            try:
                self._atomically_write_db(db)
            except Exception as exc:
                _LOGGER.error(
                    "Keystore delete failed for '%s': %s", name, exc.__class__.__name__
                )
                raise StorageWriteError("Delete operation failed") from exc
            _LOGGER.info("Keystore item '%s' deleted.", name)

    # Key rotation methods

    def needs_reencryption(self, name: str) -> bool:
        """
        Check if item needs re-encryption with current key version.

        Args:
            name: item name.

        Returns:
            True if re-encryption recommended.

        Raises:
            KeyError: if item not found.
        """
        with self._lock:
            db = self._read_db_checked()
            if name not in db:
                raise KeyError(name)
            rec = db[name]
            key_ver_raw = rec.get("v", 0)

            # Ensure version is int
            if not isinstance(key_ver_raw, int):
                return True  # Malformed version, needs reencryption

            key_ver: int = key_ver_raw
            return key_ver < _CURRENT_KEY_VERSION

    def reencrypt(
        self,
        name: str,
        new_key_provider: Callable[[], bytes],
    ) -> None:
        """
        Re-encrypt item with new key (for key rotation).

        Args:
            name: item name.
            new_key_provider: callable returning new 32-byte key.

        Raises:
            KeyError: if item not found.
            StorageError: on re-encryption failure.
        """
        with self._lock:
            # Load with old key
            plaintext = self.load(name)

            # Re-encrypt with new key
            old_provider = self._key_provider
            self._key_provider = new_key_provider

            try:
                self.save(name, plaintext)
                _LOGGER.info("Item '%s' re-encrypted successfully.", name)
            except Exception as exc:
                # Rollback
                self._key_provider = old_provider
                _LOGGER.error(
                    "Re-encryption failed for '%s': %s", name, exc.__class__.__name__
                )
                raise StorageError("Re-encryption failed") from exc
            finally:
                # Best-effort wipe plaintext
                if isinstance(plaintext, bytearray):
                    try:
                        zero_memory(plaintext)
                    except Exception:
                        pass

    def reencrypt_all(self, new_key_provider: Callable[[], bytes]) -> None:
        """
        Re-encrypt all items with new key (batch operation).

        Args:
            new_key_provider: callable returning new 32-byte key.

        Raises:
            StorageError: on re-encryption failure for any item.
        """
        with self._lock:
            db = self._read_db_checked()
            item_names = list(db.keys())

            _LOGGER.info("Starting batch re-encryption of %d items...", len(item_names))

            for name in item_names:
                try:
                    self.reencrypt(name, new_key_provider)
                except Exception as exc:
                    _LOGGER.error(
                        "Batch re-encryption stopped at item '%s': %s",
                        name,
                        exc.__class__.__name__,
                    )
                    raise StorageError(
                        f"Batch re-encryption failed at '{name}'"
                    ) from exc

            _LOGGER.info("Batch re-encryption completed successfully.")

    # Internals

    def _read_db_checked(self) -> Dict[str, _RecordDict]:
        """
        Read JSON mapping from file or return empty dict if file does not exist.

        Raises:
            StorageReadError: if file content is invalid.
        """
        if not self._filepath.exists():
            return {}

        try:
            with self._filepath.open("r", encoding="utf-8") as f:
                content = f.read()
        except Exception as exc:
            _LOGGER.error("Keystore read error: %s", exc.__class__.__name__)
            raise StorageReadError("Failed to read keystore file") from exc

        try:
            obj = json.loads(content)
            if not isinstance(obj, dict):
                raise ValueError("Root must be a JSON object")

            # Validate and build typed dict
            result: Dict[str, _RecordDict] = {}

            for k, v in obj.items():
                if not isinstance(k, str) or not isinstance(v, dict):
                    raise ValueError("Invalid record entry")
                if "n" not in v or "c" not in v:
                    raise ValueError("Missing fields")
                if not isinstance(v["n"], str) or not isinstance(v["c"], str):
                    raise ValueError("Fields must be base64 strings")
                # 'v' is optional (legacy compatibility)
                if "v" in v and not isinstance(v["v"], int):
                    raise ValueError("Version must be integer")

                result[k] = v

            return result
        except Exception as exc:
            _LOGGER.error("Keystore parse error: %s", exc.__class__.__name__)
            raise StorageReadError("Invalid keystore format") from exc

    def _atomically_write_db(self, db: Dict[str, _RecordDict]) -> None:
        """
        Write JSON to a temp file and atomically replace the target file, then harden permissions.

        Includes file locking to prevent race conditions on concurrent access.
        """
        data = json.dumps(db, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

        # Use pathlib for directory operations (Windows Unicode support)
        self._filepath.parent.mkdir(parents=True, exist_ok=True)

        fd: Optional[int] = None
        tmp_path: Optional[str] = None
        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix=".keystore-",
                suffix=".tmp",
                dir=str(self._filepath.parent),
                text=True,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
                fd = None  # fd now managed by file object

                # Acquire exclusive lock before writing (prevent race conditions)
                try:
                    _lock_file(tmp_f.fileno())
                except (IOError, OSError) as e:
                    _LOGGER.error("Could not acquire file lock: %s", e)
                    raise StorageWriteError(f"Could not acquire file lock: {e}") from e

                tmp_f.write(data)
                tmp_f.flush()
                os.fsync(tmp_f.fileno())

            # Use Path.replace for proper Unicode handling
            Path(tmp_path).replace(self._filepath)
            set_secure_file_permissions(self._filepath_str)

        except Exception:
            try:
                if fd is not None:
                    os.close(fd)
            except Exception:
                pass
            if tmp_path and Path(tmp_path).exists():
                try:
                    Path(tmp_path).unlink()
                except Exception:
                    pass
            raise
