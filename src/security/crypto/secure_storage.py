# security/crypto/secure_storage.py
# -*- coding: utf-8 -*-
"""
RU: Потокобезопасный зашифрованный файловый backend хранилища (AES-256-GCM) с атомарной записью,
едиными правами доступа к файлу, best-effort zeroization и DI-совместимостью.

EN: Thread-safe encrypted file keystore backend (AES-256-GCM) with atomic writes,
uniform file permission hardening, best-effort zeroization, and DI compatibility.

Design:
- Implements KeyStoreProtocol (save/load/delete) for use by higher-level secure storage.
- Encryption via SymmetricCipherProtocol; key provided by a user-supplied callable.
- On-disk format: JSON mapping name -> { "n": base64(nonce), "c": base64(ciphertext||tag) }.
- Atomic writes using a temp file + os.replace under a process-wide compatible lock.
- Strict file permission application via utils.set_secure_file_permissions after each write.
- No secrets are logged; only structural events and item names.

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
import tempfile
import threading
from typing import Callable, Final, Mapping, MutableMapping, Optional

from security.crypto.exceptions import (
    StorageError,
    StorageReadError,
    StorageWriteError,
)
from security.crypto.protocols import KeyStoreProtocol, SymmetricCipherProtocol
from security.crypto.utils import set_secure_file_permissions, zero_memory

_LOGGER: Final = logging.getLogger(__name__)


def _b64e(data: bytes) -> str:
    """Encode bytes to base64 ASCII string (no newlines)."""
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    """Decode base64 ASCII string to bytes."""
    return base64.b64decode(text.encode("ascii"), validate=True)


class FileEncryptedStorageBackend(KeyStoreProtocol):
    """
    Encrypted file keystore with AES-256-GCM.

    The file contains a JSON object mapping item names to objects:
      { "<name>": { "n": "<base64-12b-nonce>", "c": "<base64-ciphertext||tag>" }, ... }

    Args:
        filepath: path to keystore file (created on first save).
        cipher: symmetric cipher provider (AES-256-GCM).
        key_provider: callable returning a 32-byte AES key (kept outside this object).

    Raises:
        StorageError: on invalid initialization parameters.
    """

    __slots__ = ("_filepath", "_cipher", "_key_provider", "_lock")

    def __init__(
        self,
        filepath: str,
        cipher: SymmetricCipherProtocol,
        key_provider: Callable[[], bytes],
    ) -> None:
        if not isinstance(filepath, str) or not filepath:
            raise StorageError("Invalid keystore path")
        self._filepath: str = filepath
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
                    nonce, combined = enc_res  # type: ignore[misc]
                else:
                    n, ct, tag = enc_res  # type: ignore[misc]
                    nonce, combined = n, ct + tag

                db[name] = {"n": _b64e(nonce), "c": _b64e(combined)}
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
                nonce_b = _b64d(rec["n"])
                combined_b = _b64d(rec["c"])
                key = self._key_provider()
                pt = self._cipher.decrypt(key, nonce_b, combined_b)
                return pt
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

    # Internals

    def _read_db_checked(self) -> MutableMapping[str, Mapping[str, str]]:
        """
        Read JSON mapping from file or return empty dict if file does not exist.

        Raises:
            StorageReadError: if file content is invalid.
        """
        if not os.path.exists(self._filepath):
            return {}

        try:
            with open(self._filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as exc:
            _LOGGER.error("Keystore read error: %s", exc.__class__.__name__)
            raise StorageReadError("Failed to read keystore file") from exc

        try:
            obj = json.loads(content)
            if not isinstance(obj, dict):
                raise ValueError("Root must be a JSON object")
            # light validation of record structure
            for k, v in obj.items():
                if not isinstance(k, str) or not isinstance(v, dict):
                    raise ValueError("Invalid record entry")
                if "n" not in v or "c" not in v:
                    raise ValueError("Missing fields")
                if not isinstance(v["n"], str) or not isinstance(v["c"], str):
                    raise ValueError("Fields must be base64 strings")
            return dict(obj)
        except Exception as exc:
            _LOGGER.error("Keystore parse error: %s", exc.__class__.__name__)
            raise StorageReadError("Invalid keystore format") from exc

    def _atomically_write_db(self, db: Mapping[str, Mapping[str, str]]) -> None:
        """Write JSON to a temp file and atomically replace the target file, then harden permissions."""
        data = json.dumps(db, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        dir_name = os.path.dirname(self._filepath) or "."
        os.makedirs(dir_name, exist_ok=True)

        fd: Optional[int] = None
        tmp_path: Optional[str] = None
        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix=".keystore-", suffix=".tmp", dir=dir_name, text=True
            )
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
                fd = None  # fd now managed by file object
                tmp_f.write(data)
                tmp_f.flush()
                os.fsync(tmp_f.fileno())
            os.replace(tmp_path, self._filepath)
            set_secure_file_permissions(self._filepath)
        except Exception:
            try:
                if fd is not None:
                    os.close(fd)
            except Exception:
                pass
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            raise
