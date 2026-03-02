"""
Зашифрованное хранилище ключей.

Реализует KeyStoreProtocol для безопасного хранения ключей на диске.
Данные шифруются AES-256-GCM, поддерживается сжатие (zlib) и
атомарная запись.

Example:
    >>> from pathlib import Path
    >>> from src.security.crypto.utilities.secure_storage import SecureStorage
    >>> storage = SecureStorage(Path("/tmp/keystore.enc"), master_key)
    >>> storage.store_key("my_key", key_data)
    >>> retrieved = storage.retrieve_key("my_key")

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import zlib
from base64 import b64decode, b64encode
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional

from src.security.crypto.core.exceptions import (
    CryptoError,
    CryptoKeyError,
    DecryptionFailedError,
    EncryptionFailedError,
    InvalidParameterError,
)

__all__: list[str] = [
    "SecureStorage",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"

logger = logging.getLogger(__name__)

# AES-256-GCM параметры
_KEY_SIZE = 32
_NONCE_SIZE = 12


# ==============================================================================
# SECURE STORAGE
# ==============================================================================


class SecureStorage:
    """
    Зашифрованное хранилище ключей.

    Реализует KeyStoreProtocol. Хранит ключи в JSON, зашифрованном
    AES-256-GCM. Поддерживает сжатие, атомарную запись и метаданные.

    Thread-safe: все операции защищены RLock.

    Example:
        >>> storage = SecureStorage(Path("keystore.enc"), master_key)
        >>> storage.store_key("aes_key", key_bytes)
        >>> storage.list_keys()
        ['aes_key']
    """

    def __init__(
        self,
        path: Path,
        master_key: bytes,
        compress: bool = False,
    ) -> None:
        """
        Открытие или создание зашифрованного хранилища.

        Args:
            path: Путь к файлу хранилища.
            master_key: Мастер-ключ для шифрования (32 байта).
            compress: Использовать zlib-сжатие.

        Raises:
            InvalidParameterError: Если master_key неверного размера.
        """
        if len(master_key) != _KEY_SIZE:
            raise InvalidParameterError(
                parameter_name="master_key",
                reason=f"Ожидается {_KEY_SIZE} байт, получено {len(master_key)}",
            )

        self._path = path
        self._master_key = master_key
        self._compress = compress
        self._lock = RLock()
        self._store: Dict[str, Dict[str, Any]] = {}

        if path.exists():
            self._load_from_disk()

    # --- KeyStoreProtocol ---

    def save(self, name: str, data: bytes) -> None:
        """Persist an item by name (KeyStoreProtocol)."""
        self.store_key(name, data)

    def load(self, name: str) -> bytes:
        """Load an item by name (KeyStoreProtocol)."""
        return self.retrieve_key(name)

    def delete(self, name: str) -> None:
        """Delete an item by name (KeyStoreProtocol)."""
        self.delete_key(name)

    # --- Public API ---

    def store_key(
        self,
        name: str,
        key_data: bytes,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Сохранение ключа в хранилище.

        Args:
            name: Уникальное имя ключа.
            key_data: Данные ключа.
            metadata: Дополнительные метаданные.
        """
        with self._lock:
            self._store[name] = {
                "key": b64encode(key_data).decode("ascii"),
                "metadata": metadata or {},
            }
            self._save_to_disk()
            logger.debug("Key stored: '%s' (%d bytes)", name, len(key_data))

    def retrieve_key(self, name: str) -> bytes:
        """
        Извлечение ключа из хранилища.

        Args:
            name: Имя ключа.

        Returns:
            Данные ключа.

        Raises:
            CryptoKeyError: Если ключ не найден.
        """
        with self._lock:
            entry = self._store.get(name)
            if entry is None:
                raise CryptoKeyError(f"Key not found: '{name}'")
            return b64decode(entry["key"])

    def delete_key(self, name: str) -> None:
        """
        Удаление ключа из хранилища.

        Args:
            name: Имя ключа.

        Raises:
            CryptoKeyError: Если ключ не найден.
        """
        with self._lock:
            if name not in self._store:
                raise CryptoKeyError(f"Key not found: '{name}'")
            del self._store[name]
            self._save_to_disk()
            logger.debug("Key deleted: '%s'", name)

    def list_keys(self) -> List[str]:
        """
        Список имён ключей в хранилище.

        Returns:
            Отсортированный список имён.
        """
        with self._lock:
            return sorted(self._store.keys())

    def has_key(self, name: str) -> bool:
        """
        Проверка наличия ключа.

        Args:
            name: Имя ключа.

        Returns:
            True если ключ существует.
        """
        with self._lock:
            return name in self._store

    def get_metadata(self, name: str) -> Dict[str, Any]:
        """
        Получение метаданных ключа.

        Args:
            name: Имя ключа.

        Returns:
            Словарь метаданных.

        Raises:
            CryptoKeyError: Если ключ не найден.
        """
        with self._lock:
            entry = self._store.get(name)
            if entry is None:
                raise CryptoKeyError(f"Key not found: '{name}'")
            return dict(entry.get("metadata", {}))

    def export_keystore(self) -> bytes:
        """
        Экспорт хранилища для бэкапа.

        Returns:
            Зашифрованные данные хранилища.
        """
        with self._lock:
            if self._path.exists():
                return self._path.read_bytes()
            return b""

    def import_keystore(self, data: bytes) -> None:
        """
        Импорт хранилища из бэкапа.

        Args:
            data: Зашифрованные данные хранилища.

        Raises:
            DecryptionFailedError: Если данные не могут быть расшифрованы.
        """
        with self._lock:
            plaintext = self._decrypt_data(data)
            self._store = json.loads(plaintext.decode("utf-8"))
            self._save_to_disk()
            logger.info("Keystore imported (%d keys)", len(self._store))

    # --- Private ---

    def _encrypt_data(self, plaintext: bytes) -> bytes:
        """Шифрование данных AES-256-GCM."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as e:
            raise CryptoError(
                "cryptography library required for SecureStorage"
            ) from e

        nonce = os.urandom(_NONCE_SIZE)
        cipher = AESGCM(self._master_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def _decrypt_data(self, data: bytes) -> bytes:
        """Расшифровка данных AES-256-GCM."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as e:
            raise CryptoError(
                "cryptography library required for SecureStorage"
            ) from e

        if len(data) < _NONCE_SIZE + 16:
            raise DecryptionFailedError(
                "Data too short for AES-256-GCM"
            )

        nonce = data[:_NONCE_SIZE]
        ciphertext = data[_NONCE_SIZE:]

        try:
            cipher = AESGCM(self._master_key)
            return cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise DecryptionFailedError(
                "Failed to decrypt keystore"
            ) from e

    def _save_to_disk(self) -> None:
        """Атомарная запись хранилища на диск."""
        plaintext = json.dumps(self._store, ensure_ascii=True).encode("utf-8")

        if self._compress:
            plaintext = zlib.compress(plaintext, level=9)

        encrypted = self._encrypt_data(plaintext)

        # Атомарная запись: temp file + rename
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._path.parent),
            prefix=".keystore_",
        )
        try:
            os.write(fd, encrypted)
            os.fsync(fd)
            os.close(fd)
            os.replace(tmp_path, str(self._path))
        except Exception:
            os.close(fd) if not os.get_inheritable(fd) else None
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def _load_from_disk(self) -> None:
        """Загрузка и расшифровка хранилища с диска."""
        data = self._path.read_bytes()
        if not data:
            self._store = {}
            return

        plaintext = self._decrypt_data(data)

        if self._compress:
            try:
                plaintext = zlib.decompress(plaintext)
            except zlib.error:
                pass  # Данные могли быть сохранены без сжатия

        try:
            self._store = json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise CryptoError(
                f"Failed to parse keystore data: {e}"
            ) from e
