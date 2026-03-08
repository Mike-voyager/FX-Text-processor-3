"""
Управление ключами: импорт, экспорт и обёртывание.

Высокоуровневый API для работы с ключами через AlgorithmRegistry
и модуль сериализации. Поддерживает KEK (Key Encryption Key)
обёртывание.

Example:
    >>> from src.security.crypto.utilities.key_management import KeyManager
    >>> from src.security.crypto.core.registry import AlgorithmRegistry
    >>> manager = KeyManager(AlgorithmRegistry.get_instance())
    >>> wrapping_key = manager.generate_wrapping_key()
    >>> wrapped = manager.wrap_key(data_key, wrapping_key, "aes-256-gcm")

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from src.security.crypto.core.exceptions import (
    DecryptionFailedError,
    EncryptionFailedError,
)
from src.security.crypto.utilities.serialization import (
    KeyFormat,
    deserialize_key,
    serialize_key,
)

if TYPE_CHECKING:
    from src.security.crypto.core.registry import AlgorithmRegistry

__all__: list[str] = [
    "KeyManager",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"

logger = logging.getLogger(__name__)

# Размер ключа обёртывания (AES-256)
_WRAPPING_KEY_SIZE = 32


# ==============================================================================
# KEY MANAGER
# ==============================================================================


class KeyManager:
    """
    Управление импортом, экспортом и обёртыванием ключей.

    Делегирует сериализацию в модуль serialization.py,
    а криптографические операции — в AlgorithmRegistry.

    Example:
        >>> manager = KeyManager(registry)
        >>> exported = manager.export_key(key, KeyFormat.PEM, "aes-256-gcm")
        >>> imported = manager.import_key(exported, KeyFormat.PEM, "aes-256-gcm")
    """

    def __init__(self, registry: AlgorithmRegistry) -> None:
        """
        Инициализация менеджера ключей.

        Args:
            registry: Экземпляр AlgorithmRegistry.
        """
        self._registry = registry

    def import_key(
        self,
        data: bytes,
        fmt: KeyFormat,
        algorithm: str,
    ) -> bytes:
        """
        Импорт ключа из указанного формата.

        Args:
            data: Сериализованные данные ключа.
            fmt: Формат данных.
            algorithm: Имя алгоритма.

        Returns:
            Десериализованные данные ключа.

        Raises:
            InvalidParameterError: Если формат некорректен.
        """
        key = deserialize_key(data, fmt, algorithm)
        logger.debug(
            "Key imported: format=%s, algorithm=%s, size=%d",
            fmt.value, algorithm, len(key),
        )
        return key

    def export_key(
        self,
        key: bytes,
        fmt: KeyFormat,
        algorithm: str,
    ) -> bytes:
        """
        Экспорт ключа в указанный формат.

        Args:
            key: Данные ключа.
            fmt: Целевой формат.
            algorithm: Имя алгоритма.

        Returns:
            Сериализованные данные.
        """
        data = serialize_key(key, fmt, algorithm)
        logger.debug(
            "Key exported: format=%s, algorithm=%s, size=%d",
            fmt.value, algorithm, len(data),
        )
        return data

    def wrap_key(
        self,
        key_to_wrap: bytes,
        wrapping_key: bytes,
        algorithm: str = "aes-256-gcm",
    ) -> bytes:
        """
        Обёртывание ключа (KEK) — шифрование одного ключа другим.

        Args:
            key_to_wrap: Ключ для обёртывания.
            wrapping_key: Ключ обёртывания (KEK).
            algorithm: Алгоритм шифрования.

        Returns:
            Обёрнутый ключ (nonce + ciphertext).

        Raises:
            EncryptionFailedError: Если обёртывание не удалось.
        """
        try:
            cipher = self._registry.create(algorithm)
            nonce, ciphertext = cipher.encrypt(wrapping_key, key_to_wrap)
            result: bytes = nonce + ciphertext
            return result
        except Exception as e:
            raise EncryptionFailedError(
                f"Key wrapping failed with {algorithm}: {e}"
            ) from e

    def unwrap_key(
        self,
        wrapped: bytes,
        wrapping_key: bytes,
        algorithm: str = "aes-256-gcm",
    ) -> bytes:
        """
        Развёртывание ключа — расшифровка обёрнутого ключа.

        Args:
            wrapped: Обёрнутый ключ (nonce + ciphertext).
            wrapping_key: Ключ обёртывания (KEK).
            algorithm: Алгоритм шифрования.

        Returns:
            Развёрнутый ключ.

        Raises:
            DecryptionFailedError: Если развёртывание не удалось.
        """
        try:
            cipher = self._registry.create(algorithm)
            nonce_size = cipher.nonce_size
            if len(wrapped) < nonce_size + 16:
                raise DecryptionFailedError(
                    "Wrapped key data too short"
                )
            nonce = wrapped[:nonce_size]
            ciphertext = wrapped[nonce_size:]
            result: bytes = cipher.decrypt(wrapping_key, nonce, ciphertext)
            return result
        except DecryptionFailedError:
            raise
        except Exception as e:
            raise DecryptionFailedError(
                f"Key unwrapping failed with {algorithm}: {e}"
            ) from e

    def generate_wrapping_key(self) -> bytes:
        """
        Генерация нового ключа обёртывания (KEK).

        Returns:
            Случайный 256-битный ключ.
        """
        key = os.urandom(_WRAPPING_KEY_SIZE)
        logger.debug("Generated wrapping key (%d bytes)", _WRAPPING_KEY_SIZE)
        return key
