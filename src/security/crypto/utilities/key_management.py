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
    >>> unwrapped = manager.unwrap_key(wrapped, wrapping_key, "aes-256-gcm")
    >>> unwrapped == data_key
    True

Version: 1.1
Date: March 9, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from src.security.crypto.core.exceptions import (
    AlgorithmNotSupportedError,
    DecryptionFailedError,
    EncryptionFailedError,
    InvalidParameterError,
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

__version__ = "1.1.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-09"

logger = logging.getLogger(__name__)

_WRAPPING_KEY_SIZE: int = 32

_DEFAULT_WRAP_ALGORITHM: str = "aes-256-gcm"

_AEAD_TAG_SIZE: int = 16


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
        >>> imported == key
        True
    """

    def __init__(self, registry: AlgorithmRegistry) -> None:
        """
        Инициализация менеджера ключей.

        Args:
            registry: Экземпляр AlgorithmRegistry.
        """
        self._registry = registry
        logger.debug(
            "KeyManager initialised with registry: %s",
            type(registry).__name__,
        )

    # --------------------------------------------------------------------------
    # IMPORT / EXPORT
    # --------------------------------------------------------------------------

    def import_key(
        self,
        data: bytes,
        fmt: KeyFormat,
        algorithm: str,
    ) -> bytes:
        """
        Импорт ключа из указанного формата.

        Args:
            data: Сериализованные данные ключа (непустые).
            fmt: Формат данных.
            algorithm: Имя алгоритма.

        Returns:
            Десериализованные данные ключа.

        Raises:
            InvalidParameterError: Если data пуста или формат некорректен.
        """
        if not data:
            raise InvalidParameterError(
                parameter_name="data",
                reason="import_key: данные не могут быть пустыми",
            )

        key = deserialize_key(data, fmt, algorithm)
        logger.debug(
            "Key imported: format=%s, algorithm=%s, size=%d",
            fmt.value,
            algorithm,
            len(key),
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
            key: Данные ключа (непустые).
            fmt: Целевой формат.
            algorithm: Имя алгоритма.

        Returns:
            Сериализованные данные.

        Raises:
            InvalidParameterError: Если key пуст или формат не поддерживается.
        """
        if not key:
            raise InvalidParameterError(
                parameter_name="key",
                reason="export_key: ключ не может быть пустым",
            )

        data = serialize_key(key, fmt, algorithm)
        logger.debug(
            "Key exported: format=%s, algorithm=%s, size=%d",
            fmt.value,
            algorithm,
            len(data),
        )
        return data

    # --------------------------------------------------------------------------
    # WRAP / UNWRAP  (KEK — Key Encryption Key)
    # --------------------------------------------------------------------------

    def wrap_key(
        self,
        key_to_wrap: bytes,
        wrapping_key: bytes,
        algorithm: str = _DEFAULT_WRAP_ALGORITHM,
    ) -> bytes:
        """
        Обёртывание ключа (KEK) — шифрование одного ключа другим.

        Формат результата: nonce || ciphertext (ciphertext включает AEAD-тег).
        Nonce генерируется автоматически внутри cipher.encrypt().

        Args:
            key_to_wrap: Ключ для обёртывания (непустой).
            wrapping_key: Ключ обёртывания (KEK).
                          Для "aes-256-gcm" должен быть ровно 32 байта.
            algorithm: Алгоритм шифрования (по умолчанию "aes-256-gcm").

        Returns:
            Обёрнутый ключ в формате nonce || ciphertext.

        Raises:
            EncryptionFailedError: Если обёртывание не удалось.
            InvalidParameterError: Если key_to_wrap пуст.
            AlgorithmNotSupportedError: Если алгоритм не зарегистрирован.
        """
        if not key_to_wrap:
            raise EncryptionFailedError("wrap_key: key_to_wrap не может быть пустым")
        if len(wrapping_key) != _WRAPPING_KEY_SIZE:
            raise EncryptionFailedError(
                f"wrap_key: wrapping_key должен быть {_WRAPPING_KEY_SIZE} байт "
                f"(AES-256), получено {len(wrapping_key)}"
            )

        try:
            cipher = self._registry.create(algorithm)
            nonce, ciphertext = cipher.encrypt(wrapping_key, key_to_wrap)
            result: bytes = nonce + ciphertext
            logger.info(
                "Key wrapped: algorithm=%s, wrapped_size=%d",
                algorithm,
                len(result),
            )
            return result
        except (EncryptionFailedError, AlgorithmNotSupportedError):
            raise
        except Exception as exc:
            raise EncryptionFailedError(
                f"wrap_key: обёртывание не удалось [{algorithm}]: {exc}"
            ) from exc

    def unwrap_key(
        self,
        wrapped: bytes,
        wrapping_key: bytes,
        algorithm: str = _DEFAULT_WRAP_ALGORITHM,
    ) -> bytes:
        """
        Развёртывание ключа — расшифровка обёрнутого ключа.

        Ожидает входные данные в формате nonce || ciphertext,
        где ciphertext включает AEAD-тег (минимальная длина:
        nonce_size + _AEAD_TAG_SIZE байт).

        Args:
            wrapped: Обёрнутый ключ в формате nonce || ciphertext.
            wrapping_key: Ключ обёртывания (KEK).
                          Для "aes-256-gcm" должен быть ровно 32 байта.
            algorithm: Алгоритм шифрования (по умолчанию "aes-256-gcm").

        Returns:
            Развёрнутый (исходный) ключ.

        Raises:
            DecryptionFailedError: Если данные повреждены, слишком короткие
                                   или wrapping_key неверный.
            AlgorithmNotSupportedError: Если алгоритм не зарегистрирован.
        """
        if not wrapped:
            raise DecryptionFailedError("unwrap_key: wrapped не может быть пустым")
        if len(wrapping_key) != _WRAPPING_KEY_SIZE:
            raise DecryptionFailedError(
                f"unwrap_key: wrapping_key должен быть {_WRAPPING_KEY_SIZE} байт "
                f"(AES-256), получено {len(wrapping_key)}"
            )

        try:
            cipher = self._registry.create(algorithm)
            nonce_size: int = cipher.nonce_size

            min_size: int = nonce_size + _AEAD_TAG_SIZE
            if len(wrapped) < min_size:
                raise DecryptionFailedError(
                    f"unwrap_key: данные слишком короткие — "
                    f"ожидалось ≥ {min_size} байт "
                    f"(nonce={nonce_size} + tag={_AEAD_TAG_SIZE}), "
                    f"получено {len(wrapped)}"
                )

            nonce = wrapped[:nonce_size]
            ciphertext = wrapped[nonce_size:]

            result: bytes = cipher.decrypt(wrapping_key, nonce, ciphertext)
            logger.info(
                "Key unwrapped: algorithm=%s, key_size=%d",
                algorithm,
                len(result),
            )
            return result
        except (DecryptionFailedError, AlgorithmNotSupportedError):
            raise
        except Exception as exc:
            raise DecryptionFailedError(
                f"unwrap_key: развёртывание не удалось [{algorithm}]: {exc}"
            ) from exc

    # --------------------------------------------------------------------------
    # KEY GENERATION
    # --------------------------------------------------------------------------

    def generate_wrapping_key(self) -> bytes:
        """
        Генерация нового ключа обёртывания (KEK).

        Использует os.urandom() — системный CSPRNG.

        Returns:
            Случайный 256-битный ключ (32 байта), совместимый
            с алгоритмом _DEFAULT_WRAP_ALGORITHM ("aes-256-gcm").
        """
        key = os.urandom(_WRAPPING_KEY_SIZE)
        logger.info(
            "Wrapping key generated (%d bytes, algorithm=%s)",
            _WRAPPING_KEY_SIZE,
            _DEFAULT_WRAP_ALGORITHM,
        )
        return key
