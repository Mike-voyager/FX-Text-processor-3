"""
Депонирование ключей (Dual Key Escrow) для FX Text Processor 3.

Этот модуль реализует DualKeyEscrow — систему депонирования ключей
с двойным доступом. Зашифрованные данные могут быть расшифрованы
двумя независимыми путями: пользователем и escrow-агентом.

Что такое Key Escrow?
=====================

Key Escrow — криптографический механизм, при котором ключ шифрования
(или его копия) депонируется у доверенной третьей стороны (escrow agent).
Это обеспечивает:

- **Восстановление данных**: Если пользователь потерял ключ
- **Корпоративный аудит**: Организация может расшифровать данные сотрудников
- **Юридическое соответствие**: Compliance требования (GDPR data access)
- **Disaster Recovery**: Резервный доступ к зашифрованным данным

Архитектура:
============

DualKeyEscrow использует два независимых пути расшифровки:

1. **User Path**: Пользователь расшифровывает своим приватным ключом
2. **Escrow Path**: Escrow-агент расшифровывает своим приватным ключом

Оба пути ведут к одним и тем же данным. Data key шифруется
дважды — для user и для escrow — через гибридное шифрование.

Безопасность:
=============

- Data key одноразовый (per-message)
- User и escrow пути полностью независимы
- Компрометация одного ключа не раскрывает другой
- HKDF-SHA256 деривация ключей
- Secure memory erase после использования
- Perfect Forward Secrecy через ephemeral keys

Пример:
=======

>>> from src.security.crypto.advanced.key_escrow import DualKeyEscrow
>>>
>>> escrow = DualKeyEscrow()
>>>
>>> # Генерация ключей
>>> user_priv, user_pub = escrow.generate_keypair()
>>> escrow_priv, escrow_pub = escrow.generate_keypair()
>>>
>>> # Шифрование с депонированием
>>> encrypted = escrow.encrypt(
...     plaintext=b"Sensitive data",
...     user_public_key=user_pub,
...     escrow_public_key=escrow_pub,
... )
>>>
>>> # Расшифровка пользователем
>>> data = escrow.decrypt_as_user(user_priv, encrypted)
>>>
>>> # Расшифровка escrow-агентом
>>> data = escrow.decrypt_as_escrow(escrow_priv, encrypted)

Author: FX Text Processor 3 Team
Version: 2.3.2
Date: February 18, 2026
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Final, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.security.crypto.core.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    InvalidKeyError,
)
from src.security.crypto.core.protocols import (
    KeyExchangeProtocol,
    SymmetricCipherProtocol,
)
from src.security.crypto.core.registry import AlgorithmRegistry

# ==============================================================================
# CONSTANTS
# ==============================================================================

DATA_KEY_SIZE: Final[int] = 32
HKDF_SALT_SIZE: Final[int] = 32
HKDF_INFO_USER: Final[bytes] = b"escrow-user-path-v1"
HKDF_INFO_ESCROW: Final[bytes] = b"escrow-agent-path-v1"

logger = logging.getLogger(__name__)


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class EscrowEncryptedData:
    """
    Результат шифрования с депонированием.

    Attributes:
        ciphertext: Зашифрованные данные (symmetric)
        nonce: Nonce для расшифровки ciphertext
        user_wrapped_key: Обёрнутый data key для пользователя
            {ephemeral_public_key, nonce, ciphertext, hkdf_salt}
        escrow_wrapped_key: Обёрнутый data key для escrow-агента
            {ephemeral_public_key, nonce, ciphertext, hkdf_salt}
    """

    ciphertext: bytes
    nonce: bytes
    user_wrapped_key: Dict[str, bytes]
    escrow_wrapped_key: Dict[str, bytes]


# ==============================================================================
# DUAL KEY ESCROW
# ==============================================================================


class DualKeyEscrow:
    """
    Система депонирования ключей с двойным доступом.

    Обеспечивает два независимых пути расшифровки:
    - User Path: обычный доступ пользователя
    - Escrow Path: резервный доступ escrow-агента

    Features:
        - Два независимых пути расшифровки
        - Одноразовый data key (per-message)
        - Perfect Forward Secrecy
        - HKDF-SHA256 деривация
        - Secure memory erase

    Example:
        >>> escrow = DualKeyEscrow()
        >>> user_priv, user_pub = escrow.generate_keypair()
        >>> agent_priv, agent_pub = escrow.generate_keypair()
        >>> encrypted = escrow.encrypt(b"data", user_pub, agent_pub)
        >>> plaintext = escrow.decrypt_as_user(user_priv, encrypted)
    """

    def __init__(
        self,
        kex_algorithm: str = "x25519",
        symmetric_algorithm: str = "aes-256-gcm",
    ) -> None:
        """
        Инициализировать DualKeyEscrow.

        Args:
            kex_algorithm: Алгоритм обмена ключами (по умолчанию X25519)
            symmetric_algorithm: Алгоритм шифрования (по умолчанию AES-256-GCM)

        Raises:
            CryptoError: Алгоритм недоступен
        """
        self._logger = logging.getLogger(__name__)

        registry = AlgorithmRegistry.get_instance()
        try:
            self._kex: KeyExchangeProtocol = registry.create(kex_algorithm)
            self._cipher: SymmetricCipherProtocol = registry.create(
                symmetric_algorithm
            )
        except (KeyError, RuntimeError) as exc:
            raise CryptoError(
                f"Failed to initialize DualKeyEscrow: {exc}",
                algorithm=kex_algorithm,
            ) from exc

        self._kex_algo = kex_algorithm
        self._sym_algo = symmetric_algorithm

        self._logger.debug(
            f"DualKeyEscrow initialized: KEX={kex_algorithm}, "
            f"Symmetric={symmetric_algorithm}"
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать keypair (для user или escrow agent).

        Returns:
            (private_key, public_key): Пара ключей

        Raises:
            CryptoError: Генерация не удалась
        """
        try:
            return self._kex.generate_keypair()
        except Exception as exc:
            raise CryptoError(
                f"Keypair generation failed: {exc}"
            ) from exc

    def encrypt(
        self,
        plaintext: bytes,
        user_public_key: bytes,
        escrow_public_key: bytes,
        *,
        associated_data: Optional[bytes] = None,
    ) -> EscrowEncryptedData:
        """
        Зашифровать данные с депонированием ключа.

        Process:
            1. Сгенерировать одноразовый data key
            2. Зашифровать plaintext data key
            3. Обернуть data key для пользователя (гибридное шифрование)
            4. Обернуть data key для escrow-агента (гибридное шифрование)

        Args:
            plaintext: Данные для шифрования
            user_public_key: Публичный ключ пользователя
            escrow_public_key: Публичный ключ escrow-агента
            associated_data: Дополнительные данные для AEAD

        Returns:
            EscrowEncryptedData с обёрнутыми ключами для обоих путей

        Raises:
            ValueError: Невалидные входные данные
            EncryptionError: Шифрование не удалось
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")
        if not user_public_key:
            raise ValueError("User public key cannot be empty")
        if not escrow_public_key:
            raise ValueError("Escrow public key cannot be empty")

        data_key = b""
        try:
            # 1. Generate one-time data key
            data_key = secrets.token_bytes(DATA_KEY_SIZE)

            # 2. Encrypt plaintext with data key
            ciphertext, nonce = self._cipher.encrypt(
                key=data_key,
                plaintext=plaintext,
                aad=associated_data,
            )

            # 3. Wrap data key for user
            user_wrapped = self._wrap_key(
                data_key, user_public_key, HKDF_INFO_USER
            )

            # 4. Wrap data key for escrow agent
            escrow_wrapped = self._wrap_key(
                data_key, escrow_public_key, HKDF_INFO_ESCROW
            )

            self._logger.debug(
                f"Encrypted with escrow: plaintext_size={len(plaintext)}"
            )

            return EscrowEncryptedData(
                ciphertext=ciphertext,
                nonce=nonce,
                user_wrapped_key=user_wrapped,
                escrow_wrapped_key=escrow_wrapped,
            )

        except (ValueError, EncryptionError):
            raise
        except Exception as exc:
            raise EncryptionError(
                f"Escrow encryption failed: {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(data_key))

    def decrypt_as_user(
        self,
        user_private_key: bytes,
        encrypted_data: EscrowEncryptedData,
        *,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Расшифровать данные как пользователь (User Path).

        Args:
            user_private_key: Приватный ключ пользователя
            encrypted_data: Зашифрованные данные с депонированием
            associated_data: Дополнительные данные для AEAD

        Returns:
            Расшифрованный plaintext

        Raises:
            ValueError: Невалидный ключ
            InvalidKeyError: Неверный приватный ключ
            DecryptionError: Расшифровка не удалась
        """
        return self._decrypt_path(
            private_key=user_private_key,
            wrapped_key=encrypted_data.user_wrapped_key,
            ciphertext=encrypted_data.ciphertext,
            nonce=encrypted_data.nonce,
            hkdf_info=HKDF_INFO_USER,
            path_name="user",
            aad=associated_data,
        )

    def decrypt_as_escrow(
        self,
        escrow_private_key: bytes,
        encrypted_data: EscrowEncryptedData,
        *,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Расшифровать данные как escrow-агент (Escrow Path).

        Args:
            escrow_private_key: Приватный ключ escrow-агента
            encrypted_data: Зашифрованные данные с депонированием
            associated_data: Дополнительные данные для AEAD

        Returns:
            Расшифрованный plaintext

        Raises:
            ValueError: Невалидный ключ
            InvalidKeyError: Неверный приватный ключ
            DecryptionError: Расшифровка не удалась
        """
        return self._decrypt_path(
            private_key=escrow_private_key,
            wrapped_key=encrypted_data.escrow_wrapped_key,
            ciphertext=encrypted_data.ciphertext,
            nonce=encrypted_data.nonce,
            hkdf_info=HKDF_INFO_ESCROW,
            path_name="escrow",
            aad=associated_data,
        )

    # ==========================================================================
    # PRIVATE METHODS
    # ==========================================================================

    def _decrypt_path(
        self,
        private_key: bytes,
        wrapped_key: Dict[str, bytes],
        ciphertext: bytes,
        nonce: bytes,
        hkdf_info: bytes,
        path_name: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Общая логика расшифровки для user и escrow путей.

        Args:
            private_key: Приватный ключ (user или escrow)
            wrapped_key: Обёрнутый data key
            ciphertext: Зашифрованный plaintext
            nonce: Nonce
            hkdf_info: HKDF info для деривации
            path_name: Название пути (для логов)
            associated_data: Дополнительные данные для AEAD
        """
        if not private_key:
            raise ValueError(f"{path_name.capitalize()} private key cannot be empty")

        data_key = b""
        try:
            # 1. Unwrap data key
            data_key = self._unwrap_key(private_key, wrapped_key, hkdf_info)

            # 2. Decrypt ciphertext
            plaintext = self._cipher.decrypt(
                key=data_key,
                ciphertext=ciphertext,
                nonce=nonce,
                aad=associated_data,
            )

            self._logger.debug(
                f"Decrypted via {path_name} path: "
                f"plaintext_size={len(plaintext)}"
            )

            return plaintext

        except (ValueError, InvalidKeyError, DecryptionError):
            raise
        except Exception as exc:
            raise DecryptionError(
                f"Escrow decryption failed ({path_name} path): {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(data_key))

    def _wrap_key(
        self, data_key: bytes, recipient_public_key: bytes, hkdf_info: bytes
    ) -> Dict[str, bytes]:
        """
        Обернуть data key для получателя через гибридное шифрование.

        Args:
            data_key: Ключ данных для обёртывания
            recipient_public_key: Публичный ключ получателя
            hkdf_info: HKDF info строка

        Returns:
            {ephemeral_public_key, nonce, ciphertext, hkdf_salt}
        """
        ephemeral_private = b""
        shared_secret = b""
        wrapping_key = b""

        try:
            ephemeral_private, ephemeral_public = self._kex.generate_keypair()

            shared_secret = self._kex.derive_shared_secret(
                private_key=ephemeral_private,
                peer_public_key=recipient_public_key,
            )

            hkdf_salt = secrets.token_bytes(HKDF_SALT_SIZE)
            wrapping_key = self._derive_key(shared_secret, hkdf_salt, hkdf_info)

            ciphertext, nonce = self._cipher.encrypt(
                key=wrapping_key,
                plaintext=data_key,
            )

            return {
                "ephemeral_public_key": ephemeral_public,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "hkdf_salt": hkdf_salt,
            }

        finally:
            self._secure_erase(bytearray(ephemeral_private))
            self._secure_erase(bytearray(shared_secret))
            self._secure_erase(bytearray(wrapping_key))

    def _unwrap_key(
        self,
        private_key: bytes,
        wrapped: Dict[str, bytes],
        hkdf_info: bytes,
    ) -> bytes:
        """
        Развернуть data key из обёрнутого ключа.

        Args:
            private_key: Приватный ключ получателя
            wrapped: Обёрнутый ключ
            hkdf_info: HKDF info строка

        Returns:
            Развёрнутый data key
        """
        shared_secret = b""
        wrapping_key = b""

        try:
            shared_secret = self._kex.derive_shared_secret(
                private_key=private_key,
                peer_public_key=wrapped["ephemeral_public_key"],
            )

            hkdf_salt = wrapped.get("hkdf_salt", b"")
            wrapping_key = self._derive_key(shared_secret, hkdf_salt, hkdf_info)

            data_key = self._cipher.decrypt(
                key=wrapping_key,
                ciphertext=wrapped["ciphertext"],
                nonce=wrapped["nonce"],
            )

            return data_key

        finally:
            self._secure_erase(bytearray(shared_secret))
            self._secure_erase(bytearray(wrapping_key))

    def _derive_key(
        self, shared_secret: bytes, salt: bytes, info: bytes
    ) -> bytes:
        """Вывести wrapping key через HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=DATA_KEY_SIZE,
            salt=salt if salt else None,
            info=info,
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def _secure_erase(data: bytearray) -> None:
        """Безопасно стереть чувствительные данные из памяти."""
        if not data:
            return
        for i in range(len(data)):
            data[i] = secrets.randbits(8)
        for i in range(len(data)):
            data[i] = 0


# ==============================================================================
# EXPORTS
# ==============================================================================

__all__ = [
    "DualKeyEscrow",
    "EscrowEncryptedData",
]
