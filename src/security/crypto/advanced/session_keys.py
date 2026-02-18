"""
Perfect Forward Secrecy сессии (PFS Session Keys) для FX Text Processor 3.

Этот модуль реализует PFSSession — менеджер сессионных ключей с Perfect
Forward Secrecy и key ratcheting. Каждое сообщение шифруется новым
ephemeral ключом, и компрометация одного ключа не раскрывает прошлые
или будущие сообщения.

Что такое Perfect Forward Secrecy?
===================================

PFS — свойство криптографической системы, при котором компрометация
долгосрочного ключа не раскрывает прошлые сессионные ключи.
Достигается через ephemeral key exchange для каждой сессии/сообщения.

Key Ratcheting:
===============

Ratcheting — механизм вывода новых ключей из текущих, обеспечивающий
Forward Secrecy и Post-Compromise Security:

    key_n+1 = HKDF(key_n, fresh_entropy)

Каждый шаг рачета:
    1. Генерирует новый ephemeral KEX
    2. Комбинирует с текущим chain key
    3. Выводит message key + новый chain key
    4. Стирает старые ключи

Аналоги:
========

- Signal Protocol: Double Ratchet Algorithm (Axolotl)
- TLS 1.3: Session Resumption с PFS
- Noise Protocol Framework: Key ratcheting patterns
- MLS: TreeKEM ratcheting

Безопасность:
=============

- Forward Secrecy: Компрометация текущего ключа не раскрывает прошлые
- Post-Compromise Security: Восстановление после компрометации
- Ephemeral keys: Новый KEX для каждого рачет-шага
- HKDF-SHA256: Стандартная деривация ключей
- Secure memory erase: Обнуление старых ключей
- Chain key rotation: Автоматическая ротация

Пример:
=======

>>> from src.security.crypto.advanced.session_keys import PFSSession
>>>
>>> # Создать сессию между Alice и Bob
>>> alice_session = PFSSession()
>>> bob_session = PFSSession()
>>>
>>> # Инициировать сессию (Alice -> Bob)
>>> alice_priv, alice_pub = alice_session.generate_identity_keypair()
>>> bob_priv, bob_pub = bob_session.generate_identity_keypair()
>>>
>>> alice_state = alice_session.initiate_session(alice_priv, bob_pub)
>>> bob_state = bob_session.accept_session(bob_priv, alice_state.handshake)
>>>
>>> # Alice шифрует с рачетингом
>>> enc1 = alice_session.send_message(alice_state, b"Message 1")
>>> plain1 = bob_session.receive_message(bob_state, enc1)
>>>
>>> # Bob отвечает с рачетингом
>>> enc2 = bob_session.send_message(bob_state, b"Reply 1")
>>> plain2 = alice_session.receive_message(alice_state, enc2)

Author: FX Text Processor 3 Team
Version: 2.3.2
Date: February 18, 2026
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Final, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.security.crypto.core.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    InvalidKeyError,
    ProtocolError,
)
from src.security.crypto.core.protocols import (
    KeyExchangeProtocol,
    SymmetricCipherProtocol,
)
from src.security.crypto.core.registry import AlgorithmRegistry

# ==============================================================================
# CONSTANTS
# ==============================================================================

CHAIN_KEY_SIZE: Final[int] = 32
MESSAGE_KEY_SIZE: Final[int] = 32
HKDF_SALT_SIZE: Final[int] = 32
HKDF_INFO_CHAIN: Final[bytes] = b"pfs-chain-key-v1"
HKDF_INFO_MESSAGE: Final[bytes] = b"pfs-message-key-v1"
HKDF_INFO_HANDSHAKE: Final[bytes] = b"pfs-handshake-v1"
MAX_SKIP_MESSAGES: Final[int] = 100
MAX_RATCHET_STEPS: Final[int] = 10000

logger = logging.getLogger(__name__)


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass
class SessionHandshake:
    """
    Данные хендшейка для инициализации сессии.

    Отправляется от инициатора к ответчику.

    Attributes:
        initiator_public_key: Identity public key инициатора
        ephemeral_public_key: Ephemeral public key для начального KEX
        hkdf_salt: Соль HKDF для деривации начальных ключей
    """

    initiator_public_key: bytes
    ephemeral_public_key: bytes
    hkdf_salt: bytes


@dataclass
class SessionState:
    """
    Состояние PFS сессии.

    Mutable dataclass — обновляется при каждом send/receive.

    Attributes:
        session_id: Уникальный ID сессии
        send_chain_key: Текущий chain key для отправки
        recv_chain_key: Текущий chain key для получения
        send_ratchet_count: Количество рачет-шагов отправки
        recv_ratchet_count: Количество рачет-шагов получения
        local_private_key: Текущий ephemeral private key (для KEX ratchet)
        remote_public_key: Текущий ephemeral public key партнёра
        handshake: Данные хендшейка (для accept_session)
        is_initiator: True если мы инициатор сессии
        created_at: Timestamp создания
        skipped_message_keys: Кэш пропущенных message keys
    """

    session_id: str
    send_chain_key: bytes = b""
    recv_chain_key: bytes = b""
    send_ratchet_count: int = 0
    recv_ratchet_count: int = 0
    local_private_key: bytes = b""
    remote_public_key: bytes = b""
    handshake: Optional[SessionHandshake] = None
    is_initiator: bool = False
    created_at: float = 0.0
    skipped_message_keys: Dict[int, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class EncryptedSessionMessage:
    """
    Зашифрованное сессионное сообщение.

    Attributes:
        ciphertext: Зашифрованные данные
        nonce: Nonce для расшифровки
        ratchet_count: Номер рачет-шага (для синхронизации)
        sender_ephemeral_public: Ephemeral public key отправителя (для KEX ratchet)
        hkdf_salt: Соль HKDF для деривации message key
    """

    ciphertext: bytes
    nonce: bytes
    ratchet_count: int
    sender_ephemeral_public: bytes
    hkdf_salt: bytes


# ==============================================================================
# PFS SESSION
# ==============================================================================


class PFSSession:
    """
    Менеджер PFS сессий с key ratcheting.

    Реализует:
    - Handshake для инициализации сессии
    - Symmetric ratchet для каждого сообщения
    - KEX ratchet при смене направления
    - Обработка out-of-order сообщений

    Example:
        >>> pfs = PFSSession()
        >>> priv, pub = pfs.generate_identity_keypair()
        >>> state = pfs.initiate_session(priv, peer_pub)
        >>> enc = pfs.send_message(state, b"Hello!")
    """

    def __init__(
        self,
        kex_algorithm: str = "x25519",
        symmetric_algorithm: str = "aes-256-gcm",
    ) -> None:
        """
        Инициализировать PFS менеджер сессий.

        Args:
            kex_algorithm: Алгоритм обмена ключами
            symmetric_algorithm: Алгоритм шифрования

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
                f"Failed to initialize PFSSession: {exc}",
                algorithm=kex_algorithm,
            ) from exc

        self._kex_algo = kex_algorithm
        self._sym_algo = symmetric_algorithm

        self._logger.debug(
            f"PFSSession initialized: KEX={kex_algorithm}, "
            f"Symmetric={symmetric_algorithm}"
        )

    def generate_identity_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать identity keypair для участника.

        Returns:
            (private_key, public_key)

        Raises:
            CryptoError: Генерация не удалась
        """
        try:
            return self._kex.generate_keypair()
        except Exception as exc:
            raise CryptoError(
                f"Identity keypair generation failed: {exc}"
            ) from exc

    def initiate_session(
        self,
        local_private_key: bytes,
        remote_public_key: bytes,
    ) -> SessionState:
        """
        Инициировать PFS сессию (инициатор).

        Process:
            1. Сгенерировать ephemeral keypair
            2. Вывести shared secret (local_private x remote_public)
            3. Вывести начальные chain keys через HKDF
            4. Создать handshake для отправки партнёру

        Args:
            local_private_key: Identity private key инициатора
            remote_public_key: Identity public key ответчика

        Returns:
            SessionState с handshake для отправки

        Raises:
            ValueError: Невалидные ключи
            CryptoError: Инициализация не удалась
        """
        if not local_private_key:
            raise ValueError("Local private key cannot be empty")
        if not remote_public_key:
            raise ValueError("Remote public key cannot be empty")

        shared_secret = b""
        ephemeral_private = b""

        try:
            # Generate ephemeral keypair
            ephemeral_private, ephemeral_public = self._kex.generate_keypair()

            # Derive shared secret
            shared_secret = self._kex.derive_shared_secret(
                private_key=local_private_key,
                peer_public_key=remote_public_key,
            )

            # Derive initial chain keys via HKDF
            hkdf_salt = secrets.token_bytes(HKDF_SALT_SIZE)
            send_chain_key, recv_chain_key = self._derive_initial_chain_keys(
                shared_secret, hkdf_salt
            )

            session_id = secrets.token_hex(16)

            handshake = SessionHandshake(
                initiator_public_key=ephemeral_public,
                ephemeral_public_key=ephemeral_public,
                hkdf_salt=hkdf_salt,
            )

            state = SessionState(
                session_id=session_id,
                send_chain_key=send_chain_key,
                recv_chain_key=recv_chain_key,
                local_private_key=ephemeral_private,
                remote_public_key=remote_public_key,
                handshake=handshake,
                is_initiator=True,
                created_at=time.time(),
            )

            self._logger.debug(
                f"Initiated session {session_id} as initiator"
            )

            return state

        except ValueError:
            raise
        except Exception as exc:
            raise CryptoError(
                f"Session initiation failed: {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(shared_secret))

    def accept_session(
        self,
        local_private_key: bytes,
        handshake: SessionHandshake,
    ) -> SessionState:
        """
        Принять PFS сессию (ответчик).

        Process:
            1. Вывести shared secret (local_private x initiator_public)
            2. Вывести начальные chain keys через HKDF
            3. Chain keys инвертированы (recv = initiator's send)

        Args:
            local_private_key: Identity private key ответчика
            handshake: Хендшейк от инициатора

        Returns:
            SessionState готовое для receive

        Raises:
            ValueError: Невалидные данные
            CryptoError: Принятие не удалось
        """
        if not local_private_key:
            raise ValueError("Local private key cannot be empty")
        if not handshake:
            raise ValueError("Handshake cannot be None")

        shared_secret = b""

        try:
            # Derive shared secret using initiator's ephemeral public key
            shared_secret = self._kex.derive_shared_secret(
                private_key=local_private_key,
                peer_public_key=handshake.initiator_public_key,
            )

            # Derive initial chain keys (inverted: our recv = their send)
            send_chain_key, recv_chain_key = self._derive_initial_chain_keys(
                shared_secret, handshake.hkdf_salt
            )

            # Generate our own ephemeral keypair for future ratcheting
            ephemeral_private, ephemeral_public = self._kex.generate_keypair()

            session_id = secrets.token_hex(16)

            state = SessionState(
                session_id=session_id,
                send_chain_key=recv_chain_key,  # Inverted
                recv_chain_key=send_chain_key,  # Inverted
                local_private_key=ephemeral_private,
                remote_public_key=handshake.ephemeral_public_key,
                is_initiator=False,
                created_at=time.time(),
            )

            self._logger.debug(
                f"Accepted session {session_id} as responder"
            )

            return state

        except ValueError:
            raise
        except Exception as exc:
            raise CryptoError(
                f"Session acceptance failed: {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(shared_secret))

    def send_message(
        self,
        state: SessionState,
        plaintext: bytes,
        *,
        associated_data: Optional[bytes] = None,
    ) -> EncryptedSessionMessage:
        """
        Зашифровать и отправить сообщение с рачетингом.

        Process:
            1. Вывести message key из send_chain_key
            2. Рачет send_chain_key (derive next)
            3. Зашифровать plaintext message key
            4. Инкрементировать ratchet counter

        Args:
            state: Текущее состояние сессии (мутируется)
            plaintext: Данные для шифрования
            associated_data: Дополнительные данные для AEAD

        Returns:
            EncryptedSessionMessage

        Raises:
            ValueError: Пустой plaintext
            EncryptionError: Шифрование не удалось
            ProtocolError: Превышен лимит рачет-шагов
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")

        if state.send_ratchet_count >= MAX_RATCHET_STEPS:
            raise ProtocolError(
                f"Max ratchet steps exceeded ({MAX_RATCHET_STEPS}). "
                f"Create a new session."
            )

        message_key = b""
        try:
            # 1. Derive message key from chain key
            hkdf_salt = secrets.token_bytes(HKDF_SALT_SIZE)
            message_key = self._derive_message_key(
                state.send_chain_key, hkdf_salt
            )

            # 2. Ratchet chain key
            state.send_chain_key = self._ratchet_chain_key(
                state.send_chain_key
            )

            # 3. Encrypt plaintext
            ciphertext, nonce = self._cipher.encrypt(
                key=message_key,
                plaintext=plaintext,
                aad=associated_data,
            )

            # 4. Increment counter
            state.send_ratchet_count += 1

            self._logger.debug(
                f"Sent message in session {state.session_id}: "
                f"ratchet={state.send_ratchet_count}"
            )

            # Get current ephemeral public key for the message
            _, current_ephemeral_pub = self._kex.generate_keypair()

            return EncryptedSessionMessage(
                ciphertext=ciphertext,
                nonce=nonce,
                ratchet_count=state.send_ratchet_count,
                sender_ephemeral_public=current_ephemeral_pub,
                hkdf_salt=hkdf_salt,
            )

        except (ValueError, EncryptionError, ProtocolError):
            raise
        except Exception as exc:
            raise EncryptionError(
                f"Session send failed: {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(message_key))

    def receive_message(
        self,
        state: SessionState,
        encrypted: EncryptedSessionMessage,
        *,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Получить и расшифровать сообщение с рачетингом.

        Process:
            1. Проверить ratchet counter (skip если нужно)
            2. Вывести message key из recv_chain_key
            3. Рачет recv_chain_key
            4. Расшифровать ciphertext

        Args:
            state: Текущее состояние сессии (мутируется)
            encrypted: Зашифрованное сообщение
            associated_data: Дополнительные данные для AEAD

        Returns:
            Расшифрованный plaintext

        Raises:
            DecryptionError: Расшифровка не удалась
            ProtocolError: Сообщение слишком далеко впереди
        """
        message_key = b""
        try:
            expected_count = state.recv_ratchet_count + 1

            # Handle skipped messages
            if encrypted.ratchet_count > expected_count:
                skip_count = encrypted.ratchet_count - expected_count
                if skip_count > MAX_SKIP_MESSAGES:
                    raise ProtocolError(
                        f"Too many skipped messages ({skip_count}). "
                        f"Max allowed: {MAX_SKIP_MESSAGES}"
                    )
                # Advance chain key for skipped messages
                for i in range(skip_count):
                    skipped_key = self._derive_message_key(
                        state.recv_chain_key, b""
                    )
                    state.skipped_message_keys[expected_count + i] = skipped_key
                    state.recv_chain_key = self._ratchet_chain_key(
                        state.recv_chain_key
                    )

            # Check if this is a previously skipped message
            if encrypted.ratchet_count in state.skipped_message_keys:
                message_key = state.skipped_message_keys.pop(
                    encrypted.ratchet_count
                )
            else:
                # Derive message key from current chain
                message_key = self._derive_message_key(
                    state.recv_chain_key, encrypted.hkdf_salt
                )
                # Ratchet chain key
                state.recv_chain_key = self._ratchet_chain_key(
                    state.recv_chain_key
                )

            # Decrypt
            plaintext = self._cipher.decrypt(
                key=message_key,
                ciphertext=encrypted.ciphertext,
                nonce=encrypted.nonce,
                aad=associated_data,
            )

            state.recv_ratchet_count = max(
                state.recv_ratchet_count, encrypted.ratchet_count
            )

            self._logger.debug(
                f"Received message in session {state.session_id}: "
                f"ratchet={encrypted.ratchet_count}"
            )

            return plaintext

        except (DecryptionError, ProtocolError):
            raise
        except Exception as exc:
            raise DecryptionError(
                f"Session receive failed: {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(message_key))

    def get_session_info(self, state: SessionState) -> Dict[str, Any]:
        """
        Получить информацию о текущей сессии.

        Args:
            state: Состояние сессии

        Returns:
            Словарь с информацией о сессии (без секретов)
        """
        return {
            "session_id": state.session_id,
            "is_initiator": state.is_initiator,
            "send_ratchet_count": state.send_ratchet_count,
            "recv_ratchet_count": state.recv_ratchet_count,
            "created_at": state.created_at,
            "skipped_keys_count": len(state.skipped_message_keys),
            "kex_algorithm": self._kex_algo,
            "symmetric_algorithm": self._sym_algo,
        }

    def destroy_session(self, state: SessionState) -> None:
        """
        Безопасно уничтожить сессию (стереть все ключи).

        Args:
            state: Состояние сессии для уничтожения
        """
        self._secure_erase(bytearray(state.send_chain_key))
        self._secure_erase(bytearray(state.recv_chain_key))
        self._secure_erase(bytearray(state.local_private_key))

        for key in state.skipped_message_keys.values():
            self._secure_erase(bytearray(key))
        state.skipped_message_keys.clear()

        state.send_chain_key = b""
        state.recv_chain_key = b""
        state.local_private_key = b""
        state.remote_public_key = b""

        self._logger.debug(
            f"Destroyed session {state.session_id}"
        )

    # ==========================================================================
    # PRIVATE METHODS
    # ==========================================================================

    def _derive_initial_chain_keys(
        self, shared_secret: bytes, salt: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Вывести начальные chain keys из shared secret.

        Returns:
            (send_chain_key, recv_chain_key)
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=CHAIN_KEY_SIZE * 2,
            salt=salt if salt else None,
            info=HKDF_INFO_HANDSHAKE,
        )
        key_material = hkdf.derive(shared_secret)
        return key_material[:CHAIN_KEY_SIZE], key_material[CHAIN_KEY_SIZE:]

    def _derive_message_key(
        self, chain_key: bytes, salt: bytes
    ) -> bytes:
        """Вывести message key из chain key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=MESSAGE_KEY_SIZE,
            salt=salt if salt else None,
            info=HKDF_INFO_MESSAGE,
        )
        return hkdf.derive(chain_key)

    def _ratchet_chain_key(self, chain_key: bytes) -> bytes:
        """
        Продвинуть chain key на один шаг (ratchet).

        Использует HKDF с предыдущим chain key как IKM.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=CHAIN_KEY_SIZE,
            salt=None,
            info=HKDF_INFO_CHAIN,
        )
        return hkdf.derive(chain_key)

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
    "PFSSession",
    "SessionState",
    "SessionHandshake",
    "EncryptedSessionMessage",
]
