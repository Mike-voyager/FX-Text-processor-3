"""
Perfect Forward Secrecy сессии (PFS Session Keys) для FX Text Processor 3.

Этот модуль реализует PFSSession — менеджер сессионных ключей с Perfect
Forward Secrecy и полноценным Double Ratchet (Symmetric + DH Ratchet).
Каждое сообщение шифруется новым ephemeral ключом, и компрометация одного
ключа не раскрывает прошлые или будущие сообщения.

Что такое Perfect Forward Secrecy?
===================================

PFS — свойство криптографической системы, при котором компрометация
долгосрочного ключа не раскрывает прошлые сессионные ключи.
Достигается через ephemeral key exchange для каждой сессии/сообщения.

Double Ratchet:
===============

Комбинация двух механизмов рачетинга:

1. Symmetric Ratchet (Chain Key Ratchet):
    - Детерминированная цепочка ключей: key_n+1 = KDF(key_n)
    - Обеспечивает Forward Secrecy внутри одного DH-обмена
    - Выполняется при каждом send/receive

2. DH Ratchet (Ephemeral Key Ratchet):
    - Новый DH-обмен при смене направления коммуникации
    - Обеспечивает Post-Compromise Security
    - Восстановление безопасности после компрометации chain key
    - Выполняется когда сторона получает новый ephemeral public key

Процесс:
    Alice → Bob: message_1 (DH_alice_1 × DH_bob_0)
    Bob → Alice: message_2 (DH_bob_1 × DH_alice_1) [DH ratchet step]
    Alice → Bob: message_3 (DH_alice_2 × DH_bob_1) [DH ratchet step]

Аналоги:
========

- Signal Protocol: Double Ratchet Algorithm (Axolotl)
- TLS 1.3: Session Resumption с PFS
- Noise Protocol Framework: Key ratcheting patterns
- MLS: TreeKEM ratcheting

Безопасность:
=============

- Forward Secrecy: Компрометация текущего ключа не раскрывает прошлые
- Post-Compromise Security: Восстановление после компрометации через DH ratchet
- Ephemeral keys: Новый DH keypair при каждом DH ratchet step
- HKDF-SHA256: Стандартная деривация ключей
- Secure memory erase: Обнуление bytearray старых ключей
- Chain key rotation: Автоматическая ротация при каждом сообщении

Пример:
=======

>>> from src.security.crypto.advanced.session_keys import PFSSession
>>>
>>> # Создать сессию между Alice и Bob
>>> alice_session = PFSSession()
>>> bob_session = PFSSession()
>>>
>>> # Генерация identity keypair для обеих сторон
>>> alice_priv, alice_pub = alice_session.generate_identity_keypair()
>>> bob_priv, bob_pub = bob_session.generate_identity_keypair()
>>>
>>> # Alice инициирует сессию
>>> alice_state, alice_handshake = alice_session.initiate_session(
...     alice_priv, alice_pub, bob_pub
... )
>>>
>>> # Bob принимает сессию и отвечает хендшейком
>>> bob_state, bob_response = bob_session.accept_session(
...     bob_priv, bob_pub, alice_handshake
... )
>>>
>>> # Alice завершает handshake
>>> alice_session.complete_handshake(alice_state, bob_response)
>>>
>>> # Теперь Alice и Bob могут обмениваться сообщениями
>>> enc1 = alice_session.send_message(alice_state, b"Message 1")
>>> plain1 = bob_session.receive_message(bob_state, enc1)
>>>
>>> # Bob отвечает (DH ratchet step)
>>> enc2 = bob_session.send_message(bob_state, b"Reply 1")
>>> plain2 = alice_session.receive_message(alice_state, enc2)

Author: Mike Voyager
Version: 2.4.0
Date: March 2, 2026
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.security.crypto.core.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
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
HKDF_INFO_CHAIN: Final[bytes] = b"pfs-chain-key-v2"
HKDF_INFO_MESSAGE: Final[bytes] = b"pfs-message-key-v2"
HKDF_INFO_HANDSHAKE: Final[bytes] = b"pfs-handshake-v2"
HKDF_INFO_DH_RATCHET: Final[bytes] = b"pfs-dh-ratchet-v2"
MAX_SKIP_MESSAGES: Final[int] = 100
MAX_RATCHET_STEPS: Final[int] = 10000
MAX_SKIPPED_CACHE_SIZE: Final[int] = 1000

logger = logging.getLogger(__name__)


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass
class SessionHandshake:
    """
    Данные хендшейка для инициализации сессии (от инициатора).

    Отправляется от Alice к Bob для начала сессии.

    Attributes:
        session_id: Уникальный ID сессии (генерируется инициатором)
        initiator_identity_public: Identity public key инициатора
        initiator_ephemeral_public: Ephemeral public key инициатора для DH
        hkdf_salt: Соль HKDF для деривации начальных ключей
    """

    session_id: str
    initiator_identity_public: bytes
    initiator_ephemeral_public: bytes
    hkdf_salt: bytes

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.session_id:
            raise ValueError("session_id cannot be empty")
        if not self.initiator_identity_public:
            raise ValueError("initiator_identity_public cannot be empty")
        if not self.initiator_ephemeral_public:
            raise ValueError("initiator_ephemeral_public cannot be empty")
        if len(self.hkdf_salt) != HKDF_SALT_SIZE:
            raise ValueError(
                f"hkdf_salt must be {HKDF_SALT_SIZE} bytes, "
                f"got {len(self.hkdf_salt)}"
            )


@dataclass
class SessionHandshakeResponse:
    """
    Ответ на хендшейк (от ответчика).

    Отправляется от Bob к Alice после accept_session.

    Attributes:
        session_id: ID сессии (должен совпадать с initiator handshake)
        responder_ephemeral_public: Ephemeral public key ответчика для DH
    """

    session_id: str
    responder_ephemeral_public: bytes

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.session_id:
            raise ValueError("session_id cannot be empty")
        if not self.responder_ephemeral_public:
            raise ValueError("responder_ephemeral_public cannot be empty")


@dataclass
class SessionState:
    """
    Состояние PFS сессии с полным Double Ratchet.

    Mutable dataclass — обновляется при каждом send/receive и DH ratchet step.

    Attributes:
        session_id: Уникальный ID сессии (общий для обеих сторон)
        send_chain_key: Текущий send chain key (bytearray для secure erase)
        recv_chain_key: Текущий recv chain key (bytearray для secure erase)
        send_ratchet_count: Количество рачет-шагов отправки
        recv_ratchet_count: Количество рачет-шагов получения
        dh_send_count: Количество отправленных сообщений с текущим DH keypair
        dh_recv_count: Количество полученных сообщений с текущим remote DH pub
        local_ephemeral_private: Текущий ephemeral private key (bytearray)
        local_ephemeral_public: Текущий ephemeral public key
        remote_ephemeral_public: Текущий ephemeral public key партнёра
        is_initiator: True если мы инициатор сессии
        handshake_completed: True после завершения 3-way handshake
        created_at: Timestamp создания
        last_dh_ratchet_at: Timestamp последнего DH ratchet step
        skipped_message_keys: Кэш пропущенных message keys
    """

    session_id: str
    send_chain_key: bytearray = field(default_factory=lambda: bytearray(32))
    recv_chain_key: bytearray = field(default_factory=lambda: bytearray(32))
    send_ratchet_count: int = 0
    recv_ratchet_count: int = 0
    dh_send_count: int = 0
    dh_recv_count: int = 0
    local_ephemeral_private: bytearray = field(default_factory=lambda: bytearray())
    local_ephemeral_public: bytes = b""
    remote_ephemeral_public: bytes = b""
    is_initiator: bool = False
    handshake_completed: bool = False
    created_at: float = field(default_factory=time.time)
    last_dh_ratchet_at: float = field(default_factory=time.time)
    skipped_message_keys: dict[int, bytearray] = field(default_factory=dict)


@dataclass(frozen=True)
class EncryptedSessionMessage:
    """
    Зашифрованное сессионное сообщение с Double Ratchet.

    Attributes:
        ciphertext: Зашифрованные данные
        nonce: Nonce для расшифровки
        send_ratchet_count: Номер send рачет-шага (для синхронизации)
        dh_send_count: Количество отправленных сообщений с текущим DH keypair
        sender_ephemeral_public: Ephemeral public key отправителя (для DH ratchet)
    """

    ciphertext: bytes
    nonce: bytes
    send_ratchet_count: int
    dh_send_count: int
    sender_ephemeral_public: bytes

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.ciphertext:
            raise ValueError("ciphertext cannot be empty")
        if not self.nonce:
            raise ValueError("nonce cannot be empty")
        if self.send_ratchet_count < 0:
            raise ValueError("send_ratchet_count cannot be negative")
        if self.dh_send_count < 0:
            raise ValueError("dh_send_count cannot be negative")
        if not self.sender_ephemeral_public:
            raise ValueError("sender_ephemeral_public cannot be empty")


# ==============================================================================
# TYPED DICT FOR SESSION INFO
# ==============================================================================


class SessionInfo(dict[str, int | str | float | bool]):
    """Информация о сессии без секретных данных."""

    def __init__(
        self,
        session_id: str,
        is_initiator: bool,
        handshake_completed: bool,
        send_ratchet_count: int,
        recv_ratchet_count: int,
        dh_send_count: int,
        dh_recv_count: int,
        created_at: float,
        last_dh_ratchet_at: float,
        skipped_keys_count: int,
        kex_algorithm: str,
        symmetric_algorithm: str,
    ) -> None:
        super().__init__(
            session_id=session_id,
            is_initiator=is_initiator,
            handshake_completed=handshake_completed,
            send_ratchet_count=send_ratchet_count,
            recv_ratchet_count=recv_ratchet_count,
            dh_send_count=dh_send_count,
            dh_recv_count=dh_recv_count,
            created_at=created_at,
            last_dh_ratchet_at=last_dh_ratchet_at,
            skipped_keys_count=skipped_keys_count,
            kex_algorithm=kex_algorithm,
            symmetric_algorithm=symmetric_algorithm,
        )


# ==============================================================================
# PFS SESSION WITH DOUBLE RATCHET
# ==============================================================================


class PFSSession:
    """
    Менеджер PFS сессий с полноценным Double Ratchet Protocol.

    Реализует:
    - 3-way handshake для инициализации сессии
    - Symmetric ratchet для каждого сообщения (forward secrecy)
    - DH ratchet при смене направления (post-compromise security)
    - Обработка out-of-order сообщений через skipped keys cache
    - Replay protection через ratchet counters

    Example:
        >>> pfs = PFSSession()
        >>> # Alice
        >>> alice_priv, alice_pub = pfs.generate_identity_keypair()
        >>> # Bob
        >>> bob_priv, bob_pub = pfs.generate_identity_keypair()
        >>> # Handshake
        >>> alice_state, handshake = pfs.initiate_session(
        ...     alice_priv, alice_pub, bob_pub
        ... )
        >>> bob_state, response = pfs.accept_session(
        ...     bob_priv, bob_pub, handshake
        ... )
        >>> pfs.complete_handshake(alice_state, response)
        >>> # Messaging
        >>> enc = pfs.send_message(alice_state, b"Hello!")
        >>> plain = pfs.receive_message(bob_state, enc)
    """

    def __init__(
        self,
        kex_algorithm: str = "x25519",
        symmetric_algorithm: str = "aes-256-gcm",
    ) -> None:
        """
        Инициализировать PFS менеджер сессий.

        Args:
            kex_algorithm: Алгоритм обмена ключами (x25519, x448, ...)
            symmetric_algorithm: Алгоритм шифрования (aes-256-gcm, ...)

        Raises:
            CryptoError: Алгоритм недоступен в registry
        """
        self._logger = logging.getLogger(__name__)

        registry = AlgorithmRegistry.get_instance()
        try:
            self._kex: KeyExchangeProtocol = registry.create(kex_algorithm)
            self._cipher: SymmetricCipherProtocol = registry.create(symmetric_algorithm)
        except (KeyError, RuntimeError) as exc:
            raise CryptoError(
                f"Failed to initialize PFSSession: {exc}",
                algorithm=kex_algorithm,
            ) from exc

        self._kex_algo = kex_algorithm
        self._sym_algo = symmetric_algorithm

        self._logger.debug(
            "PFSSession initialized: KEX=%s, Symmetric=%s",
            kex_algorithm,
            symmetric_algorithm,
        )

    def generate_identity_keypair(self) -> tuple[bytes, bytes]:
        """
        Сгенерировать identity keypair для участника.

        Identity keypair используется для первичного DH-обмена при
        инициализации сессии. Должен храниться долговременно.

        Returns:
            (private_key, public_key)

        Raises:
            CryptoError: Генерация не удалась
        """
        try:
            return self._kex.generate_keypair()
        except Exception as exc:
            raise CryptoError(f"Identity keypair generation failed: {exc}") from exc

    def initiate_session(
        self,
        local_private_key: bytes,
        local_public_key: bytes,
        remote_public_key: bytes,
    ) -> tuple[SessionState, SessionHandshake]:
        """
        Инициировать PFS сессию (Alice, step 1/3).

        Process:
            1. Генерация ephemeral keypair для Alice
            2. DH(alice_identity_priv, bob_identity_pub) → shared_secret
            3. Деривация initial chain keys через HKDF(shared_secret, salt)
            4. Создание handshake для отправки Bob

        Args:
            local_private_key: Identity private key инициатора (Alice)
            local_public_key: Identity public key инициатора (Alice)
            remote_public_key: Identity public key ответчика (Bob)

        Returns:
            (SessionState, SessionHandshake):
                - SessionState с handshake_completed=False
                - SessionHandshake для отправки Bob

        Raises:
            ValueError: Невалидные ключи
            CryptoError: Инициализация не удалась
        """
        if not local_private_key:
            raise ValueError("Local private key cannot be empty")
        if not local_public_key:
            raise ValueError("Local public key cannot be empty")
        if not remote_public_key:
            raise ValueError("Remote public key cannot be empty")

        shared_secret = bytearray()

        try:
            # 1. Generate ephemeral keypair for Alice
            ephemeral_private, ephemeral_public = self._kex.generate_keypair()

            # 2. DH(alice_identity_priv, bob_identity_pub)
            ss_bytes = self._kex.derive_shared_secret(
                private_key=local_private_key,
                peer_public_key=remote_public_key,
            )
            shared_secret = bytearray(ss_bytes)

            # 3. Derive initial chain keys
            hkdf_salt = secrets.token_bytes(HKDF_SALT_SIZE)
            send_chain_key, recv_chain_key = self._derive_initial_chain_keys(
                bytes(shared_secret), hkdf_salt
            )

            # 4. Create session
            session_id = secrets.token_hex(16)

            handshake = SessionHandshake(
                session_id=session_id,
                initiator_identity_public=local_public_key,
                initiator_ephemeral_public=ephemeral_public,
                hkdf_salt=hkdf_salt,
            )

            state = SessionState(
                session_id=session_id,
                send_chain_key=bytearray(send_chain_key),
                recv_chain_key=bytearray(recv_chain_key),
                local_ephemeral_private=bytearray(ephemeral_private),
                local_ephemeral_public=ephemeral_public,
                remote_ephemeral_public=b"",  # Ждём от Bob
                is_initiator=True,
                handshake_completed=False,
            )

            self._logger.info("Initiated session %s as initiator (Alice)", session_id)

            return state, handshake

        except ValueError:
            raise
        except Exception as exc:
            raise CryptoError(f"Session initiation failed: {exc}") from exc
        finally:
            self._secure_erase(shared_secret)

    def accept_session(
        self,
        local_private_key: bytes,
        local_public_key: bytes,
        handshake: SessionHandshake,
    ) -> tuple[SessionState, SessionHandshakeResponse]:
        """
        Принять PFS сессию (Bob, step 2/3).

        Process:
            1. DH(bob_identity_priv, alice_identity_pub) → shared_secret
            2. Деривация initial chain keys (инвертированных)
            3. Генерация ephemeral keypair для Bob
            4. Создание response handshake для отправки Alice

        Args:
            local_private_key: Identity private key ответчика (Bob)
            local_public_key: Identity public key ответчика (Bob)
            handshake: Хендшейк от Alice

        Returns:
            (SessionState, SessionHandshakeResponse):
                - SessionState с handshake_completed=True (Bob готов)
                - SessionHandshakeResponse для отправки Alice

        Raises:
            ValueError: Невалидные данные
            CryptoError: Принятие не удалось
        """
        if not local_private_key:
            raise ValueError("Local private key cannot be empty")
        if not local_public_key:
            raise ValueError("Local public key cannot be empty")
        if not handshake:
            raise ValueError("Handshake cannot be None")

        shared_secret = bytearray()

        try:
            # 1. DH(bob_identity_priv, alice_identity_pub)
            ss_bytes = self._kex.derive_shared_secret(
                private_key=local_private_key,
                peer_public_key=handshake.initiator_identity_public,
            )
            shared_secret = bytearray(ss_bytes)

            # 2. Derive initial chain keys (inverted: recv = alice's send)
            send_chain_key, recv_chain_key = self._derive_initial_chain_keys(
                bytes(shared_secret), handshake.hkdf_salt
            )

            # 3. Generate ephemeral keypair for Bob
            ephemeral_private, ephemeral_public = self._kex.generate_keypair()

            # 4. Create response
            response = SessionHandshakeResponse(
                session_id=handshake.session_id,
                responder_ephemeral_public=ephemeral_public,
            )

            state = SessionState(
                session_id=handshake.session_id,
                send_chain_key=bytearray(recv_chain_key),  # Inverted
                recv_chain_key=bytearray(send_chain_key),  # Inverted
                local_ephemeral_private=bytearray(ephemeral_private),
                local_ephemeral_public=ephemeral_public,
                remote_ephemeral_public=handshake.initiator_ephemeral_public,
                is_initiator=False,
                handshake_completed=True,  # Bob готов после accept
            )

            self._logger.info(
                "Accepted session %s as responder (Bob)", handshake.session_id
            )

            return state, response

        except ValueError:
            raise
        except Exception as exc:
            raise CryptoError(f"Session acceptance failed: {exc}") from exc
        finally:
            self._secure_erase(shared_secret)

    def complete_handshake(
        self,
        state: SessionState,
        response: SessionHandshakeResponse,
    ) -> None:
        """
        Завершить handshake (Alice, step 3/3).

        Alice получает response от Bob с его ephemeral public key и
        завершает инициализацию сессии.

        Args:
            state: Состояние сессии Alice (from initiate_session)
            response: Response от Bob (from accept_session)

        Raises:
            ValueError: session_id не совпадает
            ProtocolError: Handshake уже завершён
        """
        if state.session_id != response.session_id:
            raise ValueError(
                f"Session ID mismatch: expected {state.session_id}, "
                f"got {response.session_id}"
            )

        if state.handshake_completed:
            raise ProtocolError(
                f"Handshake already completed for session {state.session_id}"
            )

        state.remote_ephemeral_public = response.responder_ephemeral_public
        state.handshake_completed = True

        self._logger.info(
            "Completed handshake for session %s (Alice)", state.session_id
        )

    def send_message(
        self,
        state: SessionState,
        plaintext: bytes,
        *,
        associated_data: bytes | None = None,
    ) -> EncryptedSessionMessage:
        """
        Зашифровать и отправить сообщение с Double Ratchet.

        Process:
            1. Check handshake completion
            2. Check if DH ratchet needed (first send after receive)
            3. Derive message key from send_chain_key
            4. Ratchet send_chain_key (symmetric ratchet)
            5. Encrypt plaintext with message key
            6. Increment counters

        Args:
            state: Текущее состояние сессии (мутируется)
            plaintext: Данные для шифрования
            associated_data: Дополнительные данные для AEAD

        Returns:
            EncryptedSessionMessage

        Raises:
            ValueError: Пустой plaintext
            ProtocolError: Handshake не завершён или превышен лимит
            EncryptionError: Шифрование не удалось
        """
        if not state.handshake_completed:
            raise ProtocolError(
                f"Handshake not completed for session {state.session_id}. "
                f"Call complete_handshake() first."
            )

        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")

        if state.send_ratchet_count >= MAX_RATCHET_STEPS:
            raise ProtocolError(
                f"Max ratchet steps exceeded ({MAX_RATCHET_STEPS}). "
                f"Create a new session."
            )

        message_key = bytearray()
        try:
            # Check if DH ratchet needed
            if state.dh_send_count == 0 and state.dh_recv_count > 0:
                # Первая отправка после получения → DH ratchet
                self._perform_dh_ratchet(state)

            # 1. Derive message key from chain key
            mk_bytes = self._derive_message_key(bytes(state.send_chain_key))
            message_key = bytearray(mk_bytes)

            # 2. Ratchet chain key (symmetric ratchet)
            new_ck = self._ratchet_chain_key(bytes(state.send_chain_key))
            self._secure_erase(state.send_chain_key)
            state.send_chain_key = bytearray(new_ck)

            # 3. Encrypt plaintext
            ciphertext, nonce = self._cipher.encrypt(
                key=bytes(message_key),
                plaintext=plaintext,
                aad=associated_data,
            )

            # 4. Increment counters
            state.send_ratchet_count += 1
            state.dh_send_count += 1

            self._logger.debug(
                "Sent message in session %s: send_ratchet=%d, dh_send=%d",
                state.session_id,
                state.send_ratchet_count,
                state.dh_send_count,
            )

            return EncryptedSessionMessage(
                ciphertext=ciphertext,
                nonce=nonce,
                send_ratchet_count=state.send_ratchet_count,
                dh_send_count=state.dh_send_count,
                sender_ephemeral_public=state.local_ephemeral_public,
            )

        except (ValueError, EncryptionError, ProtocolError):
            raise
        except Exception as exc:
            raise EncryptionError(f"Session send failed: {exc}") from exc
        finally:
            self._secure_erase(message_key)

    def receive_message(
        self,
        state: SessionState,
        encrypted: EncryptedSessionMessage,
        *,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Получить и расшифровать сообщение с Double Ratchet.

        Process:
            1. Check if DH ratchet needed (new sender ephemeral public key)
            2. Check for replay/out-of-order
            3. Handle skipped messages if needed
            4. Derive message key from recv_chain_key
            5. Ratchet recv_chain_key (symmetric ratchet)
            6. Decrypt ciphertext

        Args:
            state: Текущее состояние сессии (мутируется)
            encrypted: Зашифрованное сообщение
            associated_data: Дополнительные данные для AEAD

        Returns:
            Расшифрованный plaintext

        Raises:
            DecryptionError: Расшифровка не удалась
            ProtocolError: Сообщение слишком далеко впереди или replay
        """
        if not state.handshake_completed:
            raise ProtocolError(
                f"Handshake not completed for session {state.session_id}"
            )

        message_key = bytearray()
        try:
            # 1. Check if DH ratchet needed
            if encrypted.sender_ephemeral_public != state.remote_ephemeral_public:
                # Новый ephemeral public key от отправителя → DH ratchet
                self._perform_dh_ratchet_receive(
                    state, encrypted.sender_ephemeral_public
                )

            # 2. Replay protection
            expected_count = state.recv_ratchet_count + 1
            if (
                encrypted.send_ratchet_count < expected_count
                and encrypted.send_ratchet_count not in state.skipped_message_keys
            ):
                raise ProtocolError(
                    f"Replay or already-processed message: "
                    f"ratchet_count={encrypted.send_ratchet_count} < "
                    f"expected={expected_count}"
                )

            # 3. Handle skipped messages
            if encrypted.send_ratchet_count > expected_count:
                skip_count = encrypted.send_ratchet_count - expected_count
                if skip_count > MAX_SKIP_MESSAGES:
                    raise ProtocolError(
                        f"Too many skipped messages ({skip_count}). "
                        f"Max allowed: {MAX_SKIP_MESSAGES}"
                    )

                # Cache keys for skipped messages
                for i in range(skip_count):
                    skipped_idx = expected_count + i
                    skipped_key_bytes = self._derive_message_key(
                        bytes(state.recv_chain_key)
                    )
                    state.skipped_message_keys[skipped_idx] = bytearray(
                        skipped_key_bytes
                    )

                    # Ratchet chain key
                    new_ck = self._ratchet_chain_key(bytes(state.recv_chain_key))
                    self._secure_erase(state.recv_chain_key)
                    state.recv_chain_key = bytearray(new_ck)

                # Cleanup skipped cache if too large
                self._cleanup_skipped_cache(state)

            # 4. Get message key
            if encrypted.send_ratchet_count in state.skipped_message_keys:
                # Previously skipped message
                message_key = state.skipped_message_keys.pop(
                    encrypted.send_ratchet_count
                )
            else:
                # Current message
                mk_bytes = self._derive_message_key(bytes(state.recv_chain_key))
                message_key = bytearray(mk_bytes)

                # Ratchet chain key
                new_ck = self._ratchet_chain_key(bytes(state.recv_chain_key))
                self._secure_erase(state.recv_chain_key)
                state.recv_chain_key = bytearray(new_ck)

            # 5. Decrypt
            plaintext = self._cipher.decrypt(
                key=bytes(message_key),
                ciphertext=encrypted.ciphertext,
                nonce=encrypted.nonce,
                aad=associated_data,
            )

            # 6. Update counters
            state.recv_ratchet_count = max(
                state.recv_ratchet_count, encrypted.send_ratchet_count
            )
            state.dh_recv_count = max(state.dh_recv_count, encrypted.dh_send_count)

            self._logger.debug(
                "Received message in session %s: recv_ratchet=%d, dh_recv=%d",
                state.session_id,
                state.recv_ratchet_count,
                state.dh_recv_count,
            )

            return plaintext

        except (DecryptionError, ProtocolError):
            raise
        except Exception as exc:
            raise DecryptionError(f"Session receive failed: {exc}") from exc
        finally:
            self._secure_erase(message_key)

    def get_session_info(self, state: SessionState) -> SessionInfo:
        """
        Получить информацию о текущей сессии.

        Args:
            state: Состояние сессии

        Returns:
            SessionInfo без секретных данных (типизированный dict)
        """
        return SessionInfo(
            session_id=state.session_id,
            is_initiator=state.is_initiator,
            handshake_completed=state.handshake_completed,
            send_ratchet_count=state.send_ratchet_count,
            recv_ratchet_count=state.recv_ratchet_count,
            dh_send_count=state.dh_send_count,
            dh_recv_count=state.dh_recv_count,
            created_at=state.created_at,
            last_dh_ratchet_at=state.last_dh_ratchet_at,
            skipped_keys_count=len(state.skipped_message_keys),
            kex_algorithm=self._kex_algo,
            symmetric_algorithm=self._sym_algo,
        )

    def destroy_session(self, state: SessionState) -> None:
        """
        Безопасно уничтожить сессию (стереть все ключи из памяти).

        Args:
            state: Состояние сессии для уничтожения
        """
        self._secure_erase(state.send_chain_key)
        self._secure_erase(state.recv_chain_key)
        self._secure_erase(state.local_ephemeral_private)

        for key in state.skipped_message_keys.values():
            self._secure_erase(key)
        state.skipped_message_keys.clear()

        # Clear references
        state.send_chain_key = bytearray()
        state.recv_chain_key = bytearray()
        state.local_ephemeral_private = bytearray()
        state.local_ephemeral_public = b""
        state.remote_ephemeral_public = b""

        self._logger.info("Destroyed session %s", state.session_id)

    # ==========================================================================
    # PRIVATE METHODS
    # ==========================================================================

    def _derive_initial_chain_keys(
        self, shared_secret: bytes, salt: bytes
    ) -> tuple[bytes, bytes]:
        """
        Вывести начальные chain keys из shared secret.

        Returns:
            (send_chain_key, recv_chain_key)
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=CHAIN_KEY_SIZE * 2,
            salt=salt,
            info=HKDF_INFO_HANDSHAKE,
        )
        key_material = hkdf.derive(shared_secret)
        return key_material[:CHAIN_KEY_SIZE], key_material[CHAIN_KEY_SIZE:]

    def _derive_message_key(self, chain_key: bytes) -> bytes:
        """Вывести message key из chain key (детерминированно)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=MESSAGE_KEY_SIZE,
            salt=None,
            info=HKDF_INFO_MESSAGE,
        )
        return hkdf.derive(chain_key)

    def _ratchet_chain_key(self, chain_key: bytes) -> bytes:
        """
        Продвинуть chain key на один шаг (symmetric ratchet).

        Использует HKDF с предыдущим chain key как input key material.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=CHAIN_KEY_SIZE,
            salt=None,
            info=HKDF_INFO_CHAIN,
        )
        return hkdf.derive(chain_key)

    def _perform_dh_ratchet(self, state: SessionState) -> None:
        """
        Выполнить DH ratchet step (отправитель генерирует новый keypair).

        Вызывается при первой отправке после получения сообщений.
        Обеспечивает Post-Compromise Security.
        """
        shared_secret = bytearray()
        try:
            # 1. Generate new ephemeral keypair
            new_private, new_public = self._kex.generate_keypair()

            # 2. DH(new_private, remote_ephemeral_public) → new shared secret
            ss_bytes = self._kex.derive_shared_secret(
                private_key=new_private,
                peer_public_key=state.remote_ephemeral_public,
            )
            shared_secret = bytearray(ss_bytes)

            # 3. Derive new chain keys
            new_send_ck, new_recv_ck = self._derive_dh_ratchet_keys(
                bytes(shared_secret)
            )

            # 4. Secure erase old keys
            self._secure_erase(state.send_chain_key)
            self._secure_erase(state.recv_chain_key)
            self._secure_erase(state.local_ephemeral_private)

            # 5. Update state
            state.send_chain_key = bytearray(new_send_ck)
            state.recv_chain_key = bytearray(new_recv_ck)
            state.local_ephemeral_private = bytearray(new_private)
            state.local_ephemeral_public = new_public
            state.dh_send_count = 0
            state.last_dh_ratchet_at = time.time()

            self._logger.debug(
                "Performed DH ratchet (send) for session %s",
                state.session_id,
            )

        finally:
            self._secure_erase(shared_secret)

    def _perform_dh_ratchet_receive(
        self, state: SessionState, new_remote_public: bytes
    ) -> None:
        """
        Выполнить DH ratchet step при получении нового remote ephemeral key.

        Вызывается когда получатель видит новый sender_ephemeral_public.
        """
        shared_secret = bytearray()
        try:
            # 1. DH(local_private, new_remote_public) → new shared secret
            ss_bytes = self._kex.derive_shared_secret(
                private_key=bytes(state.local_ephemeral_private),
                peer_public_key=new_remote_public,
            )
            shared_secret = bytearray(ss_bytes)

            # 2. Derive new chain keys (inverted for receiver)
            new_send_ck, new_recv_ck = self._derive_dh_ratchet_keys(
                bytes(shared_secret)
            )

            # 3. Secure erase old keys
            self._secure_erase(state.send_chain_key)
            self._secure_erase(state.recv_chain_key)

            # 4. Update state
            state.send_chain_key = bytearray(new_recv_ck)  # Inverted
            state.recv_chain_key = bytearray(new_send_ck)  # Inverted
            state.remote_ephemeral_public = new_remote_public
            state.dh_recv_count = 0
            state.last_dh_ratchet_at = time.time()

            self._logger.debug(
                "Performed DH ratchet (receive) for session %s",
                state.session_id,
            )

        finally:
            self._secure_erase(shared_secret)

    def _derive_dh_ratchet_keys(self, shared_secret: bytes) -> tuple[bytes, bytes]:
        """Вывести новые chain keys после DH ratchet."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=CHAIN_KEY_SIZE * 2,
            salt=None,
            info=HKDF_INFO_DH_RATCHET,
        )
        key_material = hkdf.derive(shared_secret)
        return key_material[:CHAIN_KEY_SIZE], key_material[CHAIN_KEY_SIZE:]

    def _cleanup_skipped_cache(self, state: SessionState) -> None:
        """
        Очистить старые записи из skipped_message_keys cache.

        Удаляет самые старые ключи, если размер кэша превысил лимит.
        """
        if len(state.skipped_message_keys) > MAX_SKIPPED_CACHE_SIZE:
            # Удалить самые старые ключи
            sorted_keys = sorted(state.skipped_message_keys.keys())
            keys_to_remove = sorted_keys[
                : len(state.skipped_message_keys) - MAX_SKIPPED_CACHE_SIZE
            ]

            for key in keys_to_remove:
                removed_key = state.skipped_message_keys.pop(key)
                self._secure_erase(removed_key)

            self._logger.warning(
                "Cleaned up %d old skipped keys from cache in session %s",
                len(keys_to_remove),
                state.session_id,
            )

    @staticmethod
    def _secure_erase(data: bytearray) -> None:
        """
        Безопасно стереть чувствительные данные из памяти.

        Перезаписывает bytearray случайными байтами, затем нулями.
        """
        if not data:
            return
        # Перезапись случайными байтами
        for i in range(len(data)):
            data[i] = secrets.randbits(8)
        # Перезапись нулями
        for i in range(len(data)):
            data[i] = 0


# ==============================================================================
# EXPORTS
# ==============================================================================

__all__ = [
    "PFSSession",
    "SessionState",
    "SessionHandshake",
    "SessionHandshakeResponse",
    "EncryptedSessionMessage",
    "SessionInfo",
]
