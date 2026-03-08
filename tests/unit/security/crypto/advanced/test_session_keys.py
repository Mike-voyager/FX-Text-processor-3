"""
Тесты для модуля Perfect Forward Secrecy Session Keys.

Этот модуль содержит исчерпывающие тесты для PFSSession и связанных
компонентов Double Ratchet Protocol.
"""

from __future__ import annotations

import secrets
import time
from typing import Final
from pytest_mock import MockerFixture


import pytest

from src.security.crypto.advanced.session_keys import (
    CHAIN_KEY_SIZE,
    HKDF_SALT_SIZE,
    MAX_RATCHET_STEPS,
    MAX_SKIP_MESSAGES,
    MAX_SKIPPED_CACHE_SIZE,
    MESSAGE_KEY_SIZE,
    EncryptedSessionMessage,
    PFSSession,
    SessionHandshake,
    SessionHandshakeResponse,
    SessionInfo,
    SessionState,
)
from src.security.crypto.core.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    ProtocolError,
)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def pfs_session() -> PFSSession:
    """Создать новую PFS сессию с дефолтными алгоритмами."""
    return PFSSession(kex_algorithm="x25519", symmetric_algorithm="aes-256-gcm")


@pytest.fixture
def alice_session() -> PFSSession:
    """PFS сессия для Alice."""
    return PFSSession()


@pytest.fixture
def bob_session() -> PFSSession:
    """PFS сессия для Bob."""
    return PFSSession()


@pytest.fixture
def alice_keypair(alice_session: PFSSession) -> tuple[bytes, bytes]:
    """Identity keypair для Alice."""
    return alice_session.generate_identity_keypair()


@pytest.fixture
def bob_keypair(bob_session: PFSSession) -> tuple[bytes, bytes]:
    """Identity keypair для Bob."""
    return bob_session.generate_identity_keypair()


@pytest.fixture
def established_session(
    alice_session: PFSSession,
    bob_session: PFSSession,
    alice_keypair: tuple[bytes, bytes],
    bob_keypair: tuple[bytes, bytes],
) -> tuple[SessionState, SessionState]:
    """Установленная сессия между Alice и Bob после handshake."""
    alice_priv, alice_pub = alice_keypair
    bob_priv, bob_pub = bob_keypair

    # 1. Alice инициирует
    alice_state, handshake = alice_session.initiate_session(
        alice_priv, alice_pub, bob_pub
    )

    # 2. Bob принимает
    bob_state, response = bob_session.accept_session(bob_priv, bob_pub, handshake)

    # 3. Alice завершает
    alice_session.complete_handshake(alice_state, response)

    return alice_state, bob_state


@pytest.fixture
def session() -> PFSSession:
    """Один PFSSession для тестов без полного handshake."""
    return PFSSession()


# ==============================================================================
# CONSTANTS TESTS
# ==============================================================================


class TestConstants:
    """Тесты для модульных констант."""

    def test_chain_key_size(self) -> None:
        """Chain key должен быть 32 байта."""
        assert CHAIN_KEY_SIZE == 32

    def test_message_key_size(self) -> None:
        """Message key должен быть 32 байта."""
        assert MESSAGE_KEY_SIZE == 32

    def test_hkdf_salt_size(self) -> None:
        """HKDF salt должен быть 32 байта."""
        assert HKDF_SALT_SIZE == 32

    def test_max_skip_messages(self) -> None:
        """Максимум пропущенных сообщений не должен быть слишком большим."""
        assert MAX_SKIP_MESSAGES == 100
        assert MAX_SKIP_MESSAGES > 0

    def test_max_ratchet_steps(self) -> None:
        """Максимум рачет-шагов должен быть достаточно большим."""
        assert MAX_RATCHET_STEPS == 10000
        assert MAX_RATCHET_STEPS > 1000

    def test_max_skipped_cache_size(self) -> None:
        """Размер кэша пропущенных ключей должен быть разумным."""
        assert MAX_SKIPPED_CACHE_SIZE == 1000
        assert MAX_SKIPPED_CACHE_SIZE >= MAX_SKIP_MESSAGES


# ==============================================================================
# DATACLASS TESTS
# ==============================================================================


class TestSessionHandshake:
    """Тесты для SessionHandshake."""

    def test_create_valid_handshake(self) -> None:
        """Создание валидного handshake."""
        handshake = SessionHandshake(
            session_id="test-session-id",
            initiator_identity_public=b"alice-pub-key-32-bytes-xxxxxxxx",
            initiator_ephemeral_public=b"alice-eph-pub-key-32-bytes-xxx",
            hkdf_salt=secrets.token_bytes(HKDF_SALT_SIZE),
        )

        assert handshake.session_id == "test-session-id"
        assert len(handshake.hkdf_salt) == HKDF_SALT_SIZE

    def test_empty_session_id_raises_error(self) -> None:
        """Пустой session_id должен вызывать ValueError."""
        with pytest.raises(ValueError, match="session_id cannot be empty"):
            SessionHandshake(
                session_id="",
                initiator_identity_public=b"key",
                initiator_ephemeral_public=b"key",
                hkdf_salt=secrets.token_bytes(HKDF_SALT_SIZE),
            )

    def test_empty_initiator_identity_public_raises_error(self) -> None:
        """Пустой initiator_identity_public должен вызывать ValueError."""
        with pytest.raises(
            ValueError, match="initiator_identity_public cannot be empty"
        ):
            SessionHandshake(
                session_id="test",
                initiator_identity_public=b"",
                initiator_ephemeral_public=b"key",
                hkdf_salt=secrets.token_bytes(HKDF_SALT_SIZE),
            )

    def test_invalid_salt_size_raises_error(self) -> None:
        """Невалидный размер salt должен вызывать ValueError."""
        with pytest.raises(ValueError, match="hkdf_salt must be 32 bytes"):
            SessionHandshake(
                session_id="test",
                initiator_identity_public=b"key",
                initiator_ephemeral_public=b"key",
                hkdf_salt=b"short",
            )


class TestSessionHandshakeResponse:
    """Тесты для SessionHandshakeResponse."""

    def test_create_valid_response(self) -> None:
        """Создание валидного response."""
        response = SessionHandshakeResponse(
            session_id="test-session-id",
            responder_ephemeral_public=b"bob-eph-pub-key-32-bytes-xxxxx",
        )

        assert response.session_id == "test-session-id"
        assert len(response.responder_ephemeral_public) > 0

    def test_empty_session_id_raises_error(self) -> None:
        """Пустой session_id должен вызывать ValueError."""
        with pytest.raises(ValueError, match="session_id cannot be empty"):
            SessionHandshakeResponse(session_id="", responder_ephemeral_public=b"key")


class TestEncryptedSessionMessage:
    """Тесты для EncryptedSessionMessage."""

    def test_create_valid_message(self) -> None:
        """Создание валидного зашифрованного сообщения."""
        msg = EncryptedSessionMessage(
            ciphertext=b"encrypted-data",
            nonce=b"nonce-12-bytes-x",
            send_ratchet_count=5,
            dh_send_count=2,
            sender_ephemeral_public=b"eph-pub-key",
        )

        assert msg.ciphertext == b"encrypted-data"
        assert msg.send_ratchet_count == 5
        assert msg.dh_send_count == 2

    def test_negative_ratchet_count_raises_error(self) -> None:
        """Отрицательный счётчик рачета должен вызывать ValueError."""
        with pytest.raises(ValueError, match="send_ratchet_count cannot be negative"):
            EncryptedSessionMessage(
                ciphertext=b"data",
                nonce=b"nonce",
                send_ratchet_count=-1,
                dh_send_count=0,
                sender_ephemeral_public=b"key",
            )


class TestSessionState:
    """Тесты для SessionState."""

    def test_create_default_state(self) -> None:
        """Создание состояния сессии с дефолтными значениями."""
        state = SessionState(session_id="test-session")

        assert state.session_id == "test-session"
        assert state.send_ratchet_count == 0
        assert state.recv_ratchet_count == 0
        assert state.dh_send_count == 0
        assert state.dh_recv_count == 0
        assert state.is_initiator is False
        assert state.handshake_completed is False
        assert len(state.skipped_message_keys) == 0


# ==============================================================================
# PFS SESSION INITIALIZATION TESTS
# ==============================================================================


class TestPFSSessionInit:
    """Тесты для инициализации PFSSession."""

    def test_init_with_default_algorithms(self) -> None:
        """Инициализация с дефолтными алгоритмами."""
        session = PFSSession()

        assert session is not None
        info = session.get_session_info(SessionState(session_id="dummy"))

        # Type-safe проверки
        kex_algo = info["kex_algorithm"]
        assert isinstance(kex_algo, str), f"Expected str, got {type(kex_algo)}"
        assert "x25519" in kex_algo

    @pytest.mark.parametrize(
        "kex_algo,sym_algo",
        [
            ("x25519", "aes-256-gcm"),
            ("x25519", "chacha20-poly1305"),
        ],
    )
    def test_init_with_custom_algorithms(self, kex_algo: str, sym_algo: str) -> None:
        """Инициализация с кастомными алгоритмами."""
        session = PFSSession(kex_algorithm=kex_algo, symmetric_algorithm=sym_algo)

        info = session.get_session_info(SessionState(session_id="dummy"))
        assert info["kex_algorithm"] == kex_algo
        assert info["symmetric_algorithm"] == sym_algo

    def test_init_with_invalid_algorithm_raises_error(self) -> None:
        """Инициализация с несуществующим алгоритмом должна вызывать CryptoError."""
        with pytest.raises(CryptoError, match="Failed to initialize PFSSession"):
            PFSSession(kex_algorithm="invalid-algo")


# ==============================================================================
# IDENTITY KEYPAIR GENERATION TESTS
# ==============================================================================


class TestIdentityKeypairGeneration:
    """Тесты для генерации identity keypair."""

    def test_generate_keypair_success(self, pfs_session: PFSSession) -> None:
        """Успешная генерация keypair."""
        private_key, public_key = pfs_session.generate_identity_keypair()

        assert len(private_key) == 32  # x25519 private key size
        assert len(public_key) == 32  # x25519 public key size

    def test_generate_multiple_keypairs_are_unique(
        self, pfs_session: PFSSession
    ) -> None:
        """Генерируемые keypair уникальны."""
        priv1, pub1 = pfs_session.generate_identity_keypair()
        priv2, pub2 = pfs_session.generate_identity_keypair()

        assert priv1 != priv2
        assert pub1 != pub2


# ==============================================================================
# SESSION HANDSHAKE TESTS
# ==============================================================================


class TestSessionHandshakeProtocol:
    """Тесты для 3-way handshake протокола."""

    def test_full_handshake_success(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        alice_keypair: tuple[bytes, bytes],
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Успешный 3-way handshake между Alice и Bob."""
        alice_priv, alice_pub = alice_keypair
        bob_priv, bob_pub = bob_keypair

        # Step 1: Alice инициирует
        alice_state, handshake = alice_session.initiate_session(
            alice_priv, alice_pub, bob_pub
        )

        assert alice_state.is_initiator is True
        assert alice_state.handshake_completed is False
        assert handshake.session_id == alice_state.session_id

        # Step 2: Bob принимает
        bob_state, response = bob_session.accept_session(bob_priv, bob_pub, handshake)

        assert bob_state.is_initiator is False
        assert bob_state.handshake_completed is True
        assert bob_state.session_id == handshake.session_id

        # Step 3: Alice завершает
        alice_session.complete_handshake(alice_state, response)

        assert alice_state.handshake_completed is True
        assert alice_state.session_id == bob_state.session_id

    def test_initiate_session_with_empty_private_key_raises_error(
        self,
        alice_session: PFSSession,
        alice_keypair: tuple[bytes, bytes],
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Инициация с пустым private key должна вызывать ValueError."""
        _, alice_pub = alice_keypair
        _, bob_pub = bob_keypair

        with pytest.raises(ValueError, match="Local private key cannot be empty"):
            alice_session.initiate_session(b"", alice_pub, bob_pub)

    def test_accept_session_with_empty_public_key_raises_error(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        alice_keypair: tuple[bytes, bytes],
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Принятие сессии с пустым public key должно вызывать ValueError."""
        alice_priv, alice_pub = alice_keypair
        bob_priv, bob_pub = bob_keypair

        alice_state, handshake = alice_session.initiate_session(
            alice_priv, alice_pub, bob_pub
        )

        with pytest.raises(ValueError, match="Local public key cannot be empty"):
            bob_session.accept_session(bob_priv, b"", handshake)

    def test_complete_handshake_with_mismatched_session_id_raises_error(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        alice_keypair: tuple[bytes, bytes],
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Завершение handshake с несовпадающим session_id должно вызывать ValueError."""
        alice_priv, alice_pub = alice_keypair
        bob_priv, bob_pub = bob_keypair

        alice_state, handshake = alice_session.initiate_session(
            alice_priv, alice_pub, bob_pub
        )
        bob_state, response = bob_session.accept_session(bob_priv, bob_pub, handshake)

        # Подменяем session_id в response
        fake_response = SessionHandshakeResponse(
            session_id="fake-id",
            responder_ephemeral_public=response.responder_ephemeral_public,
        )

        with pytest.raises(ValueError, match="Session ID mismatch"):
            alice_session.complete_handshake(alice_state, fake_response)

    def test_complete_handshake_twice_raises_error(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        alice_keypair: tuple[bytes, bytes],
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Повторное завершение handshake должно вызывать ProtocolError."""
        alice_priv, alice_pub = alice_keypair
        bob_priv, bob_pub = bob_keypair

        alice_state, handshake = alice_session.initiate_session(
            alice_priv, alice_pub, bob_pub
        )
        bob_state, response = bob_session.accept_session(bob_priv, bob_pub, handshake)
        alice_session.complete_handshake(alice_state, response)

        with pytest.raises(ProtocolError, match="Handshake already completed"):
            alice_session.complete_handshake(alice_state, response)


# ==============================================================================
# MESSAGE SENDING/RECEIVING TESTS
# ==============================================================================


class TestMessageExchange:
    """Тесты для отправки и получения сообщений."""

    def test_send_and_receive_single_message(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Отправка и получение одного сообщения."""
        alice_state, bob_state = established_session
        plaintext = b"Hello, Bob!"

        # Alice отправляет
        encrypted = alice_session.send_message(alice_state, plaintext)

        assert encrypted.ciphertext != plaintext
        assert encrypted.send_ratchet_count == 1
        assert encrypted.dh_send_count == 1

        # Bob получает
        decrypted = bob_session.receive_message(bob_state, encrypted)

        assert decrypted == plaintext

    def test_bidirectional_message_exchange(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Двусторонний обмен сообщениями."""
        alice_state, bob_state = established_session

        # Alice → Bob
        msg1 = b"Message 1 from Alice"
        enc1 = alice_session.send_message(alice_state, msg1)
        dec1 = bob_session.receive_message(bob_state, enc1)
        assert dec1 == msg1

        # Bob → Alice (DH ratchet step)
        msg2 = b"Reply from Bob"
        enc2 = bob_session.send_message(bob_state, msg2)
        dec2 = alice_session.receive_message(alice_state, enc2)
        assert dec2 == msg2

        # Alice → Bob снова
        msg3 = b"Another message"
        enc3 = alice_session.send_message(alice_state, msg3)
        dec3 = bob_session.receive_message(bob_state, enc3)
        assert dec3 == msg3

    def test_send_message_without_handshake_raises_error(
        self,
        alice_session: PFSSession,
        alice_keypair: tuple[bytes, bytes],
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Отправка без завершённого handshake должна вызывать ProtocolError."""
        alice_priv, alice_pub = alice_keypair
        _, bob_pub = bob_keypair

        alice_state, _ = alice_session.initiate_session(alice_priv, alice_pub, bob_pub)

        with pytest.raises(ProtocolError, match="Handshake not completed"):
            alice_session.send_message(alice_state, b"test")

    def test_send_empty_plaintext_raises_error(
        self,
        alice_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Отправка пустого plaintext должна вызывать ValueError."""
        alice_state, _ = established_session

        with pytest.raises(ValueError, match="Cannot encrypt empty plaintext"):
            alice_session.send_message(alice_state, b"")

    def test_receive_message_without_handshake_raises_error(
        self,
        bob_session: PFSSession,
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Получение без завершённого handshake должно вызывать ProtocolError."""
        bob_state = SessionState(session_id="test", handshake_completed=False)

        fake_encrypted = EncryptedSessionMessage(
            ciphertext=b"fake",
            nonce=b"fake-nonce",
            send_ratchet_count=1,
            dh_send_count=1,
            sender_ephemeral_public=b"fake-key-32-bytes-xxxxxxxxxxxxxxx",
        )

        with pytest.raises(ProtocolError, match="Handshake not completed"):
            bob_session.receive_message(bob_state, fake_encrypted)

    def test_message_with_associated_data(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Отправка и получение сообщения с associated data (AEAD)."""
        alice_state, bob_state = established_session
        plaintext = b"Authenticated message"
        aad = b"metadata-context"

        # Alice отправляет с AAD
        encrypted = alice_session.send_message(
            alice_state, plaintext, associated_data=aad
        )

        # Bob получает с тем же AAD
        decrypted = bob_session.receive_message(
            bob_state, encrypted, associated_data=aad
        )

        assert decrypted == plaintext

    def test_message_with_wrong_associated_data_fails(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Получение с неправильным AAD должно вызывать DecryptionError."""
        alice_state, bob_state = established_session
        plaintext = b"Authenticated message"
        aad = b"correct-metadata"
        wrong_aad = b"wrong-metadata"

        encrypted = alice_session.send_message(
            alice_state, plaintext, associated_data=aad
        )

        with pytest.raises(DecryptionError):
            bob_session.receive_message(bob_state, encrypted, associated_data=wrong_aad)


# ==============================================================================
# DOUBLE RATCHET TESTS
# ==============================================================================


class TestDoubleRatchet:
    """Тесты для Double Ratchet (Symmetric + DH)."""

    def test_symmetric_ratchet_on_each_send(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Symmetric ratchet продвигается при каждой отправке."""
        alice_state, bob_state = established_session

        initial_count = alice_state.send_ratchet_count

        # Отправить 3 сообщения
        for i in range(3):
            msg = f"Message {i}".encode()
            enc = alice_session.send_message(alice_state, msg)
            bob_session.receive_message(bob_state, enc)

        assert alice_state.send_ratchet_count == initial_count + 3

    def test_dh_ratchet_on_direction_change(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """DH ratchet выполняется при смене направления коммуникации."""
        alice_state, bob_state = established_session

        # Alice отправляет
        alice_initial_eph_pub = alice_state.local_ephemeral_public
        enc1 = alice_session.send_message(alice_state, b"Message 1")
        bob_session.receive_message(bob_state, enc1)

        # Bob отправляет (DH ratchet)
        bob_initial_eph_pub = bob_state.local_ephemeral_public
        enc2 = bob_session.send_message(bob_state, b"Reply")
        alice_session.receive_message(alice_state, enc2)

        # Ephemeral keys должны измениться после DH ratchet
        assert bob_state.local_ephemeral_public != bob_initial_eph_pub

        # Alice отправляет снова (DH ratchet)
        enc3 = alice_session.send_message(alice_state, b"Message 2")

        assert alice_state.local_ephemeral_public != alice_initial_eph_pub

    def test_dh_ratchet_resets_counters(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """DH ratchet сбрасывает счётчики dh_send/recv."""
        alice_state, bob_state = established_session

        # Alice отправляет несколько сообщений
        for _ in range(3):
            enc = alice_session.send_message(alice_state, b"test")
            bob_session.receive_message(bob_state, enc)

        assert alice_state.dh_send_count == 3
        assert bob_state.dh_recv_count == 3

        # Bob отвечает (DH ratchet)
        enc = bob_session.send_message(bob_state, b"reply")
        alice_session.receive_message(alice_state, enc)

        # dh_send_count для Bob должен сброситься
        assert bob_state.dh_send_count == 1


# ==============================================================================
# OUT-OF-ORDER AND SKIPPED MESSAGES TESTS
# ==============================================================================


class TestOutOfOrderMessages:
    """Тесты для обработки out-of-order и пропущенных сообщений."""

    def test_receive_out_of_order_messages(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Получение сообщений не по порядку."""
        alice_state, bob_state = established_session

        # Alice отправляет 3 сообщения
        enc1 = alice_session.send_message(alice_state, b"Message 1")
        enc2 = alice_session.send_message(alice_state, b"Message 2")
        enc3 = alice_session.send_message(alice_state, b"Message 3")

        # Bob получает в обратном порядке: 3, 1, 2
        dec3 = bob_session.receive_message(bob_state, enc3)
        assert dec3 == b"Message 3"

        dec1 = bob_session.receive_message(bob_state, enc1)
        assert dec1 == b"Message 1"

        dec2 = bob_session.receive_message(bob_state, enc2)
        assert dec2 == b"Message 2"

    def test_skipped_messages_cached(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Пропущенные сообщения кешируются для последующей обработки."""
        alice_state, bob_state = established_session

        # Alice отправляет 5 сообщений
        messages = []
        for i in range(5):
            enc = alice_session.send_message(alice_state, f"Message {i}".encode())
            messages.append(enc)

        # Bob получает только 5-е (пропускает 1-4)
        bob_session.receive_message(bob_state, messages[4])

        # Кэш должен содержать ключи для 1-4
        assert len(bob_state.skipped_message_keys) == 4

        # Bob может расшифровать пропущенные
        for i in range(4):
            dec = bob_session.receive_message(bob_state, messages[i])
            assert dec == f"Message {i}".encode()

    def test_too_many_skipped_messages_raises_error(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Пропуск слишком многих сообщений должен вызывать ProtocolError."""
        alice_state, bob_state = established_session

        # Alice отправляет MAX_SKIP_MESSAGES + 1 сообщений
        for _ in range(MAX_SKIP_MESSAGES + 2):
            alice_session.send_message(alice_state, b"test")

        # Последнее сообщение
        final_enc = alice_session.send_message(alice_state, b"final")

        with pytest.raises(ProtocolError, match="Too many skipped messages"):
            bob_session.receive_message(bob_state, final_enc)

    def test_replay_message_raises_error(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Повторная отправка уже обработанного сообщения должна вызывать ProtocolError."""
        alice_state, bob_state = established_session

        # Alice отправляет
        enc = alice_session.send_message(alice_state, b"Message")

        # Bob получает первый раз
        bob_session.receive_message(bob_state, enc)

        # Bob пытается получить снова (replay attack)
        with pytest.raises(ProtocolError, match="Replay or already-processed message"):
            bob_session.receive_message(bob_state, enc)


# ==============================================================================
# LIMITS AND EDGE CASES TESTS
# ==============================================================================


class TestLimitsAndEdgeCases:
    """Тесты для лимитов и граничных случаев."""

    def test_max_ratchet_steps_exceeded_raises_error(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Превышение MAX_RATCHET_STEPS должно вызывать ProtocolError."""
        alice_state, bob_state = established_session

        # Искусственно установить счётчик на максимум
        alice_state.send_ratchet_count = MAX_RATCHET_STEPS

        with pytest.raises(ProtocolError, match="Max ratchet steps exceeded"):
            alice_session.send_message(alice_state, b"test")

    def test_skipped_cache_cleanup(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Очистка кэша пропущенных ключей при превышении лимита."""
        alice_state, bob_state = established_session

        # Искусственно заполнить кэш
        for i in range(MAX_SKIPPED_CACHE_SIZE + 50):
            bob_state.skipped_message_keys[i] = bytearray(32)

        # Отправить сообщение, которое инициирует cleanup
        enc = alice_session.send_message(alice_state, b"trigger cleanup")

        # Попытка получить должна вызвать cleanup
        bob_session.receive_message(bob_state, enc)

        # Кэш должен уменьшиться
        assert len(bob_state.skipped_message_keys) <= MAX_SKIPPED_CACHE_SIZE

    def test_large_plaintext_message(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Отправка и получение большого plaintext."""
        alice_state, bob_state = established_session
        large_plaintext = b"X" * 10000  # 10KB

        enc = alice_session.send_message(alice_state, large_plaintext)
        dec = bob_session.receive_message(bob_state, enc)

        assert dec == large_plaintext

    def test_unicode_plaintext_message(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Отправка и получение Unicode текста."""
        alice_state, bob_state = established_session
        unicode_plaintext = "Привет, мир! 🚀".encode("utf-8")

        enc = alice_session.send_message(alice_state, unicode_plaintext)
        dec = bob_session.receive_message(bob_state, enc)

        assert dec == unicode_plaintext
        assert dec.decode("utf-8") == "Привет, мир! 🚀"


# ==============================================================================
# SESSION INFO TESTS
# ==============================================================================


class TestSessionInfo:
    """Тесты для получения информации о сессии."""

    def test_session_info_basic(
        self,
        alice_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Получение базовой информации о сессии."""
        alice_state, _ = established_session

        info = alice_session.get_session_info(alice_state)

        assert isinstance(info, SessionInfo)
        assert info["session_id"] == alice_state.session_id
        assert info["is_initiator"] is True
        assert info["handshake_completed"] is True

        # Type-safe проверки для алгоритмов
        assert "kex_algorithm" in info
        assert isinstance(info["kex_algorithm"], str)
        assert "symmetric_algorithm" in info
        assert isinstance(info["symmetric_algorithm"], str)

    def test_session_info_after_messages(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Информация о сессии обновляется после обмена сообщениями."""
        alice_state, bob_state = established_session

        # Отправить несколько сообщений
        for _ in range(3):
            enc = alice_session.send_message(alice_state, b"test")
            bob_session.receive_message(bob_state, enc)

        alice_info = alice_session.get_session_info(alice_state)
        bob_info = bob_session.get_session_info(bob_state)

        assert alice_info["send_ratchet_count"] == 3
        assert bob_info["recv_ratchet_count"] == 3

    def test_session_info_no_secret_data(
        self,
        alice_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Информация о сессии не должна содержать секретных данных."""
        alice_state, _ = established_session

        info = alice_session.get_session_info(alice_state)

        # Проверяем, что нет чувствительных полей
        info_dict = dict(info)
        assert "send_chain_key" not in info_dict
        assert "recv_chain_key" not in info_dict
        assert "local_ephemeral_private" not in info_dict


# ==============================================================================
# SESSION DESTRUCTION TESTS
# ==============================================================================


class TestSessionDestruction:
    """Тесты для безопасного уничтожения сессии."""

    def test_destroy_session_clears_keys(
        self,
        alice_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Уничтожение сессии стирает все ключи."""
        alice_state, _ = established_session

        # Отправить сообщение для инициализации ключей
        alice_session.send_message(alice_state, b"test")

        # Уничтожить
        alice_session.destroy_session(alice_state)

        # Ключи должны быть стёрты
        assert len(alice_state.send_chain_key) == 0
        assert len(alice_state.recv_chain_key) == 0
        assert len(alice_state.local_ephemeral_private) == 0
        assert alice_state.local_ephemeral_public == b""
        assert len(alice_state.skipped_message_keys) == 0

    def test_destroy_session_with_skipped_keys(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Уничтожение сессии с кэшированными пропущенными ключами."""
        alice_state, bob_state = established_session

        # Создать пропущенные сообщения
        for i in range(5):
            alice_session.send_message(alice_state, f"Message {i}".encode())

        enc_last = alice_session.send_message(alice_state, b"Last")
        bob_session.receive_message(bob_state, enc_last)

        # Bob должен иметь 5 пропущенных ключей
        assert len(bob_state.skipped_message_keys) == 5

        # Уничтожить
        bob_session.destroy_session(bob_state)

        # Все ключи должны быть стёрты
        assert len(bob_state.skipped_message_keys) == 0


# ==============================================================================
# SECURITY PROPERTIES TESTS
# ==============================================================================


@pytest.mark.security
class TestSecurityProperties:
    """Тесты для проверки криптографических свойств безопасности."""

    def test_perfect_forward_secrecy(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Perfect Forward Secrecy: компрометация текущего ключа не раскрывает прошлые."""
        alice_state, bob_state = established_session

        # Отправить несколько сообщений
        messages = []
        encrypted = []
        for i in range(3):
            msg = f"Message {i}".encode()
            messages.append(msg)
            enc = alice_session.send_message(alice_state, msg)
            encrypted.append(enc)
            bob_session.receive_message(bob_state, enc)

        # Сохранить текущий chain key
        compromised_chain_key = bytes(alice_state.send_chain_key)

        # Отправить ещё одно сообщение
        alice_session.send_message(alice_state, b"Message 3")

        # Даже зная текущий chain key, нельзя расшифровать прошлые сообщения
        # (это концептуальный тест - в реальности требуется криптоанализ)
        assert compromised_chain_key != bytes(alice_state.send_chain_key)

    def test_post_compromise_security_via_dh_ratchet(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Post-Compromise Security: восстановление через DH ratchet."""
        alice_state, bob_state = established_session

        # Alice отправляет
        enc1 = alice_session.send_message(alice_state, b"Before compromise")
        bob_session.receive_message(bob_state, enc1)

        # Симулируем компрометацию chain key
        old_chain_key = bytes(alice_state.send_chain_key)

        # Bob отвечает (DH ratchet step)
        enc2 = bob_session.send_message(bob_state, b"After compromise")
        alice_session.receive_message(alice_state, enc2)

        # После DH ratchet chain key должен измениться
        new_chain_key = bytes(alice_state.send_chain_key)
        assert old_chain_key != new_chain_key

    def test_ephemeral_keys_change_on_dh_ratchet(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Ephemeral ключи изменяются при каждом DH ratchet step."""
        alice_state, bob_state = established_session

        alice_initial_eph = alice_state.local_ephemeral_public
        bob_initial_eph = bob_state.local_ephemeral_public

        # Alice → Bob
        enc1 = alice_session.send_message(alice_state, b"msg1")
        bob_session.receive_message(bob_state, enc1)

        # Bob → Alice (DH ratchet)
        enc2 = bob_session.send_message(bob_state, b"msg2")
        alice_session.receive_message(alice_state, enc2)

        # Alice → Bob (DH ratchet)
        enc3 = alice_session.send_message(alice_state, b"msg3")

        # Ephemeral ключи должны измениться
        assert alice_state.local_ephemeral_public != alice_initial_eph
        assert bob_state.local_ephemeral_public != bob_initial_eph

    def test_secure_memory_erase(
        self,
        alice_session: PFSSession,
        established_session: tuple[SessionState, SessionState],
    ) -> None:
        """Проверка безопасного стирания памяти."""
        alice_state, _ = established_session

        # Сохранить ссылку на старый chain key
        old_key_id = id(alice_state.send_chain_key)

        # Отправить сообщение (вызовет ratchet и erase)
        alice_session.send_message(alice_state, b"test")

        # ID должен остаться тем же (in-place erase), но содержимое изменится
        # (это концептуальная проверка - настоящая проверка требует memory dump)
        assert id(alice_state.send_chain_key) == old_key_id


# ==============================================================================
# INTEGRATION TESTS
# ==============================================================================


@pytest.mark.integration
class TestIntegration:
    """Интеграционные тесты для полных сценариев."""

    def test_full_conversation_scenario(
        self,
        alice_session: PFSSession,
        bob_session: PFSSession,
        alice_keypair: tuple[bytes, bytes],
        bob_keypair: tuple[bytes, bytes],
    ) -> None:
        """Полный сценарий: handshake → многостороннее общение → destroy."""
        alice_priv, alice_pub = alice_keypair
        bob_priv, bob_pub = bob_keypair

        # 1. Handshake
        alice_state, handshake = alice_session.initiate_session(
            alice_priv, alice_pub, bob_pub
        )
        bob_state, response = bob_session.accept_session(bob_priv, bob_pub, handshake)
        alice_session.complete_handshake(alice_state, response)

        # 2. Conversation
        conversation = [
            (alice_session, alice_state, b"Hello, Bob!"),
            (bob_session, bob_state, b"Hi, Alice! How are you?"),
            (alice_session, alice_state, b"I'm good, thanks!"),
            (bob_session, bob_state, b"Great to hear!"),
        ]

        for sender_session, sender_state, message in conversation:
            enc = sender_session.send_message(sender_state, message)

            # Определить получателя
            if sender_session is alice_session:
                receiver_session = bob_session
                receiver_state = bob_state
            else:
                receiver_session = alice_session
                receiver_state = alice_state

            dec = receiver_session.receive_message(receiver_state, enc)
            assert dec == message

        # 3. Destroy
        alice_session.destroy_session(alice_state)
        bob_session.destroy_session(bob_state)

        assert len(alice_state.send_chain_key) == 0
        assert len(bob_state.send_chain_key) == 0

    def test_multiple_parallel_sessions(self) -> None:
        """Параллельные сессии между разными парами участников."""
        # Alice ↔ Bob
        alice_bob_session1 = PFSSession()
        alice_bob_session2 = PFSSession()
        alice_priv1, alice_pub1 = alice_bob_session1.generate_identity_keypair()
        bob_priv1, bob_pub1 = alice_bob_session2.generate_identity_keypair()

        alice_state1, handshake1 = alice_bob_session1.initiate_session(
            alice_priv1, alice_pub1, bob_pub1
        )
        bob_state1, response1 = alice_bob_session2.accept_session(
            bob_priv1, bob_pub1, handshake1
        )
        alice_bob_session1.complete_handshake(alice_state1, response1)

        # Alice ↔ Charlie
        alice_charlie_session1 = PFSSession()
        alice_charlie_session2 = PFSSession()
        alice_priv2, alice_pub2 = alice_charlie_session1.generate_identity_keypair()
        charlie_priv, charlie_pub = alice_charlie_session2.generate_identity_keypair()

        alice_state2, handshake2 = alice_charlie_session1.initiate_session(
            alice_priv2, alice_pub2, charlie_pub
        )
        charlie_state, response2 = alice_charlie_session2.accept_session(
            charlie_priv, charlie_pub, handshake2
        )
        alice_charlie_session1.complete_handshake(alice_state2, response2)

        # Проверка независимости сессий
        assert alice_state1.session_id != alice_state2.session_id

        # Сообщения в обеих сессиях
        enc1 = alice_bob_session1.send_message(alice_state1, b"To Bob")
        enc2 = alice_charlie_session1.send_message(alice_state2, b"To Charlie")

        dec1 = alice_bob_session2.receive_message(bob_state1, enc1)
        dec2 = alice_charlie_session2.receive_message(charlie_state, enc2)

        assert dec1 == b"To Bob"
        assert dec2 == b"To Charlie"


# ==============================================================================
# GROUP 1: Dataclass __post_init__ validation
# Lines: 166, 194, 261, 263, 267, 269
# ==============================================================================


class TestDataclassValidationCoverage:
    """Покрывает непокрытые ветки __post_init__ в датаклассах."""

    # --- SessionHandshake (line 166) ---

    def test_session_handshake_empty_ephemeral_public_raises(self) -> None:
        """Строка 166: пустой initiator_ephemeral_public → ValueError."""
        with pytest.raises(
            ValueError, match="initiator_ephemeral_public cannot be empty"
        ):
            SessionHandshake(
                session_id="test",
                initiator_identity_public=b"key",
                initiator_ephemeral_public=b"",  # ← line 166
                hkdf_salt=secrets.token_bytes(HKDF_SALT_SIZE),
            )

    # --- SessionHandshakeResponse (line 194) ---

    def test_session_handshake_response_empty_ephemeral_raises(self) -> None:
        """Строка 194: пустой responder_ephemeral_public → ValueError."""
        with pytest.raises(
            ValueError, match="responder_ephemeral_public cannot be empty"
        ):
            SessionHandshakeResponse(
                session_id="test",
                responder_ephemeral_public=b"",  # ← line 194
            )

    # --- EncryptedSessionMessage (lines 261, 263, 267, 269) ---

    def test_encrypted_message_empty_ciphertext_raises(self) -> None:
        """Строка 261: пустой ciphertext → ValueError."""
        with pytest.raises(ValueError, match="ciphertext cannot be empty"):
            EncryptedSessionMessage(
                ciphertext=b"",  # ← line 261
                nonce=b"nonce",
                send_ratchet_count=1,
                dh_send_count=1,
                sender_ephemeral_public=b"key",
            )

    def test_encrypted_message_empty_nonce_raises(self) -> None:
        """Строка 263: пустой nonce → ValueError."""
        with pytest.raises(ValueError, match="nonce cannot be empty"):
            EncryptedSessionMessage(
                ciphertext=b"data",
                nonce=b"",  # ← line 263
                send_ratchet_count=1,
                dh_send_count=1,
                sender_ephemeral_public=b"key",
            )

    def test_encrypted_message_negative_dh_send_count_raises(self) -> None:
        """Строка 267: отрицательный dh_send_count → ValueError."""
        with pytest.raises(ValueError, match="dh_send_count cannot be negative"):
            EncryptedSessionMessage(
                ciphertext=b"data",
                nonce=b"nonce",
                send_ratchet_count=1,
                dh_send_count=-1,  # ← line 267
                sender_ephemeral_public=b"key",
            )

    def test_encrypted_message_empty_sender_ephemeral_raises(self) -> None:
        """Строка 269: пустой sender_ephemeral_public → ValueError."""
        with pytest.raises(ValueError, match="sender_ephemeral_public cannot be empty"):
            EncryptedSessionMessage(
                ciphertext=b"data",
                nonce=b"nonce",
                send_ratchet_count=1,
                dh_send_count=1,
                sender_ephemeral_public=b"",  # ← line 269
            )


# ==============================================================================
# GROUP 2: generate_identity_keypair exception path — Lines: 397-398
# ==============================================================================


class TestGenerateKeypairExceptionPath:

    def test_keypair_generation_failure_raises_crypto_error(
        self, session: PFSSession, mocker: MockerFixture
    ) -> None:
        """Строки 397-398: сбой _kex.generate_keypair → CryptoError."""
        mocker.patch.object(
            session._kex,
            "generate_keypair",
            side_effect=RuntimeError("hardware failure"),
        )
        with pytest.raises(CryptoError, match="Identity keypair generation failed"):
            session.generate_identity_keypair()


# ==============================================================================
# GROUP 3: initiate_session input validation — Lines: 432, 434
# ==============================================================================


class TestInitiateSessionValidation:

    def test_initiate_empty_local_public_key_raises(self, session: PFSSession) -> None:
        """Строка 432: пустой local_public_key → ValueError."""
        priv, _ = session.generate_identity_keypair()
        _, remote_pub = session.generate_identity_keypair()

        with pytest.raises(ValueError, match="Local public key cannot be empty"):
            session.initiate_session(
                local_private_key=priv,
                local_public_key=b"",  # ← line 432
                remote_public_key=remote_pub,
            )

    def test_initiate_empty_remote_public_key_raises(self, session: PFSSession) -> None:
        """Строка 434: пустой remote_public_key → ValueError."""
        priv, pub = session.generate_identity_keypair()

        with pytest.raises(ValueError, match="Remote public key cannot be empty"):
            session.initiate_session(
                local_private_key=priv,
                local_public_key=pub,
                remote_public_key=b"",  # ← line 434
            )


# ==============================================================================
# GROUP 4: initiate_session generic exception — Lines: 480-483
# ==============================================================================


class TestInitiateSessionExceptionPath:

    def test_initiate_session_kex_failure_raises_crypto_error(
        self, session: PFSSession, mocker: MockerFixture
    ) -> None:
        """Строки 480-483: сбой derive_shared_secret → CryptoError."""
        priv, pub = session.generate_identity_keypair()
        _, remote_pub = session.generate_identity_keypair()

        mocker.patch.object(
            session._kex,
            "derive_shared_secret",
            side_effect=RuntimeError("kex internal error"),
        )

        with pytest.raises(CryptoError, match="Session initiation failed"):
            session.initiate_session(
                local_private_key=priv,
                local_public_key=pub,
                remote_public_key=remote_pub,
            )


# ==============================================================================
# GROUP 5: accept_session input validation — Lines: 517, 521
# ==============================================================================


class TestAcceptSessionValidation:

    def test_accept_empty_local_public_key_raises(self, session: PFSSession) -> None:
        """Строка 517: пустой local_public_key → ValueError."""
        initiator = PFSSession()
        a_priv, a_pub = initiator.generate_identity_keypair()
        b_priv, b_pub = session.generate_identity_keypair()
        _, handshake = initiator.initiate_session(a_priv, a_pub, b_pub)

        with pytest.raises(ValueError, match="Local public key cannot be empty"):
            session.accept_session(
                local_private_key=b_priv,
                local_public_key=b"",  # ← line 517
                handshake=handshake,
            )

    def test_accept_none_handshake_raises(self, session: PFSSession) -> None:
        """Строка 521: handshake=None → ValueError."""
        priv, pub = session.generate_identity_keypair()

        with pytest.raises(ValueError, match="Handshake cannot be None"):
            session.accept_session(
                local_private_key=priv,
                local_public_key=pub,
                handshake=None,  # type: ignore[arg-type]
                # ← line 521
            )


# ==============================================================================
# GROUP 6: accept_session generic exception — Lines: 564-567
# ==============================================================================


class TestAcceptSessionExceptionPath:

    def test_accept_session_kex_failure_raises_crypto_error(
        self, session: PFSSession, mocker: MockerFixture
    ) -> None:
        """Строки 564-567: сбой derive_shared_secret → CryptoError."""
        initiator = PFSSession()
        a_priv, a_pub = initiator.generate_identity_keypair()
        b_priv, b_pub = session.generate_identity_keypair()
        _, handshake = initiator.initiate_session(a_priv, a_pub, b_pub)

        mocker.patch.object(
            session._kex,
            "derive_shared_secret",
            side_effect=RuntimeError("kex accept error"),
        )

        with pytest.raises(CryptoError, match="Session acceptance failed"):
            session.accept_session(
                local_private_key=b_priv,
                local_public_key=b_pub,
                handshake=handshake,
            )


# ==============================================================================
# GROUP 7: send_message generic exception — Lines: 696-699
# ==============================================================================


class TestSendMessageExceptionPath:

    def test_send_message_cipher_failure_raises_encryption_error(
        self, mocker: MockerFixture
    ) -> None:
        """Строки 696-699: сбой _cipher.encrypt → EncryptionError."""
        alice_session = PFSSession()
        bob_session = PFSSession()
        a_priv, a_pub = alice_session.generate_identity_keypair()
        b_priv, b_pub = bob_session.generate_identity_keypair()
        alice_state, handshake = alice_session.initiate_session(a_priv, a_pub, b_pub)
        bob_state, response = bob_session.accept_session(b_priv, b_pub, handshake)
        alice_session.complete_handshake(alice_state, response)

        mocker.patch.object(
            alice_session._cipher,
            "encrypt",
            side_effect=RuntimeError("cipher hardware fault"),
        )

        with pytest.raises(EncryptionError, match="Session send failed"):
            alice_session.send_message(alice_state, b"test message")
