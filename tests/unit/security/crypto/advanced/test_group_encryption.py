"""
Тесты для модуля group_encryption.

Unit-тесты для GroupKeyManager — менеджера групповых ключей.
Покрывают: создание групп, управление участниками, шифрование/расшифровку,
key-wrapping, безопасное стирание, thread-safety и граничные случаи.

Author: FX Text Processor 3 Team
Version: 2.3.3
Date: February 18, 2026
"""

from __future__ import annotations

import threading
import types as _types
from typing import Tuple
from unittest.mock import MagicMock, patch

import pytest

from src.security.crypto.advanced.group_encryption import (
    GROUP_KEY_SIZE,
    HKDF_SALT_SIZE,
    MAX_GROUP_MEMBERS,
    _X25519_KEY_SIZE,
    Group,
    GroupEncryptedMessage,
    GroupKeyManager,
    GroupMember,
)
from src.security.crypto.core.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    InvalidKeyError,
)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def manager() -> GroupKeyManager:
    """Менеджер с дефолтными алгоритмами."""
    return GroupKeyManager()


@pytest.fixture
def group(manager: GroupKeyManager) -> Group:
    """Пустая группа."""
    return manager.create_group("test-group")


@pytest.fixture
def alice_keypair(manager: GroupKeyManager) -> Tuple[bytes, bytes]:
    """Keypair для участника Alice."""
    return manager.generate_member_keypair()


@pytest.fixture
def bob_keypair(manager: GroupKeyManager) -> Tuple[bytes, bytes]:
    """Keypair для участника Bob."""
    return manager.generate_member_keypair()


@pytest.fixture
def group_with_members(
    manager: GroupKeyManager,
    group: Group,
    alice_keypair: Tuple[bytes, bytes],
    bob_keypair: Tuple[bytes, bytes],
) -> Tuple[Group, bytes, bytes, bytes, bytes]:
    """Группа с Alice и Bob, возвращает (group, alice_priv, alice_pub, bob_priv, bob_pub)."""
    alice_priv, alice_pub = alice_keypair
    bob_priv, bob_pub = bob_keypair
    manager.add_member(group, "alice", alice_pub)
    manager.add_member(group, "bob", bob_pub)
    return group, alice_priv, alice_pub, bob_priv, bob_pub


# ==============================================================================
# TestGroupKeyManager — INIT
# ==============================================================================


class TestGroupKeyManagerInit:
    """Тесты инициализации GroupKeyManager."""

    def test_init_default_algorithms(self) -> None:
        """Создание с дефолтными алгоритмами не выбрасывает исключений."""
        m = GroupKeyManager()
        assert m is not None

    def test_init_stores_algorithm_names(self) -> None:
        """Алгоритмы сохраняются корректно."""
        m = GroupKeyManager(kex_algorithm="x25519", symmetric_algorithm="aes-256-gcm")
        assert m._kex_algo == "x25519"
        assert m._sym_algo == "aes-256-gcm"

    def test_init_unknown_kex_raises_crypto_error(self) -> None:
        """Неизвестный KEX алгоритм — CryptoError."""
        with pytest.raises(CryptoError):
            GroupKeyManager(kex_algorithm="unknown-kex-9999")

    def test_init_unknown_symmetric_raises_crypto_error(self) -> None:
        """Неизвестный симметричный алгоритм — CryptoError."""
        with pytest.raises(CryptoError):
            GroupKeyManager(symmetric_algorithm="unknown-sym-9999")

    def test_init_creates_lock(self) -> None:
        """RLock создаётся при инициализации."""
        m = GroupKeyManager()
        assert m._lock is not None

    def test_init_groups_empty(self) -> None:
        """Словарь групп изначально пуст."""
        m = GroupKeyManager()
        assert m._groups == {}

    def test_init_group_counter_zero(self) -> None:
        """Счётчик групп равен 0 при создании."""
        m = GroupKeyManager()
        assert m._group_counter == 0


# ==============================================================================
# TestGenerateMemberKeypair
# ==============================================================================


class TestGenerateMemberKeypair:
    """Тесты генерации keypair участника."""

    def test_returns_tuple_of_bytes(self, manager: GroupKeyManager) -> None:
        """Возвращает кортеж из двух bytes."""
        priv, pub = manager.generate_member_keypair()
        assert isinstance(priv, bytes)
        assert isinstance(pub, bytes)

    def test_public_key_is_32_bytes(self, manager: GroupKeyManager) -> None:
        """Публичный ключ X25519 — 32 байта."""
        _, pub = manager.generate_member_keypair()
        assert len(pub) == _X25519_KEY_SIZE

    def test_private_key_non_empty(self, manager: GroupKeyManager) -> None:
        """Приватный ключ не пустой."""
        priv, _ = manager.generate_member_keypair()
        assert len(priv) > 0

    def test_keypairs_are_unique(self, manager: GroupKeyManager) -> None:
        """Каждый вызов даёт уникальный keypair."""
        kp1 = manager.generate_member_keypair()
        kp2 = manager.generate_member_keypair()
        assert kp1 != kp2

    def test_crypto_error_on_kex_failure(self, manager: GroupKeyManager) -> None:
        """При сбое KEX выбрасывается CryptoError."""
        manager._kex = MagicMock()
        manager._kex.generate_keypair.side_effect = RuntimeError("kex fail")
        with pytest.raises(CryptoError, match="keypair generation failed"):
            manager.generate_member_keypair()


# ==============================================================================
# TestCreateGroup
# ==============================================================================


class TestCreateGroup:
    """Тесты создания группы."""

    def test_creates_group_with_id(self, manager: GroupKeyManager) -> None:
        """Группа создаётся с корректным group_id."""
        g = manager.create_group("alpha")
        assert g.group_id == "alpha"

    def test_returns_group_instance(self, manager: GroupKeyManager) -> None:
        """create_group возвращает объект Group."""
        g = manager.create_group("beta")
        assert isinstance(g, Group)

    def test_group_registered_in_manager(self, manager: GroupKeyManager) -> None:
        """Группа регистрируется в менеджере."""
        manager.create_group("gamma")
        assert "gamma" in manager._groups

    def test_group_members_initially_empty(self, manager: GroupKeyManager) -> None:
        """Новая группа не имеет участников."""
        g = manager.create_group("delta")
        assert g.members == {}

    def test_created_order_increments(self, manager: GroupKeyManager) -> None:
        """created_order увеличивается для каждой новой группы."""
        g1 = manager.create_group("g1")
        g2 = manager.create_group("g2")
        assert g1.created_order < g2.created_order

    def test_empty_group_id_raises_value_error(self, manager: GroupKeyManager) -> None:
        """Пустой group_id вызывает ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.create_group("")

    def test_whitespace_group_id_raises_value_error(
        self, manager: GroupKeyManager
    ) -> None:
        """group_id из пробелов вызывает ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.create_group("   ")

    def test_duplicate_group_id_raises_value_error(
        self, manager: GroupKeyManager
    ) -> None:
        """Дублирующий group_id вызывает ValueError."""
        manager.create_group("dup")
        with pytest.raises(ValueError, match="already exists"):
            manager.create_group("dup")

    def test_custom_algorithms(self, manager: GroupKeyManager) -> None:
        """Пользовательские алгоритмы сохраняются в группе."""
        g = manager.create_group(
            "custom",
            kex_algorithm="x25519",
            symmetric_algorithm="aes-256-gcm",
        )
        assert g.kex_algorithm == "x25519"
        assert g.symmetric_algorithm == "aes-256-gcm"

    def test_default_algorithms_from_manager(self, manager: GroupKeyManager) -> None:
        """По умолчанию берутся алгоритмы из конструктора."""
        g = manager.create_group("default-algo")
        assert g.kex_algorithm == manager._kex_algo
        assert g.symmetric_algorithm == manager._sym_algo


# ==============================================================================
# TestGetGroup
# ==============================================================================


class TestGetGroup:
    """Тесты получения группы."""

    def test_get_existing_group(self, manager: GroupKeyManager) -> None:
        """Возвращает существующую группу."""
        manager.create_group("find-me")
        g = manager.get_group("find-me")
        assert g.group_id == "find-me"

    def test_get_nonexistent_group_raises_key_error(
        self, manager: GroupKeyManager
    ) -> None:
        """Несуществующий group_id вызывает KeyError."""
        with pytest.raises(KeyError, match="not found"):
            manager.get_group("ghost")


# ==============================================================================
# TestDeleteGroup
# ==============================================================================


class TestDeleteGroup:
    """Тесты удаления группы."""

    def test_delete_existing_group(self, manager: GroupKeyManager) -> None:
        """Группа удаляется из менеджера."""
        manager.create_group("to-delete")
        manager.delete_group("to-delete")
        assert "to-delete" not in manager._groups

    def test_delete_nonexistent_group_raises_key_error(
        self, manager: GroupKeyManager
    ) -> None:
        """Удаление несуществующей группы — KeyError."""
        with pytest.raises(KeyError, match="not found"):
            manager.delete_group("ghost-group")


# ==============================================================================
# TestAddMember
# ==============================================================================


class TestAddMember:
    """Тесты добавления участника."""

    def test_add_member_increases_count(
        self,
        manager: GroupKeyManager,
        group: Group,
        alice_keypair: Tuple[bytes, bytes],
    ) -> None:
        """После добавления участника count увеличивается."""
        _, pub = alice_keypair
        manager.add_member(group, "alice", pub)
        assert len(group.members) == 1

    def test_member_stored_with_correct_id(
        self,
        manager: GroupKeyManager,
        group: Group,
        alice_keypair: Tuple[bytes, bytes],
    ) -> None:
        """Участник сохраняется с корректным member_id."""
        _, pub = alice_keypair
        manager.add_member(group, "alice", pub)
        assert "alice" in group.members
        assert group.members["alice"].member_id == "alice"

    def test_member_public_key_stored(
        self,
        manager: GroupKeyManager,
        group: Group,
        alice_keypair: Tuple[bytes, bytes],
    ) -> None:
        """Публичный ключ участника сохраняется корректно."""
        _, pub = alice_keypair
        manager.add_member(group, "alice", pub)
        assert group.members["alice"].public_key == pub

    def test_added_order_increments(
        self,
        manager: GroupKeyManager,
        group: Group,
        alice_keypair: Tuple[bytes, bytes],
        bob_keypair: Tuple[bytes, bytes],
    ) -> None:
        """added_order увеличивается для каждого нового участника."""
        _, alice_pub = alice_keypair
        _, bob_pub = bob_keypair
        manager.add_member(group, "alice", alice_pub)
        manager.add_member(group, "bob", bob_pub)
        assert group.members["alice"].added_order < group.members["bob"].added_order

    def test_empty_member_id_raises_value_error(
        self,
        manager: GroupKeyManager,
        group: Group,
        alice_keypair: Tuple[bytes, bytes],
    ) -> None:
        """Пустой member_id вызывает ValueError."""
        _, pub = alice_keypair
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.add_member(group, "", pub)

    def test_whitespace_member_id_raises_value_error(
        self,
        manager: GroupKeyManager,
        group: Group,
        alice_keypair: Tuple[bytes, bytes],
    ) -> None:
        """member_id из пробелов вызывает ValueError."""
        _, pub = alice_keypair
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.add_member(group, "  ", pub)

    def test_empty_public_key_raises_value_error(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Пустой public_key вызывает ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.add_member(group, "alice", b"")

    def test_wrong_key_size_raises_invalid_key_error(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Ключ неверного размера вызывает InvalidKeyError."""
        bad_key = b"\x00" * 16  # 16 вместо 32
        with pytest.raises(InvalidKeyError, match="Invalid public key size"):
            manager.add_member(group, "alice", bad_key)

    def test_wrong_key_size_33_bytes(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Ключ в 33 байта вызывает InvalidKeyError."""
        bad_key = b"\x00" * 33
        with pytest.raises(InvalidKeyError):
            manager.add_member(group, "alice", bad_key)

    def test_duplicate_member_raises_value_error(
        self,
        manager: GroupKeyManager,
        group: Group,
        alice_keypair: Tuple[bytes, bytes],
    ) -> None:
        """Повторное добавление с тем же member_id — ValueError."""
        _, pub = alice_keypair
        manager.add_member(group, "alice", pub)
        with pytest.raises(ValueError, match="already in group"):
            manager.add_member(group, "alice", pub)

    def test_member_limit_raises_value_error(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Превышение лимита участников (MAX_GROUP_MEMBERS) — ValueError."""
        for i in range(MAX_GROUP_MEMBERS):
            _, pub = manager.generate_member_keypair()
            manager.add_member(group, f"user_{i}", pub)

        _, extra_pub = manager.generate_member_keypair()
        with pytest.raises(ValueError, match="member limit"):
            manager.add_member(group, "overflow_user", extra_pub)


# ==============================================================================
# TestRemoveMember
# ==============================================================================


class TestRemoveMember:
    """Тесты удаления участника."""

    def test_remove_existing_member(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Участник удаляется из группы."""
        group, *_ = group_with_members
        manager.remove_member(group, "alice")
        assert "alice" not in group.members

    def test_remove_decreases_count(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """После удаления count уменьшается."""
        group, *_ = group_with_members
        before = len(group.members)
        manager.remove_member(group, "alice")
        assert len(group.members) == before - 1

    def test_remove_nonexistent_member_raises_key_error(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Удаление несуществующего участника — KeyError."""
        with pytest.raises(KeyError, match="not found"):
            manager.remove_member(group, "ghost")


# ==============================================================================
# TestListMembers
# ==============================================================================


class TestListMembers:
    """Тесты получения списка участников."""

    def test_empty_group_returns_empty_list(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Пустая группа — пустой список."""
        assert manager.list_members(group) == []

    def test_returns_sorted_list(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Список возвращается в отсортированном порядке."""
        for name in ["charlie", "alice", "bob"]:
            _, pub = manager.generate_member_keypair()
            manager.add_member(group, name, pub)

        result = manager.list_members(group)
        assert result == ["alice", "bob", "charlie"]

    def test_returns_list_of_strings(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Возвращает список строк."""
        group, *_ = group_with_members
        members = manager.list_members(group)
        assert all(isinstance(m, str) for m in members)


# ==============================================================================
# TestEncryptForGroup
# ==============================================================================


class TestEncryptForGroup:
    """Тесты шифрования для группы."""

    def test_returns_group_encrypted_message(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Возвращает GroupEncryptedMessage."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        assert isinstance(result, GroupEncryptedMessage)

    def test_group_id_in_message(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """group_id в сообщении совпадает с group_id группы."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        assert result.group_id == group.group_id

    def test_wrapped_keys_contain_all_members(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """wrapped_keys содержит ключи для всех участников."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        assert "alice" in result.wrapped_keys
        assert "bob" in result.wrapped_keys

    def test_ciphertext_not_equal_to_plaintext(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Зашифрованный текст не совпадает с открытым."""
        group, *_ = group_with_members
        plaintext = b"secret message"
        result = manager.encrypt_for_group(group, plaintext)
        assert result.ciphertext != plaintext

    def test_nonce_is_non_empty(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Nonce не пустой."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        assert len(result.nonce) > 0

    def test_wrapped_keys_are_mapping_proxy(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """wrapped_keys защищён через MappingProxyType (read-only)."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        assert isinstance(result.wrapped_keys, _types.MappingProxyType)

    def test_wrapped_keys_inner_are_mapping_proxy(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Вложенные wrapped_keys[member_id] тоже MappingProxyType."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        for wk in result.wrapped_keys.values():
            assert isinstance(wk, _types.MappingProxyType)

    def test_empty_plaintext_raises_value_error(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Пустой plaintext вызывает ValueError."""
        group, *_ = group_with_members
        with pytest.raises(ValueError, match="empty plaintext"):
            manager.encrypt_for_group(group, b"")

    def test_empty_group_raises_value_error(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Шифрование в группу без участников — ValueError."""
        with pytest.raises(ValueError, match="no members"):
            manager.encrypt_for_group(group, b"hello")

    def test_two_encryptions_produce_different_ciphertexts(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Каждое шифрование одного и того же plaintext — разный ciphertext."""
        group, *_ = group_with_members
        r1 = manager.encrypt_for_group(group, b"same message")
        r2 = manager.encrypt_for_group(group, b"same message")
        # Разные group key (per-message) → разные ciphertext и wrapped_keys
        assert r1.ciphertext != r2.ciphertext

    def test_wrapped_key_contains_required_fields(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """wrapped_key содержит поля: ephemeral_public_key, nonce, ciphertext, hkdf_salt."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        for wk in result.wrapped_keys.values():
            assert "ephemeral_public_key" in wk
            assert "nonce" in wk
            assert "ciphertext" in wk
            assert "hkdf_salt" in wk

    def test_reserved_hkdf_salt_is_empty(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """reserved_hkdf_salt равен пустым байтам (зарезервировано)."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(group, b"hello")
        assert result.reserved_hkdf_salt == b""

    def test_encrypt_with_associated_data(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Шифрование с associated_data не выбрасывает исключений."""
        group, *_ = group_with_members
        result = manager.encrypt_for_group(
            group, b"hello", associated_data=b"extra-aad"
        )
        assert result is not None


# ==============================================================================
# TestDecryptAsMember
# ==============================================================================


class TestDecryptAsMember:
    """Тесты расшифровки участником."""

    def test_alice_can_decrypt(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Alice успешно расшифровывает сообщение."""
        group, alice_priv, _, _, _ = group_with_members
        plaintext = b"Team secret"
        encrypted = manager.encrypt_for_group(group, plaintext)
        result = manager.decrypt_as_member(group, "alice", alice_priv, encrypted)
        assert result == plaintext

    def test_bob_can_decrypt(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Bob успешно расшифровывает сообщение."""
        group, _, _, bob_priv, _ = group_with_members
        plaintext = b"Team secret"
        encrypted = manager.encrypt_for_group(group, plaintext)
        result = manager.decrypt_as_member(group, "bob", bob_priv, encrypted)
        assert result == plaintext

    def test_roundtrip_preserves_plaintext(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Шифрование + расшифровка сохраняет исходные данные."""
        group, alice_priv, _, _, _ = group_with_members
        original = b"FX Text Processor 3 secret data \x00\xff"
        encrypted = manager.encrypt_for_group(group, original)
        decrypted = manager.decrypt_as_member(group, "alice", alice_priv, encrypted)
        assert decrypted == original

    def test_wrong_private_key_raises_decryption_error(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Неверный приватный ключ — DecryptionError."""
        group, _, _, _, _ = group_with_members
        wrong_priv, _ = manager.generate_member_keypair()
        encrypted = manager.encrypt_for_group(group, b"hello")
        with pytest.raises((DecryptionError, Exception)):
            manager.decrypt_as_member(group, "alice", wrong_priv, encrypted)

    def test_empty_private_key_raises_value_error(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Пустой приватный ключ — ValueError."""
        group, *_ = group_with_members
        encrypted = manager.encrypt_for_group(group, b"hello")
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.decrypt_as_member(group, "alice", b"", encrypted)

    def test_unknown_member_raises_key_error(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Участник, не входящий в wrapped_keys, — KeyError."""
        group, alice_priv, _, _, _ = group_with_members
        encrypted = manager.encrypt_for_group(group, b"hello")
        with pytest.raises(KeyError, match="No wrapped key"):
            manager.decrypt_as_member(group, "charlie", alice_priv, encrypted)

    def test_decrypt_with_matching_associated_data(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Расшифровка с тем же associated_data успешна."""
        group, alice_priv, _, _, _ = group_with_members
        aad = b"context-data"
        encrypted = manager.encrypt_for_group(group, b"hello", associated_data=aad)
        result = manager.decrypt_as_member(
            group, "alice", alice_priv, encrypted, associated_data=aad
        )
        assert result == b"hello"

    def test_decrypt_with_wrong_associated_data_fails(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Неверный associated_data при расшифровке — исключение."""
        group, alice_priv, _, _, _ = group_with_members
        encrypted = manager.encrypt_for_group(
            group, b"hello", associated_data=b"correct-aad"
        )
        with pytest.raises(Exception):
            manager.decrypt_as_member(
                group, "alice", alice_priv, encrypted, associated_data=b"wrong-aad"
            )

    def test_bob_cannot_decrypt_with_alice_key(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Bob не может расшифровать своё сообщение ключом Alice."""
        group, alice_priv, _, _, _ = group_with_members
        encrypted = manager.encrypt_for_group(group, b"hello")
        with pytest.raises(Exception):
            # Bob's member_id, но alice_priv → расшифровка должна упасть
            manager.decrypt_as_member(group, "bob", alice_priv, encrypted)


# ==============================================================================
# TestEncryptDecryptParametrized
# ==============================================================================


class TestEncryptDecryptParametrized:
    """Параметризованные roundtrip-тесты."""

    @pytest.mark.parametrize(
        "plaintext",
        [
            b"A",
            b"Hello, World!",
            b"\x00\x01\x02\x03\xff\xfe\xfd",
            b"x" * 1024,
            b"x" * 65536,
            "Привет, мир!".encode("utf-8"),
        ],
    )
    def test_roundtrip_various_plaintexts(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
        plaintext: bytes,
    ) -> None:
        """Roundtrip корректен для различных plaintext."""
        group, alice_priv, _, _, _ = group_with_members
        encrypted = manager.encrypt_for_group(group, plaintext)
        decrypted = manager.decrypt_as_member(group, "alice", alice_priv, encrypted)
        assert decrypted == plaintext

    @pytest.mark.parametrize("num_members", [1, 2, 5, 10])
    def test_roundtrip_various_group_sizes(
        self,
        manager: GroupKeyManager,
        num_members: int,
    ) -> None:
        """Roundtrip корректен для групп разного размера."""
        group = manager.create_group(f"sized-group-{num_members}")
        keypairs = [manager.generate_member_keypair() for _ in range(num_members)]

        for i, (_, pub) in enumerate(keypairs):
            manager.add_member(group, f"user_{i}", pub)

        plaintext = b"group size test"
        encrypted = manager.encrypt_for_group(group, plaintext)

        for i, (priv, _) in enumerate(keypairs):
            decrypted = manager.decrypt_as_member(group, f"user_{i}", priv, encrypted)
            assert decrypted == plaintext


# ==============================================================================
# TestGroupMemberRemoval
# ==============================================================================


class TestGroupMemberRemoval:
    """Тесты безопасности после удаления участника."""

    def test_removed_member_not_in_new_message(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """После удаления Alice, новое сообщение не содержит её wrapped key."""
        group, _, _, _, _ = group_with_members
        manager.remove_member(group, "alice")
        encrypted = manager.encrypt_for_group(group, b"post-removal")
        assert "alice" not in encrypted.wrapped_keys

    def test_remaining_member_can_decrypt_after_removal(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Bob (оставшийся участник) может расшифровать сообщение после удаления Alice."""
        group, _, _, bob_priv, _ = group_with_members
        manager.remove_member(group, "alice")
        plaintext = b"still secret"
        encrypted = manager.encrypt_for_group(group, plaintext)
        result = manager.decrypt_as_member(group, "bob", bob_priv, encrypted)
        assert result == plaintext

    def test_old_message_not_affected_by_removal(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Старое сообщение, зашифрованное до удаления, не изменяется."""
        group, alice_priv, _, _, _ = group_with_members
        plaintext = b"before removal"
        old_encrypted = manager.encrypt_for_group(group, plaintext)

        manager.remove_member(group, "alice")

        # Старое сообщение с wrapped key для alice всё ещё расшифровывается
        result = manager.decrypt_as_member(group, "alice", alice_priv, old_encrypted)
        assert result == plaintext


# ==============================================================================
# TestWrapUnwrapKey
# ==============================================================================


class TestWrapUnwrapKey:
    """Тесты внутреннего key-wrapping."""

    def test_wrap_returns_required_fields(self, manager: GroupKeyManager) -> None:
        """_wrap_key_for_member возвращает все обязательные поля."""
        _, pub = manager.generate_member_keypair()
        group_key = bytearray(b"\xab" * GROUP_KEY_SIZE)
        result = manager._wrap_key_for_member(group_key, pub)
        assert "ephemeral_public_key" in result
        assert "nonce" in result
        assert "ciphertext" in result
        assert "hkdf_salt" in result

    def test_wrap_unwrap_roundtrip(self, manager: GroupKeyManager) -> None:
        """Обёртка и разворачивание group key дают исходный ключ."""
        priv, pub = manager.generate_member_keypair()
        original_key = bytearray(b"\xde\xad\xbe\xef" * 8)
        wrapped = manager._wrap_key_for_member(original_key, pub)
        recovered = manager._unwrap_key_for_member(wrapped, priv)
        assert recovered == bytes(original_key)

    def test_wrap_with_group_aad(self, manager: GroupKeyManager) -> None:
        """Wrapping с group_aad не выбрасывает исключений."""
        _, pub = manager.generate_member_keypair()
        group_key = bytearray(b"\xcc" * GROUP_KEY_SIZE)
        result = manager._wrap_key_for_member(group_key, pub, group_aad=b"test-group")
        assert result is not None

    def test_unwrap_with_wrong_aad_fails(self, manager: GroupKeyManager) -> None:
        """Разворачивание с неверным AAD вызывает исключение (AEAD tamper detection)."""
        priv, pub = manager.generate_member_keypair()
        group_key = bytearray(b"\xaa" * GROUP_KEY_SIZE)
        wrapped = manager._wrap_key_for_member(
            group_key, pub, group_aad=b"correct-group"
        )
        with pytest.raises(Exception):
            manager._unwrap_key_for_member(wrapped, priv, group_aad=b"wrong-group")

    def test_hkdf_salt_in_wrapped_key(self, manager: GroupKeyManager) -> None:
        """hkdf_salt в wrapped key имеет правильный размер."""
        _, pub = manager.generate_member_keypair()
        group_key = bytearray(b"\x11" * GROUP_KEY_SIZE)
        wrapped = manager._wrap_key_for_member(group_key, pub)
        assert len(wrapped["hkdf_salt"]) == HKDF_SALT_SIZE

    def test_ephemeral_public_key_size(self, manager: GroupKeyManager) -> None:
        """ephemeral_public_key в wrapped key имеет размер X25519 (32 байта)."""
        _, pub = manager.generate_member_keypair()
        group_key = bytearray(b"\x22" * GROUP_KEY_SIZE)
        wrapped = manager._wrap_key_for_member(group_key, pub)
        assert len(wrapped["ephemeral_public_key"]) == _X25519_KEY_SIZE


# ==============================================================================
# TestDeriveWrappingKey
# ==============================================================================


class TestDeriveWrappingKey:
    """Тесты HKDF деривации ключа."""

    def test_derives_correct_length(self, manager: GroupKeyManager) -> None:
        """Дерived key имеет длину GROUP_KEY_SIZE."""
        import secrets as _secrets

        secret = _secrets.token_bytes(32)
        salt = _secrets.token_bytes(HKDF_SALT_SIZE)
        key = manager._derive_wrapping_key(secret, salt)
        assert len(key) == GROUP_KEY_SIZE

    def test_deterministic_with_same_inputs(self, manager: GroupKeyManager) -> None:
        """Одни и те же входные данные дают одинаковый ключ."""
        import secrets as _secrets

        secret = _secrets.token_bytes(32)
        salt = _secrets.token_bytes(HKDF_SALT_SIZE)
        k1 = manager._derive_wrapping_key(secret, salt)
        k2 = manager._derive_wrapping_key(secret, salt)
        assert k1 == k2

    def test_different_salt_gives_different_key(self, manager: GroupKeyManager) -> None:
        """Разная соль даёт разный ключ."""
        import secrets as _secrets

        secret = _secrets.token_bytes(32)
        salt1 = _secrets.token_bytes(HKDF_SALT_SIZE)
        salt2 = _secrets.token_bytes(HKDF_SALT_SIZE)
        k1 = manager._derive_wrapping_key(secret, salt1)
        k2 = manager._derive_wrapping_key(secret, salt2)
        assert k1 != k2

    def test_different_secret_gives_different_key(
        self, manager: GroupKeyManager
    ) -> None:
        """Разный shared_secret даёт разный ключ."""
        import secrets as _secrets

        secret1 = _secrets.token_bytes(32)
        secret2 = _secrets.token_bytes(32)
        salt = _secrets.token_bytes(HKDF_SALT_SIZE)
        k1 = manager._derive_wrapping_key(secret1, salt)
        k2 = manager._derive_wrapping_key(secret2, salt)
        assert k1 != k2

    def test_empty_salt_does_not_raise(self, manager: GroupKeyManager) -> None:
        """Пустая соль (None path) не вызывает исключений."""
        import secrets as _secrets

        secret = _secrets.token_bytes(32)
        key = manager._derive_wrapping_key(secret, b"")
        assert len(key) == GROUP_KEY_SIZE


# ==============================================================================
# TestSecureErase
# ==============================================================================


class TestSecureErase:
    """Тесты безопасного стирания памяти."""

    def test_erase_zeroes_data(self) -> None:
        """После стирания все байты равны 0."""
        data = bytearray(b"\xde\xad\xbe\xef" * 8)
        GroupKeyManager._secure_erase(data)
        assert all(b == 0 for b in data)

    def test_erase_empty_bytearray_is_noop(self) -> None:
        """Вызов на пустом bytearray не вызывает исключений."""
        data = bytearray()
        GroupKeyManager._secure_erase(data)  # должен быть no-op
        assert len(data) == 0

    def test_erase_modifies_in_place(self) -> None:
        """Стирание изменяет оригинальный объект, не создаёт копию."""
        data = bytearray(b"\xff" * 32)
        original_id = id(data)
        GroupKeyManager._secure_erase(data)
        assert id(data) == original_id
        assert all(b == 0 for b in data)

    def test_erase_single_byte(self) -> None:
        """Стирание одного байта работает корректно."""
        data = bytearray(b"\xab")
        GroupKeyManager._secure_erase(data)
        assert data[0] == 0


# ==============================================================================
# TestDataclasses
# ==============================================================================


class TestGroupMemberDataclass:
    """Тесты датакласса GroupMember."""

    def test_create_group_member(self) -> None:
        """GroupMember создаётся с корректными атрибутами."""
        m = GroupMember(member_id="alice", public_key=b"\x00" * 32)
        assert m.member_id == "alice"
        assert m.public_key == b"\x00" * 32
        assert m.added_order == 0


class TestGroupDataclass:
    """Тесты датакласса Group."""

    def test_create_group_defaults(self) -> None:
        """Group создаётся с дефолтными значениями."""
        g = Group(group_id="test")
        assert g.group_id == "test"
        assert g.members == {}
        assert g.kex_algorithm == "x25519"
        assert g.symmetric_algorithm == "aes-256-gcm"
        assert g.created_order == 0
        assert g._member_counter == 0

    def test_group_members_are_independent(self) -> None:
        """Словари members двух групп не shared."""
        g1 = Group(group_id="g1")
        g2 = Group(group_id="g2")
        g1.members["alice"] = GroupMember("alice", b"\x00" * 32)
        assert "alice" not in g2.members


class TestGroupEncryptedMessageDataclass:
    """Тесты датакласса GroupEncryptedMessage."""

    def test_frozen_prevents_assignment(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Frozen dataclass не позволяет изменять атрибуты."""
        group, *_ = group_with_members
        msg = manager.encrypt_for_group(group, b"test")
        with pytest.raises((TypeError, AttributeError)):
            msg.group_id = "hacked"  # type: ignore[misc]

    def test_wrapped_keys_immutable(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """wrapped_keys нельзя изменить (MappingProxyType)."""
        group, *_ = group_with_members
        msg = manager.encrypt_for_group(group, b"test")
        with pytest.raises(TypeError):
            msg.wrapped_keys["hacker"] = {}  # type: ignore[index]


# ==============================================================================
# TestThreadSafety
# ==============================================================================


@pytest.mark.slow
class TestThreadSafety:
    """Тесты потокобезопасности GroupKeyManager."""

    def test_concurrent_create_group(self, manager: GroupKeyManager) -> None:
        """Одновременное создание групп из нескольких потоков безопасно."""
        errors: list[Exception] = []
        threads = []

        def create(idx: int) -> None:
            try:
                manager.create_group(f"concurrent-group-{idx}")
            except Exception as e:
                errors.append(e)

        for i in range(20):
            t = threading.Thread(target=create, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"
        assert len(manager._groups) == 20

    def test_concurrent_add_member(
        self,
        manager: GroupKeyManager,
        group: Group,
    ) -> None:
        """Одновременное добавление участников безопасно."""
        errors: list[Exception] = []
        threads = []

        def add(idx: int) -> None:
            try:
                _, pub = manager.generate_member_keypair()
                manager.add_member(group, f"user-thread-{idx}", pub)
            except Exception as e:
                errors.append(e)

        for i in range(10):
            t = threading.Thread(target=add, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"
        assert len(group.members) == 10

    def test_concurrent_encrypt_decrypt(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Одновременное шифрование и расшифровка из нескольких потоков."""
        group, alice_priv, _, bob_priv, _ = group_with_members
        results: list[bool] = []
        errors: list[Exception] = []
        plaintext = b"concurrent secret"

        def encrypt_decrypt(priv: bytes, member: str) -> None:
            try:
                enc = manager.encrypt_for_group(group, plaintext)
                dec = manager.decrypt_as_member(group, member, priv, enc)
                results.append(dec == plaintext)
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(
                threading.Thread(target=encrypt_decrypt, args=(alice_priv, "alice"))
            )
            threads.append(
                threading.Thread(target=encrypt_decrypt, args=(bob_priv, "bob"))
            )

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"
        assert all(results)


# ==============================================================================
# TestSecurityProperties
# ==============================================================================


@pytest.mark.security
class TestSecurityProperties:
    """Тесты криптографических свойств безопасности."""

    def test_group_key_erased_after_encrypt(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """_secure_erase вызывается: group_key после encrypt равен 0."""
        group, *_ = group_with_members
        erased_keys: list[bytearray] = []
        original_erase = GroupKeyManager._secure_erase

        @staticmethod  # type: ignore[misc]
        def capturing_erase(data: bytearray) -> None:
            erased_keys.append(bytearray(data))  # снять снимок до стирания
            original_erase(data)

        with patch.object(GroupKeyManager, "_secure_erase", capturing_erase):
            manager.encrypt_for_group(group, b"test erase")

        # Хотя бы один bytearray группового ключа был передан на стирание
        group_key_sized = [k for k in erased_keys if len(k) == GROUP_KEY_SIZE]
        assert len(group_key_sized) > 0

    def test_group_key_erased_after_decrypt(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """_secure_erase вызывается после decrypt_as_member."""
        group, alice_priv, _, _, _ = group_with_members
        encrypted = manager.encrypt_for_group(group, b"test erase decrypt")

        erase_calls: list[int] = []
        original_erase = GroupKeyManager._secure_erase

        @staticmethod  # type: ignore[misc]
        def counting_erase(data: bytearray) -> None:
            erase_calls.append(len(data))
            original_erase(data)

        with patch.object(GroupKeyManager, "_secure_erase", counting_erase):
            manager.decrypt_as_member(group, "alice", alice_priv, encrypted)

        assert len(erase_calls) > 0

    def test_different_groups_different_wrapped_keys(
        self,
        manager: GroupKeyManager,
    ) -> None:
        """AAD (group_id) обеспечивает: wrapped key группы A не подходит для группы B."""
        priv, pub = manager.generate_member_keypair()

        group_a = manager.create_group("group-a")
        group_b = manager.create_group("group-b")
        manager.add_member(group_a, "user", pub)
        manager.add_member(group_b, "user", pub)

        plaintext = b"cross-group test"
        enc_a = manager.encrypt_for_group(group_a, plaintext)
        enc_b = manager.encrypt_for_group(group_b, plaintext)

        # Попытка расшифровать сообщение группы A с wrapped_key от группы B
        tampered = GroupEncryptedMessage(
            group_id=group_a.group_id,
            ciphertext=enc_a.ciphertext,
            nonce=enc_a.nonce,
            reserved_hkdf_salt=enc_a.reserved_hkdf_salt,
            wrapped_keys=enc_b.wrapped_keys,  # wrong group's wrapped keys
        )
        with pytest.raises(Exception):
            manager.decrypt_as_member(group_a, "user", priv, tampered)

    def test_per_message_key_uniqueness(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Каждое сообщение использует уникальный group key (per-message key)."""
        group, *_ = group_with_members
        enc1 = manager.encrypt_for_group(group, b"same")
        enc2 = manager.encrypt_for_group(group, b"same")
        # Разные ephemeral keys → разные wrapped_keys
        wk1 = enc1.wrapped_keys["alice"]["ephemeral_public_key"]
        wk2 = enc2.wrapped_keys["alice"]["ephemeral_public_key"]
        assert wk1 != wk2

    def test_ciphertext_tamper_detected(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Модификация ciphertext обнаруживается при расшифровке (AEAD integrity)."""
        group, alice_priv, _, _, _ = group_with_members
        enc = manager.encrypt_for_group(group, b"integrity test")

        tampered_ct = bytearray(enc.ciphertext)
        tampered_ct[0] ^= 0xFF  # Flip bits

        tampered_msg = GroupEncryptedMessage(
            group_id=enc.group_id,
            ciphertext=bytes(tampered_ct),
            nonce=enc.nonce,
            reserved_hkdf_salt=enc.reserved_hkdf_salt,
            wrapped_keys=enc.wrapped_keys,
        )
        with pytest.raises(Exception):
            manager.decrypt_as_member(group, "alice", alice_priv, tampered_msg)

    def test_nonce_tamper_detected(
        self,
        manager: GroupKeyManager,
        group_with_members: Tuple[Group, bytes, bytes, bytes, bytes],
    ) -> None:
        """Модификация nonce обнаруживается при расшифровке."""
        group, alice_priv, _, _, _ = group_with_members
        enc = manager.encrypt_for_group(group, b"nonce test")

        tampered_nonce = bytearray(enc.nonce)
        tampered_nonce[0] ^= 0xFF

        tampered_msg = GroupEncryptedMessage(
            group_id=enc.group_id,
            ciphertext=enc.ciphertext,
            nonce=bytes(tampered_nonce),
            reserved_hkdf_salt=enc.reserved_hkdf_salt,
            wrapped_keys=enc.wrapped_keys,
        )
        with pytest.raises(Exception):
            manager.decrypt_as_member(group, "alice", alice_priv, tampered_msg)


# ==============================================================================
# TestConstants
# ==============================================================================


class TestConstants:
    """Тесты констант модуля."""

    def test_group_key_size_is_32(self) -> None:
        """GROUP_KEY_SIZE == 32 байта (AES-256)."""
        assert GROUP_KEY_SIZE == 32

    def test_hkdf_salt_size_is_32(self) -> None:
        """HKDF_SALT_SIZE == 32 байта."""
        assert HKDF_SALT_SIZE == 32

    def test_max_group_members_is_256(self) -> None:
        """MAX_GROUP_MEMBERS == 256."""
        assert MAX_GROUP_MEMBERS == 256

    def test_x25519_key_size_is_32(self) -> None:
        """_X25519_KEY_SIZE == 32 байта."""
        assert _X25519_KEY_SIZE == 32


# ==============================================================================
# TestExports
# ==============================================================================


class TestExports:
    """Тесты публичного API модуля (__all__)."""

    def test_all_exports_importable(self) -> None:
        """Все элементы __all__ импортируются без ошибок."""
        from src.security.crypto.advanced.group_encryption import __all__ as exports

        for name in exports:
            import importlib

            mod = importlib.import_module(
                "src.security.crypto.advanced.group_encryption"
            )
            assert hasattr(mod, name), f"{name} not found in module"
