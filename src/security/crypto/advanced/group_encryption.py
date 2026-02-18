"""
Групповое шифрование (Group Encryption) для FX Text Processor 3.

Этот модуль реализует GroupKeyManager — менеджер групповых ключей для
шифрования сообщений в группе получателей. Использует гибридное шифрование
(HybridEncryption) для обёртки группового ключа каждому участнику.


Что такое Group Encryption?
============================

Group Encryption — схема шифрования для множества получателей.
Вместо шифрования сообщения N раз (для каждого получателя), сообщение
шифруется один раз симметричным ключом, а ключ обёртывается для
каждого получателя.


Архитектура:
============

1. Сгенерировать random group symmetric key (одноразовый)
2. Зашифровать сообщение group key
3. Для каждого получателя: обернуть group key гибридным шифрованием
4. Каждый получатель разворачивает свою копию group key
5. Расшифровать сообщение


Аналоги:
========

- PGP/GPG Multi-recipient: RFC 4880 Section 5.1
- S/MIME EnvelopedData: RFC 5652
- MLS (Messaging Layer Security): RFC 9420
- Signal Sealed Sender Groups


Безопасность:
=============

- Группой ключ одноразовый (per-message)
- Perfect Forward Secrecy через ephemeral keys
- Каждый участник имеет свою обёрнутую копию ключа
- Удаление участника = новый group key
- HKDF-SHA256 деривация ключей
- Secure memory erase после использования
- group_id привязан как AAD при key-wrapping (defense-in-depth)
- Публичный ключ валидируется по размеру при добавлении участника



Пример:
=======

>>> from src.security.crypto.advanced.group_encryption import GroupKeyManager
>>>
>>> manager = GroupKeyManager()
>>> group = manager.create_group("team-alpha")
>>>
>>> # Добавить участников
>>> alice_priv, alice_pub = manager.generate_member_keypair()
>>> bob_priv, bob_pub = manager.generate_member_keypair()
>>> manager.add_member(group, "alice", alice_pub)
>>> manager.add_member(group, "bob", bob_pub)
>>>
>>> # Зашифровать для группы
>>> encrypted = manager.encrypt_for_group(group, b"Team secret")
>>>
>>> # Каждый участник расшифровывает
>>> plaintext = manager.decrypt_as_member(group, "alice", alice_priv, encrypted)
>>> assert plaintext == b"Team secret"


Author: Mike Voyager
Version: 2.3.3
Date: February 18, 2026
"""

from __future__ import annotations

import logging
import secrets
import threading
import types as _types
from dataclasses import dataclass, field
from typing import Dict, Final, List, Mapping, Optional, Tuple

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

GROUP_KEY_SIZE: Final[int] = 32
HKDF_SALT_SIZE: Final[int] = 32
HKDF_INFO_GROUP: Final[bytes] = b"group-encryption-v1"
MAX_GROUP_MEMBERS: Final[int] = 256

# Ожидаемый размер публичного ключа для алгоритма X25519.
# При добавлении поддержки других KEX — расширить через реестр.
_X25519_KEY_SIZE: Final[int] = 32

logger = logging.getLogger(__name__)


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass
class GroupMember:
    """
    Информация об участнике группы.

    Attributes:
        member_id: Уникальный идентификатор участника.
        public_key: Публичный ключ KEX (32 байта для X25519).
        added_order: Порядковый номер добавления участника в группу.
    """

    member_id: str
    public_key: bytes
    added_order: int = 0


@dataclass
class Group:
    """
    Криптографическая группа с участниками.

    Attributes:
        group_id: Уникальный идентификатор группы.
        members: Словарь участников {member_id -> GroupMember}.
        kex_algorithm: Алгоритм обмена ключами.
        symmetric_algorithm: Алгоритм симметричного шифрования.
        created_order: Порядковый номер создания группы в менеджере.
        _member_counter: Счётчик добавленных участников (приватный).

    Note:
        Не является thread-safe сам по себе; все мутации должны
        выполняться через GroupKeyManager под его внутренней блокировкой.
    """

    group_id: str
    members: Dict[str, GroupMember] = field(default_factory=dict)
    kex_algorithm: str = "x25519"
    symmetric_algorithm: str = "aes-256-gcm"
    created_order: int = 0
    _member_counter: int = 0


@dataclass(frozen=True)
class GroupEncryptedMessage:
    """
    Зашифрованное групповое сообщение.

    Attributes:
        group_id: Идентификатор группы.
        ciphertext: Зашифрованный plaintext (AES-256-GCM).
        nonce: Nonce для симметричного шифрования сообщения.
        reserved_hkdf_salt: Зарезервировано для будущего использования.
            Не применяется при расшифровке сообщения; соль HKDF хранится
            внутри каждого элемента wrapped_keys отдельно.
        wrapped_keys: Read-only mapping обёрнутых group keys для каждого
            участника {member_id -> MappingProxy{ephemeral_public_key,
            ciphertext, nonce, hkdf_salt}}.

    Note:
        ``wrapped_keys`` защищён через ``types.MappingProxyType`` —
        внешняя мутация вложенных dict невозможна.
        Frozen dataclass запрещает переназначение любого атрибута.
    """

    group_id: str
    ciphertext: bytes
    nonce: bytes
    reserved_hkdf_salt: bytes
    wrapped_keys: Mapping[str, Mapping[str, bytes]]


# ==============================================================================
# GROUP KEY MANAGER
# ==============================================================================


class GroupKeyManager:
    """
    Менеджер групповых ключей для шифрования в группах получателей.

    Поддерживает:
    - Создание и управление группами
    - Добавление и удаление участников
    - Шифрование сообщений для группы
    - Расшифровку участником
    - Thread-safe операции (RLock)

    Security guarantees:
    - group_key хранится как bytearray и стирается из памяти после
      использования через _secure_erase (не как копия bytes).
    - ephemeral_private, shared_secret, derived_key стираются
      в блоках finally каждого вызова key-wrapping.
    - group_id передаётся как AAD при оборачивании ключа (defense-in-depth).

    Example:
        >>> manager = GroupKeyManager()
        >>> group = manager.create_group("my-group")
        >>> priv, pub = manager.generate_member_keypair()
        >>> manager.add_member(group, "user1", pub)
        >>> encrypted = manager.encrypt_for_group(group, b"Hello group!")
        >>> plaintext = manager.decrypt_as_member(group, "user1", priv, encrypted)
        >>> assert plaintext == b"Hello group!"
    """

    def __init__(
        self,
        kex_algorithm: str = "x25519",
        symmetric_algorithm: str = "aes-256-gcm",
    ) -> None:
        """
        Инициализировать менеджер групповых ключей.

        Args:
            kex_algorithm: Алгоритм обмена ключами (по умолчанию X25519).
            symmetric_algorithm: Алгоритм шифрования (по умолчанию AES-256-GCM).

        Raises:
            CryptoError: Алгоритм недоступен в реестре.
        """
        self._kex_algo = kex_algorithm
        self._sym_algo = symmetric_algorithm
        self._lock = threading.RLock()
        self._groups: Dict[str, Group] = {}
        self._group_counter = 0
        self._logger = logging.getLogger(__name__)

        registry = AlgorithmRegistry.get_instance()
        try:
            self._kex: KeyExchangeProtocol = registry.create(kex_algorithm)
            self._cipher: SymmetricCipherProtocol = registry.create(symmetric_algorithm)
        except (KeyError, RuntimeError) as exc:
            raise CryptoError(
                f"Failed to initialize GroupKeyManager: {exc}",
                algorithm=kex_algorithm,
            ) from exc

        # %-форматирование: f-string вычисляется даже при выключенном DEBUG
        self._logger.debug(
            "GroupKeyManager initialized: KEX=%s, Symmetric=%s",
            kex_algorithm,
            symmetric_algorithm,
        )

    # ==========================================================================
    # KEYPAIR
    # ==========================================================================

    def generate_member_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать keypair для нового участника.

        Returns:
            (private_key, public_key): Пара ключей в bytes.

        Raises:
            CryptoError: Генерация не удалась.
        """
        try:
            return self._kex.generate_keypair()
        except Exception as exc:
            raise CryptoError(f"Member keypair generation failed: {exc}") from exc

    # ==========================================================================
    # GROUP MANAGEMENT
    # ==========================================================================

    def create_group(
        self,
        group_id: str,
        *,
        kex_algorithm: Optional[str] = None,
        symmetric_algorithm: Optional[str] = None,
    ) -> Group:
        """
        Создать новую криптографическую группу.

        Args:
            group_id: Уникальный идентификатор группы.
            kex_algorithm: KEX алгоритм (по умолчанию из конструктора).
            symmetric_algorithm: Симметричный алгоритм (по умолчанию из конструктора).

        Returns:
            Созданная группа.

        Raises:
            ValueError: group_id пустой или группа уже существует.
        """
        if not group_id or not group_id.strip():
            raise ValueError("Group ID cannot be empty")

        with self._lock:
            if group_id in self._groups:
                raise ValueError(f"Group '{group_id}' already exists")

            self._group_counter += 1
            group = Group(
                group_id=group_id,
                kex_algorithm=kex_algorithm or self._kex_algo,
                symmetric_algorithm=symmetric_algorithm or self._sym_algo,
                created_order=self._group_counter,
            )
            self._groups[group_id] = group

            self._logger.debug("Created group '%s'", group_id)
            return group

    def get_group(self, group_id: str) -> Group:
        """
        Получить группу по ID.

        Args:
            group_id: Идентификатор группы.

        Returns:
            Группа.

        Raises:
            KeyError: Группа не найдена.
        """
        with self._lock:
            if group_id not in self._groups:
                raise KeyError(f"Group '{group_id}' not found")
            return self._groups[group_id]

    def delete_group(self, group_id: str) -> None:
        """
        Удалить группу.

        Args:
            group_id: Идентификатор группы.

        Raises:
            KeyError: Группа не найдена.
        """
        with self._lock:
            if group_id not in self._groups:
                raise KeyError(f"Group '{group_id}' not found")
            del self._groups[group_id]
            self._logger.debug("Deleted group '%s'", group_id)

    # ==========================================================================
    # MEMBER MANAGEMENT
    # ==========================================================================

    def add_member(self, group: Group, member_id: str, public_key: bytes) -> None:
        """
        Добавить участника в группу.

        Валидирует длину публичного ключа: X25519 требует ровно 32 байта.

        Args:
            group: Целевая группа.
            member_id: Уникальный ID участника в группе.
            public_key: Публичный ключ KEX участника (32 байта для X25519).

        Raises:
            ValueError: Дублирующий member_id, пустой ключ или лимит участников.
            InvalidKeyError: Неверная длина публичного ключа.
        """
        if not member_id or not member_id.strip():
            raise ValueError("Member ID cannot be empty")
        if not public_key:
            raise ValueError("Public key cannot be empty")
        if len(public_key) != _X25519_KEY_SIZE:
            raise InvalidKeyError(
                f"Invalid public key size for '{member_id}': "
                f"expected {_X25519_KEY_SIZE} bytes, got {len(public_key)}. "
                f"Ensure the key was generated via generate_member_keypair()."
            )

        with self._lock:
            if member_id in group.members:
                raise ValueError(
                    f"Member '{member_id}' already in group '{group.group_id}'"
                )
            if len(group.members) >= MAX_GROUP_MEMBERS:
                raise ValueError(
                    f"Group '{group.group_id}' reached member limit "
                    f"({MAX_GROUP_MEMBERS})"
                )

            group._member_counter += 1
            group.members[member_id] = GroupMember(
                member_id=member_id,
                public_key=public_key,
                added_order=group._member_counter,
            )

            self._logger.debug(
                "Added member '%s' to group '%s' (total: %d)",
                member_id,
                group.group_id,
                len(group.members),
            )

    def remove_member(self, group: Group, member_id: str) -> None:
        """
        Удалить участника из группы.

        После удаления необходимо перевыпустить group key: зашифровать
        новое сообщение без этого участника.

        Args:
            group: Целевая группа.
            member_id: ID участника для удаления.

        Raises:
            KeyError: Участник не найден.
        """
        with self._lock:
            if member_id not in group.members:
                raise KeyError(
                    f"Member '{member_id}' not found in group '{group.group_id}'"
                )
            del group.members[member_id]
            self._logger.debug(
                "Removed member '%s' from group '%s'",
                member_id,
                group.group_id,
            )

    def list_members(self, group: Group) -> List[str]:
        """
        Получить список ID участников группы.

        Args:
            group: Целевая группа.

        Returns:
            Отсортированный список member_id.
        """
        with self._lock:
            return sorted(group.members.keys())

    # ==========================================================================
    # ENCRYPTION / DECRYPTION
    # ==========================================================================

    def encrypt_for_group(
        self,
        group: Group,
        plaintext: bytes,
        *,
        associated_data: Optional[bytes] = None,
    ) -> GroupEncryptedMessage:
        """
        Зашифровать сообщение для всех участников группы.

        Process:
            1. Сгенерировать одноразовый group key (bytearray для secure erase).
            2. Зашифровать plaintext group key (symmetric).
            3. Обернуть group key для каждого участника (hybrid KEX).
            4. Стереть group key из памяти (finally).
            5. Вернуть GroupEncryptedMessage с wrapped_keys под MappingProxyType.

        Args:
            group: Целевая группа.
            plaintext: Данные для шифрования.
            associated_data: Дополнительные данные для AEAD (опционально).

        Returns:
            GroupEncryptedMessage с обёрнутыми ключами для каждого участника.

        Raises:
            ValueError: Пустой plaintext или пустая группа.
            EncryptionError: Шифрование не удалось.
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")

        with self._lock:
            if not group.members:
                raise ValueError(f"Group '{group.group_id}' has no members")

            # bytearray — изменяемый: _secure_erase работает на оригинале,
            # а не на копии (в отличие от bytes)
            group_key = bytearray(GROUP_KEY_SIZE)
            try:
                # 1. Generate random group key (in-place в bytearray)
                group_key[:] = secrets.token_bytes(GROUP_KEY_SIZE)

                # 2. Encrypt plaintext with group key
                nonce, ciphertext = self._cipher.encrypt(
                    key=bytes(group_key),
                    plaintext=plaintext,
                    aad=associated_data,
                )

                # 3. Wrap group key for each member.
                # group_id.encode() как AAD привязывает wrapped key
                # к конкретной группе (defense-in-depth).
                group_aad = group.group_id.encode()
                raw_wrapped: Dict[str, Dict[str, bytes]] = {}
                for member_id, member in group.members.items():
                    raw_wrapped[member_id] = self._wrap_key_for_member(
                        group_key, member.public_key, group_aad=group_aad
                    )

                # Защита: wrapped_keys доступен только для чтения снаружи
                wrapped_keys: Mapping[str, Mapping[str, bytes]] = (
                    _types.MappingProxyType(
                        {
                            mid: _types.MappingProxyType(wk)
                            for mid, wk in raw_wrapped.items()
                        }
                    )
                )

                self._logger.debug(
                    "Encrypted for group '%s': %d members, plaintext_size=%d",
                    group.group_id,
                    len(group.members),
                    len(plaintext),
                )

                return GroupEncryptedMessage(
                    group_id=group.group_id,
                    ciphertext=ciphertext,
                    nonce=nonce,
                    reserved_hkdf_salt=b"",
                    wrapped_keys=wrapped_keys,
                )

            except (ValueError, EncryptionError):
                raise
            except Exception as exc:
                raise EncryptionError(f"Group encryption failed: {exc}") from exc
            finally:
                # Стирает оригинальный bytearray, а не его копию
                self._secure_erase(group_key)

    def decrypt_as_member(
        self,
        group: Group,
        member_id: str,
        member_private_key: bytes,
        encrypted_message: GroupEncryptedMessage,
        *,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Расшифровать групповое сообщение как участник.

        Process:
            1. Развернуть group key из wrapped_keys[member_id].
            2. Расшифровать ciphertext group key.
            3. Стереть group key из памяти (finally).

        Args:
            group: Группа.
            member_id: ID участника.
            member_private_key: Приватный ключ участника.
            encrypted_message: Зашифрованное сообщение.
            associated_data: Дополнительные данные для AEAD (опционально).

        Returns:
            Расшифрованный plaintext.

        Raises:
            ValueError: Пустой приватный ключ.
            KeyError: member_id не найден в wrapped_keys.
            InvalidKeyError: Неверный приватный ключ.
            DecryptionError: Расшифровка не удалась.
        """
        if not member_private_key:
            raise ValueError("Member private key cannot be empty")

        if member_id not in encrypted_message.wrapped_keys:
            raise KeyError(f"No wrapped key for member '{member_id}' in message")

        group_key = bytearray(GROUP_KEY_SIZE)
        try:
            wrapped = dict(encrypted_message.wrapped_keys[member_id])

            # group_id как AAD: должен совпадать с тем, что использовался
            # при шифровании (defense-in-depth привязка к группе)
            group_aad = group.group_id.encode()

            # 1. Unwrap group key
            raw_group_key = self._unwrap_key_for_member(
                wrapped, member_private_key, group_aad=group_aad
            )
            group_key[:] = raw_group_key

            # 2. Decrypt message with group key
            plaintext = self._cipher.decrypt(
                key=bytes(group_key),
                nonce=encrypted_message.nonce,
                ciphertext=encrypted_message.ciphertext,
                aad=associated_data,
            )

            self._logger.debug(
                "Decrypted as member '%s' in group '%s'",
                member_id,
                group.group_id,
            )

            return plaintext

        except KeyError:
            raise
        except (InvalidKeyError, DecryptionError):
            raise
        except Exception as exc:
            raise DecryptionError(
                f"Group decryption failed for member '{member_id}': {exc}"
            ) from exc
        finally:
            self._secure_erase(group_key)

    # ==========================================================================
    # KEY WRAPPING (PRIVATE)
    # ==========================================================================

    def _wrap_key_for_member(
        self,
        group_key: bytearray,
        member_public_key: bytes,
        *,
        group_aad: bytes = b"",
    ) -> Dict[str, bytes]:
        """
        Обернуть group key для одного участника (гибридное шифрование).

        Scheme: X25519 ECDH → HKDF-SHA256 → AES-256-GCM(group_key).
        group_aad привязывает wrapped key к конкретной группе (AAD).

        Args:
            group_key: Симметричный ключ группы (bytearray).
            member_public_key: Публичный ключ участника.
            group_aad: Контекст группы для AAD (group_id.encode()).

        Returns:
            Dict с полями: ephemeral_public_key, nonce, ciphertext, hkdf_salt.
        """
        ephemeral_private = bytearray()
        shared_secret = bytearray()
        derived_key = bytearray()

        try:
            raw_eph_priv, ephemeral_public = self._kex.generate_keypair()
            ephemeral_private = bytearray(raw_eph_priv)

            raw_shared = self._kex.derive_shared_secret(
                private_key=bytes(ephemeral_private),
                peer_public_key=member_public_key,
            )
            shared_secret = bytearray(raw_shared)

            hkdf_salt = secrets.token_bytes(HKDF_SALT_SIZE)
            raw_derived = self._derive_wrapping_key(bytes(shared_secret), hkdf_salt)
            derived_key = bytearray(raw_derived)

            nonce, ciphertext = self._cipher.encrypt(
                key=bytes(derived_key),
                plaintext=bytes(group_key),
                aad=group_aad if group_aad else None,
            )

            return {
                "ephemeral_public_key": ephemeral_public,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "hkdf_salt": hkdf_salt,
            }

        finally:
            self._secure_erase(ephemeral_private)
            self._secure_erase(shared_secret)
            self._secure_erase(derived_key)

    def _unwrap_key_for_member(
        self,
        wrapped: Dict[str, bytes],
        member_private_key: bytes,
        *,
        group_aad: bytes = b"",
    ) -> bytes:
        """
        Развернуть group key для одного участника.

        Args:
            wrapped: Обёрнутый ключ (из _wrap_key_for_member).
            member_private_key: Приватный ключ участника.
            group_aad: Контекст группы для AAD (group_id.encode()).

        Returns:
            Развёрнутый group key (bytes).
        """
        shared_secret = bytearray()
        derived_key = bytearray()

        try:
            raw_shared = self._kex.derive_shared_secret(
                private_key=member_private_key,
                peer_public_key=wrapped["ephemeral_public_key"],
            )
            shared_secret = bytearray(raw_shared)

            hkdf_salt = wrapped.get("hkdf_salt", b"")
            raw_derived = self._derive_wrapping_key(bytes(shared_secret), hkdf_salt)
            derived_key = bytearray(raw_derived)

            group_key = self._cipher.decrypt(
                key=bytes(derived_key),
                nonce=wrapped["nonce"],
                ciphertext=wrapped["ciphertext"],
                aad=group_aad if group_aad else None,
            )

            return group_key

        finally:
            self._secure_erase(shared_secret)
            self._secure_erase(derived_key)

    def _derive_wrapping_key(self, shared_secret: bytes, salt: bytes) -> bytes:
        """
        Вывести wrapping key из shared secret через HKDF-SHA256.

        Args:
            shared_secret: Общий секрет из KEX.
            salt: Случайная соль HKDF (HKDF_SALT_SIZE байт).

        Returns:
            Derived key (GROUP_KEY_SIZE байт).
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=GROUP_KEY_SIZE,
            salt=salt if salt else None,
            info=HKDF_INFO_GROUP,
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def _secure_erase(data: bytearray) -> None:
        """
        Безопасно стереть чувствительные данные из памяти.

        Выполняет двухпроходное затирание: сначала случайными битами,
        затем нулями. Работает только с bytearray (изменяемый тип).
        Вызов на пустом bytearray безопасен и является no-op.

        Args:
            data: Изменяемый буфер для стирания (bytearray).
        """
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
    "GroupKeyManager",
    "Group",
    "GroupMember",
    "GroupEncryptedMessage",
]
