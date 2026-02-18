"""
Гибридное шифрование (Hybrid Encryption) для FX Text Processor 3.

Этот модуль реализует гибридное шифрование — комбинацию алгоритмов обмена ключами
(KEX/KEM) и симметричного шифрования (AEAD). Это индустриальный стандарт,
используемый в PGP, TLS 1.3, Signal Protocol.

Что такое Hybrid Encryption?
=============================

Hybrid Encryption = Key Exchange (KEX) + Symmetric Cipher

Почему гибридное шифрование?
- Быстро: Симметричное шифрование ~1000x быстрее RSA
- Без ограничений по размеру: RSA ограничен ~190 байтами, симметричное — нет
- Post-Quantum ready: Можно использовать Kyber (PQC KEM) вместо X25519
- Индустриальный стандарт: PGP, TLS 1.3, Signal Protocol

Поддерживаемые конфигурации:
=============================

1. **Classical Standard** (X25519 + AES-256-GCM)
   - Современная классическая криптография
   - 128-bit security level

2. **Classical Paranoid** (X448 + ChaCha20-Poly1305)
   - Максимальная классическая безопасность
   - 224-bit security level

3. **Post-Quantum Standard** (Kyber768 + AES-256-GCM)
   - Квантово-устойчивое шифрование
   - NIST security level 3

4. **Post-Quantum Paranoid** (Kyber1024 + ChaCha20-Poly1305)
   - Максимальная квантовая безопасность
   - NIST security level 5

Безопасность:
=============

- Perfect Forward Secrecy: Ephemeral ключи для каждого сообщения
- HKDF-SHA256: Стандартная деривация ключей (не сырой shared secret!)
- Secure Memory: Обнуление ephemeral ключей после использования
- AEAD: Authenticated Encryption (целостность + конфиденциальность)

Примеры использования:
=====================

>>> from src.security.crypto.advanced.hybrid_encryption import create_hybrid_cipher
>>>
>>> # Создать cipher
>>> cipher = create_hybrid_cipher("classical_standard")
>>>
>>> # Bob генерирует keypair
>>> bob_priv, bob_pub = cipher.generate_recipient_keypair()
>>>
>>> # Alice шифрует для Bob
>>> encrypted = cipher.encrypt_for_recipient(bob_pub, b"Secret message")
>>>
>>> # Bob расшифровывает
>>> plaintext = cipher.decrypt_from_sender(bob_priv, encrypted)
>>> assert plaintext == b"Secret message"

References:
===========

- TLS 1.3: RFC 8446 (ECDHE + AEAD)
- Signal Protocol: Double Ratchet (ephemeral keys + PFS)
- PGP/GPG: RFC 4880 (hybrid encryption)
- NIST ML-KEM: Kyber (PQC KEM standard, FIPS 203)
- RFC 7748: X25519, X448
- RFC 5869: HKDF

Author: FX Text Processor 3 Team
Version: 2.3.2
Date: February 18, 2026
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Dict, Final, Literal, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.security.crypto.core.exceptions import (
    AlgorithmNotAvailableError,
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
# TYPE ALIASES & CONSTANTS
# ==============================================================================

KEXAlgorithm = Literal["x25519", "x448", "kyber768", "kyber1024"]
SymmetricAlgorithm = Literal["aes-256-gcm", "chacha20-poly1305"]

HKDF_INFO_HYBRID_ENCRYPTION: Final[bytes] = b"hybrid-encryption-v1"
HKDF_SALT_SIZE: Final[int] = 32
SYMMETRIC_KEY_SIZE: Final[int] = 32

logger = logging.getLogger(__name__)


# ==============================================================================
# CONFIGURATION DATACLASS
# ==============================================================================


@dataclass(frozen=True)
class HybridConfig:
    """
    Конфигурация для гибридного шифрования.

    Attributes:
        kex_algorithm: Алгоритм обмена ключами (lowercase ID)
        symmetric_algorithm: Алгоритм симметричного шифрования (lowercase ID)
        name: Читаемое название конфигурации
        description: Краткое описание

    Example:
        >>> config = HybridConfig(
        ...     kex_algorithm="x25519",
        ...     symmetric_algorithm="aes-256-gcm",
        ...     name="Classical Standard",
        ...     description="X25519 + AES-256-GCM (fast, modern)"
        ... )
    """

    kex_algorithm: KEXAlgorithm
    symmetric_algorithm: SymmetricAlgorithm
    name: str
    description: str


PRESETS: Dict[str, HybridConfig] = {
    "classical_standard": HybridConfig(
        kex_algorithm="x25519",
        symmetric_algorithm="aes-256-gcm",
        name="Classical Standard",
        description="X25519 + AES-256-GCM (fast, modern)",
    ),
    "classical_paranoid": HybridConfig(
        kex_algorithm="x448",
        symmetric_algorithm="chacha20-poly1305",
        name="Classical Paranoid",
        description="X448 + ChaCha20-Poly1305 (max classical security)",
    ),
    "pqc_standard": HybridConfig(
        kex_algorithm="kyber768",
        symmetric_algorithm="aes-256-gcm",
        name="Post-Quantum Standard",
        description="Kyber768 + AES-256-GCM (quantum-resistant)",
    ),
    "pqc_paranoid": HybridConfig(
        kex_algorithm="kyber1024",
        symmetric_algorithm="chacha20-poly1305",
        name="Post-Quantum Paranoid",
        description="Kyber1024 + ChaCha20-Poly1305 (max quantum security)",
    ),
}


# ==============================================================================
# HYBRID ENCRYPTION CLASS
# ==============================================================================


class HybridEncryption:
    """
    Гибридное шифрование: KEX + Symmetric cipher.

    Комбинирует алгоритмы обмена ключами (X25519, Kyber) с симметричным
    шифрованием (AES-GCM, ChaCha20) для эффективного шифрования данных
    произвольного размера.

    Features:
        - Perfect Forward Secrecy (ephemeral keys)
        - Нет ограничений по размеру сообщения
        - Post-Quantum поддержка (Kyber)
        - Индустриальный стандарт (PGP, TLS)

    Example:
        >>> config = PRESETS["classical_standard"]
        >>> cipher = HybridEncryption(config)
        >>> bob_priv, bob_pub = cipher.generate_recipient_keypair()
        >>> encrypted = cipher.encrypt_for_recipient(bob_pub, b"Secret")
        >>> plaintext = cipher.decrypt_from_sender(bob_priv, encrypted)
    """

    def __init__(self, config: HybridConfig) -> None:
        """
        Инициализировать гибридное шифрование с конфигурацией.

        Args:
            config: Конфигурация гибридного шифрования

        Raises:
            AlgorithmNotAvailableError: Требуемый алгоритм недоступен
        """
        self._config = config
        self._logger = logging.getLogger(__name__)

        registry = AlgorithmRegistry.get_instance()

        try:
            self._kex: KeyExchangeProtocol = registry.create(
                config.kex_algorithm
            )
            self._cipher: SymmetricCipherProtocol = registry.create(
                config.symmetric_algorithm
            )
        except KeyError as exc:
            raise AlgorithmNotAvailableError(
                algorithm=config.kex_algorithm,
                reason=f"Algorithm not found in registry: {exc}",
            ) from exc
        except RuntimeError as exc:
            raise AlgorithmNotAvailableError(
                algorithm=config.kex_algorithm,
                reason=f"Algorithm not available (missing library): {exc}",
            ) from exc

        self._logger.debug(
            f"Initialized HybridEncryption: "
            f"KEX={config.kex_algorithm}, "
            f"Symmetric={config.symmetric_algorithm}"
        )

    @property
    def config(self) -> HybridConfig:
        """Текущая конфигурация."""
        return self._config

    def generate_recipient_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать долгосрочный keypair для получателя.

        Returns:
            (private_key, public_key): Пара ключей для KEX

        Raises:
            EncryptionError: Генерация ключей не удалась

        Example:
            >>> cipher = HybridEncryption(PRESETS["classical_standard"])
            >>> priv, pub = cipher.generate_recipient_keypair()
            >>> len(pub)  # X25519 public key
            32
        """
        try:
            private_key, public_key = self._kex.generate_keypair()

            self._logger.debug(
                f"Generated recipient keypair: "
                f"pub_size={len(public_key)}, priv_size={len(private_key)}"
            )

            return private_key, public_key

        except Exception as exc:
            raise EncryptionError(f"Keypair generation failed: {exc}") from exc

    def encrypt_for_recipient(
        self,
        recipient_public_key: bytes,
        plaintext: bytes,
        *,
        associated_data: Optional[bytes] = None,
    ) -> Dict[str, bytes]:
        """
        Зашифровать данные для получателя используя гибридное шифрование.

        Process:
            1. Сгенерировать ephemeral KEX keypair
            2. Вывести shared secret с public ключом получателя
            3. Вывести symmetric key из shared secret (HKDF-SHA256)
            4. Зашифровать plaintext с symmetric cipher
            5. Вернуть ephemeral public key + ciphertext

        Args:
            recipient_public_key: Долгосрочный public ключ получателя (KEX)
            plaintext: Данные для шифрования (любой размер)
            associated_data: Дополнительные аутентифицируемые данные (AEAD)

        Returns:
            {
                "ephemeral_public_key": bytes,
                "nonce": bytes,
                "ciphertext": bytes,
                "hkdf_salt": bytes,
            }

        Raises:
            ValueError: Невалидный input (пустые keys/plaintext)
            InvalidKeyError: Невалидный recipient public key
            EncryptionError: Шифрование не удалось
        """
        if not recipient_public_key:
            raise ValueError("Recipient public key cannot be empty")
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")

        ephemeral_private = b""
        shared_secret = b""
        symmetric_key = b""

        try:
            # 1. Generate ephemeral keypair
            ephemeral_private, ephemeral_public = self._kex.generate_keypair()

            # 2. Derive shared secret
            shared_secret = self._kex.derive_shared_secret(
                private_key=ephemeral_private,
                peer_public_key=recipient_public_key,
            )

            # 3. Derive symmetric key via HKDF-SHA256
            hkdf_salt = secrets.token_bytes(HKDF_SALT_SIZE)
            symmetric_key = self._derive_symmetric_key(shared_secret, hkdf_salt)

            # 4. Encrypt with symmetric cipher
            ciphertext, nonce = self._cipher.encrypt(
                key=symmetric_key,
                plaintext=plaintext,
                aad=associated_data,
            )

            self._logger.debug(
                f"Encrypted: plaintext_size={len(plaintext)}, "
                f"ciphertext_size={len(ciphertext)}"
            )

            return {
                "ephemeral_public_key": ephemeral_public,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "hkdf_salt": hkdf_salt,
            }

        except ValueError as exc:
            raise InvalidKeyError(
                f"Invalid recipient public key: {exc}"
            ) from exc
        except (InvalidKeyError, EncryptionError):
            raise
        except Exception as exc:
            raise EncryptionError(
                f"Hybrid encryption failed: {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(ephemeral_private))
            self._secure_erase(bytearray(shared_secret))
            self._secure_erase(bytearray(symmetric_key))

    def decrypt_from_sender(
        self,
        recipient_private_key: bytes,
        encrypted_data: Dict[str, bytes],
        *,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Расшифровать данные от отправителя используя гибридное шифрование.

        Args:
            recipient_private_key: Долгосрочный private ключ получателя (KEX)
            encrypted_data: Вывод из encrypt_for_recipient()
            associated_data: Дополнительные аутентифицируемые данные (AEAD)

        Returns:
            Расшифрованный plaintext

        Raises:
            ValueError: Невалидный input или отсутствующие поля
            InvalidKeyError: Невалидный recipient private key
            DecryptionError: Расшифровка не удалась
        """
        if not recipient_private_key:
            raise ValueError("Recipient private key cannot be empty")

        self._validate_encrypted_data(encrypted_data)

        shared_secret = b""
        symmetric_key = b""

        try:
            ephemeral_public = encrypted_data["ephemeral_public_key"]
            nonce = encrypted_data["nonce"]
            ciphertext = encrypted_data["ciphertext"]
            hkdf_salt = encrypted_data.get("hkdf_salt", b"")

            # 1. Derive shared secret
            shared_secret = self._kex.derive_shared_secret(
                private_key=recipient_private_key,
                peer_public_key=ephemeral_public,
            )

            # 2. Derive symmetric key via HKDF-SHA256
            symmetric_key = self._derive_symmetric_key(shared_secret, hkdf_salt)

            # 3. Decrypt ciphertext
            plaintext = self._cipher.decrypt(
                key=symmetric_key,
                ciphertext=ciphertext,
                nonce=nonce,
                aad=associated_data,
            )

            self._logger.debug(f"Decrypted plaintext: size={len(plaintext)}")

            return plaintext

        except ValueError as exc:
            raise InvalidKeyError(
                f"Invalid recipient private key: {exc}"
            ) from exc
        except (InvalidKeyError, DecryptionError):
            raise
        except Exception as exc:
            raise DecryptionError(
                f"Hybrid decryption failed: {exc}"
            ) from exc
        finally:
            self._secure_erase(bytearray(shared_secret))
            self._secure_erase(bytearray(symmetric_key))

    # ==========================================================================
    # PRIVATE METHODS
    # ==========================================================================

    def _derive_symmetric_key(
        self, shared_secret: bytes, salt: bytes
    ) -> bytes:
        """
        Вывести symmetric key из shared secret используя HKDF-SHA256.

        Args:
            shared_secret: Сырой shared secret из KEX
            salt: Соль для HKDF

        Returns:
            Выведенный symmetric key (32 байта)
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SYMMETRIC_KEY_SIZE,
            salt=salt if salt else None,
            info=HKDF_INFO_HYBRID_ENCRYPTION,
        )
        return hkdf.derive(shared_secret)

    def _validate_encrypted_data(
        self, encrypted_data: Dict[str, bytes]
    ) -> None:
        """
        Проверить структуру encrypted_data.

        Raises:
            ValueError: Отсутствующие обязательные поля или пустые значения
        """
        required_fields = {"ephemeral_public_key", "nonce", "ciphertext"}
        missing = required_fields - set(encrypted_data.keys())

        if missing:
            raise ValueError(
                f"Missing required fields in encrypted_data: {missing}"
            )

        for field_name in required_fields:
            if not encrypted_data[field_name]:
                raise ValueError(f"Field '{field_name}' cannot be empty")

    @staticmethod
    def _secure_erase(data: bytearray) -> None:
        """
        Безопасно стереть чувствительные данные из памяти.

        Args:
            data: Bytearray для стирания
        """
        if not data:
            return
        for i in range(len(data)):
            data[i] = secrets.randbits(8)
        for i in range(len(data)):
            data[i] = 0


# ==============================================================================
# FACTORY FUNCTION
# ==============================================================================


def create_hybrid_cipher(
    preset: str = "classical_standard",
) -> HybridEncryption:
    """
    Создать hybrid encryption cipher с предустановленной конфигурацией.

    Args:
        preset: Название предустановки:
            - "classical_standard": X25519 + AES-256-GCM (default)
            - "classical_paranoid": X448 + ChaCha20-Poly1305
            - "pqc_standard": Kyber768 + AES-256-GCM
            - "pqc_paranoid": Kyber1024 + ChaCha20-Poly1305

    Returns:
        Сконфигурированный экземпляр HybridEncryption

    Raises:
        ValueError: Неизвестная предустановка
        AlgorithmNotAvailableError: Требуемый алгоритм недоступен

    Example:
        >>> cipher = create_hybrid_cipher("classical_standard")
        >>> cipher = create_hybrid_cipher("pqc_standard")
    """
    if preset not in PRESETS:
        raise ValueError(
            f"Unknown preset '{preset}'. "
            f"Available: {list(PRESETS.keys())}"
        )

    config = PRESETS[preset]
    logger.debug(
        f"Creating hybrid cipher with preset '{preset}': {config.description}"
    )
    return HybridEncryption(config)


# ==============================================================================
# EXPORTS
# ==============================================================================

__all__ = [
    "HybridEncryption",
    "HybridConfig",
    "PRESETS",
    "create_hybrid_cipher",
]
