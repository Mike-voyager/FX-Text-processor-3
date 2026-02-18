"""
Унифицированный высокоуровневый API криптографической подсистемы.

CryptoService предоставляет единую точку доступа ко всем криптографическим
операциям FX Text Processor 3. Вместо прямой работы с алгоритмами приложение
использует этот сервис, который:

- Управляет выбором алгоритмов через CryptoProfile
- Делегирует операции в AlgorithmRegistry
- Ведёт аудит-лог всех операций (через стандартный logging, будущая интеграция
  с src/audit/ когда модуль будет готов)
- Форматирует результаты в единых dataclass-структурах (EncryptedDocument,
  SignedDocument)

Поддерживаемые операции:
    encrypt_document()        — Симметричное шифрование документа
    decrypt_document()        — Расшифровка документа
    sign_document()           — Создание цифровой подписи
    verify_signature()        — Проверка подписи
    generate_keypair()        — Генерация пары ключей
    encrypt_hybrid()          — Гибридное шифрование (KEX + symmetric)
    decrypt_hybrid()          — Расшифровка гибридного шифра
    hash_data()               — Вычисление хеша
    generate_symmetric_key()  — Генерация симметричного ключа
    estimate_storage_size()   — Оценка размера (для дискет, Phase 8)

Note:
    Функции group encryption и key escrow будут добавлены в Phase 11 после
    реализации group_encryption.py и key_escrow.py.

Example:
    >>> from src.security.crypto.service.crypto_service import CryptoService
    >>> from src.security.crypto.service.profiles import CryptoProfile
    >>>
    >>> service = CryptoService(profile=CryptoProfile.STANDARD)
    >>>
    >>> # Шифрование документа
    >>> key = service.generate_symmetric_key()
    >>> encrypted = service.encrypt_document(b"Secret document", key)
    >>> plaintext = service.decrypt_document(encrypted, key)
    >>> assert plaintext == b"Secret document"
    >>>
    >>> # Цифровая подпись
    >>> private_key, public_key = service.generate_keypair()
    >>> signed = service.sign_document(b"Document", private_key)
    >>> assert service.verify_signature(
    ...     b"Document", signed.signature, public_key, signed.algorithm_id
    ... )

Version: 1.0
Date: February 17, 2026
Priority: Phase 7 — Service Layer (CRITICAL)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from src.security.crypto.core.exceptions import (
    AlgorithmNotFoundError,
    CryptoError,
    DecryptionError,
    EncryptionError,
    SignatureError,
)
from src.security.crypto.core.metadata import AlgorithmCategory
from src.security.crypto.core.protocols import (
    HashProtocol,
    KDFProtocol,
    SignatureProtocol,
    SymmetricCipherProtocol,
)
from src.security.crypto.core.registry import AlgorithmRegistry
from src.security.crypto.service.profiles import (
    CryptoProfile,
    ProfileConfig,
    get_profile_config,
)

__all__ = [
    "CryptoService",
    "EncryptedDocument",
    "SignedDocument",
]

logger = logging.getLogger(__name__)

# Audit logger (заглушка; будет заменена на src.audit.AuditLogger в Phase 11)
# TODO: from src.audit import AuditLogger
_audit_logger = logging.getLogger("audit.crypto")


# ==============================================================================
# RESULT DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class EncryptedDocument:
    """
    Результат операции шифрования документа.

    Содержит все данные, необходимые для расшифровки. Immutable — после
    создания данные не могут быть изменены.

    Attributes:
        nonce: Nonce/IV, использованный при шифровании (случайный, уникальный)
        ciphertext: Зашифрованные данные (включает authentication tag для AEAD)
        algorithm_id: Registry ID алгоритма (например, "aes-256-gcm")
        aad: Additional Authenticated Data (для AEAD, не зашифрованы)

    Example:
        >>> encrypted = service.encrypt_document(b"Secret", key)
        >>> encrypted.algorithm_id
        'aes-256-gcm'
        >>> len(encrypted.nonce)
        12  # AES-GCM nonce size
    """

    nonce: bytes
    ciphertext: bytes
    algorithm_id: str
    aad: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализовать в словарь для сохранения/передачи.

        Returns:
            Словарь с hex-encoded полями (bytes → hex string)

        Example:
            >>> d = encrypted.to_dict()
            >>> d["algorithm_id"]
            'aes-256-gcm'
        """
        result: Dict[str, Any] = {
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "algorithm_id": self.algorithm_id,
        }
        if self.aad is not None:
            result["aad"] = self.aad.hex()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EncryptedDocument:
        """
        Десериализовать из словаря (обратная операция к to_dict).

        Args:
            data: Словарь с hex-encoded полями

        Returns:
            EncryptedDocument объект

        Raises:
            KeyError: Обязательное поле отсутствует
            ValueError: Некорректный hex

        Example:
            >>> restored = EncryptedDocument.from_dict(encrypted.to_dict())
        """
        aad_hex = data.get("aad")
        return cls(
            nonce=bytes.fromhex(data["nonce"]),
            ciphertext=bytes.fromhex(data["ciphertext"]),
            algorithm_id=data["algorithm_id"],
            aad=bytes.fromhex(aad_hex) if aad_hex else None,
        )


@dataclass(frozen=True)
class SignedDocument:
    """
    Результат операции цифровой подписи.

    Содержит подпись и метаданные для верификации. Сам документ не хранится —
    передаётся отдельно при вызове verify_signature().

    Attributes:
        signature: Байты цифровой подписи
        algorithm_id: Registry ID алгоритма подписи (например, "Ed25519")
        public_key_hint: Первые 8 байт публичного ключа (hex) для идентификации

    Example:
        >>> signed = service.sign_document(b"Document", private_key)
        >>> signed.algorithm_id
        'Ed25519'
        >>> len(signed.signature)
        64  # Ed25519 signature size
    """

    signature: bytes
    algorithm_id: str
    public_key_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализовать в словарь.

        Returns:
            Словарь с hex-encoded полями
        """
        return {
            "signature": self.signature.hex(),
            "algorithm_id": self.algorithm_id,
            "public_key_hint": self.public_key_hint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SignedDocument:
        """
        Десериализовать из словаря.

        Args:
            data: Словарь с hex-encoded полями

        Returns:
            SignedDocument объект

        Raises:
            KeyError: Обязательное поле отсутствует
        """
        return cls(
            signature=bytes.fromhex(data["signature"]),
            algorithm_id=data["algorithm_id"],
            public_key_hint=data.get("public_key_hint", ""),
        )


# ==============================================================================
# MAIN CLASS: CRYPTO SERVICE
# ==============================================================================


class CryptoService:
    """
    Унифицированный высокоуровневый API криптографической подсистемы.

    Единая точка доступа ко всем криптографическим операциям. Управляет
    выбором алгоритмов через CryptoProfile, логирует все операции.

    Thread Safety:
        CryptoService является stateless — не хранит ключи или промежуточные
        данные. Безопасен для использования из нескольких потоков одновременно.

    Attributes:
        profile: Активный профиль конфигурации
        config: ProfileConfig с algorithm IDs для профиля

    Example:
        >>> service = CryptoService()  # STANDARD profile by default
        >>> service = CryptoService(profile=CryptoProfile.PARANOID)
        >>> service = CryptoService(profile=CryptoProfile.FLOPPY_BASIC)
    """

    def __init__(
        self,
        profile: CryptoProfile = CryptoProfile.STANDARD,
        *,
        registry: Optional[AlgorithmRegistry] = None,
    ) -> None:
        """
        Инициализировать CryptoService.

        Args:
            profile: Профиль конфигурации (алгоритмы по умолчанию).
                     По умолчанию CryptoProfile.STANDARD.
            registry: Реестр алгоритмов. Если None — используется singleton.

        Raises:
            ValueError: Некорректный профиль

        Example:
            >>> service = CryptoService(profile=CryptoProfile.PQC_STANDARD)
        """
        self.profile = profile
        self.config: ProfileConfig = get_profile_config(profile)
        self._registry = registry or AlgorithmRegistry.get_instance()

        logger.info(
            "CryptoService инициализирован с профилем '%s' (%s)",
            profile.value,
            profile.label(),
        )

    # --------------------------------------------------------------------------
    # KEY GENERATION
    # --------------------------------------------------------------------------

    def generate_symmetric_key(self, algorithm_id: Optional[str] = None) -> bytes:
        """
        Сгенерировать случайный симметричный ключ для шифрования.

        Использует CSPRNG (os.urandom) для генерации ключа нужного размера.
        Размер ключа определяется из метаданных алгоритма.

        Args:
            algorithm_id: Registry ID алгоритма. Если None — используется
                          алгоритм из текущего профиля.

        Returns:
            Случайные байты ключа нужного размера

        Raises:
            AlgorithmNotFoundError: Алгоритм не найден в реестре
            CryptoError: Ошибка получения метаданных

        Example:
            >>> key = service.generate_symmetric_key()
            >>> len(key)
            32  # AES-256-GCM key size
            >>> key = service.generate_symmetric_key("chacha20-poly1305")
            >>> len(key)
            32  # ChaCha20-Poly1305 key size
        """
        algo_id = algorithm_id or self.config.symmetric_algorithm
        metadata = self._registry.get_metadata(algo_id)

        key_size = metadata.key_size
        if key_size is None:
            raise CryptoError(
                f"Алгоритм '{algo_id}' не предоставляет key_size в метаданных"
            )

        key = os.urandom(key_size)
        _audit_logger.info(
            "generate_symmetric_key: algorithm=%s key_size=%d", algo_id, key_size
        )
        return key

    def generate_keypair(
        self, algorithm_id: Optional[str] = None
    ) -> Tuple[bytes, bytes]:
        """
        Сгенерировать асимметричную пару ключей (приватный, публичный).

        Работает с алгоритмами подписи (SignatureProtocol) и обмена ключами
        (KeyExchangeProtocol) — оба имеют метод generate_keypair().

        Args:
            algorithm_id: Registry ID алгоритма. Если None — используется
                          алгоритм подписи из текущего профиля.

        Returns:
            Кортеж (private_key_bytes, public_key_bytes)

        Raises:
            AlgorithmNotFoundError: Алгоритм не найден
            CryptoError: Ошибка генерации

        Example:
            >>> private_key, public_key = service.generate_keypair()
            >>> private_key, public_key = service.generate_keypair("ML-DSA-65")
        """
        algo_id = algorithm_id or self.config.signing_algorithm
        algorithm = self._registry.create(algo_id)

        if not hasattr(algorithm, "generate_keypair"):
            raise CryptoError(
                f"Алгоритм '{algo_id}' не поддерживает generate_keypair(). "
                f"Используйте алгоритм подписи или обмена ключами."
            )

        private_key, public_key = algorithm.generate_keypair()
        pub_hint = public_key[:8].hex() if len(public_key) >= 8 else public_key.hex()
        _audit_logger.info(
            "generate_keypair: algorithm=%s public_key_hint=%s", algo_id, pub_hint
        )
        return private_key, public_key

    # --------------------------------------------------------------------------
    # SYMMETRIC ENCRYPTION
    # --------------------------------------------------------------------------

    def encrypt_document(
        self,
        document: bytes,
        key: bytes,
        *,
        algorithm_id: Optional[str] = None,
        aad: Optional[bytes] = None,
    ) -> EncryptedDocument:
        """
        Зашифровать документ симметричным шифром.

        Использует AEAD (Authenticated Encryption with Associated Data) если
        алгоритм его поддерживает. Nonce генерируется случайно (CSPRNG).

        Args:
            document: Данные для шифрования (минимум 1 байт)
            key: Ключ шифрования (размер должен соответствовать алгоритму)
            algorithm_id: Registry ID симметричного алгоритма. По умолчанию
                          из профиля (например, "aes-256-gcm").
            aad: Additional Authenticated Data (только для AEAD алгоритмов).
                 Данные аутентифицируются, но не шифруются.

        Returns:
            EncryptedDocument с nonce, ciphertext, algorithm_id

        Raises:
            ValueError: Пустой документ или некорректный ключ
            AlgorithmNotFoundError: Алгоритм не найден в реестре
            EncryptionError: Ошибка шифрования

        Example:
            >>> key = service.generate_symmetric_key()
            >>> encrypted = service.encrypt_document(b"Invoice #123", key)
            >>> encrypted.algorithm_id
            'aes-256-gcm'
        """
        if not document:
            raise ValueError("Документ не может быть пустым")
        if not key:
            raise ValueError("Ключ не может быть пустым")

        algo_id = algorithm_id or self.config.symmetric_algorithm

        cipher: SymmetricCipherProtocol = self._registry.create(algo_id)

        try:
            nonce, ciphertext = cipher.encrypt(key, document, aad=aad)
        except Exception as exc:
            _audit_logger.error(
                "encrypt_document FAILED: algorithm=%s data_size=%d error=%s",
                algo_id,
                len(document),
                type(exc).__name__,
            )
            raise EncryptionError(
                f"Ошибка шифрования документа алгоритмом '{algo_id}': {exc}",
                algorithm=algo_id,
            ) from exc

        _audit_logger.info(
            "encrypt_document: algorithm=%s data_size=%d ciphertext_size=%d",
            algo_id,
            len(document),
            len(ciphertext),
        )
        return EncryptedDocument(
            nonce=nonce,
            ciphertext=ciphertext,
            algorithm_id=algo_id,
            aad=aad,
        )

    def decrypt_document(
        self,
        encrypted: EncryptedDocument,
        key: bytes,
    ) -> bytes:
        """
        Расшифровать документ.

        Использует algorithm_id из EncryptedDocument — не нужно помнить
        какой алгоритм использовался при шифровании.

        Args:
            encrypted: Результат encrypt_document()
            key: Ключ расшифровки (тот же, что при шифровании)

        Returns:
            Исходные данные (plaintext)

        Raises:
            ValueError: Некорректный ключ или encrypted объект
            AlgorithmNotFoundError: Алгоритм не найден в реестре
            DecryptionError: Ошибка расшифровки (неверный ключ или повреждены данные)

        Example:
            >>> plaintext = service.decrypt_document(encrypted, key)
            >>> assert plaintext == original_document
        """
        if not key:
            raise ValueError("Ключ не может быть пустым")

        algo_id = encrypted.algorithm_id
        cipher: SymmetricCipherProtocol = self._registry.create(algo_id)

        try:
            plaintext = cipher.decrypt(
                key, encrypted.nonce, encrypted.ciphertext, aad=encrypted.aad
            )
        except Exception as exc:
            _audit_logger.warning(
                "decrypt_document FAILED: algorithm=%s error=%s",
                algo_id,
                type(exc).__name__,
            )
            raise DecryptionError(
                f"Ошибка расшифровки алгоритмом '{algo_id}'. "
                "Проверьте правильность ключа и целостность данных.",
                algorithm=algo_id,
            ) from exc

        _audit_logger.info(
            "decrypt_document: algorithm=%s plaintext_size=%d",
            algo_id,
            len(plaintext),
        )
        return plaintext

    # --------------------------------------------------------------------------
    # DIGITAL SIGNATURES
    # --------------------------------------------------------------------------

    def sign_document(
        self,
        document: bytes,
        private_key: bytes,
        *,
        algorithm_id: Optional[str] = None,
    ) -> SignedDocument:
        """
        Создать цифровую подпись документа.

        Args:
            document: Данные для подписи
            private_key: Приватный ключ подписанта (DER/raw формат)
            algorithm_id: Registry ID алгоритма подписи. По умолчанию
                          из профиля (например, "Ed25519").

        Returns:
            SignedDocument с подписью и метаданными

        Raises:
            ValueError: Пустой документ или ключ
            AlgorithmNotFoundError: Алгоритм не найден
            SignatureError: Ошибка подписи

        Example:
            >>> private_key, public_key = service.generate_keypair()
            >>> signed = service.sign_document(b"Invoice data", private_key)
            >>> signed.algorithm_id
            'Ed25519'
        """
        if not document:
            raise ValueError("Документ для подписи не может быть пустым")
        if not private_key:
            raise ValueError("Приватный ключ не может быть пустым")

        algo_id = algorithm_id or self.config.signing_algorithm
        signer: SignatureProtocol = self._registry.create(algo_id)

        try:
            signature = signer.sign(private_key, document)
        except Exception as exc:
            _audit_logger.error(
                "sign_document FAILED: algorithm=%s data_size=%d error=%s",
                algo_id,
                len(document),
                type(exc).__name__,
            )
            raise SignatureError(
                f"Ошибка создания подписи алгоритмом '{algo_id}': {exc}",
                algorithm=algo_id,
            ) from exc

        _audit_logger.info(
            "sign_document: algorithm=%s data_size=%d sig_size=%d",
            algo_id,
            len(document),
            len(signature),
        )
        return SignedDocument(
            signature=signature,
            algorithm_id=algo_id,
            public_key_hint="",  # публичный ключ неизвестен здесь
        )

    def verify_signature(
        self,
        document: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm_id: str,
    ) -> bool:
        """
        Проверить цифровую подпись документа.

        Args:
            document: Исходные данные (те же, что подписывались)
            signature: Байты подписи (из SignedDocument.signature)
            public_key: Публичный ключ подписанта
            algorithm_id: Registry ID алгоритма (из SignedDocument.algorithm_id)

        Returns:
            True если подпись верна, False если нет

        Raises:
            ValueError: Пустые аргументы
            AlgorithmNotFoundError: Алгоритм не найден

        Note:
            Функция возвращает False (не бросает исключение) при неверной
            подписи — это ожидаемый результат верификации, а не ошибка.

        Example:
            >>> is_valid = service.verify_signature(
            ...     document, signed.signature, public_key, signed.algorithm_id
            ... )
            >>> assert is_valid is True
        """
        if not document:
            raise ValueError("Документ не может быть пустым")
        if not signature:
            raise ValueError("Подпись не может быть пустой")
        if not public_key:
            raise ValueError("Публичный ключ не может быть пустым")

        signer: SignatureProtocol = self._registry.create(algorithm_id)

        try:
            result = signer.verify(public_key, document, signature)
        except Exception as exc:
            _audit_logger.warning(
                "verify_signature EXCEPTION: algorithm=%s error=%s",
                algorithm_id,
                type(exc).__name__,
            )
            # Ошибка верификации = подпись недействительна
            logger.debug("Верификация подписи вызвала исключение: %s", exc)
            return False

        _audit_logger.info(
            "verify_signature: algorithm=%s result=%s", algorithm_id, result
        )
        return bool(result)

    # --------------------------------------------------------------------------
    # HYBRID ENCRYPTION
    # --------------------------------------------------------------------------

    def encrypt_hybrid(
        self,
        document: bytes,
        recipient_public_key: bytes,
        *,
        config_name: str = "classical_standard",
    ) -> Dict[str, bytes]:
        """
        Зашифровать документ для получателя используя гибридное шифрование.

        Гибридное шифрование = KEX (обмен ключами) + симметричное шифрование.
        Позволяет шифровать данные любого размера для публичного ключа
        получателя без необходимости предварительного обмена симметричным ключом.

        Поддерживаемые конфигурации:
            "classical_standard"  — X25519 + AES-256-GCM (рекомендуется)
            "classical_paranoid"  — X448 + ChaCha20-Poly1305
            "pqc_standard"        — ML-KEM-768 + AES-256-GCM (post-quantum)
            "pqc_paranoid"        — ML-KEM-1024 + ChaCha20-Poly1305

        Args:
            document: Данные для шифрования
            recipient_public_key: Публичный ключ получателя
            config_name: Конфигурация гибридного шифрования

        Returns:
            Словарь с зашифрованными данными:
            {
                "ephemeral_public_key": bytes,  # для KEX
                "nonce": bytes,
                "ciphertext": bytes,
                "config": str  # имя конфигурации
            }

        Raises:
            ValueError: Пустые аргументы
            CryptoError: Ошибка шифрования

        Example:
            >>> _, recipient_pub = service.generate_keypair("x25519")
            >>> encrypted = service.encrypt_hybrid(b"Secret", recipient_pub)
            >>> plaintext = service.decrypt_hybrid(encrypted, recipient_priv)
        """
        if not document:
            raise ValueError("Документ не может быть пустым")
        if not recipient_public_key:
            raise ValueError("Публичный ключ получателя не может быть пустым")

        from src.security.crypto.advanced.hybrid_encryption import (
            HybridEncryption,
            create_hybrid_cipher,
        )

        cipher = create_hybrid_cipher(config_name)
        result = cipher.encrypt_for_recipient(recipient_public_key, document)

        _audit_logger.info(
            "encrypt_hybrid: config=%s data_size=%d", config_name, len(document)
        )
        return result  # type: ignore[return-value]

    def decrypt_hybrid(
        self,
        encrypted_data: Dict[str, bytes],
        recipient_private_key: bytes,
    ) -> bytes:
        """
        Расшифровать данные гибридного шифрования.

        Args:
            encrypted_data: Результат encrypt_hybrid() (словарь с ephemeral_public_key,
                            nonce, ciphertext, config)
            recipient_private_key: Приватный ключ получателя

        Returns:
            Исходные данные (plaintext)

        Raises:
            ValueError: Пустые аргументы или некорректный формат данных
            DecryptionError: Ошибка расшифровки

        Example:
            >>> plaintext = service.decrypt_hybrid(encrypted_data, private_key)
        """
        if not recipient_private_key:
            raise ValueError("Приватный ключ не может быть пустым")

        from src.security.crypto.advanced.hybrid_encryption import create_hybrid_cipher

        config_name = str(encrypted_data.get("config", b"classical_standard"))
        if isinstance(config_name, bytes):
            config_name = config_name.decode()

        cipher = create_hybrid_cipher(config_name)

        try:
            plaintext = cipher.decrypt_from_sender(recipient_private_key, encrypted_data)
        except Exception as exc:
            _audit_logger.warning(
                "decrypt_hybrid FAILED: config=%s error=%s",
                config_name,
                type(exc).__name__,
            )
            raise DecryptionError(
                f"Ошибка расшифровки гибридного шифра ({config_name})",
                algorithm=config_name,
            ) from exc

        _audit_logger.info(
            "decrypt_hybrid: config=%s plaintext_size=%d", config_name, len(plaintext)
        )
        return plaintext

    # --------------------------------------------------------------------------
    # HASHING
    # --------------------------------------------------------------------------

    def hash_data(
        self,
        data: bytes,
        *,
        algorithm_id: Optional[str] = None,
    ) -> bytes:
        """
        Вычислить криптографический хеш данных.

        Args:
            data: Данные для хеширования
            algorithm_id: Registry ID хеш-алгоритма. По умолчанию из профиля
                          (например, "sha256").

        Returns:
            Байты дайджеста

        Raises:
            ValueError: Пустые данные
            AlgorithmNotFoundError: Алгоритм не найден
            CryptoError: Ошибка хеширования

        Example:
            >>> digest = service.hash_data(b"Document content")
            >>> len(digest)
            32  # SHA-256 output size
        """
        if not data:
            raise ValueError("Данные для хеширования не могут быть пустыми")

        algo_id = algorithm_id or self.config.hash_algorithm
        hasher: HashProtocol = self._registry.create(algo_id)
        return hasher.hash(data)

    # --------------------------------------------------------------------------
    # KEY DERIVATION
    # --------------------------------------------------------------------------

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        *,
        algorithm_id: Optional[str] = None,
        key_length: int = 32,
    ) -> bytes:
        """
        Вывести криптографический ключ из пароля.

        Args:
            password: Пароль (байты)
            salt: Соль (случайная, минимум 16 байт)
            algorithm_id: Registry ID KDF. По умолчанию из профиля ("argon2id").
            key_length: Длина выходного ключа в байтах (по умолчанию 32)

        Returns:
            Ключ заданной длины

        Raises:
            ValueError: Пустой пароль или слишком короткая соль
            AlgorithmNotFoundError: Алгоритм не найден

        Example:
            >>> salt = os.urandom(32)
            >>> key = service.derive_key(b"MyPassword", salt)
            >>> len(key)
            32
        """
        if not password:
            raise ValueError("Пароль не может быть пустым")
        if len(salt) < 16:
            raise ValueError(
                f"Соль слишком короткая: {len(salt)} байт (минимум 16)"
            )

        algo_id = algorithm_id or self.config.kdf_algorithm
        kdf: KDFProtocol = self._registry.create(algo_id)
        return kdf.derive_key(password, salt, key_length=key_length)

    # --------------------------------------------------------------------------
    # ALGORITHM DISCOVERY
    # --------------------------------------------------------------------------

    def get_default_algorithms(self) -> Dict[str, str]:
        """
        Получить алгоритмы по умолчанию для текущего профиля.

        Returns:
            Словарь {категория: algorithm_id}

        Example:
            >>> service = CryptoService(CryptoProfile.STANDARD)
            >>> service.get_default_algorithms()
            {'symmetric': 'aes-256-gcm', 'signing': 'Ed25519', ...}
        """
        return self.config.algorithm_ids()

    def get_available_algorithms(
        self, category: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Получить список доступных алгоритмов с метаданными.

        Args:
            category: Фильтр по категории ("symmetric", "signing", "hash", "kdf",
                      "kex", "asymmetric"). Если None — все категории.

        Returns:
            Словарь {algorithm_id: {"name": str, "security_level": str,
                     "floppy_friendly": int, "is_post_quantum": bool}}

        Example:
            >>> algos = service.get_available_algorithms("symmetric")
            >>> "aes-256-gcm" in algos
            True
        """
        _category_map = {
            "symmetric": AlgorithmCategory.SYMMETRIC_CIPHER,
            "signing": AlgorithmCategory.SIGNATURE,
            "asymmetric": AlgorithmCategory.ASYMMETRIC_ENCRYPTION,
            "kex": AlgorithmCategory.KEY_EXCHANGE,
            "hash": AlgorithmCategory.HASH,
            "kdf": AlgorithmCategory.KDF,
        }

        result: Dict[str, Any] = {}
        target_category = _category_map.get(category) if category else None

        for name in self._registry.list_algorithms():
            try:
                meta = self._registry.get_metadata(name)
            except Exception:
                continue

            if target_category is not None and meta.category != target_category:
                continue

            result[name] = {
                "name": meta.name,
                "security_level": meta.security_level.value,
                "floppy_friendly": meta.floppy_friendly.value,
                "is_post_quantum": meta.is_post_quantum,
                "is_aead": meta.is_aead,
                "status": meta.status.value,
                "description_ru": meta.description_ru,
            }

        return result

    def is_algorithm_available(self, algorithm_id: str) -> bool:
        """
        Проверить, доступен ли алгоритм в реестре.

        Args:
            algorithm_id: Registry ID алгоритма

        Returns:
            True если алгоритм зарегистрирован

        Example:
            >>> service.is_algorithm_available("aes-256-gcm")
            True
            >>> service.is_algorithm_available("unknown-algo")
            False
        """
        return self._registry.is_registered(algorithm_id)

    # --------------------------------------------------------------------------
    # FLOPPY DISK HELPERS (Phase 8 — partial implementation)
    # --------------------------------------------------------------------------

    def estimate_storage_size(
        self,
        data_size: int,
        *,
        include_signature: bool = True,
        algorithm_id: Optional[str] = None,
        signing_algorithm_id: Optional[str] = None,
    ) -> Dict[str, int]:
        """
        Оценить размер зашифрованных+подписанных данных.

        Используется для проверки, поместятся ли данные на дискету 1.44 MB.
        Оценка приближённая — реальный размер может отличаться на ~1-5%.

        Note:
            Полная оптимизация для дискет (сжатие, compact format) будет
            реализована в Phase 8 при создании utils/floppy_optimizer.py.

        Args:
            data_size: Размер исходных данных в байтах
            include_signature: Учитывать ли размер подписи
            algorithm_id: ID симметричного алгоритма (по умолчанию из профиля)
            signing_algorithm_id: ID алгоритма подписи (по умолчанию из профиля)

        Returns:
            Словарь с оценками в байтах:
            {
                "plaintext": <data_size>,
                "encrypted": <data_size + nonce + tag>,
                "signature": <размер подписи если include_signature>,
                "total": <общий размер>,
                "floppy_fits": <True если total < 1.44 MB>
            }

        Example:
            >>> sizes = service.estimate_storage_size(50_000)
            >>> sizes["total"]
            50096  # для AES-256-GCM: 50000 + 12 (nonce) + 16 (tag) + 64 (Ed25519)
            >>> sizes["floppy_fits"]
            True
        """
        FLOPPY_MAX_BYTES = 1_474_560  # 1.44 MB в байтах

        sym_id = algorithm_id or self.config.symmetric_algorithm
        sig_id = signing_algorithm_id or self.config.signing_algorithm

        try:
            sym_meta = self._registry.get_metadata(sym_id)
            nonce_size = sym_meta.nonce_size or 12
            tag_size = 16 if sym_meta.is_aead else 0
        except Exception:
            nonce_size, tag_size = 12, 16

        encrypted_size = data_size + nonce_size + tag_size

        signature_size = 0
        if include_signature:
            try:
                sig_meta = self._registry.get_metadata(sig_id)
                signature_size = sig_meta.signature_size or 64
            except Exception:
                signature_size = 64

        total = encrypted_size + signature_size
        return {
            "plaintext": data_size,
            "encrypted": encrypted_size,
            "signature": signature_size,
            "total": total,
            "floppy_fits": total <= FLOPPY_MAX_BYTES,
        }

    # --------------------------------------------------------------------------
    # REPR / STRING
    # --------------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"CryptoService("
            f"profile={self.profile.value!r}, "
            f"sym={self.config.symmetric_algorithm!r}, "
            f"sign={self.config.signing_algorithm!r})"
        )


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-17"
