"""
Иерархия исключений для криптографической подсистемы.

Централизованные исключения обеспечивают:
- Единый обработчик ошибок на верхних уровнях
- Чёткую типизацию ошибок
- Структурированное логирование

Иерархия:
    CryptoError (базовое)
    ├── EncryptionError
    ├── DecryptionError
    ├── SignatureError
    │   ├── InvalidSignatureError
    │   ├── SignatureVerificationError
    │   └── SignatureGenerationError
    ├── KeyError
    │   ├── KeyNotFoundError
    │   ├── KeyGenerationError
    │   ├── InvalidKeyError
    │   └── KeyRotationError
    ├── KdfError
    │   ├── KDFParameterError
    │   └── KDFAlgorithmError
    ├── HashingError
    │   └── HashSchemeError
    └── StorageError
        ├── StorageReadError
        └── StorageWriteError

Example:
    >>> from security.crypto.exceptions import DecryptionError
    >>> try:
    ...     cipher.decrypt(bad_data, key, nonce)
    ... except DecryptionError as e:
    ...     logger.error(f"Decryption failed: {e}")
"""

from typing import Optional, Any


class CryptoError(Exception):
    """
    Базовое исключение для всех криптографических ошибок.

    Все специфичные исключения должны наследоваться от этого класса.
    """

    def __init__(
        self,
        message: str,
        cause: Optional[Exception] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Args:
            message: Описание ошибки
            cause: Исходное исключение (если есть)
            details: Дополнительная информация для логирования
        """
        super().__init__(message)
        self.message = message
        self.cause = cause
        self.details = details or {}


# ============================================================================
# Encryption/Decryption Errors
# ============================================================================


class EncryptionError(CryptoError):
    """Ошибка при шифровании данных."""

    pass


class DecryptionError(CryptoError):
    """
    Ошибка при дешифровании данных.

    Может быть вызвана:
    - Неверным ключом
    - Повреждёнными данными
    - Неверным MAC/тегом аутентификации
    """

    pass


# ============================================================================
# Signature Errors
# ============================================================================


class SignatureError(CryptoError):
    """Базовое исключение для ошибок подписи."""

    pass


class InvalidSignatureError(SignatureError):
    """Цифровая подпись недействительна или повреждена."""

    pass


class SignatureVerificationError(SignatureError):
    """Ошибка при проверке цифровой подписи."""

    pass


class SignatureGenerationError(SignatureError):
    """Ошибка при создании цифровой подписи."""

    pass


# ============================================================================
# Key Management Errors
# ============================================================================


class KeyError(CryptoError):
    """Базовое исключение для ошибок управления ключами."""

    pass


class KeyNotFoundError(KeyError):
    """Ключ не найден в хранилище."""

    def __init__(self, key_id: str, message: Optional[str] = None) -> None:
        """
        Args:
            key_id: Идентификатор ненайденного ключа
            message: Кастомное сообщение (опционально)
        """
        msg = message or f"Key '{key_id}' not found in keystore"
        super().__init__(msg, details={"key_id": key_id})
        self.key_id = key_id


class KeyGenerationError(KeyError):
    """Ошибка при генерации ключа."""

    pass


class InvalidKeyError(KeyError):
    """
    Неверный формат, длина или содержимое ключа.

    Может быть вызвана:
    - Неправильной длиной ключа
    - Некорректным форматом (PEM/DER)
    - Повреждённым ключом
    """

    pass


class KeyRotationError(KeyError):
    """Ошибка при ротации ключа."""

    pass


# ============================================================================
# KDF Errors
# ============================================================================


class KdfError(CryptoError):
    """Базовое исключение для ошибок Key Derivation Function."""

    pass


class KDFParameterError(KdfError):
    """
    Неверные параметры для KDF.

    Может быть вызвана:
    - Слишком коротким/длинным паролем
    - Неверной длиной соли
    - Некорректными параметрами Argon2id (memory, time, parallelism)
    """

    pass


class KDFAlgorithmError(KdfError):
    """Неподдерживаемый или неизвестный алгоритм KDF."""

    pass


class KDFEntropyWarning(Warning):
    """
    Предупреждение о низкой энтропии пароля/соли.

    Не останавливает выполнение, но логируется для аудита.
    """

    pass


# ============================================================================
# Hashing Errors
# ============================================================================


class HashingError(CryptoError):
    """Ошибка при хешировании или HMAC."""

    pass


class HashSchemeError(HashingError):
    """Неподдерживаемая схема хеширования."""

    def __init__(self, scheme: str) -> None:
        """
        Args:
            scheme: Название неподдерживаемой схемы
        """
        super().__init__(
            f"Unsupported hashing scheme: '{scheme}'", details={"scheme": scheme}
        )
        self.scheme = scheme


# ============================================================================
# Storage Errors
# ============================================================================


class StorageError(CryptoError):
    """Базовое исключение для ошибок хранилища."""

    pass


class StorageReadError(StorageError):
    """Ошибка при чтении из зашифрованного хранилища."""

    pass


class StorageWriteError(StorageError):
    """Ошибка при записи в зашифрованное хранилище."""

    pass


# ============================================================================
# Configuration Errors
# ============================================================================


class ConfigurationError(CryptoError):
    """Ошибка конфигурации криптографической подсистемы."""

    pass


class UnsupportedAlgorithmError(ConfigurationError):
    """Запрошенный алгоритм не поддерживается."""

    def __init__(self, algorithm: str) -> None:
        """
        Args:
            algorithm: Название неподдерживаемого алгоритма
        """
        super().__init__(
            f"Algorithm '{algorithm}' is not supported",
            details={"algorithm": algorithm},
        )
        self.algorithm = algorithm


# ============================================================================
# Export for convenience
# ============================================================================

__all__ = [
    # Base
    "CryptoError",
    # Encryption/Decryption
    "EncryptionError",
    "DecryptionError",
    # Signatures
    "SignatureError",
    "InvalidSignatureError",
    "SignatureVerificationError",
    "SignatureGenerationError",
    # Keys
    "KeyError",
    "KeyNotFoundError",
    "KeyGenerationError",
    "InvalidKeyError",
    "KeyRotationError",
    # KDF
    "KdfError",
    "KDFParameterError",
    "KDFAlgorithmError",
    "KDFEntropyWarning",
    # Hashing
    "HashingError",
    "HashSchemeError",
    # Storage
    "StorageError",
    "StorageReadError",
    "StorageWriteError",
    # Configuration
    "ConfigurationError",
    "UnsupportedAlgorithmError",
]
