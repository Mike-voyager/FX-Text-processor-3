"""
Централизованные исключения криптографического модуля.

Иерархия типизированных исключений для всех 46 алгоритмов
из CRYPTO_MASTER_PLAN v2.3. Обеспечивает единообразную обработку
ошибок и безопасность (NO раскрытия секретных данных).

Example:
    >>> from src.security.crypto.core.exceptions import CryptoError
    >>> try:
    ...     cipher.encrypt(key, plaintext)
    ... except CryptoError as e:
    ...     logger.error(f"Crypto failed: {e}")
    ...     print(f"Algorithm: {e.algorithm}")

Иерархия:
    CryptoError (базовое)
    ├── AlgorithmError
    ├── CryptoKeyError
    ├── EncryptionError
    ├── SignatureError
    ├── HashError
    ├── ProtocolError
    ├── RegistryError
    └── ValidationError

Security Note:
    Все исключения НЕ раскрывают:
    - Ключи или их части
    - Plaintext или ciphertext
    - Nonce/IV значения
    - Другие чувствительные данные

Version: 1.0
Date: February 9, 2026
Priority: 🔴 CRITICAL (Phase 1, Day 1)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__: list[str] = [
    # Base exception
    "CryptoError",
    # Algorithm errors
    "AlgorithmError",
    "AlgorithmNotFoundError",
    "AlgorithmNotSupportedError",
    "AlgorithmNotAvailableError",
    "AlgorithmInitializationError",
    # Key errors
    "CryptoKeyError",
    "InvalidKeyError",
    "InvalidKeySizeError",
    "KeyGenerationError",
    "KeyDerivationError",
    # Encryption errors
    "EncryptionError",
    "EncryptionFailedError",
    "DecryptionError",
    "DecryptionFailedError",
    "InvalidNonceError",
    "InvalidTagError",
    "PlaintextTooLargeError",
    # Signature errors
    "SignatureError",
    "SigningFailedError",
    "VerificationFailedError",
    "InvalidSignatureError",
    # Hash errors
    "HashError",
    "HashingFailedError",
    "InvalidDigestError",
    # Protocol errors
    "ProtocolError",
    "ProtocolMismatchError",
    "ProtocolViolationError",
    # Registry errors
    "RegistryError",
    "AlgorithmNotRegisteredError",
    "DuplicateRegistrationError",
    # Validation errors
    "ValidationError",
    "InvalidParameterError",
    "InvalidInputError",
    "InvalidOutputError",
    # Hardware device errors
    "HardwareDeviceError",
    "DeviceNotFoundError",
    "DeviceCommunicationError",
    "PINError",
    "SlotError",
]


# ==============================================================================
# BASE EXCEPTION
# ==============================================================================


class CryptoError(Exception):
    """
    Базовое исключение для всех криптографических ошибок.

    Все исключения криптографического модуля наследуют от этого класса.
    Позволяет перехватывать любые криптографические ошибки через один тип.

    Attributes:
        message: Человекочитаемое сообщение об ошибке
        algorithm: Имя алгоритма, вызвавшего ошибку (опционально)
        context: Дополнительный контекст для отладки (опционально)

    Example:
        >>> try:
        ...     cipher.encrypt(key, plaintext)
        ... except CryptoError as e:
        ...     logger.error(f"Crypto operation failed: {e}")
        ...     print(f"Algorithm: {e.algorithm}")

    Security Note:
        Сообщения ошибок НЕ должны содержать:
        - Ключи или их части
        - Plaintext или ciphertext
        - Nonce/IV значения
        - Другие чувствительные данные
    """

    def __init__(
        self,
        message: str,
        *,
        algorithm: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Инициализация базового исключения.

        Args:
            message: Человекочитаемое описание ошибки
            algorithm: Имя алгоритма (например, "AES-256-GCM")
            context: Дополнительный контекст (без секретов!)

        Example:
            >>> raise CryptoError(
            ...     "Operation failed",
            ...     algorithm="AES-256-GCM",
            ...     context={"operation": "encrypt", "reason": "invalid_input"}
            ... )
        """
        super().__init__(message)
        self.message = message
        self.algorithm = algorithm
        self.context = context or {}

    def __str__(self) -> str:
        """
        Строковое представление исключения.

        Returns:
            Форматированное сообщение с контекстом

        Example:
            >>> str(error)
            'CryptoError: Operation failed [algorithm=AES-256-GCM]'
        """
        parts = [self.__class__.__name__, ": ", self.message]

        if self.algorithm:
            parts.append(f" [algorithm={self.algorithm}]")

        if self.context:
            ctx_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f" ({ctx_str})")

        return "".join(parts)

    def __repr__(self) -> str:
        """Представление для отладки."""
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"algorithm={self.algorithm!r}, "
            f"context={self.context!r})"
        )


# ==============================================================================
# ALGORITHM ERRORS
# ==============================================================================


class AlgorithmError(CryptoError):
    """
    Ошибки, связанные с алгоритмами.

    Используется для проблем с выбором, инициализацией
    или работой криптографических алгоритмов.

    Example:
        >>> raise AlgorithmError("Algorithm initialization failed")
    """

    pass


class AlgorithmNotFoundError(AlgorithmError):
    """
    Алгоритм не найден в реестре.

    Raises когда:
    - Запрошен несуществующий алгоритм
    - Алгоритм не зарегистрирован в реестре

    Attributes:
        algorithm_name: Имя запрошенного алгоритма
        available: Список доступных алгоритмов

    Example:
        >>> registry.create("NonExistent-Algorithm")
        AlgorithmNotFoundError: Algorithm 'NonExistent-Algorithm' not found in registry
    """

    def __init__(
        self,
        algorithm_name: str,
        available: Optional[List[str]] = None,
    ) -> None:
        """
        Инициализация ошибки.

        Args:
            algorithm_name: Имя запрошенного алгоритма
            available: Список доступных алгоритмов (опционально)
        """
        message = f"Algorithm '{algorithm_name}' not found in registry"

        if available:
            message += f". Available: {', '.join(available[:5])}"
            if len(available) > 5:
                message += f" ... ({len(available)} total)"

        super().__init__(
            message,
            algorithm=algorithm_name,
            context={"available_count": len(available) if available else 0},
        )
        self.algorithm_name = algorithm_name
        self.available = available or []


class AlgorithmNotSupportedError(AlgorithmError):
    """
    Алгоритм не поддерживается в текущей конфигурации.

    Raises когда:
    - Отсутствует необходимая библиотека (liboqs-python для PQC)
    - Платформа не поддерживает алгоритм
    - Аппаратное ускорение недоступно

    Attributes:
        reason: Причина отсутствия поддержки
        required_library: Требуемая библиотека (если применимо)

    Example:
        >>> cipher = Kyber768()
        AlgorithmNotSupportedError: Algorithm 'Kyber768' requires liboqs-python library
    """

    def __init__(
        self,
        algorithm: str,
        reason: str,
        *,
        required_library: Optional[str] = None,
    ) -> None:
        """
        Инициализация ошибки.

        Args:
            algorithm: Имя алгоритма
            reason: Причина отсутствия поддержки
            required_library: Требуемая библиотека (если применимо)
        """
        message = f"Algorithm '{algorithm}' not supported: {reason}"

        context: Dict[str, Any] = {"reason": reason}
        if required_library:
            context["required_library"] = required_library

        super().__init__(message, algorithm=algorithm, context=context)
        self.reason = reason
        self.required_library = required_library


class AlgorithmNotAvailableError(AlgorithmNotSupportedError):
    """Алгоритм недоступен (отсутствует библиотека или аппаратная поддержка)."""

    pass


class AlgorithmInitializationError(AlgorithmError):
    """
    Ошибка инициализации алгоритма.

    Raises когда:
    - Не удалось создать экземпляр алгоритма
    - Ошибка загрузки библиотеки
    - Некорректная конфигурация

    Example:
        >>> algo = SomeAlgorithm()
        AlgorithmInitializationError: Failed to initialize algorithm
    """

    pass


# ==============================================================================
# KEY ERRORS
# ==============================================================================


class CryptoKeyError(CryptoError):
    """
    Базовая ошибка для операций с ключами.

    Note:
        Названа CryptoKeyError чтобы не конфликтовать с builtin KeyError.

    Example:
        >>> raise CryptoKeyError("Key operation failed")
    """

    pass


class InvalidKeyError(CryptoKeyError):
    """
    Некорректный ключ.

    Raises когда:
    - Ключ имеет неверный формат
    - Ключ не соответствует спецификации алгоритма
    - Ключ поврежден

    Attributes:
        expected_size: Ожидаемый размер ключа в байтах
        actual_size: Фактический размер ключа в байтах

    Example:
        >>> cipher.encrypt(b"short_key", plaintext)
        InvalidKeyError: Key must be 32 bytes for AES-256-GCM, got 9 bytes
    """

    def __init__(
        self,
        message: str,
        *,
        algorithm: Optional[str] = None,
        expected_size: Optional[int] = None,
        actual_size: Optional[int] = None,
    ) -> None:
        """
        Инициализация ошибки.

        Args:
            message: Описание ошибки
            algorithm: Имя алгоритма
            expected_size: Ожидаемый размер ключа в байтах
            actual_size: Фактический размер ключа в байтах
        """
        context: Dict[str, Any] = {}
        if expected_size is not None:
            context["expected_size"] = expected_size
        if actual_size is not None:
            context["actual_size"] = actual_size

        super().__init__(message, algorithm=algorithm, context=context)
        self.expected_size = expected_size
        self.actual_size = actual_size


class InvalidKeySizeError(InvalidKeyError):
    """
    Неверный размер ключа.

    Специализированное исключение для ошибок размера ключа.

    Example:
        >>> InvalidKeySizeError("AES-256-GCM", 32, 16)
        InvalidKeySizeError: Invalid key size for AES-256-GCM: expected 32 bytes, got 16 bytes
    """

    def __init__(
        self,
        algorithm: str,
        expected: int,
        actual: int,
    ) -> None:
        """
        Инициализация ошибки размера ключа.

        Args:
            algorithm: Имя алгоритма
            expected: Ожидаемый размер в байтах
            actual: Фактический размер в байтах
        """
        message = (
            f"Invalid key size for {algorithm}: "
            f"expected {expected} bytes, got {actual} bytes"
        )
        super().__init__(
            message,
            algorithm=algorithm,
            expected_size=expected,
            actual_size=actual,
        )


class KeyGenerationError(CryptoKeyError):
    """
    Ошибка генерации ключа.

    Raises когда:
    - Не удалось сгенерировать ключ
    - Недостаточно энтропии
    - Ошибка CSPRNG

    Example:
        >>> key = algo.generate_key()
        KeyGenerationError: Failed to generate key: insufficient entropy
    """

    pass


class KeyDerivationError(CryptoKeyError):
    """
    Ошибка вывода ключа (KDF).

    Raises когда:
    - Не удалось вывести ключ из пароля
    - Некорректные параметры KDF
    - Ошибка Argon2id/PBKDF2/HKDF/Scrypt

    Example:
        >>> key = kdf.derive(password, salt)
        KeyDerivationError: Key derivation failed with Argon2id
    """

    pass


# ==============================================================================
# ENCRYPTION ERRORS
# ==============================================================================


class EncryptionError(CryptoError):
    """
    Базовая ошибка операций шифрования.

    Example:
        >>> raise EncryptionError("Encryption operation failed")
    """

    pass


class EncryptionFailedError(EncryptionError):
    """
    Неудачное шифрование.

    Raises когда:
    - Ошибка во время шифрования
    - Некорректные параметры
    - Внутренняя ошибка алгоритма

    Example:
        >>> ciphertext = cipher.encrypt(key, plaintext)
        EncryptionFailedError: Encryption failed for AES-256-GCM
    """

    pass


class DecryptionError(EncryptionError):
    """Базовый класс ошибок расшифровки."""

    pass


class DecryptionFailedError(EncryptionError):
    """
    Неудачная расшифровка.

    Raises когда:
    - Расшифровка не удалась
    - Неверный ключ
    - Поврежденный ciphertext
    - Неверный authentication tag (для AEAD)

    Security Note:
        Для AEAD шифров причина неудачи НЕ раскрывается
        (timing attack prevention).

    Example:
        >>> plaintext = cipher.decrypt(key, ciphertext, tag)
        DecryptionFailedError: Decryption failed (authentication tag mismatch)
    """

    pass


class InvalidNonceError(EncryptionError):
    """
    Некорректный nonce/IV.

    Raises когда:
    - Nonce неверного размера
    - Nonce повторно использован (critical security issue!)
    - Nonce в неверном формате

    Attributes:
        expected_size: Ожидаемый размер nonce
        actual_size: Фактический размер nonce

    Example:
        >>> cipher.encrypt(key, plaintext, nonce=b"short")
        InvalidNonceError: Nonce must be 12 bytes for AES-256-GCM, got 5 bytes
    """

    def __init__(
        self,
        message: str,
        *,
        algorithm: Optional[str] = None,
        expected_size: Optional[int] = None,
        actual_size: Optional[int] = None,
    ) -> None:
        """
        Инициализация ошибки nonce.

        Args:
            message: Описание ошибки
            algorithm: Имя алгоритма
            expected_size: Ожидаемый размер nonce
            actual_size: Фактический размер nonce
        """
        context: Dict[str, Any] = {}
        if expected_size is not None:
            context["expected_nonce_size"] = expected_size
        if actual_size is not None:
            context["actual_nonce_size"] = actual_size

        super().__init__(message, algorithm=algorithm, context=context)
        self.expected_size = expected_size
        self.actual_size = actual_size


class InvalidTagError(EncryptionError):
    """
    Некорректный authentication tag (AEAD).

    Raises когда:
    - Tag не прошел проверку (data tampered)
    - Tag неверного размера
    - Tag в неверном формате

    Security Note:
        Сообщение НЕ должно раскрывать детали атаки.

    Example:
        >>> plaintext = cipher.decrypt(key, ciphertext, wrong_tag)
        InvalidTagError: Authentication tag verification failed
    """

    pass


class PlaintextTooLargeError(EncryptionError):
    """
    Plaintext превышает максимальный размер.

    Raises когда:
    - Для RSA-OAEP: plaintext > (key_size - padding_overhead)
    - Для других алгоритмов с ограничениями размера

    Attributes:
        max_size: Максимальный размер plaintext
        actual_size: Фактический размер plaintext

    Example:
        >>> rsa_cipher.encrypt(public_key, large_plaintext)
        PlaintextTooLargeError: Plaintext too large for RSA-OAEP-2048 (max 190 bytes)
    """

    def __init__(
        self,
        algorithm: str,
        max_size: int,
        actual_size: int,
    ) -> None:
        """
        Инициализация ошибки.

        Args:
            algorithm: Имя алгоритма
            max_size: Максимальный размер plaintext
            actual_size: Фактический размер plaintext
        """
        message = (
            f"Plaintext too large for {algorithm}: "
            f"max {max_size} bytes, got {actual_size} bytes"
        )
        super().__init__(
            message,
            algorithm=algorithm,
            context={"max_size": max_size, "actual_size": actual_size},
        )
        self.max_size = max_size
        self.actual_size = actual_size


# ==============================================================================
# SIGNATURE ERRORS
# ==============================================================================


class SignatureError(CryptoError):
    """
    Базовая ошибка операций с подписями.

    Example:
        >>> raise SignatureError("Signature operation failed")
    """

    pass


class SigningFailedError(SignatureError):
    """
    Неудачная генерация подписи.

    Raises когда:
    - Ошибка во время подписи
    - Некорректный private key
    - Внутренняя ошибка алгоритма

    Example:
        >>> signature = algo.sign(private_key, message)
        SigningFailedError: Signing failed for Ed25519
    """

    pass


class VerificationFailedError(SignatureError):
    """
    Неудачная проверка подписи.

    Raises когда:
    - Подпись не прошла проверку
    - Данные изменены
    - Неверный public key

    Security Note:
        Сообщение НЕ должно раскрывать причину сбоя.

    Example:
        >>> result = algo.verify(public_key, message, signature)
        VerificationFailedError: Signature verification failed
    """

    pass


class InvalidSignatureError(SignatureError):
    """
    Некорректная подпись.

    Raises когда:
    - Подпись неверного формата
    - Подпись неверного размера
    - Подпись повреждена

    Attributes:
        expected_size: Ожидаемый размер подписи
        actual_size: Фактический размер подписи

    Example:
        >>> algo.verify(public_key, message, short_signature)
        InvalidSignatureError: Invalid signature size: expected 64 bytes, got 32 bytes
    """

    def __init__(
        self,
        message: str,
        *,
        algorithm: Optional[str] = None,
        expected_size: Optional[int] = None,
        actual_size: Optional[int] = None,
    ) -> None:
        """
        Инициализация ошибки подписи.

        Args:
            message: Описание ошибки
            algorithm: Имя алгоритма
            expected_size: Ожидаемый размер подписи
            actual_size: Фактический размер подписи
        """
        context: Dict[str, Any] = {}
        if expected_size is not None:
            context["expected_signature_size"] = expected_size
        if actual_size is not None:
            context["actual_signature_size"] = actual_size

        super().__init__(message, algorithm=algorithm, context=context)
        self.expected_size = expected_size
        self.actual_size = actual_size


# ==============================================================================
# HASH ERRORS
# ==============================================================================


class HashError(CryptoError):
    """
    Базовая ошибка операций хеширования.

    Example:
        >>> raise HashError("Hashing operation failed")
    """

    pass


class HashingFailedError(HashError):
    """
    Неудачное хеширование.

    Raises когда:
    - Ошибка во время хеширования
    - Некорректные параметры
    - Внутренняя ошибка алгоритма

    Example:
        >>> digest = hasher.hash(data)
        HashingFailedError: Hashing failed for SHA-256
    """

    pass


class InvalidDigestError(HashError):
    """
    Некорректный digest (результат хеширования).

    Raises когда:
    - Digest неверного размера
    - Digest в неверном формате
    - Digest поврежден

    Example:
        >>> validate_digest(digest, expected_size=32)
        InvalidDigestError: Invalid digest size: expected 32 bytes, got 16 bytes
    """

    pass


# ==============================================================================
# PROTOCOL ERRORS
# ==============================================================================


class ProtocolError(CryptoError):
    """
    Ошибки соответствия Protocol интерфейсам.

    Используется в registry для валидации соответствия
    алгоритмов их Protocol интерфейсам.

    Example:
        >>> raise ProtocolError("Algorithm does not implement required protocol")
    """

    pass


class ProtocolMismatchError(ProtocolError):
    """
    Алгоритм не соответствует Protocol.

    Raises когда:
    - Класс не реализует требуемый Protocol
    - Отсутствуют обязательные методы
    - Некорректные сигнатуры методов

    Attributes:
        protocol_name: Имя Protocol интерфейса
        missing_methods: Список отсутствующих методов

    Example:
        >>> registry.register_algorithm("Custom", CustomClass, metadata)
        ProtocolMismatchError: CustomClass does not implement SymmetricCipherProtocol
    """

    def __init__(
        self,
        algorithm: str,
        protocol_name: str,
        missing_methods: Optional[List[str]] = None,
    ) -> None:
        """
        Инициализация ошибки Protocol.

        Args:
            algorithm: Имя алгоритма
            protocol_name: Имя Protocol интерфейса
            missing_methods: Список отсутствующих методов
        """
        message = f"{algorithm} does not implement {protocol_name}"

        if missing_methods:
            message += f". Missing methods: {', '.join(missing_methods)}"

        super().__init__(
            message,
            algorithm=algorithm,
            context={"protocol": protocol_name, "missing": missing_methods or []},
        )
        self.protocol_name = protocol_name
        self.missing_methods = missing_methods or []


class ProtocolViolationError(ProtocolError):
    """
    Нарушение контракта Protocol.

    Raises когда:
    - Метод возвращает некорректный тип
    - Нарушены пред/пост-условия
    - Некорректное поведение метода

    Example:
        >>> result = algo.encrypt(key, plaintext)
        ProtocolViolationError: encrypt() must return tuple[bytes, bytes], got bytes
    """

    pass


# ==============================================================================
# REGISTRY ERRORS
# ==============================================================================


class RegistryError(CryptoError):
    """
    Ошибки реестра алгоритмов.

    Example:
        >>> raise RegistryError("Registry operation failed")
    """

    pass


class AlgorithmNotRegisteredError(RegistryError):
    """
    Алгоритм не зарегистрирован.

    Аналогично AlgorithmNotFoundError, но специфично для реестра.

    Example:
        >>> registry.get_metadata("Unknown-Algo")
        AlgorithmNotRegisteredError: Algorithm 'Unknown-Algo' not registered
    """

    pass


class DuplicateRegistrationError(RegistryError):
    """
    Попытка повторной регистрации алгоритма.

    Raises когда:
    - Алгоритм уже зарегистрирован под тем же именем
    - Попытка перезаписать существующий алгоритм

    Attributes:
        algorithm_name: Имя алгоритма

    Example:
        >>> registry.register_algorithm("AES-256-GCM", AES256GCM, metadata)
        >>> registry.register_algorithm("AES-256-GCM", CustomAES, metadata)
        DuplicateRegistrationError: Algorithm 'AES-256-GCM' already registered
    """

    def __init__(self, algorithm_name: str) -> None:
        """
        Инициализация ошибки дубликата.

        Args:
            algorithm_name: Имя алгоритма
        """
        message = f"Algorithm '{algorithm_name}' is already registered"
        super().__init__(message, algorithm=algorithm_name)
        self.algorithm_name = algorithm_name


# ==============================================================================
# VALIDATION ERRORS
# ==============================================================================


class ValidationError(CryptoError):
    """
    Базовая ошибка валидации.

    Example:
        >>> raise ValidationError("Validation failed")
    """

    pass


class InvalidParameterError(ValidationError):
    """
    Некорректный параметр.

    Raises когда:
    - Параметр вне допустимого диапазона
    - Параметр неверного типа
    - Параметр не соответствует спецификации

    Attributes:
        parameter_name: Имя параметра
        reason: Причина ошибки

    Example:
        >>> cipher.set_rounds(-5)
        InvalidParameterError: Invalid parameter 'rounds': must be positive, got -5
    """

    def __init__(
        self,
        parameter_name: str,
        reason: str,
        *,
        value: Any = None,
    ) -> None:
        """
        Инициализация ошибки параметра.

        Args:
            parameter_name: Имя параметра
            reason: Причина ошибки
            value: Значение параметра (без секретов!)
        """
        message = f"Invalid parameter '{parameter_name}': {reason}"

        context: Dict[str, Any] = {"parameter": parameter_name, "reason": reason}
        if value is not None:
            # SECURITY: убедитесь что value НЕ секрет!
            context["value"] = str(value)[:50]  # truncate для safety

        super().__init__(message, context=context)
        self.parameter_name = parameter_name
        self.reason = reason


class InvalidInputError(ValidationError):
    """
    Некорректный входной параметр.

    Raises когда:
    - Входные данные не соответствуют требованиям
    - Входные данные повреждены
    - Входные данные в неверном формате

    Example:
        >>> algo.process(invalid_input)
        InvalidInputError: Input data must be bytes, got str
    """

    pass


class InvalidOutputError(ValidationError):
    """
    Некорректный выходной результат.

    Raises когда:
    - Выходные данные не прошли валидацию
    - Внутренняя несогласованность
    - Нарушение инвариантов

    Note:
        Обычно указывает на баг в реализации алгоритма.

    Example:
        >>> result = algo.compute(input)
        InvalidOutputError: Output validation failed: digest size mismatch
    """

    pass


# ==============================================================================
# HARDWARE DEVICE ERRORS
# ==============================================================================


class HardwareDeviceError(CryptoError):
    """
    Базовая ошибка аппаратного криптографического устройства.

    Raises когда:
    - Ошибка взаимодействия со смарткартой или YubiKey
    - Устройство вернуло неожиданный ответ
    - Общие ошибки аппаратных операций

    Attributes:
        device_id: Идентификатор устройства (опционально)

    Example:
        >>> manager.sign_with_device("card_001", 0x9C, message, pin)
        HardwareDeviceError: Hardware device error on card_001
    """

    def __init__(
        self,
        message: str,
        *,
        device_id: Optional[str] = None,
        algorithm: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Инициализация ошибки аппаратного устройства.

        Args:
            message: Описание ошибки
            device_id: Идентификатор устройства
            algorithm: Имя алгоритма (опционально)
            context: Дополнительный контекст (без секретов!)
        """
        ctx = context or {}
        if device_id:
            ctx["device_id"] = device_id

        super().__init__(message, algorithm=algorithm, context=ctx)
        self.device_id = device_id


class DeviceNotFoundError(HardwareDeviceError):
    """
    Устройство не найдено.

    Raises когда:
    - Смарткарта не подключена
    - YubiKey не вставлен
    - Устройство с указанным ID не обнаружено

    Example:
        >>> manager.get_device_info("nonexistent_card")
        DeviceNotFoundError: Device 'nonexistent_card' not found
    """

    def __init__(
        self,
        device_id: str,
    ) -> None:
        """
        Инициализация ошибки.

        Args:
            device_id: Идентификатор запрошенного устройства
        """
        message = f"Device '{device_id}' not found. Check connection and try again."
        super().__init__(message, device_id=device_id)


class DeviceCommunicationError(HardwareDeviceError):
    """
    Ошибка связи с устройством.

    Raises когда:
    - Потеряно соединение с устройством
    - Устройство извлечено во время операции
    - Ошибка APDU-обмена со смарткартой
    - Таймаут связи

    Example:
        >>> manager.sign_with_device("card_001", 0x9C, message, pin)
        DeviceCommunicationError: Communication error with device 'card_001'
    """

    def __init__(
        self,
        device_id: str,
        reason: str,
    ) -> None:
        """
        Инициализация ошибки связи.

        Args:
            device_id: Идентификатор устройства
            reason: Причина ошибки связи
        """
        message = f"Communication error with device '{device_id}': {reason}"
        super().__init__(
            message,
            device_id=device_id,
            context={"reason": reason},
        )
        self.reason = reason


class PINError(HardwareDeviceError):
    """
    Ошибка аутентификации PIN.

    Raises когда:
    - Неверный PIN
    - PIN заблокирован (превышено количество попыток)
    - PIN не установлен

    Attributes:
        retries_remaining: Оставшееся количество попыток (если известно)

    Security Note:
        Сообщение НЕ должно содержать значение PIN.

    Example:
        >>> manager.sign_with_device("card_001", 0x9C, message, wrong_pin)
        PINError: PIN verification failed for device 'card_001' (2 retries remaining)
    """

    def __init__(
        self,
        device_id: str,
        reason: str,
        *,
        retries_remaining: Optional[int] = None,
    ) -> None:
        """
        Инициализация ошибки PIN.

        Args:
            device_id: Идентификатор устройства
            reason: Причина ошибки (без значения PIN!)
            retries_remaining: Оставшееся количество попыток
        """
        message = f"PIN error for device '{device_id}': {reason}"
        if retries_remaining is not None:
            message += f" ({retries_remaining} retries remaining)"

        ctx: Dict[str, Any] = {"reason": reason}
        if retries_remaining is not None:
            ctx["retries_remaining"] = retries_remaining

        super().__init__(message, device_id=device_id, context=ctx)
        self.retries_remaining = retries_remaining


class SlotError(HardwareDeviceError):
    """
    Ошибка слота устройства.

    Raises когда:
    - Слот не содержит ключ
    - Слот не поддерживает запрошенную операцию
    - Недопустимый номер слота для данного устройства

    Attributes:
        slot: Номер слота

    Example:
        >>> manager.get_public_key("card_001", 0xFF)
        SlotError: Slot 0xff not available on device 'card_001'
    """

    def __init__(
        self,
        device_id: str,
        slot: int,
        reason: str,
    ) -> None:
        """
        Инициализация ошибки слота.

        Args:
            device_id: Идентификатор устройства
            slot: Номер слота
            reason: Причина ошибки
        """
        message = f"Slot 0x{slot:02x} error on device '{device_id}': {reason}"
        super().__init__(
            message,
            device_id=device_id,
            context={"slot": f"0x{slot:02x}", "reason": reason},
        )
        self.slot = slot


__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-09"
