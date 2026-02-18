"""
Асимметричное шифрование — RSA-OAEP варианты.

Этот модуль реализует 3 варианта RSA-OAEP с различными размерами ключей:
- RSA-OAEP-2048: Минимально допустимо по NIST (112-bit security)
- RSA-OAEP-3072: Рекомендуется NIST (128-bit security) [DEFAULT]
- RSA-OAEP-4096: Максимальная защита (152-bit security)

RSA-OAEP (Optimal Asymmetric Encryption Padding):
    OAEP — это схема padding для RSA, защищающая от chosen-ciphertext attacks.
    Использует SHA-256 и MGF1 (Mask Generation Function) для randomized padding,
    что обеспечивает provably secure шифрование при условии стойкости RSA
    и hash-функции.

Алгоритмы:
    1. RSA-OAEP-2048:
       - Key size: 2048 бит (256 байт модуля)
       - Max plaintext: 190 байт
       - Security: 112-bit (минимум NIST)
       - Floppy: ACCEPTABLE (~500 байт keypair)

    2. RSA-OAEP-3072 [RECOMMENDED]:
       - Key size: 3072 бит (384 байт модуля)
       - Max plaintext: 318 байт
       - Security: 128-bit (рекомендуется NIST)
       - Floppy: ACCEPTABLE (~750 байт keypair)

    3. RSA-OAEP-4096:
       - Key size: 4096 бит (512 байт модуля)
       - Max plaintext: 446 байт
       - Security: 152-bit (максимальная защита)
       - Floppy: POOR (~1024 байт keypair)

Security Notes:
    - RSA-2048 минимально допустим по NIST SP 800-57, рекомендуется 3072+ бит
    - Для больших данных используй hybrid encryption (RSA для ключа + AES для данных)
    - Max plaintext size = key_size_bytes - 2*hash_size - 2
    - OAEP padding обеспечивает защиту от padding oracle attacks
    - Каждое шифрование randomized → разный ciphertext для одного plaintext

Performance:
    - Key generation: RSA-2048 ~200-500ms, RSA-4096 ~2-5s
    - Encryption: RSA-2048 ~5-10ms, RSA-4096 ~15-25ms
    - Decryption: RSA-2048 ~30-50ms, RSA-4096 ~100-150ms (медленнее из-за private key ops)

Compliance:
    - PKCS#1 v2.2 (RSA-OAEP specification)
    - RFC 8017: PKCS #1 v2.2: RSA Cryptography Specifications
    - FIPS 186-4: Digital Signature Standard (DSS)
    - NIST SP 800-57 Part 1 Rev. 5: Key Management Recommendations

References:
    - RFC 8017: https://tools.ietf.org/html/rfc8017
    - NIST SP 800-57: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
    - PKCS#1 v2.2: https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1

Examples:
    >>> # Basic usage (recommended RSA-3072)
    >>> from src.security.crypto.algorithms.asymmetric import RSAOAEP3072
    >>> cipher = RSAOAEP3072()
    >>> private_key, public_key = cipher.generate_keypair()
    >>> ciphertext = cipher.encrypt(public_key, b"Secret message")
    >>> plaintext = cipher.decrypt(private_key, ciphertext)
    >>> assert plaintext == b"Secret message"

    >>> # Using registry
    >>> from src.security.crypto.algorithms.asymmetric import get_asymmetric_algorithm
    >>> cipher = get_asymmetric_algorithm("RSA-OAEP-3072")
    >>> private_key, public_key = cipher.generate_keypair()

Version: 2.3
Date: February 10, 2026
Author: Mike Voyager
"""

from __future__ import annotations

import logging
from typing import Tuple, Type

# Cryptography library
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Project imports
from src.security.crypto.core.protocols import AsymmetricEncryptionProtocol
from src.security.crypto.core.metadata import (
    AlgorithmMetadata,
    AlgorithmCategory,
    SecurityLevel,
    FloppyFriendly,
    ImplementationStatus,
)
from src.security.crypto.core.exceptions import (
    EncryptionError,
    EncryptionFailedError,
    DecryptionFailedError,
    KeyGenerationError,
    InvalidKeyError,
    PlaintextTooLargeError,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# CONSTANTS
# ==============================================================================

# RSA standard public exponent (F4 = 2^16 + 1)
RSA_PUBLIC_EXPONENT = 65537

# Max plaintext sizes (key_size_bytes - 2*hash_output_size - 2)
# For SHA-256 (32 bytes output):
# Formula: max = (key_size / 8) - 2*32 - 2
MAX_PLAINTEXT_SIZE_2048 = 190  # 256 - 64 - 2
MAX_PLAINTEXT_SIZE_3072 = 318  # 384 - 64 - 2
MAX_PLAINTEXT_SIZE_4096 = 446  # 512 - 64 - 2


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================


def _ensure_bytes(value: bytes, name: str) -> None:
    """
    Проверить, что значение является bytes.

    Args:
        value: Значение для проверки
        name: Имя параметра (для сообщения об ошибке)

    Raises:
        TypeError: Если value не является bytes
    """
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")


def _validate_plaintext_size(plaintext: bytes, max_size: int, algorithm: str) -> None:
    """
    Проверить размер plaintext для RSA-OAEP.

    Args:
        plaintext: Данные для шифрования
        max_size: Максимальный допустимый размер в байтах
        algorithm: Имя алгоритма (для сообщения об ошибке)

    Raises:
        PlaintextTooLargeError: Если plaintext слишком большой

    Note:
        RSA-OAEP имеет ограничение на размер plaintext из-за padding overhead.
        Для больших данных используйте hybrid encryption (RSA + симметричное шифрование).
    """
    if len(plaintext) > max_size:
        raise PlaintextTooLargeError(
            algorithm=algorithm,
            max_size=max_size,
            actual_size=len(plaintext),
        )


# ==============================================================================
# RSA-OAEP ALGORITHMS
# ==============================================================================


class RSAOAEP2048:
    """
    RSA-OAEP с 2048-битным ключом.

    OAEP (Optimal Asymmetric Encryption Padding) — это схема padding для RSA,
    обеспечивающая защиту от chosen-ciphertext attacks и padding oracle attacks.

    Параметры:
        - Key size: 2048 бит (256 байт модуля)
        - Hash function: SHA-256
        - MGF (Mask Generation Function): MGF1 с SHA-256
        - Label: None (пустой по умолчанию)
        - Max plaintext: 190 байт

    Security:
        - 112-bit security level (минимально допустимо по NIST SP 800-57)
        - Рекомендуется переход на 3072+ бит для новых систем
        - Защита от padding oracle attacks благодаря OAEP
        - Provably secure при условии стойкости RSA и SHA-256

    Performance:
        - Key generation: ~200-500 ms
        - Encryption: ~5-10 ms
        - Decryption: ~30-50 ms (медленнее из-за приватного ключа)

    Floppy Friendly:
        - Keypair size: ~500 байт (ACCEPTABLE)
        - Private key: ~500 байт (PKCS#8 DER)
        - Public key: ~294 байт (SubjectPublicKeyInfo DER)
        - Ciphertext: 256 байт (всегда фиксированный размер)

    Example:
        >>> cipher = RSAOAEP2048()
        >>> priv, pub = cipher.generate_keypair()
        >>> ct = cipher.encrypt(pub, b"Hello, World!")
        >>> pt = cipher.decrypt(priv, ct)
        >>> assert pt == b"Hello, World!"

    References:
        - PKCS#1 v2.2 Section 7.1 (RSAES-OAEP)
        - RFC 8017: https://tools.ietf.org/html/rfc8017
        - NIST SP 800-57 Part 1 Rev. 5
    """

    ALGORITHM_NAME = "RSA-OAEP-2048"
    KEY_SIZE = 2048
    HASH_ALGORITHM = hashes.SHA256()
    MAX_PLAINTEXT_SIZE = MAX_PLAINTEXT_SIZE_2048

    def __init__(self) -> None:
        """Инициализировать RSA-OAEP-2048 cipher."""
        self.algorithm_name: str = self.ALGORITHM_NAME
        self.key_size: int = self.KEY_SIZE
        self.max_plaintext_size: int = self.MAX_PLAINTEXT_SIZE
        self._logger = logger.getChild("rsa-oaep-2048")
        self._padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=self.HASH_ALGORITHM),
            algorithm=self.HASH_ALGORITHM,
            label=None,
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать новую пару ключей RSA-2048.

        Returns:
            Кортеж (private_key, public_key) в DER формате:
            - private_key: PKCS#8 DER (~500 байт)
            - public_key: SubjectPublicKeyInfo DER (~294 байт)

        Raises:
            KeyGenerationError: При ошибке генерации ключей

        Example:
            >>> cipher = RSAOAEP2048()
            >>> priv, pub = cipher.generate_keypair()
            >>> print(f"Private: {len(priv)} bytes, Public: {len(pub)} bytes")
            Private: 500 bytes, Public: 294 bytes

        Security Note:
            - Используется безопасный CSPRNG (os.urandom через cryptography)
            - Public exponent: 65537 (F4) — стандарт RSA, оптимальный компромисс
              между безопасностью и производительностью
            - Private key НЕ зашифрован (NoEncryption) — ответственность за защиту
              лежит на уровне хранилища ключей
        """
        try:
            self._logger.debug("Generating RSA-2048 keypair...")

            # Generate private key
            private_key_obj = rsa.generate_private_key(
                public_exponent=RSA_PUBLIC_EXPONENT,
                key_size=self.KEY_SIZE,
                backend=default_backend(),
            )

            # Extract public key
            public_key_obj = private_key_obj.public_key()

            # Serialize to DER format (binary, compact)
            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            self._logger.debug(
                f"Generated RSA-2048 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"RSA-2048 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("RSA-2048 key generation failed") from exc

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """
        Зашифровать данные с использованием RSA-OAEP-2048.

        Args:
            public_key: Публичный ключ в DER формате (SubjectPublicKeyInfo)
            plaintext: Данные для шифрования (максимум 190 байт)

        Returns:
            Ciphertext (всегда 256 байт для RSA-2048)

        Raises:
            TypeError: Если параметры не являются bytes
            InvalidKeyError: Если public_key неверного формата
            PlaintextTooLargeError: Если plaintext слишком большой
            EncryptionFailedError: Если шифрование не удалось

        Example:
            >>> cipher = RSAOAEP2048()
            >>> _, pub = cipher.generate_keypair()
            >>> ct = cipher.encrypt(pub, b"Secret data")
            >>> print(f"Ciphertext: {len(ct)} bytes")
            Ciphertext: 256 bytes

        Security Note:
            OAEP padding обеспечивает randomized encryption:
            каждое шифрование одного и того же plaintext даёт разный ciphertext.
            Это защищает от chosen-plaintext attacks.
        """
        # Zero Trust: validate all inputs
        _ensure_bytes(public_key, "public_key")
        _ensure_bytes(plaintext, "plaintext")
        _validate_plaintext_size(
            plaintext, self.MAX_PLAINTEXT_SIZE, self.ALGORITHM_NAME
        )

        try:
            # Deserialize public key from DER
            public_key_obj = serialization.load_der_public_key(
                public_key, backend=default_backend()
            )

            # Validate it's actually RSA key
            if not isinstance(public_key_obj, rsa.RSAPublicKey):
                raise InvalidKeyError("Key must be RSA public key")

            # Encrypt with OAEP padding
            ciphertext = public_key_obj.encrypt(plaintext, self._padding)

            self._logger.debug(
                f"Encrypted {len(plaintext)}B → {len(ciphertext)}B (RSA-2048)"
            )

            return ciphertext

        except (InvalidKeyError, PlaintextTooLargeError):
            raise
        except Exception as exc:
            self._logger.error(f"RSA-2048 encryption failed: {exc}", exc_info=True)
            raise EncryptionFailedError("RSA-2048 encryption failed") from exc

    def decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Расшифровать данные с использованием RSA-OAEP-2048.

        Args:
            private_key: Приватный ключ в DER формате (PKCS#8)
            ciphertext: Зашифрованные данные (256 байт)

        Returns:
            Plaintext (оригинальные данные, до 190 байт)

        Raises:
            TypeError: Если параметры не являются bytes
            InvalidKeyError: Если private_key неверного формата
            DecryptionFailedError: Если расшифровка не удалась (неверный ключ или ciphertext)

        Example:
            >>> cipher = RSAOAEP2048()
            >>> priv, pub = cipher.generate_keypair()
            >>> ct = cipher.encrypt(pub, b"Secret")
            >>> pt = cipher.decrypt(priv, ct)
            >>> assert pt == b"Secret"

        Security Note:
            При неверном ciphertext или ключе бросается DecryptionFailedError
            БЕЗ раскрытия деталей ошибки. Это защищает от padding oracle attacks.
            cryptography.io использует constant-time операции для OAEP.
        """
        # Zero Trust: validate all inputs
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(ciphertext, "ciphertext")

        try:
            # Deserialize private key from DER
            private_key_obj = serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )

            # Validate it's actually RSA key
            if not isinstance(private_key_obj, rsa.RSAPrivateKey):
                raise InvalidKeyError("Key must be RSA private key")

            # Decrypt with OAEP padding
            plaintext = private_key_obj.decrypt(ciphertext, self._padding)

            self._logger.debug(
                f"Decrypted {len(ciphertext)}B → {len(plaintext)}B (RSA-2048)"
            )

            return plaintext

        except (InvalidKeyError,):
            raise
        except Exception as exc:
            # НЕ раскрываем детали ошибки (security: padding oracle protection)
            self._logger.warning(
                "RSA-2048 decryption failed (invalid key or ciphertext)"
            )
            raise DecryptionFailedError(
                "RSA-2048 decryption failed: invalid key or ciphertext"
            ) from exc


class RSAOAEP3072:
    """
    RSA-OAEP с 3072-битным ключом (RECOMMENDED).

    OAEP (Optimal Asymmetric Encryption Padding) — это схема padding для RSA,
    обеспечивающая защиту от chosen-ciphertext attacks и padding oracle attacks.

    Параметры:
        - Key size: 3072 бит (384 байт модуля)
        - Hash function: SHA-256
        - MGF (Mask Generation Function): MGF1 с SHA-256
        - Label: None (пустой по умолчанию)
        - Max plaintext: 318 байт

    Security:
        - 128-bit security level (РЕКОМЕНДУЕТСЯ NIST SP 800-57)
        - Эквивалентно AES-128 по стойкости
        - Рекомендуется как default для новых систем
        - Защита от padding oracle attacks благодаря OAEP

    Performance:
        - Key generation: ~500ms - 1s
        - Encryption: ~10-15 ms
        - Decryption: ~50-70 ms

    Floppy Friendly:
        - Keypair size: ~750 байт (ACCEPTABLE)
        - Private key: ~750 байт
        - Public key: ~422 байт
        - Ciphertext: 384 байт

    Example:
        >>> cipher = RSAOAEP3072()
        >>> priv, pub = cipher.generate_keypair()
        >>> ct = cipher.encrypt(pub, b"Sensitive data")
        >>> pt = cipher.decrypt(priv, ct)

    References:
        - NIST SP 800-57: Recommends 3072-bit RSA for 128-bit security
        - RFC 8017: PKCS #1 v2.2
    """

    ALGORITHM_NAME = "RSA-OAEP-3072"
    KEY_SIZE = 3072
    HASH_ALGORITHM = hashes.SHA256()
    MAX_PLAINTEXT_SIZE = MAX_PLAINTEXT_SIZE_3072

    def __init__(self) -> None:
        """Инициализировать RSA-OAEP-3072 cipher."""
        self.algorithm_name: str = self.ALGORITHM_NAME
        self.key_size: int = self.KEY_SIZE
        self.max_plaintext_size: int = self.MAX_PLAINTEXT_SIZE
        self._logger = logger.getChild("rsa-oaep-3072")
        self._padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=self.HASH_ALGORITHM),
            algorithm=self.HASH_ALGORITHM,
            label=None,
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать новую пару ключей RSA-3072.

        Returns:
            Кортеж (private_key, public_key) в DER формате:
            - private_key: PKCS#8 DER (~750 байт)
            - public_key: SubjectPublicKeyInfo DER (~422 байт)

        Raises:
            KeyGenerationError: При ошибке генерации ключей
        """
        try:
            self._logger.debug("Generating RSA-3072 keypair...")

            private_key_obj = rsa.generate_private_key(
                public_exponent=RSA_PUBLIC_EXPONENT,
                key_size=self.KEY_SIZE,
                backend=default_backend(),
            )

            public_key_obj = private_key_obj.public_key()

            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            self._logger.debug(
                f"Generated RSA-3072 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"RSA-3072 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("RSA-3072 key generation failed") from exc

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """
        Зашифровать данные с использованием RSA-OAEP-3072.

        Args:
            public_key: Публичный ключ в DER формате
            plaintext: Данные для шифрования (максимум 318 байт)

        Returns:
            Ciphertext (всегда 384 байт для RSA-3072)

        Raises:
            TypeError: Если параметры не являются bytes
            InvalidKeyError: Если public_key неверного формата
            PlaintextTooLargeError: Если plaintext слишком большой
            EncryptionFailedError: Если шифрование не удалось
        """
        _ensure_bytes(public_key, "public_key")
        _ensure_bytes(plaintext, "plaintext")
        _validate_plaintext_size(
            plaintext, self.MAX_PLAINTEXT_SIZE, self.ALGORITHM_NAME
        )
        try:
            public_key_obj = serialization.load_der_public_key(
                public_key, backend=default_backend()
            )

            if not isinstance(public_key_obj, rsa.RSAPublicKey):
                raise InvalidKeyError("Key must be RSA public key")

            ciphertext = public_key_obj.encrypt(plaintext, self._padding)

            self._logger.debug(
                f"Encrypted {len(plaintext)}B → {len(ciphertext)}B (RSA-3072)"
            )

            return ciphertext

        except (InvalidKeyError, PlaintextTooLargeError):
            raise
        except Exception as exc:
            self._logger.error(f"RSA-3072 encryption failed: {exc}", exc_info=True)
            raise EncryptionFailedError("RSA-3072 encryption failed") from exc

    def decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Расшифровать данные с использованием RSA-OAEP-3072.

        Args:
            private_key: Приватный ключ в DER формате
            ciphertext: Зашифрованные данные (384 байт)

        Returns:
            Plaintext (оригинальные данные, до 318 байт)

        Raises:
            TypeError: Если параметры не являются bytes
            InvalidKeyError: Если private_key неверного формата
            DecryptionFailedError: Если расшифровка не удалась
        """
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(ciphertext, "ciphertext")

        try:
            private_key_obj = serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )

            if not isinstance(private_key_obj, rsa.RSAPrivateKey):
                raise InvalidKeyError("Key must be RSA private key")

            plaintext = private_key_obj.decrypt(ciphertext, self._padding)

            self._logger.debug(
                f"Decrypted {len(ciphertext)}B → {len(plaintext)}B (RSA-3072)"
            )

            return plaintext

        except (InvalidKeyError,):
            raise
        except Exception as exc:
            self._logger.warning(
                "RSA-3072 decryption failed (invalid key or ciphertext)"
            )
            raise DecryptionFailedError(
                "RSA-3072 decryption failed: invalid key or ciphertext"
            ) from exc


class RSAOAEP4096:
    """
    RSA-OAEP с 4096-битным ключом (MAXIMUM SECURITY).

    OAEP (Optimal Asymmetric Encryption Padding) — это схема padding для RSA,
    обеспечивающая защиту от chosen-ciphertext attacks и padding oracle attacks.

    Параметры:
        - Key size: 4096 бит (512 байт модуля)
        - Hash function: SHA-256
        - MGF (Mask Generation Function): MGF1 с SHA-256
        - Label: None (пустой по умолчанию)
        - Max plaintext: 446 байт

    Security:
        - 152-bit security level (высокая защита)
        - Максимальная защита среди RSA вариантов
        - Подходит для long-term security (20+ лет)
        - Защита от padding oracle attacks благодаря OAEP

    Performance:
        - Key generation: ~2-5 секунд
        - Encryption: ~15-25 ms
        - Decryption: ~100-150 ms
        - ⚠️ Значительно медленнее RSA-2048/3072

    Floppy Friendly:
        - Keypair size: ~1024 байт (POOR для floppy disk)
        - Private key: ~1024 байт
        - Public key: ~550 байт
        - Ciphertext: 512 байт

    Example:
        >>> cipher = RSAOAEP4096()
        >>> priv, pub = cipher.generate_keypair()  # Медленно!
        >>> ct = cipher.encrypt(pub, b"Top secret")
        >>> pt = cipher.decrypt(priv, ct)

    Use Cases:
        - Long-term security (20+ years)
        - High-value targets
        - Government/military applications
        - Root CA certificates

    References:
        - RFC 8017: PKCS #1 v2.2
        - NIST SP 800-57: Long-term key protection
    """

    ALGORITHM_NAME = "RSA-OAEP-4096"
    KEY_SIZE = 4096
    HASH_ALGORITHM = hashes.SHA256()
    MAX_PLAINTEXT_SIZE = MAX_PLAINTEXT_SIZE_4096

    def __init__(self) -> None:
        """Инициализировать RSA-OAEP-4096 cipher."""
        self.algorithm_name: str = self.ALGORITHM_NAME
        self.key_size: int = self.KEY_SIZE
        self.max_plaintext_size: int = self.MAX_PLAINTEXT_SIZE
        self._logger = logger.getChild("rsa-oaep-4096")
        self._padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=self.HASH_ALGORITHM),
            algorithm=self.HASH_ALGORITHM,
            label=None,
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать новую пару ключей RSA-4096.

        Returns:
            Кортеж (private_key, public_key) в DER формате:
            - private_key: PKCS#8 DER (~1024 байт)
            - public_key: SubjectPublicKeyInfo DER (~550 байт)

        Raises:
            KeyGenerationError: При ошибке генерации ключей

        Warning:
            Генерация ключа может занять 2-5 секунд!
        """
        try:
            self._logger.debug("Generating RSA-4096 keypair (this may take a while)...")

            private_key_obj = rsa.generate_private_key(
                public_exponent=RSA_PUBLIC_EXPONENT,
                key_size=self.KEY_SIZE,
                backend=default_backend(),
            )

            public_key_obj = private_key_obj.public_key()

            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            self._logger.debug(
                f"Generated RSA-4096 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"RSA-4096 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("RSA-4096 key generation failed") from exc

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """
        Зашифровать данные с использованием RSA-OAEP-4096.

        Args:
            public_key: Публичный ключ в DER формате
            plaintext: Данные для шифрования (максимум 446 байт)

        Returns:
            Ciphertext (всегда 512 байт для RSA-4096)

        Raises:
            TypeError: Если параметры не являются bytes
            InvalidKeyError: Если public_key неверного формата
            PlaintextTooLargeError: Если plaintext слишком большой
            EncryptionFailedError: Если шифрование не удалось
        """
        _ensure_bytes(public_key, "public_key")
        _ensure_bytes(plaintext, "plaintext")
        _validate_plaintext_size(
            plaintext, self.MAX_PLAINTEXT_SIZE, self.ALGORITHM_NAME
        )
        try:
            public_key_obj = serialization.load_der_public_key(
                public_key, backend=default_backend()
            )

            if not isinstance(public_key_obj, rsa.RSAPublicKey):
                raise InvalidKeyError("Key must be RSA public key")

            ciphertext = public_key_obj.encrypt(plaintext, self._padding)

            self._logger.debug(
                f"Encrypted {len(plaintext)}B → {len(ciphertext)}B (RSA-4096)"
            )

            return ciphertext

        except (InvalidKeyError, PlaintextTooLargeError):
            raise
        except Exception as exc:
            self._logger.error(f"RSA-4096 encryption failed: {exc}", exc_info=True)
            raise EncryptionFailedError("RSA-4096 encryption failed") from exc

    def decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Расшифровать данные с использованием RSA-OAEP-4096.

        Args:
            private_key: Приватный ключ в DER формате
            ciphertext: Зашифрованные данные (512 байт)

        Returns:
            Plaintext (оригинальные данные, до 446 байт)

        Raises:
            TypeError: Если параметры не являются bytes
            InvalidKeyError: Если private_key неверного формата
            DecryptionFailedError: Если расшифровка не удалась
        """
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(ciphertext, "ciphertext")

        try:
            private_key_obj = serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )

            if not isinstance(private_key_obj, rsa.RSAPrivateKey):
                raise InvalidKeyError("Key must be RSA private key")

            plaintext = private_key_obj.decrypt(ciphertext, self._padding)

            self._logger.debug(
                f"Decrypted {len(ciphertext)}B → {len(plaintext)}B (RSA-4096)"
            )

            return plaintext

        except (InvalidKeyError,):
            raise
        except Exception as exc:
            self._logger.warning(
                "RSA-4096 decryption failed (invalid key or ciphertext)"
            )
            raise DecryptionFailedError(
                "RSA-4096 decryption failed: invalid key or ciphertext"
            ) from exc


# ==============================================================================
# ALGORITHM METADATA
# ==============================================================================

METADATA_RSA_OAEP_2048 = AlgorithmMetadata(
    name="RSA-OAEP-2048",
    category=AlgorithmCategory.ASYMMETRIC_ENCRYPTION,
    protocol_class=AsymmetricEncryptionProtocol,
    library="cryptography",
    implementation_class="RSAOAEP2048",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.ACCEPTABLE,
    status=ImplementationStatus.STABLE,
    key_size=2048,
    public_key_size=294,
    private_key_size=1217,
    max_plaintext_size=MAX_PLAINTEXT_SIZE_2048,
    description_ru=(
        "RSA-OAEP с 2048-битным ключом. "
        "Минимально допустимо по NIST (112-bit security). "
        "Hash: SHA-256, MGF: MGF1. Max plaintext: 190 байт."
    ),
    description_en=(
        "RSA-OAEP with 2048-bit key. "
        "Minimum acceptable by NIST (112-bit security). "
        "Hash: SHA-256, MGF: MGF1. Max plaintext: 190 bytes."
    ),
    use_cases=[
        "Legacy system compatibility",
        "Short-term data protection",
        "Key exchange",
        "Hybrid encryption (RSA + AES)",
    ],
    test_vectors_source="RFC 8017",
)

METADATA_RSA_OAEP_3072 = AlgorithmMetadata(
    name="RSA-OAEP-3072",
    category=AlgorithmCategory.ASYMMETRIC_ENCRYPTION,
    protocol_class=AsymmetricEncryptionProtocol,
    library="cryptography",
    implementation_class="RSAOAEP3072",
    security_level=SecurityLevel.HIGH,
    floppy_friendly=FloppyFriendly.ACCEPTABLE,
    status=ImplementationStatus.STABLE,
    key_size=3072,
    public_key_size=422,
    private_key_size=1793,
    max_plaintext_size=MAX_PLAINTEXT_SIZE_3072,
    description_ru=(
        "RSA-OAEP с 3072-битным ключом (RECOMMENDED). "
        "Рекомендуется NIST (128-bit security). "
        "Hash: SHA-256, MGF: MGF1. Max plaintext: 318 байт."
    ),
    description_en=(
        "RSA-OAEP with 3072-bit key (RECOMMENDED). "
        "NIST recommended (128-bit security). "
        "Hash: SHA-256, MGF: MGF1. Max plaintext: 318 bytes."
    ),
    use_cases=[
        "Default asymmetric encryption",
        "Key exchange (recommended)",
        "Hybrid encryption (RSA + AES)",
        "TLS/SSL certificates",
        "Code signing",
    ],
    test_vectors_source="RFC 8017",
)

METADATA_RSA_OAEP_4096 = AlgorithmMetadata(
    name="RSA-OAEP-4096",
    category=AlgorithmCategory.ASYMMETRIC_ENCRYPTION,
    protocol_class=AsymmetricEncryptionProtocol,
    library="cryptography",
    implementation_class="RSAOAEP4096",
    security_level=SecurityLevel.HIGH,
    floppy_friendly=FloppyFriendly.POOR,
    status=ImplementationStatus.STABLE,
    key_size=4096,
    public_key_size=550,
    private_key_size=2374,
    max_plaintext_size=MAX_PLAINTEXT_SIZE_4096,
    description_ru=(
        "RSA-OAEP с 4096-битным ключом (MAXIMUM SECURITY). "
        "Максимальная защита (152-bit security). "
        "Hash: SHA-256, MGF: MGF1. Max plaintext: 446 байт. "
        "⚠️ Медленнее RSA-2048/3072."
    ),
    description_en=(
        "RSA-OAEP with 4096-bit key (MAXIMUM SECURITY). "
        "Maximum protection (152-bit security). "
        "Hash: SHA-256, MGF: MGF1. Max plaintext: 446 bytes. "
        "⚠️ Slower than RSA-2048/3072."
    ),
    use_cases=[
        "Long-term security (20+ years)",
        "High-value data protection",
        "Government/military applications",
        "Root CA certificates",
        "Critical infrastructure",
    ],
    test_vectors_source="RFC 8017",
)


# ==============================================================================
# REGISTRY
# ==============================================================================

ALL_METADATA: list[AlgorithmMetadata] = [
    METADATA_RSA_OAEP_2048,
    METADATA_RSA_OAEP_3072,
    METADATA_RSA_OAEP_4096,
]

ASYMMETRIC_ALGORITHMS: dict[str, tuple[Type[object], AlgorithmMetadata]] = {
    "RSA-OAEP-2048": (RSAOAEP2048, METADATA_RSA_OAEP_2048),
    "RSA-OAEP-3072": (RSAOAEP3072, METADATA_RSA_OAEP_3072),
    "RSA-OAEP-4096": (RSAOAEP4096, METADATA_RSA_OAEP_4096),
}


def get_asymmetric_algorithm(algorithm_name: str) -> AsymmetricEncryptionProtocol:
    """
    Получить реализацию алгоритма асимметричного шифрования по имени.

    Args:
        algorithm_name: Имя алгоритма.
            Доступные значения:
            - "RSA-OAEP-2048": RSA-OAEP с 2048-битным ключом (минимум)
            - "RSA-OAEP-3072": RSA-OAEP с 3072-битным ключом (RECOMMENDED)
            - "RSA-OAEP-4096": RSA-OAEP с 4096-битным ключом (максимум)

    Returns:
        Экземпляр класса, реализующего AsymmetricEncryptionProtocol.

    Raises:
        KeyError: Если алгоритм не найден.

    Example:
        >>> # Get recommended cipher (RSA-3072)
        >>> cipher = get_asymmetric_algorithm("RSA-OAEP-3072")
        >>> priv, pub = cipher.generate_keypair()
        >>> ct = cipher.encrypt(pub, b"Secret")
        >>> pt = cipher.decrypt(priv, ct)

        >>> # List available algorithms
        >>> from src.security.crypto.algorithms.asymmetric import ASYMMETRIC_ALGORITHMS
        >>> print(list(ASYMMETRIC_ALGORITHMS.keys()))
        ['RSA-OAEP-2048', 'RSA-OAEP-3072', 'RSA-OAEP-4096']
    """
    try:
        cipher_cls, metadata = ASYMMETRIC_ALGORITHMS[algorithm_name]
    except KeyError as exc:
        available = list(ASYMMETRIC_ALGORITHMS.keys())
        raise KeyError(
            f"Asymmetric algorithm '{algorithm_name}' not found. "
            f"Available: {available}"
        ) from exc

    return cipher_cls()  # type: ignore[return-value]


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__ = [
    # Classes
    "RSAOAEP2048",
    "RSAOAEP3072",
    "RSAOAEP4096",
    # Metadata
    "METADATA_RSA_OAEP_2048",
    "METADATA_RSA_OAEP_3072",
    "METADATA_RSA_OAEP_4096",
    "ALL_METADATA",
    # Registry
    "ASYMMETRIC_ALGORITHMS",
    "get_asymmetric_algorithm",
    # Constants
    "RSA_PUBLIC_EXPONENT",
    "MAX_PLAINTEXT_SIZE_2048",
    "MAX_PLAINTEXT_SIZE_3072",
    "MAX_PLAINTEXT_SIZE_4096",
]
