"""
Key Derivation Functions (KDF) — преобразование паролей в криптографические ключи.

Этот модуль предоставляет 4 KDF алгоритма для различных сценариев:

Password-Based KDF (для паролей):
1. **Argon2id** — современный, memory-hard (PHC winner 2015) [RECOMMENDED]
2. **PBKDF2-SHA256** — NIST стандарт (широкая совместимость)
3. **Scrypt** — memory-hard (Bitcoin, Litecoin)

Key Expansion (для shared secrets):
4. **HKDF-SHA256** — быстрое расширение ключей (НЕ для паролей!)

Security Considerations
-----------------------
Salt Management:
    - Минимум 16 байт (рекомендуется 32 байта)
    - Уникальный для каждого пароля
    - Генерируется через secrets.token_bytes()
    - Хранится вместе с зашифрованными данными

Parameter Tuning:
    - Argon2id: time_cost=2, memory=64MB (интерактивное использование)
    - PBKDF2: минимум 600,000 iterations (OWASP 2023)
    - Scrypt: N=2^14 (16384), r=8, p=1
    - HKDF: только для high-entropy inputs!

Performance vs Security:
    - Password KDF должны быть МЕДЛЕННЫМИ (защита от brute-force)
    - Argon2id: ~200-500 ms (оптимально)
    - PBKDF2: ~50-200 ms (требует больше iterations)
    - HKDF: <1 ms (НЕ для паролей!)

Use Case Guidance
-----------------
Password Storage/Authentication:
    >>> # RECOMMENDED: Argon2id
    >>> kdf = Argon2idKDF()
    >>> salt = generate_salt(32)
    >>> key = kdf.derive_key(password.encode(), salt)

Derive Encryption Key from Password:
    >>> kdf = Argon2idKDF()
    >>> salt = generate_salt(32)  # Save with ciphertext!
    >>> encryption_key = kdf.derive_key(password.encode(), salt, key_length=32)

After Key Exchange (X25519, ECDH):
    >>> # Use HKDF (input = shared_secret, NOT password)
    >>> shared_secret = x25519_exchange(my_priv, peer_pub)
    >>> kdf = HKDFSHA256()
    >>> encryption_key = kdf.derive_key(
    ...     password=shared_secret,
    ...     salt=b"",
    ...     info=b"encryption"
    ... )

⚠️ Security Warnings
--------------------
1. **HKDF НЕ для паролей**:
   - HKDF слишком быстрый → легко брутфорсить
   - Используйте только для shared secrets (ECDH output)

2. **Параметры критичны**:
   - PBKDF2: минимум 600,000 iterations (2023)
   - Argon2id: минимум 64 MB memory
   - Низкие значения = НЕБЕЗОПАСНО

3. **Не логировать пароли**:
   - Даже в debug mode
   - Логировать только длину и алгоритм

Standards & References
----------------------
- RFC 9106: Argon2 Memory-Hard Function
- NIST SP 800-132: Password-Based Key Derivation
- RFC 5869: HMAC-based Extract-and-Expand KDF (HKDF)
- RFC 7914: The scrypt Password-Based KDF
- OWASP Password Storage Cheat Sheet (2023)

Author: FX Text Processor 3 Team
Version: 2.3 Final
Date: February 10, 2026
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Protocol, runtime_checkable

import logging
from src.security.crypto.core.exceptions import (
    AlgorithmNotSupportedError,
    KeyDerivationError,
)
from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    SecurityLevel,
    ImplementationStatus,
    create_kdf_metadata,
)

# Logger
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS & DEFAULTS
# ============================================================================

# Argon2id defaults (OWASP 2023)
ARGON2_DEFAULT_TIME_COST = 2  # iterations
ARGON2_DEFAULT_MEMORY_COST = 65536  # KB (64 MB)
ARGON2_DEFAULT_PARALLELISM = 4  # threads
ARGON2_DEFAULT_SALT_LENGTH = 32  # bytes

# PBKDF2 defaults (OWASP 2023)
PBKDF2_DEFAULT_ITERATIONS = 600_000  # SHA-256
PBKDF2_MIN_ITERATIONS = 100_000  # Absolute minimum
PBKDF2_DEFAULT_SALT_LENGTH = 32

# Scrypt defaults
SCRYPT_DEFAULT_N = 2**14  # 16384 (CPU/memory cost)
SCRYPT_DEFAULT_R = 8  # block size
SCRYPT_DEFAULT_P = 1  # parallelization
SCRYPT_DEFAULT_SALT_LENGTH = 32

# General
MIN_SALT_LENGTH = 16  # bytes
MAX_KEY_LENGTH = 128  # bytes
MIN_KEY_LENGTH = 16  # bytes


# ============================================================================
# PROTOCOL
# ============================================================================


@runtime_checkable
class KDFProtocol(Protocol):
    """
    Протокол для Key Derivation Functions.

    Все KDF алгоритмы должны реализовывать метод derive_key() для
    преобразования пароля/входных данных в криптографический ключ.
    """

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        *,
        key_length: int = 32,
        **kwargs: Any,
    ) -> bytes:
        """
        Вывести ключ из пароля/входных данных.

        Args:
            password: Пароль пользователя (bytes) или входной материал ключа
            salt: Случайная соль (минимум 16 байт, рекомендуется 32)
            key_length: Желаемая длина ключа в байтах (по умолчанию: 32)
            **kwargs: Алгоритм-специфичные параметры:
                - iterations (PBKDF2, Scrypt)
                - memory_cost (Argon2id, Scrypt)
                - parallelism (Argon2id)
                - info (HKDF)

        Returns:
            Выведенный ключ (key_length bytes)

        Raises:
            ValueError: Некорректные параметры
            AlgorithmNotSupportedError: Ошибка при выводе ключа
        """
        ...


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _validate_salt(salt: bytes, min_length: int = MIN_SALT_LENGTH) -> None:
    """
    Валидация соли на соответствие минимальным требованиям безопасности.

    Args:
        salt: Соль для валидации
        min_length: Минимально допустимая длина (по умолчанию: 16 байт)

    Raises:
        ValueError: Соль пустая или слишком короткая
    """
    if not salt:
        raise ValueError("Salt cannot be empty")
    if len(salt) < min_length:
        raise ValueError(
            f"Salt too short: {len(salt)} bytes (minimum: {min_length} bytes)"
        )


def _validate_key_length(length: int) -> None:
    """
    Валидация длины ключа.

    Args:
        length: Желаемая длина ключа в байтах

    Raises:
        ValueError: Длина за пределами разумных границ
    """
    if length < MIN_KEY_LENGTH:
        raise ValueError(
            f"key_length too short: {length} bytes (minimum: {MIN_KEY_LENGTH})"
        )
    if length > MAX_KEY_LENGTH:
        raise ValueError(
            f"key_length too long: {length} bytes (maximum: {MAX_KEY_LENGTH})"
        )


def generate_salt(length: int = 32) -> bytes:
    """
    Генерация криптографически стойкой случайной соли.

    Args:
        length: Длина соли в байтах (по умолчанию: 32)

    Returns:
        Случайная соль

    Raises:
        ValueError: Длина меньше минимальной

    Example:
        >>> salt = generate_salt(32)
        >>> len(salt)
        32
        >>> # Используйте при каждом выводе ключа
        >>> key = kdf.derive_key(password, salt)
    """
    if length < MIN_SALT_LENGTH:
        raise ValueError(f"Salt length {length} < minimum {MIN_SALT_LENGTH} bytes")
    return secrets.token_bytes(length)


# ============================================================================
# ALGORITHM IMPLEMENTATIONS
# ============================================================================


class Argon2idKDF:
    """
    Argon2id — современная password-based KDF (PHC winner 2015).

    Особенности:
    - **Type**: Hybrid (Argon2i + Argon2d)
    - **Memory-hard**: устойчив к GPU/ASIC атакам
    - **Time-hard**: настраиваемое время вычисления
    - **Parallelizable**: использует многопоточность

    Default Parameters (OWASP 2023):
    - time_cost: 2 iterations
    - memory_cost: 65536 KB (64 MB)
    - parallelism: 4 threads
    - salt: 32 bytes (random)

    Use Cases:
    - Password storage (hash + verify)
    - Key derivation from passwords
    - Authentication systems

    Security Notes:
    - Устойчива к side-channel attacks (Argon2i component)
    - Устойчива к GPU cracking (Argon2d component)
    - Рекомендуется OWASP, NIST, RFC 9106

    Performance:
    - Interactive use: ~200-500 ms (time_cost=2, memory=64MB)
    - High security: ~2-5 seconds (time_cost=4, memory=128MB)

    Example:
        >>> kdf = Argon2idKDF()
        >>> salt = generate_salt(32)
        >>> # Derive 256-bit encryption key
        >>> key = kdf.derive_key(
        ...     password=b"user_password",
        ...     salt=salt,
        ...     key_length=32
        ... )
        >>> len(key)
        32

    References:
    - RFC 9106: Argon2 Memory-Hard Function
    - OWASP Password Storage Cheat Sheet
    """

    ALGORITHM_ID = "argon2id"

    # OWASP 2023 recommended parameters
    DEFAULT_TIME_COST = ARGON2_DEFAULT_TIME_COST
    DEFAULT_MEMORY_COST = ARGON2_DEFAULT_MEMORY_COST
    DEFAULT_PARALLELISM = ARGON2_DEFAULT_PARALLELISM
    DEFAULT_SALT_LENGTH = ARGON2_DEFAULT_SALT_LENGTH

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        *,
        key_length: int = 32,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost: int = DEFAULT_MEMORY_COST,
        parallelism: int = DEFAULT_PARALLELISM,
        **kwargs: Any,
    ) -> bytes:
        """
        Вывести ключ из пароля используя Argon2id.

        Args:
            password: Пароль пользователя (bytes)
            salt: Случайная соль (минимум 16 байт, рекомендуется 32)
            key_length: Длина выходного ключа (по умолчанию: 32 байта)
            time_cost: Количество итераций (по умолчанию: 2)
            memory_cost: Использование памяти в KB (по умолчанию: 65536 = 64 MB)
            parallelism: Количество потоков (по умолчанию: 4)

        Returns:
            Выведенный ключ (key_length bytes)

        Raises:
            ValueError: Некорректные параметры
            AlgorithmNotSupportedError: argon2-cffi не установлен
            AlgorithmNotSupportedError: Ошибка при выводе ключа

        Performance:
        - ~200-500 ms на современном CPU (намеренно медленно)
        - Память: 64 MB (настраивается)

        Security Tuning:
        - Увеличьте memory_cost для большей GPU-устойчивости
        - Увеличьте time_cost для замедления brute-force
        - Баланс: 0.5-1 секунда приемлемо для аутентификации

        Example:
            >>> kdf = Argon2idKDF()
            >>> salt = secrets.token_bytes(32)
            >>> key = kdf.derive_key(b"user_password", salt)
            >>> len(key)
            32
        """
        # Validation
        _validate_salt(salt, min_length=MIN_SALT_LENGTH)
        _validate_key_length(key_length)

        if time_cost < 1:
            raise ValueError(f"time_cost must be >= 1, got: {time_cost}")
        if memory_cost < 8:
            raise ValueError(f"memory_cost must be >= 8 KB, got: {memory_cost}")
        if parallelism < 1:
            raise ValueError(f"parallelism must be >= 1, got: {parallelism}")

        logger.debug(
            f"Argon2id: deriving {key_length}-byte key "
            f"(time={time_cost}, memory={memory_cost}KB, parallelism={parallelism})"
        )

        try:
            from argon2.low_level import Type, hash_secret_raw

            # Use low-level API for raw key derivation
            derived_key = hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=key_length,
                type=Type.ID,  # Argon2id
            )

            logger.debug(f"Argon2id: key derived successfully ({key_length} bytes)")
            return derived_key

        except ImportError as exc:
            raise AlgorithmNotSupportedError(
                algorithm="Argon2id",
                reason="argon2-cffi library not installed",
                required_library="argon2-cffi",
            ) from exc
        except Exception as exc:
            raise KeyDerivationError(f"Argon2id derivation failed: {exc}") from exc


class PBKDF2SHA256KDF:
    """
    PBKDF2-SHA256 — password-based KDF (NIST standard).

    Особенности:
    - **Standard**: NIST SP 800-132, PKCS#5
    - **Widely compatible**: доступен везде (stdlib)
    - **Iterations**: высокий count компенсирует отсутствие memory-hardness

    Default Parameters (OWASP 2023):
    - iterations: 600,000 (SHA-256)
    - salt: 32 bytes (random)
    - hash: SHA-256

    Use Cases:
    - Legacy system compatibility
    - Systems without Argon2 support
    - FIPS 140-2 compliance requirement

    Security Notes:
    - **NOT memory-hard** (уязвим к GPU cracking)
    - Требует HIGH iteration count (600k+)
    - Рассмотрите Argon2id для новых систем

    Performance:
    - ~50-200 ms (600k iterations)
    - Линейно зависит от iteration count

    Example:
        >>> kdf = PBKDF2SHA256KDF()
        >>> salt = generate_salt(32)
        >>> key = kdf.derive_key(
        ...     password=b"user_password",
        ...     salt=salt,
        ...     iterations=600_000
        ... )

    References:
    - NIST SP 800-132: Recommendation for Password-Based Key Derivation
    - RFC 8018: PKCS #5 v2.1
    """

    ALGORITHM_ID = "pbkdf2-sha256"

    # OWASP 2023: 600,000 iterations for SHA-256
    DEFAULT_ITERATIONS = PBKDF2_DEFAULT_ITERATIONS
    MIN_ITERATIONS = PBKDF2_MIN_ITERATIONS
    DEFAULT_SALT_LENGTH = PBKDF2_DEFAULT_SALT_LENGTH

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        *,
        key_length: int = 32,
        iterations: int = DEFAULT_ITERATIONS,
        **kwargs: Any,
    ) -> bytes:
        """
        Вывести ключ из пароля используя PBKDF2-SHA256.

        Args:
            password: Пароль пользователя (bytes)
            salt: Случайная соль (минимум 16 байт)
            key_length: Длина выходного ключа (по умолчанию: 32 байта)
            iterations: Количество итераций (по умолчанию: 600,000)

        Returns:
            Выведенный ключ (key_length bytes)

        Raises:
            ValueError: iterations < 100,000 (НЕБЕЗОПАСНО)
            AlgorithmNotSupportedError: Ошибка при выводе ключа

        Security Warning:
        - Минимум 600,000 iterations (OWASP 2023)
        - Более низкие значения НЕБЕЗОПАСНЫ против GPU атак

        Example:
            >>> kdf = PBKDF2SHA256KDF()
            >>> salt = secrets.token_bytes(32)
            >>> # High security: 1,000,000 iterations
            >>> key = kdf.derive_key(
            ...     b"password", salt, iterations=1_000_000
            ... )
        """
        # Validation
        _validate_salt(salt, min_length=MIN_SALT_LENGTH)
        _validate_key_length(key_length)

        if iterations < self.MIN_ITERATIONS:
            raise ValueError(
                f"iterations={iterations} is INSECURE. "
                f"Minimum: {self.MIN_ITERATIONS:,} "
                f"(OWASP recommends {self.DEFAULT_ITERATIONS:,})"
            )

        logger.debug(
            f"PBKDF2-SHA256: deriving {key_length}-byte key "
            f"(iterations={iterations:,})"
        )

        try:
            derived_key = hashlib.pbkdf2_hmac(
                hash_name="sha256",
                password=password,
                salt=salt,
                iterations=iterations,
                dklen=key_length,
            )

            logger.debug(
                f"PBKDF2-SHA256: key derived successfully ({key_length} bytes)"
            )
            return derived_key

        except Exception as exc:
            raise KeyDerivationError(f"PBKDF2-SHA256 derivation failed: {exc}") from exc


class ScryptKDF:
    """
    Scrypt — memory-hard password-based KDF.

    Особенности:
    - **Memory-hard**: требует много RAM (защита от GPU/ASIC)
    - **Tunable**: параметры N, r, p настраиваются
    - **Used in**: Bitcoin, Litecoin, Tarsnap

    Default Parameters:
    - N: 2^14 (16384) - CPU/memory cost
    - r: 8 - block size
    - p: 1 - parallelization
    - memory: ~16 MB (N * r * 128 bytes)

    Use Cases:
    - High-security password storage
    - Cryptocurrency key derivation
    - Systems requiring memory-hardness

    Security Notes:
    - More memory-hard than PBKDF2
    - Less flexible than Argon2id
    - Standardized: RFC 7914

    Performance:
    - ~100-300 ms (default parameters)
    - Memory: ~16 MB (adjustable)

    Example:
        >>> kdf = ScryptKDF()
        >>> salt = generate_salt(32)
        >>> # Default: N=16384, r=8, p=1
        >>> key = kdf.derive_key(b"password", salt)
        >>> # High security: N=32768 (32 MB)
        >>> key = kdf.derive_key(b"password", salt, n=2**15)

    References:
    - RFC 7914: The scrypt Password-Based Key Derivation Function
    """

    ALGORITHM_ID = "scrypt"

    # Default parameters (moderate security)
    DEFAULT_N = SCRYPT_DEFAULT_N  # 16384
    DEFAULT_R = SCRYPT_DEFAULT_R  # 8
    DEFAULT_P = SCRYPT_DEFAULT_P  # 1
    DEFAULT_SALT_LENGTH = SCRYPT_DEFAULT_SALT_LENGTH

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        *,
        key_length: int = 32,
        n: int = DEFAULT_N,
        r: int = DEFAULT_R,
        p: int = DEFAULT_P,
        **kwargs: Any,
    ) -> bytes:
        """
        Вывести ключ из пароля используя Scrypt.

        Args:
            password: Пароль пользователя (bytes)
            salt: Случайная соль (минимум 16 байт)
            key_length: Длина выходного ключа (по умолчанию: 32 байта)
            n: CPU/memory cost (должно быть степенью 2, по умолчанию: 16384)
            r: Block size (по умолчанию: 8)
            p: Parallelization (по умолчанию: 1)

        Returns:
            Выведенный ключ (key_length bytes)

        Raises:
            ValueError: N не степень 2 или некорректные параметры
            AlgorithmNotSupportedError: Ошибка при выводе ключа

        Memory Usage:
        - memory ≈ 128 * N * r bytes
        - Default (N=16384, r=8): ~16 MB
        - High security (N=32768, r=8): ~32 MB
        - Maximum (N=65536, r=8): ~64 MB

        Security Tuning:
        - Увеличьте N для большей памяти/времени
        - N должен быть степенью 2
        - Высокие значения: N=2^15 (32 MB), N=2^16 (64 MB)

        Example:
            >>> kdf = ScryptKDF()
            >>> salt = secrets.token_bytes(32)
            >>> # Default: ~16 MB memory
            >>> key = kdf.derive_key(b"password", salt)
            >>> # High security: ~64 MB memory
            >>> key = kdf.derive_key(b"password", salt, n=2**16)
        """
        # Validation
        _validate_salt(salt, min_length=MIN_SALT_LENGTH)
        _validate_key_length(key_length)

        # Validate N is power of 2
        if n < 2 or (n & (n - 1)) != 0:
            raise ValueError(f"N must be power of 2, got: {n}")
        if r < 1:
            raise ValueError(f"r must be >= 1, got: {r}")
        if p < 1:
            raise ValueError(f"p must be >= 1, got: {p}")

        memory_mb = (128 * n * r) / (1024 * 1024)
        logger.debug(
            f"Scrypt: deriving {key_length}-byte key "
            f"(N={n}, r={r}, p={p}, memory≈{memory_mb:.1f}MB)"
        )

        try:
            derived_key = hashlib.scrypt(
                password=password,
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=key_length,
            )

            logger.debug(f"Scrypt: key derived successfully ({key_length} bytes)")
            return derived_key

        except Exception as exc:
            raise KeyDerivationError(f"Scrypt derivation failed: {exc}") from exc


class HKDFSHA256:
    """
    HKDF-SHA256 — HMAC-based Key Derivation Function.

    Особенности:
    - **Purpose**: Expand/extract keys from shared secrets
    - **NOT for passwords**: используйте Argon2id/PBKDF2 вместо этого!
    - **Fast**: подходит для key derivation, НЕ для password hashing

    Use Cases:
    - Derive keys after ECDH/X25519 key exchange
    - Expand a master key into multiple subkeys
    - TLS 1.3 key derivation
    - Signal Protocol key ratcheting

    Parameters:
    - info: Optional context/application-specific info
    - salt: Optional salt (can be empty)

    Security Notes:
    - **DO NOT use for password hashing** (слишком быстро)
    - Input ДОЛЖЕН иметь high entropy (shared secret, master key)
    - RFC 5869 compliant

    Performance:
    - <1 ms (очень быстро)
    - НЕ подходит для защиты паролей!

    Example:
        >>> # ✅ GOOD: После key exchange
        >>> shared_secret = x25519_exchange(my_priv, peer_pub)
        >>> kdf = HKDFSHA256()
        >>> encryption_key = kdf.derive_key(
        ...     password=shared_secret,
        ...     salt=b"",
        ...     info=b"encryption"
        ... )
        >>>
        >>> # ❌ BAD: Для пароля пользователя
        >>> key = HKDFSHA256().derive_key(b"password123", salt)
        >>> # НЕБЕЗОПАСНО! Используйте Argon2id!

    References:
    - RFC 5869: HMAC-based Extract-and-Expand KDF (HKDF)
    """

    ALGORITHM_ID = "hkdf-sha256"

    def derive_key(
        self,
        password: bytes,  # Actually "input key material" (IKM)
        salt: bytes,
        *,
        key_length: int = 32,
        info: bytes = b"",
        **kwargs: Any,
    ) -> bytes:
        """
        Вывести ключ из входного материала используя HKDF-SHA256.

        Args:
            password: Входной материал ключа (НЕ пароль пользователя!)
                     Должен иметь high-entropy (shared secret, master key)
            salt: Опциональная соль (может быть пустой, но рекомендуется)
            key_length: Длина выходного ключа (по умолчанию: 32 байта)
            info: Опциональная контекстная информация (по умолчанию: пусто)

        Returns:
            Выведенный ключ (key_length bytes)

        Raises:
            ValueError: Некорректные параметры
            AlgorithmNotSupportedError: Ошибка при выводе ключа

        ⚠️ WARNING:
        - НЕ используйте для паролей пользователей (используйте Argon2id)
        - Input должен быть high-entropy (>= 128 bits)

        Example:
            >>> # После X25519 key exchange
            >>> shared_secret = ecdh_derive(my_priv, peer_pub)
            >>> kdf = HKDFSHA256()
            >>> encryption_key = kdf.derive_key(
            ...     password=shared_secret,
            ...     salt=b"",
            ...     info=b"encryption",
            ...     key_length=32
            ... )
            >>> mac_key = kdf.derive_key(
            ...     password=shared_secret,
            ...     salt=b"",
            ...     info=b"authentication",
            ...     key_length=32
            ... )
        """
        # Validation
        _validate_key_length(key_length)

        # Note: HKDF allows empty salt (uses zero-filled)
        if len(salt) > 0 and len(salt) < MIN_SALT_LENGTH:
            raise ValueError(f"If salt provided, min length is {MIN_SALT_LENGTH} bytes")

        logger.debug(
            f"HKDF-SHA256: deriving {key_length}-byte key "
            f"(salt_len={len(salt)}, info_len={len(info)})"
        )

        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt if salt else None,
                info=info,
            )

            derived_key = hkdf.derive(password)

            logger.debug(f"HKDF-SHA256: key derived successfully ({key_length} bytes)")
            return derived_key

        except Exception as exc:
            raise KeyDerivationError(f"HKDF-SHA256 derivation failed: {exc}") from exc


# ============================================================================
# METADATA
# ============================================================================

METADATA_ARGON2ID = create_kdf_metadata(
    name="Argon2id",
    library="argon2-cffi",
    implementation_class="Argon2idKDF",
    recommended_iterations=ARGON2_DEFAULT_TIME_COST,
    recommended_memory_cost=ARGON2_DEFAULT_MEMORY_COST,
    security_level=SecurityLevel.HIGH,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "Argon2id — modern password-based KDF (PHC winner 2015). "
        "Memory-hard, GPU-resistant. OWASP recommended."
    ),
    description_en=(
        "Argon2id — modern password-based KDF (PHC winner 2015). "
        "Memory-hard, resistant to GPU/ASIC attacks. OWASP recommended."
    ),
    test_vectors_source="RFC 9106",
    use_cases=[
        "Password storage",
        "Key derivation from passwords",
        "Authentication systems",
    ],
)

METADATA_PBKDF2 = create_kdf_metadata(
    name="PBKDF2-SHA256",
    library="hashlib",
    implementation_class="PBKDF2SHA256KDF",
    recommended_iterations=PBKDF2_DEFAULT_ITERATIONS,
    security_level=SecurityLevel.STANDARD,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "PBKDF2-SHA256 — NIST standard password-based KDF (PKCS#5). "
        "Widely compatible (stdlib). NOT memory-hard, requires high iteration count (600k+)."
    ),
    description_en=(
        "PBKDF2-SHA256 — NIST standard password-based KDF (PKCS#5). "
        "Widely compatible. NOT memory-hard, requires high iteration count (600k+)."
    ),
    test_vectors_source="NIST SP 800-132, RFC 8018",
    use_cases=[
        "Legacy system compatibility",
        "FIPS 140-2 compliance",
        "Systems without Argon2 support",
    ],
)

METADATA_SCRYPT = create_kdf_metadata(
    name="Scrypt",
    library="hashlib",
    implementation_class="ScryptKDF",
    recommended_iterations=SCRYPT_DEFAULT_N,
    recommended_memory_cost=SCRYPT_DEFAULT_N * SCRYPT_DEFAULT_R * 128 // 1024,  # KB
    security_level=SecurityLevel.STANDARD,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "Scrypt — memory-hard password-based KDF (RFC 7914). "
        "Used in Bitcoin, Litecoin. More memory-hard than PBKDF2."
    ),
    description_en=(
        "Scrypt — memory-hard password-based KDF (RFC 7914). "
        "Used in cryptocurrencies. More memory-hard than PBKDF2."
    ),
    test_vectors_source="RFC 7914",
    use_cases=[
        "High-security password storage",
        "Cryptocurrency key derivation",
        "Memory-hard KDF requirement",
    ],
)

METADATA_HKDF = create_kdf_metadata(
    name="HKDF-SHA256",
    library="cryptography",
    implementation_class="HKDFSHA256",
    recommended_iterations=1,  # HKDF не использует iterations
    security_level=SecurityLevel.STANDARD,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "HKDF-SHA256 — HMAC-based key expansion (RFC 5869). "
        "For shared secrets, NOT passwords. Used in TLS 1.3, Signal Protocol."
    ),
    description_en=(
        "HKDF-SHA256 — HMAC-based key expansion (RFC 5869). "
        "For shared secrets, NOT passwords. Used in TLS 1.3, Signal."
    ),
    test_vectors_source="RFC 5869",
    use_cases=[
        "Key expansion after ECDH/X25519",
        "Master key expansion",
        "TLS 1.3 key derivation",
    ],
    extra={"warning": "NOT suitable for password hashing (too fast)"},
)

# ============================================================================
# REGISTRY & FACTORY
# ============================================================================

# All metadata objects
ALL_METADATA: list[AlgorithmMetadata] = [
    METADATA_ARGON2ID,
    METADATA_PBKDF2,
    METADATA_SCRYPT,
    METADATA_HKDF,
]

# Algorithm registry: {id: (class, metadata)}
ALGORITHMS: dict[str, tuple[type[KDFProtocol], AlgorithmMetadata]] = {
    "argon2id": (Argon2idKDF, METADATA_ARGON2ID),
    "pbkdf2-sha256": (PBKDF2SHA256KDF, METADATA_PBKDF2),
    "scrypt": (ScryptKDF, METADATA_SCRYPT),
    "hkdf-sha256": (HKDFSHA256, METADATA_HKDF),
}


def get_kdf_algorithm(algorithm_id: str) -> KDFProtocol:
    """
    Получить экземпляр KDF алгоритма по ID.

    Args:
        algorithm_id: ID алгоритма ('argon2id', 'pbkdf2-sha256', 'scrypt', 'hkdf-sha256')

    Returns:
        Экземпляр KDF алгоритма

    Raises:
        KeyError: Алгоритм не найден
        AlgorithmNotSupportedError: Требуемая библиотека не установлена

    Example:
        >>> # Get recommended KDF
        >>> kdf = get_kdf_algorithm('argon2id')
        >>> salt = generate_salt(32)
        >>> key = kdf.derive_key(b"password", salt)
        >>>
        >>> # Get legacy KDF
        >>> kdf = get_kdf_algorithm('pbkdf2-sha256')
    """
    if algorithm_id not in ALGORITHMS:
        available = ", ".join(ALGORITHMS.keys())
        raise KeyError(f"Algorithm '{algorithm_id}' not found. Available: {available}")

    cls, metadata = ALGORITHMS[algorithm_id]

    # Check if algorithm requires external library (Argon2id)
    if metadata.library == "argon2-cffi":
        try:
            import argon2  # noqa: F401
        except ImportError:
            raise AlgorithmNotSupportedError(
                algorithm=algorithm_id,
                reason="argon2-cffi library not installed",
                required_library="argon2-cffi",
            ) from None

    logger.debug(f"Creating KDF instance: {algorithm_id}")
    return cls()


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    # Protocol
    "KDFProtocol",
    # Classes
    "Argon2idKDF",
    "PBKDF2SHA256KDF",
    "ScryptKDF",
    "HKDFSHA256",
    # Metadata
    "METADATA_ARGON2ID",
    "METADATA_PBKDF2",
    "METADATA_SCRYPT",
    "METADATA_HKDF",
    "ALL_METADATA",
    # Registry
    "ALGORITHMS",
    "get_kdf_algorithm",
    # Helpers
    "generate_salt",
]
