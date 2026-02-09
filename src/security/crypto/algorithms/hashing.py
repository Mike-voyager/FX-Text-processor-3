"""
Криптографические хеш-функции для FX Text Processor 3.

Этот модуль содержит 8 хеш-алгоритмов:
- SHA-2: SHA-256, SHA-384, SHA-512 (NIST FIPS 180-4)
- SHA-3: SHA3-256, SHA3-512 (NIST FIPS 202)
- BLAKE: BLAKE2b, BLAKE2s (RFC 7693), BLAKE3 (2020)

Performance Characteristics:
    - BLAKE3: ~800 MB/s (fastest, parallelizable)
    - BLAKE2b/s: ~600 MB/s (fast, widely used in Argon2/WireGuard)
    - SHA-512: ~600 MB/s (64-bit optimized)
    - SHA-256: ~400 MB/s (industry standard, Bitcoin/TLS)
    - SHA3-256: ~150 MB/s (Keccak-based, different design)

Security Considerations:
    - All algorithms provide collision resistance (128-256 bits)
    - All algorithms provide preimage resistance
    - SHA-256 recommended by NIST for most applications
    - BLAKE3 recommended for high-performance scenarios
    - SHA-3 provides alternative to SHA-2 (different mathematical foundation)

Use Cases:
    - File integrity verification (checksums)
    - Digital signatures (pre-hashing before signing)
    - Password hashing (as part of PBKDF2, Argon2)
    - Content-addressable storage (Git-like systems)
    - Message authentication (HMAC)

Streaming Support:
    All algorithms support streaming for large files via hash_stream().
    Optimal chunk size: 64 KB (CHUNK_SIZE constant).

Example:
    >>> from src.security.crypto.algorithms.hashing import SHA256Hash
    >>> hasher = SHA256Hash()
    >>> hash_value = hasher.hash(b"Hello, World!")
    >>> len(hash_value)
    32
    >>> hash_value.hex()[:16]
    'dffd6021bb2bd5b0'

References:
    - FIPS 180-4: Secure Hash Standard (SHA-2)
      https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    - FIPS 202: SHA-3 Standard
      https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    - RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code
      https://tools.ietf.org/html/rfc7693
    - BLAKE3 Specification:
      https://github.com/BLAKE3-team/BLAKE3-specs
    - NIST SP 800-107: Recommendation for Applications Using Hash Functions
      https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final

Author: FX Text Processor 3 Team
Version: 2.3
Date: February 10, 2026
"""

from __future__ import annotations

import hashlib
from typing import BinaryIO, Final

import logging
from src.security.crypto.core.exceptions import (
    AlgorithmNotSupportedError,
    HashingFailedError,
    InvalidInputError,
)
from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
)
from src.security.crypto.core.protocols import HashProtocol

logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTS
# ==============================================================================

CHUNK_SIZE: Final[int] = 65536  # 64 KB - optimal for I/O operations

# Output sizes (in bytes)
SHA256_OUTPUT_SIZE: Final[int] = 32
SHA384_OUTPUT_SIZE: Final[int] = 48
SHA512_OUTPUT_SIZE: Final[int] = 64
SHA3_256_OUTPUT_SIZE: Final[int] = 32
SHA3_512_OUTPUT_SIZE: Final[int] = 64
BLAKE2B_OUTPUT_SIZE: Final[int] = 64
BLAKE2S_OUTPUT_SIZE: Final[int] = 32
BLAKE3_OUTPUT_SIZE: Final[int] = 32


# ==============================================================================
# BASE CLASS FOR STDLIB HASHES
# ==============================================================================


class _StdlibHashBase:
    """
    Базовый класс для хеш-функций из стандартной библиотеки hashlib.

    Упрощает реализацию за счёт унификации кода для всех stdlib-based
    хеш-функций (SHA-2, SHA-3, BLAKE2).

    Attributes:
        _HASHLIB_NAME: Имя алгоритма для hashlib.new()
        ALGORITHM_ID: Уникальный идентификатор алгоритма
        OUTPUT_SIZE: Размер выходного хеша в байтах
    """

    _HASHLIB_NAME: str
    ALGORITHM_ID: str
    OUTPUT_SIZE: int

    def hash(self, data: bytes) -> bytes:
        """
        Хешировать данные (one-shot).

        Args:
            data: Данные для хеширования (любой размер)

        Returns:
            Хеш фиксированного размера (OUTPUT_SIZE байт)

        Raises:
            TypeError: Если data не является bytes
            InvalidInputError: Если data пустые
            HashingFailedError: Если хеширование не удалось

        Example:
            >>> hasher = SHA256Hash()
            >>> hash_value = hasher.hash(b"test data")
            >>> len(hash_value) == 32
            True
        """
        if not isinstance(data, bytes):
            raise TypeError(f"data must be bytes, got {type(data).__name__}")

        if len(data) == 0:
            raise InvalidInputError("Cannot hash empty data")

        try:
            hasher = hashlib.new(self._HASHLIB_NAME)
            hasher.update(data)
            return hasher.digest()

        except Exception as exc:
            logger.error(
                f"{self.ALGORITHM_ID.upper()} hashing failed for "
                f"{len(data)} bytes: {exc}"
            )
            raise HashingFailedError(
                f"{self.ALGORITHM_ID.upper()} hashing failed"
            ) from exc

    def hash_stream(self, stream: BinaryIO) -> bytes:
        """
        Хешировать поток данных (для больших файлов).

        Читает данные чанками по CHUNK_SIZE (64 KB) для оптимальной
        производительности и минимального использования памяти.

        Args:
            stream: Бинарный поток (открытый файл, BytesIO)

        Returns:
            Хеш фиксированного размера (OUTPUT_SIZE байт)

        Raises:
            TypeError: Если stream не является BinaryIO
            InvalidInputError: Если поток пустой
            HashingFailedError: Если хеширование не удалось

        Example:
            >>> hasher = SHA256Hash()
            >>> with open("large_file.bin", "rb") as f:
            ...     hash_value = hasher.hash_stream(f)
            >>> len(hash_value) == 32
            True
        """
        if not hasattr(stream, "read"):
            raise TypeError("stream must be a binary readable object")

        hasher = hashlib.new(self._HASHLIB_NAME)
        bytes_processed = 0

        try:
            while chunk := stream.read(CHUNK_SIZE):
                hasher.update(chunk)
                bytes_processed += len(chunk)

            if bytes_processed == 0:
                raise InvalidInputError("Cannot hash empty stream")

            digest = hasher.digest()

            logger.debug(
                f"{self.ALGORITHM_ID.upper()} hashed {bytes_processed} bytes "
                f"from stream"
            )

            return digest

        except InvalidInputError:
            raise
        except Exception as exc:
            logger.error(
                f"{self.ALGORITHM_ID.upper()} stream hashing failed after "
                f"{bytes_processed} bytes: {exc}"
            )
            raise HashingFailedError(
                f"{self.ALGORITHM_ID.upper()} stream hashing failed"
            ) from exc


# ==============================================================================
# SHA-2 FAMILY (FIPS 180-4)
# ==============================================================================


class SHA256Hash(_StdlibHashBase):
    """
    SHA-256 — криптографическая хеш-функция семейства SHA-2.

    Особенности:
        - Размер хеша: 256 бит (32 байта)
        - Скорость: ~400 MB/s на современных CPU
        - Безопасность: 128-бит collision resistance
        - Рекомендуется: NIST для большинства применений

    Use Cases:
        - Digital signatures (Bitcoin, TLS certificates)
        - File integrity checks (checksums)
        - Password hashing (as part of PBKDF2, Argon2)
        - HMAC (message authentication)
        - Content-addressable storage

    Security Notes:
        - Устойчива к collision attacks (в отличие от SHA-1)
        - Устойчива к preimage attacks
        - Рекомендуется NIST FIPS 180-4
        - Используется в Bitcoin mining

    Performance:
        - Оптимизирована для 32-bit systems
        - ~400 MB/s на Intel Core i7
        - Хорошо подходит для embedded systems

    References:
        - FIPS 180-4: Secure Hash Standard
        - RFC 6234: US Secure Hash Algorithms
        - ISO/IEC 10118-3: Hash functions
    """

    _HASHLIB_NAME = "sha256"
    ALGORITHM_ID = "sha256"
    OUTPUT_SIZE = SHA256_OUTPUT_SIZE


class SHA384Hash(_StdlibHashBase):
    """
    SHA-384 — криптографическая хеш-функция семейства SHA-2.

    Особенности:
        - Размер хеша: 384 бит (48 байт)
        - Скорость: ~500 MB/s на современных CPU
        - Безопасность: 192-бит collision resistance
        - Truncated версия SHA-512

    Use Cases:
        - Высокая безопасность без overhead SHA-512
        - Digital signatures (когда требуется >128-bit security)
        - NIST Suite B Cryptography
        - Government applications

    Security Notes:
        - Более высокая безопасность чем SHA-256
        - Основана на SHA-512 (64-bit operations)
        - Рекомендуется для long-term security

    Performance:
        - Оптимизирована для 64-bit systems
        - Быстрее SHA-256 на 64-bit CPU
        - ~500 MB/s на Intel Core i7

    References:
        - FIPS 180-4: Secure Hash Standard
        - NIST Suite B Cryptography
    """

    _HASHLIB_NAME = "sha384"
    ALGORITHM_ID = "sha384"
    OUTPUT_SIZE = SHA384_OUTPUT_SIZE


class SHA512Hash(_StdlibHashBase):
    """
    SHA-512 — криптографическая хеш-функция семейства SHA-2.

    Особенности:
        - Размер хеша: 512 бит (64 байта)
        - Скорость: ~600 MB/s на современных CPU
        - Безопасность: 256-бит collision resistance
        - Оптимизирована для 64-bit systems

    Use Cases:
        - Maximum security для long-term storage
        - Digital signatures с высокими требованиями к безопасности
        - Blockchain applications
        - Government/military applications

    Security Notes:
        - Наивысшая безопасность в семействе SHA-2
        - Оптимальна для 64-bit architectures
        - Рекомендуется для данных с долгим сроком хранения

    Performance:
        - Fastest SHA-2 на 64-bit systems
        - ~600 MB/s на Intel Core i7
        - Медленнее SHA-256 на 32-bit systems

    References:
        - FIPS 180-4: Secure Hash Standard
        - NIST Suite B Cryptography
        - ISO/IEC 10118-3: Hash functions
    """

    _HASHLIB_NAME = "sha512"
    ALGORITHM_ID = "sha512"
    OUTPUT_SIZE = SHA512_OUTPUT_SIZE


# ==============================================================================
# SHA-3 FAMILY (FIPS 202, Keccak)
# ==============================================================================


class SHA3_256Hash(_StdlibHashBase):
    """
    SHA3-256 — криптографическая хеш-функция семейства SHA-3 (Keccak).

    Особенности:
        - Размер хеша: 256 бит (32 байта)
        - Скорость: ~150 MB/s на современных CPU
        - Безопасность: 128-бит collision resistance
        - Основана на sponge construction (отличается от SHA-2)

    Use Cases:
        - Альтернатива SHA-256 (другой математический дизайн)
        - Системы требующие diversity (защита от common-mode failures)
        - Post-quantum scenarios (разный дизайн от SHA-2)
        - NIST recommended alternative

    Security Notes:
        - Совершенно другой дизайн от SHA-2 (sponge vs Merkle-Damgård)
        - Устойчива к length-extension attacks (в отличие от SHA-2)
        - Winner of SHA-3 competition (2012)

    Performance:
        - Медленнее SHA-256 (~3x)
        - ~150 MB/s на Intel Core i7
        - Может быть ускорена на специализированном hardware

    References:
        - FIPS 202: SHA-3 Standard
        - Keccak Team: https://keccak.team/
        - NIST SHA-3 Competition
    """

    _HASHLIB_NAME = "sha3_256"
    ALGORITHM_ID = "sha3-256"
    OUTPUT_SIZE = SHA3_256_OUTPUT_SIZE


class SHA3_512Hash(_StdlibHashBase):
    """
    SHA3-512 — криптографическая хеш-функция семейства SHA-3 (Keccak).

    Особенности:
        - Размер хеша: 512 бит (64 байта)
        - Скорость: ~100 MB/s на современных CPU
        - Безопасность: 256-бит collision resistance
        - Основана на sponge construction

    Use Cases:
        - Maximum security с SHA-3 design
        - Long-term data protection
        - Diversity в crypto systems
        - Alternative к SHA-512

    Security Notes:
        - Наивысшая безопасность в семействе SHA-3
        - Устойчива к length-extension attacks
        - Другой математический фундамент от SHA-2

    Performance:
        - Медленнее SHA-512 (~6x)
        - ~100 MB/s на Intel Core i7
        - Trade-off: безопасность vs скорость

    References:
        - FIPS 202: SHA-3 Standard
        - Keccak Team: https://keccak.team/
    """

    _HASHLIB_NAME = "sha3_512"
    ALGORITHM_ID = "sha3-512"
    OUTPUT_SIZE = SHA3_512_OUTPUT_SIZE


# ==============================================================================
# BLAKE2 FAMILY (RFC 7693)
# ==============================================================================


class BLAKE2bHash(_StdlibHashBase):
    """
    BLAKE2b — быстрая криптографическая хеш-функция.

    Особенности:
        - Размер хеша: 512 бит (64 байта, настраиваемый)
        - Скорость: ~600 MB/s на современных CPU
        - Безопасность: 256-бит collision resistance
        - Finalist SHA-3 competition

    Use Cases:
        - Argon2 password hashing (internal hash)
        - WireGuard VPN (handshake)
        - File integrity (faster than SHA-512)
        - Content-addressable storage

    Security Notes:
        - Основана на ChaCha stream cipher design
        - Faster than SHA-2 без компромисса в безопасности
        - RFC 7693 standardized

    Performance:
        - ~600 MB/s на Intel Core i7
        - Comparable to SHA-512 но с лучшим дизайном
        - Оптимизирована для 64-bit systems

    References:
        - RFC 7693: The BLAKE2 Cryptographic Hash
        - https://www.blake2.net/
        - Argon2 RFC 9106
    """

    _HASHLIB_NAME = "blake2b"
    ALGORITHM_ID = "blake2b"
    OUTPUT_SIZE = BLAKE2B_OUTPUT_SIZE


class BLAKE2sHash(_StdlibHashBase):
    """
    BLAKE2s — компактная криптографическая хеш-функция.

    Особенности:
        - Размер хеша: 256 бит (32 байта, настраиваемый)
        - Скорость: ~600 MB/s на современных CPU
        - Безопасность: 128-бит collision resistance
        - Оптимизирована для 8-32 bit platforms

    Use Cases:
        - Embedded systems (smaller state size)
        - Mobile devices
        - IoT applications
        - Compact alternative к SHA-256

    Security Notes:
        - Same design как BLAKE2b но с меньшим state
        - Оптимальна для 32-bit и меньше systems
        - RFC 7693 standardized

    Performance:
        - ~600 MB/s на Intel Core i7
        - Более эффективна на small systems чем BLAKE2b
        - Faster than SHA-256

    References:
        - RFC 7693: The BLAKE2 Cryptographic Hash
        - https://www.blake2.net/
    """

    _HASHLIB_NAME = "blake2s"
    ALGORITHM_ID = "blake2s"
    OUTPUT_SIZE = BLAKE2S_OUTPUT_SIZE


# ==============================================================================
# BLAKE3 (2020, External Library)
# ==============================================================================


class BLAKE3Hash:
    """
    BLAKE3 — fastest cryptographic hash function (2020).

    Особенности:
        - Размер хеша: 256 бит (32 байта, настраиваемый до 2^64-1)
        - Скорость: ~800 MB/s (single-threaded), 5+ GB/s (multi-threaded)
        - Безопасность: 128-бит collision resistance
        - Parallelizable и tree-based design

    Use Cases:
        - Content-addressable storage (Git-like systems)
        - Fast file integrity checks
        - Large file checksums (benefits from parallelization)
        - Modern applications requiring maximum speed

    Security Notes:
        - Основана на BLAKE2 (SHA-3 finalist)
        - Not backward-compatible с BLAKE2b/BLAKE2s
        - Рекомендуется для новых систем (2020+)
        - Still awaiting NIST standardization

    Performance:
        - ~800 MB/s single-threaded на Intel Core i7
        - 5+ GB/s multi-threaded (automatic parallelization)
        - 2x faster than SHA-256, BLAKE2b
        - Optimal для больших файлов

    External Dependency:
        Требует установки библиотеки blake3-py:
        pip install blake3

    References:
        - BLAKE3 Specification: https://github.com/BLAKE3-team/BLAKE3-specs
        - blake3-py: https://github.com/oconnor663/blake3-py
        - Paper: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
    """

    ALGORITHM_ID = "blake3"
    OUTPUT_SIZE = BLAKE3_OUTPUT_SIZE

    def hash(self, data: bytes) -> bytes:
        """
        Хешировать данные с BLAKE3.

        Args:
            data: Данные для хеширования

        Returns:
            BLAKE3 хеш (32 байта по умолчанию)

        Raises:
            TypeError: Если data не является bytes
            InvalidInputError: Если data пустые
            AlgorithmNotSupportedError: Если blake3 library не установлена
            HashingFailedError: Если хеширование не удалось

        Example:
            >>> hasher = BLAKE3Hash()
            >>> hash_value = hasher.hash(b"test data")
            >>> len(hash_value) == 32
            True
        """
        if not isinstance(data, bytes):
            raise TypeError(f"data must be bytes, got {type(data).__name__}")

        if len(data) == 0:
            raise InvalidInputError("Cannot hash empty data")

        try:
            import blake3

            return blake3.blake3(data).digest()

        except ImportError as exc:
            raise AlgorithmNotSupportedError(
                algorithm="blake3",
                reason="blake3 library not installed",
                required_library="blake3",
            ) from exc

        except Exception as exc:
            logger.error(f"BLAKE3 hashing failed for {len(data)} bytes: {exc}")
            raise HashingFailedError("BLAKE3 hashing failed") from exc

    def hash_stream(self, stream: BinaryIO) -> bytes:
        """
        Хешировать поток с BLAKE3 (с автоматической параллелизацией).

        BLAKE3 автоматически использует многопоточность для больших файлов,
        достигая скорости 5+ GB/s на multi-core systems.

        Args:
            stream: Бинарный поток (открытый файл, BytesIO)

        Returns:
            BLAKE3 хеш (32 байта по умолчанию)

        Raises:
            TypeError: Если stream не является BinaryIO
            InvalidInputError: Если поток пустой
            AlgorithmNotSupportedError: Если blake3 library не установлена
            HashingFailedError: Если хеширование не удалось

        Example:
            >>> hasher = BLAKE3Hash()
            >>> with open("large_file.bin", "rb") as f:
            ...     hash_value = hasher.hash_stream(f)
            >>> len(hash_value) == 32
            True
        """
        if not hasattr(stream, "read"):
            raise TypeError("stream must be a binary readable object")

        try:
            import blake3

            hasher = blake3.blake3()
            bytes_processed = 0

            while chunk := stream.read(CHUNK_SIZE):
                hasher.update(chunk)
                bytes_processed += len(chunk)

            if bytes_processed == 0:
                raise InvalidInputError("Cannot hash empty stream")

            digest = hasher.digest()

            logger.debug(
                f"BLAKE3 hashed {bytes_processed} bytes from stream "
                f"(parallelization: automatic)"
            )

            return digest

        except ImportError as exc:
            raise AlgorithmNotSupportedError(
                algorithm="blake3",
                reason="blake3 library not installed",
                required_library="blake3",
            ) from exc

        except InvalidInputError:
            raise

        except Exception as exc:
            logger.error(
                f"BLAKE3 stream hashing failed after {bytes_processed} bytes: {exc}"
            )
            raise HashingFailedError("BLAKE3 stream hashing failed") from exc


# ==============================================================================
# METADATA DEFINITIONS
# ==============================================================================

# SHA256
METADATA_SHA256 = AlgorithmMetadata(
    name="SHA-256",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="hashlib",
    implementation_class="SHA256Hash",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=32,
    description_ru=(
        "SHA-256 — криптографическая хеш-функция семейства SHA-2 (FIPS 180-4). "
        "Индустриальный стандарт для цифровых подписей, TLS, Bitcoin. "
        "Выход: 32 байта (256 бит). Скорость: ~400 MB/s."
    ),
    description_en=(
        "SHA-256 is a cryptographic hash function from the SHA-2 family (FIPS 180-4). "
        "Industry standard for digital signatures, TLS, Bitcoin. "
        "Output: 32 bytes (256 bits). Speed: ~400 MB/s."
    ),
    is_post_quantum=False,
    use_cases=[
        "Digital signatures (Bitcoin, TLS)",
        "File integrity checks",
        "HMAC authentication",
        "Password hashing (PBKDF2, Argon2)",
    ],
)

# SHA384
METADATA_SHA384 = AlgorithmMetadata(
    name="SHA-384",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="hashlib",
    implementation_class="SHA384Hash",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=48,
    description_ru=(
        "SHA-384 — криптографическая хеш-функция семейства SHA-2 (FIPS 180-4). "
        "Truncated версия SHA-512. Выход: 48 байт (384 бит). "
        "Скорость: ~500 MB/s на 64-bit systems."
    ),
    description_en=(
        "SHA-384 is a cryptographic hash function from the SHA-2 family (FIPS 180-4). "
        "Truncated version of SHA-512. Output: 48 bytes (384 bits). "
        "Speed: ~500 MB/s on 64-bit systems."
    ),
    is_post_quantum=False,
    use_cases=[
        "High security digital signatures",
        "NIST Suite B Cryptography",
        "Government applications",
    ],
)

# SHA512
METADATA_SHA512 = AlgorithmMetadata(
    name="SHA-512",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="hashlib",
    implementation_class="SHA512Hash",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=64,
    description_ru=(
        "SHA-512 — криптографическая хеш-функция семейства SHA-2 (FIPS 180-4). "
        "Maximum security в SHA-2. Выход: 64 байта (512 бит). "
        "Скорость: ~600 MB/s на 64-bit systems."
    ),
    description_en=(
        "SHA-512 is a cryptographic hash function from the SHA-2 family (FIPS 180-4). "
        "Maximum security in SHA-2. Output: 64 bytes (512 bits). "
        "Speed: ~600 MB/s on 64-bit systems."
    ),
    is_post_quantum=False,
    use_cases=[
        "Long-term data protection",
        "Blockchain applications",
        "Government/military applications",
    ],
)

# SHA3-256
METADATA_SHA3_256 = AlgorithmMetadata(
    name="SHA3-256",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="hashlib",
    implementation_class="SHA3_256Hash",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=32,
    description_ru=(
        "SHA3-256 — криптографическая хеш-функция семейства SHA-3 (FIPS 202, Keccak). "
        "Альтернатива SHA-256 с другим математическим дизайном (sponge construction). "
        "Выход: 32 байта (256 бит). Скорость: ~150 MB/s."
    ),
    description_en=(
        "SHA3-256 is a cryptographic hash function from the SHA-3 family (FIPS 202, Keccak). "
        "Alternative to SHA-256 with different mathematical design (sponge construction). "
        "Output: 32 bytes (256 bits). Speed: ~150 MB/s."
    ),
    is_post_quantum=False,
    use_cases=[
        "Alternative to SHA-256",
        "Diversity in crypto systems",
        "Post-quantum scenarios",
    ],
)

# SHA3-512
METADATA_SHA3_512 = AlgorithmMetadata(
    name="SHA3-512",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="hashlib",
    implementation_class="SHA3_512Hash",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=64,
    description_ru=(
        "SHA3-512 — криптографическая хеш-функция семейства SHA-3 (FIPS 202, Keccak). "
        "Maximum security в SHA-3. Выход: 64 байта (512 бит). "
        "Скорость: ~100 MB/s."
    ),
    description_en=(
        "SHA3-512 is a cryptographic hash function from the SHA-3 family (FIPS 202, Keccak). "
        "Maximum security in SHA-3. Output: 64 bytes (512 bits). "
        "Speed: ~100 MB/s."
    ),
    is_post_quantum=False,
    use_cases=[
        "Maximum security with SHA-3",
        "Long-term data protection",
        "Alternative to SHA-512",
    ],
)

# BLAKE2b
METADATA_BLAKE2B = AlgorithmMetadata(
    name="BLAKE2b",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="hashlib",
    implementation_class="BLAKE2bHash",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=64,
    description_ru=(
        "BLAKE2b — быстрая криптографическая хеш-функция (RFC 7693). "
        "Финалист конкурса SHA-3. Используется в Argon2, WireGuard. "
        "Выход: 64 байта (512 бит). Скорость: ~600 MB/s."
    ),
    description_en=(
        "BLAKE2b is a fast cryptographic hash function (RFC 7693). "
        "SHA-3 competition finalist. Used in Argon2, WireGuard. "
        "Output: 64 bytes (512 bits). Speed: ~600 MB/s."
    ),
    is_post_quantum=False,
    use_cases=[
        "Argon2 password hashing",
        "WireGuard VPN",
        "Fast file integrity",
    ],
)

# BLAKE2s
METADATA_BLAKE2S = AlgorithmMetadata(
    name="BLAKE2s",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="hashlib",
    implementation_class="BLAKE2sHash",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=32,
    description_ru=(
        "BLAKE2s — компактная криптографическая хеш-функция (RFC 7693). "
        "Оптимизирована для 8-32 bit platforms. "
        "Выход: 32 байта (256 бит). Скорость: ~600 MB/s."
    ),
    description_en=(
        "BLAKE2s is a compact cryptographic hash function (RFC 7693). "
        "Optimized for 8-32 bit platforms. "
        "Output: 32 bytes (256 bits). Speed: ~600 MB/s."
    ),
    is_post_quantum=False,
    use_cases=[
        "Embedded systems",
        "Mobile devices",
        "IoT applications",
    ],
)

# BLAKE3
METADATA_BLAKE3 = AlgorithmMetadata(
    name="BLAKE3",
    category=AlgorithmCategory.HASH,
    protocol_class=HashProtocol,
    library="blake3-py",
    implementation_class="BLAKE3Hash",
    security_level=SecurityLevel.HIGH,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=None,
    digest_size=32,
    description_ru=(
        "BLAKE3 — fastest криптографическая хеш-функция (2020). "
        "Parallelizable, ~2x быстрее SHA-256. Основана на BLAKE2. "
        "Выход: 32 байта. Скорость: ~800 MB/s (single), 5+ GB/s (multi)."
    ),
    description_en=(
        "BLAKE3 is the fastest cryptographic hash function (2020). "
        "Parallelizable, ~2x faster than SHA-256. Based on BLAKE2. "
        "Output: 32 bytes. Speed: ~800 MB/s (single), 5+ GB/s (multi)."
    ),
    is_post_quantum=False,
    use_cases=[
        "Content-addressable storage",
        "Fast file integrity checks",
        "Large file checksums",
    ],
)


# ==============================================================================
# REGISTRY & FACTORY
# ==============================================================================

ALL_METADATA: list[AlgorithmMetadata] = [
    METADATA_SHA256,
    METADATA_SHA384,
    METADATA_SHA512,
    METADATA_SHA3_256,
    METADATA_SHA3_512,
    METADATA_BLAKE2B,
    METADATA_BLAKE2S,
    METADATA_BLAKE3,
]

HASH_ALGORITHMS: dict[str, tuple[type, AlgorithmMetadata]] = {
    "sha256": (SHA256Hash, METADATA_SHA256),
    "sha384": (SHA384Hash, METADATA_SHA384),
    "sha512": (SHA512Hash, METADATA_SHA512),
    "sha3-256": (SHA3_256Hash, METADATA_SHA3_256),
    "sha3-512": (SHA3_512Hash, METADATA_SHA3_512),
    "blake2b": (BLAKE2bHash, METADATA_BLAKE2B),
    "blake2s": (BLAKE2sHash, METADATA_BLAKE2S),
    "blake3": (BLAKE3Hash, METADATA_BLAKE3),
}


def get_hash_algorithm(algorithm_id: str) -> HashProtocol:
    """
    Получить экземпляр хеш-алгоритма по идентификатору.

    Args:
        algorithm_id: Идентификатор алгоритма
            ("sha256", "sha384", "sha512", "sha3-256", "sha3-512",
             "blake2b", "blake2s", "blake3")

    Returns:
        Экземпляр класса, реализующего HashingProtocol

    Raises:
        KeyError: Если алгоритм не найден
        AlgorithmNotSupportedError: Если требуемая библиотека не установлена

    Example:
        >>> hasher = get_hash_algorithm("sha256")
        >>> hash_value = hasher.hash(b"test data")
        >>> len(hash_value) == 32
        True

        >>> hasher = get_hash_algorithm("blake3")
        >>> hash_value = hasher.hash(b"test data")  # May raise if blake3 not installed
    """
    if algorithm_id not in HASH_ALGORITHMS:
        available = ", ".join(sorted(HASH_ALGORITHMS.keys()))
        raise KeyError(
            f"Hash algorithm '{algorithm_id}' not found. " f"Available: {available}"
        )

    algorithm_class, metadata = HASH_ALGORITHMS[algorithm_id]

    logger.debug(f"Creating hash algorithm instance: {algorithm_id}")

    instance: HashProtocol = algorithm_class()
    return instance


# ==============================================================================
# EXPORTS
# ==============================================================================

__all__ = [
    # Constants
    "CHUNK_SIZE",
    "SHA256_OUTPUT_SIZE",
    "SHA384_OUTPUT_SIZE",
    "SHA512_OUTPUT_SIZE",
    "SHA3_256_OUTPUT_SIZE",
    "SHA3_512_OUTPUT_SIZE",
    "BLAKE2B_OUTPUT_SIZE",
    "BLAKE2S_OUTPUT_SIZE",
    "BLAKE3_OUTPUT_SIZE",
    # SHA-2 Classes
    "SHA256Hash",
    "SHA384Hash",
    "SHA512Hash",
    # SHA-3 Classes
    "SHA3_256Hash",
    "SHA3_512Hash",
    # BLAKE Classes
    "BLAKE2bHash",
    "BLAKE2sHash",
    "BLAKE3Hash",
    # Metadata
    "METADATA_SHA256",
    "METADATA_SHA384",
    "METADATA_SHA512",
    "METADATA_SHA3_256",
    "METADATA_SHA3_512",
    "METADATA_BLAKE2B",
    "METADATA_BLAKE2S",
    "METADATA_BLAKE3",
    # Registry
    "ALL_METADATA",
    "HASH_ALGORITHMS",
    "get_hash_algorithm",
]
