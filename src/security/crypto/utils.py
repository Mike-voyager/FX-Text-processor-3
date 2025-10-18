"""
Криптографические утилиты для ESC/P Text Editor.

Потокобезопасные утилиты для:
- Зануления памяти (memory zeroization)
- Генерации случайных чисел с entropy mixing и проверкой качества
- Base64/Hex кодирования/декодирования
- Constant-time сравнения
- Валидации ключей и параметров
- Работы с файловой системой

Thread-safety:
    Все функции thread-safe. Генерация случайных чисел использует
    secrets.token_bytes() и os.urandom(), которые гарантированно
    thread-safe на уровне ОС.

Security:
    - Entropy audit при каждой генерации
    - XOR-mixing двух независимых источников случайности
    - Проверка доступности CSPRNG при первом использовании
    - Ограничение максимального размера генерируемых данных

Example:
    >>> from security.crypto.utils import generate_random_bytes, secure_bytes
    >>>
    >>> # Генерация ключа с автоматической проверкой качества
    >>> key = generate_random_bytes(32)
    >>>
    >>> # Автоматическое зануление при выходе из контекста
    >>> with secure_bytes(32) as secret:
    ...     secret[:] = key
    ...     # Работа с секретом
    ...     # Автоматически занулится при выходе
"""

from __future__ import annotations

import base64
import secrets
import os
import sys
import logging
import threading
from contextlib import contextmanager
from typing import Optional, Final, Generator

_LOGGER: Final = logging.getLogger(__name__)
_ZERO_BYTE: Final[int] = 0

# Thread-safety для одноразовой инициализации
_ENTROPY_CHECKED: bool = False
_ENTROPY_LOCK = threading.Lock()

# Limits
MAX_RANDOM_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MB максимум


# ============================================================================
# Platform Detection
# ============================================================================


def _get_platform_rng() -> str:
    """Определение используемого системного генератора случайных чисел."""
    if sys.platform == "linux":
        return "getrandom/urandom"
    elif sys.platform == "win32":
        return "CryptGenRandom"
    elif sys.platform == "darwin":
        return "SecRandomCopyBytes"
    else:
        return "os.urandom (generic)"


# Логирование используемого RNG при импорте модуля
_LOGGER.info(f"Platform RNG: {_get_platform_rng()}")


# ============================================================================
# Memory Management
# ============================================================================


def zero_memory(buf: Optional[bytearray]) -> None:
    """
    Зануление байтового буфера в памяти (thread-safe).

    Best-effort очистка чувствительных данных перед освобождением памяти.
    Python не гарантирует немедленное удаление из RAM, но это лучше чем ничего.

    Args:
        buf: Байтовый буфер для зануления (или None — будет проигнорировано)

    Raises:
        TypeError: Если buf не bytearray и не None

    Example:
        >>> secret = bytearray(b"password123")
        >>> zero_memory(secret)
        >>> assert all(b == 0 for b in secret)
    """
    if buf is None:
        return

    if not isinstance(buf, bytearray):
        raise TypeError(f"Expected bytearray or None, got {type(buf).__name__}")

    # Занулить каждый байт
    for i in range(len(buf)):
        buf[i] = _ZERO_BYTE


@contextmanager
def secure_bytes(length: int) -> Generator[bytearray, None, None]:
    """
    Context manager для автоматического зануления секретных данных.

    Создаёт bytearray и гарантирует его зануление при выходе из контекста,
    даже если произошло исключение.

    Args:
        length: Размер буфера в байтах

    Yields:
        bytearray для работы с секретными данными

    Example:
        >>> with secure_bytes(32) as secret:
        ...     secret[:] = generate_random_bytes(32)
        ...     # Работа с секретным ключом
        ...     # При выходе автоматически занулится
    """
    buf = bytearray(length)
    try:
        yield buf
    finally:
        zero_memory(buf)


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time сравнение байтов (защита от timing attacks, thread-safe).

    Использует secrets.compare_digest() для защиты от атак по времени
    выполнения при проверке MAC, токенов, паролей.

    Args:
        a: Первая последовательность байтов
        b: Вторая последовательность байтов

    Returns:
        True если последовательности идентичны, False иначе

    Example:
        >>> mac1 = b"authentic_mac_value"
        >>> mac2 = b"authentic_mac_value"
        >>> secure_compare(mac1, mac2)
        True
    """
    return secrets.compare_digest(a, b)


# ============================================================================
# Entropy Management
# ============================================================================


def diagnose_rng() -> None:
    """
    Диагностика CSPRNG (Cryptographically Secure Pseudo-Random Number Generator).

    Проверяет работоспособность os.urandom() — системного генератора
    случайных чисел. Thread-safe.

    Raises:
        RuntimeError: Если CSPRNG недоступен или неисправен

    Example:
        >>> diagnose_rng()  # Ничего не вернёт, если всё OK
    """
    try:
        b = os.urandom(8)
        if not isinstance(b, bytes) or len(b) != 8:
            raise RuntimeError("CSPRNG returned invalid data")
    except Exception as e:
        _LOGGER.error(f"CSPRNG health check failed: {e}")
        raise RuntimeError(f"OS-level CSPRNG unavailable: {e}")


def ensure_entropy_available() -> None:
    """
    Проверка доступности entropy при первом использовании.

    Выполняется один раз при первом вызове generate_random_bytes().
    Thread-safe с использованием double-check locking.

    Raises:
        RuntimeError: Если CSPRNG недоступен
    """
    global _ENTROPY_CHECKED

    # Fast path без блокировки
    if _ENTROPY_CHECKED:
        return

    # Slow path с блокировкой (double-check locking)
    with _ENTROPY_LOCK:
        if _ENTROPY_CHECKED:  # Проверка внутри блокировки
            return

        diagnose_rng()
        _ENTROPY_CHECKED = True
        _LOGGER.info("Entropy source verified and available")


def _audit_entropy(data: bytes) -> None:
    """
    Аудит качества случайных данных на подозрительные паттерны.

    Проверяет:
    - Слишком много нулевых байтов (> 50%)
    - Слишком мало уникальных значений (< 25% от длины)

    Args:
        data: Байты для проверки

    Raises:
        ValueError: Если обнаружена низкая энтропия или подозрительные паттерны

    Note:
        Это эвристическая проверка, не заменяющая полноценный NIST тест.
    """
    if not data:
        raise ValueError("Empty entropy stream")

    zero_count = data.count(0)
    unique_count = len(set(data))

    # Эвристики для обнаружения плохой энтропии
    if zero_count > len(data) // 2:
        _LOGGER.error(
            f"Low entropy detected: too many zeros ({zero_count}/{len(data)})"
        )
        raise ValueError("Suspicious randomness: excessive zero bytes")

    if unique_count < len(data) // 4:
        _LOGGER.error(
            f"Low entropy detected: too few unique bytes ({unique_count}/{len(data)})"
        )
        raise ValueError("Suspicious randomness: low byte diversity")

    _LOGGER.debug(
        f"Entropy audit OK: unique={unique_count}, zeros={zero_count}, total={len(data)}"
    )


def entropy_mixer(length: int) -> bytes:
    """
    XOR-миксер двух независимых источников случайности (thread-safe).

    Комбинирует secrets.token_bytes() и os.urandom() через XOR для
    дополнительной защиты. Проверяет качество результата через _audit_entropy().

    Args:
        length: Количество байтов для генерации

    Returns:
        Смешанные случайные байты

    Raises:
        RuntimeError: Если CSPRNG недоступен
        ValueError: Если обнаружена низкая энтропия

    Example:
        >>> data = entropy_mixer(32)
        >>> len(data)
        32
    """
    diagnose_rng()

    # Два независимых источника
    a = secrets.token_bytes(length)
    b = os.urandom(length)

    # XOR-миксинг
    mixed = bytes(x ^ y for x, y in zip(a, b))

    # Проверка качества КАЖДОЙ генерации
    _audit_entropy(mixed)

    return mixed


# ============================================================================
# Random Generation
# ============================================================================


def generate_random_bytes(length: int, use_mixer: bool = True) -> bytes:
    """
    Генерация криптостойких случайных байтов (thread-safe).

    Проверка entropy:
    - При первом вызове: проверка доступности CSPRNG
    - При каждой генерации: аудит качества через _audit_entropy()

    Args:
        length: Количество байтов для генерации
        use_mixer: Использовать XOR-миксер (рекомендуется, по умолчанию True)

    Returns:
        Криптостойкие случайные байты

    Raises:
        ValueError: Если length <= 0 или > MAX_RANDOM_BYTES
        RuntimeError: Если CSPRNG недоступен

    Example:
        >>> key = generate_random_bytes(32)
        >>> len(key)
        32
        >>>
        >>> # Без миксера (быстрее, но менее параноидально)
        >>> nonce = generate_random_bytes(12, use_mixer=False)
    """
    if length <= 0:
        raise ValueError(f"Length must be positive, got {length}")

    if length > MAX_RANDOM_BYTES:
        raise ValueError(f"Requested {length} bytes exceeds maximum {MAX_RANDOM_BYTES}")

    # Проверка доступности entropy (один раз при первом вызове)
    ensure_entropy_available()

    if use_mixer:
        # XOR-миксер с проверкой качества
        return entropy_mixer(length)
    else:
        # Прямой вызов secrets (быстрее, без аудита)
        return secrets.token_bytes(length)


def generate_random_bytes_batched(
    total_length: int, batch_size: int = 1024 * 1024
) -> bytes:
    """
    Генерация больших объёмов случайных данных пакетами (thread-safe).

    Используется для генерации больших ключей или случайных файлов
    без блокировки на долгое время.

    Args:
        total_length: Общее количество байтов
        batch_size: Размер одного пакета (по умолчанию 1 MB)

    Returns:
        Случайные байты

    Raises:
        ValueError: Если total_length > MAX_RANDOM_BYTES

    Example:
        >>> # Генерация 5 MB случайных данных
        >>> data = generate_random_bytes_batched(5 * 1024 * 1024)
        >>> len(data)
        5242880
    """
    if total_length > MAX_RANDOM_BYTES:
        raise ValueError(
            f"Total length {total_length} exceeds maximum {MAX_RANDOM_BYTES}"
        )

    ensure_entropy_available()

    result = bytearray()
    remaining = total_length

    while remaining > 0:
        chunk_size = min(batch_size, remaining)
        result.extend(entropy_mixer(chunk_size))
        remaining -= chunk_size

    return bytes(result)


def generate_salt(length: int = 16) -> bytes:
    """
    Генерация криптостойкой соли для KDF (thread-safe).

    Args:
        length: Длина соли в байтах (рекомендуется 8-64)

    Returns:
        Случайная соль

    Raises:
        ValueError: Если длина вне рекомендуемого диапазона

    Example:
        >>> salt = generate_salt(16)
        >>> len(salt)
        16
    """
    if not (8 <= length <= 64):
        raise ValueError(f"Salt length should be 8..64 bytes, got {length}")

    return generate_random_bytes(length, use_mixer=True)


def generate_token_hex(nbytes: int = 32) -> str:
    """
    Генерация случайного hex-токена (thread-safe).

    Args:
        nbytes: Количество байтов (результат будет в 2 раза длиннее в hex)

    Returns:
        Hex-строка

    Example:
        >>> token = generate_token_hex(16)
        >>> len(token)
        32
    """
    return secrets.token_hex(nbytes)


# ============================================================================
# Encoding/Decoding
# ============================================================================


def encode_base64(data: bytes) -> str:
    """
    URL-safe Base64 кодирование (без padding).

    Args:
        data: Байты для кодирования

    Returns:
        Base64 строка (URL-safe, без '=')

    Example:
        >>> encode_base64(b"hello world")
        'aGVsbG8gd29ybGQ'
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_base64(data: str) -> bytes:
    """
    URL-safe Base64 декодирование.

    Args:
        data: Base64 строка

    Returns:
        Декодированные байты

    Raises:
        ValueError: Если строка не валидный Base64

    Example:
        >>> decode_base64('aGVsbG8gd29ybGQ')
        b'hello world'
    """
    # Восстановление padding
    padding = 4 - (len(data) % 4)
    if padding and padding != 4:
        data += "=" * padding

    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Invalid Base64 string: {e}")


def encode_hex(data: bytes) -> str:
    """
    Hex кодирование (lowercase).

    Args:
        data: Байты для кодирования

    Returns:
        Hex-строка (lowercase)

    Example:
        >>> encode_hex(b"\\x00\\xff\\xaa")
        '00ffaa'
    """
    return data.hex()


def decode_hex(data: str) -> bytes:
    """
    Hex декодирование.

    Args:
        data: Hex-строка (case-insensitive)

    Returns:
        Декодированные байты

    Raises:
        ValueError: Если строка не валидный hex

    Example:
        >>> decode_hex('00ffaa')
        b'\\x00\\xff\\xaa'
    """
    try:
        return bytes.fromhex(data)
    except Exception as e:
        raise ValueError(f"Invalid hex string: {e}")


# ============================================================================
# Validation
# ============================================================================


def validate_key_length(key: bytes, expected_length: int, name: str = "key") -> None:
    """
    Валидация длины криптографического ключа.

    Args:
        key: Ключ для проверки
        expected_length: Ожидаемая длина в байтах
        name: Имя ключа для сообщения об ошибке

    Raises:
        ValueError: Если длина не совпадает

    Example:
        >>> key = b"\\x00" * 32
        >>> validate_key_length(key, 32, "AES-256 key")
    """
    if len(key) != expected_length:
        raise ValueError(
            f"Invalid {name} length: {len(key)} bytes, expected {expected_length}"
        )


def validate_nonce_length(nonce: bytes, expected_length: int) -> None:
    """
    Валидация длины nonce/IV.

    Args:
        nonce: Nonce для проверки
        expected_length: Ожидаемая длина в байтах

    Raises:
        ValueError: Если длина не совпадает

    Example:
        >>> nonce = b"\\x00" * 12
        >>> validate_nonce_length(nonce, 12)
    """
    if len(nonce) != expected_length:
        raise ValueError(
            f"Invalid nonce length: {len(nonce)} bytes, expected {expected_length}"
        )


def validate_non_empty(data: bytes, name: str = "data") -> None:
    """
    Валидация что данные не пусты.

    Args:
        data: Данные для проверки
        name: Имя данных для сообщения об ошибке

    Raises:
        ValueError: Если данные пусты

    Example:
        >>> validate_non_empty(b"hello", "message")
        >>> validate_non_empty(b"", "message")  # Вызовет ValueError
    """
    if not data:
        raise ValueError(f"{name} cannot be empty")


# ============================================================================
# File System Utilities
# ============================================================================


def set_secure_file_permissions(filepath: str) -> None:
    """
    Установка строгих прав доступа к файлу (0600 — только владелец, thread-safe).

    Устанавливает права read/write только для владельца файла.
    На Windows может не работать — используется только на Unix-подобных ОС.

    Args:
        filepath: Путь к файлу

    Example:
        >>> set_secure_file_permissions("secret_key.bin")
    """
    import stat

    try:
        # 0600: read/write только для владельца
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
        _LOGGER.debug(f"Set secure permissions (0600) for {filepath}")
    except Exception as e:
        _LOGGER.warning(f"Could not set strict permissions for {filepath}: {e}")


# ============================================================================
# Export
# ============================================================================

__all__ = [
    # Memory management
    "zero_memory",
    "secure_bytes",
    "secure_compare",
    # Entropy management
    "diagnose_rng",
    "ensure_entropy_available",
    "entropy_mixer",
    # Random generation
    "generate_random_bytes",
    "generate_random_bytes_batched",
    "generate_salt",
    "generate_token_hex",
    # Encoding/Decoding
    "encode_base64",
    "decode_base64",
    "encode_hex",
    "decode_hex",
    # Validation
    "validate_key_length",
    "validate_nonce_length",
    "validate_non_empty",
    # File system
    "set_secure_file_permissions",
    # Constants
    "MAX_RANDOM_BYTES",
]
