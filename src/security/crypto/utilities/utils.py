"""
Базовые криптографические утилиты.

Генерация ключей и солей, управление nonce, безопасная работа с памятью
и оптимизация для дискет. Реализует NonceManagerProtocol и
SecureMemoryProtocol из core/protocols.py.

Example:
    >>> from src.security.crypto.utilities.utils import generate_key, NonceManager
    >>> key = generate_key(32)
    >>> len(key)
    32
    >>> manager = NonceManager()
    >>> nonce = manager.generate_nonce(12)
    >>> manager.track_nonce("key_1", nonce)

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import logging
import os
import secrets
import zlib
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Generator, List, Optional, Set

from src.security.crypto.core.exceptions import (
    CryptoError,
    InvalidNonceError,
    InvalidParameterError,
    ValidationError,
)

__all__: list[str] = [
    "generate_key",
    "generate_salt",
    "constant_time_compare",
    "NonceManager",
    "SecureMemory",
    "FloppyOptimizer",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"

logger = logging.getLogger(__name__)


# ==============================================================================
# BASIC UTILITIES
# ==============================================================================


def generate_key(size: int) -> bytes:
    """
    Генерация криптографически стойкого ключа.

    Использует secrets.token_bytes() (CSPRNG) для генерации.

    Args:
        size: Размер ключа в байтах (16, 32, 64 и т.д.).

    Returns:
        Случайный ключ заданного размера.

    Raises:
        InvalidParameterError: Если size <= 0.

    Example:
        >>> key = generate_key(32)
        >>> len(key)
        32
    """
    if size <= 0:
        raise InvalidParameterError(
            parameter_name="size",
            reason="Размер ключа должен быть положительным",
            value=str(size),
        )
    return secrets.token_bytes(size)


def generate_salt(size: int = 32) -> bytes:
    """
    Генерация криптографически стойкой соли.

    Args:
        size: Размер соли в байтах (по умолчанию 32).

    Returns:
        Случайная соль заданного размера.

    Raises:
        InvalidParameterError: Если size <= 0.

    Example:
        >>> salt = generate_salt()
        >>> len(salt)
        32
    """
    if size <= 0:
        raise InvalidParameterError(
            parameter_name="size",
            reason="Размер соли должен быть положительным",
            value=str(size),
        )
    return secrets.token_bytes(size)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Сравнение в постоянном времени (timing-safe).

    Защита от timing attacks при проверке MAC/authentication tags.

    Args:
        a: Первая последовательность байт.
        b: Вторая последовательность байт.

    Returns:
        True если a == b, False иначе.

    Example:
        >>> constant_time_compare(b"tag1", b"tag1")
        True
        >>> constant_time_compare(b"tag1", b"tag2")
        False
    """
    return secrets.compare_digest(a, b)


# ==============================================================================
# NONCE MANAGER
# ==============================================================================


class NonceManager:
    """
    Управление nonce/IV для предотвращения повторного использования.

    Реализует NonceManagerProtocol из core/protocols.py.
    Thread-safe: все операции защищены RLock.

    КРИТИЧНО: Повторное использование nonce с тем же ключом в AEAD
    режимах (GCM, CCM) = ПОЛНЫЙ ВЗЛОМ шифрования.

    Example:
        >>> manager = NonceManager()
        >>> nonce = manager.generate_nonce(12)
        >>> manager.track_nonce("key_1", nonce)
    """

    def __init__(self) -> None:
        """Инициализация менеджера nonce."""
        self._used_nonces: Dict[str, Set[bytes]] = {}
        self._lock = RLock()

    def generate_nonce(self, size: int) -> bytes:
        """
        Генерация криптографически стойкого nonce.

        Args:
            size: Размер nonce в байтах (обычно 12 для GCM, 24 для XChaCha20).

        Returns:
            Случайный nonce заданного размера.

        Raises:
            InvalidParameterError: Если size <= 0.
        """
        if size <= 0:
            raise InvalidParameterError(
                parameter_name="size",
                reason="Размер nonce должен быть положительным",
                value=str(size),
            )
        return secrets.token_bytes(size)

    def track_nonce(self, key_id: str, nonce: bytes) -> None:
        """
        Отслеживание использованных nonce для ключа.

        Регистрирует nonce как использованный. Если nonce уже использовался
        с данным key_id, выбрасывается InvalidNonceError.

        Args:
            key_id: Идентификатор ключа.
            nonce: Nonce для отслеживания.

        Raises:
            InvalidNonceError: Если nonce уже использовался с этим ключом.
        """
        with self._lock:
            if key_id not in self._used_nonces:
                self._used_nonces[key_id] = set()

            if nonce in self._used_nonces[key_id]:
                raise InvalidNonceError(
                    f"Nonce already used with key '{key_id}'",
                    expected_size=len(nonce),
                    actual_size=len(nonce),
                    algorithm=f"key:{key_id}",
                )

            self._used_nonces[key_id].add(nonce)
            logger.debug(
                "Nonce tracked for key '%s' (%d total)",
                key_id,
                len(self._used_nonces[key_id]),
            )

    def clear(self, key_id: Optional[str] = None) -> None:
        """
        Очистка отслеживаемых nonce.

        Args:
            key_id: Если указан, очищает nonce только для этого ключа.
                   Если None, очищает все.
        """
        with self._lock:
            if key_id is not None:
                self._used_nonces.pop(key_id, None)
            else:
                self._used_nonces.clear()

    def get_nonce_count(self, key_id: str) -> int:
        """
        Количество использованных nonce для ключа.

        Args:
            key_id: Идентификатор ключа.

        Returns:
            Количество отслеживаемых nonce.
        """
        with self._lock:
            return len(self._used_nonces.get(key_id, set()))


# ==============================================================================
# SECURE MEMORY
# ==============================================================================


class SecureMemory:
    """
    Безопасная работа с чувствительными данными в памяти.

    Реализует SecureMemoryProtocol из core/protocols.py.
    Обеспечивает обнуление памяти и constant-time сравнение.

    Example:
        >>> mem = SecureMemory()
        >>> key = bytearray(os.urandom(32))
        >>> mem.secure_zero(key)
        >>> key == bytearray(32)
        True
    """

    def secure_zero(self, data: bytearray) -> None:
        """
        Гарантированное обнуление памяти.

        Перезаписывает содержимое bytearray случайными данными,
        затем нулями — для предотвращения извлечения из дампов.

        Args:
            data: Байтовый массив для обнуления (bytearray, НЕ bytes!).

        Raises:
            TypeError: Если data не является bytearray.
        """
        if not isinstance(data, bytearray):
            raise TypeError(
                f"secure_zero requires bytearray, got {type(data).__name__}"
            )
        length = len(data)
        # Перезапись случайными данными
        for i in range(length):
            data[i] = secrets.randbelow(256)
        # Перезапись нулями
        for i in range(length):
            data[i] = 0

    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Сравнение в постоянном времени.

        Args:
            a: Первая последовательность байт.
            b: Вторая последовательность байт.

        Returns:
            True если a == b, False иначе.
        """
        return secrets.compare_digest(a, b)

    @contextmanager
    def secure_context(self, key: bytes) -> Generator[bytearray, None, None]:
        """
        Context manager для безопасной работы с ключом.

        Создаёт bytearray копию ключа, предоставляет её в блоке with,
        и обнуляет при выходе.

        Args:
            key: Ключ для безопасного использования.

        Yields:
            bytearray копия ключа.

        Example:
            >>> mem = SecureMemory()
            >>> with mem.secure_context(b"secret") as key:
            ...     # использовать key
            ...     pass
            >>> # key обнулён
        """
        key_copy = bytearray(key)
        try:
            yield key_copy
        finally:
            self.secure_zero(key_copy)


# ==============================================================================
# FLOPPY OPTIMIZER
# ==============================================================================


class FloppyOptimizer:
    """
    Оптимизация криптографических операций для дискет.

    Валидация размеров файлов, сжатие хранилища, управление бэкапами
    и рекомендации по алгоритмам для ограниченных носителей.

    Example:
        >>> from src.security.crypto.utilities.config import CryptoConfig
        >>> optimizer = FloppyOptimizer(CryptoConfig.floppy_aggressive())
        >>> optimizer.validate_file_size(1000)
        True
    """

    # Рекомендуемые алгоритмы по категориям для floppy
    _RECOMMENDED: Dict[str, List[str]] = {
        "symmetric": ["aes-256-gcm", "chacha20-poly1305", "aes-128-gcm"],
        "signing": ["ed25519"],
        "hash": ["sha-256", "blake2s"],
        "kdf": ["argon2id", "scrypt"],
        "key_exchange": ["x25519"],
    }

    def __init__(self, config: Optional[Any] = None) -> None:
        """
        Инициализация оптимизатора.

        Args:
            config: Экземпляр CryptoConfig. Если None, используется default.
        """
        if config is None:
            from src.security.crypto.utilities.config import CryptoConfig
            config = CryptoConfig.default()
        self._config = config

    def validate_file_size(self, size: int) -> bool:
        """
        Проверка, вмещается ли файл в ограничения floppy.

        Args:
            size: Размер файла в байтах.

        Returns:
            True если размер допустим.
        """
        return size <= self._config.max_storage_size

    def estimate_storage_size(self, directory: Path) -> int:
        """
        Оценка суммарного размера файлов в директории.

        Args:
            directory: Путь к директории.

        Returns:
            Суммарный размер в байтах.

        Raises:
            ValidationError: Если директория не существует.
        """
        if not directory.exists():
            raise ValidationError(
                f"Директория не существует: {directory}"
            )
        total = 0
        for item in directory.rglob("*"):
            if item.is_file():
                total += item.stat().st_size
        return total

    def compress_keystore(self, data: bytes) -> bytes:
        """
        Сжатие данных хранилища ключей (zlib).

        Args:
            data: Данные для сжатия.

        Returns:
            Сжатые данные.
        """
        return zlib.compress(data, level=9)

    def decompress_keystore(self, data: bytes) -> bytes:
        """
        Декомпрессия данных хранилища ключей.

        Args:
            data: Сжатые данные.

        Returns:
            Исходные данные.

        Raises:
            CryptoError: Если данные не являются валидным zlib.
        """
        try:
            return zlib.decompress(data)
        except zlib.error as e:
            raise CryptoError(f"Ошибка декомпрессии: {e}") from e

    def cleanup_old_backups(self, directory: Path) -> int:
        """
        Удаление старых бэкапов, оставляя max_backup_count последних.

        Args:
            directory: Директория с бэкапами.

        Returns:
            Количество удалённых файлов.
        """
        if not directory.exists():
            return 0

        backups = sorted(
            [f for f in directory.iterdir() if f.is_file() and f.suffix == ".bak"],
            key=lambda f: f.stat().st_mtime,
        )

        max_count = self._config.max_backup_count
        to_remove = backups[:-max_count] if len(backups) > max_count else []
        for backup in to_remove:
            backup.unlink()
            logger.info("Удалён старый бэкап: %s", backup.name)

        return len(to_remove)

    def get_recommended_algorithms(self, category: str) -> List[str]:
        """
        Рекомендуемые алгоритмы для floppy по категории.

        Args:
            category: Категория ('symmetric', 'signing', 'hash', 'kdf',
                      'key_exchange').

        Returns:
            Список рекомендуемых алгоритмов.
        """
        return list(self._RECOMMENDED.get(category, []))
