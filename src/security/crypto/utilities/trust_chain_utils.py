"""
Утилиты Trust Chain для работы с цепочками доверия.

Вспомогательные функции для сериализации, валидации и отображения
цепочек доверия. Поддерживает thread-safe операции с файлами через
advisory locking (fcntl на Unix).

Example:
    >>> from src.security.crypto.utilities.trust_chain_utils import (
    ...     serialize_trust_chain,
    ...     deserialize_trust_chain,
    ...     validate_key_format,
    ...     generate_key_id,
    ...     format_chain_for_display,
    ...     get_trusted_keys_file_path,
    ...     TrustChainFileManager,
    ...     TRUSTED_KEYS_FILENAME,
    ... )
    >>> chain = [TrustChainLink(...)]
    >>> json_data = serialize_trust_chain(chain)
    >>> display = format_chain_for_display(chain)

Version: 1.0
Date: April 11, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from src.security.crypto.core.exceptions import (
    InvalidParameterError,
)
from src.services.protocols.template_security import TrustChainLink, TrustStatus

__all__: list[str] = [
    # Constants
    "TRUSTED_KEYS_FILENAME",
    "ED25519_KEY_SIZE",
    "ML_DSA_65_KEY_SIZE",
    "MIN_KEY_SIZE",
    "MAX_KEY_SIZE",
    "TRUSTED_KEYS_FILE",
    "KEY_ID_PREFIX",
    # Exceptions
    "TrustChainError",
    "TrustChainFileError",
    "TrustChainValidationError",
    "TrustChainSerializationError",
    # Functions
    "serialize_trust_chain",
    "deserialize_trust_chain",
    "validate_key_format",
    "generate_key_id",
    "format_chain_for_display",
    "get_trusted_keys_file_path",
    "file_lock",
    "save_trusted_keys",
    "load_trusted_keys",
    "validate_chain",
    "find_chain_root",
    "get_chain_depth",
    # Classes
    "TrustChainFileManager",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-11"

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

TRUSTED_KEYS_FILENAME: str = "trusted_keys.json"
"""Имя файла для хранения доверенных ключей."""

ED25519_KEY_SIZE: int = 32
"""Размер публичного ключа Ed25519 в байтах."""

ML_DSA_65_KEY_SIZE: int = 1952
"""Размер публичного ключа ML-DSA-65 в байтах."""

TRUSTED_KEYS_FILE: Path = Path.home() / ".fxtextprocessor" / "keystore" / "trusted_keys.json"
"""Путь к файлу доверенных ключей.

Расширяется до абсолютного пути через Path.home().
Файл хранит сериализованную цепочку доверия в формате JSON.
"""

KEY_ID_PREFIX: str = "key-"
"""Префикс для идентификаторов ключей.

Все сгенерированные ID ключей начинаются с этого префикса.
"""

MIN_KEY_SIZE: int = 32
"""Минимальный размер публичного ключа в байтах.

Минимальный размер соответствует Ed25519 (32 байта).
"""

MAX_KEY_SIZE: int = 2592
"""Максимальный размер публичного ключа в байтах.

Максимальный размер соответствует ML-DSA-87 (2592 байта).
"""

# Ожидаемые размеры ключей по алгоритмам
_EXPECTED_KEY_SIZES: dict[str, int] = {
    "ed25519": 32,
    "ed448": 57,
    "ml-dsa-44": 1312,
    "ml-dsa-65": 1952,
    "ml-dsa-87": 2592,
    "rsa-2048": 256,
    "rsa-4096": 512,
}


# =============================================================================
# EXCEPTIONS
# =============================================================================


class TrustChainError(Exception):
    """Базовое исключение для ошибок цепочки доверия."""

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Инициализация исключения.

        Args:
            message: Сообщение об ошибке.
            details: Дополнительные детали для отладки.
        """
        super().__init__(message)
        self.details = details or {}

    def __str__(self) -> str:
        """Строковое представление с деталями."""
        msg: str = str(self.args[0])
        if self.details:
            return f"{msg} (details: {self.details})"
        return msg


class TrustChainFileError(TrustChainError):
    """Ошибка при работе с файлами цепочки доверия."""

    pass


class TrustChainValidationError(TrustChainError):
    """Ошибка валидации цепочки доверия."""

    pass


class TrustChainSerializationError(TrustChainError):
    """Ошибка сериализации/десериализации цепочки доверия."""

    pass


# =============================================================================
# THREAD-SAFE FILE OPERATIONS
# =============================================================================


@contextmanager
def file_lock(
    filepath: Path,
    exclusive: bool = True,
) -> Iterator[int]:
    """Контекстный менеджер для advisory file locking.

    Использует fcntl.flock на Unix-системах для обеспечения
    thread-safe и process-safe доступа к файлам.

    Args:
        filepath: Путь к файлу для блокировки.
        exclusive: True для эксклюзивной блокировки (запись),
            False для shared (чтение).

    Yields:
        Файловый дескриптор.

    Raises:
        TrustChainFileError: Если не удалось открыть или заблокировать файл.

    Example:
        >>> with file_lock(Path("/tmp/data.json"), exclusive=True) as fd:
        ...     os.write(fd, b"data")
    """
    # Deferred import for platform compatibility
    import fcntl

    fd = -1
    try:
        # Создаём директории если нужно
        filepath.parent.mkdir(parents=True, exist_ok=True)

        # Открываем файл
        flags = os.O_RDWR | os.O_CREAT
        fd = os.open(str(filepath), flags, 0o600)

        # Выбираем тип блокировки
        lock_type = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH

        # Блокируем файл
        fcntl.flock(fd, lock_type)
        logger.debug(f"File locked: {filepath} (exclusive={exclusive})")

        yield fd

    except OSError as e:
        raise TrustChainFileError(
            f"Failed to lock file: {filepath}",
            details={"error": str(e), "errno": e.errno},
        ) from e
    finally:
        if fd >= 0:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
                logger.debug(f"File unlocked: {filepath}")
            except OSError:
                pass  # Игнорируем ошибки при cleanup


# =============================================================================
# SERIALIZATION
# =============================================================================


def serialize_trust_chain(links: list[TrustChainLink]) -> str:
    """Сериализует цепочку доверия в JSON строку.

    Преобразует список TrustChainLink в JSON-строку с
    сохранением всех полей и метаданных.

    Args:
        links: Список звеньев цепочки доверия.

    Returns:
        JSON строка с сериализованной цепочкой.

    Raises:
        InvalidParameterError: Если links некорректен.

    Example:
        >>> links = [TrustChainLink(key_id="key-1", ...)]
        >>> json_str = serialize_trust_chain(links)
        >>> isinstance(json_str, str)
        True
    """
    if not isinstance(links, list):
        raise InvalidParameterError(
            parameter_name="links",
            reason="Expected list of TrustChainLink",
        )

    # Validate all items are TrustChainLink
    for link in links:
        if not isinstance(link, TrustChainLink):
            raise InvalidParameterError(
                parameter_name="links",
                reason=f"Expected TrustChainLink, got {type(link).__name__}",
            )

    # Serialize to list of dicts (JSON array format)
    data = [link.to_dict() for link in links]
    return json.dumps(data, ensure_ascii=False, indent=2)


def deserialize_trust_chain(data: str | bytes) -> list[TrustChainLink]:
    """Десериализует цепочку доверия из JSON строки.

    Преобразует JSON-строку обратно в список TrustChainLink.

    Args:
        data: JSON строка или байты с сериализованной цепочкой.

    Returns:
        Список связей цепочки доверия.

    Raises:
        TrustChainSerializationError: Если данные некорректны.
        InvalidParameterError: Если JSON невалиден.

    Example:
        >>> json_str = '[{"key_id": "key-1", ...}]'
        >>> chain = deserialize_trust_chain(json_str)
        >>> len(chain) >= 0
        True
    """
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")

        parsed = json.loads(data)

        if not isinstance(parsed, list):
            raise TrustChainSerializationError(
                "Expected JSON array",
                details={"got_type": type(parsed).__name__},
            )

        chain: list[TrustChainLink] = []
        for i, item in enumerate(parsed):
            if not isinstance(item, dict):
                raise TrustChainSerializationError(
                    f"Failed to parse TrustChainLink at index {i}",
                    details={"got_type": type(item).__name__},
                )
            try:
                link = TrustChainLink.from_dict(item)
                chain.append(link)
            except (KeyError, ValueError, TypeError) as e:
                raise TrustChainSerializationError(
                    f"Failed to parse TrustChainLink at index {i}",
                    details={"error": str(e)},
                ) from e

        return chain

    except json.JSONDecodeError as e:
        raise InvalidParameterError(
            parameter_name="data",
            reason=f"Invalid JSON: {e}",
        ) from e


# =============================================================================
# KEY VALIDATION
# =============================================================================


def validate_key_format(key: bytes, algorithm: str = "ed25519") -> bool:
    """Проверяет формат публичного ключа для указанного алгоритма.

    Валидирует размер ключа в соответствии с алгоритмом.
    Поддерживает Ed25519, Ed448, ML-DSA, RSA.

    Args:
        key: Публичный ключ в бинарном формате.
        algorithm: Название алгоритма (case-insensitive).

    Returns:
        True если формат ключа валиден для указанного алгоритма.

    Raises:
        InvalidParameterError: Если key пустой.

    Example:
        >>> validate_key_format(b"\\x00" * 32, "ed25519")
        True
        >>> validate_key_format(b"short", "ed25519")
        False
    """
    if not isinstance(key, bytes):
        raise InvalidParameterError(
            parameter_name="key",
            reason="Expected bytes",
        )

    if not key:
        raise InvalidParameterError(
            parameter_name="key",
            reason="Public key is empty",
        )

    algo_lower = algorithm.lower().replace("_", "-")

    # Проверяем глобальные ограничения размера
    if len(key) < MIN_KEY_SIZE:
        logger.warning(f"Key too short: {len(key)} bytes (min: {MIN_KEY_SIZE})")
        return False

    if len(key) > MAX_KEY_SIZE:
        logger.warning(f"Key too long: {len(key)} bytes (max: {MAX_KEY_SIZE})")
        return False

    # Проверяем размер для конкретного алгоритма
    expected_size = _EXPECTED_KEY_SIZES.get(algo_lower)
    if expected_size is not None:
        if len(key) != expected_size:
            logger.warning(
                f"Key size mismatch for {algorithm}: expected {expected_size}, got {len(key)}"
            )
            return False

    return True


# =============================================================================
# KEY ID GENERATION
# =============================================================================


def generate_key_id(prefix: str = KEY_ID_PREFIX) -> str:
    """Генерирует уникальный идентификатор ключа.

    Использует первые 12 символов UUID4 с заданным префиксом.

    Args:
        prefix: Префикс для ID (по умолчанию KEY_ID_PREFIX).

    Returns:
        Уникальный идентификатор ключа (prefix + 12 hex chars).

    Example:
        >>> key_id = generate_key_id()
        >>> key_id.startswith(KEY_ID_PREFIX)
        True
        >>> len(key_id) == len(KEY_ID_PREFIX) + 12
        True
    """
    unique_part = uuid.uuid4().hex[:12]  # 12 hex chars = 48 bits
    return f"{prefix}{unique_part}"


# =============================================================================
# DISPLAY FORMATTING
# =============================================================================


def format_chain_for_display(
    links: list[TrustChainLink],
    statuses: dict[str, TrustStatus] | None = None,
) -> str:
    """Форматирует цепочку доверия для отображения в UI.

    Создаёт человекочитаемое представление с эмодзи-индикаторами
    статуса и визуальными отступами для иерархии.

    Args:
        links: Список связей цепочки доверия (от подписанта к корневому).
        statuses: Опциональный словарь статусов ключей.

    Returns:
        Отформатированная строка для отображения.

    Example:
        >>> chain = [TrustChainLink(key_id="key-1", ...)]
        >>> display = format_chain_for_display(chain)
        >>> "🔗" in display or "✅" in display or "🟢" in display
        True
    """
    if statuses is None:
        statuses = {}

    if not links:
        return "Цепочка доверия пуста"

    lines: list[str] = []
    depth = 0

    for link in links:
        indent = "  " * depth
        status = statuses.get(link.key_id, TrustStatus.TRUSTED)
        emoji = status.emoji()
        algo = link.algorithm

        if link.is_root():
            lines.append(f"{indent}{emoji} Root Key ({algo}): {link.key_id} (корневой)")
        else:
            lines.append(f"{indent}{emoji} Key ({algo}): {link.key_id}")

        if link.parent_key_id:
            lines.append(f"{indent}  └─ подписан: {link.parent_key_id}")

        depth += 1

    return "\n".join(lines)


# =============================================================================
# FILE PATH UTILITIES
# =============================================================================


def get_trusted_keys_file_path() -> Path:
    """Возвращает путь к файлу доверенных ключей.

    Returns:
        Путь к файлу в директории конфигурации приложения.

    Example:
        >>> path = get_trusted_keys_file_path()
        >>> path.name == TRUSTED_KEYS_FILENAME
        True
    """
    # Используем стандартную директорию конфигурации пользователя
    config_dir = Path.home() / ".fx-text-processor" / "security"
    return config_dir / TRUSTED_KEYS_FILENAME


# =============================================================================
# THREAD-SAFE FILE MANAGER
# =============================================================================


class TrustChainFileManager:
    """Thread-safe менеджер файловых операций для цепочек доверия.

    Обеспечивает безопасную работу с файлами доверенных ключей
    в многопоточной среде.

    Example:
        >>> manager = TrustChainFileManager()
        >>> manager.save_trusted_keys([TrustChainLink(...)])
        >>> loaded = manager.load_trusted_keys()
    """

    def __init__(self, file_path: Path | None = None) -> None:
        """Инициализация менеджера.

        Args:
            file_path: Путь к файлу ключей. Если None, используется
                путь по умолчанию.
        """
        self._file_path = file_path or get_trusted_keys_file_path()
        self._lock = threading.RLock()

    def save_trusted_keys(self, links: list[TrustChainLink]) -> None:
        """Сохраняет цепочку доверия в файл.

        Args:
            links: Список звеньев для сохранения.

        Thread-safe: метод защищен RLock.
        """
        with self._lock:
            # Создаем директорию если не существует
            self._file_path.parent.mkdir(parents=True, exist_ok=True)

            data = serialize_trust_chain(links)
            self._file_path.write_text(data, encoding="utf-8")

    def load_trusted_keys(self) -> list[TrustChainLink]:
        """Загружает цепочку доверия из файла.

        Returns:
            Список звеньев цепочки доверия.

        Raises:
            TrustChainError: Если файл не существует или поврежден.

        Thread-safe: метод защищен RLock.
        """
        with self._lock:
            if not self._file_path.exists():
                return []

            data = self._file_path.read_text(encoding="utf-8")
            return deserialize_trust_chain(data)

    def file_exists(self) -> bool:
        """Проверяет существование файла ключей.

        Returns:
            True если файл существует.
        """
        with self._lock:
            return self._file_path.exists()

    def get_file_path(self) -> Path:
        """Возвращает путь к файлу ключей.

        Returns:
            Путь к файлу.
        """
        return self._file_path


# =============================================================================
# COMPATIBILITY FUNCTIONS
# =============================================================================


def save_trusted_keys(
    chain: list[TrustChainLink],
    filepath: Path = TRUSTED_KEYS_FILE,
) -> None:
    """Сохраняет цепочку доверия в файл (thread-safe).

    Использует advisory file locking для обеспечения
    thread-safe и process-safe записи.

    Args:
        chain: Список связей для сохранения.
        filepath: Путь к файлу (по умолчанию TRUSTED_KEYS_FILE).

    Raises:
        TrustChainFileError: Если не удалось записать файл.

    Example:
        >>> save_trusted_keys(chain, Path("/tmp/keys.json"))
    """
    json_data = serialize_trust_chain(chain)

    try:
        with file_lock(filepath, exclusive=True) as fd:
            # Очищаем файл и записываем новые данные
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, json_data.encode("utf-8"))
            os.fsync(fd)
        logger.info(f"Saved {len(chain)} keys to {filepath}")
    except OSError as e:
        raise TrustChainFileError(
            f"Failed to save trusted keys: {e}",
            details={"filepath": str(filepath)},
        ) from e


def load_trusted_keys(
    filepath: Path = TRUSTED_KEYS_FILE,
) -> list[TrustChainLink]:
    """Загружает цепочку доверия из файла (thread-safe).

    Использует advisory file locking для обеспечения
    thread-safe и process-safe чтения.

    Args:
        filepath: Путь к файлу (по умолчанию TRUSTED_KEYS_FILE).

    Returns:
        Список связей цепочки доверия. Пустой список если файл не существует.

    Raises:
        TrustChainFileError: Если не удалось прочитать или распарсить файл.

    Example:
        >>> chain = load_trusted_keys(Path("/tmp/keys.json"))
    """
    if not filepath.exists():
        return []

    try:
        with file_lock(filepath, exclusive=False) as fd:
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 10_000_000)  # Max 10MB

        if not data:
            return []

        return deserialize_trust_chain(data.decode("utf-8"))
    except OSError as e:
        raise TrustChainFileError(
            f"Failed to load trusted keys: {e}",
            details={"filepath": str(filepath)},
        ) from e


# =============================================================================
# CHAIN VALIDATION
# =============================================================================


def validate_chain(chain: list[TrustChainLink]) -> tuple[bool, list[str]]:
    """Валидирует целостность цепочки доверия.

    Проверяет:
    - Корректность порядка (parent_id должен соответствовать следующему key_id)
    - Отсутствие просроченных ключей
    - Наличие ровно одного корневого ключа

    Args:
        chain: Список связей цепочки доверия.

    Returns:
        Кортеж (is_valid, list_of_errors).

    Example:
        >>> valid, errors = validate_chain(chain)
        >>> if not valid:
        ...     print("Ошибки:", errors)
    """
    errors: list[str] = []

    if not chain:
        return True, []  # Пустая цепочка валидна

    # Проверяем количество корневых ключей
    root_keys = [link for link in chain if link.is_root()]
    if len(root_keys) != 1:
        errors.append(f"Expected 1 root key, found {len(root_keys)}")

    # Проверяем порядок и parent-child связи
    key_ids = {link.key_id for link in chain}
    for i, link in enumerate(chain):
        # Проверяем срок действия
        if link.is_expired():
            errors.append(f"Key {link.key_id} (index {i}) is expired")

        # Проверяем формат ключа
        if not validate_key_format(link.public_key, link.algorithm):
            errors.append(f"Key {link.key_id} has invalid format")

        # Проверяем parent ссылку
        if link.parent_key_id is not None:
            if link.parent_key_id not in key_ids:
                errors.append(f"Key {link.key_id} references unknown parent: {link.parent_key_id}")
            # Проверяем что parent идёт после текущего в списке
            parent_found = False
            for j in range(i + 1, len(chain)):
                if chain[j].key_id == link.parent_key_id:
                    parent_found = True
                    break
            if not parent_found:
                errors.append(
                    f"Key {link.key_id} parent {link.parent_key_id} not found "
                    "in subsequent chain links"
                )

    return len(errors) == 0, errors


def find_chain_root(chain: list[TrustChainLink]) -> TrustChainLink | None:
    """Находит корневой ключ в цепочке.

    Args:
        chain: Список связей цепочки доверия.

    Returns:
        Корневой TrustChainLink или None если не найден.

    Example:
        >>> root = find_chain_root(chain)
        >>> if root:
        ...     print(f"Root: {root.key_id}")
    """
    for link in chain:
        if link.is_root():
            return link
    return None


def get_chain_depth(chain: list[TrustChainLink]) -> int:
    """Возвращает глубину цепочки.

    Args:
        chain: Список связей цепочки доверия.

    Returns:
        Глубина цепочки (0 для пустой).

    Example:
        >>> depth = get_chain_depth(chain)
        >>> depth >= 0
        True
    """
    return len(chain)
