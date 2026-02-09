"""
Централизованный реестр криптографических алгоритмов.

Thread-safe Singleton реестр всех 46 алгоритмов из CRYPTO_MASTER_PLAN v2.3.
Обеспечивает:
- Регистрацию алгоритмов с валидацией Protocol
- Фабричные методы для создания экземпляров
- Thread-safe доступ (RLock)
- Query API для поиска алгоритмов
- Статистику по реестру

Example:
    >>> from src.security.crypto.core.registry import AlgorithmRegistry
    >>> registry = AlgorithmRegistry.get_instance()
    >>> cipher = registry.create("AES-256-GCM")
    >>> key = cipher.generate_key()

Thread Safety:
    Все публичные методы thread-safe благодаря RLock.
    Можно безопасно вызывать из разных потоков.

Version: 1.0
Date: February 9, 2026
Priority: 🔴 CRITICAL (Phase 1, Day 2-3)
"""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import logging

from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# CUSTOM EXCEPTIONS
# ==============================================================================


class RegistryError(Exception):
    """Базовая ошибка реестра криптографических алгоритмов."""

    pass


class ProtocolError(RegistryError):
    """Ошибка валидации соответствия Protocol интерфейсу."""

    pass


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class RegistryEntry:
    """
    Запись в реестре криптографического алгоритма.

    Attributes:
        name: Имя алгоритма
        factory: Фабричная функция для создания экземпляра
        metadata: Метаданные алгоритма

    Example:
        >>> entry = RegistryEntry(
        ...     name="AES-256-GCM",
        ...     factory=AES256GCM,
        ...     metadata=AES256GCM.metadata,
        ... )
    """

    name: str
    factory: Callable[[], Any]
    metadata: AlgorithmMetadata


@dataclass(frozen=True)
class RegistryStatistics:
    """
    Статистика зарегистрированных алгоритмов.

    Attributes:
        total: Общее количество алгоритмов
        by_category: Количество по категориям
        by_security_level: Количество по уровням безопасности
        by_floppy_friendly: Количество по floppy-friendly уровням
        post_quantum_count: Количество постквантовых
        aead_count: Количество AEAD симметричных
        safe_for_production_count: Количество безопасных для production

    Example:
        >>> stats = registry.get_statistics()
        >>> print(f"Total: {stats.total}")
        Total: 46
        >>> print(f"Symmetric: {stats.by_category[AlgorithmCategory.SYMMETRIC_CIPHER]}")
        Symmetric: 10
    """

    total: int
    by_category: Dict[AlgorithmCategory, int]
    by_security_level: Dict[SecurityLevel, int]
    by_floppy_friendly: Dict[FloppyFriendly, int]
    post_quantum_count: int
    aead_count: int
    safe_for_production_count: int

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация в словарь.

        Returns:
            Словарь со статистикой

        Example:
            >>> stats.to_dict()
            {'total': 46, 'by_category': {...}, ...}
        """
        return {
            "total": self.total,
            "by_category": {
                cat.value: count for cat, count in self.by_category.items()
            },
            "by_security_level": {
                level.value: count for level, count in self.by_security_level.items()
            },
            "by_floppy_friendly": {
                level.value: count for level, count in self.by_floppy_friendly.items()
            },
            "post_quantum_count": self.post_quantum_count,
            "aead_count": self.aead_count,
            "safe_for_production_count": self.safe_for_production_count,
        }


# ==============================================================================
# MAIN CLASS: ALGORITHM REGISTRY
# ==============================================================================


class AlgorithmRegistry:
    """
    Thread-safe реестр криптографических алгоритмов.

    Singleton класс для централизованного управления всеми 46 алгоритмами
    из CRYPTO_MASTER_PLAN v2.3. Обеспечивает:
    - Регистрацию алгоритмов с валидацией Protocol
    - Фабричные методы для создания экземпляров
    - Thread-safe доступ
    - Query API для поиска алгоритмов

    Attributes:
        _instance: Singleton instance
        _lock: RLock для thread-safety
        _registry: Словарь {algorithm_name -> RegistryEntry}
        _initialized: Флаг инициализации

    Example:
        >>> registry = AlgorithmRegistry.get_instance()
        >>> registry.register_algorithm(
        ...     name="AES-256-GCM",
        ...     factory=lambda: AES256GCM(),
        ...     metadata=AES256GCM.metadata,
        ... )
        >>> cipher = registry.create("AES-256-GCM")
        >>> isinstance(cipher, SymmetricCipherProtocol)
        True

    Thread Safety:
        Все публичные методы thread-safe благодаря RLock.
        Можно безопасно вызывать из разных потоков.
    """

    # Singleton instance (class-level)
    _instance: Optional[AlgorithmRegistry] = None
    _lock: threading.RLock = threading.RLock()

    def __init__(self) -> None:
        """
        Приватный конструктор (используйте get_instance()).

        Raises:
            RuntimeError: Если попытка создать второй экземпляр
        """
        if AlgorithmRegistry._instance is not None:
            raise RuntimeError(
                "AlgorithmRegistry is a singleton. "
                "Use AlgorithmRegistry.get_instance()"
            )

        # Реестр: {algorithm_name -> RegistryEntry}
        self._registry: Dict[str, RegistryEntry] = {}

        # Флаг инициализации
        self._initialized: bool = False

        logger.info("AlgorithmRegistry initialized")

    @classmethod
    def get_instance(cls) -> AlgorithmRegistry:
        """
        Получить singleton instance реестра.

        Returns:
            Единственный экземпляр AlgorithmRegistry

        Thread Safety:
            Thread-safe double-checked locking

        Example:
            >>> registry = AlgorithmRegistry.get_instance()
            >>> registry2 = AlgorithmRegistry.get_instance()
            >>> registry is registry2
            True
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """
        Сбросить singleton (только для тестов).

        WARNING:
            Используйте только в unit-тестах!
            В production коде вызов этого метода может
            нарушить работу системы.
        """
        with cls._lock:
            cls._instance = None
            logger.warning("AlgorithmRegistry instance reset (testing only!)")

    def register_algorithm(
        self,
        name: str,
        factory: Callable[[], Any],
        metadata: AlgorithmMetadata,
        *,
        validate: bool = True,
    ) -> None:
        """
        Зарегистрировать алгоритм в реестре.

        Args:
            name: Уникальное имя алгоритма (например, "AES-256-GCM")
            factory: Фабричная функция для создания экземпляра
            metadata: Метаданные алгоритма
            validate: Валидировать соответствие Protocol (по умолчанию True)

        Raises:
            ValueError: Если алгоритм уже зарегистрирован или имя пустое
            TypeError: Если factory не callable или метаданные некорректны
            ProtocolError: Если экземпляр не соответствует Protocol (validate=True)

        Example:
            >>> from src.security.crypto.algorithms.symmetric import AES256GCM
            >>> registry.register_algorithm(
            ...     name="AES-256-GCM",
            ...     factory=AES256GCM,
            ...     metadata=AES256GCM.metadata,
            ... )

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            # Валидация имени
            if not name or not name.strip():
                raise ValueError("Имя алгоритма не может быть пустым")

            # Проверка дубликатов
            if name in self._registry:
                raise ValueError(
                    f"Алгоритм '{name}' уже зарегистрирован. "
                    f"Используйте update_algorithm() для обновления."
                )

            # Валидация factory
            if not callable(factory):
                raise TypeError(
                    f"factory должна быть callable, получено {type(factory).__name__}"
                )

            # Валидация metadata
            if not isinstance(metadata, AlgorithmMetadata):
                raise TypeError(
                    f"metadata должна быть AlgorithmMetadata, "
                    f"получено {type(metadata).__name__}"
                )

            # Валидация соответствия Protocol
            if validate:
                self._validate_protocol(factory, metadata)

            # Регистрация
            entry = RegistryEntry(
                name=name,
                factory=factory,
                metadata=metadata,
            )
            self._registry[name] = entry

            logger.info(
                f"Registered algorithm: {name} "
                f"(category={metadata.category.value}, "
                f"security={metadata.security_level.value})"
            )

    def _validate_protocol(
        self,
        factory: Callable[[], Any],
        metadata: AlgorithmMetadata,
    ) -> None:
        """
        Валидация соответствия экземпляра Protocol интерфейсу.

        Args:
            factory: Фабрика для создания тестового экземпляра
            metadata: Метаданные с protocol_class

        Raises:
            ProtocolError: Если экземпляр не соответствует Protocol
        """
        try:
            # Создать тестовый экземпляр
            instance = factory()

            # Проверка isinstance с @runtime_checkable Protocol
            if not isinstance(instance, metadata.protocol_class):
                raise ProtocolError(
                    f"Экземпляр {type(instance).__name__} не реализует "
                    f"{metadata.protocol_class.__name__}"
                )

            logger.debug(
                f"Protocol validation passed: {metadata.name} -> "
                f"{metadata.protocol_class.__name__}"
            )

        except ProtocolError:
            raise
        except Exception as e:
            raise ProtocolError(
                f"Не удалось валидировать Protocol для {metadata.name}: {e}"
            ) from e

    def create(self, name: str) -> Any:
        """
        Создать экземпляр алгоритма по имени.

        Args:
            name: Имя алгоритма (например, "AES-256-GCM")

        Returns:
            Новый экземпляр алгоритма

        Raises:
            KeyError: Если алгоритм не найден в реестре
            RuntimeError: Если не удалось создать экземпляр

        Example:
            >>> cipher = registry.create("AES-256-GCM")
            >>> key = cipher.generate_key()
            >>> ciphertext, tag = cipher.encrypt(key, b"data")

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            if name not in self._registry:
                available = ", ".join(sorted(self._registry.keys())[:5])
                raise KeyError(
                    f"Алгоритм '{name}' не найден в реестре. "
                    f"Доступные (первые 5): {available}..."
                )

            entry = self._registry[name]

            try:
                instance = entry.factory()
                logger.debug(f"Created instance of {name}")
                return instance

            except Exception as e:
                logger.error(f"Failed to create instance of {name}: {e}", exc_info=True)
                raise RuntimeError(f"Не удалось создать экземпляр {name}: {e}") from e

    def get_metadata(self, name: str) -> AlgorithmMetadata:
        """
        Получить метаданные алгоритма.

        Args:
            name: Имя алгоритма

        Returns:
            Метаданные алгоритма

        Raises:
            KeyError: Если алгоритм не найден

        Example:
            >>> meta = registry.get_metadata("AES-256-GCM")
            >>> meta.security_level
            <SecurityLevel.STANDARD: 'standard'>
        """
        with self._lock:
            if name not in self._registry:
                raise KeyError(f"Алгоритм '{name}' не найден в реестре")
            return self._registry[name].metadata

    def list_algorithms(self) -> List[str]:
        """
        Получить список всех зарегистрированных алгоритмов.

        Returns:
            Список имён алгоритмов (sorted)

        Example:
            >>> registry.list_algorithms()
            ['AES-128-GCM', 'AES-256-GCM', 'ChaCha20-Poly1305', ...]
        """
        with self._lock:
            return sorted(self._registry.keys())

    def list_by_category(self, category: AlgorithmCategory) -> List[str]:
        """
        Получить список алгоритмов по категории.

        Args:
            category: Категория алгоритмов

        Returns:
            Список имён алгоритмов в категории (sorted)

        Example:
            >>> registry.list_by_category(AlgorithmCategory.SYMMETRIC_CIPHER)
            ['AES-128-GCM', 'AES-256-CTR', 'AES-256-GCM', ...]
        """
        with self._lock:
            return sorted(
                [
                    name
                    for name, entry in self._registry.items()
                    if entry.metadata.category == category
                ]
            )

    def list_by_security_level(self, security_level: SecurityLevel) -> List[str]:
        """
        Получить список алгоритмов по уровню безопасности.

        Args:
            security_level: Уровень безопасности

        Returns:
            Список имён алгоритмов (sorted)

        Example:
            >>> # Только постквантовые алгоритмы
            >>> registry.list_by_security_level(SecurityLevel.QUANTUM_RESISTANT)
            ['Dilithium2', 'Dilithium3', 'Kyber768', ...]
        """
        with self._lock:
            return sorted(
                [
                    name
                    for name, entry in self._registry.items()
                    if entry.metadata.security_level == security_level
                ]
            )

    def list_safe_for_production(self) -> List[str]:
        """
        Получить список алгоритмов безопасных для production.

        Returns:
            Список имён алгоритмов (status=STABLE, не BROKEN/LEGACY)

        Example:
            >>> safe_algos = registry.list_safe_for_production()
            >>> 'DES' in safe_algos
            False  # DES - BROKEN
            >>> 'AES-256-GCM' in safe_algos
            True   # STABLE + STANDARD
        """
        with self._lock:
            return sorted(
                [
                    name
                    for name, entry in self._registry.items()
                    if entry.metadata.is_safe_for_production()
                ]
            )

    def list_floppy_friendly(self, level: FloppyFriendly) -> List[str]:
        """
        Получить список алгоритмов по floppy-friendly уровню.

        Args:
            level: Уровень floppy-friendly (EXCELLENT/ACCEPTABLE/POOR)

        Returns:
            Список имён алгоритмов (sorted)

        Example:
            >>> # Алгоритмы отлично подходящие для дискет
            >>> registry.list_floppy_friendly(FloppyFriendly.EXCELLENT)
            ['AES-128-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', ...]
        """
        with self._lock:
            return sorted(
                [
                    name
                    for name, entry in self._registry.items()
                    if entry.metadata.floppy_friendly == level
                ]
            )

    def search(
        self,
        *,
        category: Optional[AlgorithmCategory] = None,
        security_level: Optional[SecurityLevel] = None,
        floppy_friendly: Optional[FloppyFriendly] = None,
        status: Optional[ImplementationStatus] = None,
        is_post_quantum: Optional[bool] = None,
        is_aead: Optional[bool] = None,
    ) -> List[str]:
        """
        Поиск алгоритмов по множественным критериям.

        Args:
            category: Фильтр по категории
            security_level: Фильтр по уровню безопасности
            floppy_friendly: Фильтр по floppy-friendly
            status: Фильтр по статусу реализации
            is_post_quantum: Только постквантовые (True/False)
            is_aead: Только AEAD симметричные шифры (True/False)

        Returns:
            Список имён алгоритмов, соответствующих всем фильтрам

        Example:
            >>> # Постквантовые подписи
            >>> registry.search(
            ...     category=AlgorithmCategory.SIGNATURE,
            ...     is_post_quantum=True,
            ... )
            ['Dilithium2', 'Dilithium3', 'Dilithium5', 'FALCON-512', ...]

            >>> # AEAD шифры с отличным floppy-friendly
            >>> registry.search(
            ...     category=AlgorithmCategory.SYMMETRIC_CIPHER,
            ...     is_aead=True,
            ...     floppy_friendly=FloppyFriendly.EXCELLENT,
            ... )
            ['AES-128-GCM', 'AES-256-GCM', 'ChaCha20-Poly1305', ...]
        """
        with self._lock:
            results = []

            for name, entry in self._registry.items():
                meta = entry.metadata

                # Проверка всех фильтров (AND логика)
                if category is not None and meta.category != category:
                    continue

                if security_level is not None and meta.security_level != security_level:
                    continue

                if (
                    floppy_friendly is not None
                    and meta.floppy_friendly != floppy_friendly
                ):
                    continue

                if status is not None and meta.status != status:
                    continue

                if (
                    is_post_quantum is not None
                    and meta.is_post_quantum != is_post_quantum
                ):
                    continue

                if is_aead is not None and meta.is_aead != is_aead:
                    continue

                results.append(name)

            return sorted(results)

    def get_statistics(self) -> RegistryStatistics:
        """
        Получить статистику по зарегистрированным алгоритмам.

        Returns:
            RegistryStatistics с подсчётами

        Example:
            >>> stats = registry.get_statistics()
            >>> stats.total
            46
            >>> stats.by_category[AlgorithmCategory.SYMMETRIC_CIPHER]
            10
            >>> stats.floppy_excellent_count
            30
        """
        with self._lock:
            return self._calculate_statistics()

    def _calculate_statistics(self) -> RegistryStatistics:
        """Внутренний метод для подсчёта статистики."""
        total = len(self._registry)

        categories = Counter(
            entry.metadata.category for entry in self._registry.values()
        )

        security_levels = Counter(
            entry.metadata.security_level for entry in self._registry.values()
        )

        floppy_levels = Counter(
            entry.metadata.floppy_friendly for entry in self._registry.values()
        )

        post_quantum_count = sum(
            1 for entry in self._registry.values() if entry.metadata.is_post_quantum
        )

        aead_count = sum(
            1 for entry in self._registry.values() if entry.metadata.is_aead
        )

        safe_for_production = sum(
            1
            for entry in self._registry.values()
            if entry.metadata.is_safe_for_production()
        )

        return RegistryStatistics(
            total=total,
            by_category=dict(categories),
            by_security_level=dict(security_levels),
            by_floppy_friendly=dict(floppy_levels),
            post_quantum_count=post_quantum_count,
            aead_count=aead_count,
            safe_for_production_count=safe_for_production,
        )

    def is_registered(self, name: str) -> bool:
        """
        Проверка, зарегистрирован ли алгоритм.

        Args:
            name: Имя алгоритма

        Returns:
            True если зарегистрирован, False иначе

        Example:
            >>> registry.is_registered("AES-256-GCM")
            True
            >>> registry.is_registered("Unknown-Algo")
            False
        """
        with self._lock:
            return name in self._registry

    def unregister(self, name: str) -> None:
        """
        Удалить алгоритм из реестра.

        WARNING:
            Используйте с осторожностью! Удаление алгоритма
            может нарушить работу зависимого кода.

        Args:
            name: Имя алгоритма

        Raises:
            KeyError: Если алгоритм не найден
        """
        with self._lock:
            if name not in self._registry:
                raise KeyError(f"Алгоритм '{name}' не найден в реестре")

            del self._registry[name]
            logger.warning(f"Unregistered algorithm: {name}")


# ==============================================================================
# REGISTRATION FUNCTION
# ==============================================================================


def register_all_algorithms() -> None:
    """
    Зарегистрировать все 46 алгоритмов из CRYPTO_MASTER_PLAN v2.3.

    Вызывается автоматически при первом импорте модуля или
    вручную для переинициализации реестра.

    Example:
        >>> from src.security.crypto.core.registry import register_all_algorithms
        >>> register_all_algorithms()
        >>> registry = AlgorithmRegistry.get_instance()
        >>> len(registry.list_algorithms())
        46

    Note:
        Использует lazy imports для минимизации времени импорта.
        Реальные классы алгоритмов импортируются только при вызове create().

    TODO:
        Заполнить импорты и регистрацию после реализации всех 46 алгоритмов.
        Сейчас это заглушка с комментариями структуры.
    """
    registry = AlgorithmRegistry.get_instance()

    logger.info("Starting registration of all algorithms...")

    # ========== SYMMETRIC CIPHERS (10) ==========
    # TODO: Uncomment when algorithms are implemented
    #
    # from src.security.crypto.algorithms.symmetric import (
    #     AES128GCM,
    #     AES256GCM,
    #     AES256GCMSIV,
    #     ChaCha20Poly1305,
    #     XChaCha20Poly1305,
    #     AES256SIV,
    #     AES256OCB,
    #     AES256CTR,
    #     TripleDES,
    #     DES,
    # )
    # registry.register_algorithm("AES-128-GCM", AES128GCM, AES128GCM.metadata)
    # registry.register_algorithm("AES-256-GCM", AES256GCM, AES256GCM.metadata)
    # ... и т.д.

    # ========== SIGNATURES (17) ==========
    # TODO: Uncomment when algorithms are implemented

    # ========== ASYMMETRIC ENCRYPTION (3) ==========
    # TODO: Uncomment when algorithms are implemented

    # ========== KEY EXCHANGE (8) ==========
    # TODO: Uncomment when algorithms are implemented

    # ========== HASHING (8) ==========
    # TODO: Uncomment when algorithms are implemented

    # ========== KDF (4) ==========
    # TODO: Uncomment when algorithms are implemented

    logger.info(f"Registered {len(registry.list_algorithms())} algorithms")


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__: list[str] = [
    # Main class
    "AlgorithmRegistry",
    # Dataclasses
    "RegistryEntry",
    "RegistryStatistics",
    # Exceptions
    "RegistryError",
    "ProtocolError",
    # Functions
    "register_all_algorithms",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-09"
