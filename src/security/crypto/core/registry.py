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

import logging
import threading
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

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
            "by_category": {cat.value: count for cat, count in self.by_category.items()},
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
                "AlgorithmRegistry is a singleton. Use AlgorithmRegistry.get_instance()"
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
                raise TypeError(f"factory должна быть callable, получено {type(factory).__name__}")

            # Валидация metadata
            if not isinstance(metadata, AlgorithmMetadata):
                raise TypeError(
                    f"metadata должна быть AlgorithmMetadata, получено {type(metadata).__name__}"
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
                f"Protocol validation passed: {metadata.name} -> {metadata.protocol_class.__name__}"
            )

        except ProtocolError:
            raise
        except Exception as e:
            raise ProtocolError(f"Не удалось валидировать Protocol для {metadata.name}: {e}") from e

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
                    f"Алгоритм '{name}' не найден в реестре. Доступные (первые 5): {available}..."
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

    def list_algorithms(self) -> List[AlgorithmMetadata]:
        """
        Получить список метаданных всех зарегистрированных алгоритмов.

        Returns:
            Список AlgorithmMetadata (sorted by name). Spec: List[AlgorithmMetadata].

        Example:
            >>> metas = registry.list_algorithms()
            >>> {m.id for m in metas}
            {'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', ...}
        """
        with self._lock:
            return sorted(
                (entry.metadata for entry in self._registry.values()),
                key=lambda m: m.name,
            )

    def list_algorithm_names(self) -> List[str]:
        """
        Получить список имён всех зарегистрированных алгоритмов.

        Returns:
            Список имён алгоритмов (sorted)
        """
        with self._lock:
            return sorted(self._registry.keys())

    def get_algorithm(self, name: str) -> Any:
        """
        Получить экземпляр алгоритма по имени. Spec: AlgorithmRegistry.get_algorithm().

        Args:
            name: Имя алгоритма

        Returns:
            Экземпляр алгоритма

        Raises:
            KeyError: Если алгоритм не найден

        Example:
            >>> cipher = registry.get_algorithm("aes-256-gcm")
        """
        return self.create(name)

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
            ['Dilithium2', 'Dilithium3', 'ml-kem-768', ...]
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
            results: list[str] = []

            for name, entry in self._registry.items():
                meta = entry.metadata

                # Проверка всех фильтров (AND логика)
                if category is not None and meta.category != category:
                    continue

                if security_level is not None and meta.security_level != security_level:
                    continue

                if floppy_friendly is not None and meta.floppy_friendly != floppy_friendly:
                    continue

                if status is not None and meta.status != status:
                    continue

                if is_post_quantum is not None and meta.is_post_quantum != is_post_quantum:
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

        categories = Counter(entry.metadata.category for entry in self._registry.values())

        security_levels = Counter(
            entry.metadata.security_level for entry in self._registry.values()
        )

        floppy_levels = Counter(entry.metadata.floppy_friendly for entry in self._registry.values())

        post_quantum_count = sum(
            1 for entry in self._registry.values() if entry.metadata.is_post_quantum
        )

        aead_count = sum(1 for entry in self._registry.values() if entry.metadata.is_aead)

        safe_for_production = sum(
            1 for entry in self._registry.values() if entry.metadata.is_safe_for_production()
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
    Зарегистрировать все реализованные алгоритмы из CRYPTO_MASTER_PLAN v2.3.

    Регистрирует только РЕАЛИЗОВАННЫЕ алгоритмы (ленивая загрузка).
    Пропускает алгоритмы если их библиотеки не установлены.

    Метаданные создаются динамически из свойств классов алгоритмов.
    """
    registry = AlgorithmRegistry.get_instance()

    logger.info("🔧 Starting registration of all cryptographic algorithms...")

    # ==========================================================================
    # 1. SYMMETRIC CIPHERS (10)
    # ==========================================================================

    try:
        from src.security.crypto.algorithms.symmetric import (
            ALGORITHMS as SYM_ALGORITHMS,
        )
        from src.security.crypto.algorithms.symmetric import (
            ALL_METADATA as SYM_METADATA,
        )

        # Создаём mapping: algorithm_id -> metadata
        metadata_map = {
            meta.name.lower().replace(" ", "-").replace("_", "-"): meta for meta in SYM_METADATA
        }

        # Регистрируем каждый алгоритм с его метаданными
        registered_count = 0
        for algo_id, algo_class in SYM_ALGORITHMS.items():
            # Найти соответствующую метадату
            meta = metadata_map.get(algo_id)
            if meta is None:
                logger.warning(f"Metadata not found for {algo_id}, skipping")
                continue

            try:
                registry.register_algorithm(
                    name=algo_id,
                    factory=algo_class,
                    metadata=meta,
                    validate=True,
                )
                registered_count += 1
            except Exception as e:
                logger.warning(f"⚠️  Skipping symmetric algorithm {algo_id}: {e}")

        logger.info(
            f"✅ Registered {registered_count}/{len(SYM_ALGORITHMS)} symmetric cipher algorithms"
        )

    except Exception as e:
        logger.error(f"❌ Failed to import symmetric algorithms: {e}")

    # ==========================================================================
    # 2. ASYMMETRIC ENCRYPTION (3) - RSA-OAEP
    # ==========================================================================

    try:
        from src.security.crypto.algorithms.asymmetric import (
            ASYMMETRIC_ALGORITHMS,
        )

        # Регистрируем каждый алгоритм
        # ASYMMETRIC_ALGORITHMS = {"RSA-OAEP-2048": (class, metadata), ...}
        registered_count = 0
        for algo_name, (algo_class, metadata) in ASYMMETRIC_ALGORITHMS.items():
            try:
                registry.register_algorithm(
                    name=algo_name,
                    factory=algo_class,
                    metadata=metadata,
                    validate=True,
                )
                registered_count += 1
            except Exception as e:
                logger.warning(f"⚠️  Skipping asymmetric algorithm {algo_name}: {e}")

        logger.info(
            f"✅ Registered {registered_count}/{len(ASYMMETRIC_ALGORITHMS)}"
            " asymmetric encryption algorithms"
        )

    except Exception as e:
        logger.error(f"❌ Failed to import asymmetric encryption algorithms: {e}")

    # ==========================================================================
    # 3. SIGNATURES (20) - EdDSA, ECDSA, RSA-PSS, ML-DSA, Falcon, SLH-DSA
    # ==========================================================================

    try:
        # Импорт автоматически зарегистрирует все 20 алгоритмов через _register_all_signatures()
        from src.security.crypto.algorithms import signing as _signing  # noqa: F401

        _ = _signing  # ensure import is used
        # Проверяем, что зарегистрировались
        sig_algos = [
            "Ed25519",
            "Ed448",
            "ECDSA-P256",
            "ECDSA-P384",
            "ECDSA-P521",
            "ECDSA-secp256k1",
            "RSA-PSS-2048",
            "RSA-PSS-3072",
            "RSA-PSS-4096",
            "RSA-PKCS1v15",
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "Falcon-512",
            "Falcon-1024",
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-256s",
            "Dilithium2",
            "SPHINCS+-128s",
        ]

        registered_sigs = [name for name in sig_algos if registry.is_registered(name)]

        logger.info(
            f"✅ Registered {len(registered_sigs)}/20 signature algorithms (auto-registration)"
        )

        if len(registered_sigs) < len(sig_algos):
            missing = set(sig_algos) - set(registered_sigs)
            logger.warning(f"⚠️  Missing signature algorithms: {missing}")

    except ImportError as e:
        logger.error(f"❌ Failed to import signing algorithms: {e}")

    # ==========================================================================
    # 4. KEY EXCHANGE (8) - X25519, X448, ECDH-P256/384/521, ML-KEM-512/768/1024
    # ==========================================================================

    try:
        from src.security.crypto.algorithms.key_exchange import (
            KEY_EXCHANGE_ALGORITHMS,
        )

        # Регистрируем каждый алгоритм
        # KEY_EXCHANGE_ALGORITHMS = {"x25519": (class, metadata), ...}
        registered_count = 0
        for algo_id, (algo_class, metadata) in KEY_EXCHANGE_ALGORITHMS.items():
            try:
                registry.register_algorithm(
                    name=algo_id, factory=algo_class, metadata=metadata, validate=True
                )
                registered_count += 1
            except Exception as e:
                logger.warning(f"⚠️  Skipping key exchange algorithm {algo_id}: {e}")

        logger.info(
            f"✅ Registered {registered_count}/{len(KEY_EXCHANGE_ALGORITHMS)}"
            " key exchange algorithms"
        )

    except Exception as e:
        logger.error(f"❌ Failed to import key exchange algorithms: {e}")

    # ==========================================================================
    # 5. KEY DERIVATION FUNCTIONS (4) - Argon2id, PBKDF2, Scrypt, HKDF
    # ==========================================================================

    try:
        from src.security.crypto.algorithms.kdf import ALGORITHMS as KDF_ALGORITHMS

        # Регистрируем каждый KDF алгоритм
        # KDF_ALGORITHMS = {"argon2id": (class, metadata), ...}
        registered_count = 0
        for algo_id, (algo_class, metadata) in KDF_ALGORITHMS.items():
            try:
                registry.register_algorithm(
                    name=algo_id, factory=algo_class, metadata=metadata, validate=True
                )
                registered_count += 1
            except Exception as e:
                logger.warning(f"⚠️  Skipping KDF algorithm {algo_id}: {e}")

        logger.info(f"✅ Registered {registered_count}/{len(KDF_ALGORITHMS)} KDF algorithms")

    except Exception as e:
        logger.error(f"❌ Failed to import KDF algorithms: {e}")

    # ==========================================================================
    # 6. HASHING (8) - SHA-256/384/512, SHA3-256/512, BLAKE2b/s, BLAKE3
    # ==========================================================================

    try:
        from src.security.crypto.algorithms.hashing import HASH_ALGORITHMS

        # Регистрируем каждый hash алгоритм
        # HASH_ALGORITHMS = {"sha256": (class, metadata), ...}
        registered_count = 0
        for hash_id, (hash_class, hash_metadata) in HASH_ALGORITHMS.items():
            try:
                registry.register_algorithm(
                    name=hash_id, factory=hash_class, metadata=hash_metadata, validate=True
                )
                registered_count += 1
            except Exception as e:
                logger.warning(f"⚠️  Skipping hash algorithm {hash_id}: {e}")

        logger.info(f"✅ Registered {registered_count}/{len(HASH_ALGORITHMS)} hashing algorithms")

    except Exception as e:
        logger.error(f"❌ Failed to import hashing algorithms: {e}")


# Автоматическая регистрация при импорте модуля
try:
    register_all_algorithms()
except Exception as e:
    logger.error(f"Auto-registration failed: {e}. Call register_all_algorithms() manually.")


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__ = [
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
