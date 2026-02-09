"""
Метаданные криптографических алгоритмов.

Единая система метаданных для всех 46 алгоритмов CRYPTO_MASTER_PLAN v2.3.
Определяет:
- AlgorithmMetadata — immutable dataclass с характеристиками алгоритма
- Enums для категоризации (AlgorithmCategory, SecurityLevel,
FloppyFriendly, ImplementationStatus)
- Factory functions для создания метаданных
- Validation правила

Example:
    >>> from src.security.crypto.core.metadata import AlgorithmMetadata, SecurityLevel
    >>> metadata = AlgorithmMetadata(
    ...     name="AES-256-GCM",
    ...     category=AlgorithmCategory.SYMMETRIC_CIPHER,
    ...     library="cryptography",
    ...     security_level=SecurityLevel.STANDARD,
    ... )
    >>> metadata.is_safe_for_production()
    True

Version: 1.0
Date: February 9, 2026
Priority: 🔴 CRITICAL (Phase 1, Day 1-2)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Type

from src.security.crypto.core.protocols import (
    AsymmetricEncryptionProtocol,
    HashProtocol,
    KDFProtocol,
    KeyExchangeProtocol,
    NonceManagerProtocol,
    SecureMemoryProtocol,
    SignatureProtocol,
    SymmetricCipherProtocol,
)


# ==============================================================================
# ENUM: ALGORITHM CATEGORY
# ==============================================================================


class AlgorithmCategory(str, Enum):
    """
    Категория криптографического алгоритма.

    Используется для группировки 46 алгоритмов CRYPTO_MASTER_PLAN v2.3.
    Наследует str для корректной JSON сериализации.

    Распределение алгоритмов:
        - SYMMETRIC_CIPHER: 10 алгоритмов
        - SIGNATURE: 17 алгоритмов
        - ASYMMETRIC_ENCRYPTION: 3 алгоритма
        - KEY_EXCHANGE: 8 алгоритмов
        - HASH: 8 алгоритмов
        - KDF: 4 алгоритма

    Example:
        >>> category = AlgorithmCategory.SYMMETRIC_CIPHER
        >>> category.value
        'symmetric_cipher'
        >>> category.label()
        'Симметричное шифрование'
    """

    SYMMETRIC_CIPHER = "symmetric_cipher"
    SIGNATURE = "signature"
    ASYMMETRIC_ENCRYPTION = "asymmetric_encryption"
    KEY_EXCHANGE = "key_exchange"
    HASH = "hash"
    KDF = "kdf"

    def label(self) -> str:
        """
        Человекочитаемое название категории на русском.

        Returns:
            Локализованное название

        Example:
            >>> AlgorithmCategory.SYMMETRIC_CIPHER.label()
            'Симметричное шифрование'
        """
        labels = {
            AlgorithmCategory.SYMMETRIC_CIPHER: "Симметричное шифрование",
            AlgorithmCategory.SIGNATURE: "Цифровая подпись",
            AlgorithmCategory.ASYMMETRIC_ENCRYPTION: "Асимметричное шифрование",
            AlgorithmCategory.KEY_EXCHANGE: "Обмен ключами",
            AlgorithmCategory.HASH: "Хеширование",
            AlgorithmCategory.KDF: "Вывод ключей",
        }
        return labels[self]

    @classmethod
    def from_str(cls, value: str) -> AlgorithmCategory:
        """
        Парсинг из строки (case-insensitive).

        Args:
            value: Строковое представление ("symmetric_cipher" или "SYMMETRIC_CIPHER")

        Returns:
            Соответствующий AlgorithmCategory

        Raises:
            ValueError: Некорректное значение

        Example:
            >>> AlgorithmCategory.from_str("symmetric_cipher")
            <AlgorithmCategory.SYMMETRIC_CIPHER: 'symmetric_cipher'>
        """
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(
                f"Неизвестная категория алгоритма: {value}. "
                f"Допустимые значения: {[c.value for c in cls]}"
            ) from None


# ==============================================================================
# ENUM: SECURITY LEVEL
# ==============================================================================


class SecurityLevel(str, Enum):
    """
    Уровень безопасности криптографического алгоритма.

    Градация:
        - BROKEN: Сломан, не использовать (DES)
        - LEGACY: Устаревший, только для совместимости (3DES, RSA-PKCS1v15)
        - STANDARD: Стандартный, рекомендуется (AES-256-GCM, Ed25519)
        - HIGH: Повышенный (AES-256-GCM-SIV, RSA-4096)
        - QUANTUM_RESISTANT: Постквантовый (Dilithium, Kyber, FALCON)

    Example:
        >>> level = SecurityLevel.QUANTUM_RESISTANT
        >>> level.is_safe_for_new_systems()
        True
        >>> SecurityLevel.BROKEN.is_safe_for_new_systems()
        False
    """

    BROKEN = "broken"  # ⛔ DES
    LEGACY = "legacy"  # ⚠️  3DES, RSA-PKCS1v15
    STANDARD = "standard"  # ✅ AES-256-GCM, Ed25519, X25519
    HIGH = "high"  # 🏆 AES-256-GCM-SIV, RSA-4096
    QUANTUM_RESISTANT = "quantum"  # 🛡️  Dilithium, Kyber, FALCON

    def label(self) -> str:
        """
        Человекочитаемое название на русском.

        Returns:
            Локализованное название
        """
        labels = {
            SecurityLevel.BROKEN: "Сломан",
            SecurityLevel.LEGACY: "Устаревший",
            SecurityLevel.STANDARD: "Стандартный",
            SecurityLevel.HIGH: "Повышенный",
            SecurityLevel.QUANTUM_RESISTANT: "Постквантовый",
        }
        return labels[self]

    def is_safe_for_new_systems(self) -> bool:
        """
        Безопасен ли для новых систем.

        Returns:
            False для BROKEN и LEGACY, True для остальных

        Note:
            LEGACY алгоритмы допустимы только для совместимости с legacy systems
        """
        return self not in (SecurityLevel.BROKEN, SecurityLevel.LEGACY)

    def emoji(self) -> str:
        """
        Эмоджи-индикатор для визуализации.

        Returns:
            Эмоджи: ⛔/⚠️/✅/🏆/🛡️
        """
        emojis = {
            SecurityLevel.BROKEN: "⛔",
            SecurityLevel.LEGACY: "⚠️",
            SecurityLevel.STANDARD: "✅",
            SecurityLevel.HIGH: "🏆",
            SecurityLevel.QUANTUM_RESISTANT: "🛡️",
        }
        return emojis[self]


# ==============================================================================
# ENUM: FLOPPY FRIENDLY
# ==============================================================================


class FloppyFriendly(int, Enum):
    """
    Оценка пригодности алгоритма для дискет 3.5" (1.44 MB).

    Критерий: размер ключей + подписей/ciphertext overhead.

    Градация:
        - EXCELLENT (1): < 100 bytes (Ed25519, ChaCha20, X25519)
        - ACCEPTABLE (2): 100-1000 bytes (RSA-2048, AES-256)
        - POOR (3): > 1000 bytes (Dilithium, FALCON, Kyber, RSA-4096)

    Статистика (из CRYPTO_v2.3):
        - 💚 EXCELLENT: 30 алгоритмов (65%)
        - 💛 ACCEPTABLE: 7 алгоритмов (15%)
        - ❌ POOR: 9 алгоритмов (20%)

    Example:
        >>> floppy = FloppyFriendly.EXCELLENT
        >>> floppy.value
        1
        >>> floppy.label()
        'Отлично'
        >>> floppy < FloppyFriendly.POOR
        True
    """

    EXCELLENT = 1  # 💚 < 100 bytes
    ACCEPTABLE = 2  # 💛 100-1000 bytes
    POOR = 3  # ❌ > 1000 bytes

    def label(self) -> str:
        """
        Человекочитаемое название на русском.

        Returns:
            Локализованное название
        """
        labels = {
            FloppyFriendly.EXCELLENT: "Отлично",
            FloppyFriendly.ACCEPTABLE: "Приемлемо",
            FloppyFriendly.POOR: "Плохо",
        }
        return labels[self]

    def emoji(self) -> str:
        """
        Эмоджи-индикатор.

        Returns:
            Эмоджи: 💚/💛/❌
        """
        emojis = {
            FloppyFriendly.EXCELLENT: "💚",
            FloppyFriendly.ACCEPTABLE: "💛",
            FloppyFriendly.POOR: "❌",
        }
        return emojis[self]

    @classmethod
    def from_size(cls, size_bytes: int) -> FloppyFriendly:
        """
        Автоматическая оценка по размеру в байтах.

        Args:
            size_bytes: Размер ключа + подписи/ciphertext overhead

        Returns:
            Соответствующий FloppyFriendly уровень

        Example:
            >>> FloppyFriendly.from_size(32)  # Ed25519 key
            <FloppyFriendly.EXCELLENT: 1>
            >>> FloppyFriendly.from_size(2592)  # Dilithium3 signature
            <FloppyFriendly.POOR: 3>
        """
        if size_bytes < 100:
            return cls.EXCELLENT
        elif size_bytes < 1000:
            return cls.ACCEPTABLE
        else:
            return cls.POOR


# ==============================================================================
# ENUM: IMPLEMENTATION STATUS
# ==============================================================================


class ImplementationStatus(str, Enum):
    """
    Статус реализации алгоритма.

    Values:
        - STABLE: Production-ready (большинство алгоритмов)
        - EXPERIMENTAL: Экспериментальный (новые PQC алгоритмы)
        - DEPRECATED: Устаревший, не использовать в новом коде (DES)
    """

    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"

    def label(self) -> str:
        """
        Человекочитаемое название на русском.

        Returns:
            Локализованное название
        """
        labels = {
            ImplementationStatus.STABLE: "Стабильный",
            ImplementationStatus.EXPERIMENTAL: "Экспериментальный",
            ImplementationStatus.DEPRECATED: "Устаревший",
        }
        return labels[self]


# ==============================================================================
# DATACLASS: ALGORITHM METADATA
# ==============================================================================


@dataclass(frozen=True)
class AlgorithmMetadata:
    """
    Метаданные криптографического алгоритма.

    Immutable dataclass содержащий все характеристики алгоритма:
    - Идентификация (имя, категория)
    - Безопасность (security_level)
    - Производительность (floppy_friendly)
    - Техническая информация (библиотека, класс, размеры ключей)
    - Статус реализации

    Attributes:
        name: Уникальное имя алгоритма (например, "AES-256-GCM")
        category: Категория алгоритма
        protocol_class: Protocol класс для проверки соответствия
        library: Python библиотека (cryptography, pycryptodome, liboqs-python, stdlib)
        implementation_class: Полное имя класса
        security_level: Уровень безопасности
        floppy_friendly: Пригодность для дискет
        status: Статус реализации
        key_size: Размер ключа в байтах (для симметричных и хешей)
        signature_size: Размер подписи в байтах (для подписей)
        public_key_size: Размер публичного ключа (для асимметричных)
        private_key_size: Размер приватного ключа
        nonce_size: Размер nonce/IV (для симметричных)
        digest_size: Размер дайджеста (для хешей)
        is_aead: Поддержка AEAD (для симметричных)
        is_post_quantum: Постквантовый алгоритм
        max_plaintext_size: Максимальный размер plaintext (для асимметричных)
        description_ru: Краткое описание на русском
        description_en: Краткое описание на английском
        use_cases: Рекомендуемые сценарии использования
        test_vectors_source: Источник тестовых векторов (NIST, RFC и т.д.)
        extra: Дополнительные параметры (гибкое поле)

    Example:
        >>> metadata = AlgorithmMetadata(
        ...     name="AES-256-GCM",
        ...     category=AlgorithmCategory.SYMMETRIC_CIPHER,
        ...     protocol_class=SymmetricCipherProtocol,
        ...     library="cryptography",
        ...     implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCM",
        ...     security_level=SecurityLevel.STANDARD,
        ...     floppy_friendly=FloppyFriendly.EXCELLENT,
        ...     status=ImplementationStatus.STABLE,
        ...     key_size=32,
        ...     nonce_size=12,
        ...     is_aead=True,
        ...     description_ru="AES-256 в режиме Galois/Counter Mode",
        ... )
        >>> metadata.name
        'AES-256-GCM'
        >>> metadata.is_safe_for_production()
        True
    """

    # Обязательные поля
    name: str
    category: AlgorithmCategory
    protocol_class: Type[object]
    library: str
    implementation_class: str
    security_level: SecurityLevel
    floppy_friendly: FloppyFriendly
    status: ImplementationStatus

    # Опциональные размеры (зависят от категории)
    key_size: Optional[int] = None
    signature_size: Optional[int] = None
    public_key_size: Optional[int] = None
    private_key_size: Optional[int] = None
    nonce_size: Optional[int] = None
    digest_size: Optional[int] = None

    # Флаги
    is_aead: bool = False
    is_post_quantum: bool = False

    # Ограничения
    max_plaintext_size: Optional[int] = None

    # Описания
    description_ru: str = ""
    description_en: str = ""
    use_cases: List[str] = field(default_factory=list)

    # Тестирование
    test_vectors_source: Optional[str] = None

    # Расширяемость
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Валидация метаданных после инициализации.

        Raises:
            ValueError: Некорректные значения полей
            TypeError: Неверные типы
        """
        # Валидация name
        if not self.name or not self.name.strip():
            raise ValueError("name не может быть пустым")

        # Валидация library
        allowed_libraries = {
            "cryptography",
            "pycryptodome",
            "liboqs-python",
            "hashlib",  # stdlib
            "argon2-cffi",
            "blake3-py",
            "secrets",  # stdlib
        }
        if self.library not in allowed_libraries:
            raise ValueError(
                f"Неизвестная библиотека: {self.library}. "
                f"Допустимые: {allowed_libraries}"
            )

        # Валидация категория-специфичных полей
        if self.category == AlgorithmCategory.SYMMETRIC_CIPHER:
            if self.key_size is None or self.nonce_size is None:
                raise ValueError(
                    f"Симметричный шифр {self.name} требует key_size и nonce_size"
                )

        if self.category == AlgorithmCategory.SIGNATURE:
            if self.signature_size is None:
                raise ValueError(f"Алгоритм подписи {self.name} требует signature_size")

        if self.category == AlgorithmCategory.HASH:
            if self.digest_size is None:
                raise ValueError(f"Хеш-функция {self.name} требует digest_size")

        # Валидация размеров (должны быть положительными)
        for size_attr in [
            "key_size",
            "signature_size",
            "nonce_size",
            "digest_size",
            "public_key_size",
            "private_key_size",
        ]:
            size_value = getattr(self, size_attr)
            if size_value is not None and size_value <= 0:
                raise ValueError(f"{size_attr} должен быть > 0, получено {size_value}")

        # Валидация постквантовых алгоритмов
        if (
            self.is_post_quantum
            and self.security_level != SecurityLevel.QUANTUM_RESISTANT
        ):
            raise ValueError(
                f"Постквантовый алгоритм {self.name} должен иметь "
                f"security_level=QUANTUM_RESISTANT"
            )

    def is_safe_for_production(self) -> bool:
        """
        Безопасен ли алгоритм для production использования.

        Returns:
            True если status=STABLE и security_level не BROKEN/LEGACY
        """
        return (
            self.status == ImplementationStatus.STABLE
            and self.security_level.is_safe_for_new_systems()
        )

    def total_overhead_bytes(self) -> int:
        """
        Общий overhead в байтах (для floppy_friendly оценки).

        Сумма размеров ключей + подписей/тегов.

        Returns:
            Суммарный размер в байтах

        Example:
            >>> ed25519_meta.total_overhead_bytes()
            128  # 32 (private) + 32 (public) + 64 (signature)
        """
        total = 0
        if self.key_size:
            total += self.key_size
        if self.signature_size:
            total += self.signature_size
        if self.public_key_size:
            total += self.public_key_size
        if self.private_key_size:
            total += self.private_key_size
        return total

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация в словарь (для JSON/YAML).

        Returns:
            Словарь с примитивными типами

        Example:
            >>> metadata.to_dict()
            {'name': 'AES-256-GCM', 'category': 'symmetric_cipher', ...}
        """
        return {
            "name": self.name,
            "category": self.category.value,
            "library": self.library,
            "implementation_class": self.implementation_class,
            "security_level": self.security_level.value,
            "floppy_friendly": self.floppy_friendly.value,
            "status": self.status.value,
            "key_size": self.key_size,
            "signature_size": self.signature_size,
            "public_key_size": self.public_key_size,
            "private_key_size": self.private_key_size,
            "nonce_size": self.nonce_size,
            "digest_size": self.digest_size,
            "is_aead": self.is_aead,
            "is_post_quantum": self.is_post_quantum,
            "max_plaintext_size": self.max_plaintext_size,
            "description_ru": self.description_ru,
            "description_en": self.description_en,
            "use_cases": self.use_cases,
            "test_vectors_source": self.test_vectors_source,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AlgorithmMetadata:
        """
        Десериализация из словаря.

        Args:
            data: Словарь с метаданными (из to_dict())

        Returns:
            AlgorithmMetadata instance

        Raises:
            ValueError: Некорректные данные

        Note:
            protocol_class должен быть передан отдельно, так как не сериализуется
        """
        # Копировать data, чтобы не изменять оригинал
        data = data.copy()

        # Преобразовать строки обратно в Enum
        data["category"] = AlgorithmCategory.from_str(data["category"])
        data["security_level"] = SecurityLevel[data["security_level"].upper()]
        data["floppy_friendly"] = FloppyFriendly(data["floppy_friendly"])
        data["status"] = ImplementationStatus[data["status"].upper()]

        # protocol_class нужно передать отдельно (placeholder)
        if "protocol_class" not in data:
            data["protocol_class"] = object

        return cls(**data)


# ==============================================================================
# FACTORY FUNCTIONS
# ==============================================================================


def create_symmetric_metadata(
    name: str,
    library: str,
    implementation_class: str,
    key_size: int,
    nonce_size: int,
    *,
    is_aead: bool = True,
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    status: ImplementationStatus = ImplementationStatus.STABLE,
    description_ru: str = "",
    description_en: str = "",
    test_vectors_source: Optional[str] = None,
    use_cases: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> AlgorithmMetadata:
    """
    Factory для создания метаданных симметричного шифра.

    Args:
        name: Имя алгоритма (например, "AES-256-GCM")
        library: Библиотека ("cryptography", "pycryptodome")
        implementation_class: Полное имя класса
        key_size: Размер ключа в байтах
        nonce_size: Размер nonce/IV в байтах
        is_aead: AEAD режим (по умолчанию True)
        security_level: Уровень безопасности
        status: Статус реализации
        description_ru: Описание на русском
        description_en: Описание на английском
        test_vectors_source: Источник тестовых векторов
        use_cases: Рекомендуемые сценарии использования
        extra: Дополнительные параметры

    Returns:
        Сконфигурированный AlgorithmMetadata

    Example:
        >>> aes_meta = create_symmetric_metadata(
        ...     name="AES-256-GCM",
        ...     library="cryptography",
        ...     implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCM",
        ...     key_size=32,
        ...     nonce_size=12,
        ...     description_ru="AES-256 в режиме Galois/Counter Mode",
        ...     test_vectors_source="NIST CAVP",
        ... )
    """
    # Автоопределение floppy_friendly
    overhead = key_size + nonce_size + (16 if is_aead else 0)  # 16 = tag size
    floppy = FloppyFriendly.from_size(overhead)

    return AlgorithmMetadata(
        name=name,
        category=AlgorithmCategory.SYMMETRIC_CIPHER,
        protocol_class=SymmetricCipherProtocol,
        library=library,
        implementation_class=implementation_class,
        security_level=security_level,
        floppy_friendly=floppy,
        status=status,
        key_size=key_size,
        nonce_size=nonce_size,
        is_aead=is_aead,
        description_ru=description_ru,
        description_en=description_en,
        test_vectors_source=test_vectors_source,
        use_cases=use_cases or [],
        extra=extra or {},
    )


def create_signature_metadata(
    name: str,
    library: str,
    implementation_class: str,
    signature_size: int,
    public_key_size: int,
    private_key_size: int,
    *,
    is_post_quantum: bool = False,
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    status: ImplementationStatus = ImplementationStatus.STABLE,
    description_ru: str = "",
    description_en: str = "",
    test_vectors_source: Optional[str] = None,
    use_cases: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> AlgorithmMetadata:
    """
    Factory для создания метаданных алгоритма подписи.

    Args:
        name: Имя алгоритма (например, "Ed25519")
        library: Библиотека
        implementation_class: Полное имя класса
        signature_size: Размер подписи в байтах
        public_key_size: Размер публичного ключа в байтах
        private_key_size: Размер приватного ключа в байтах
        is_post_quantum: Постквантовый алгоритм
        security_level: Уровень безопасности
        status: Статус реализации
        description_ru: Описание на русском
        description_en: Описание на английском
        test_vectors_source: Источник тестовых векторов
        use_cases: Рекомендуемые сценарии использования
        extra: Дополнительные параметры

    Returns:
        Сконфигурированный AlgorithmMetadata

    Example:
        >>> ed25519_meta = create_signature_metadata(
        ...     name="Ed25519",
        ...     library="cryptography",
        ...     implementation_class="cryptography.hazmat.primitives.asymmetric.ed25519",
        ...     signature_size=64,
        ...     public_key_size=32,
        ...     private_key_size=32,
        ...     description_ru="EdDSA подпись на кривой Curve25519",
        ...     test_vectors_source="RFC 8032",
        ... )
    """
    # Автоопределение floppy_friendly
    overhead = signature_size + public_key_size
    floppy = FloppyFriendly.from_size(overhead)

    # Постквантовые алгоритмы автоматически получают QUANTUM_RESISTANT
    if is_post_quantum:
        security_level = SecurityLevel.QUANTUM_RESISTANT

    return AlgorithmMetadata(
        name=name,
        category=AlgorithmCategory.SIGNATURE,
        protocol_class=SignatureProtocol,
        library=library,
        implementation_class=implementation_class,
        security_level=security_level,
        floppy_friendly=floppy,
        status=status,
        signature_size=signature_size,
        public_key_size=public_key_size,
        private_key_size=private_key_size,
        is_post_quantum=is_post_quantum,
        description_ru=description_ru,
        description_en=description_en,
        test_vectors_source=test_vectors_source,
        use_cases=use_cases or [],
        extra=extra or {},
    )


def create_asymmetric_encryption_metadata(
    name: str,
    library: str,
    implementation_class: str,
    key_size: int,
    max_plaintext_size: int,
    *,
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    status: ImplementationStatus = ImplementationStatus.STABLE,
    description_ru: str = "",
    description_en: str = "",
    test_vectors_source: Optional[str] = None,
    use_cases: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> AlgorithmMetadata:
    """
    Factory для создания метаданных асимметричного шифрования.

    Args:
        name: Имя алгоритма (например, "RSA-OAEP-2048")
        library: Библиотека
        implementation_class: Полное имя класса
        key_size: Размер ключа в битах (2048, 3072, 4096)
        max_plaintext_size: Максимальный размер plaintext в байтах
        security_level: Уровень безопасности
        status: Статус реализации
        description_ru: Описание на русском
        description_en: Описание на английском
        test_vectors_source: Источник тестовых векторов
        use_cases: Рекомендуемые сценарии использования
        extra: Дополнительные параметры

    Returns:
        Сконфигурированный AlgorithmMetadata
    """
    # Для RSA overhead зависит от key_size
    overhead = key_size // 8  # Бит → байт
    floppy = FloppyFriendly.from_size(overhead)

    return AlgorithmMetadata(
        name=name,
        category=AlgorithmCategory.ASYMMETRIC_ENCRYPTION,
        protocol_class=AsymmetricEncryptionProtocol,
        library=library,
        implementation_class=implementation_class,
        security_level=security_level,
        floppy_friendly=floppy,
        status=status,
        key_size=key_size,
        max_plaintext_size=max_plaintext_size,
        description_ru=description_ru,
        description_en=description_en,
        test_vectors_source=test_vectors_source,
        use_cases=use_cases or [],
        extra=extra or {},
    )


def create_key_exchange_metadata(
    name: str,
    library: str,
    implementation_class: str,
    shared_secret_size: int,
    public_key_size: int,
    private_key_size: int,
    *,
    is_post_quantum: bool = False,
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    status: ImplementationStatus = ImplementationStatus.STABLE,
    description_ru: str = "",
    description_en: str = "",
    test_vectors_source: Optional[str] = None,
    use_cases: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> AlgorithmMetadata:
    """
    Factory для создания метаданных обмена ключами.

    Args:
        name: Имя алгоритма (например, "X25519")
        library: Библиотека
        implementation_class: Полное имя класса
        shared_secret_size: Размер общего секрета в байтах
        public_key_size: Размер публичного ключа в байтах
        private_key_size: Размер приватного ключа в байтах
        is_post_quantum: Постквантовый алгоритм (KEM)
        security_level: Уровень безопасности
        status: Статус реализации
        description_ru: Описание на русском
        description_en: Описание на английском
        test_vectors_source: Источник тестовых векторов
        use_cases: Рекомендуемые сценарии использования
        extra: Дополнительные параметры

    Returns:
        Сконфигурированный AlgorithmMetadata
    """
    overhead = public_key_size
    floppy = FloppyFriendly.from_size(overhead)

    if is_post_quantum:
        security_level = SecurityLevel.QUANTUM_RESISTANT

    return AlgorithmMetadata(
        name=name,
        category=AlgorithmCategory.KEY_EXCHANGE,
        protocol_class=KeyExchangeProtocol,
        library=library,
        implementation_class=implementation_class,
        security_level=security_level,
        floppy_friendly=floppy,
        status=status,
        public_key_size=public_key_size,
        private_key_size=private_key_size,
        is_post_quantum=is_post_quantum,
        description_ru=description_ru,
        description_en=description_en,
        test_vectors_source=test_vectors_source,
        use_cases=use_cases or [],
        extra=extra or {"shared_secret_size": shared_secret_size},
    )


def create_hash_metadata(
    name: str,
    library: str,
    implementation_class: str,
    digest_size: int,
    *,
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    status: ImplementationStatus = ImplementationStatus.STABLE,
    description_ru: str = "",
    description_en: str = "",
    test_vectors_source: Optional[str] = None,
    use_cases: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> AlgorithmMetadata:
    """
    Factory для создания метаданных хеш-функции.

    Args:
        name: Имя алгоритма (например, "SHA-256")
        library: Библиотека
        implementation_class: Полное имя класса
        digest_size: Размер дайджеста в байтах
        security_level: Уровень безопасности
        status: Статус реализации
        description_ru: Описание на русском
        description_en: Описание на английском
        test_vectors_source: Источник тестовых векторов
        use_cases: Рекомендуемые сценарии использования
        extra: Дополнительные параметры

    Returns:
        Сконфигурированный AlgorithmMetadata
    """
    floppy = FloppyFriendly.from_size(digest_size)

    return AlgorithmMetadata(
        name=name,
        category=AlgorithmCategory.HASH,
        protocol_class=HashProtocol,
        library=library,
        implementation_class=implementation_class,
        security_level=security_level,
        floppy_friendly=floppy,
        status=status,
        digest_size=digest_size,
        description_ru=description_ru,
        description_en=description_en,
        test_vectors_source=test_vectors_source,
        use_cases=use_cases or [],
        extra=extra or {},
    )


def create_kdf_metadata(
    name: str,
    library: str,
    implementation_class: str,
    *,
    recommended_iterations: int = 100000,
    recommended_memory_cost: Optional[int] = None,
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    status: ImplementationStatus = ImplementationStatus.STABLE,
    description_ru: str = "",
    description_en: str = "",
    test_vectors_source: Optional[str] = None,
    use_cases: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> AlgorithmMetadata:
    """
    Factory для создания метаданных KDF.

    Args:
        name: Имя алгоритма (например, "Argon2id")
        library: Библиотека
        implementation_class: Полное имя класса
        recommended_iterations: Рекомендованное количество итераций
        recommended_memory_cost: Рекомендованный объём памяти (КБ)
        security_level: Уровень безопасности
        status: Статус реализации
        description_ru: Описание на русском
        description_en: Описание на английском
        test_vectors_source: Источник тестовых векторов
        use_cases: Рекомендуемые сценарии использования
        extra: Дополнительные параметры

    Returns:
        Сконфигурированный AlgorithmMetadata
    """
    # KDF не имеют фиксированных размеров ключей, всегда EXCELLENT
    floppy = FloppyFriendly.EXCELLENT

    extra = extra or {}
    extra.update(
        {
            "recommended_iterations": recommended_iterations,
            "recommended_memory_cost": recommended_memory_cost,
        }
    )

    return AlgorithmMetadata(
        name=name,
        category=AlgorithmCategory.KDF,
        protocol_class=KDFProtocol,
        library=library,
        implementation_class=implementation_class,
        security_level=security_level,
        floppy_friendly=floppy,
        status=status,
        description_ru=description_ru,
        description_en=description_en,
        test_vectors_source=test_vectors_source,
        use_cases=use_cases or [],
        extra=extra,
    )


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__: list[str] = [
    # Enums
    "AlgorithmCategory",
    "SecurityLevel",
    "FloppyFriendly",
    "ImplementationStatus",
    # Dataclass
    "AlgorithmMetadata",
    # Factory functions
    "create_symmetric_metadata",
    "create_signature_metadata",
    "create_asymmetric_encryption_metadata",
    "create_key_exchange_metadata",
    "create_hash_metadata",
    "create_kdf_metadata",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-09"
