"""Protocol definitions для Template Security фазы 5.

Определяет контракты для:
- TrustChainService — управление цепочками доверия шаблонов
- FloppyOptimizer — оптимизация размера под дискеты 3.5" (1.44 MB)

Example:
    >>> from src.services.protocols.template_security import (
    ...     TrustChainServiceProtocol,
    ...     FloppyOptimizerProtocol,
    ...     TrustChainLink,
    ...     OptimizationResult,
    ... )
    >>> class TrustService(TrustChainServiceProtocol):
    ...     def verify_template(self, template, trusted_keys):
    ...         return TrustVerificationResult(...)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_FLOPPY_BYTES: int = 1_340_000
"""Максимальный размер данных для дискеты 3.5" (1.44 MB).

Значение ~1.28 MB учитывает:
- 1.44 MB физическая ёмкость
- FAT12 filesystem overhead (~100 KB)
- Directory entries (~10 KB)
- Safety margin (~100 KB)
"""

# =============================================================================
# ENUMS
# =============================================================================


class TrustStatus(str, Enum):
    """Статус доверия ключа или шаблона.

    Наследует str для корректной JSON сериализации.

    Values:
        TRUSTED: Доверенный (проверка успешна).
        UNTRUSTED: Не доверенный (подпись невалидна или ключ неизвестен).
        REVOKED: Отозванный (ключ явно отозван).
        EXPIRED: Срок действия истёк.
        PENDING: В ожидании (цепочка неполная).

    Example:
        >>> status = TrustStatus.TRUSTED
        >>> status.label()
        'Доверенный'
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"

    def label(self) -> str:
        """Человекочитаемое название на русском.

        Returns:
            Локализованное название статуса.
        """
        labels = {
            TrustStatus.TRUSTED: "Доверенный",
            TrustStatus.UNTRUSTED: "Не доверенный",
            TrustStatus.REVOKED: "Отозванный",
            TrustStatus.EXPIRED: "Истёк срок",
            TrustStatus.PENDING: "В ожидании",
        }
        return labels[self]

    def emoji(self) -> str:
        """Эмоджи-индикатор статуса.

        Returns:
            Эмоджи: ✅/❌/🚫/⏰/⏳
        """
        emojis = {
            TrustStatus.TRUSTED: "✅",
            TrustStatus.UNTRUSTED: "❌",
            TrustStatus.REVOKED: "🚫",
            TrustStatus.EXPIRED: "⏰",
            TrustStatus.PENDING: "⏳",
        }
        return emojis[self]

    def is_valid(self) -> bool:
        """Проверяет, является ли статус валидным для использования.

        Returns:
            True только для TRUSTED.
        """
        return self == TrustStatus.TRUSTED


class OptimizationType(str, Enum):
    """Тип оптимизации для уменьшения размера.

    Наследует str для корректной JSON сериализации.

    Values:
        COMPRESSION: Сжатие данных (gzip/zlib).
        SIGNATURE_CHANGE: Смена алгоритма подписи (Ed25519 вместо ML-DSA).
        SPLIT: Разделение на несколько файлов.
        TRUNCATE_METADATA: Усечение метаданных.
        REMOVE_REDUNDANT: Удаление избыточных данных.
        USE_COMPACT_FORMAT: Использование компактного бинарного формата.

    Example:
        >>> opt_type = OptimizationType.COMPRESSION
        >>> opt_type.label()
        'Сжатие данных'
    """

    COMPRESSION = "compression"
    SIGNATURE_CHANGE = "signature_change"
    SPLIT = "split"
    TRUNCATE_METADATA = "truncate_metadata"
    REMOVE_REDUNDANT = "remove_redundant"
    USE_COMPACT_FORMAT = "use_compact_format"

    def label(self) -> str:
        """Человекочитаемое название на русском.

        Returns:
            Локализованное название типа оптимизации.
        """
        labels = {
            OptimizationType.COMPRESSION: "Сжатие данных",
            OptimizationType.SIGNATURE_CHANGE: "Смена алгоритма подписи",
            OptimizationType.SPLIT: "Разделение на части",
            OptimizationType.TRUNCATE_METADATA: "Усечение метаданных",
            OptimizationType.REMOVE_REDUNDANT: "Удаление избыточных данных",
            OptimizationType.USE_COMPACT_FORMAT: "Компактный формат",
        }
        return labels[self]


# =============================================================================
# DATACLASSES
# =============================================================================


@dataclass(frozen=True)
class TrustChainLink:
    """Связь в цепочке доверия.

    Представляет один узел цепочки доверия — связь между ключом
    и его родительским (подписывающим) ключом.

    Attributes:
        key_id: Уникальный идентификатор ключа.
        parent_key_id: ID родительского ключа (None для корневого).
        public_key: Публичный ключ в бинарном формате.
        algorithm: Алгоритм подписи (например, "Ed25519", "ML-DSA-65").
        added_at: Время добавления ключа в цепочку.
        expires_at: Время истечения срока действия (None если бессрочно).
        signature: Подпись от родительского ключа (None для корневого).
        metadata: Дополнительные данные (имя, email, организация).

    Example:
        >>> link = TrustChainLink(
        ...     key_id="key-123",
        ...     parent_key_id="root-key",
        ...     public_key=b"\x01\x02\x03...",
        ...     algorithm="Ed25519",
        ...     added_at=datetime.now(),
        ...     signature=b"\xaa\xbb\xcc...",
        ... )
    """

    key_id: str
    public_key: bytes
    algorithm: str
    added_at: datetime
    parent_key_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    signature: Optional[bytes] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_root(self) -> bool:
        """Проверяет, является ли узел корневым.

        Returns:
            True если parent_key_id is None.
        """
        return self.parent_key_id is None

    def is_expired(self) -> bool:
        """Проверяет, истёк ли срок действия ключа.

        Returns:
            True если expires_at прошёл.
        """
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Сериализует связь в словарь.

        Returns:
            Словарь с примитивными типами.
        """
        return {
            "key_id": self.key_id,
            "parent_key_id": self.parent_key_id,
            "public_key": self.public_key.hex(),
            "algorithm": self.algorithm,
            "added_at": self.added_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "signature": self.signature.hex() if self.signature else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustChainLink:
        """Десериализует связь из словаря.

        Args:
            data: Словарь с данными связи.

        Returns:
            Экземпляр TrustChainLink.
        """
        from datetime import datetime

        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])

        signature = None
        if data.get("signature"):
            signature = bytes.fromhex(data["signature"])

        return cls(
            key_id=data["key_id"],
            parent_key_id=data.get("parent_key_id"),
            public_key=bytes.fromhex(data["public_key"]),
            algorithm=data["algorithm"],
            added_at=datetime.fromisoformat(data["added_at"]),
            expires_at=expires_at,
            signature=signature,
            metadata=data.get("metadata", {}),
        )


@dataclass(frozen=True)
class TrustVerificationResult:
    """Результат верификации шаблона по цепочке доверия.

    Содержит полный результат проверки подписи шаблона,
    включая статус доверия, глубину цепочки и возможные ошибки.

    Attributes:
        template_id: Идентификатор проверенного шаблона.
        is_valid: Валидна ли криптографическая подпись.
        trust_status: Статус доверия (TRUSTED, REVOKED, etc.).
        chain_depth: Глубина цепочки доверия (0 для корневого).
        signing_key_id: ID ключа, которым подписан шаблон.
        verified_at: Время проверки.
        errors: Список ошибок (если verification failed).
        warnings: Список предупреждений.

    Example:
        >>> result = TrustVerificationResult(
        ...     template_id="tpl-123",
        ...     is_valid=True,
        ...     trust_status=TrustStatus.TRUSTED,
        ...     chain_depth=2,
        ...     signing_key_id="key-456",
        ... )
        >>> result.can_trust
        True
    """

    template_id: str
    is_valid: bool
    trust_status: TrustStatus
    chain_depth: int
    signing_key_id: str
    verified_at: datetime = field(default_factory=datetime.now)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def can_trust(self) -> bool:
        """Можно ли доверять шаблону.

        Returns:
            True если is_valid и trust_status == TRUSTED.
        """
        return self.is_valid and self.trust_status == TrustStatus.TRUSTED

    @property
    def is_revoked(self) -> bool:
        """Проверяет, отозван ли ключ.

        Returns:
            True если trust_status == REVOKED.
        """
        return self.trust_status == TrustStatus.REVOKED

    def to_dict(self) -> dict[str, Any]:
        """Сериализует результат в словарь.

        Returns:
            Словарь с примитивными типами.
        """
        return {
            "template_id": self.template_id,
            "is_valid": self.is_valid,
            "trust_status": self.trust_status.value,
            "chain_depth": self.chain_depth,
            "signing_key_id": self.signing_key_id,
            "verified_at": self.verified_at.isoformat(),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class OptimizationResult:
    """Результат анализа или оптимизации размера данных.

    Содержит информацию об оптимизации для сохранения на дискету:
    исходный размер, оптимизированный размер, применённые методы.

    Attributes:
        original_size: Исходный размер в байтах.
        optimized_size: Оптимизированный размер в байтах.
        savings_bytes: Экономия в байтах.
        savings_percent: Экономия в процентах (0.0-100.0).
        fits_on_floppy: Помещается ли на дискету после оптимизации.
        target_bytes: Целевой размер (обычно MAX_FLOPPY_BYTES).
        applied_methods: Применённые методы оптимизации.
        recommendations: Рекомендации для дальнейшей оптимизации.
        warnings: Предупреждения (потеря данных, совместимость).

    Example:
        >>> result = OptimizationResult(
        ...     original_size=2_000_000,
        ...     optimized_size=1_200_000,
        ...     applied_methods=[OptimizationType.COMPRESSION],
        ... )
        >>> result.fits_on_floppy
        True
        >>> f"Сэкономлено {result.savings_percent:.1f}%"
        'Сэкономлено 40.0%'
    """

    original_size: int
    optimized_size: int
    applied_methods: list[OptimizationType]
    fits_on_floppy: bool = False
    target_bytes: int = MAX_FLOPPY_BYTES
    recommendations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def savings_bytes(self) -> int:
        """Экономия в байтах.

        Returns:
            original_size - optimized_size.
        """
        return self.original_size - self.optimized_size

    @property
    def savings_percent(self) -> float:
        """Экономия в процентах.

        Returns:
            Процент экономии (0.0-100.0).
        """
        if self.original_size == 0:
            return 0.0
        return ((self.original_size - self.optimized_size) / self.original_size) * 100

    def get_status_message(self) -> str:
        """Формирует сообщение о статусе оптимизации.

        Returns:
            Человекочитаемое сообщение на русском.
        """
        if self.fits_on_floppy:
            return (
                f"✅ Данные помещаются на дискету: "
                f"{self.optimized_size:,} байт (экономия {self.savings_percent:.1f}%)"
            )
        else:
            overflow = self.optimized_size - self.target_bytes
            return (
                f"❌ Превышение размера дискеты на {overflow:,} байт. "
                f"Требуется дополнительная оптимизация."
            )

    def to_dict(self) -> dict[str, Any]:
        """Сериализует результат в словарь.

        Returns:
            Словарь с примитивными типами.
        """
        return {
            "original_size": self.original_size,
            "optimized_size": self.optimized_size,
            "savings_bytes": self.savings_bytes,
            "savings_percent": self.savings_percent,
            "fits_on_floppy": self.fits_on_floppy,
            "target_bytes": self.target_bytes,
            "applied_methods": [m.value for m in self.applied_methods],
            "recommendations": list(self.recommendations),
            "warnings": list(self.warnings),
        }


# =============================================================================
# PROTOCOLS
# =============================================================================


@runtime_checkable
class TrustChainServiceProtocol(Protocol):
    """Protocol для сервиса цепочек доверия шаблонов.

    Определяет контракт для управления цепочками доверия:
    верификация шаблонов, добавление/отзыв ключей,
    построение и проверка цепочек доверия.

    Example:
        >>> class TrustService(TrustChainServiceProtocol):
        ...     def verify_template(self, template, trusted_keys):
        ...         return TrustVerificationResult(...)
        ...     def get_trust_chain(self, template_id):
        ...         return []

    Note:
        Все методы должны быть thread-safe.
    """

    def verify_template(
        self,
        template: Any,
        trusted_keys: Optional[set[str]] = None,
        verify_chain: bool = True,
    ) -> TrustVerificationResult:
        """Верифицирует шаблон по цепочке доверия.

        Проверяет подпись шаблона и валидность цепочки доверия
        от подписавшего ключа до корневого.

        Args:
            template: Шаблон для проверки (FormTemplate или аналог).
            trusted_keys: Множество ID доверенных ключей (None = все из реестра).
            verify_chain: Проверять ли полную цепочку или только подпись.

        Returns:
            TrustVerificationResult с полным результатом проверки.

        Raises:
            ValueError: Если шаблон не имеет подписи.
            KeyError: Если ключ не найден в реестре.
        """
        ...

    def get_trust_chain(
        self,
        key_id: str,
        include_revoked: bool = False,
    ) -> list[TrustChainLink]:
        """Возвращает цепочку доверия для ключа.

        Строит цепочку от указанного ключа до корневого,
        включая все промежуточные звенья.

        Args:
            key_id: ID ключа, для которого строится цепочка.
            include_revoked: Включать ли отозванные ключи в цепочку.

        Returns:
            Список TrustChainLink от ключа к корневому.
            Пустой список если ключ не найден.

        Example:
            >>> chain = service.get_trust_chain("key-456")
            >>> len(chain)
            2
            >>> chain[0].key_id
            'key-456'
            >>> chain[1].is_root()
            True
        """
        ...

    def add_trusted_key(
        self,
        key_id: str,
        public_key: bytes,
        algorithm: str,
        parent_key_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> TrustChainLink:
        """Добавляет новый доверенный ключ в цепочку.

        Добавляет публичный ключ в реестр доверенных.
        Если parent_key_id указан — создаёт связь в цепочке.

        Args:
            key_id: Уникальный идентификатор ключа.
            public_key: Публичный ключ в бинарном формате.
            algorithm: Алгоритм подписи ("Ed25519", "ML-DSA-65", etc.).
            parent_key_id: ID родительского ключа (None для корневого).
            expires_at: Срок действия (None для бессрочного).
            metadata: Дополнительные данные (имя, организация).

        Returns:
            Созданный TrustChainLink.

        Raises:
            ValueError: Если key_id уже существует.
            KeyError: Если parent_key_id не найден.
        """
        ...

    def revoke_key(
        self,
        key_id: str,
        reason: str,
        revoked_by: str,
    ) -> bool:
        """Отзывает ключ из цепочки доверия.

        Помечает ключ как отозванный. Ключ остаётся в реестре
        для проверки старых подписей, но новые подписи
        считаются недоверенными.

        Args:
            key_id: ID ключа для отзыва.
            reason: Причина отзыва.
            revoked_by: ID ключа, которым выполнен отзыв.

        Returns:
            True если отзыв выполнен успешно.

        Raises:
            KeyError: Если key_id не найден.
            ValueError: Если revoked_by нет прав на отзыв.
        """
        ...

    def is_key_trusted(
        self,
        key_id: str,
        at_time: Optional[datetime] = None,
    ) -> bool:
        """Проверяет, является ли ключ доверенным.

        Проверяет статус ключа: не отозван, не истёк,
        цепочка валидна до корневого.

        Args:
            key_id: ID ключа для проверки.
            at_time: Время для проверки (None = текущее).

        Returns:
            True если ключ доверенный и валидный.
        """
        ...

    def get_root_keys(self) -> list[TrustChainLink]:
        """Возвращает все корневые (self-signed) ключи.

        Returns:
            Список корневых ключей (где parent_key_id is None).
        """
        ...


@runtime_checkable
class FloppyOptimizerProtocol(Protocol):
    """Protocol для оптимизатора размера под дискеты.

    Определяет контракт для анализа и оптимизации данных
    для сохранения на дискету 3.5" (1.44 MB физически,
    ~1.28 MB полезной нагрузки).

    Example:
        >>> class Optimizer(FloppyOptimizerProtocol):
        ...     def analyze(self, data):
        ...         return OptimizationResult(...)
        ...     def optimize(self, data, target_size):
        ...         return b"optimized"

    Constants:
        MAX_FLOPPY_BYTES: ~1.28 MB полезной нагрузки.

    Note:
        Ed25519 предпочтительнее ML-DSA-65 для дискет
        (64 байт против 3,309 байт подписи).
    """

    def analyze(self, data: bytes) -> OptimizationResult:
        """Анализирует данные и оценивает возможность оптимизации.

        Анализирует структуру данных и предоставляет оценку:
        текущий размер, возможная экономия, рекомендации.

        Args:
            data: Данные для анализа.

        Returns:
            OptimizationResult с рекомендациями (без изменения данных).

        Example:
            >>> result = optimizer.analyze(template_bytes)
            >>> result.fits_on_floppy
            False
            >>> result.recommendations
            ['Используйте Ed25519 вместо ML-DSA-65', 'Включите сжатие gzip']
        """
        ...

    def optimize(
        self,
        data: bytes,
        target_size: int = MAX_FLOPPY_BYTES,
        allowed_methods: Optional[set[OptimizationType]] = None,
    ) -> tuple[bytes, OptimizationResult]:
        """Оптимизирует данные до целевого размера.

        Применяет разрешённые методы оптимизации для достижения
        целевого размера. Возвращает оптимизированные данные
        и результат с описанием применённых методов.

        Args:
            data: Исходные данные.
            target_size: Целевой размер в байтах (по умолчанию MAX_FLOPPY_BYTES).
            allowed_methods: Разрешённые методы оптимизации (None = все).

        Returns:
            Кортеж (optimized_data, result).

        Raises:
            ValueError: Если target_size меньше минимально возможного.
            RuntimeError: Если оптимизация невозможна.

        Example:
            >>> optimized, result = optimizer.optimize(data, MAX_FLOPPY_BYTES)
            >>> result.fits_on_floppy
            True
            >>> OptimizationType.COMPRESSION in result.applied_methods
            True
        """
        ...

    def get_recommendations(
        self,
        data: bytes,
        target_size: int = MAX_FLOPPY_BYTES,
    ) -> list[str]:
        """Возвращает список рекомендаций по оптимизации.

        Анализирует данные и предоставляет человекочитаемые
        рекомендации на русском языке.

        Args:
            data: Данные для анализа.
            target_size: Целевой размер.

        Returns:
            Список рекомендаций (строки на русском).

        Example:
            >>> recs = optimizer.get_recommendations(large_data)
            >>> len(recs) > 0
            True
            >>> "Ed25519" in recs[0]
            True
        """
        ...

    def estimate_signature_size(
        self,
        algorithm: str,
        include_key: bool = True,
    ) -> int:
        """Оценивает размер подписи для алгоритма.

        Возвращает ожидаемый размер подписи и опционально
        публичного ключа для различных алгоритмов.

        Args:
            algorithm: Название алгоритма ("Ed25519", "ML-DSA-65", etc.).
            include_key: Включать ли размер публичного ключа.

        Returns:
            Размер в байтах.

        Example:
            >>> optimizer.estimate_signature_size("Ed25519")
            64
            >>> optimizer.estimate_signature_size("ML-DSA-65")
            3293
        """
        ...


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Constants
    "MAX_FLOPPY_BYTES",
    # Enums
    "TrustStatus",
    "OptimizationType",
    # Dataclasses
    "TrustChainLink",
    "TrustVerificationResult",
    "OptimizationResult",
    # Protocols
    "TrustChainServiceProtocol",
    "FloppyOptimizerProtocol",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-11"
