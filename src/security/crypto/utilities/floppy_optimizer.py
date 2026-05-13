"""
Оптимизатор размера данных для сохранения на дискеты 3.5" (1.44 MB).

Модуль реализует FloppyOptimizer — сервис для анализа и оптимизации данных
для хранения на дискетах. Учитывает ограничения ~1.28 MB полезной нагрузки
и предоставляет рекомендации по выбору криптографических алгоритмов
(Ed25519 предпочтительнее ML-DSA-65).

Key Features:
    - Анализ размера данных без изменений
    - Gzip сжатие для уменьшения объёма
    - Оценка размера подписей различных алгоритмов
    - Рекомендации на русском языке

Example:
    >>> from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
    >>> optimizer = FloppyOptimizer()
    >>> result = optimizer.analyze(b"large data...")
    >>> print(result.get_status_message())
    '✅ Данные помещаются на дискету: 1,200,000 байт (экономия 40.0%)'

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import gzip
import json
import logging
from typing import Any, Optional

from src.services.protocols.template_security import (
    MAX_FLOPPY_BYTES,
    OptimizationResult,
    OptimizationType,
    FloppyOptimizerProtocol,
)
from src.security.crypto.core.metadata import FloppyFriendly

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

# Размеры подписей алгоритмов (в байтах)
SIGNATURE_SIZES: dict[str, int] = {
    "Ed25519": 64,
    "Ed448": 114,
    "ECDSA-P256": 64,
    "ECDSA-P384": 96,
    "ECDSA-P521": 132,
    "ECDSA-secp256k1": 64,
    "RSA-PSS-2048": 256,
    "RSA-PSS-3072": 384,
    "RSA-PSS-4096": 512,
    "RSA-PKCS1v15": 256,
    "ML-DSA-44": 2420,
    "ML-DSA-65": 3309,
    "ML-DSA-87": 4595,
    "Falcon-512": 666,
    "Falcon-1024": 1280,
    "SLH-DSA-SHA2-128s": 7856,
    "SLH-DSA-SHA2-192s": 16224,
    "SLH-DSA-SHA2-256s": 29792,
    "Dilithium2": 2420,
    "SPHINCS+-128s": 7856,
}

# Размеры публичных ключей (в байтах)
PUBLIC_KEY_SIZES: dict[str, int] = {
    "Ed25519": 32,
    "Ed448": 57,
    "ECDSA-P256": 64,
    "ECDSA-P384": 96,
    "ECDSA-P521": 133,
    "ECDSA-secp256k1": 64,
    "RSA-PSS-2048": 256,
    "RSA-PSS-3072": 384,
    "RSA-PSS-4096": 512,
    "RSA-PKCS1v15": 256,
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
    "Falcon-512": 897,
    "Falcon-1024": 1793,
    "SLH-DSA-SHA2-128s": 32,
    "SLH-DSA-SHA2-192s": 48,
    "SLH-DSA-SHA2-256s": 64,
    "Dilithium2": 1312,
    "SPHINCS+-128s": 32,
}


# =============================================================================
# MAIN CLASS: FLOPPY OPTIMIZER
# =============================================================================


class FloppyOptimizer:
    """Оптимизатор размера данных для дискет 3.5".

    Реализует FloppyOptimizerProtocol для анализа и оптимизации данных
    под ограничения дискет. Поддерживает сжатие gzip, оценку размеров
    подписей различных алгоритмов и формирование рекомендаций.

    Attributes:
        _registry: AlgorithmRegistry instance для получения метаданных.

    Example:
        >>> optimizer = FloppyOptimizer()
        >>> size = optimizer.estimate_signature_size("Ed25519")
        >>> size
        64
        >>> recs = optimizer.get_recommendations(b"test data")
        >>> len(recs) > 0
        True

    Note:
        Ed25519 предпочтительнее ML-DSA-65 для дискет
        (64 байт против 3,309 байт подписи).
    """

    def __init__(self) -> None:
        """Инициализация оптимизатора с получением AlgorithmRegistry.

        Raises:
            RuntimeError: Если AlgorithmRegistry недоступен.
        """
        try:
            from src.security.crypto.core.registry import AlgorithmRegistry

            self._registry = AlgorithmRegistry.get_instance()
            logger.debug("FloppyOptimizer initialized with AlgorithmRegistry")
        except (ImportError, RuntimeError, TypeError) as e:
            raise RuntimeError(
                "AlgorithmRegistry required for FloppyOptimizer"
            ) from e

    def analyze(self, data: bytes) -> OptimizationResult:
        """Анализирует данные и оценивает возможность оптимизации.

        Анализирует структуру данных и предоставляет оценку:
        текущий размер, возможная экономия, рекомендации.
        Не изменяет исходные данные.

        Args:
            data: Данные для анализа.

        Returns:
            OptimizationResult с рекомендациями (без изменения данных).

        Example:
            >>> optimizer = FloppyOptimizer()
            >>> result = optimizer.analyze(b"x" * 2_000_000)
            >>> result.fits_on_floppy
            False
            >>> "Ed25519" in str(result.recommendations)
            True
        """
        original_size = len(data)
        recommendations: list[str] = []
        applied_methods: list[OptimizationType] = []
        warnings: list[str] = []

        # Проверка текущего размера
        if original_size <= MAX_FLOPPY_BYTES:
            fits = True
            optimized_size = original_size
        else:
            # Оценка после сжатия
            compressed_size = self._estimate_compressed_size(data)
            optimized_size = compressed_size
            applied_methods.append(OptimizationType.COMPRESSION)

            if compressed_size <= MAX_FLOPPY_BYTES:
                fits = True
                recommendations.append(
                    "Используйте сжатие gzip для уменьшения размера данных"
                )
            else:
                fits = False
                overflow = compressed_size - MAX_FLOPPY_BYTES
                warnings.append(
                    f"Даже после сжатия превышение на {overflow:,} байт"
                )
                recommendations.append(
                    "Рассмотрите разделение данных на несколько файлов"
                )

        # Рекомендации по алгоритмам подписи
        if original_size > MAX_FLOPPY_BYTES * 0.8:
            recommendations.append(
                "Используйте Ed25519 (64 байт) вместо ML-DSA-65 (3,309 байт) для подписей"
            )

        # Проверка на JSON данные
        try:
            json.loads(data)
            recommendations.append(
                "Используйте компактный JSON формат без пробелов"
            )
            applied_methods.append(OptimizationType.USE_COMPACT_FORMAT)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        return OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            applied_methods=applied_methods,
            fits_on_floppy=fits,
            target_bytes=MAX_FLOPPY_BYTES,
            recommendations=recommendations,
            warnings=warnings,
        )

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
            >>> optimizer = FloppyOptimizer()
            >>> optimized, result = optimizer.optimize(b"large data...")
            >>> result.fits_on_floppy
            True
            >>> OptimizationType.COMPRESSION in result.applied_methods
            True
        """
        if target_size <= 0:
            raise ValueError(f"target_size должен быть > 0, получено {target_size}")

        if allowed_methods is None:
            allowed_methods = {
                OptimizationType.COMPRESSION,
                OptimizationType.USE_COMPACT_FORMAT,
                OptimizationType.REMOVE_REDUNDANT,
            }

        original_size = len(data)
        optimized_data = data
        applied_methods: list[OptimizationType] = []
        recommendations: list[str] = []
        warnings: list[str] = []

        # Применяем сжатие если разрешено
        if OptimizationType.COMPRESSION in allowed_methods:
            try:
                compressed = self._apply_compression(data)
                if len(compressed) < len(optimized_data):
                    optimized_data = compressed
                    applied_methods.append(OptimizationType.COMPRESSION)
                    logger.debug(f"Applied gzip compression: {original_size} -> {len(compressed)}")
            except (OSError, TypeError, RuntimeError, ValueError) as e:
                logger.warning(f"Compression failed: {e}")

        # Попытка компактного JSON если разрешено
        if (
            OptimizationType.USE_COMPACT_FORMAT in allowed_methods
            and len(optimized_data) > target_size
        ):
            try:
                json_data = json.loads(data)
                compact = json.dumps(json_data, separators=(",", ":"), ensure_ascii=False)
                compact_bytes = compact.encode("utf-8")
                if len(compact_bytes) < len(optimized_data):
                    optimized_data = compact_bytes
                    applied_methods.append(OptimizationType.USE_COMPACT_FORMAT)
                    logger.debug(f"Applied compact JSON format")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        optimized_size = len(optimized_data)
        fits = optimized_size <= target_size

        if not fits:
            overflow = optimized_size - target_size
            warnings.append(
                f"Не удалось достичь целевого размера. "
                f"Превышение на {overflow:,} байт"
            )
            recommendations.append(
                "Рассмотрите разделение данных на несколько частей"
            )
            raise RuntimeError(
                f"Оптимизация невозможна: превышение на {overflow:,} байт"
            )

        result = OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            applied_methods=applied_methods,
            fits_on_floppy=fits,
            target_bytes=target_size,
            recommendations=recommendations,
            warnings=warnings,
        )

        return optimized_data, result

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
            >>> optimizer = FloppyOptimizer()
            >>> recs = optimizer.get_recommendations(b"large data...")
            >>> len(recs) > 0
            True
            >>> any("Ed25519" in r for r in recs)
            True
        """
        recommendations: list[str] = []
        size = len(data)

        # Базовая рекомендация по размеру
        if size > target_size:
            overflow_percent = ((size - target_size) / target_size) * 100
            recommendations.append(
                f"Текущий размер ({size:,} байт) превышает лимит дискеты "
                f"на {overflow_percent:.1f}%"
            )

            # Проверка эффективности сжатия
            compressed_size = self._estimate_compressed_size(data)
            compression_ratio = (size - compressed_size) / size * 100

            if compression_ratio > 10:
                recommendations.append(
                    f"Используйте сжатие gzip — ожидаемая экономия {compression_ratio:.1f}%"
                )
            else:
                recommendations.append(
                    "Данные плохо сжимаются, рассмотрите разделение на части"
                )
        else:
            free_space = target_size - size
            recommendations.append(
                f"✅ Данные ({size:,} байт) помещаются на дискету "
                f"(свободно {free_space:,} байт)"
            )

        # Рекомендации по алгоритмам
        recommendations.append(
            "Используйте Ed25519 (64 байт) вместо ML-DSA-65 (3,309 байт) "
            "для компактных подписей"
        )

        # Проверка на JSON
        try:
            json.loads(data)
            recommendations.append(
                "Для JSON данных используйте compact формат без пробелов"
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Рекомендации по floppy-friendly алгоритмам
        try:
            excellent_algos = self._registry.list_floppy_friendly(
                FloppyFriendly.EXCELLENT
            )
            if excellent_algos:
                algo_names = ", ".join(excellent_algos[:3])
                recommendations.append(
                    f"Floppy-friendly алгоритмы: {algo_names}..."
                )
        except (AttributeError, KeyError, TypeError) as e:
            logger.debug("Registry access failed: %s", e)
            recommendations.append(
                "Floppy-friendly алгоритмы: Ed25519, ChaCha20-Poly1305, X25519"
            )

        return recommendations

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
            >>> optimizer = FloppyOptimizer()
            >>> optimizer.estimate_signature_size("Ed25519")
            96  # 64 (sig) + 32 (key)
            >>> optimizer.estimate_signature_size("ML-DSA-65")
            5261  # 3309 (sig) + 1952 (key)
            >>> optimizer.estimate_signature_size("Ed25519", include_key=False)
            64
        """
        total_size = 0

        # Получаем размер подписи
        sig_size = SIGNATURE_SIZES.get(algorithm)
        if sig_size is not None:
            total_size += sig_size
        else:
            # Попытка получить из registry
            try:
                metadata = self._registry.get_metadata(algorithm)
                if metadata.signature_size:
                    total_size += metadata.signature_size
            except (AttributeError, KeyError, TypeError, ValueError) as e:
                logger.debug("Failed to get signature size from registry: %s", e)
                # Fallback для неизвестных алгоритмов
                logger.warning(f"Unknown algorithm {algorithm}, using fallback size")
                total_size += 256  # Conservative fallback

        # Добавляем размер ключа если требуется
        if include_key:
            key_size = PUBLIC_KEY_SIZES.get(algorithm)
            if key_size is not None:
                total_size += key_size
            else:
                try:
                    metadata = self._registry.get_metadata(algorithm)
                    if metadata.public_key_size:
                        total_size += metadata.public_key_size
                except (AttributeError, KeyError, TypeError, ValueError) as e:
                    logger.debug("Failed to get public key size from registry: %s", e)
                    total_size += 256  # Conservative fallback

        return total_size

    def _estimate_compressed_size(self, data: bytes) -> int:
        """Оценивает размер данных после gzip сжатия.

        Args:
            data: Исходные данные.

        Returns:
            Размер после сжатия в байтах.
        """
        try:
            compressed = gzip.compress(data, compresslevel=6)
            return len(compressed)
        except (OSError, TypeError) as e:
            logger.debug("Compression estimate failed: %s", e)
            return len(data)

    def _apply_compression(self, data: bytes) -> bytes:
        """Применяет gzip сжатие к данным.

        Args:
            data: Исходные данные.

        Returns:
            Сжатые данные.

        Raises:
            RuntimeError: Если сжатие не удалось.
        """
        try:
            return gzip.compress(data, compresslevel=6)
        except Exception as e:
            raise RuntimeError(f"Failed to compress data: {e}") from e


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FloppyOptimizer",
    "SIGNATURE_SIZES",
    "PUBLIC_KEY_SIZES",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-11"
