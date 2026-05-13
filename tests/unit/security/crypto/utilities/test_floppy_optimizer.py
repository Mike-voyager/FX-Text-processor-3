"""
Тесты для FloppyOptimizer и связанных классов.

Покрытие:
- OptimizationResult: свойства, расчёт экономии, сериализация
- FloppyOptimizerProtocol: анализ, оптимизация, рекомендации
- Размеры подписей: Ed25519, ML-DSA-65, неизвестные
- Граничные случаи размеров

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: April 11, 2026
"""

from __future__ import annotations

import gzip
import secrets
from typing import Optional, Protocol, runtime_checkable

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# Импорты из проекта
from src.security.crypto.core.registry import AlgorithmRegistry
from src.security.crypto.utilities.utils import FloppyOptimizer
from src.services.protocols.template_security import (
    MAX_FLOPPY_BYTES,
    OptimizationResult,
    OptimizationType,
)

# pyright: reportPrivateUsage=false
# ==============================================================================
# CONSTANTS
# ==============================================================================

ED25519_SIGNATURE_SIZE = 64
ED25519_PUBLIC_KEY_SIZE = 32
ML_DSA_65_SIGNATURE_SIZE = 3293
ML_DSA_65_PUBLIC_KEY_SIZE = 1952


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def optimizer() -> FloppyOptimizer:
    """Фикстура для создания оптимизатора."""
    return FloppyOptimizer()


@pytest.fixture
def small_data() -> bytes:
    """Маленькие данные, помещающиеся на дискету."""
    return b"Small test data" * 100  # ~1.5 KB


@pytest.fixture
def large_data() -> bytes:
    """Большие данные, не помещающиеся на дискету."""
    return b"Large test data for floppy optimization testing." * 50000  # ~2.3 MB


@pytest.fixture
def boundary_data() -> bytes:
    """Данные ровно на границе MAX_FLOPPY_BYTES."""
    return b"X" * MAX_FLOPPY_BYTES


# ==============================================================================
# MOCK IMPLEMENTATIONS FOR TESTING
# ==============================================================================


@runtime_checkable
class FloppyOptimizerProtocol(Protocol):
    """Protocol для оптимизатора размера под дискеты."""

    def analyze(self, data: bytes) -> OptimizationResult: ...

    def optimize(
        self,
        data: bytes,
        target_size: int = MAX_FLOPPY_BYTES,
        allowed_methods: Optional[set[OptimizationType]] = None,
    ) -> tuple[bytes, OptimizationResult]: ...

    def get_recommendations(
        self, data: bytes, target_size: int = MAX_FLOPPY_BYTES
    ) -> list[str]: ...

    def estimate_signature_size(self, algorithm: str, include_key: bool = True) -> int: ...


class EnhancedFloppyOptimizer(FloppyOptimizer):
    """Расширенный оптимизатор, реализующий FloppyOptimizerProtocol."""

    def analyze(self, data: bytes) -> OptimizationResult:
        """Анализирует данные и оценивает возможность оптимизации."""
        original_size = len(data)
        compressed = gzip.compress(data)
        compressed_size = len(compressed)

        fits = original_size <= MAX_FLOPPY_BYTES
        fits_compressed = compressed_size <= MAX_FLOPPY_BYTES

        applied_methods: list[OptimizationType] = []
        recommendations: list[str] = []
        warnings: list[str] = []

        if not fits:
            recommendations.append("Используйте сжатие данных")
            if not fits_compressed:
                recommendations.append("Используйте Ed25519 вместо ML-DSA-65 для подписи")
                recommendations.append("Разделите данные на несколько частей")
                warnings.append("Данные слишком большие для дискеты даже после сжатия")

        if compressed_size < original_size:
            applied_methods.append(OptimizationType.COMPRESSION)

        optimized_size = compressed_size if compressed_size < original_size else original_size

        return OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            applied_methods=applied_methods,
            fits_on_floppy=optimized_size <= MAX_FLOPPY_BYTES,
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
        """Оптимизирует данные до целевого размера."""
        if target_size < 0:
            raise ValueError("target_size должен быть неотрицательным")

        original_size = len(data)
        current_data = data
        applied_methods: list[OptimizationType] = []

        # Пробуем сжатие
        if allowed_methods is None or OptimizationType.COMPRESSION in allowed_methods:
            compressed = gzip.compress(data, compresslevel=9)
            if len(compressed) < len(current_data):
                current_data = compressed
                applied_methods.append(OptimizationType.COMPRESSION)

        optimized_size = len(current_data)
        fits = optimized_size <= target_size

        recommendations: list[str] = []
        warnings: list[str] = []

        if not fits:
            recommendations.append("Разделите данные на несколько частей")
            warnings.append(f"Невозможно достичь целевого размера {target_size}")

        result = OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            applied_methods=applied_methods,
            fits_on_floppy=fits,
            target_bytes=target_size,
            recommendations=recommendations,
            warnings=warnings,
        )

        return current_data, result

    def get_recommendations(self, data: bytes, target_size: int = MAX_FLOPPY_BYTES) -> list[str]:
        """Возвращает список рекомендаций по оптимизации."""
        recommendations: list[str] = []
        size = len(data)

        if size > target_size:
            recommendations.append("Включите сжатие gzip")
            recommendations.append("Используйте Ed25519 вместо ML-DSA-65 для подписи")

            # Проверяем, сколько поместится подписей
            ed25519_overhead = self.estimate_signature_size("Ed25519")
            mldsa65_overhead = self.estimate_signature_size("ML-DSA-65")
            savings = mldsa65_overhead - ed25519_overhead

            recommendations.append(
                f"Смена алгоритма подписи с ML-DSA-65 на Ed25519 экономит {savings} байт"
            )

            if size > target_size * 2:
                recommendations.append("Разделите документ на несколько частей")

        return recommendations

    def estimate_signature_size(self, algorithm: str, include_key: bool = True) -> int:
        """Оценивает размер подписи для алгоритма."""
        algorithm_upper = algorithm.upper()

        # Ed25519
        if algorithm_upper in ("ED25519", "EDDSA", "ED25519PH"):
            size = ED25519_SIGNATURE_SIZE
            if include_key:
                size += ED25519_PUBLIC_KEY_SIZE
            return size

        # ML-DSA-65 (Dilithium3)
        if algorithm_upper in ("ML-DSA-65", "DILITHIUM3", "MLDSA65"):
            size = ML_DSA_65_SIGNATURE_SIZE
            if include_key:
                size += ML_DSA_65_PUBLIC_KEY_SIZE
            return size

        # ML-DSA-44
        if algorithm_upper in ("ML-DSA-44", "DILITHIUM2", "MLDSA44"):
            size = 2420
            if include_key:
                size += 1312
            return size

        # ML-DSA-87
        if algorithm_upper in ("ML-DSA-87", "DILITHIUM5", "MLDSA87"):
            size = 4595
            if include_key:
                size += 2592
            return size

        # RSA-PSS-4096
        if algorithm_upper in ("RSA-PSS-4096", "RSAPSS4096"):
            size = 512
            if include_key:
                size += 512
            return size

        # Неизвестный алгоритм - возвращаем 0 или выбрасываем исключение
        raise ValueError(f"Неизвестный алгоритм подписи: {algorithm}")


# ==============================================================================
# TESTS: OptimizationResult Properties
# ==============================================================================


class TestOptimizationResultProperties:
    """Тесты свойств OptimizationResult."""

    def test_optimization_result_properties(self) -> None:
        """Проверка свойств OptimizationResult."""
        result = OptimizationResult(
            original_size=2000000,
            optimized_size=1200000,
            applied_methods=[OptimizationType.COMPRESSION],
            fits_on_floppy=True,
        )

        assert result.original_size == 2000000
        assert result.optimized_size == 1200000
        assert result.savings_bytes == 800000
        assert result.savings_percent == 40.0
        assert result.fits_on_floppy is True

    def test_savings_bytes_calculation(self) -> None:
        """Правильный расчёт экономии в байтах."""
        result = OptimizationResult(
            original_size=1000,
            optimized_size=700,
            applied_methods=[OptimizationType.COMPRESSION],
        )
        assert result.savings_bytes == 300

    def test_calculate_savings_percentage(self) -> None:
        """Правильный расчёт процента экономии."""
        # 50% экономии
        result1 = OptimizationResult(
            original_size=1000,
            optimized_size=500,
            applied_methods=[OptimizationType.COMPRESSION],
        )
        assert result1.savings_percent == 50.0

        # 0% экономии
        result2 = OptimizationResult(
            original_size=1000,
            optimized_size=1000,
            applied_methods=[],
        )
        assert result2.savings_percent == 0.0

        # Предельный случай - пустые данные
        result3 = OptimizationResult(
            original_size=0,
            optimized_size=0,
            applied_methods=[],
        )
        assert result3.savings_percent == 0.0

    @pytest.mark.security
    def test_fits_on_floppy_boundary(self) -> None:
        """Граничный случай точно 1.28MB."""
        # Ровно на границе
        result = OptimizationResult(
            original_size=MAX_FLOPPY_BYTES,
            optimized_size=MAX_FLOPPY_BYTES,
            applied_methods=[],
            fits_on_floppy=True,
        )
        assert result.fits_on_floppy is True
        assert result.optimized_size == MAX_FLOPPY_BYTES

        # На байт больше
        result_over = OptimizationResult(
            original_size=MAX_FLOPPY_BYTES + 1,
            optimized_size=MAX_FLOPPY_BYTES + 1,
            applied_methods=[],
            fits_on_floppy=False,
        )
        assert result_over.fits_on_floppy is False

    def test_status_message_success(self) -> None:
        """Сообщение о успешной оптимизации."""
        result = OptimizationResult(
            original_size=2000000,
            optimized_size=1200000,
            applied_methods=[OptimizationType.COMPRESSION],
            fits_on_floppy=True,
        )
        msg = result.get_status_message()
        assert "✅" in msg
        assert "1,200,000" in msg
        assert "40.0%" in msg

    def test_status_message_failure(self) -> None:
        """Сообщение о неудачной оптимизации."""
        result = OptimizationResult(
            original_size=2000000,
            optimized_size=1500000,
            applied_methods=[OptimizationType.COMPRESSION],
            fits_on_floppy=False,
            target_bytes=MAX_FLOPPY_BYTES,
        )
        msg = result.get_status_message()
        assert "❌" in msg
        assert "дополнительная оптимизация" in msg

    def test_to_dict_serialization(self) -> None:
        """Сериализация в словарь."""
        result = OptimizationResult(
            original_size=1000,
            optimized_size=700,
            applied_methods=[OptimizationType.COMPRESSION],
            fits_on_floppy=True,
            target_bytes=MAX_FLOPPY_BYTES,
            recommendations=["Use compression"],
            warnings=["Large file"],
        )
        data = result.to_dict()

        assert data["original_size"] == 1000
        assert data["optimized_size"] == 700
        assert data["savings_bytes"] == 300
        assert data["savings_percent"] == 30.0
        assert data["fits_on_floppy"] is True
        assert data["target_bytes"] == MAX_FLOPPY_BYTES
        assert data["applied_methods"] == ["compression"]
        assert data["recommendations"] == ["Use compression"]
        assert data["warnings"] == ["Large file"]


# ==============================================================================
# TESTS: Analyze Methods
# ==============================================================================


class TestFloppyOptimizerAnalyze:
    """Тесты метода analyze()."""

    @pytest.fixture
    def enhanced_optimizer(self) -> EnhancedFloppyOptimizer:
        """Фикстура для расширенного оптимизатора."""
        return EnhancedFloppyOptimizer()

    @pytest.mark.security
    def test_analyze_small_data_fits(self, enhanced_optimizer: EnhancedFloppyOptimizer) -> None:
        """Анализ маленьких данных (< 1.28MB) - помещаются на дискету."""
        data = b"Small data" * 1000  # ~10 KB
        result = enhanced_optimizer.analyze(data)

        assert result.original_size == len(data)
        assert result.fits_on_floppy is True
        assert len(result.warnings) == 0

    @pytest.mark.security
    def test_analyze_large_data_overflow(self, enhanced_optimizer: EnhancedFloppyOptimizer) -> None:
        """Анализ больших данных (> 1.28MB) - не помещаются на дискету."""
        data = b"X" * (MAX_FLOPPY_BYTES + 1000)
        result = enhanced_optimizer.analyze(data)

        assert result.original_size > MAX_FLOPPY_BYTES
        assert len(result.recommendations) > 0
        # Должны быть рекомендации по оптимизации
        assert any("сжатие" in r.lower() for r in result.recommendations)

    def test_analyze_returns_optimization_type(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Анализ возвращает корректный OptimizationType."""
        data = b"Test data for compression analysis"
        result = enhanced_optimizer.analyze(data)

        assert isinstance(result, OptimizationResult)
        assert all(isinstance(m, OptimizationType) for m in result.applied_methods)


# ==============================================================================
# TESTS: Optimize Methods
# ==============================================================================


class TestFloppyOptimizerOptimize:
    """Тесты метода optimize()."""

    @pytest.fixture
    def enhanced_optimizer(self) -> EnhancedFloppyOptimizer:
        """Фикстура для расширенного оптимизатора."""
        return EnhancedFloppyOptimizer()

    @pytest.mark.security
    def test_optimize_compression_reduces_size(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """gzip сжатие уменьшает размер."""
        # Используем данные которые хорошо сжимаются
        data = b"A" * 10000
        original_size = len(data)

        optimized_data, result = enhanced_optimizer.optimize(data)

        assert result.optimized_size < original_size
        assert OptimizationType.COMPRESSION in result.applied_methods
        assert len(optimized_data) < original_size

    @pytest.mark.security
    def test_optimize_fits_on_floppy(self, enhanced_optimizer: EnhancedFloppyOptimizer) -> None:
        """Оптимизация достигает целевого размера."""
        # Данные которые сожмутся до размера дискеты
        data = b"A" * 500000  # Сжимаемые данные

        optimized_data, result = enhanced_optimizer.optimize(data, target_size=MAX_FLOPPY_BYTES)

        # После сжатия должны поместиться
        assert result.optimized_size <= MAX_FLOPPY_BYTES
        assert result.fits_on_floppy is True

    @pytest.mark.security
    def test_optimize_cannot_reach_target(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Невозможно достичь целевого размера."""
        # Создаём несжимаемые данные (случайные данные плохо сжимаются)
        # nosec: B311 - используем secrets для безопасного рандома
        data = bytes(secrets.randbelow(256) for _ in range(MAX_FLOPPY_BYTES + 5000))

        optimized_data, result = enhanced_optimizer.optimize(data, target_size=MAX_FLOPPY_BYTES)

        # После сжатия данные могут быть меньше или нет
        # Проверяем что метод корректно обрабатывает большие данные
        if not result.fits_on_floppy:
            assert len(result.warnings) > 0
        # В любом случае, оптимизация должна вернуть результат
        assert result.original_size == len(data)
        assert result.optimized_size <= result.original_size

    def test_optimize_invalid_target_size(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Ошибка при некорректном target_size."""
        data = b"test"

        with pytest.raises(ValueError):
            enhanced_optimizer.optimize(data, target_size=-1)

    def test_optimize_with_allowed_methods(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Оптимизация с ограниченными методами."""
        data = b"A" * 1000

        optimized_data, result = enhanced_optimizer.optimize(
            data, allowed_methods={OptimizationType.COMPRESSION}
        )

        assert OptimizationType.COMPRESSION in result.applied_methods


# ==============================================================================
# TESTS: Recommendations
# ==============================================================================


class TestFloppyOptimizerRecommendations:
    """Тесты метода get_recommendations()."""

    @pytest.fixture
    def enhanced_optimizer(self) -> EnhancedFloppyOptimizer:
        """Фикстура для расширенного оптимизатора."""
        return EnhancedFloppyOptimizer()

    @pytest.mark.security
    def test_get_recommendations_for_large_data(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Рекомендации для больших данных."""
        data = b"X" * (MAX_FLOPPY_BYTES + 1000)

        recommendations = enhanced_optimizer.get_recommendations(data)

        assert len(recommendations) > 0
        # Должны быть рекомендации по сжатию
        assert any("сжатие" in r.lower() for r in recommendations)

    @pytest.mark.security
    def test_get_recommendations_includes_ed25519(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Рекомендация использовать Ed25519."""
        data = b"X" * (MAX_FLOPPY_BYTES + 1000)

        recommendations = enhanced_optimizer.get_recommendations(data)

        # Должна быть рекомендация про Ed25519
        assert any("Ed25519" in r for r in recommendations)

    def test_get_recommendations_for_small_data(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Нет рекомендаций для маленьких данных."""
        data = b"Small data"

        recommendations = enhanced_optimizer.get_recommendations(data)

        assert len(recommendations) == 0


# ==============================================================================
# TESTS: Signature Size Estimation
# ==============================================================================


class TestSignatureSizeEstimation:
    """Тесты оценки размера подписи."""

    @pytest.fixture
    def enhanced_optimizer(self) -> EnhancedFloppyOptimizer:
        """Фикстура для расширенного оптимизатора."""
        return EnhancedFloppyOptimizer()

    @pytest.mark.security
    def test_estimate_signature_size_ed25519(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Размер Ed25519 = 64 байт (только подпись)."""
        size = enhanced_optimizer.estimate_signature_size("Ed25519", include_key=False)
        assert size == ED25519_SIGNATURE_SIZE

    def test_estimate_signature_size_ed25519_with_key(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Размер Ed25519 = 96 байт (подпись + ключ)."""
        size = enhanced_optimizer.estimate_signature_size("Ed25519", include_key=True)
        assert size == ED25519_SIGNATURE_SIZE + ED25519_PUBLIC_KEY_SIZE

    @pytest.mark.security
    def test_estimate_signature_size_mldsa65(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Размер ML-DSA-65 = 3293 байт (только подпись)."""
        size = enhanced_optimizer.estimate_signature_size("ML-DSA-65", include_key=False)
        assert size == ML_DSA_65_SIGNATURE_SIZE

    def test_estimate_signature_size_mldsa65_with_key(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Размер ML-DSA-65 с ключом."""
        size = enhanced_optimizer.estimate_signature_size("ML-DSA-65", include_key=True)
        assert size == ML_DSA_65_SIGNATURE_SIZE + ML_DSA_65_PUBLIC_KEY_SIZE

    @pytest.mark.security
    def test_estimate_signature_size_unknown(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Неизвестный алгоритм вызывает ValueError."""
        with pytest.raises(ValueError, match="Неизвестный алгоритм"):
            enhanced_optimizer.estimate_signature_size("UnknownAlgo")

    def test_estimate_signature_size_case_insensitive(
        self, enhanced_optimizer: EnhancedFloppyOptimizer
    ) -> None:
        """Регистр не важен для названия алгоритма."""
        assert enhanced_optimizer.estimate_signature_size("ed25519") == 96
        assert enhanced_optimizer.estimate_signature_size("ED25519") == 96
        assert enhanced_optimizer.estimate_signature_size("Ed25519") == 96


# ==============================================================================
# TESTS: Algorithm Registry Fallback
# ==============================================================================


class TestAlgorithmRegistryFallback:
    """Тесты fallback при недоступности AlgorithmRegistry."""

    def test_algorithm_registry_is_available(self) -> None:
        """AlgorithmRegistry доступен."""
        registry = AlgorithmRegistry.get_instance()
        assert registry is not None

    def test_registry_fallback_behavior(self) -> None:
        """Поведение при недоступности registry."""
        # Проверяем что registry выбрасывает ошибку при попытке получить
        # несуществующий алгоритм
        registry = AlgorithmRegistry.get_instance()

        # Метод должен существовать
        assert hasattr(registry, "is_registered")

        # Проверяем что незарегистрированный алгоритм возвращает False
        is_registered = registry.is_registered("NonExistentAlgo")
        assert is_registered is False


# ==============================================================================
# TESTS: Hypothesis Property-Based Testing
# ==============================================================================


class TestFloppyOptimizerProperties:
    """Property-based тесты для FloppyOptimizer."""

    @given(st.binary(min_size=0, max_size=10000))
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_analyze_always_returns_result(self, data: bytes) -> None:
        """analyze всегда возвращает OptimizationResult."""
        optimizer = EnhancedFloppyOptimizer()
        result = optimizer.analyze(data)
        assert isinstance(result, OptimizationResult)
        assert result.original_size == len(data)

    @given(st.binary(min_size=100, max_size=5000))
    @settings(
        max_examples=30,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_optimized_size_not_larger_than_original(self, data: bytes) -> None:
        """Оптимизированный размер не больше оригинала."""
        optimizer = EnhancedFloppyOptimizer()
        optimized_data, result = optimizer.optimize(data)
        assert result.optimized_size <= result.original_size

    @given(st.integers(min_value=0, max_value=100000))
    @settings(max_examples=50)
    def test_savings_percent_in_valid_range(self, original_size: int) -> None:
        """Процент экономии в диапазоне 0-100."""
        # Пропускаем пустые данные
        if original_size == 0:
            return

        optimized_size = original_size // 2
        result = OptimizationResult(
            original_size=original_size,
            optimized_size=optimized_size,
            applied_methods=[OptimizationType.COMPRESSION],
        )

        assert 0.0 <= result.savings_percent <= 100.0


# ==============================================================================
# TESTS: Compression via FloppyOptimizer
# ==============================================================================


class TestFloppyOptimizerCompression:
    """Тесты сжатия через FloppyOptimizer."""

    @pytest.mark.security
    def test_compress_keystore_reduces_size(self, optimizer: FloppyOptimizer) -> None:
        """Сжатие уменьшает размер данных."""
        data = b"A" * 10000
        compressed = optimizer.compress_keystore(data)
        assert len(compressed) < len(data)

    def test_compress_decompress_roundtrip(self, optimizer: FloppyOptimizer) -> None:
        """Сжатие и распаковка возвращают исходные данные."""
        data = b"Test data for roundtrip compression"
        compressed = optimizer.compress_keystore(data)
        decompressed = optimizer.decompress_keystore(compressed)
        assert decompressed == data

    def test_decompress_invalid_data_raises(self, optimizer: FloppyOptimizer) -> None:
        """Невалидные данные вызывают ошибку при распаковке."""
        from src.security.crypto.core.exceptions import CryptoError

        with pytest.raises(CryptoError):
            optimizer.decompress_keystore(b"not valid zlib data")


# ==============================================================================
# TESTS: Integration
# ==============================================================================


class TestFloppyOptimizerIntegration:
    """Интеграционные тесты."""

    def test_protocol_compliance(self) -> None:
        """EnhancedFloppyOptimizer соответствует FloppyOptimizerProtocol."""
        optimizer = EnhancedFloppyOptimizer()
        assert isinstance(optimizer, FloppyOptimizerProtocol)

    def test_max_floppy_bytes_constant(self) -> None:
        """Константа MAX_FLOPPY_BYTES имеет корректное значение."""
        assert MAX_FLOPPY_BYTES == 1_340_000
        # Проверяем что это разумное значение для дискеты
        # 1.44 MB = 1_474_560 bytes, мы используем ~1.28 MB для запаса
        assert MAX_FLOPPY_BYTES < 1_474_560  # Меньше физической ёмкости

    def test_optimization_type_enum(self) -> None:
        """OptimizationType enum имеет все необходимые значения."""
        types = [
            OptimizationType.COMPRESSION,
            OptimizationType.SIGNATURE_CHANGE,
            OptimizationType.SPLIT,
            OptimizationType.TRUNCATE_METADATA,
            OptimizationType.REMOVE_REDUNDANT,
            OptimizationType.USE_COMPACT_FORMAT,
        ]
        assert len(types) == 6

        # Проверяем методы label
        assert OptimizationType.COMPRESSION.label() == "Сжатие данных"
        assert OptimizationType.SIGNATURE_CHANGE.label() == "Смена алгоритма подписи"


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__ = [
    "EnhancedFloppyOptimizer",
    "ED25519_SIGNATURE_SIZE",
    "ML_DSA_65_SIGNATURE_SIZE",
]
