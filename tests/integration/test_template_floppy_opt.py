"""Интеграционные тесты Floppy Optimizer для шаблонов.

E2E тесты для проверки полного цикла оптимизации шаблонов форм
для сохранения на дискеты 3.5" (1.44 MB).

Test Scenarios:
    1. Оптимизация большого шаблона до размера дискеты
    2. Невозможность оптимизации слишком большого шаблона
    3. Выбор алгоритма подписи (ML-DSA-65 vs Ed25519)
    4. Сохранение функциональности после оптимизации
    5. Многопоточная оптимизация

Coverage: integration tests with real FloppyOptimizer
Author: Mike Voyager
Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import gzip
import json
import secrets
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Generator
from uuid import uuid4

import pytest

from src.documents.constructor.form_constructor import FormTemplate
from src.documents.format.template_format import TemplateSerializer
from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
from src.services.protocols.template_security import (
    MAX_FLOPPY_BYTES,
    OptimizationType,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def optimizer() -> FloppyOptimizer:
    """Фикстура для создания реального FloppyOptimizer."""
    return FloppyOptimizer()


@pytest.fixture
def serializer() -> TemplateSerializer:
    """Фикстура для создания TemplateSerializer."""
    return TemplateSerializer()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Временная директория для тестовых файлов."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def create_large_template(
    serializer: TemplateSerializer,
    size_target: int = 1_600_000,  # ~1.6MB
    algorithm: str = "Ed25519",
) -> bytes:
    """Создаёт шаблон указанного размера с JSON-данными.

    Args:
        serializer: TemplateSerializer для сериализации.
        size_target: Целевой размер в байтах.
        algorithm: Алгоритм подписи для использования.

    Returns:
        Сериализованные данные шаблона.
    """
    # Базовый шаблон
    template = FormTemplate(
        type_code="DVN",
        subtype="44",
        series="K53",
        field_defaults={},
        metadata={
            "algorithm": algorithm,
            "description": "Large template for floppy optimization testing",
            "created_at": "2026-04-11T00:00:00",
        },
    )

    # Добавляем поля для увеличения размера
    num_fields = (size_target // 1000) + 100  # ~1KB per field
    for i in range(num_fields):
        template.metadata[f"field_{i}"] = {
            "name": f"Field {i}",
            "type": "text",
            "description": f"Description for field {i}",
            "help_text": "This is a help text that adds size to the template",
            "validation_rules": ["required", "max_length:255"],
            "default_value": f"default_value_{i}_" + "x" * 100,
        }

    # Генерируем ключи если нужно подписать
    private_key, public_key = serializer.generate_keypair()

    # Сериализуем с подписью
    data = serializer.serialize_template(template, sign=True, private_key=private_key)

    # Если нужно больше размера - добавляем padding через JSON
    current_size = len(data)
    if current_size < size_target:
        json_obj = json.loads(data.decode("utf-8"))
        padding_needed = size_target - current_size
        json_obj["_padding"] = "x" * padding_needed
        data = json.dumps(json_obj, ensure_ascii=False, indent=2).encode("utf-8")

    return data


def create_incompressible_template(
    serializer: TemplateSerializer,
    size_target: int = 5_500_000,  # ~5.5MB
) -> bytes:
    """Создаёт шаблон с несжимаемыми данными (random bytes).

    Args:
        serializer: TemplateSerializer для сериализации.
        size_target: Целевой размер в байтах.

    Returns:
        Сериализованные данные с random payload.
    """
    template = FormTemplate(
        type_code="INV",
        subtype="01",
        series="TEST",
        field_defaults={},
        metadata={"description": "Incompressible template"},
    )

    data = serializer.serialize_template(template, sign=False)

    # Добавляем random data (плохо сжимается)
    json_obj = json.loads(data.decode("utf-8"))
    random_data = bytes(secrets.randbelow(256) for _ in range(size_target))
    json_obj["_random_payload"] = random_data.hex()

    return json.dumps(json_obj, ensure_ascii=False, indent=2).encode("utf-8")


# =============================================================================
# TESTS: Scenario 1 - Optimize large template to floppy size
# =============================================================================


@pytest.mark.integration
class TestFloppyOptimizationE2E:
    """E2E тесты оптимизации шаблонов до размера дискеты."""

    def test_optimize_large_template_to_floppy_size(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
        temp_dir: Path,
    ) -> None:
        """Оптимизация шаблона >1.5MB до размера <1.28MB.

        Steps:
            1. Создать шаблон >1.5MB
            2. Применить все оптимизации через FloppyOptimizer
            3. Проверить что размер <1.28MB
            4. Экспортировать в файл
        """
        # Step 1: Create template > 1.5MB
        template_data = create_large_template(serializer, size_target=1_600_000)
        original_size = len(template_data)

        assert original_size > 1_500_000, f"Template too small: {original_size}"
        assert original_size > MAX_FLOPPY_BYTES, "Template should exceed floppy limit"

        # Step 2: Apply optimizations
        optimized_data, result = optimizer.optimize(
            template_data,
            target_size=MAX_FLOPPY_BYTES,
            allowed_methods={
                OptimizationType.COMPRESSION,
                OptimizationType.USE_COMPACT_FORMAT,
                OptimizationType.REMOVE_REDUNDANT,
            },
        )

        # Step 3: Verify size < 1.28MB
        assert result.fits_on_floppy, (
            f"Template still too large: {result.optimized_size:,} bytes "
            f"(limit: {MAX_FLOPPY_BYTES:,})"
        )
        assert len(optimized_data) <= MAX_FLOPPY_BYTES, "Optimized data exceeds limit"

        # Verify compression was applied
        assert OptimizationType.COMPRESSION in result.applied_methods
        assert result.savings_percent > 0

        # Step 4: Export to file
        output_path = temp_dir / "optimized_template.fxstpl"
        output_path.write_bytes(optimized_data)

        assert output_path.exists()
        assert output_path.stat().st_size <= MAX_FLOPPY_BYTES

    def test_analyze_large_template_before_optimization(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Анализ шаблона перед оптимизацией даёт корректные рекомендации."""
        template_data = create_large_template(serializer, size_target=1_600_000)

        result = optimizer.analyze(template_data)

        assert result.original_size == len(template_data)
        assert result.original_size > MAX_FLOPPY_BYTES
        # Note: fits_on_floppy may be True after compression analysis

        # Should have recommendations for optimization
        assert len(result.recommendations) > 0
        assert any(
            "Ed25519" in rec or "сжатие" in rec.lower() or "compact" in rec.lower()
            for rec in result.recommendations
        )


# =============================================================================
# TESTS: Scenario 2 - Cannot optimize oversized template
# =============================================================================


@pytest.mark.integration
class TestFloppyOptimizationFailure:
    """Тесты невозможности оптимизации слишком больших шаблонов."""

    def test_cannot_optimize_oversized_template(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Шаблон >5MB не может быть оптимизирован до размера дискеты.

        Steps:
            1. Создать шаблон >5MB с несжимаемыми данными
            2. Проверить что даже с оптимизацией не помещается
            3. Получить сообщение об ошибке
        """
        # Create incompressible template > 5MB
        template_data = create_incompressible_template(serializer, size_target=5_500_000)

        assert len(template_data) > 5_000_000, f"Template too small: {len(template_data)}"

        # Analysis should show it won't fit
        analysis = optimizer.analyze(template_data)
        assert not analysis.fits_on_floppy
        assert len(analysis.warnings) > 0

        # Optimization should raise RuntimeError
        with pytest.raises(RuntimeError) as exc_info:
            optimizer.optimize(
                template_data,
                target_size=MAX_FLOPPY_BYTES,
            )

        error_msg = str(exc_info.value)
        assert "превышение" in error_msg.lower() or "overflow" in error_msg.lower()

    def test_analyze_shows_warning_for_oversized(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Анализ показывает предупреждение для слишком больших данных."""
        template_data = create_incompressible_template(serializer, size_target=5_500_000)

        result = optimizer.analyze(template_data)

        assert not result.fits_on_floppy
        assert len(result.warnings) > 0
        assert any(
            "превышение" in w.lower() or "разделение" in w.lower()
            for w in result.warnings + result.recommendations
        )


# =============================================================================
# TESTS: Scenario 3 - Signature algorithm selection
# =============================================================================


@pytest.mark.integration
class TestSignatureAlgorithmSelection:
    """Тесты выбора алгоритма подписи для оптимизации."""

    def test_ed25519_savings_over_mldsa65(
        self,
        optimizer: FloppyOptimizer,
    ) -> None:
        """Выбор Ed25519 вместо ML-DSA-65 экономит ~3KB.

        Steps:
            1. Создать шаблон с ML-DSA-65
            2. Оптимизатор предлагает Ed25519
            3. Экономия ~3KB
        """
        # Calculate signature sizes
        ed25519_size = optimizer.estimate_signature_size("Ed25519", include_key=True)
        mldsa65_size = optimizer.estimate_signature_size("ML-DSA-65", include_key=True)

        # Ed25519: 64 (sig) + 32 (key) = 96 bytes
        assert ed25519_size == 96, f"Ed25519 size mismatch: {ed25519_size}"

        # ML-DSA-65: 3309 (sig) + 1952 (key) = 5261 bytes
        assert mldsa65_size == 5261, f"ML-DSA-65 size mismatch: {mldsa65_size}"

        # Savings should be ~5.1KB
        savings = mldsa65_size - ed25519_size
        expected_savings = 5261 - 96  # 5165 bytes
        assert savings == expected_savings
        assert savings > 3000, f"Expected >3KB savings, got {savings} bytes"

    def test_recommendations_include_signature_change(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Рекомендации включают смену алгоритма подписи."""
        # Create template close to limit
        template_data = create_large_template(serializer, size_target=1_400_000)

        recommendations = optimizer.get_recommendations(template_data)

        # Should recommend Ed25519
        assert any("Ed25519" in rec for rec in recommendations)

        # Should mention size difference
        ed25519_rec = [r for r in recommendations if "Ed25519" in r]
        assert len(ed25519_rec) > 0


# =============================================================================
# TESTS: Scenario 4 - Functionality preservation after optimization
# =============================================================================


@pytest.mark.integration
class TestFunctionalityPreservation:
    """Тесты сохранения функциональности после оптимизации."""

    def test_template_structure_preserved_after_optimization(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Структура шаблона сохраняется после оптимизации.

        Steps:
            1. Оптимизировать шаблон
            2. Загрузить и проверить структуру
            3. Все поля на месте
        """
        # Create template with known fields
        template = FormTemplate(
            type_code="DVN",
            subtype="44",
            series="K53",
            field_defaults={
                "customer_name": "",
                "amount": 0.0,
                "date": "",
            },
            metadata={
                "version": "1.0",
                "author": "Test",
                "description": "Test template",
            },
        )

        private_key, public_key = serializer.generate_keypair()
        original_data = serializer.serialize_template(
            template, sign=True, private_key=private_key
        )

        # Store original structure
        original_json = json.loads(original_data.decode("utf-8"))
        original_template_data = original_json.get("template", {})

        # Optimize
        optimized_data, result = optimizer.optimize(
            original_data,
            target_size=MAX_FLOPPY_BYTES,
        )

        # Decompress and verify structure
        try:
            decompressed = gzip.decompress(optimized_data)
            optimized_json = json.loads(decompressed.decode("utf-8"))
        except (gzip.BadGzipFile, OSError):
            # Data might not be gzipped if it was already small
            optimized_json = json.loads(optimized_data.decode("utf-8"))

        optimized_template_data = optimized_json.get("template", {})

        # Verify structure preserved
        assert optimized_template_data.get("type_code") == template.type_code
        assert optimized_template_data.get("subtype") == template.subtype
        assert optimized_template_data.get("series") == template.series

        # Verify metadata preserved
        opt_metadata = optimized_template_data.get("metadata", {})
        assert opt_metadata.get("version") == "1.0"
        assert opt_metadata.get("author") == "Test"

    def test_deserialization_after_optimization(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Десериализация работает после оптимизации."""
        # Create and sign template
        template = FormTemplate(
            type_code="INV",
            subtype="01",
            series="TEST",
        )

        private_key, public_key = serializer.generate_keypair()
        original_data = serializer.serialize_template(
            template, sign=True, private_key=private_key
        )

        # Optimize
        optimized_data, _ = optimizer.optimize(original_data)

        # Try to decompress and parse
        try:
            decompressed = gzip.decompress(optimized_data)
            json_data = json.loads(decompressed.decode("utf-8"))
        except (gzip.BadGzipFile, OSError):
            json_data = json.loads(optimized_data.decode("utf-8"))

        # Verify it's valid JSON with expected structure
        assert "template" in json_data or "format_version" in json_data


# =============================================================================
# TESTS: Scenario 5 - Multi-threaded optimization
# =============================================================================


@pytest.mark.integration
class TestMultiThreadedOptimization:
    """Тесты многопоточной оптимизации."""

    def test_parallel_template_optimization(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Оптимизация нескольких шаблонов параллельно.

        Steps:
            1. Создать несколько шаблонов
            2. Оптимизировать параллельно через ThreadPoolExecutor
            3. Проверить thread-safety
        """
        # Create multiple templates
        templates: list[bytes] = []
        for i in range(5):
            tpl = create_large_template(
                serializer,
                size_target=1_400_000 + i * 50_000,
            )
            templates.append(tpl)

        # Optimize in parallel
        results: list[tuple[bytes, Any]] = []

        def optimize_template(data: bytes) -> tuple[bytes, Any]:
            """Helper function for thread pool."""
            return optimizer.optimize(
                data,
                target_size=MAX_FLOPPY_BYTES,
            )

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(optimize_template, tpl): i
                for i, tpl in enumerate(templates)
            }

            for future in as_completed(futures):
                idx = futures[future]
                try:
                    optimized_data, result = future.result()
                    results.append((optimized_data, result))
                except Exception as e:
                    pytest.fail(f"Optimization {idx} failed: {e}")

        # All should complete successfully
        assert len(results) == len(templates)

        # Verify all results are valid
        for optimized_data, result in results:
            assert len(optimized_data) <= MAX_FLOPPY_BYTES
            assert result.fits_on_floppy

    def test_optimizer_thread_safety(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """FloppyOptimizer thread-safe при одновременном доступе."""
        template = create_large_template(serializer, size_target=1_500_000)

        errors: list[Exception] = []
        results: list[bool] = []

        def analyze_and_optimize() -> None:
            """Analyze and optimize in thread."""
            try:
                # Analyze
                analysis = optimizer.analyze(template)

                # Optimize
                optimized_data, result = optimizer.optimize(
                    template,
                    target_size=MAX_FLOPPY_BYTES,
                )

                results.append(result.fits_on_floppy)
            except Exception as e:
                errors.append(e)

        # Run multiple threads concurrently
        import threading

        threads = [
            threading.Thread(target=analyze_and_optimize)
            for _ in range(5)
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # No errors should occur
        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(results) == 5
        assert all(results)


# =============================================================================
# TESTS: Additional edge cases
# =============================================================================


@pytest.mark.integration
class TestFloppyOptimizationEdgeCases:
    """Граничные случаи оптимизации."""

    def test_exact_floppy_size_boundary(
        self,
        optimizer: FloppyOptimizer,
        serializer: TemplateSerializer,
    ) -> None:
        """Шаблон ровно на границе 1.28MB."""
        # Create template at exact boundary
        template = FormTemplate(
            type_code="TST",
            subtype="00",
            series="BND",
        )

        data = serializer.serialize_template(template, sign=False)

        # Add padding to reach exactly MAX_FLOPPY_BYTES
        json_obj = json.loads(data.decode("utf-8"))
        padding_size = MAX_FLOPPY_BYTES - len(data) - 100  # Leave some margin
        if padding_size > 0:
            json_obj["_padding"] = "x" * padding_size
            data = json.dumps(json_obj, ensure_ascii=False, indent=2).encode("utf-8")

        # Should fit or be optimizable
        result = optimizer.analyze(data)

        if len(data) > MAX_FLOPPY_BYTES:
            # Should be able to optimize
            optimized_data, opt_result = optimizer.optimize(data)
            assert opt_result.fits_on_floppy or not opt_result.warnings

    def test_compression_ratio_calculation(
        self,
        optimizer: FloppyOptimizer,
    ) -> None:
        """Правильный расчёт коэффициента сжатия."""
        # Highly compressible data
        compressible = b"A" * 10000

        result = optimizer.analyze(compressible)

        if result.optimized_size < result.original_size:
            assert result.savings_percent > 0
            assert result.savings_bytes > 0

    def test_recommendations_for_json_data(
        self,
        optimizer: FloppyOptimizer,
    ) -> None:
        """Рекомендации для JSON-данных."""
        json_data = json.dumps(
            {"key": "value", "nested": {"data": "test"}},
            indent=2,
        ).encode("utf-8")

        recommendations = optimizer.get_recommendations(json_data)

        # Should mention compact format
        assert any(
            "compact" in rec.lower() or "json" in rec.lower()
            for rec in recommendations
        )


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestFloppyOptimizationE2E",
    "TestFloppyOptimizationFailure",
    "TestSignatureAlgorithmSelection",
    "TestFunctionalityPreservation",
    "TestMultiThreadedOptimization",
    "TestFloppyOptimizationEdgeCases",
]
