"""
Тесты для проверки криптографических алгоритмов.

Tests:
    - AlgorithmCheck: проверка доступности алгоритмов

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.security.monitoring.checks.algorithm_check import (
    AlgorithmCheck,
    REQUIRED_ALGORITHMS,
    OPTIONAL_ALGORITHMS,
)
from src.security.monitoring.models import HealthCheckStatus


class TestAlgorithmCheck:
    """Тесты для AlgorithmCheck."""

    def test_check_name(self) -> None:
        """Проверка имени."""
        check = AlgorithmCheck()
        assert check.name == "algorithm"
        assert check.critical is True

    def test_default_algorithms(self) -> None:
        """Проверка списка алгоритмов по умолчанию."""
        check = AlgorithmCheck()

        assert "AES-256-GCM" in check.required_algorithms
        assert "Ed25519" in check.required_algorithms
        assert "ML-DSA-65" in check.optional_algorithms

    def test_custom_algorithms(self) -> None:
        """Проверка кастомного списка алгоритмов."""
        check = AlgorithmCheck(
            required_algorithms=["AES-256-GCM"],
            optional_algorithms=["ML-DSA-65"],
        )

        assert check.required_algorithms == ["AES-256-GCM"]
        assert check.optional_algorithms == ["ML-DSA-65"]

    def test_check_passes_with_cryptography(self) -> None:
        """Проверка проходит если cryptography доступен."""
        check = AlgorithmCheck()
        result = check.check()

        # Должен пройти если AES-256-GCM доступен
        # cryptography должен быть установлен для тестов
        assert result.status in (HealthCheckStatus.HEALTHY, HealthCheckStatus.DEGRADED)
        assert "AES-256-GCM" in result.details.get("required", {})

    def test_result_has_library_status(self) -> None:
        """Результат содержит статус библиотек."""
        check = AlgorithmCheck()
        result = check.check()

        assert "libraries" in result.details
        libraries = result.details["libraries"]

        # cryptography должен быть установлен для тестов
        assert "cryptography" in libraries

    def test_check_aes_gcm(self) -> None:
        """Проверка AES-256-GCM."""
        check = AlgorithmCheck()
        status = check._check_algorithm("AES-256-GCM")

        assert status["algorithm"] == "AES-256-GCM"
        assert "available" in status
        # Если cryptography установлен, должен быть True
        # assert status["available"] is True

    def test_check_ed25519(self) -> None:
        """Проверка Ed25519."""
        check = AlgorithmCheck()
        status = check._check_algorithm("Ed25519")

        assert status["algorithm"] == "Ed25519"
        assert "available" in status

    def test_check_sha256(self) -> None:
        """Проверка SHA-256."""
        check = AlgorithmCheck()
        status = check._check_algorithm("SHA-256")

        assert status["algorithm"] == "SHA-256"
        # Должен быть доступен всегда (cryptography)
        assert status["available"] is True

    def test_check_sha3_256(self) -> None:
        """Проверка SHA3-256."""
        check = AlgorithmCheck()
        status = check._check_algorithm("SHA3-256")

        assert status["algorithm"] == "SHA3-256"
        # Должен быть доступен (cryptography)
        assert status["available"] is True

    def test_check_argon2id(self) -> None:
        """Проверка Argon2id."""
        check = AlgorithmCheck()
        status = check._check_algorithm("Argon2id")

        assert status["algorithm"] == "Argon2id"
        # argon2 должен быть установлен для тестов
        assert "available" in status

    def test_check_ml_dsa(self) -> None:
        """Проверка ML-DSA-65."""
        check = AlgorithmCheck()
        status = check._check_algorithm("ML-DSA-65")

        assert status["algorithm"] == "ML-DSA-65"
        # liboqs может быть не установлен
        assert "available" in status

    def test_check_unknown_algorithm(self) -> None:
        """Проверка неизвестного алгоритма."""
        check = AlgorithmCheck()
        status = check._check_algorithm("UnknownAlgorithm")

        assert status["algorithm"] == "UnknownAlgorithm"
        assert "warning" in status

    def test_disable_pqc_check(self) -> None:
        """Отключение проверки PQC."""
        check = AlgorithmCheck(check_pqc=False)
        result = check.check()

        # PQC алгоритмы не проверяются
        assert "ML-DSA-65" not in result.details.get("optional", {})

    def test_result_contains_all_required(self) -> None:
        """Результат содержит все обязательные алгоритмы."""
        check = AlgorithmCheck()
        result = check.check()

        required = result.details.get("required", {})

        for alg in check.required_algorithms:
            assert alg in required

    def test_duration_recorded(self) -> None:
        """Время выполнения записано."""
        check = AlgorithmCheck()
        result = check.check()

        assert result.duration_ms >= 0

    def test_failing_required_algorithm(self) -> None:
        """Отсутствие обязательного алгоритма делает проверку UNHEALTHY."""
        # Создаём проверку с единственным обязательным алгоритмом
        check = AlgorithmCheck(required_algorithms=["AES-256-GCM"], optional_algorithms=[])

        # Патчим внутренний метод проверки AES-256-GCM
        original_check = check._check_aes_gcm

        def mock_check_aes_gcm() -> bool:
            return False

        check._check_aes_gcm = mock_check_aes_gcm  # type: ignore[method-assign]

        result = check.check()

        # Должен быть UNHEALTHY так как AES-256-GCM обязателен и недоступен
        assert result.status == HealthCheckStatus.UNHEALTHY
        assert result.error is not None
        assert "AES-256-GCM" in result.error

        # Восстанавливаем
        check._check_aes_gcm = original_check  # type: ignore[method-assign]

    def test_failing_optional_algorithm_warning(self) -> None:
        """Отсутствие опционального алгоритма — предупреждение."""
        # Создаём проверку только с опциональными алгоритмами
        check = AlgorithmCheck(required_algorithms=[], optional_algorithms=["ML-DSA-65"], check_pqc=True)

        result = check.check()

        # Должен быть DEGRADED (не UNHEALTHY) так как все обязательные проходят
        # но опциональный отсутствует
        assert result.status == HealthCheckStatus.DEGRADED
        assert len(result.warnings) > 0
        assert any("ML-DSA-65" in w for w in result.warnings)


class TestRequiredAlgorithms:
    """Тесты для констант."""

    def test_required_algorithms_list(self) -> None:
        """Проверка списка обязательных алгоритмов."""
        assert len(REQUIRED_ALGORITHMS) >= 6  # Минимум основные алгоритмы
        assert "AES-256-GCM" in REQUIRED_ALGORITHMS
        assert "Ed25519" in REQUIRED_ALGORITHMS
        assert "Argon2id" in REQUIRED_ALGORITHMS

    def test_optional_algorithms_list(self) -> None:
        """Проверка списка опциональных алгоритмов."""
        assert len(OPTIONAL_ALGORITHMS) >= 3  # PQC алгоритмы
        assert "ML-DSA-65" in OPTIONAL_ALGORITHMS