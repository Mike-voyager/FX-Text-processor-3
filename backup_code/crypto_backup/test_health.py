# -*- coding: utf-8 -*-
"""Тесты для health.py - health check криптоподсистемы."""
from __future__ import annotations

import pytest

from src.security.crypto.health import crypto_health_check


class TestCryptoHealthCheck:
    """Тесты для crypto_health_check."""

    def test_health_check_returns_dict(self) -> None:
        """Health check возвращает словарь."""
        results = crypto_health_check()

        assert isinstance(results, dict)
        assert len(results) > 0

    def test_health_check_includes_symmetric_ciphers(self) -> None:
        """Health check включает симметричные шифры."""
        results = crypto_health_check()

        assert "aes-256-gcm" in results
        assert "chacha20-poly1305" in results
        # XChaCha20 removed

    def test_health_check_includes_asymmetric_algorithms(self) -> None:
        """Health check включает асимметричные алгоритмы."""
        results = crypto_health_check()

        assert "ed25519" in results
        assert "rsa-4096" in results
        assert "ecdsa-p256" in results

    def test_health_check_includes_pqc(self) -> None:
        """Health check включает пост-квантовую криптографию."""
        results = crypto_health_check()

        assert "optional-kyber-768" in results
        assert "optional-dilithium-3" in results

    def test_health_check_includes_password_hashing(self) -> None:
        """Health check включает password hashing."""
        results = crypto_health_check()

        assert "passwords-argon2id" in results
        assert "passwords-pbkdf2" in results

    def test_health_check_includes_kdf(self) -> None:
        """Health check включает key derivation."""
        results = crypto_health_check()

        assert "kdf-argon2" in results
        assert "kdf-pbkdf2" in results

    def test_health_check_includes_hashing(self) -> None:
        """Health check включает функции хеширования."""
        results = crypto_health_check()

        assert "hashing" in results
        assert "optional-blake3" in results

    def test_health_check_includes_standards(self) -> None:
        """Health check включает стандарты PIV/OpenPGP."""
        results = crypto_health_check()

        assert "piv-rsa" in results
        assert "openpgp-brainpool" in results

    def test_health_check_includes_storage(self) -> None:
        """Health check включает secure storage."""
        results = crypto_health_check()

        assert "secure-storage" in results

    def test_health_check_includes_legacy(self) -> None:
        """Health check включает устаревшие протоколы."""
        results = crypto_health_check()

        assert "legacy-3des" in results
        assert "legacy-dsa" in results

    def test_health_check_all_values_are_bool(self) -> None:
        """Все значения в results - bool."""
        results = crypto_health_check()

        for key, value in results.items():
            assert isinstance(
                value, bool
            ), f"{key} должен быть bool, получен {type(value)}"

    def test_health_check_core_algorithms_pass(self) -> None:
        """Основные алгоритмы должны пройти проверку."""
        results = crypto_health_check()

        # Core algorithms (должны быть доступны всегда)
        core = [
            "aes-256-gcm",
            "chacha20-poly1305",
            "ed25519",
            "rsa-4096",
            "ecdsa-p256",
            "passwords-pbkdf2",
            "kdf-pbkdf2",
            "hashing",
            "secure-storage",
            "openpgp-brainpool",
        ]

        for algo in core:
            assert results.get(algo) is True, f"Core algorithm {algo} failed"

    def test_health_check_optional_algorithms_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Опциональные алгоритмы логируются при недоступности."""
        with caplog.at_level("INFO"):
            results = crypto_health_check()

        # PQC - опциональные зависимости
        if not results.get("optional-kyber-768"):
            assert any("Kyber" in r.message for r in caplog.records)

        if not results.get("optional-dilithium-3"):
            assert any("Dilithium" in r.message for r in caplog.records)

        if not results.get("optional-blake3"):
            assert any("BLAKE3" in r.message for r in caplog.records)

    def test_health_check_legacy_marked_deprecated(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Устаревшие протоколы помечены DEPRECATED."""
        with caplog.at_level("WARNING"):
            results = crypto_health_check()

        if results.get("legacy-3des"):
            assert any("Triple-DES is DEPRECATED" in r.message for r in caplog.records)

        if results.get("legacy-dsa"):
            assert any("DSA is DEPRECATED" in r.message for r in caplog.records)

    def test_health_check_passes_overall(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Health check в целом проходит успешно (игнорируя опциональные)."""
        with caplog.at_level("INFO"):
            results = crypto_health_check()

        # Отфильтровываем опциональные алгоритмы
        required_results = {
            k: v for k, v in results.items() if not k.startswith("optional-")
        }

        failures = [k for k, v in required_results.items() if not v]

        assert len(failures) == 0, f"Required algorithms failed: {failures}"

    @pytest.mark.parametrize(
        "algorithm",
        [
            "aes-256-gcm",
            "chacha20-poly1305",
            "ed25519",
            "rsa-4096",
            "ecdsa-p256",
            "passwords-pbkdf2",
            "hashing",
            "piv-rsa",
            "openpgp-brainpool",
        ],
    )
    def test_individual_algorithm_health(self, algorithm: str) -> None:
        """Тест отдельных алгоритмов."""
        results = crypto_health_check()

        # Каждый из этих алгоритмов должен быть протестирован
        assert algorithm in results

        # Они должны быть True (core dependencies)
        assert results[algorithm] is True, f"{algorithm} should pass health check"

    def test_health_check_no_exceptions_raised(self) -> None:
        """Health check не выбрасывает исключения."""
        try:
            results = crypto_health_check()
            assert isinstance(results, dict)
        except Exception as e:
            pytest.fail(f"Health check raised exception: {e}")

    def test_health_check_count_total_algorithms(self) -> None:
        """Health check проверяет правильное количество алгоритмов."""
        results = crypto_health_check()

        # Ожидаем минимум 18 групп алгоритмов
        expected_min = 18
        assert (
            len(results) >= expected_min
        ), f"Expected at least {expected_min} algorithm groups, got {len(results)}"
