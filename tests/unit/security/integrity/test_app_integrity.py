"""
Тесты для модуля integrity: AppIntegrityChecker.

Проверка целостности бинарника приложения.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from src.security.integrity.app_integrity import (
    HASH_BUFFER_SIZE,
    HASH_FILE_NAME,
    AppIntegrityChecker,
)
from src.security.integrity.exceptions import IntegrityCheckError
from src.security.integrity.models import IntegrityCheckType


class TestAppIntegrityChecker:
    """Тесты AppIntegrityChecker."""

    def test_compute_hash_sha3_256(self, tmp_path: Path) -> None:
        """Тест вычисления SHA3-256 хеша."""
        # Создаём тестовый файл
        test_file = tmp_path / "test_app.py"
        content = b"test content for hashing"
        test_file.write_bytes(content)

        # Вычисляем ожидаемый хеш
        expected_hash = hashlib.sha3_256(content).hexdigest()

        checker = AppIntegrityChecker(app_path=test_file)
        actual_hash = checker.compute_hash()

        assert actual_hash == expected_hash
        assert len(actual_hash) == 64  # SHA3-256 = 64 hex chars

    def test_compute_hash_empty_file(self, tmp_path: Path) -> None:
        """Тест хеша пустого файла."""
        test_file = tmp_path / "empty.py"
        test_file.touch()

        checker = AppIntegrityChecker(app_path=test_file)
        actual_hash = checker.compute_hash()

        # SHA3-256 пустого файла
        expected_hash = hashlib.sha3_256(b"").hexdigest()
        assert actual_hash == expected_hash

    def test_compute_hash_large_file(self, tmp_path: Path) -> None:
        """Тест хеша большого файла (> HASH_BUFFER_SIZE)."""
        test_file = tmp_path / "large.bin"
        # Файл больше буфера
        content = os.urandom(HASH_BUFFER_SIZE * 2)
        test_file.write_bytes(content)

        expected_hash = hashlib.sha3_256(content).hexdigest()

        checker = AppIntegrityChecker(app_path=test_file)
        actual_hash = checker.compute_hash()

        assert actual_hash == expected_hash

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Тест ошибки при отсутствии файла."""
        nonexistent = tmp_path / "nonexistent.py"

        checker = AppIntegrityChecker(app_path=nonexistent)

        with pytest.raises(IntegrityCheckError) as exc_info:
            checker.compute_hash()

        assert "не найден" in str(exc_info.value)

    def test_check_integrity_pass(self, tmp_path: Path) -> None:
        """Тест успешной проверки целостности."""
        test_file = tmp_path / "app.py"
        content = b"valid application"
        test_file.write_bytes(content)

        expected_hash = hashlib.sha3_256(content).hexdigest()
        checker = AppIntegrityChecker(
            expected_hash=expected_hash,
            app_path=test_file,
        )

        result = checker.check_integrity()

        assert result.passed is True
        assert result.check_type == IntegrityCheckType.APP_BINARY
        assert result.hash_match is True
        assert result.actual_hash == expected_hash
        assert result.error_message is None

    def test_check_integrity_fail(self, tmp_path: Path) -> None:
        """Тест неуспешной проверки целостности."""
        test_file = tmp_path / "app.py"
        test_file.write_bytes(b"original content")

        # Хеш от другого содержимого
        wrong_hash = hashlib.sha3_256(b"modified content").hexdigest()
        checker = AppIntegrityChecker(
            expected_hash=wrong_hash,
            app_path=test_file,
        )

        result = checker.check_integrity()

        assert result.passed is False
        assert result.hash_match is False
        assert "не совпадает" in (result.error_message or "")

    def test_check_integrity_no_expected_hash(self, tmp_path: Path) -> None:
        """Тест проверки без ожидаемого хеша."""
        test_file = tmp_path / "app.py"
        test_file.write_bytes(b"some content")

        checker = AppIntegrityChecker(expected_hash=None, app_path=test_file)
        result = checker.check_integrity()

        # Должен вернуть passed=True с предупреждением
        assert result.passed is True
        assert len(result.warnings) > 0
        assert any("Ожидаемый хеш не задан" in w for w in result.warnings)

    def test_load_expected_hash_from_file(self, tmp_path: Path) -> None:
        """Тест загрузки хеша из файла."""
        test_file = tmp_path / "app.py"
        test_file.write_bytes(b"app content")

        expected_hash = hashlib.sha3_256(b"app content").hexdigest()
        hash_file = tmp_path / HASH_FILE_NAME
        hash_file.write_text(f"{expected_hash}  app.py\n", encoding="utf-8")

        checker = AppIntegrityChecker(
            app_path=test_file,
            hash_file_path=hash_file,
        )

        assert checker.expected_hash == expected_hash

    def test_load_expected_hash_from_env(self, tmp_path: Path, monkeypatch) -> None:
        """Тест загрузки хеша из переменной окружения."""
        test_file = tmp_path / "app.py"
        test_file.write_bytes(b"app content")

        expected_hash = hashlib.sha3_256(b"app content").hexdigest()
        monkeypatch.setenv("APP_HASH", expected_hash.upper())

        checker = AppIntegrityChecker(app_path=test_file)

        assert checker.expected_hash == expected_hash.lower()

    def test_save_current_hash(self, tmp_path: Path) -> None:
        """Тест сохранения текущего хеша в файл."""
        test_file = tmp_path / "app.py"
        test_file.write_bytes(b"app content")

        checker = AppIntegrityChecker(app_path=test_file)
        saved_path = checker.save_current_hash()

        assert saved_path.exists()
        content = saved_path.read_text(encoding="utf-8")
        expected_hash = hashlib.sha3_256(b"app content").hexdigest()
        assert content.startswith(expected_hash)

    def test_hash_case_insensitive(self, tmp_path: Path) -> None:
        """Тест что хеш сравнивается без учёта регистра."""
        test_file = tmp_path / "app.py"
        content = b"app content"
        test_file.write_bytes(content)

        expected_hash = hashlib.sha3_256(content).hexdigest()

        # Передаём хеш в верхнем регистре
        checker = AppIntegrityChecker(
            expected_hash=expected_hash.upper(),
            app_path=test_file,
        )

        result = checker.check_integrity()

        assert result.passed is True

    def test_detect_app_path_frozen(self, tmp_path: Path, monkeypatch) -> None:
        """Тест определения пути для frozen (PyInstaller) приложения."""
        # Создаём файл для frozen executable
        frozen_app = tmp_path / "frozen_app.exe"
        frozen_app.touch()

        # Эмулируем frozen состояние
        # Используем setattr для модификации sys.frozen
        original_frozen = getattr(sys, "frozen", None)
        original_executable = getattr(sys, "executable", None)

        try:
            sys.frozen = True  # type: ignore[attr-defined]
            sys.executable = str(frozen_app)

            checker = AppIntegrityChecker()
            assert "frozen_app.exe" in str(checker.app_path)
        finally:
            # Восстанавливаем оригинальные значения
            if original_frozen is not None:
                sys.frozen = original_frozen  # type: ignore[attr-defined]
            elif hasattr(sys, "frozen"):
                delattr(sys, "frozen")
            if original_executable is not None:
                sys.executable = original_executable

    def test_reproducible_hash(self, tmp_path: Path) -> None:
        """Тест что хеш детерминирован и воспроизводим."""
        test_file = tmp_path / "app.py"
        content = b"reproducible test"
        test_file.write_bytes(content)

        checker = AppIntegrityChecker(app_path=test_file)

        hash1 = checker.compute_hash()
        hash2 = checker.compute_hash()
        hash3 = checker.compute_hash()

        assert hash1 == hash2 == hash3


class TestAppIntegrityCheckerResult:
    """Тесты IntegrityCheckResult."""

    def test_result_to_dict(self, tmp_path: Path) -> None:
        """Тест сериализации результата."""
        from src.security.integrity.models import IntegrityCheckResult

        result = IntegrityCheckResult(
            check_type=IntegrityCheckType.APP_BINARY,
            passed=True,
            expected_hash="a" * 64,
            actual_hash="a" * 64,
            file_path=str(tmp_path / "app.py"),
            algorithm="sha3-256",
        )

        data = result.to_dict()

        assert data["check_type"] == "app_binary"
        assert data["passed"] is True
        assert data["algorithm"] == "sha3-256"
        assert data["actual_hash"] == "aaaaaaaaaaaaaaaa..."  # Обрезан

    def test_result_from_dict(self) -> None:
        """Тест десериализации результата."""
        from src.security.integrity.models import IntegrityCheckResult

        data = {
            "check_type": "app_binary",
            "passed": False,
            "timestamp": "2026-03-23T12:00:00+00:00",
            "error_message": "Хеш не совпадает",
        }

        result = IntegrityCheckResult.from_dict(data)

        assert result.check_type == IntegrityCheckType.APP_BINARY
        assert result.passed is False
        assert result.error_message == "Хеш не совпадает"

    def test_hash_match_property(self) -> None:
        """Тест свойства hash_match."""
        from src.security.integrity.models import IntegrityCheckResult

        # Совпадающие хеши
        result_match = IntegrityCheckResult(
            check_type=IntegrityCheckType.APP_BINARY,
            passed=True,
            expected_hash="a" * 64,
            actual_hash="a" * 64,
        )
        assert result_match.hash_match is True

        # Несовпадающие хеши
        result_no_match = IntegrityCheckResult(
            check_type=IntegrityCheckType.APP_BINARY,
            passed=False,
            expected_hash="a" * 64,
            actual_hash="b" * 64,
        )
        assert result_no_match.hash_match is False

        # Без хешей
        result_no_hash = IntegrityCheckResult(
            check_type=IntegrityCheckType.APP_BINARY,
            passed=True,
        )
        assert result_no_hash.hash_match is None


class TestIntegrityCheckType:
    """Тесты IntegrityCheckType enum."""

    def test_description(self) -> None:
        """Тест описаний типов проверок."""
        assert "бинарника" in IntegrityCheckType.APP_BINARY.description
        assert "конфигурации" in IntegrityCheckType.CONFIG_FILE.description
        assert "Все проверки" in IntegrityCheckType.ALL.description

    def test_values(self) -> None:
        """Тест значений enum."""
        assert IntegrityCheckType.APP_BINARY.value == "app_binary"
        assert IntegrityCheckType.CONFIG_FILE.value == "config_file"
        assert IntegrityCheckType.ALL.value == "all"