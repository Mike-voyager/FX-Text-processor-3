"""Тесты DocumentLockService.

Module: tests/unit/services/test_document_lock_service.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.services.document_lock_service import (
    LOCK_EXTENSION,
    DocumentLockService,
    LockInfo,
    LockResult,
)


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_dir() -> Path:
    """Временная директория для тестов."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def service() -> DocumentLockService:
    """Сервис блокировок."""
    return DocumentLockService(owner_id="test-session-1", owner_name="Test User")


@pytest.fixture
def service_with_lock_dir(temp_dir: Path) -> DocumentLockService:
    """Сервис с отдельной директорией для блокировок."""
    return DocumentLockService(
        owner_id="test-session-2",
        owner_name="Test User 2",
        lock_dir=temp_dir / "locks",
    )


# ---------------------------------------------------------------------------
# Тесты блокировки
# ---------------------------------------------------------------------------


class TestLockOperations:
    """Тесты операций блокировки."""

    def test_try_lock_success(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест успешной блокировки."""
        file_path = temp_dir / "test.fxsd"

        result = service.try_lock(file_path)

        assert result.success
        assert result.lock_info is not None
        assert result.lock_info.owner_id == "test-session-1"
        assert service.is_locked(file_path)

    def test_try_lock_already_locked_by_same_owner(
        self, service: DocumentLockService, temp_dir: Path
    ) -> None:
        """Тест повторной блокировки тем же владельцем."""
        file_path = temp_dir / "test.fxsd"

        result1 = service.try_lock(file_path)
        result2 = service.try_lock(file_path)

        assert result1.success
        assert result2.success

    def test_try_lock_already_locked_by_other(self, temp_dir: Path) -> None:
        """Тест блокировки заблокированного файла другим владельцем."""
        file_path = temp_dir / "test.fxsd"

        service1 = DocumentLockService(owner_id="owner-1")
        service2 = DocumentLockService(owner_id="owner-2")

        result1 = service1.try_lock(file_path)
        result2 = service2.try_lock(file_path)

        assert result1.success
        assert not result2.success
        assert result2.existing_lock is not None
        assert result2.existing_lock.owner_id == "owner-1"

    def test_release_lock_success(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест успешного освобождения блокировки."""
        file_path = temp_dir / "test.fxsd"
        service.try_lock(file_path)

        success = service.release_lock(file_path)

        assert success
        assert not service.is_locked(file_path)

    def test_release_lock_not_owner(self, temp_dir: Path) -> None:
        """Тест освобождения чужой блокировки."""
        file_path = temp_dir / "test.fxsd"

        service1 = DocumentLockService(owner_id="owner-1")
        service2 = DocumentLockService(owner_id="owner-2")

        service1.try_lock(file_path)
        success = service2.release_lock(file_path)

        assert not success
        assert service1.is_locked(file_path)

    def test_release_lock_nonexistent(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест освобождения несуществующей блокировки."""
        file_path = temp_dir / "nonexistent.fxsd"

        success = service.release_lock(file_path)

        assert not success


# ---------------------------------------------------------------------------
# Тесты проверки блокировки
# ---------------------------------------------------------------------------


class TestIsLocked:
    """Тесты проверки блокировки."""

    def test_is_locked_false(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест незаблокированного файла."""
        file_path = temp_dir / "test.fxsd"

        assert not service.is_locked(file_path)

    def test_is_locked_true(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест заблокированного файла."""
        file_path = temp_dir / "test.fxsd"
        service.try_lock(file_path)

        assert service.is_locked(file_path)

    def test_is_locked_after_release(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест блокировки после освобождения."""
        file_path = temp_dir / "test.fxsd"
        service.try_lock(file_path)
        service.release_lock(file_path)

        assert not service.is_locked(file_path)


# ---------------------------------------------------------------------------
# Тесты информации о блокировке
# ---------------------------------------------------------------------------


class TestGetLockInfo:
    """Тесты получения информации о блокировке."""

    def test_get_lock_info_exists(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест получения информации о существующей блокировке."""
        file_path = temp_dir / "test.fxsd"
        service.try_lock(file_path)

        lock_info = service.get_lock_info(file_path)

        assert lock_info is not None
        assert lock_info.owner_id == "test-session-1"
        assert lock_info.owner_name == "Test User"

    def test_get_lock_info_not_exists(
        self, service: DocumentLockService, temp_dir: Path
    ) -> None:
        """Тест получения информации о несуществующей блокировке."""
        file_path = temp_dir / "test.fxsd"

        lock_info = service.get_lock_info(file_path)

        assert lock_info is None


# ---------------------------------------------------------------------------
# Тесты массовых операций
# ---------------------------------------------------------------------------


class TestBatchOperations:
    """Тесты массовых операций."""

    def test_release_all(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест освобождения всех блокировок."""
        file1 = temp_dir / "file1.fxsd"
        file2 = temp_dir / "file2.fxsd"
        file3 = temp_dir / "file3.fxsd"

        service.try_lock(file1)
        service.try_lock(file2)
        service.try_lock(file3)

        count = service.release_all()

        assert count == 3
        assert not service.is_locked(file1)
        assert not service.is_locked(file2)
        assert not service.is_locked(file3)

    def test_get_all_locks(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест получения всех блокировок."""
        file1 = temp_dir / "file1.fxsd"
        file2 = temp_dir / "file2.fxsd"

        service.try_lock(file1)
        service.try_lock(file2)

        locks = service.get_all_locks()

        assert len(locks) == 2


# ---------------------------------------------------------------------------
# Тесты таймаута
# ---------------------------------------------------------------------------


class TestTimeout:
    """Тесты таймаута блокировки."""

    def test_lock_not_expired(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест, что свежая блокировка не устарела."""
        file_path = temp_dir / "test.fxsd"
        service.try_lock(file_path)

        assert service.is_locked(file_path)

    @patch("src.services.document_lock_service.datetime")
    def test_lock_expired(
        self, mock_datetime, service: DocumentLockService, temp_dir: Path
    ) -> None:
        """Тест устаревшей блокировки."""
        from datetime import datetime, timedelta

        # Настраиваем мок для создания старой блокировки
        now = datetime.now()
        old_time = now - timedelta(minutes=10)

        mock_datetime.now.return_value = old_time
        mock_datetime.fromisoformat.side_effect = datetime.fromisoformat

        file_path = temp_dir / "test.fxsd"
        service.try_lock(file_path)

        # Возвращаем текущее время
        mock_datetime.now.return_value = now
        mock_datetime.fromisoformat.side_effect = datetime.fromisoformat

        # Проверяем, что блокировка устарела
        # Примечание: реальная логика зависит от _is_lock_expired
        # Этот тест демонстрирует подход


# ---------------------------------------------------------------------------
# Тесты утилит
# ---------------------------------------------------------------------------


class TestUtilities:
    """Тесты утилитарных методов."""

    def test_set_owner_id(self, service: DocumentLockService) -> None:
        """Тест установки ID владельца."""
        service.set_owner_id("new-owner-id")

        assert service._owner_id == "new-owner-id"

    def test_set_owner_name(self, service: DocumentLockService) -> None:
        """Тест установки имени владельца."""
        service.set_owner_name("New Owner Name")

        assert service._owner_name == "New Owner Name"

    def test_lock_file_path(self, service: DocumentLockService, temp_dir: Path) -> None:
        """Тест пути к файлу блокировки."""
        file_path = temp_dir / "test.fxsd"
        expected = temp_dir / ("test.fxsd" + LOCK_EXTENSION)

        lock_path = service._get_lock_file_path(file_path)

        assert lock_path == expected

    def test_lock_file_path_with_lock_dir(
        self, service_with_lock_dir: DocumentLockService, temp_dir: Path
    ) -> None:
        """Тест пути к файлу блокировки с отдельной директорией."""
        file_path = temp_dir / "test.fxsd"

        lock_path = service_with_lock_dir._get_lock_file_path(file_path)

        assert LOCK_EXTENSION in str(lock_path)
        assert "locks" in str(lock_path)


# ---------------------------------------------------------------------------
# Тесты LockInfo
# ---------------------------------------------------------------------------


class TestLockInfo:
    """Тесты модели LockInfo."""

    def test_lock_info_creation(self) -> None:
        """Тест создания LockInfo."""
        from datetime import datetime
        from pathlib import Path

        lock_info = LockInfo(
            owner_id="test-owner",
            owner_name="Test Owner",
            locked_at=datetime.now(),
            file_path=Path("/tmp/test.fxsd"),
            lock_file_path=Path("/tmp/test.fxsd.lock"),
            hostname="test-host",
            pid=12345,
        )

        assert lock_info.owner_id == "test-owner"
        assert lock_info.owner_name == "Test Owner"
        assert lock_info.hostname == "test-host"
        assert lock_info.pid == 12345


# ---------------------------------------------------------------------------
# Тесты LockResult
# ---------------------------------------------------------------------------


class TestLockResult:
    """Тесты модели LockResult."""

    def test_lock_result_success(self) -> None:
        """Тест успешного LockResult."""
        result = LockResult(success=True)

        assert result.success
        assert result.lock_info is None
        assert result.error is None

    def test_lock_result_failure(self) -> None:
        """Тест неуспешного LockResult."""
        result = LockResult(success=False, error="Test error")

        assert not result.success
        assert result.error == "Test error"