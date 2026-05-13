"""Тесты AutoSaveService.

Module: tests/unit/services/test_auto_save_service.py
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

from src.services.auto_save_service import (
    AutoSaveConfig,
    AutoSaveService,
    AutoSaveStats,
)


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_document_manager() -> MagicMock:
    """Мок DocumentManagerService."""
    manager = MagicMock()
    manager.modified_documents = []
    manager.get_document_path = MagicMock(return_value=None)
    manager.save = MagicMock(return_value=MagicMock(success=True, path=Path("/test.fxsd")))
    return manager


@pytest.fixture
def config() -> AutoSaveConfig:
    """Конфигурация автосохранения."""
    return AutoSaveConfig(
        enabled=True,
        interval_seconds=1,  # Быстрый интервал для тестов
        save_modified_only=True,
        backup_enabled=True,
    )


@pytest.fixture
def auto_save(
    mock_document_manager: MagicMock,
    config: AutoSaveConfig,
) -> AutoSaveService:
    """Сервис автосохранения."""
    return AutoSaveService(
        document_manager=mock_document_manager,
        config=config,
    )


# ---------------------------------------------------------------------------
# Тесты конфигурации
# ---------------------------------------------------------------------------


class TestAutoSaveConfig:
    """Тесты конфигурации."""

    def test_default_config(self) -> None:
        """Тест конфигурации по умолчанию."""
        config = AutoSaveConfig()

        assert config.enabled is True
        assert config.interval_seconds == 300
        assert config.save_modified_only is True
        assert config.backup_enabled is True

    def test_custom_config(self) -> None:
        """Тест кастомной конфигурации."""
        config = AutoSaveConfig(
            enabled=False,
            interval_seconds=60,
            backup_enabled=False,
        )

        assert config.enabled is False
        assert config.interval_seconds == 60
        assert config.backup_enabled is False


# ---------------------------------------------------------------------------
# Тесты управления таймером
# ---------------------------------------------------------------------------


class TestTimerManagement:
    """Тесты управления таймером."""

    def test_start(self, auto_save: AutoSaveService) -> None:
        """Тест запуска таймера."""
        auto_save.start()

        assert auto_save.is_running()

    def test_stop(self, auto_save: AutoSaveService) -> None:
        """Тест остановки таймера."""
        auto_save.start()
        auto_save.stop()

        assert not auto_save.is_running()

    def test_restart(self, auto_save: AutoSaveService) -> None:
        """Тест перезапуска таймера."""
        auto_save.start()
        auto_save.restart()

        assert auto_save.is_running()

    def test_start_disabled(self, mock_document_manager: MagicMock) -> None:
        """Тест запуска с отключённой конфигурацией."""
        config = AutoSaveConfig(enabled=False)
        auto_save = AutoSaveService(mock_document_manager, config)

        auto_save.start()

        assert not auto_save.is_running()

    def test_double_start(self, auto_save: AutoSaveService) -> None:
        """Тест двойного запуска."""
        auto_save.start()
        auto_save.start()  # Второй запуск не должен падать

        assert auto_save.is_running()


# ---------------------------------------------------------------------------
# Тесты сохранения
# ---------------------------------------------------------------------------


class TestSaving:
    """Тесты сохранения документов."""

    def test_save_all_modified(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест сохранения изменённых документов."""
        # Создаём мок-документ
        doc = MagicMock()
        doc.id = UUID("12345678-1234-5678-1234-567812345678")
        doc.is_modified = True

        mock_document_manager.modified_documents = [doc]
        mock_document_manager.get_document_path = MagicMock(
            return_value=Path("/test.fxsd")
        )

        results = auto_save.save_all_modified()

        assert len(results) == 1
        assert doc.id in results

    def test_save_all_modified_no_path(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест сохранения документа без пути."""
        doc = MagicMock()
        doc.id = UUID("12345678-1234-5678-1234-567812345678")
        doc.is_modified = True

        mock_document_manager.modified_documents = [doc]
        mock_document_manager.get_document_path = MagicMock(return_value=None)

        results = auto_save.save_all_modified()

        assert results[doc.id] is False

    def test_save_document_success(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Тест успешного сохранения документа."""
        doc_id = UUID("12345678-1234-5678-1234-567812345678")
        test_file = tmp_path / "test.fxsd"
        test_file.write_text("test")

        mock_document_manager.get_document_path = MagicMock(return_value=test_file)
        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=True, path=test_file)
        )

        auto_save._save_document(doc_id, test_file)

        mock_document_manager.save.assert_called_once()

    def test_save_document_with_backup(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Тест сохранения с резервной копией."""
        doc_id = UUID("12345678-1234-5678-1234-567812345678")
        test_file = tmp_path / "test.fxsd"
        test_file.write_text("original")

        mock_document_manager.get_document_path = MagicMock(return_value=test_file)
        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=True, path=test_file)
        )

        auto_save._save_document(doc_id, test_file)

        # Проверяем, что резервная копия создана
        backup_file = tmp_path / "test.fxsd.bak"
        assert backup_file.exists()

    def test_save_document_error(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест ошибки сохранения документа."""
        doc_id = UUID("12345678-1234-5678-1234-567812345678")

        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=False, error="Test error")
        )

        success = auto_save._save_document(doc_id, Path("/test.fxsd"))

        assert success is False


# ---------------------------------------------------------------------------
# Тесты статистики
# ---------------------------------------------------------------------------


class TestStats:
    """Тесты статистики."""

    def test_initial_stats(self, auto_save: AutoSaveService) -> None:
        """Тест начальной статистики."""
        stats = auto_save.get_stats()

        assert stats.total_saves == 0
        assert stats.successful_saves == 0
        assert stats.failed_saves == 0

    def test_update_stats_on_success(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест обновления статистики при успехе."""
        doc_id = UUID("12345678-1234-5678-1234-567812345678")
        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=True, path=Path("/test.fxsd"))
        )

        auto_save._save_document(doc_id, Path("/test.fxsd"))

        stats = auto_save.get_stats()
        assert stats.total_saves == 1
        assert stats.successful_saves == 1
        assert stats.failed_saves == 0

    def test_update_stats_on_failure(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест обновления статистики при ошибке."""
        doc_id = UUID("12345678-1234-5678-1234-567812345678")
        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=False, error="Error")
        )

        auto_save._save_document(doc_id, Path("/test.fxsd"))

        stats = auto_save.get_stats()
        assert stats.total_saves == 1
        assert stats.successful_saves == 0
        assert stats.failed_saves == 1

    def test_document_stats(
        self,
        auto_save: AutoSaveService,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест статистики документа."""
        doc_id = UUID("12345678-1234-5678-1234-567812345678")
        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=True, path=Path("/test.fxsd"))
        )

        auto_save._save_document(doc_id, Path("/test.fxsd"))

        doc_stats = auto_save.get_document_stats(doc_id)
        assert doc_stats is not None
        assert doc_stats.total_saves == 1

    def test_reset_stats(self, auto_save: AutoSaveService) -> None:
        """Тест сброса статистики."""
        auto_save._stats = AutoSaveStats(
            total_saves=10,
            successful_saves=8,
            failed_saves=2,
        )

        auto_save.reset_stats()

        stats = auto_save.get_stats()
        assert stats.total_saves == 0


# ---------------------------------------------------------------------------
# Тесты callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    """Тесты callbacks."""

    def test_on_save_callback(
        self,
        mock_document_manager: MagicMock,
        config: AutoSaveConfig,
    ) -> None:
        """Тест callback при сохранении."""
        saved_docs: list[tuple[UUID, Path]] = []

        def on_save(doc_id: UUID, path: Path) -> None:
            saved_docs.append((doc_id, path))

        auto_save = AutoSaveService(
            mock_document_manager,
            config,
            on_save=on_save,
        )

        doc_id = UUID("12345678-1234-5678-1234-567812345678")
        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=True, path=Path("/test.fxsd"))
        )

        auto_save._save_document(doc_id, Path("/test.fxsd"))

        assert len(saved_docs) == 1

    def test_on_error_callback(
        self,
        mock_document_manager: MagicMock,
        config: AutoSaveConfig,
    ) -> None:
        """Тест callback при ошибке."""
        errors: list[tuple[UUID, str]] = []

        def on_error(doc_id: UUID, error: str) -> None:
            errors.append((doc_id, error))

        auto_save = AutoSaveService(
            mock_document_manager,
            config,
            on_error=on_error,
        )

        doc_id = UUID("12345678-1234-5678-1234-567812345678")
        mock_document_manager.save = MagicMock(
            return_value=MagicMock(success=False, error="Test error")
        )

        auto_save._save_document(doc_id, Path("/test.fxsd"))

        assert len(errors) == 1
        assert "Test error" in errors[0][1]


# ---------------------------------------------------------------------------
# Тесты изменения конфигурации
# ---------------------------------------------------------------------------


class TestConfigChanges:
    """Тесты изменения конфигурации."""

    def test_set_interval(self, auto_save: AutoSaveService) -> None:
        """Тест установки интервала."""
        auto_save.set_interval(60)

        assert auto_save.get_config().interval_seconds == 60

    def test_set_interval_minimum(
        self, auto_save: AutoSaveService
    ) -> None:
        """Тест минимального интервала."""
        auto_save.set_interval(5)

        # Минимум 10 секунд
        assert auto_save.get_config().interval_seconds == 10

    def test_enable(self, auto_save: AutoSaveService) -> None:
        """Тест включения автосохранения."""
        auto_save._config.enabled = False
        auto_save.enable()

        assert auto_save.get_config().enabled is True
        assert auto_save.is_running()

    def test_disable(self, auto_save: AutoSaveService) -> None:
        """Тест отключения автосохранения."""
        auto_save.start()
        auto_save.disable()

        assert auto_save.get_config().enabled is False
        assert not auto_save.is_running()