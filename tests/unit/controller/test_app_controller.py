"""Тесты для AppController."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from src.controller.app_controller import AppController
from src.model.document import Document, DocumentMetadata


class TestAppController:
    """Тесты для AppController."""

    @pytest.fixture
    def mock_document_manager(self) -> MagicMock:
        """Создаёт мок DocumentManagerService."""
        manager = MagicMock()
        manager.create_new.return_value = MagicMock(
            success=True,
            document=Document(metadata=DocumentMetadata(title="Test")),
        )
        manager.open_file.return_value = MagicMock(
            success=True,
            document=Document(metadata=DocumentMetadata(title="Test")),
        )
        return manager

    @pytest.fixture
    def mock_notification(self) -> MagicMock:
        """Создаёт мок NotificationService."""
        return MagicMock()

    @pytest.fixture
    def mock_key_bindings(self) -> MagicMock:
        """Создаёт мок KeyBindingsService."""
        return MagicMock()

    @pytest.fixture
    def mock_clipboard(self) -> MagicMock:
        """Создаёт мок ClipboardService."""
        return MagicMock()

    @pytest.fixture
    def app_controller(
        self,
        mock_document_manager: MagicMock,
        mock_notification: MagicMock,
        mock_key_bindings: MagicMock,
        mock_clipboard: MagicMock,
    ) -> AppController:
        """Создаёт AppController."""
        return AppController(
            document_manager=mock_document_manager,
            notification=mock_notification,
            key_bindings=mock_key_bindings,
            clipboard=mock_clipboard,
        )

    def test_init(
        self,
        app_controller: AppController,
        mock_document_manager: MagicMock,
        mock_notification: MagicMock,
        mock_key_bindings: MagicMock,
        mock_clipboard: MagicMock,
    ) -> None:
        """Тест инициализации."""
        assert app_controller._document_manager == mock_document_manager
        assert app_controller._notification == mock_notification
        assert app_controller._key_bindings == mock_key_bindings
        assert app_controller._clipboard == mock_clipboard
        assert app_controller._main_window is None
        assert app_controller._document_controllers == {}
        assert app_controller._active_document is None

    def test_set_main_window(self, app_controller: AppController) -> None:
        """Тест установки главного окна."""
        mock_window = MagicMock()
        app_controller.set_main_window(mock_window)
        assert app_controller._main_window == mock_window

    def test_get_main_window(self, app_controller: AppController) -> None:
        """Тест получения главного окна."""
        assert app_controller.get_main_window() is None

        mock_window = MagicMock()
        app_controller.set_main_window(mock_window)
        assert app_controller.get_main_window() == mock_window

    def test_new_document(
        self,
        app_controller: AppController,
        mock_document_manager: MagicMock,
        mock_notification: MagicMock,
    ) -> None:
        """Тест создания нового документа."""
        document = app_controller.new_document("Test Document")

        assert document is not None
        mock_document_manager.create_new.assert_called_once_with(title="Test Document")
        mock_notification.success.assert_called_once()
        assert len(app_controller._document_controllers) == 1

    def test_new_document_failure(
        self,
        app_controller: AppController,
        mock_document_manager: MagicMock,
        mock_notification: MagicMock,
    ) -> None:
        """Тест неудачного создания документа."""
        mock_document_manager.create_new.return_value = MagicMock(
            success=False,
            document=None,
            error="Test error",
        )

        result = app_controller.new_document("Test")

        assert result is None
        mock_notification.error.assert_called_once()

    def test_open_document_with_path(
        self,
        app_controller: AppController,
        mock_document_manager: MagicMock,
        mock_notification: MagicMock,
    ) -> None:
        """Тест открытия документа по пути."""
        with patch("src.controller.app_controller.Path") as mock_path:
            mock_path.return_value = Path("/test/document.fxsd")

            document = app_controller.open_document("/test/document.fxsd")

            assert document is not None
            mock_document_manager.open_file.assert_called_once()
            mock_notification.success.assert_called_once()

    def test_open_document_cancel_dialog(
        self,
        app_controller: AppController,
        mock_notification: MagicMock,
    ) -> None:
        """Тест отмены диалога открытия."""
        with patch(
            "src.controller.app_controller.OpenFileDialog"
        ) as mock_dialog_class:
            mock_dialog = MagicMock()
            mock_dialog.show.return_value = None
            mock_dialog_class.return_value = mock_dialog

            result = app_controller.open_document()

            assert result is None
            mock_notification.success.assert_not_called()

    def test_get_document_none(self, app_controller: AppController) -> None:
        """Тест получения документа без активного."""
        assert app_controller.get_document() is None

    def test_get_document_with_document(
        self,
        app_controller: AppController,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест получения активного документа."""
        app_controller.new_document("Test")
        document = app_controller.get_document()

        assert document is not None

    def test_undo_no_document(self, app_controller: AppController) -> None:
        """Тест undo без активного документа."""
        result = app_controller.undo()
        assert result is False

    def test_redo_no_document(self, app_controller: AppController) -> None:
        """Тест redo без активного документа."""
        result = app_controller.redo()
        assert result is False

    def test_save_document_no_active(
        self,
        app_controller: AppController,
        mock_notification: MagicMock,
    ) -> None:
        """Тест сохранения без активного документа."""
        result = app_controller.save_document()
        assert result is False

    def test_save_document_as_no_active(
        self,
        app_controller: AppController,
        mock_notification: MagicMock,
    ) -> None:
        """Тест сохранения как без активного документа."""
        result = app_controller.save_document_as("/test/path.fxsd")
        assert result is False

    def test_close_document_no_active(self, app_controller: AppController) -> None:
        """Тест закрытия без активного документа."""
        result = app_controller.close_document()
        assert result is True

    def test_exit_app_no_documents(
        self,
        app_controller: AppController,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест выхода без документов."""
        result = app_controller.exit_app()
        assert result is True

    def test_setup_key_bindings(
        self,
        app_controller: AppController,
        mock_key_bindings: MagicMock,
    ) -> None:
        """Тест настройки горячих клавиш."""
        app_controller.setup_key_bindings()

        # Проверяем, что действия зарегистрированы
        assert mock_key_bindings.register_action.call_count >= 5

    def test_get_active_controller_none(self, app_controller: AppController) -> None:
        """Тест получения контроллера без активного документа."""
        controller = app_controller._get_active_controller()
        assert controller is None


class TestAppControllerWithDocument:
    """Тесты AppController с документом."""

    @pytest.fixture
    def mock_document_manager(self) -> MagicMock:
        """Создаёт мок DocumentManagerService."""
        manager = MagicMock()
        document = Document(metadata=DocumentMetadata(title="Test"))
        manager.create_new.return_value = MagicMock(
            success=True,
            document=document,
        )
        return manager

    @pytest.fixture
    def mock_notification(self) -> MagicMock:
        """Создаёт мок NotificationService."""
        return MagicMock()

    @pytest.fixture
    def mock_key_bindings(self) -> MagicMock:
        """Создаёт мок KeyBindingsService."""
        return MagicMock()

    @pytest.fixture
    def mock_clipboard(self) -> MagicMock:
        """Создаёт мок ClipboardService."""
        return MagicMock()

    @pytest.fixture
    def app_controller(
        self,
        mock_document_manager: MagicMock,
        mock_notification: MagicMock,
        mock_key_bindings: MagicMock,
        mock_clipboard: MagicMock,
    ) -> AppController:
        """Создаёт AppController с документом."""
        controller = AppController(
            document_manager=mock_document_manager,
            notification=mock_notification,
            key_bindings=mock_key_bindings,
            clipboard=mock_clipboard,
        )
        controller.new_document("Test")
        return controller

    def test_get_document_returns_document(
        self,
        app_controller: AppController,
    ) -> None:
        """Тест получения документа."""
        document = app_controller.get_document()
        assert document is not None
        assert document.metadata.title == "Test"

    def test_get_active_controller_returns_controller(
        self,
        app_controller: AppController,
    ) -> None:
        """Тест получения контроллера активного документа."""
        controller = app_controller._get_active_controller()
        assert controller is not None

    def test_close_document(
        self,
        app_controller: AppController,
        mock_document_manager: MagicMock,
    ) -> None:
        """Тест закрытия документа."""
        document = app_controller.get_document()
        assert document is not None

        result = app_controller.close_document()
        assert result is True
        mock_document_manager.close.assert_called_once()
