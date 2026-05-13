"""Тесты для DocumentController."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from src.controller.document_controller import DocumentController
from src.model.document import Document, DocumentMetadata


class TestDocumentController:
    """Тесты для DocumentController."""

    @pytest.fixture
    def document(self) -> Document:
        """Создаёт тестовый документ."""
        return Document(metadata=DocumentMetadata(title="Test Document"))

    @pytest.fixture
    def mock_command_history(self) -> MagicMock:
        """Создаёт мок CommandHistoryService."""
        history = MagicMock()
        history.can_undo.return_value = False
        history.can_redo.return_value = False
        history.undo.return_value = MagicMock(success=False)
        history.redo.return_value = MagicMock(success=False)
        return history

    @pytest.fixture
    def mock_clipboard(self) -> MagicMock:
        """Создаёт мок ClipboardService."""
        clipboard = MagicMock()
        clipboard.copy_text.return_value = MagicMock(success=True)
        clipboard.cut_text.return_value = MagicMock(success=True)
        clipboard.paste_text.return_value = "pasted text"
        return clipboard

    @pytest.fixture
    def mock_find_replace(self) -> MagicMock:
        """Создаёт мок FindReplaceService."""
        fr = MagicMock()
        fr.find.return_value = MagicMock(success=False, matches=[])
        fr.find_next.return_value = MagicMock(success=False, current_index=-1)
        fr.replace_all.return_value = MagicMock(replaced_count=0)
        fr.replace_one.return_value = MagicMock(success=False)
        return fr

    @pytest.fixture
    def document_controller(
        self,
        document: Document,
        mock_command_history: MagicMock,
        mock_clipboard: MagicMock,
        mock_find_replace: MagicMock,
    ) -> DocumentController:
        """Создаёт DocumentController."""
        return DocumentController(
            document=document,
            command_history=mock_command_history,
            clipboard=mock_clipboard,
            find_replace=mock_find_replace,
        )

    def test_init(
        self,
        document_controller: DocumentController,
        document: Document,
        mock_command_history: MagicMock,
        mock_clipboard: MagicMock,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест инициализации."""
        assert document_controller._document == document
        assert document_controller._command_history == mock_command_history
        assert document_controller._clipboard == mock_clipboard
        assert document_controller._find_replace == mock_find_replace
        assert document_controller._document_view is None
        assert document_controller._is_modified is False
        assert document_controller._file_path is None

    def test_get_document(
        self,
        document_controller: DocumentController,
        document: Document,
    ) -> None:
        """Тест получения документа."""
        result = document_controller.get_document()
        assert result == document

    def test_set_view(self, document_controller: DocumentController) -> None:
        """Тест установки представления."""
        mock_view = MagicMock()
        document_controller.set_view(mock_view)
        assert document_controller._document_view == mock_view

    def test_can_undo_false(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест can_undo когда нет истории."""
        result = document_controller.can_undo()
        assert result is False
        mock_command_history.can_undo.assert_called_once()

    def test_can_undo_true(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест can_undo когда есть история."""
        mock_command_history.can_undo.return_value = True
        result = document_controller.can_undo()
        assert result is True

    def test_can_redo_false(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест can_redo когда нет истории."""
        result = document_controller.can_redo()
        assert result is False
        mock_command_history.can_redo.assert_called_once()

    def test_can_redo_true(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест can_redo когда есть история."""
        mock_command_history.can_redo.return_value = True
        result = document_controller.can_redo()
        assert result is True

    def test_undo_success(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест успешной отмены."""
        mock_command_history.can_undo.return_value = True
        mock_command_history.undo.return_value = MagicMock(success=True)

        result = document_controller.undo()
        assert result is True
        mock_command_history.undo.assert_called_once()

    def test_undo_failure(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест неудачной отмены."""
        mock_command_history.can_undo.return_value = True
        mock_command_history.undo.return_value = MagicMock(success=False)

        result = document_controller.undo()
        assert result is False

    def test_redo_success(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест успешного повтора."""
        mock_command_history.can_redo.return_value = True
        mock_command_history.redo.return_value = MagicMock(success=True)

        result = document_controller.redo()
        assert result is True
        mock_command_history.redo.assert_called_once()

    def test_redo_failure(
        self,
        document_controller: DocumentController,
        mock_command_history: MagicMock,
    ) -> None:
        """Тест неудачного повтора."""
        mock_command_history.can_redo.return_value = True
        mock_command_history.redo.return_value = MagicMock(success=False)

        result = document_controller.redo()
        assert result is False

    def test_save_no_file_path(
        self,
        document_controller: DocumentController,
    ) -> None:
        """Тест сохранения без указания пути."""
        # Без _save_as_dialog возвращает False
        result = document_controller.save()
        assert result is False

    def test_save_as(
        self,
        document_controller: DocumentController,
    ) -> None:
        """Тест сохранения как."""
        # Используем временную директорию для теста
        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "test.fxsd"
            result = document_controller.save_as(test_path)
            assert result is True
            assert document_controller._file_path == test_path
            assert document_controller._is_modified is False

    def test_copy_no_view(self, document_controller: DocumentController) -> None:
        """Тест копирования без представления."""
        document_controller.copy()  # Не должно выбросить исключение

    def test_copy_with_view(
        self,
        document_controller: DocumentController,
        mock_clipboard: MagicMock,
    ) -> None:
        """Тест копирования с представлением."""
        import tkinter as tk

        mock_view = MagicMock()
        mock_view.get_selection.return_value = (0, 5)
        # Создаем mock Text widget
        mock_text_widget = MagicMock()
        mock_text_widget.get.return_value = "Hello"
        mock_view.get_text_widget.return_value = mock_text_widget
        document_controller.set_view(mock_view)

        document_controller.copy()

        mock_view.get_selection.assert_called_once()
        mock_text_widget.get.assert_called_once_with("sel.first", "sel.last")
        mock_clipboard.copy_text.assert_called_once_with("Hello")

    def test_copy_no_selection(
        self,
        document_controller: DocumentController,
        mock_clipboard: MagicMock,
    ) -> None:
        """Тест копирования без выделения."""
        mock_view = MagicMock()
        mock_view.get_selection.return_value = (0, 0)
        document_controller.set_view(mock_view)

        document_controller.copy()

        mock_clipboard.copy_text.assert_not_called()

    def test_cut_no_view(self, document_controller: DocumentController) -> None:
        """Тест вырезания без представления."""
        document_controller.cut()  # Не должно выбросить исключение

    def test_cut_with_view(
        self,
        document_controller: DocumentController,
        mock_clipboard: MagicMock,
    ) -> None:
        """Тест вырезания с представлением."""
        mock_view = MagicMock()
        mock_view.get_selection.return_value = (0, 5)
        mock_view.get_text_widget.return_value.get.return_value = "Hello"
        document_controller.set_view(mock_view)

        document_controller.cut()

        mock_view.get_selection.assert_called_once()
        mock_clipboard.cut_text.assert_called_once_with("Hello")
        mock_view.delete_text.assert_called_once_with(0, 5)

    def test_paste_no_view(self, document_controller: DocumentController) -> None:
        """Тест вставки без представления."""
        document_controller.paste()  # Не должно выбросить исключение

    def test_paste_with_view(
        self,
        document_controller: DocumentController,
        mock_clipboard: MagicMock,
    ) -> None:
        """Тест вставки с представлением."""
        mock_view = MagicMock()
        mock_view.get_cursor_position.return_value = 0
        document_controller.set_view(mock_view)

        document_controller.paste()

        mock_clipboard.paste_text.assert_called_once()
        mock_view.insert_text.assert_called_once_with(0, "pasted text")

    def test_paste_empty_clipboard(
        self,
        document_controller: DocumentController,
        mock_clipboard: MagicMock,
    ) -> None:
        """Тест вставки из пустого буфера."""
        mock_clipboard.paste_text.return_value = ""
        mock_view = MagicMock()
        document_controller.set_view(mock_view)

        document_controller.paste()

        mock_view.insert_text.assert_not_called()

    def test_find(
        self,
        document_controller: DocumentController,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест поиска."""
        mock_find_replace.find.return_value = MagicMock(
            success=True,
            matches=[MagicMock(start_offset=0, end_offset=5)],
        )

        result = document_controller.find("test")

        assert result == [0]
        mock_find_replace.find.assert_called_once()

    def test_find_no_results(
        self,
        document_controller: DocumentController,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест поиска без результатов."""
        mock_find_replace.find.return_value = MagicMock(
            success=False,
            matches=[],
        )

        result = document_controller.find("nonexistent")

        assert result == []

    def test_find_next(
        self,
        document_controller: DocumentController,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест поиска следующего."""
        mock_match = MagicMock(start_offset=10, end_offset=15)
        mock_find_replace.find_next.return_value = MagicMock(
            success=True,
            current_index=0,
            matches=[mock_match],
        )
        mock_view = MagicMock()
        document_controller.set_view(mock_view)

        result = document_controller.find_next("test")

        assert result == 10
        mock_view.set_selection.assert_called_once_with(10, 15)

    def test_find_next_no_view(
        self,
        document_controller: DocumentController,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест поиска следующего без представления."""
        result = document_controller.find_next("test")
        assert result == -1

    def test_replace_all(
        self,
        document_controller: DocumentController,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест замены всех."""
        mock_find_replace.replace_all.return_value = MagicMock(replaced_count=5)

        result = document_controller.replace_all("old", "new")

        assert result == 5
        mock_find_replace.replace_all.assert_called_once()

    def test_replace_next(
        self,
        document_controller: DocumentController,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест замены следующего."""
        mock_find_replace.replace_one.return_value = MagicMock(success=True)
        mock_view = MagicMock()
        document_controller.set_view(mock_view)

        result = document_controller.replace_next("old", "new")

        assert result is True
        mock_find_replace.replace_one.assert_called_once()

    def test_replace_next_no_view(
        self,
        document_controller: DocumentController,
        mock_find_replace: MagicMock,
    ) -> None:
        """Тест замены следующего без представления."""
        result = document_controller.replace_next("old", "new")
        assert result is False

    def test_is_modified_no_view(self, document_controller: DocumentController) -> None:
        """Тест проверки модификации без представления."""
        result = document_controller.is_modified()
        assert result is False

    def test_is_modified_with_view(self, document_controller: DocumentController) -> None:
        """Тест проверки модификации с представлением."""
        mock_view = MagicMock()
        mock_view.is_modified.return_value = True
        document_controller.set_view(mock_view)

        result = document_controller.is_modified()
        assert result is True

    def test_set_modified(self, document_controller: DocumentController) -> None:
        """Тест установки статуса модификации."""
        mock_view = MagicMock()
        document_controller.set_view(mock_view)

        document_controller.set_modified(True)

        assert document_controller._is_modified is True
        mock_view.set_modified.assert_called_once_with(True)

    def test_get_file_path_none(self, document_controller: DocumentController) -> None:
        """Тест получения пути к файлу без сохранения."""
        result = document_controller.get_file_path()
        assert result is None

    def test_get_file_path_after_save(self, document_controller: DocumentController) -> None:
        """Тест получения пути к файлу после сохранения."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "test.fxsd"
            document_controller.save_as(test_path)
            result = document_controller.get_file_path()
            assert result == test_path

    def test_close(self, document_controller: DocumentController) -> None:
        """Тест закрытия документа."""
        result = document_controller.close()
        assert result is True
        assert document_controller._document_view is None


class TestDocumentControllerModified:
    """Тесты DocumentController с модифицированным документом."""

    @pytest.fixture
    def document(self) -> Document:
        """Создаёт тестовый документ."""
        return Document(metadata=DocumentMetadata(title="Modified Document"))

    @pytest.fixture
    def mock_command_history(self) -> MagicMock:
        """Создаёт мок CommandHistoryService."""
        return MagicMock()

    @pytest.fixture
    def mock_clipboard(self) -> MagicMock:
        """Создаёт мок ClipboardService."""
        return MagicMock()

    @pytest.fixture
    def mock_find_replace(self) -> MagicMock:
        """Создаёт мок FindReplaceService."""
        return MagicMock()

    @pytest.fixture
    def document_controller(
        self,
        document: Document,
        mock_command_history: MagicMock,
        mock_clipboard: MagicMock,
        mock_find_replace: MagicMock,
    ) -> DocumentController:
        """Создаёт DocumentController."""
        return DocumentController(
            document=document,
            command_history=mock_command_history,
            clipboard=mock_clipboard,
            find_replace=mock_find_replace,
        )

    def test_close_modified(
        self,
        document_controller: DocumentController,
    ) -> None:
        """Тест закрытия модифицированного документа."""
        mock_view = MagicMock()
        mock_view.is_modified.return_value = True
        document_controller.set_view(mock_view)

        # close() возвращает True даже если модифицирован
        # (логика диалога "Сохранить изменения?" на уровне AppController)
        result = document_controller.close()
        assert result is True
