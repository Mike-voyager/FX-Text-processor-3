"""Тесты для DocumentController (GUI layer).

Тестируют интеграцию с CommandStack для undo/redo и execute_command.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/controllers/test_document_controller.py -v
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.gui.core.commands.command_stack import CommandStack
from src.gui.controllers.document_controller import DocumentController
from src.gui.dialogs.print_settings import PrintSettings
from src.services.document_manager_service import DocumentManagerService


@pytest.fixture
def mock_service() -> MagicMock:
    """Создаёт мок DocumentManagerService."""
    service = MagicMock(spec=DocumentManagerService)
    service.active_document = None
    return service


@pytest.fixture
def mock_command_stack() -> MagicMock:
    """Создаёт мок CommandStack."""
    stack = MagicMock(spec=CommandStack)
    stack.can_undo.return_value = True
    stack.can_redo.return_value = True
    return stack


@pytest.fixture
def document_controller(
    mock_service: MagicMock,
    mock_command_stack: MagicMock,
) -> DocumentController:
    """Создаёт DocumentController с DI."""
    return DocumentController(
        service=mock_service,
        command_stack=mock_command_stack,
    )


class TestDocumentControllerUndoRedo:
    """Тесты undo/redo и execute_command."""

    def test_on_undo_calls_command_stack_undo(
        self,
        document_controller: DocumentController,
        mock_command_stack: MagicMock,
    ) -> None:
        """on_undo() вызывает command_stack.undo() и возвращает True."""
        mock_command_stack.can_undo.return_value = True
        result = document_controller.on_undo()
        assert result is True
        mock_command_stack.undo.assert_called_once()

    def test_on_undo_returns_false_when_empty(
        self,
        document_controller: DocumentController,
        mock_command_stack: MagicMock,
    ) -> None:
        """on_undo() возвращает False когда can_undo() == False."""
        mock_command_stack.can_undo.return_value = False
        result = document_controller.on_undo()
        assert result is False
        mock_command_stack.undo.assert_not_called()

    def test_on_redo_calls_command_stack_redo(
        self,
        document_controller: DocumentController,
        mock_command_stack: MagicMock,
    ) -> None:
        """on_redo() вызывает command_stack.redo() и возвращает True."""
        mock_command_stack.can_redo.return_value = True
        result = document_controller.on_redo()
        assert result is True
        mock_command_stack.redo.assert_called_once()

    def test_execute_command_proxies_to_stack(
        self,
        document_controller: DocumentController,
        mock_command_stack: MagicMock,
    ) -> None:
        """execute_command() проксирует вызов в CommandStack.execute()."""
        cmd = MagicMock()
        document_controller.execute_command(cmd)
        mock_command_stack.execute.assert_called_once_with(cmd)


class TestDocumentControllerDispatch:
    """Тесты dispatch."""

    def test_dispatch_edit_undo_calls_on_undo(
        self,
        document_controller: DocumentController,
        mock_command_stack: MagicMock,
    ) -> None:
        """dispatch('edit_undo') вызывает on_undo()."""
        mock_command_stack.can_undo.return_value = True
        result = document_controller.dispatch("edit_undo")
        assert result is True
        mock_command_stack.undo.assert_called_once()

    def test_dispatch_edit_redo_calls_on_redo(
        self,
        document_controller: DocumentController,
        mock_command_stack: MagicMock,
    ) -> None:
        """dispatch('edit_redo') вызывает on_redo()."""
        mock_command_stack.can_redo.return_value = True
        result = document_controller.dispatch("edit_redo")
        assert result is True
        mock_command_stack.redo.assert_called_once()


class TestDocumentControllerDefaults:
    """Тесты для конструктора без явного CommandStack."""

    def test_default_command_stack_created_when_none(
        self, mock_service: MagicMock
    ) -> None:
        """Если command_stack не передан, создаётся новый CommandStack."""
        with patch.object(
            CommandStack, "__init__", return_value=None
        ) as mock_init:
            # Убираем can_undo / can_redo side effects чтобы не сломать
            # создание внутри __init__, так как patch заменяет весь метод
            controller = DocumentController(service=mock_service)
            assert controller._command_stack is not None

    def test_on_undo_with_default_stack_returns_false(
        self, mock_service: MagicMock
    ) -> None:
        """on_undo() с дефолтным пустым стеком возвращает False."""
        controller = DocumentController(service=mock_service)
        result = controller.on_undo()
        assert result is False

    def test_on_redo_with_default_stack_returns_false(
        self, mock_service: MagicMock
    ) -> None:
        """on_redo() с дефолтным пустым стеком возвращает False."""
        controller = DocumentController(service=mock_service)
        result = controller.on_redo()
        assert result is False
