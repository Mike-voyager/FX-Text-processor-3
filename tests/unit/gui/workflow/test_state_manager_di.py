"""Тесты DI и валидации конструктора WorkflowStateManager.

Проверяет:
- Обязательность workflow_controller и mfa_gate
- Успешный _execute_transition() с мокнутыми зависимостями

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from src.gui.workflow.state_manager import WorkflowStateManager


class TestWorkflowStateManagerConstructor:
    """Тесты валидации конструктора."""

    def test_rejects_none_workflow_controller(self) -> None:
        """ValueError при None workflow_controller."""
        mock_mfa = MagicMock()
        with pytest.raises(ValueError, match="workflow_controller обязателен"):
            WorkflowStateManager(workflow_controller=None, mfa_gate=mock_mfa)  # type: ignore[arg-type]

    def test_rejects_none_mfa_gate(self) -> None:
        """ValueError при None mfa_gate."""
        mock_wc = MagicMock()
        with pytest.raises(ValueError, match="mfa_gate обязателен"):
            WorkflowStateManager(workflow_controller=mock_wc, mfa_gate=None)  # type: ignore[arg-type]

    def test_rejects_both_none(self) -> None:
        """ValueError при обоих None."""
        with pytest.raises(ValueError):
            WorkflowStateManager(workflow_controller=None, mfa_gate=None)  # type: ignore[arg-type]


class TestWorkflowStateManagerExecuteTransition:
    """Тесты _execute_transition() с мокнутыми зависимостями."""

    @patch("src.gui.workflow.transition_command.WorkflowCommandFactory")
    @patch("src.gui.workflow.snapshot.SnapshotManager")
    def test_successful_execute_transition(
        self,
        mock_snapshot_cls: MagicMock,
        mock_factory_cls: MagicMock,
    ) -> None:
        """_execute_transition() возвращает success=True при валидном mock."""
        mock_wc = MagicMock()
        mock_wc.current_role = MagicMock()
        mock_mfa = MagicMock()

        # Setup mock snapshot
        mock_snapshot = MagicMock()
        mock_snapshot_cls.return_value = mock_snapshot

        # Setup mock command
        mock_command = MagicMock()
        mock_command.description_for_undo = "test undo"
        mock_factory = MagicMock()
        mock_factory.create_transition_command.return_value = mock_command
        mock_factory_cls.return_value = mock_factory

        manager = WorkflowStateManager(
            workflow_controller=mock_wc,
            mfa_gate=mock_mfa,
        )

        doc_id = uuid4()
        from_state = MagicMock()
        to_state = MagicMock()

        result = manager._execute_transition(
            doc_id=doc_id,
            from_state=from_state,
            to_state=to_state,
            reason="test reason",
        )

        assert result.success is True
        assert result.from_state is from_state
        assert result.to_state is to_state
        assert result.reason == "test reason"
        assert result.command is mock_command
        mock_wc.transition.assert_called_once_with(
            doc_id=doc_id,
            target=to_state,
            reason="test reason",
        )


class TestWorkflowStateManagerProtocolMethods:
    """Регрессионные тесты для Protocol-методов WorkflowStateManager.

    Bug: WorkflowStateManagerProtocol требовал get_last_undo_description,
         get_last_redo_description, request_transition_by_action,
         но WorkflowStateManager их не реализовывал.
    Fix: Добавлены недостающие методы.
    """

    def test_request_transition_by_action_unknown_action(self) -> None:
        """request_transition_by_action возвращает None для неизвестного действия."""
        mock_wc = MagicMock()
        mock_wc.get_current_state = MagicMock(return_value=MagicMock(value="draft"))
        mock_mfa = MagicMock()

        manager = WorkflowStateManager(
            workflow_controller=mock_wc,
            mfa_gate=mock_mfa,
        )

        result = manager.request_transition_by_action(
            doc_id=uuid4(),
            action="unknown_action",
        )
        assert result is None

    def test_request_transition_by_action_with_uuid(self) -> None:
        """request_transition_by_action принимает UUID."""
        mock_wc = MagicMock()
        mock_wc.get_current_state = MagicMock(return_value=MagicMock(value="draft"))
        mock_wc.can_transition = MagicMock(return_value=False)
        mock_mfa = MagicMock()

        manager = WorkflowStateManager(
            workflow_controller=mock_wc,
            mfa_gate=mock_mfa,
        )

        doc_id = uuid4()
        # can_transition возвращает False — переход не разрешён
        result = manager.request_transition_by_action(doc_id=doc_id, action="sign")
        # Результат зависит от валидации, но метод не падает
        assert result is None or hasattr(result, "success")

    def test_get_last_undo_description_empty(self) -> None:
        """get_last_undo_description возвращает None при пустой истории."""
        mock_wc = MagicMock()
        mock_mfa = MagicMock()

        manager = WorkflowStateManager(
            workflow_controller=mock_wc,
            mfa_gate=mock_mfa,
        )

        assert manager.get_last_undo_description() is None

    def test_get_last_redo_description_empty(self) -> None:
        """get_last_redo_description возвращает None при пустой истории."""
        mock_wc = MagicMock()
        mock_mfa = MagicMock()

        manager = WorkflowStateManager(
            workflow_controller=mock_wc,
            mfa_gate=mock_mfa,
        )

        assert manager.get_last_redo_description() is None

    def test_request_transition_by_action_with_string_doc_id(self) -> None:
        """request_transition_by_action принимает строковый UUID."""
        mock_wc = MagicMock()
        mock_wc.get_current_state = MagicMock(return_value=MagicMock(value="draft"))
        mock_wc.can_transition = MagicMock(return_value=False)
        mock_mfa = MagicMock()

        manager = WorkflowStateManager(
            workflow_controller=mock_wc,
            mfa_gate=mock_mfa,
        )

        doc_id_str = str(uuid4())
        # Не должно падать при строковом doc_id
        result = manager.request_transition_by_action(doc_id=doc_id_str, action="sign")
        assert result is None or hasattr(result, "success")
