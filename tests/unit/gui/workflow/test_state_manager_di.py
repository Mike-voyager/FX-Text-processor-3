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
