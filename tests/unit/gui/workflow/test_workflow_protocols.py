"""Тесты для workflow protocols.

Проверяет корректность Protocol-интерфейсов,
их conformability и @runtime_checkable.
"""

from __future__ import annotations

from typing import Optional
from uuid import uuid4

import pytest

from src.gui.workflow.protocols import (
    WorkflowStateListener,
    WorkflowTransitionResult,
    WorkflowUIProtocol,
)


class TestWorkflowUIProtocolConformance:
    """Тесты conformances WorkflowUIProtocol."""

    def test_conforming_class_is_instance(self) -> None:
        """Класс, реализующий WorkflowUIProtocol, проходит isinstance."""
        class FakeFormStatus:
            DRAFT = "draft"
            FILLED = "filled"

        class MyWorkflowUI:
            """Полная реализация WorkflowUIProtocol."""

            def show_transition_dialog(
                self, from_state, to_state, on_confirm, on_cancel,
            ) -> None:
                pass

            def update_workflow_indicator(self, status) -> None:
                pass

            def show_mfa_challenge(self, operation, callback) -> None:
                pass

            def can_execute_transition(self, from_state, to_state) -> bool:
                return True

            def can_undo(self, doc_id) -> bool:
                return False

            def can_redo(self, doc_id) -> bool:
                return False

            def undo_transition(self, doc_id) -> bool:
                return False

            def redo_transition(self, doc_id) -> bool:
                return False

        ui = MyWorkflowUI()
        assert isinstance(ui, WorkflowUIProtocol)

    def test_non_conforming_class_not_instance(self) -> None:
        """Класс без методов не проходит isinstance."""
        class NotAWorkflowUI:
            pass

        obj = NotAWorkflowUI()
        assert not isinstance(obj, WorkflowUIProtocol)


class TestWorkflowStateListenerConformance:
    """Тесты conformances WorkflowStateListener."""

    def test_conforming_class_is_instance(self) -> None:
        """Класс, реализующий WorkflowStateListener, проходит isinstance."""
        class MyListener:
            """Полная реализация WorkflowStateListener."""

            def on_state_changed(self, doc_id, old_state, new_state, role) -> None:
                pass

            def on_mfa_required(self, operation) -> None:
                pass

            def on_undo_available(self, doc_id, description) -> None:
                pass

            def on_redo_available(self, doc_id, description) -> None:
                pass

        listener = MyListener()
        assert isinstance(listener, WorkflowStateListener)


class TestWorkflowTransitionResultConformance:
    """Тесты conformances WorkflowTransitionResult."""

    def test_conforming_class_is_instance(self) -> None:
        """Класс, реализующий WorkflowTransitionResult, проходит isinstance."""
        class MyResult:
            """Полная реализация WorkflowTransitionResult."""

            @property
            def success(self) -> bool:
                return True

            @property
            def from_state(self):
                return "draft"

            @property
            def to_state(self):
                return "filled"

            @property
            def reason(self) -> str:
                return "Заполнена"

            @property
            def mfa_verified(self) -> bool:
                return True

        result = MyResult()
        assert isinstance(result, WorkflowTransitionResult)
        assert result.success is True
        assert result.reason == "Заполнена"