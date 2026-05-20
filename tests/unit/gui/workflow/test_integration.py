"""Тесты для workflow integration module.

Проверяет WorkflowUIFactory и WorkflowUIBuilder.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from src.gui.workflow.integration import WorkflowUIBuilder, WorkflowUIFactory


def _make_controller() -> MagicMock:
    """Создаёт поддельный WorkflowController."""
    controller = MagicMock()
    controller.get_current_state = MagicMock()
    controller.can_transition = MagicMock(return_value=True)
    controller.transition = MagicMock()
    controller.current_role = MagicMock()
    controller.current_role.value = "operator"
    return controller


def _make_mfa_gate() -> MagicMock:
    """Создаёт поддельный MFAGate."""
    mfa_gate = MagicMock()
    mfa_gate.execute = MagicMock(side_effect=lambda **kwargs: kwargs.get("operation", lambda: None)())
    return mfa_gate


class TestWorkflowUIFactory:
    """Тесты WorkflowUIFactory."""

    def test_create_factory(self) -> None:
        """Фабрика создаётся корректно."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        factory = WorkflowUIFactory(controller, mfa_gate)
        assert factory._state_manager is not None
        assert factory._mfa_gate is mfa_gate

    def test_state_manager_property(self) -> None:
        """state_manager возвращает менеджер состояний."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        factory = WorkflowUIFactory(controller, mfa_gate)
        sm = factory.state_manager
        assert sm is not None

    def test_request_transition(self) -> None:
        """request_transition делегирует StateManager."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        factory = WorkflowUIFactory(controller, mfa_gate)
        # Мокаем StateManager для упрощения
        factory._state_manager.request_transition = MagicMock(
            return_value=MagicMock(success=False, error_message="test")
        )

        doc_id = uuid4()
        from enum import Enum

        class FakeFormStatus(Enum):
            FILLED = "filled"

        result = factory.request_transition(
            doc_id=doc_id,
            target_state=FakeFormStatus.FILLED,
            reason="Тест",
        )
        factory._state_manager.request_transition.assert_called_once()

    def test_can_undo(self) -> None:
        """can_undo делегирует StateManager."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        factory = WorkflowUIFactory(controller, mfa_gate)
        factory._state_manager.can_undo = MagicMock(return_value=True)

        doc_id = uuid4()
        assert factory.can_undo(doc_id) is True

    def test_can_redo(self) -> None:
        """can_redo делегирует StateManager."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        factory = WorkflowUIFactory(controller, mfa_gate)
        factory._state_manager.can_redo = MagicMock(return_value=False)

        doc_id = uuid4()
        assert factory.can_redo(doc_id) is False

    def test_undo(self) -> None:
        """undo делегирует StateManager."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        factory = WorkflowUIFactory(controller, mfa_gate)
        factory._state_manager.undo = MagicMock(return_value=True)

        doc_id = uuid4()
        assert factory.undo(doc_id) is True

    def test_redo(self) -> None:
        """redo делегирует StateManager."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        factory = WorkflowUIFactory(controller, mfa_gate)
        factory._state_manager.redo = MagicMock(return_value=False)

        doc_id = uuid4()
        assert factory.redo(doc_id) is False


class TestWorkflowUIBuilder:
    """Тесты WorkflowUIBuilder."""

    def test_builder_creates_factory(self) -> None:
        """Builder создаёт WorkflowUIFactory."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        builder = WorkflowUIBuilder(controller, mfa_gate)
        factory = builder.build()
        assert isinstance(factory, WorkflowUIFactory)

    def test_builder_with_undo_redo(self) -> None:
        """with_undo_redo настраивает max_steps."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        builder = WorkflowUIBuilder(controller, mfa_gate)
        factory = builder.with_undo_redo(max_steps=100).build()
        assert isinstance(factory, WorkflowUIFactory)

    def test_builder_with_free_role_mode(self) -> None:
        """with_free_role_mode включает свободный режим."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        builder = WorkflowUIBuilder(controller, mfa_gate)
        factory = builder.with_free_role_mode(enabled=True).build()
        assert isinstance(factory, WorkflowUIFactory)

    def test_builder_with_listeners(self) -> None:
        """with_listeners добавляет слушателей."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        class FakeListener:
            def on_state_changed(self, doc_id, old_state, new_state, role) -> None:
                pass

            def on_mfa_required(self, operation) -> None:
                pass

            def on_undo_available(self, doc_id, description) -> None:
                pass

            def on_redo_available(self, doc_id, description) -> None:
                pass

        listener = FakeListener()
        builder = WorkflowUIBuilder(controller, mfa_gate)
        factory = builder.with_listeners([listener]).build()
        assert isinstance(factory, WorkflowUIFactory)

    def test_builder_chaining(self) -> None:
        """Builder поддерживает chaining."""
        controller = _make_controller()
        mfa_gate = _make_mfa_gate()

        builder = WorkflowUIBuilder(controller, mfa_gate)
        factory = (
            builder
            .with_undo_redo(max_steps=25)
            .with_free_role_mode()
            .build()
        )
        assert isinstance(factory, WorkflowUIFactory)