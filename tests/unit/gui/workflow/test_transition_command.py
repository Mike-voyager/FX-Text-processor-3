"""Тесты для workflow transition command.

Проверяет Command паттерн для workflow переходов,
включая execute, undo, redo и WorkflowCommandHistory.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.gui.workflow.transition_command import (
    WorkflowCommandFactory,
    WorkflowCommandHistory,
    WorkflowTransitionCommand,
)
from src.gui.workflow.snapshot import TransitionSnapshot


class _FakeFormStatus(Enum):
    """Поддельный FormStatus для тестов."""
    DRAFT = "draft"
    FILLED = "filled"
    VALIDATED = "validated"
    APPROVED = "approved"
    SIGNED = "signed"
    ARCHIVED = "archived"


class _FakeWorkflowRole(Enum):
    """Поддельный WorkflowRole для тестов."""
    OPERATOR = "operator"


def _make_snapshot(
    status: _FakeFormStatus = _FakeFormStatus.DRAFT,
) -> TransitionSnapshot:
    """Создаёт тестовый снимок."""
    return TransitionSnapshot(
        form_status=status,
        field_values={"field1": "value1"},
        comments=[],
        timestamp=datetime.now(),
        role=_FakeWorkflowRole.OPERATOR,
    )


def _make_controller() -> MagicMock:
    """Создаёт поддельный WorkflowController."""
    controller = MagicMock()
    controller.transition = MagicMock()
    return controller


class TestWorkflowTransitionCommand:
    """Тесты WorkflowTransitionCommand."""

    def test_execute(self) -> None:
        """Выполнение перехода."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Заполнение формы",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        command.execute()
        assert command._executed is True
        controller.transition.assert_called_once()

    def test_execute_idempotent(self) -> None:
        """Повторный execute не вызывает переход."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Заполнение",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        command.execute()
        command.execute()  # Второй вызов
        assert controller.transition.call_count == 1

    def test_undo_archived_not_allowed(self) -> None:
        """Undo для ARCHIVED не выполняется."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.SIGNED,
            to_state=_FakeFormStatus.ARCHIVED,
            reason="Архивация",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        command.execute()
        command.undo()
        # is_undoable = False для archived
        assert command.is_undoable is False
        assert command._undone is False

    def test_description(self) -> None:
        """Описание команды корректно."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        assert "draft" in command.description
        assert "filled" in command.description

    def test_description_for_undo(self) -> None:
        """Описание для undo меню."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        assert "filled" in command.description_for_undo

    def test_description_for_redo(self) -> None:
        """Описание для redo меню."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        assert "filled" in command.description_for_redo

    def test_can_undo_before_execute(self) -> None:
        """can_undo=False до выполнения."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        assert command.can_undo() is False

    def test_can_undo_after_execute(self) -> None:
        """can_undo=True после выполнения (для не-archived)."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        command.execute()
        assert command.can_undo() is True

    def test_redo(self) -> None:
        """Redo после undo выполняет переход заново."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        command.execute()
        command.undo()
        command.redo()
        assert command._executed is True
        assert command._undone is False

    def test_doc_id_property(self) -> None:
        """doc_id возвращает правильный ID."""
        doc_id = uuid4()
        controller = _make_controller()
        snapshot = _make_snapshot()

        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )

        assert command.doc_id == doc_id


class TestWorkflowCommandFactory:
    """Тесты WorkflowCommandFactory."""

    def test_create_transition_command(self) -> None:
        """Фабрика создаёт команду перехода."""
        controller = _make_controller()
        factory = WorkflowCommandFactory(controller)
        doc_id = uuid4()
        snapshot = _make_snapshot()

        command = factory.create_transition_command(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Заполнение",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
        )

        assert isinstance(command, WorkflowTransitionCommand)
        assert command.doc_id == doc_id


class TestWorkflowCommandHistory:
    """Тесты WorkflowCommandHistory."""

    def test_push_and_can_undo(self) -> None:
        """После push can_undo=True."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)

        controller = _make_controller()
        snapshot = _make_snapshot()
        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )
        command.execute()

        history.push(command)
        assert history.can_undo() is True
        assert history.can_redo() is False

    def test_undo(self) -> None:
        """Undo возвращает команду и переключает стеки."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)

        controller = _make_controller()
        snapshot = _make_snapshot()
        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )
        command.execute()
        history.push(command)

        undone = history.undo()
        assert undone is not None
        assert history.can_undo() is False
        assert history.can_redo() is True

    def test_redo(self) -> None:
        """Redo после undo возвращает команду."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)

        controller = _make_controller()
        snapshot = _make_snapshot()
        command = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snapshot,
            workflow_controller=controller,
        )
        command.execute()
        history.push(command)

        history.undo()
        redone = history.redo()
        assert redone is not None
        assert history.can_undo() is True
        assert history.can_redo() is False

    def test_undo_empty_stack(self) -> None:
        """Undo пустого стека возвращает None."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)
        assert history.undo() is None

    def test_redo_empty_stack(self) -> None:
        """Redo пустого стека возвращает None."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)
        assert history.redo() is None

    def test_new_action_clears_redo(self) -> None:
        """Новая команда очищает redo стек."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)

        controller = _make_controller()

        # Первая команда
        snap1 = _make_snapshot()
        cmd1 = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="1",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snap1,
            workflow_controller=controller,
        )
        cmd1.execute()
        history.push(cmd1)
        history.undo()

        # Новая команда очищает redo
        snap2 = _make_snapshot(_FakeFormStatus.FILLED)
        cmd2 = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.FILLED,
            to_state=_FakeFormStatus.VALIDATED,
            reason="2",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snap2,
            workflow_controller=controller,
        )
        cmd2.execute()
        history.push(cmd2)

        assert history.can_redo() is False

    def test_max_size(self) -> None:
        """Превышение max_size удаляет старые команды."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id, max_size=2)

        controller = _make_controller()

        for i in range(5):
            snap = _make_snapshot()
            cmd = WorkflowTransitionCommand(
                doc_id=doc_id,
                from_state=_FakeFormStatus.DRAFT,
                to_state=_FakeFormStatus.FILLED,
                reason=str(i),
                role=_FakeWorkflowRole.OPERATOR,
                before_snapshot=snap,
                workflow_controller=controller,
            )
            cmd.execute()
            history.push(cmd)

        assert len(history._undo_stack) <= 2

    def test_get_undo_description(self) -> None:
        """get_undo_description возвращает описание."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)

        controller = _make_controller()
        snap = _make_snapshot()
        cmd = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snap,
            workflow_controller=controller,
        )
        cmd.execute()
        history.push(cmd)

        desc = history.get_undo_description()
        assert desc is not None
        assert len(desc) > 0

    def test_get_undo_description_empty(self) -> None:
        """get_undo_description для пустого стека возвращает None."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)
        assert history.get_undo_description() is None

    def test_get_redo_description(self) -> None:
        """get_redo_description возвращает описание после undo."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)

        controller = _make_controller()
        snap = _make_snapshot()
        cmd = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snap,
            workflow_controller=controller,
        )
        cmd.execute()
        history.push(cmd)
        history.undo()

        desc = history.get_redo_description()
        assert desc is not None

    def test_clear(self) -> None:
        """clear() очищает обе стеки."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)

        controller = _make_controller()
        snap = _make_snapshot()
        cmd = WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=_FakeFormStatus.DRAFT,
            to_state=_FakeFormStatus.FILLED,
            reason="Тест",
            role=_FakeWorkflowRole.OPERATOR,
            before_snapshot=snap,
            workflow_controller=controller,
        )
        cmd.execute()
        history.push(cmd)
        history.undo()

        history.clear()
        assert history.can_undo() is False
        assert history.can_redo() is False

    def test_doc_id_property(self) -> None:
        """doc_id возвращает правильный ID."""
        doc_id = uuid4()
        history = WorkflowCommandHistory(doc_id=doc_id)
        assert history.doc_id == doc_id