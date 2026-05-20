"""Тесты для WorkflowManager.

Проверяет корректность таблиц ROLE_ACTIONS и STATE_ACTIONS,
а также метод get_visible_actions.
"""

from __future__ import annotations

import pytest

from src.controller.workflow_controller import FormStatus, WorkflowRole
from src.gui.workflow.workflow_manager import (
    ROLE_ACTIONS,
    STATE_ACTIONS,
    WorkflowManager,
)


class TestWorkflowManagerTables:
    """Тесты таблиц доступных действий."""

    def test_role_actions_operator(self) -> None:
        """OPERATOR имеет ожидаемые действия."""
        assert ROLE_ACTIONS["operator"] == {
            "fill_fields",
            "save_draft",
            "print",
            "switch_to_editor",
        }

    def test_role_actions_editor(self) -> None:
        """EDITOR имеет ожидаемые действия."""
        assert ROLE_ACTIONS["editor"] == {
            "fill_fields",
            "validate",
            "reject",
            "save_draft",
            "switch_to_operator",
            "switch_to_supervisor",
        }

    def test_role_actions_supervisor(self) -> None:
        """SUPERVISOR имеет ожидаемые действия."""
        assert ROLE_ACTIONS["supervisor"] == {
            "validate",
            "approve",
            "reject",
            "view_comments",
            "switch_to_editor",
            "switch_to_signatory",
        }

    def test_role_actions_signatory(self) -> None:
        """SIGNATORY имеет ожидаемые действия."""
        assert ROLE_ACTIONS["signatory"] == {
            "sign",
            "reject",
            "view_comments",
            "print",
            "switch_to_supervisor",
        }

    def test_state_actions_draft(self) -> None:
        """DRAFT позволяет заполнение и сохранение."""
        assert STATE_ACTIONS["draft"] == {
            "fill_fields",
            "save_draft",
            "submit_for_validation",
            "switch_role",
        }

    def test_state_actions_filled(self) -> None:
        """FILLED позволяет валидацию и отклонение."""
        assert STATE_ACTIONS["filled"] == {
            "validate",
            "reject",
            "view_comments",
        }

    def test_state_actions_validated(self) -> None:
        """VALIDATED позволяет утверждение и отклонение."""
        assert STATE_ACTIONS["validated"] == {
            "approve",
            "reject",
            "view_comments",
        }

    def test_state_actions_approved(self) -> None:
        """APPROVED позволяет подписание и отклонение."""
        assert STATE_ACTIONS["approved"] == {
            "sign",
            "reject",
            "view_comments",
        }

    def test_state_actions_signed(self) -> None:
        """SIGNED позволяет печать и архивацию."""
        assert STATE_ACTIONS["signed"] == {
            "print",
            "archive",
        }

    def test_state_actions_archived_empty(self) -> None:
        """ARCHIVED не позволяет никаких действий."""
        assert STATE_ACTIONS["archived"] == set()


class TestWorkflowManagerGetVisibleActions:
    """Тесты метода get_visible_actions."""

    def test_operator_draft(self) -> None:
        """OPERATOR в DRAFT видит fill_fields и save_draft."""
        manager = WorkflowManager()
        actions = manager.get_visible_actions(
            WorkflowRole.OPERATOR, FormStatus.DRAFT
        )
        assert actions == {"fill_fields", "save_draft"}

    def test_editor_filled(self) -> None:
        """EDITOR в FILLED видит validate и reject (view_comments недоступен редактору)."""
        manager = WorkflowManager()
        actions = manager.get_visible_actions(
            WorkflowRole.EDITOR, FormStatus.FILLED
        )
        assert actions == {"validate", "reject"}

    def test_supervisor_validated(self) -> None:
        """SUPERVISOR в VALIDATED видит approve, reject, view_comments."""
        manager = WorkflowManager()
        actions = manager.get_visible_actions(
            WorkflowRole.SUPERVISOR, FormStatus.VALIDATED
        )
        assert actions == {"approve", "reject", "view_comments"}

    def test_signatory_approved(self) -> None:
        """SIGNATORY в APPROVED видит sign, reject, view_comments."""
        manager = WorkflowManager()
        actions = manager.get_visible_actions(
            WorkflowRole.SIGNATORY, FormStatus.APPROVED
        )
        assert actions == {"sign", "reject", "view_comments"}

    def test_operator_signed_empty(self) -> None:
        """OPERATOR в SIGNED видит print (обе таблицы разрешают)."""
        manager = WorkflowManager()
        actions = manager.get_visible_actions(
            WorkflowRole.OPERATOR, FormStatus.SIGNED
        )
        assert actions == {"print"}

    def test_archived_any_role_empty(self) -> None:
        """В ARCHIVED никакая роль не видит действий."""
        manager = WorkflowManager()
        for role in WorkflowRole:
            actions = manager.get_visible_actions(role, FormStatus.ARCHIVED)
            assert actions == set(), f"{role.value} should see no actions in ARCHIVED"


class TestWorkflowManagerRoleProperty:
    """Тесты свойства current_role."""

    def test_default_role_is_operator(self) -> None:
        """По умолчанию роль OPERATOR."""
        manager = WorkflowManager()
        assert manager.current_role == WorkflowRole.OPERATOR.value

    def test_set_role(self) -> None:
        """set_role обновляет current_role."""
        manager = WorkflowManager()
        manager.set_role(WorkflowRole.SUPERVISOR)
        assert manager.current_role == WorkflowRole.SUPERVISOR.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
