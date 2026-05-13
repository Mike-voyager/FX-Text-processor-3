"""WorkflowManager — центральный менеджер для управления видимостью workflow действий.

Определяет доступные действия на основе пересечения ролевых прав
и допустимых действий в текущем состоянии документа.

Реализует таблицу visible actions по роли + статусу из GUI_ARCHITECTURE §5.2.

Example:
    >>> from src.gui.workflow.workflow_manager import WorkflowManager
    >>> manager = WorkflowManager()
    >>> actions = manager.get_visible_actions(
    ...     WorkflowRole.OPERATOR, FormStatus.DRAFT
    ... )
    >>> "save_draft" in actions
    True

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from src.controller.workflow_controller import FormStatus, WorkflowRole

# =============================================================================
# ACTION TABLES
# =============================================================================

# Действия, доступные для каждой роли
ROLE_ACTIONS: Final[dict[str, set[str]]] = {
    "operator": {
        "fill_fields",
        "save_draft",
        "print",
        "switch_to_editor",
    },
    "editor": {
        "fill_fields",
        "validate",
        "reject",
        "save_draft",
        "switch_to_operator",
        "switch_to_supervisor",
    },
    "supervisor": {
        "validate",
        "approve",
        "reject",
        "view_comments",
        "switch_to_editor",
        "switch_to_signatory",
    },
    "signatory": {
        "sign",
        "reject",
        "view_comments",
        "print",
        "switch_to_supervisor",
    },
}

# Действия, доступные в каждом состоянии документа
STATE_ACTIONS: Final[dict[str, set[str]]] = {
    "draft": {
        "fill_fields",
        "save_draft",
        "submit_for_validation",
        "switch_role",
    },
    "filled": {
        "validate",
        "reject",
        "view_comments",
    },
    "validated": {
        "approve",
        "reject",
        "view_comments",
    },
    "approved": {
        "sign",
        "reject",
        "view_comments",
    },
    "signed": {
        "print",
        "archive",
    },
    "printed": {
        "print",
        "archive",
    },
    "archived": set(),
    "rejected": set(),
}


class WorkflowManager:
    """Менеджер видимости workflow действий по роли и статусу.

    Attributes:
        current_role: Текущая активная роль.
    """

    def __init__(self, initial_role: str = "operator") -> None:
        """Инициализация менеджера.

        Args:
            initial_role: Начальная роль (строковое значение WorkflowRole).
        """
        self._current_role_value: str = initial_role

    # -------------------------------------------------------------------------
    # Role Management
    # -------------------------------------------------------------------------

    @property
    def current_role(self) -> WorkflowRole:
        """Возвращает текущую активную роль.

        Returns:
            Текущая роль пользователя.
        """
        from src.controller.workflow_controller import WorkflowRole

        return WorkflowRole(self._current_role_value)

    def set_role(self, role: WorkflowRole) -> None:
        """Устанавливает текущую роль.

        Args:
            role: Новая роль.
        """
        self._current_role_value = role.value

    # -------------------------------------------------------------------------
    # Action Resolution
    # -------------------------------------------------------------------------

    def get_visible_actions(self, role: WorkflowRole, status: FormStatus) -> set[str]:
        """Возвращает множество видимых действий для роли и статуса.

        Вычисляет пересечение действий, разрешённых роли,
        и действий, разрешённых в данном состоянии документа.

        Args:
            role: Роль пользователя.
            status: Текущий статус формы.

        Returns:
            Множество имён доступных действий.

        Example:
            >>> manager = WorkflowManager()
            >>> actions = manager.get_visible_actions(
            ...     WorkflowRole.OPERATOR, FormStatus.DRAFT
            ... )
            >>> "save_draft" in actions
            True
            >>> "approve" in actions
            False
        """
        role_actions = ROLE_ACTIONS.get(role.value, set())
        state_actions = STATE_ACTIONS.get(status.value, set())
        return role_actions & state_actions


__all__ = [
    "WorkflowManager",
    "ROLE_ACTIONS",
    "STATE_ACTIONS",
]
