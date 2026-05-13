"""Workflow Service для FX Text Processor 3.

Абстракция сервисного слоя для управления workflow документов.
Содержит бизнес-логику переходов между состояниями, проверку ролей и MFA.

Module: src/services/workflow_service.py
Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Final, List, Optional, Tuple
from uuid import UUID

from src.controller.workflow_controller import (
    ApprovalWorkflow,
    FormStatus,
    PermissionError,
    WorkflowEvent,
    WorkflowRole,
)

logger = logging.getLogger(__name__)

# Маппинг действий на переходы между состояниями
_TRANSITION_ACTIONS: Final[Dict[Tuple[FormStatus, FormStatus], str]] = {
    (FormStatus.DRAFT, FormStatus.FILLED): "submit",
    (FormStatus.DRAFT, FormStatus.REJECTED): "reject",
    (FormStatus.FILLED, FormStatus.VALIDATED): "submit",
    (FormStatus.FILLED, FormStatus.DRAFT): "edit",
    (FormStatus.FILLED, FormStatus.REJECTED): "reject",
    (FormStatus.VALIDATED, FormStatus.APPROVED): "approve",
    (FormStatus.VALIDATED, FormStatus.FILLED): "reject",
    (FormStatus.VALIDATED, FormStatus.REJECTED): "reject",
    (FormStatus.APPROVED, FormStatus.SIGNED): "sign",
    (FormStatus.APPROVED, FormStatus.VALIDATED): "reject",
    (FormStatus.APPROVED, FormStatus.REJECTED): "reject",
    (FormStatus.SIGNED, FormStatus.ARCHIVED): "archive",
    (FormStatus.SIGNED, FormStatus.APPROVED): "reject",
    (FormStatus.REJECTED, FormStatus.DRAFT): "edit",
}

# Маппинг WorkflowRole на строковые ключи ROLE_PERMISSIONS
_WORKFLOW_ROLE_TO_STR: Final[Dict[WorkflowRole, str]] = {
    WorkflowRole.OPERATOR: "creator",
    WorkflowRole.EDITOR: "reviewer",
    WorkflowRole.SUPERVISOR: "reviewer",
    WorkflowRole.SIGNATORY: "signer",
}

# Доступные действия для каждого состояния (для lookup в get_role_permissions)
_STATE_ACTIONS: Final[Dict[FormStatus, List[str]]] = {
    FormStatus.DRAFT: ["create", "edit", "submit", "view"],
    FormStatus.FILLED: ["review", "approve", "reject", "edit", "submit", "view"],
    FormStatus.VALIDATED: ["review", "approve", "reject", "sign", "view"],
    FormStatus.APPROVED: ["sign", "reject", "view"],
    FormStatus.SIGNED: ["archive", "reject", "view"],
    FormStatus.ARCHIVED: ["view"],
    FormStatus.REJECTED: ["edit", "view"],
}

# Словарь ролей и прав
ROLE_PERMISSIONS: Final[Dict[str, List[str]]] = {
    "creator": ["create", "edit", "submit", "view"],
    "reviewer": ["review", "approve", "reject", "view"],
    "signer": ["sign", "view"],
    "admin": ["create", "edit", "submit", "review", "approve", "reject", "sign", "archive", "view"],
}


class WorkflowService:
    """Сервис управления workflow документов.

    Реализует:
    - State machine для переходов между состояниями
    - Проверку прав ролей
    - MFA-требования для критичных переходов
    - Историю событий workflow

    Attributes:
        _workflow: State machine ApprovalWorkflow.
        _events: История workflow событий.
        _current_roles: Текущие роли пользователей {doc_id: WorkflowRole}.

    Example:
        >>> service = WorkflowService()
        >>> service.can_transition(doc_id, FormStatus.FILLED)
        True
        >>> service.transition(doc_id, FormStatus.VALIDATED, "Валидация", role)
    """

    def __init__(self) -> None:
        """Инициализирует сервис workflow."""
        self._workflow: ApprovalWorkflow = ApprovalWorkflow()
        self._events: Dict[UUID, List[WorkflowEvent]] = {}
        self._current_roles: Dict[UUID, WorkflowRole] = {}
        self._states: Dict[UUID, FormStatus] = {
            UUID("00000000-0000-0000-0000-000000000000"): FormStatus.DRAFT,
        }

    # --- Transition operations ---

    def can_transition(self, doc_id: UUID, to_state: FormStatus) -> bool:
        """Проверяет, возможен ли переход в указанное состояние.

        Args:
            doc_id: ID документа.
            to_state: Целевое состояние.

        Returns:
            True если переход допустим.
        """
        current_state = self._states.get(doc_id, FormStatus.DRAFT)
        return self._workflow.can_transition(current_state, to_state)

    def is_mfa_required(self, doc_id: UUID, to_state: FormStatus) -> bool:
        """Проверяет, требуется ли MFA для перехода.

        Args:
            doc_id: ID документа.
            to_state: Целевое состояние.

        Returns:
            True если переход требует MFA.
        """
        current_state = self._states.get(doc_id, FormStatus.DRAFT)
        return self._workflow.is_mfa_required(current_state, to_state)

    def get_allowed_transitions(self, doc_id: UUID) -> List[FormStatus]:
        """Возвращает список допустимых переходов для документа.

        Args:
            doc_id: ID документа.

        Returns:
            Список допустимых целевых состояний.
        """
        current_state = self._states.get(doc_id, FormStatus.DRAFT)
        return self._workflow.get_allowed_transitions(current_state)

    def transition(
        self,
        doc_id: UUID,
        to_state: FormStatus,
        reason: str,
        role: WorkflowRole,
        mfa_verified: bool = False,
    ) -> bool:
        """Выполняет переход в новое состояние.

        Args:
            doc_id: ID документа.
            to_state: Целевое состояние.
            reason: Причина перехода.
            role: Роль, выполняющая переход.
            mfa_verified: Подтверждено ли MFA.

        Returns:
            True если переход успешен.

        Raises:
           WorkflowTransitionError: Если переход недопустим.
            PermissionError: Если роль не имеет прав.
        """
        current_state = self._states.get(doc_id, FormStatus.DRAFT)

        if not self._workflow.can_transition(current_state, to_state):
            raise Exception(f"Недопустимый переход из {current_state.value} в {to_state.value}")

        # Check role permissions
        action = _TRANSITION_ACTIONS.get((current_state, to_state), "")
        if not self.has_permission(role, action):
            raise PermissionError(
                role.value,
                f"переход из {current_state.value} в {to_state.value}",
            )

        # Log transition
        self._add_event(
            doc_id=doc_id,
            from_state=current_state,
            to_state=to_state,
            role=role,
            reason=reason,
            mfa_verified=mfa_verified,
        )

        # Update state
        self._states[doc_id] = to_state
        self._current_roles[doc_id] = role

        logger.info(
            "Workflow transition: doc_id=%s %s->%s by %s (MFA=%s)",
            doc_id,
            current_state.value,
            to_state.value,
            role.value,
            mfa_verified,
        )

        return True

    # --- Role operations ---

    def get_current_role(self, doc_id: UUID) -> Optional[WorkflowRole]:
        """Возвращает текущую роль пользователя для документа.

        Args:
            doc_id: ID документа.

        Returns:
            Текущая роль или None.
        """
        return self._current_roles.get(doc_id)

    def set_role(self, doc_id: UUID, role: WorkflowRole) -> None:
        """Устанавливает роль пользователя для документа.

        Args:
            doc_id: ID документа.
            role: Новая роль.
        """
        self._current_roles[doc_id] = role
        logger.info("Role set for doc_id=%s: %s", doc_id, role.value)

    # --- State queries ---

    def get_current_state(self, doc_id: UUID) -> FormStatus:
        """Возвращает текущее состояние документа.

        Args:
            doc_id: ID документа.

        Returns:
            Текущее состояние.
        """
        return self._states.get(doc_id, FormStatus.DRAFT)

    def get_role_permissions(self, state: FormStatus) -> List[WorkflowRole]:
        """Возвращает список ролей, имеющих права для состояния.

        Args:
            state: Состояние документа.

        Returns:
            Список допустимых ролей.
        """
        allowed_roles: List[WorkflowRole] = []
        for role in WorkflowRole:
            for action in _STATE_ACTIONS.get(state, []):
                if self.has_permission(role, action):
                    allowed_roles.append(role)
                    break
        return allowed_roles

    def has_permission(self, role: WorkflowRole, action: str) -> bool:
        """Проверяет, имеет ли роль право на указанное действие.

        Zero Trust: deny by default — при неизвестной роли возвращает False.

        Args:
            role: Роль пользователя.
            action: Действие для проверки.

        Returns:
            True если роль имеет право на действие.
            False для неизвестных ролей.
        """
        role_str = _WORKFLOW_ROLE_TO_STR.get(role, "")
        if not role_str:
            logger.warning("Неизвестная роль '%s', deny by default", role.value)
            return False
        return action in ROLE_PERMISSIONS.get(role_str, [])

    # --- Event history ---

    def get_workflow_history(self, doc_id: UUID) -> List[WorkflowEvent]:
        """Возвращает историю workflow событий для документа.

        Args:
            doc_id: ID документа.

        Returns:
            Список событий в chronological order.
        """
        return self._events.get(doc_id, []).copy()

    # --- Internal helpers ---

    def _add_event(
        self,
        doc_id: UUID,
        from_state: FormStatus,
        to_state: FormStatus,
        role: WorkflowRole,
        reason: str,
        mfa_verified: bool,
    ) -> None:
        """Добавляет событие в историю workflow.

        Args:
            doc_id: ID документа.
            from_state: Исходное состояние.
            to_state: Целевое состояние.
            role: Роль, выполнившая переход.
            reason: Причина перехода.
            mfa_verified: Подтверждено ли MFA.
        """
        event = WorkflowEvent(
            event_id=f"{doc_id}:{from_state.value}:{to_state.value}:{datetime.now().timestamp()}",
            doc_id=doc_id,
            from_state=from_state,
            to_state=to_state,
            role=role,
            timestamp=datetime.now(),
            reason=reason,
            mfa_verified=mfa_verified,
        )

        if doc_id not in self._events:
            self._events[doc_id] = []
        self._events[doc_id].append(event)

    # --- Proxy to ApprovalWorkflow methods ---

    def __getattr__(self, name: str) -> Any:
        """Прокси-доступ к ApprovalWorkflow methods для совместимости с legacy кодом."""
        if hasattr(self._workflow, name):
            return getattr(self._workflow, name)
        raise AttributeError(f"'WorkflowService' object has no attribute '{name}'")
