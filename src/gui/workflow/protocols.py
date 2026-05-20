"""Workflow UI Protocols для FX Text Processor 3.

Определяет интерфейсы для workflow UI компонентов с поддержкой
state transitions, MFA challenges и undo/redo операций.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Protocol, runtime_checkable
from uuid import UUID

if TYPE_CHECKING:
    from src.controller.workflow_controller import FormStatus, WorkflowRole


@runtime_checkable
class WorkflowUIProtocol(Protocol):
    """Protocol для workflow UI компонентов.

    Определяет интерфейс для диалогов и виджетов, управляющих
    workflow состояниями документов.

    Example:
        >>> class MyWorkflowDialog(WorkflowUIProtocol):
        ...     def show_transition_dialog(self, from_state, to_state, on_confirm, on_cancel):
        ...         # Implementation
        ...         pass
    """

    def show_transition_dialog(
        self,
        from_state: "FormStatus",
        to_state: "FormStatus",
        on_confirm: Callable[[str], None],
        on_cancel: Callable[[], None],
    ) -> None:
        """Показывает диалог подтверждения перехода состояния.

        Args:
            from_state: Исходное состояние документа.
            to_state: Целевое состояние документа.
            on_confirm: Callback при подтверждении с причиной перехода.
            on_cancel: Callback при отмене.
        """
        ...

    def update_workflow_indicator(self, status: "FormStatus") -> None:
        """Обновляет индикатор текущего состояния workflow.

        Args:
            status: Новое состояние документа.
        """
        ...

    def show_mfa_challenge(
        self,
        operation: str,
        callback: Callable[[bool], None],
    ) -> None:
        """Показывает MFA challenge для критичной операции.

        Args:
            operation: Описание операции для отображения.
            callback: Колбэк с результатом (True = подтверждено).
        """
        ...

    def can_execute_transition(
        self,
        from_state: "FormStatus",
        to_state: "FormStatus",
    ) -> bool:
        """Проверяет возможность выполнения перехода.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            True если переход разрешён.
        """
        ...

    def can_undo(self, doc_id: UUID) -> bool:
        """Проверяет возможность отмены последнего перехода.

        Args:
            doc_id: ID документа.

        Returns:
            True если можно отменить последний переход.
        """
        ...

    def can_redo(self, doc_id: UUID) -> bool:
        """Проверяет возможность повтора отменённого перехода.

        Args:
            doc_id: ID документа.

        Returns:
            True если можно повторить отменённый переход.
        """
        ...

    def undo_transition(self, doc_id: UUID) -> bool:
        """Отменяет последний переход для документа.

        Args:
            doc_id: ID документа.

        Returns:
            True если отмена выполнена успешно.
        """
        ...

    def redo_transition(self, doc_id: UUID) -> bool:
        """Повторяет отменённый переход для документа.

        Args:
            doc_id: ID документа.

        Returns:
            True если повтор выполнен успешно.
        """
        ...


@runtime_checkable
class WorkflowStateListener(Protocol):
    """Protocol для слушателей изменений состояния workflow.

    Компоненты, реализующие этот protocol, получают уведомления
    о событиях workflow и могут реагировать на них.

    Example:
        >>> class StatusBarListener(WorkflowStateListener):
        ...     def on_state_changed(self, doc_id, old_state, new_state, role):
        ...         self.update_status_display(new_state)
    """

    def on_state_changed(
        self,
        doc_id: UUID,
        old_state: "FormStatus",
        new_state: "FormStatus",
        role: "WorkflowRole",
    ) -> None:
        """Вызывается при изменении состояния документа.

        Args:
            doc_id: ID документа.
            old_state: Предыдущее состояние.
            new_state: Новое состояние.
            role: Роль, выполнившая переход.
        """
        ...

    def on_mfa_required(self, operation: str) -> None:
        """Вызывается при необходимости MFA.

        Args:
            operation: Описание операции.
        """
        ...

    def on_undo_available(self, doc_id: UUID, description: str) -> None:
        """Вызывается когда становится доступна операция undo.

        Args:
            doc_id: ID документа.
            description: Описание операции для отмены.
        """
        ...

    def on_redo_available(self, doc_id: UUID, description: str) -> None:
        """Вызывается когда становится доступна операция redo.

        Args:
            doc_id: ID документа.
            description: Описание операции для повтора.
        """
        ...


@runtime_checkable
class WorkflowTransitionResult(Protocol):
    """Protocol для результата перехода workflow.

    Определяет структуру данных, возвращаемую после выполнения
    перехода состояния.
    """

    @property
    def success(self) -> bool:
        """True если переход выполнен успешно."""
        ...

    @property
    def from_state(self) -> "FormStatus":
        """Исходное состояние."""
        ...

    @property
    def to_state(self) -> "FormStatus":
        """Целевое состояние."""
        ...

    @property
    def reason(self) -> str:
        """Причина перехода."""
        ...

    @property
    def mfa_verified(self) -> bool:
        """True если MFA было подтверждено."""
        ...


__all__ = [
    "WorkflowUIProtocol",
    "WorkflowStateListener",
    "WorkflowTransitionResult",
]
