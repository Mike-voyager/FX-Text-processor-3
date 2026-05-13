"""Integration module для workflow UI components.

Предоставляет удобные фабричные методы и адаптеры для интеграции
всех workflow компонентов в единую систему.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Optional
from uuid import UUID

if TYPE_CHECKING:
    from src.controller.workflow_controller import (
        FormStatus,
        WorkflowController,
        WorkflowRole,
    )
    from src.gui.dialogs.role_switch_dialog import RoleSwitchDialog
    from src.gui.dialogs.transition_dialog import TransitionDialog
    from src.gui.security.mfa_gate import MFAGate
    from src.gui.workflow.protocols import WorkflowStateListener
    from src.gui.workflow.state_manager import TransitionResult, WorkflowStateManager


class WorkflowUIFactory:
    """Фабрика для создания workflow UI компонентов.

    Централизованная точка создания всех workflow-related
    UI компонентов с автоматической интеграцией.

    Attributes:
        _state_manager: Менеджер состояний.
        _mfa_gate: MFA gate.

    Example:
        >>> factory = WorkflowUIFactory(controller, mfa_gate)
        >>> transition_dialog = factory.create_transition_dialog(
        ...     parent=root,
        ...     from_state=FormStatus.DRAFT,
        ...     to_state=FormStatus.FILLED,
        ... )
    """

    def __init__(
        self,
        workflow_controller: "WorkflowController",
        mfa_gate: "MFAGate",
    ) -> None:
        """Инициализация фабрики.

        Args:
            workflow_controller: Контроллер workflow.
            mfa_gate: MFA gate.
        """
        from src.gui.workflow.state_manager import WorkflowStateManager

        self._state_manager = WorkflowStateManager(
            workflow_controller=workflow_controller,
            mfa_gate=mfa_gate,
        )
        self._mfa_gate = mfa_gate

    def create_transition_dialog(
        self,
        parent: Any,
        from_state: "FormStatus",
        to_state: "FormStatus",
        reason: str = "",
        on_confirm: Optional[Callable[[str, bool], None]] = None,
    ) -> "TransitionDialog":
        """Создаёт диалог перехода состояния.

        Args:
            parent: Родительский виджет.
            from_state: Исходное состояние.
            to_state: Целевое состояние.
            reason: Причина перехода.
            on_confirm: Callback при подтверждении.

        Returns:
            Созданный диалог.
        """
        from src.gui.dialogs.transition_dialog import TransitionDialog
        from src.gui.workflow.mfa_checker import MFARequirementChecker

        # Check if MFA required
        checker = MFARequirementChecker()
        requires_mfa = checker.is_transition_mfa_required(from_state, to_state)

        return TransitionDialog(
            parent=parent,
            from_state=from_state,
            to_state=to_state,
            requires_mfa=requires_mfa,
            on_confirm=on_confirm,
        )

    def create_role_switch_dialog(
        self,
        parent: Any,
        current_role: "WorkflowRole",
        free_mode: bool = False,
        on_role_selected: Optional[Callable[["WorkflowRole", bool], None]] = None,
    ) -> "RoleSwitchDialog":
        """Создаёт диалог смены роли.

        Args:
            parent: Родительский виджет.
            current_role: Текущая роль.
            free_mode: Режим свободного переключения.
            on_role_selected: Callback при выборе роли.

        Returns:
            Созданный диалог.
        """
        from src.gui.dialogs.role_switch_dialog import RoleSwitchDialog

        return RoleSwitchDialog(
            parent=parent,
            current_role=current_role,
            free_mode_enabled=free_mode,
            on_role_selected=on_role_selected,
        )

    @property
    def state_manager(self) -> "WorkflowStateManager":
        """Возвращает менеджер состояний."""
        return self._state_manager

    def request_transition(
        self,
        doc_id: UUID,
        target_state: "FormStatus",
        reason: str = "",
    ) -> "TransitionResult":
        """Запрашивает переход через StateManager.

        Args:
            doc_id: ID документа.
            target_state: Целевое состояние.
            reason: Причина перехода.

        Returns:
            Результат перехода.
        """
        return self._state_manager.request_transition(
            doc_id=doc_id,
            target_state=target_state,
            reason=reason,
        )

    def can_undo(self, doc_id: UUID) -> bool:
        """Проверяет возможность отмены."""
        return self._state_manager.can_undo(doc_id)

    def can_redo(self, doc_id: UUID) -> bool:
        """Проверяет возможность повтора."""
        return self._state_manager.can_redo(doc_id)

    def undo(self, doc_id: UUID) -> bool:
        """Отменяет последний переход."""
        return self._state_manager.undo(doc_id)

    def redo(self, doc_id: UUID) -> bool:
        """Повторяет отменённый переход."""
        return self._state_manager.redo(doc_id)


class WorkflowUIBuilder:
    """Builder для пошагового создания workflow UI.

    Позволяет настраивать все аспекты workflow UI
    через fluent interface.

    Example:
        >>> ui = (WorkflowUIBuilder(controller, mfa_gate)
        ...     .with_undo_redo()
        ...     .with_free_role_mode()
        ...     .with_listeners([listener])
        ...     .build())
    """

    def __init__(
        self,
        workflow_controller: "WorkflowController",
        mfa_gate: "MFAGate",
    ) -> None:
        """Инициализация builder."""
        self._factory = WorkflowUIFactory(workflow_controller, mfa_gate)
        self._listeners: list["WorkflowStateListener"] = []
        self._free_role_mode = False
        self._max_undo_steps = 50

    def with_undo_redo(self, max_steps: int = 50) -> "WorkflowUIBuilder":
        """Настраивает undo/redo.

        Args:
            max_steps: Максимальное количество undo шагов.

        Returns:
            Self для chaining.
        """
        self._max_undo_steps = max_steps
        return self

    def with_free_role_mode(self, enabled: bool = True) -> "WorkflowUIBuilder":
        """Включает режим свободного переключения ролей.

        Args:
            enabled: True для включения.

        Returns:
            Self для chaining.
        """
        self._free_role_mode = enabled
        return self

    def with_listeners(
        self,
        listeners: list["WorkflowStateListener"],
    ) -> "WorkflowUIBuilder":
        """Добавляет слушателей.

        Args:
            listeners: Список слушателей.

        Returns:
            Self для chaining.
        """
        self._listeners.extend(listeners)
        return self

    def build(self) -> WorkflowUIFactory:
        """Создаёт UI factory с настроенными компонентами."""
        # Apply settings
        if self._free_role_mode:
            self._factory.state_manager.set_free_role_mode(True)

        # Register listeners
        for listener in self._listeners:
            self._factory.state_manager.add_listener(listener)

        return self._factory


__all__ = [
    "WorkflowUIFactory",
    "WorkflowUIBuilder",
]
