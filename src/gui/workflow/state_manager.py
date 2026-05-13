"""WorkflowStateManager — GUI-layer менеджер состояний workflow.

Предоставляет управление состояниями документов с интеграцией
MFA-gated transitions и поддержкой undo/redo операций.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Final, List, Optional, Set
from uuid import UUID

if TYPE_CHECKING:
    from src.controller.workflow_controller import (
        FormStatus,
        WorkflowController,
        WorkflowRole,
    )
    from src.gui.security.mfa_gate import MFAGate
    from src.gui.workflow.protocols import WorkflowStateListener
    from src.gui.workflow.snapshot import TransitionSnapshot
    from src.gui.workflow.transition_command import (
        WorkflowCommandHistory,
        WorkflowTransitionCommand,
    )


# Статусы, доступные в Simple Mode
_SIMPLE_MODE_STATES: set[str] = {"draft", "signed"}

# Действия, доступные в Simple Mode
_SIMPLE_MODE_ACTIONS: set[str] = {
    "fill_fields",
    "save_draft",
    "sign",
    "reject",
    "print",
}

# Переходы Simple Mode: DRAFT ↔ SIGNED.
_SIMPLE_MODE_ALLOWED_TRANSITIONS: Final[dict[str, list[str]]] = {
    "draft": ["signed"],
    "signed": ["draft"],
}

# MFA требуется для перехода DRAFT → SIGNED в Simple Mode.
_SIMPLE_MODE_MFA_TRANSITIONS: Final[set[tuple[str, str]]] = {
    ("draft", "signed"),
}


@dataclass(frozen=True)
class TransitionRequest:
    """Запрос на переход состояния.

    Attributes:
        doc_id: ID документа.
        target_state: Целевое состояние.
        reason: Причина перехода.
        skip_mfa: Пропустить MFA (только для внутреннего использования).
    """

    doc_id: UUID
    target_state: "FormStatus"
    reason: str
    skip_mfa: bool = False


@dataclass(frozen=True)
class TransitionResult:
    """Результат перехода состояния.

    Attributes:
        success: Успешность перехода.
        from_state: Исходное состояние.
        to_state: Целевое состояние.
        reason: Причина перехода.
        mfa_verified: MFA подтверждено.
        error_message: Сообщение об ошибке.
        command: Созданная команда (для undo).
    """

    success: bool
    from_state: Optional["FormStatus"] = None
    to_state: Optional["FormStatus"] = None
    reason: str = ""
    mfa_verified: bool = False
    error_message: Optional[str] = None
    command: Optional["WorkflowTransitionCommand"] = None


class WorkflowStateManager:
    """Менеджер состояний workflow с MFA-gated transitions и undo/redo.

    Ответственности:
    - Отслеживание текущего состояния документа
    - Валидация переходов перед выполнением
    - Запрос MFA для критичных переходов
    - Управление undo/redo стеком
    - Уведомление слушателей об изменениях
    - Simple Mode: только DRAFT ↔ SIGNED

    Attributes:
        workflow_controller: Бэкенд контроллер workflow.
        mfa_gate: Gate для MFA операций.
        snapshot_manager: Менеджер снимков для undo.
        listeners: Список слушателей изменений состояния.
        _command_histories: История команд по doc_id.
        _lock: Блокировка для thread-safety.
        _max_undo_steps: Максимальное количество undo шагов.
        _simple_mode: Флаг Simple Mode.
        _hidden_states: Скрытые состояния в Simple Mode.

    Example:
        >>> manager = WorkflowStateManager(
        ...     workflow_controller=controller,
        ...     mfa_gate=mfa_gate,
        ... )
        >>> result = manager.request_transition(doc_id, FormStatus.FILLED)
        >>> if result.success:
        ...     print(f"Transitioned to {result.to_state}")
        >>> manager.undo(doc_id)  # Отмена
    """

    def __init__(
        self,
        workflow_controller: "WorkflowController",
        mfa_gate: "MFAGate",
        max_undo_steps: int = 50,
        simple_mode: bool = False,
    ) -> None:
        """Инициализация менеджера состояний.

        Args:
            workflow_controller: Контроллер workflow.
            mfa_gate: MFA gate для проверки.
            max_undo_steps: Максимальное количество undo шагов.
            simple_mode: Если True, использовать упрощённый workflow.
        """
        if workflow_controller is None:
            raise ValueError("workflow_controller обязателен")
        if mfa_gate is None:
            raise ValueError("mfa_gate обязателен")

        self.workflow_controller = workflow_controller
        self.mfa_gate = mfa_gate
        self._max_undo_steps = max_undo_steps
        self._simple_mode: bool = simple_mode

        # Internal state
        self.listeners: List["WorkflowStateListener"] = []
        self._command_histories: Dict[UUID, "WorkflowCommandHistory"] = {}
        self._lock = threading.Lock()

        # Initialize snapshot manager
        from src.gui.workflow.snapshot import SnapshotManager

        self._snapshot_manager = SnapshotManager(max_snapshots_per_doc=max_undo_steps * 2)

        # MFA checker
        from src.gui.workflow.mfa_checker import MFARequirementChecker

        self._mfa_checker = MFARequirementChecker()

        # Hidden states for query filtering
        self._hidden_states: Set[str] = (
            {"filled", "validated", "approved"} if simple_mode else set()
        )

    # -------------------------------------------------------------------------
    # Simple Mode
    # -------------------------------------------------------------------------

    def set_simple_mode(self, enabled: bool) -> None:
        """Переключает Simple Mode.

        Если enabled=True:
        - Доступные состояния только: DRAFT и SIGNED.
        - Действия: fill_fields, save_draft, sign, reject, print.
        - Переход: DRAFT -> SIGNED (требует MFA), SIGNED -> DRAFT (reject).
        - Скрытые состояния: FILLED, VALIDATED, APPROVED.

        Если enabled=False:
        - Возвращается Full Mode (все состояния и переходы).

        Args:
            enabled: True для включения Simple Mode, False для Full Mode.
        """
        self._simple_mode = enabled
        self._hidden_states = {"filled", "validated", "approved"} if enabled else set()

        # Обновляем MFA checker для Simple Mode
        if enabled:
            for from_state, to_state in _SIMPLE_MODE_MFA_TRANSITIONS:
                self._mfa_checker.add_required_transition(from_state, to_state)
            # Удаляем классические MFA-переходы, неактуальные в Simple Mode
            for pair in list(self._mfa_checker.DEFAULT_REQUIRED_TRANSITIONS):
                if pair not in _SIMPLE_MODE_MFA_TRANSITIONS:
                    self._mfa_checker.remove_required_transition(pair[0], pair[1])
        else:
            # Восстанавливаем классические MFA-переходы
            for from_state, to_state in self._mfa_checker.DEFAULT_REQUIRED_TRANSITIONS:
                self._mfa_checker.add_required_transition(from_state, to_state)

    def is_simple_mode(self) -> bool:
        """Проверяет, активен ли Simple Mode.

        Returns:
            True если включён Simple Mode.
        """
        return self._simple_mode

    def _is_allowed_state(self, state: str) -> bool:
        """Проверяет, доступно ли состояние в текущем режиме.

        Args:
            state: Строковое значение состояния.

        Returns:
            True если состояние доступно.
        """
        if not self._simple_mode:
            return True
        return state in _SIMPLE_MODE_STATES

    def _is_allowed_action(self, action: str) -> bool:
        """Проверяет, доступно ли действие в текущем режиме.

        Args:
            action: Имя действия.

        Returns:
            True если действие доступно.
        """
        if not self._simple_mode:
            return True
        return action in _SIMPLE_MODE_ACTIONS

    # -------------------------------------------------------------------------
    # Listeners Management
    # -------------------------------------------------------------------------

    def add_listener(self, listener: "WorkflowStateListener") -> None:
        """Добавляет слушателя изменений состояния.

        Args:
            listener: Слушатель для добавления.
        """
        with self._lock:
            if listener not in self.listeners:
                self.listeners.append(listener)

    def remove_listener(self, listener: "WorkflowStateListener") -> None:
        """Удаляет слушателя.

        Args:
            listener: Слушатель для удаления.
        """
        with self._lock:
            if listener in self.listeners:
                self.listeners.remove(listener)

    def notify_transition(
        self,
        doc_id: UUID,
        old_state: "FormStatus",
        new_state: "FormStatus",
        role: "WorkflowRole",
    ) -> None:
        """Уведомляет слушателей о переходе.

        Args:
            doc_id: ID документа.
            old_state: Предыдущее состояние.
            new_state: Новое состояние.
            role: Роль пользователя.
        """
        for listener in self.listeners:
            try:
                listener.on_state_changed(doc_id, old_state, new_state, role)
            except (KeyError, ValueError, TypeError) as e:
                # Log but continue
                logging.getLogger(__name__).exception(
                    "Exception ignored during state change notification: %s", e
                )

    def notify_undo_available(self, doc_id: UUID, description: str) -> None:
        """Уведомляет о доступности undo.

        Args:
            doc_id: ID документа.
            description: Описание операции для отмены.
        """
        for listener in self.listeners:
            try:
                listener.on_undo_available(doc_id, description)
            except (KeyError, ValueError, TypeError) as e:
                logging.getLogger(__name__).exception(
                    "Exception ignored during undo notification: %s", e
                )

    def notify_redo_available(self, doc_id: UUID, description: str) -> None:
        """Уведомляет о доступности redo.

        Args:
            doc_id: ID документа.
            description: Описание операции для повтора.
        """
        for listener in self.listeners:
            try:
                listener.on_redo_available(doc_id, description)
            except (KeyError, ValueError, TypeError) as e:
                logging.getLogger(__name__).exception(
                    "Exception ignored during redo notification: %s", e
                )

    # -------------------------------------------------------------------------
    # Transition Management
    # -------------------------------------------------------------------------

    def request_transition(
        self,
        doc_id: UUID,
        target_state: "FormStatus",
        reason: str = "",
        skip_mfa: bool = False,
        parent: Optional[tk.Widget] = None,
    ) -> TransitionResult:
        """Запрашивает переход с автоматическим MFA если требуется.

        В Simple Mode разрешены только переходы между DRAFT и SIGNED.
        Переход DRAFT → SIGNED требует MFA.

        Args:
            doc_id: ID документа.
            target_state: Целевое состояние.
            reason: Причина перехода.
            skip_mfa: Пропустить MFA (только для внутреннего использования).
            parent: Родительский виджет для MFA диалога (обязателен если требуется MFA).

        Returns:
            Результат перехода.
        """
        # Get current state
        current_state = self.workflow_controller.get_current_state(doc_id)

        # Simple Mode validation
        if self._simple_mode:
            if not self._is_allowed_transition(current_state.value, target_state.value):
                return TransitionResult(
                    success=False,
                    error_message="Переход недоступен в Simple Mode",
                )

        # Check if transition is valid via backend
        if not self.workflow_controller.can_transition(doc_id, target_state):
            return TransitionResult(
                success=False,
                error_message="Invalid transition",
            )

        # Check MFA requirement
        requires_mfa = self._mfa_checker.is_transition_mfa_required(current_state, target_state)

        if requires_mfa and not skip_mfa:
            if parent is None:
                # No parent provided - cannot show MFA dialog
                return TransitionResult(
                    success=False,
                    from_state=current_state,
                    to_state=target_state,
                    reason=reason,
                    error_message="MFA_REQUIRED",
                )

            # Use MFAGate to execute transition with MFA challenge
            result = self.mfa_gate.execute(
                parent=parent,
                operation=lambda: self._execute_transition(
                    doc_id, current_state, target_state, reason
                ),
                operation_name=self._mfa_checker.get_transition_description(
                    current_state, target_state
                ),
                requires_mfa=True,
            )

            if result is None:
                return TransitionResult(
                    success=False,
                    from_state=current_state,
                    to_state=target_state,
                    reason=reason,
                    error_message="MFA_REQUIRED",
                )

            return result

        # Execute transition without MFA
        return self._execute_transition(doc_id, current_state, target_state, reason)

    def _is_allowed_transition(self, from_state: str, to_state: str) -> bool:
        """Проверяет допустимость перехода в текущем режиме.

        Args:
            from_state: Исходное состояние (строка).
            to_state: Целевое состояние (строка).

        Returns:
            True если переход допустим.
        """
        if not self._simple_mode:
            return True
        allowed = _SIMPLE_MODE_ALLOWED_TRANSITIONS.get(from_state, [])
        return to_state in allowed

    def _execute_transition(
        self,
        doc_id: UUID,
        from_state: "FormStatus",
        to_state: "FormStatus",
        reason: str,
    ) -> TransitionResult:
        """Выполняет переход и создаёт undo команду.

        Args:
            doc_id: ID документа.
            from_state: Исходное состояние.
            to_state: Целевое состояние.
            reason: Причина перехода.

        Returns:
            Результат перехода.
        """
        try:
            # Create snapshot before transition
            snapshot = self._create_snapshot(doc_id, from_state)

            # Get current role
            role = self.workflow_controller.current_role

            # Create transition command
            from src.gui.workflow.transition_command import WorkflowCommandFactory

            factory = WorkflowCommandFactory(
                self.workflow_controller,
                None,  # Command stack not used directly
            )

            command = factory.create_transition_command(
                doc_id=doc_id,
                from_state=from_state,
                to_state=to_state,
                reason=reason,
                role=role,
                before_snapshot=snapshot,
            )

            # Execute transition through controller
            self.workflow_controller.transition(
                doc_id=doc_id,
                target=to_state,
                reason=reason,
            )

            # Store command in history
            history = self._get_or_create_history(doc_id)
            history.push(command)

            # Notify listeners
            self.notify_transition(doc_id, from_state, to_state, role)
            self.notify_undo_available(doc_id, command.description_for_undo)

            return TransitionResult(
                success=True,
                from_state=from_state,
                to_state=to_state,
                reason=reason,
                command=command,
            )

        except (KeyError, ValueError) as e:
            # Workflow state error: log and return failure (state revert handled by controller)
            logger = logging.getLogger(__name__)
            logger.warning("Workflow transition state error: %s", e)
            return TransitionResult(
                success=False,
                error_message=f"Ошибка состояния: {str(e)}",
            )
        except Exception as e:
            logging.exception("Unexpected error during transition execution: %s", e)
            return TransitionResult(
                success=False,
                error_message=str(e),
            )

    def _create_snapshot(
        self,
        doc_id: UUID,
        current_state: "FormStatus",
    ) -> "TransitionSnapshot":
        """Создаёт снимок состояния.

        Args:
            doc_id: ID документа.
            current_state: Текущее состояние.

        Returns:
            Созданный снимок.
        """
        from datetime import datetime

        # Get field values if available
        field_values: Dict[str, Any] = {}
        if hasattr(self.workflow_controller, "get_field_values"):
            field_values = self.workflow_controller.get_field_values(doc_id)

        # Get comments
        comments: List[Any] = []
        if hasattr(self.workflow_controller, "get_all_comments"):
            comments = self.workflow_controller.get_all_comments(doc_id)

        from src.gui.workflow.snapshot import TransitionSnapshot

        return TransitionSnapshot(
            form_status=current_state,
            field_values=field_values,
            comments=comments,
            timestamp=datetime.now(),
            role=self.workflow_controller.current_role,
        )

    def _get_or_create_history(self, doc_id: UUID) -> "WorkflowCommandHistory":
        """Получает или создаёт историю команд для документа.

        Args:
            doc_id: ID документа.

        Returns:
            История команд.
        """
        if doc_id not in self._command_histories:
            from src.gui.workflow.transition_command import WorkflowCommandHistory

            self._command_histories[doc_id] = WorkflowCommandHistory(
                doc_id=doc_id,
                max_size=self._max_undo_steps,
            )
        return self._command_histories[doc_id]

    # -------------------------------------------------------------------------
    # Undo/Redo
    # -------------------------------------------------------------------------

    def undo(self, doc_id: UUID) -> bool:
        """Отменяет последний переход для документа.

        Args:
            doc_id: ID документа.

        Returns:
            True если отмена выполнена.
        """
        history = self._command_histories.get(doc_id)
        if not history:
            return False

        command = history.undo()
        if command:
            # Notify listeners
            self.notify_redo_available(doc_id, command.description_for_redo)
            return True
        return False

    def redo(self, doc_id: UUID) -> bool:
        """Повторяет отменённый переход для документа.

        Args:
            doc_id: ID документа.

        Returns:
            True если повтор выполнен.
        """
        history = self._command_histories.get(doc_id)
        if not history:
            return False

        command = history.redo()
        if command:
            # Notify listeners
            self.notify_undo_available(doc_id, command.description_for_undo)
            return True
        return False

    def can_undo(self, doc_id: UUID) -> bool:
        """Проверяет возможность отмены.

        Args:
            doc_id: ID документа.

        Returns:
            True если можно отменить.
        """
        history = self._command_histories.get(doc_id)
        return history.can_undo() if history else False

    def can_redo(self, doc_id: UUID) -> bool:
        """Проверяет возможность повтора.

        Args:
            doc_id: ID документа.

        Returns:
            True если можно повторить.
        """
        history = self._command_histories.get(doc_id)
        return history.can_redo() if history else False

    def get_undo_description(self, doc_id: UUID) -> Optional[str]:
        """Возвращает описание undo операции.

        Args:
            doc_id: ID документа.

        Returns:
            Описание или None.
        """
        history = self._command_histories.get(doc_id)
        return history.get_undo_description() if history else None

    def get_redo_description(self, doc_id: UUID) -> Optional[str]:
        """Возвращает описание redo операции.

        Args:
            doc_id: ID документа.

        Returns:
            Описание или None.
        """
        history = self._command_histories.get(doc_id)
        return history.get_redo_description() if history else None

    # -------------------------------------------------------------------------
    # Query methods (Simple Mode filtering)
    # -------------------------------------------------------------------------

    def get_available_states(self) -> list[str]:
        """Возвращает доступные состояния в текущем режиме.

        В Simple Mode возвращает только ['draft', 'signed'].
        В Full Mode возвращает все состояния FormStatus.

        Returns:
            Список строковых значений состояний.
        """
        if self._simple_mode:
            return list(_SIMPLE_MODE_STATES)
        # Full Mode — все значения FormStatus
        return [s.value for s in FormStatus]

    def get_available_actions(self, state: str) -> list[str]:
        """Возвращает доступные действия для состояния в текущем режиме.

        В Simple Mode возвращает фиксированный набор действий.
        В Full Mode возвращает полный набор действий.

        Args:
            state: Текущее состояние (строка).

        Returns:
            Список имён действий.
        """
        if self._simple_mode:
            return list(_SIMPLE_MODE_ACTIONS)
        # Full Mode — стандартные действия workflow
        _FULL_MODE_ACTIONS: dict[str, list[str]] = {
            "draft": ["fill_fields", "save_draft", "submit_for_validation", "switch_role"],
            "filled": ["validate", "reject", "view_comments"],
            "validated": ["approve", "reject", "view_comments"],
            "approved": ["sign", "reject", "view_comments"],
            "signed": ["print", "archive"],
            "printed": ["print", "archive"],
            "archived": [],
            "rejected": [],
        }
        return _FULL_MODE_ACTIONS.get(state, []).copy()

    def get_allowed_transitions(self, state: str) -> list[str]:
        """Возвращает допустимые переходы из состояния.

        В Simple Mode: DRAFT → [SIGNED], SIGNED → [DRAFT].
        В Full Mode — через ApprovalWorkflow.

        Args:
            state: Исходное состояние.

        Returns:
            Список допустимых целевых состояний.
        """
        if self._simple_mode:
            return list(_SIMPLE_MODE_ALLOWED_TRANSITIONS.get(state, []))
        # Full Mode — напрямую через ApprovalWorkflow с минимальной инфраструктурой
        from src.controller.workflow_controller import ApprovalWorkflow, FormStatus

        engine = ApprovalWorkflow()
        try:
            from_state = FormStatus(state)
            all_allowed = engine.get_allowed_transitions(from_state)
            return [s.value for s in all_allowed]
        except (ValueError, KeyError):
            return []

    def is_state_visible(self, state: str) -> bool:
        """Проверяет, не скрыто ли состояние в текущем режиме.

        Args:
            state: Строковое значение состояния.

        Returns:
            True если состояние видимо.
        """
        return state not in self._hidden_states

    # -------------------------------------------------------------------------
    # Free Role Mode
    # -------------------------------------------------------------------------

    def set_free_role_mode(self, enabled: bool) -> None:
        """Устанавливает режим свободного переключения ролей.

        Args:
            enabled: True для включения.
        """
        self._mfa_checker.free_mode_enabled = enabled

    def is_free_role_mode(self) -> bool:
        """Проверяет режим свободного переключения.

        Returns:
            True если включён.
        """
        return self._mfa_checker.free_mode_enabled

    # -------------------------------------------------------------------------
    # Cleanup
    # -------------------------------------------------------------------------

    def clear_document_history(self, doc_id: UUID) -> None:
        """Очищает историю для документа.

        Args:
            doc_id: ID документа.
        """
        if doc_id in self._command_histories:
            self._command_histories[doc_id].clear()
            del self._command_histories[doc_id]

        self._snapshot_manager.clear_snapshots(str(doc_id))


__all__ = [
    "WorkflowStateManager",
    "TransitionRequest",
    "TransitionResult",
]
