"""Command паттерн для workflow transitions.

Реализует undo/redo функциональность для переходов
состояний документов через паттерн Command.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack

if TYPE_CHECKING:
    from uuid import UUID

    from src.controller.workflow_controller import (
        FormStatus,
        WorkflowController,
        WorkflowRole,
    )
    from src.gui.workflow.snapshot import TransitionSnapshot


class WorkflowTransitionCommand(Command):
    """Команда перехода workflow состояния с поддержкой undo.

    Хранит полное состояние документа перед переходом,
    позволяя восстановить его при операции undo.

    Attributes:
        _doc_id: ID документа.
        _from_state: Исходное состояние.
        _to_state: Целевое состояние.
        _reason: Причина перехода.
        _role: Роль пользователя.
        _before_snapshot: Снимок состояния до перехода.
        _workflow_controller: Контроллер для выполнения операций.
        _command_stack: Стек команд для undo/redo.

    Example:
        >>> command = WorkflowTransitionCommand(
        ...     doc_id=uuid,
        ...     from_state=FormStatus.DRAFT,
        ...     to_state=FormStatus.FILLED,
        ...     reason="Заполнение формы",
        ...     role=WorkflowRole.OPERATOR,
        ...     before_snapshot=snapshot,
        ...     workflow_controller=controller,
        ... )
        >>> command_stack.execute(command)
        >>> command.undo()  # Отмена перехода
    """

    def __init__(
        self,
        doc_id: "UUID",
        from_state: "FormStatus",
        to_state: "FormStatus",
        reason: str,
        role: "WorkflowRole",
        before_snapshot: "TransitionSnapshot",
        workflow_controller: "WorkflowController",
        command_stack: Optional["CommandStack"] = None,
    ) -> None:
        """Инициализация команды перехода.

        Args:
            doc_id: ID документа.
            from_state: Исходное состояние.
            to_state: Целевое состояние.
            reason: Причина перехода.
            role: Роль пользователя.
            before_snapshot: Снимок состояния до перехода.
            workflow_controller: Контроллер workflow.
            command_stack: Стек команд (опционально).
        """
        self._doc_id = doc_id
        self._from_state = from_state
        self._to_state = to_state
        self._reason = reason
        self._role = role
        self._before_snapshot = before_snapshot
        self._workflow_controller = workflow_controller
        self._command_stack = command_stack

        self._executed = False
        self._undone = False

    @property
    def doc_id(self) -> "UUID":
        """ID документа."""
        return self._doc_id

    @property
    def from_state(self) -> "FormStatus":
        """Исходное состояние."""
        return self._from_state

    @property
    def to_state(self) -> "FormStatus":
        """Целевое состояние."""
        return self._to_state

    @property
    def is_undoable(self) -> bool:
        """True если переход можно отменить.

        Переходы в ARCHIVED нельзя отменить (терминальное состояние).
        """
        from src.gui.workflow.constants import NON_UNDOABLE_STATES

        to_str = self._to_state.value if hasattr(self._to_state, "value") else str(self._to_state)
        return to_str not in NON_UNDOABLE_STATES

    @property
    def description(self) -> str:
        """Описание команды для UI."""
        from_str = (
            self._from_state.value if hasattr(self._from_state, "value") else str(self._from_state)
        )
        to_str = self._to_state.value if hasattr(self._to_state, "value") else str(self._to_state)
        return f"Переход {from_str} → {to_str}"

    @property
    def description_for_undo(self) -> str:
        """Описание для undo меню."""
        to_str = self._to_state.value if hasattr(self._to_state, "value") else str(self._to_state)
        return f"Отменить переход в {to_str}"

    @property
    def description_for_redo(self) -> str:
        """Описание для redo меню."""
        to_str = self._to_state.value if hasattr(self._to_state, "value") else str(self._to_state)
        return f"Повторить переход в {to_str}"

    def execute(self) -> None:
        """Выполняет переход состояния."""
        if self._executed and not self._undone:
            return  # Already executed

        try:
            # Execute transition through controller
            self._workflow_controller.transition(
                doc_id=self._doc_id,
                target=self._to_state,
                reason=self._reason,
            )
            self._executed = True
            self._undone = False

        except Exception as e:
            # Log error and raise
            import logging

            logging.getLogger(__name__).error(f"Failed to execute transition: {e}")
            raise

    def undo(self) -> None:
        """Отменяет переход, восстанавливая исходное состояние."""
        if not self._executed:
            return

        if not self.is_undoable:
            return

        try:
            # Restore form status from snapshot
            if hasattr(self._workflow_controller, "document_store"):
                doc_store = self._workflow_controller.document_store
                if doc_store is not None:
                    doc_store.set_status(
                        self._doc_id,
                        self._before_snapshot.form_status.value
                        if hasattr(self._before_snapshot.form_status, "value")
                        else str(self._before_snapshot.form_status),
                    )

            # Restore field values if supported
            if hasattr(self._workflow_controller, "restore_field_values"):
                self._workflow_controller.restore_field_values(
                    self._doc_id,
                    self._before_snapshot.field_values,
                )

            self._undone = True
            self._executed = False

        except Exception as e:
            import logging

            logging.getLogger(__name__).error(f"Failed to undo transition: {e}")
            raise

    def redo(self) -> None:
        """Повторяет отменённый переход."""
        if not self._undone:
            return

        self.execute()

    def can_undo(self) -> bool:
        """Проверяет возможность отмены."""
        return self._executed and self.is_undoable and not self._undone

    def can_redo(self) -> bool:
        """Проверяет возможность повтора."""
        return self._undone


class WorkflowCommandFactory:
    """Фабрика для создания workflow команд.

    Упрощает создание команд с автоматическим
    созданием snapshot и интеграцией с CommandStack.

    Example:
        >>> factory = WorkflowCommandFactory(controller, command_stack)
        >>> command = factory.create_transition_command(
        ...     doc_id=uuid,
        ...     to_state=FormStatus.FILLED,
        ...     reason="Заполнение",
        ... )
    """

    def __init__(
        self,
        workflow_controller: "WorkflowController",
        command_stack: Optional["CommandStack"] = None,
    ) -> None:
        """Инициализация фабрики.

        Args:
            workflow_controller: Контроллер workflow.
            command_stack: Стек команд (опционально).
        """
        self._controller = workflow_controller
        self._command_stack = command_stack

    def create_transition_command(
        self,
        doc_id: "UUID",
        from_state: "FormStatus",
        to_state: "FormStatus",
        reason: str,
        role: "WorkflowRole",
        before_snapshot: "TransitionSnapshot",
    ) -> WorkflowTransitionCommand:
        """Создаёт команду перехода.

        Args:
            doc_id: ID документа.
            from_state: Исходное состояние.
            to_state: Целевое состояние.
            reason: Причина перехода.
            role: Роль пользователя.
            before_snapshot: Снимок до перехода.

        Returns:
            Созданная команда.
        """
        return WorkflowTransitionCommand(
            doc_id=doc_id,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            role=role,
            before_snapshot=before_snapshot,
            workflow_controller=self._controller,
            command_stack=self._command_stack,
        )


class WorkflowCommandHistory:
    """История команд для документа.

    Управляет undo/redo стеком для конкретного документа.

    Attributes:
        _doc_id: ID документа.
        _undo_stack: Стек undo.
        _redo_stack: Стек redo.
        _max_size: Максимальный размер стека.
    """

    def __init__(
        self,
        doc_id: "UUID",
        max_size: int = 50,
    ) -> None:
        """Инициализация истории.

        Args:
            doc_id: ID документа.
            max_size: Максимальный размер стека.
        """
        self._doc_id = doc_id
        self._undo_stack: List[WorkflowTransitionCommand] = []
        self._redo_stack: List[WorkflowTransitionCommand] = []
        self._max_size = max_size

    @property
    def doc_id(self) -> "UUID":
        """ID документа."""
        return self._doc_id

    def push(self, command: WorkflowTransitionCommand) -> None:
        """Добавляет команду в undo стек.

        Args:
            command: Команда для добавления.
        """
        self._undo_stack.append(command)
        # Clear redo stack on new action
        self._redo_stack.clear()

        # Enforce max size
        if len(self._undo_stack) > self._max_size:
            self._undo_stack.pop(0)

    def undo(self) -> Optional[WorkflowTransitionCommand]:
        """Отменяет последнюю команду.

        Returns:
            Отменённая команда или None.
        """
        if not self._undo_stack:
            return None

        command = self._undo_stack.pop()
        try:
            command.undo()
            self._redo_stack.append(command)
            return command
        except Exception:
            # Restore to undo stack if undo failed
            self._undo_stack.append(command)
            return None

    def redo(self) -> Optional[WorkflowTransitionCommand]:
        """Повторяет отменённую команду.

        Returns:
            Повторённая команда или None.
        """
        if not self._redo_stack:
            return None

        command = self._redo_stack.pop()
        try:
            command.redo()
            self._undo_stack.append(command)
            return command
        except Exception:
            # Restore to redo stack if redo failed
            self._redo_stack.append(command)
            return None

    def can_undo(self) -> bool:
        """True если можно отменить."""
        return len(self._undo_stack) > 0

    def can_redo(self) -> bool:
        """True если можно повторить."""
        return len(self._redo_stack) > 0

    def get_undo_description(self) -> Optional[str]:
        """Описание следующей undo операции."""
        if self._undo_stack:
            return self._undo_stack[-1].description_for_undo
        return None

    def get_redo_description(self) -> Optional[str]:
        """Описание следующей redo операции."""
        if self._redo_stack:
            return self._redo_stack[-1].description_for_redo
        return None

    def clear(self) -> None:
        """Очищает историю."""
        self._undo_stack.clear()
        self._redo_stack.clear()


__all__ = [
    "WorkflowTransitionCommand",
    "WorkflowCommandFactory",
    "WorkflowCommandHistory",
]
