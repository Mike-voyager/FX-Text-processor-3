"""Event dataclasses для workflow UI.

Определяет структуры данных для событий workflow,
используемые в UI компонентах и для коммуникации между слоями.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional
from uuid import UUID

if TYPE_CHECKING:
    from src.controller.workflow_controller import FormStatus, WorkflowRole


@dataclass(frozen=True)
class WorkflowUIEvent:
    """Базовый класс события workflow UI.

    Attributes:
        event_id: Уникальный ID события.
        doc_id: ID документа.
        timestamp: Время события.
        event_type: Тип события.
    """

    event_id: str
    doc_id: UUID
    timestamp: datetime
    event_type: str

    def __post_init__(self) -> None:
        """Валидация после создания."""
        if not self.event_id:
            raise ValueError("event_id cannot be empty")


@dataclass(frozen=True)
class StateTransitionEvent(WorkflowUIEvent):
    """Событие перехода состояния.

    Attributes:
        from_state: Исходное состояние.
        to_state: Новое состояние.
        role: Роль, выполнившая переход.
        reason: Причина перехода.
        mfa_verified: Подтверждено ли MFA.
        undoable: Можно ли отменить переход.
    """

    from_state: "FormStatus"
    to_state: "FormStatus"
    role: "WorkflowRole"
    reason: str = ""
    mfa_verified: bool = False
    undoable: bool = True

    def __post_init__(self) -> None:
        """Валидация и установка event_type."""
        super().__post_init__()
        # Cannot use object.__setattr__ on frozen dataclass, so we rely on caller
        # to set event_type="transition" when creating

    @property
    def is_forward(self) -> bool:
        """True если переход вперёд по workflow."""
        from src.gui.workflow.constants import STATUS_ORDER

        from_val = self.from_state.value
        to_val = self.to_state.value

        # Тот же состояние — не переход вперёд и не назад
        if from_val == to_val:
            return False

        try:
            return STATUS_ORDER.index(to_val) > STATUS_ORDER.index(from_val)
        except ValueError:
            # Неизвестное состояние — не вперёд и не назад
            return False

    @property
    def is_backward(self) -> bool:
        """True если переход назад по workflow."""
        from src.gui.workflow.constants import STATUS_ORDER

        from_val = self.from_state.value
        to_val = self.to_state.value

        # Тот же состояние — не переход
        if from_val == to_val:
            return False

        try:
            return STATUS_ORDER.index(to_val) < STATUS_ORDER.index(from_val)
        except ValueError:
            # Неизвестное состояние — не вперёд и не назад
            return False


@dataclass(frozen=True)
class UndoRedoEvent(WorkflowUIEvent):
    """Событие undo или redo операции.

    Attributes:
        operation: "undo" или "redo".
        original_event: Исходное событие перехода.
        description: Описание операции.
    """

    operation: str  # "undo" или "redo"
    original_event: Optional[StateTransitionEvent] = None
    description: str = ""

    def __post_init__(self) -> None:
        """Валидация operation."""
        super().__post_init__()
        if self.operation not in ("undo", "redo"):
            raise ValueError("operation must be 'undo' or 'redo'")


@dataclass(frozen=True)
class RoleChangeEvent(WorkflowUIEvent):
    """Событие смены роли.

    Attributes:
        from_role: Предыдущая роль.
        to_role: Новая роль.
        mfa_verified: Подтверждено ли MFA.
        free_mode: Был ли включён free mode.
    """

    from_role: "WorkflowRole"
    to_role: "WorkflowRole"
    mfa_verified: bool = False
    free_mode: bool = False


@dataclass(frozen=True)
class MFAChallengeEvent(WorkflowUIEvent):
    """Событие запроса MFA.

    Attributes:
        operation: Описание операции.
        method: Метод MFA (totp, fido2, backup_code).
        success: Результат challenge.
        error_message: Сообщение об ошибке (если failed).
    """

    operation: str
    method: str = ""
    success: bool = False
    error_message: Optional[str] = None


@dataclass(frozen=True)
class CommentEvent(WorkflowUIEvent):
    """Событие работы с комментарием.

    Attributes:
        action: "add", "resolve", "delete".
        field_id: ID поля (если комментарий к полю).
        comment_id: ID комментария.
        text: Текст комментария (для add).
        severity: Уровень важности.
    """

    action: str  # "add", "resolve", "delete"
    field_id: str = ""
    comment_id: str = ""
    text: str = ""
    severity: str = "info"


@dataclass(frozen=True)
class WorkflowErrorEvent(WorkflowUIEvent):
    """Событие ошибки в workflow.

    Attributes:
        error_type: Тип ошибки.
        error_message: Сообщение об ошибке.
        recoverable: Можно ли восстановиться.
        context: Контекст ошибки.
    """

    error_type: str
    error_message: str
    recoverable: bool = False
    context: Dict[str, Any] = field(default_factory=dict)


class WorkflowEventBus:
    """Шина событий для workflow.

    Централизованная система публикации и подписки
    на события workflow UI.

    Attributes:
        _subscribers: Словарь подписчиков по типу события.

    Example:
        >>> bus = WorkflowEventBus()
        >>> bus.subscribe("transition", handler)
        >>> bus.publish(StateTransitionEvent(...))
    """

    def __init__(self) -> None:
        """Инициализация шины событий."""
        self._subscribers: Dict[str, List[Callable[..., Any]]] = {}
        self._global_subscribers: List[Callable[..., Any]] = []

    def subscribe(
        self,
        event_type: str,
        handler: Callable[[WorkflowUIEvent], None],
    ) -> None:
        """Подписывается на события определённого типа.

        Args:
            event_type: Тип события ("transition", "undo", "role_change", etc.).
            handler: Функция-обработчик.
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: Callable[[WorkflowUIEvent], None]) -> None:
        """Подписывается на все события.

        Args:
            handler: Функция-обработчик.
        """
        self._global_subscribers.append(handler)

    def unsubscribe(
        self,
        event_type: str,
        handler: Callable[[WorkflowUIEvent], None],
    ) -> None:
        """Отписывается от событий.

        Args:
            event_type: Тип события.
            handler: Функция-обработчик для удаления.
        """
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                h for h in self._subscribers[event_type] if h != handler
            ]

    def publish(self, event: WorkflowUIEvent) -> None:
        """Публикует событие всем подписчикам.

        Args:
            event: Событие для публикации.
        """
        # Глобальные подписчики
        for handler in self._global_subscribers:
            try:
                handler(event)
            except (AttributeError, ValueError, TypeError, RuntimeError) as e:
                # Log but don't stop other handlers
                logging.getLogger(__name__).warning("Exception ignored in handler: %s", e)

        # Специфичные подписчики
        event_type = event.event_type
        if event_type in self._subscribers:
            for handler in self._subscribers[event_type]:
                try:
                    handler(event)
                except (AttributeError, ValueError, TypeError, RuntimeError) as e:
                    # Log but don't stop other handlers
                    logging.getLogger(__name__).warning("Exception ignored in handler: %s", e)

    def clear(self) -> None:
        """Очищает все подписки."""
        self._subscribers.clear()
        self._global_subscribers.clear()


def create_transition_event(
    doc_id: UUID,
    from_state: "FormStatus",
    to_state: "FormStatus",
    role: "WorkflowRole",
    reason: str = "",
    mfa_verified: bool = False,
) -> StateTransitionEvent:
    """Фабричная функция для создания события перехода.

    Args:
        doc_id: ID документа.
        from_state: Исходное состояние.
        to_state: Целевое состояние.
        role: Роль пользователя.
        reason: Причина перехода.
        mfa_verified: MFA статус.

    Returns:
        Созданное событие.
    """
    from datetime import datetime

    event_id = f"{doc_id}_{datetime.now().isoformat()}"

    # Determine if undoable
    from src.gui.workflow.constants import NON_UNDOABLE_STATES

    to_str = to_state.value
    undoable = to_str not in NON_UNDOABLE_STATES

    return StateTransitionEvent(
        event_id=event_id,
        doc_id=doc_id,
        timestamp=datetime.now(),
        event_type="transition",
        from_state=from_state,
        to_state=to_state,
        role=role,
        reason=reason,
        mfa_verified=mfa_verified,
        undoable=undoable,
    )


__all__ = [
    # Events
    "WorkflowUIEvent",
    "StateTransitionEvent",
    "UndoRedoEvent",
    "RoleChangeEvent",
    "MFAChallengeEvent",
    "CommentEvent",
    "WorkflowErrorEvent",
    # Bus
    "WorkflowEventBus",
    # Factory
    "create_transition_event",
]
