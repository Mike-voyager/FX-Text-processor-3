"""WorkflowController для FX Text Processor 3.

Контроллер для управления workflow документов — переходами между состояниями,
ролями, MFA-подтверждением и комментариями к полям.

Архитектура:
    - Controller слой: координация View ↔ Service
    - Использует ApprovalWorkflow для state machine
    - Координирует AuthController для MFA
    - Работает с RoleBadge, WorkflowTimeline, FieldComment

Example:
    >>> from uuid import UUID
    >>> from src.controller.workflow_controller import WorkflowController, FormStatus
    >>> controller = WorkflowController(auth_controller=auth_ctrl)
    >>> doc_id = UUID("...")
    >>> controller.get_current_state(doc_id)
    FormStatus.DRAFT
    >>> controller.transition(doc_id, FormStatus.FILLED, reason="Заполнение формы")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Final, Optional, Protocol, TypeVar
from uuid import UUID

# Import View components for type hints
from src.gui.workflow.field_comment_widget import FieldCommentWidget, Severity as CommentSeverity
from src.gui.workflow.role_badge import RoleBadge, WorkflowRole as Role
from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog as WorkflowTimeline
from src.view.workflow import WorkflowState

__all__ = [
    "WorkflowController",
    "FormStatus",
    "WorkflowRole",
    "WorkflowEvent",
    "Severity",
    "FieldComment",
    "WorkflowTransitionError",
    "MFARequiredError",
]

logger: Final = logging.getLogger(__name__)

T = TypeVar("T")

from typing import TypeAlias

# =============================================================================
# Type Definitions
# =============================================================================

StateChangeCallback: TypeAlias = Callable[[WorkflowState], None]
"""Callback type for state change events."""


class FormStatus(Enum):
    """Состояния жизненного цикла документа.

    Состояния:
        DRAFT: Черновик — редактирование разрешено.
        FILLED: Заполнена — ожидает валидации.
        VALIDATED: Проверена — ожидает подписи.
        APPROVED: Утверждена — ожидает подписания.
        SIGNED: Подписана — поля заблокированы.
        ARCHIVED: Архивирована — терминальное состояние.
        REJECTED: Отклонена — возврат для исправления.
    """

    DRAFT = "draft"
    FILLED = "filled"
    VALIDATED = "validated"
    APPROVED = "approved"
    SIGNED = "signed"
    ARCHIVED = "archived"
    REJECTED = "rejected"

    @property
    def localized_name(self) -> str:
        """Возвращает локализованное название состояния."""
        names: dict[FormStatus, str] = {
            FormStatus.DRAFT: "Черновик",
            FormStatus.FILLED: "Заполнена",
            FormStatus.VALIDATED: "Проверена",
            FormStatus.APPROVED: "Утверждена",
            FormStatus.SIGNED: "Подписана",
            FormStatus.ARCHIVED: "Архивирована",
            FormStatus.REJECTED: "Отклонена",
        }
        return names.get(self, self.value)

    @property
    def is_editable(self) -> bool:
        """Проверяет, разрешено ли редактирование в этом состоянии."""
        return self == FormStatus.DRAFT

    @property
    def is_terminal(self) -> bool:
        """Проверяет, является ли состояние терминальным."""
        return self in (FormStatus.ARCHIVED,)

    @property
    def order(self) -> int:
        """Порядковый номер состояния в workflow."""
        orders: dict[FormStatus, int] = {
            FormStatus.DRAFT: 0,
            FormStatus.FILLED: 1,
            FormStatus.VALIDATED: 2,
            FormStatus.APPROVED: 3,
            FormStatus.SIGNED: 4,
            FormStatus.ARCHIVED: 5,
            FormStatus.REJECTED: -1,
        }
        return orders.get(self, -1)


class WorkflowRole(Enum):
    """Роли внутри single-operator workflow (режимы работы).

    Роли:
        OPERATOR: Оператор — заполнение формы (DRAFT → FILLED).
        EDITOR: Редактор — редактирование/проверка (FILLED → VALIDATED).
        SUPERVISOR: Супервайзер — согласование (VALIDATED → APPROVED).
        SIGNATORY: Подписант — подписание (APPROVED → SIGNED).
    """

    OPERATOR = "operator"
    EDITOR = "editor"
    SUPERVISOR = "supervisor"
    SIGNATORY = "signatory"

    @property
    def display_name(self) -> str:
        """Возвращает отображаемое имя роли."""
        names: dict[WorkflowRole, str] = {
            WorkflowRole.OPERATOR: "Оператор",
            WorkflowRole.EDITOR: "Редактор",
            WorkflowRole.SUPERVISOR: "Супервайзер",
            WorkflowRole.SIGNATORY: "Подписант",
        }
        return names.get(self, self.value)

    @property
    def color(self) -> str:
        """Возвращает цвет роли для UI."""
        colors: dict[WorkflowRole, str] = {
            WorkflowRole.OPERATOR: "#0080FF",  # Blue
            WorkflowRole.EDITOR: "#00C000",  # Green
            WorkflowRole.SUPERVISOR: "#FFA500",  # Orange
            WorkflowRole.SIGNATORY: "#FF0000",  # Red
        }
        return colors.get(self, "#808080")


class Severity(Enum):
    """Уровень важности комментария."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# =============================================================================
# WorkflowEvent
# =============================================================================


@dataclass(frozen=True)
class WorkflowEvent:
    """Событие в истории workflow.

    Attributes:
        event_id: Уникальный идентификатор события.
        doc_id: ID документа.
        from_state: Исходное состояние.
        to_state: Целевое состояние.
        role: Роль, выполнившая переход.
        timestamp: Время события.
        reason: Причина перехода.
        mfa_verified: Подтверждено ли MFA.
    """

    event_id: str
    doc_id: UUID
    from_state: FormStatus
    to_state: FormStatus
    role: WorkflowRole
    timestamp: datetime
    reason: str = ""
    mfa_verified: bool = False


@dataclass(frozen=True)
class FieldComment:
    """Комментарий к полю документа.

    Attributes:
        comment_id: Уникальный идентификатор комментария.
        doc_id: ID документа.
        field_id: ID поля.
        text: Текст комментария.
        author_role: Роль автора.
        severity: Уровень важности.
        created_at: Время создания.
        resolved: Решён ли комментарий.
        resolved_at: Время решения.
        resolved_by: Кем решён.
    """

    comment_id: str
    doc_id: UUID
    field_id: str
    text: str
    author_role: WorkflowRole
    severity: Severity
    created_at: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[WorkflowRole] = None


# =============================================================================
# Protocols
# =============================================================================


class AuthControllerProtocol(Protocol):
    """Протокол для AuthController.

    Определяет интерфейс для MFA-взаимодействия.
    """

    def require_mfa(
        self,
        operation: str,
        callback: Callable[[bool], None],
    ) -> None:
        """Запросить MFA для критичной операции.

        Args:
            operation: Описание операции для отображения.
            callback: Колбэк с результатом MFA (True = подтверждено).
        """
        ...

    def is_mfa_verified(self) -> bool:
        """Проверить, подтверждено ли MFA в текущей сессии."""
        ...

    def get_current_user(self) -> Optional[str]:
        """Получить ID текущего пользователя."""
        ...


class DocumentStoreProtocol(Protocol):
    """Протокол для хранилища документов."""

    def get_status(self, doc_id: UUID) -> str:
        """Получить статус документа."""
        ...

    def set_status(self, doc_id: UUID, status: str) -> None:
        """Установить статус документа."""
        ...

    def exists(self, doc_id: UUID) -> bool:
        """Проверить существование документа."""
        ...


# =============================================================================
# Exceptions
# =============================================================================


class WorkflowTransitionError(Exception):
    """Исключение при недопустимом переходе между состояниями."""

    def __init__(
        self,
        from_state: FormStatus,
        to_state: FormStatus,
        message: str = "",
    ) -> None:
        self.from_state = from_state
        self.to_state = to_state
        self.message = message or f"Недопустимый переход из {from_state.value} в {to_state.value}"
        super().__init__(self.message)


class MFARequiredError(Exception):
    """Исключение при отсутствии MFA для критичной операции."""

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"Для операции '{operation}' требуется MFA-подтверждение")


class DocumentNotFoundError(Exception):
    """Исключение при отсутствии документа."""

    def __init__(self, doc_id: UUID) -> None:
        self.doc_id = doc_id
        super().__init__(f"Документ {doc_id} не найден")


class InvalidStateError(Exception):
    """Исключение при недопустимом состоянии документа."""

    def __init__(self, state: "FormStatus", message: str = "") -> None:
        self.state = state
        self.message = message or f"Недопустимое состояние: {state.value}"
        super().__init__(self.message)


class PermissionError(Exception):
    """Исключение при недостаточных правах доступа."""

    def __init__(self, role: str, operation: str) -> None:
        self.role = role
        self.operation = operation
        super().__init__(f"Роль '{role}' не имеет прав для операции '{operation}'")


# ApprovalWorkflow (State Machine)
# =============================================================================

# Определение допустимых переходов между состояниями
_ALLOWED_TRANSITIONS: Final[dict[FormStatus, list[FormStatus]]] = {
    FormStatus.DRAFT: [FormStatus.FILLED, FormStatus.REJECTED],
    FormStatus.FILLED: [FormStatus.VALIDATED, FormStatus.DRAFT, FormStatus.REJECTED],
    FormStatus.VALIDATED: [FormStatus.APPROVED, FormStatus.FILLED, FormStatus.REJECTED],
    FormStatus.APPROVED: [FormStatus.SIGNED, FormStatus.VALIDATED, FormStatus.REJECTED],
    FormStatus.SIGNED: [FormStatus.ARCHIVED, FormStatus.APPROVED],
    FormStatus.ARCHIVED: [],  # Терминальное состояние
    FormStatus.REJECTED: [FormStatus.DRAFT],  # Возврат на доработку
}

# Состояния, требующие MFA для перехода
_MFA_REQUIRED_TRANSITIONS: Final[set[tuple[FormStatus, FormStatus]]] = {
    (FormStatus.FILLED, FormStatus.VALIDATED),
    (FormStatus.VALIDATED, FormStatus.APPROVED),
    (FormStatus.APPROVED, FormStatus.SIGNED),
    (FormStatus.SIGNED, FormStatus.ARCHIVED),
    (FormStatus.VALIDATED, FormStatus.FILLED),  # Откат валидации
    (FormStatus.APPROVED, FormStatus.VALIDATED),  # Откат утверждения
    (FormStatus.SIGNED, FormStatus.APPROVED),  # Откат подписи
}

# Права ролей для переходов (state -> allowed roles)
_ROLE_PERMISSIONS: Final[dict[FormStatus, list[WorkflowRole]]] = {
    FormStatus.DRAFT: [WorkflowRole.OPERATOR, WorkflowRole.EDITOR],
    FormStatus.FILLED: [WorkflowRole.EDITOR, WorkflowRole.SUPERVISOR],
    FormStatus.VALIDATED: [WorkflowRole.SUPERVISOR, WorkflowRole.SIGNATORY],
    FormStatus.APPROVED: [WorkflowRole.SIGNATORY],
    FormStatus.SIGNED: [],  # Terminal state
    FormStatus.ARCHIVED: [],  # Terminal state
    FormStatus.REJECTED: [WorkflowRole.OPERATOR],  # Только OPERATOR может вернуть в работу
}

# Маппинг FormStatus <-> WorkflowState
_FORM_STATUS_TO_WORKFLOW_STATE: Final[dict[FormStatus, WorkflowState]] = {
    FormStatus.DRAFT: WorkflowState.DRAFT,
    FormStatus.FILLED: WorkflowState.FILLED,
    FormStatus.VALIDATED: WorkflowState.VALIDATED,
    FormStatus.APPROVED: WorkflowState.APPROVED,
    FormStatus.SIGNED: WorkflowState.SIGNED,
}

_WORKFLOW_STATE_TO_FORM_STATUS: Final[dict[WorkflowState, FormStatus]] = {
    WorkflowState.DRAFT: FormStatus.DRAFT,
    WorkflowState.FILLED: FormStatus.FILLED,
    WorkflowState.VALIDATED: FormStatus.VALIDATED,
    WorkflowState.APPROVED: FormStatus.APPROVED,
    WorkflowState.SIGNED: FormStatus.SIGNED,
}


class ApprovalWorkflow:
    """State machine для управления переходами между состояниями документа.

    Реализует конечный автомат с проверкой допустимых переходов и MFA.
    """

    def __init__(self) -> None:
        """Инициализирует state machine."""
        self._current_state: FormStatus = FormStatus.DRAFT
        self._pending_mfa: bool = False
        self._pending_transition: Optional[tuple[FormStatus, FormStatus, str]] = None

    def get_allowed_transitions(self, from_state: FormStatus) -> list[FormStatus]:
        """Возвращает список допустимых переходов из указанного состояния.

        Args:
            from_state: Текущее состояние.

        Returns:
            Список допустимых целевых состояний.
        """
        return _ALLOWED_TRANSITIONS.get(from_state, []).copy()

    def can_transition(self, from_state: FormStatus, to_state: FormStatus) -> bool:
        """Проверяет, возможен ли переход в указанное состояние.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            True если переход допустим.
        """
        return to_state in self.get_allowed_transitions(from_state)

    def is_mfa_required(self, from_state: FormStatus, to_state: FormStatus) -> bool:
        """Проверяет, требуется ли MFA для перехода.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            True если требуется MFA.
        """
        return (from_state, to_state) in _MFA_REQUIRED_TRANSITIONS

    def get_next_state(self, current: FormStatus) -> Optional[FormStatus]:
        """Возвращает следующее состояние в последовательности.

        Args:
            current: Текущее состояние.

        Returns:
            Следующее состояние или None если терминальное.
        """
        transitions: dict[FormStatus, FormStatus] = {
            FormStatus.DRAFT: FormStatus.FILLED,
            FormStatus.FILLED: FormStatus.VALIDATED,
            FormStatus.VALIDATED: FormStatus.APPROVED,
            FormStatus.APPROVED: FormStatus.SIGNED,
            FormStatus.SIGNED: FormStatus.ARCHIVED,
        }
        return transitions.get(current)


# =============================================================================
# WorkflowController
# =============================================================================


@dataclass
class WorkflowController:
    """Контроллер для управления workflow документов.

    Отвечает за:
    - Переходы между состояниями документа
    - Управление ролями пользователя
    - Координацию MFA для критичных операций
    - Управление комментариями к полям
    - Ведение истории workflow

    Attributes:
        auth_controller: Контроллер аутентификации для MFA.
        document_store: Хранилище документов (опционально).
        current_role: Текущая активная роль пользователя.
        require_mfa: Требовать ли MFA для критичных переходов.

    Example:
        >>> controller = WorkflowController(auth_controller=auth_ctrl)
        >>> controller.switch_role(WorkflowRole.EDITOR)
        >>> state = controller.get_current_state(doc_id)
        >>> controller.transition(doc_id, FormStatus.FILLED)
    """

    auth_controller: Optional[AuthControllerProtocol] = None
    document_store: Optional[DocumentStoreProtocol] = None
    current_role: WorkflowRole = field(default=WorkflowRole.OPERATOR)
    require_mfa: bool = True

    def __post_init__(self) -> None:
        """Инициализация внутренних структур."""
        self._workflow_engine: Final[ApprovalWorkflow] = ApprovalWorkflow()
        self._history: Final[dict[UUID, list[WorkflowEvent]]] = {}
        self._comments: Final[dict[UUID, list[FieldComment]]] = {}
        self._pending_mfa_callback: Optional[Callable[[bool], None]] = None
        self._pending_transition_state: Optional[tuple[UUID, FormStatus, str]] = None

    # -------------------------------------------------------------------------
    # State Management
    # -------------------------------------------------------------------------

    def get_current_state(self, doc_id: UUID) -> FormStatus:
        """Возвращает текущее состояние документа.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            Текущий статус документа.

        Raises:
            DocumentNotFoundError: Если документ не найден.
        """
        if self.document_store is not None:
            if not self.document_store.exists(doc_id):
                raise DocumentNotFoundError(doc_id)
            status_str = self.document_store.get_status(doc_id)
            return FormStatus(status_str)

        # Если нет хранилища, ищем в истории
        if doc_id in self._history and self._history[doc_id]:
            return self._history[doc_id][-1].to_state

        return FormStatus.DRAFT

    def can_transition(self, doc_id: UUID, target: FormStatus) -> bool:
        """Проверяет, возможен ли переход в указанное состояние.

        Args:
            doc_id: Идентификатор документа.
            target: Целевое состояние.

        Returns:
            True если переход допустим и разрешён текущей ролью.
        """
        try:
            current = self.get_current_state(doc_id)
        except DocumentNotFoundError:
            return False

        # Проверяем, что переход разрешён
        if not self._workflow_engine.can_transition(current, target):
            return False

        # Проверяем права роли
        allowed_roles = _ROLE_PERMISSIONS.get(current, [])
        if self.current_role not in allowed_roles:
            return False

        return True

    def transition(
        self,
        doc_id: UUID,
        target: FormStatus,
        reason: str = "",
        skip_mfa: bool = False,
    ) -> None:
        """Выполняет переход документа в указанное состояние.

        Args:
            doc_id: Идентификатор документа.
            target: Целевое состояние.
            reason: Причина перехода (опционально).
            skip_mfa: Пропустить MFA (только для внутреннего использования).

        Raises:
            WorkflowTransitionError: Если переход недопустим.
            MFARequiredError: Если требуется MFA, но не подтверждён.
            DocumentNotFoundError: Если документ не найден.
        """
        current = self.get_current_state(doc_id)

        # Проверяем возможность перехода
        if not self._workflow_engine.can_transition(current, target):
            allowed = self.get_allowed_transitions(doc_id)
            allowed_names = [s.value for s in allowed]
            raise WorkflowTransitionError(
                from_state=current,
                to_state=target,
                message=f"Допустимые переходы: {allowed_names}",
            )

        # Проверяем права роли
        if not self._check_role_permission(current):
            allowed_roles = _ROLE_PERMISSIONS.get(current, [])
            role_names = [r.display_name for r in allowed_roles]
            raise WorkflowTransitionError(
                from_state=current,
                to_state=target,
                message=f"Недостаточно прав. Требуется роль: {role_names}",
            )

        # Проверяем MFA
        if self.require_mfa and self._workflow_engine.is_mfa_required(current, target):
            if not skip_mfa and not self._is_mfa_verified():
                # Сохраняем состояние и запрашиваем MFA
                self._pending_transition_state = (doc_id, target, reason)
                self._request_mfa(f"Переход {current.value} → {target.value}")
                return

        # Выполняем переход
        self._execute_transition(doc_id, current, target, reason)

    def _execute_transition(
        self,
        doc_id: UUID,
        from_state: FormStatus,
        to_state: FormStatus,
        reason: str,
    ) -> None:
        """Внутренний метод выполнения перехода."""
        # Обновляем статус в хранилище
        if self.document_store is not None:
            self.document_store.set_status(doc_id, to_state.value)

        # Создаём событие истории
        event = WorkflowEvent(
            event_id=f"{doc_id}_{datetime.now().isoformat()}",
            doc_id=doc_id,
            from_state=from_state,
            to_state=to_state,
            role=self.current_role,
            timestamp=datetime.now(),
            reason=reason,
            mfa_verified=self._is_mfa_verified(),
        )

        # Добавляем в историю
        if doc_id not in self._history:
            self._history[doc_id] = []
        self._history[doc_id].append(event)

        logger.info(
            f"Документ {doc_id}: переход {from_state.value} → {to_state.value} "
            f"(роль: {self.current_role.value})"
        )

        # Очищаем pending состояние
        self._pending_transition_state = None

    def restore_status(self, doc_id: UUID, status: FormStatus) -> None:
        """Восстанавливает статус документа (для undo операций).

        В отличие от transition(), не проверяет допустимость перехода.
        Используется только для отмены ранее выполненных переходов.
        Обновляет document_store (если доступен) и добавляет запись в историю.

        Args:
            doc_id: Идентификатор документа.
            status: Целевое состояние для восстановления.
        """
        current = self.get_current_state(doc_id)

        if self.document_store is not None:
            self.document_store.set_status(doc_id, status.value)

        # Добавляем запись в историю для корректной работы get_current_state
        event = WorkflowEvent(
            event_id=f"{doc_id}_{datetime.now().isoformat()}_restore",
            doc_id=doc_id,
            from_state=current,
            to_state=status,
            role=self.current_role,
            timestamp=datetime.now(),
            reason="Восстановление (undo)",
        )
        if doc_id not in self._history:
            self._history[doc_id] = []
        self._history[doc_id].append(event)

        logger.info(
            "Документ %s: восстановлен статус %s (undo)",
            doc_id,
            status.value,
        )

    def get_allowed_transitions(self, doc_id: UUID) -> list[FormStatus]:
        """Возвращает список разрешённых следующих состояний.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            Список допустимых состояний с учётом прав роли.
        """
        try:
            current = self.get_current_state(doc_id)
        except DocumentNotFoundError:
            return []

        all_allowed = self._workflow_engine.get_allowed_transitions(current)

        # Фильтруем по правам роли
        allowed_roles = _ROLE_PERMISSIONS.get(current, [])
        if self.current_role not in allowed_roles:
            return []

        return all_allowed

    # -------------------------------------------------------------------------
    # Workflow History
    # -------------------------------------------------------------------------

    def get_workflow_history(self, doc_id: UUID) -> list[WorkflowEvent]:
        """Возвращает историю workflow для документа.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            Список событий в хронологическом порядке.
        """
        return self._history.get(doc_id, []).copy()

    def get_last_event(self, doc_id: UUID) -> Optional[WorkflowEvent]:
        """Возвращает последнее событие для документа.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            Последнее событие или None.
        """
        history = self._history.get(doc_id, [])
        return history[-1] if history else None

    # -------------------------------------------------------------------------
    # Role Management
    # -------------------------------------------------------------------------

    def switch_role(self, new_role: WorkflowRole) -> None:
        """Переключает текущую роль пользователя.

        Args:
            new_role: Новая роль.

        Note:
            При переключении роли сбрасывается MFA-подтверждение.
        """
        if new_role != self.current_role:
            old_role = self.current_role
            self.current_role = new_role
            logger.info(f"Переключение роли: {old_role.value} → {new_role.value}")

    def get_current_role(self) -> WorkflowRole:
        """Возвращает текущую активную роль.

        Returns:
            Текущая роль пользователя.
        """
        return self.current_role

    def _check_role_permission(self, state: FormStatus) -> bool:
        """Проверяет, имеет ли текущая роль право на действие в состоянии."""
        allowed_roles = _ROLE_PERMISSIONS.get(state, [])
        return self.current_role in allowed_roles

    # -------------------------------------------------------------------------
    # MFA Coordination
    # -------------------------------------------------------------------------

    def is_mfa_required_for_transition(self, from_state: FormStatus, to_state: FormStatus) -> bool:
        """Проверяет, требуется ли MFA для перехода.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            True если требуется MFA.
        """
        return self._workflow_engine.is_mfa_required(from_state, to_state)

    def _is_mfa_verified(self) -> bool:
        """Проверяет, подтверждено ли MFA."""
        if self.auth_controller is None:
            return True  # Без AuthController MFA не требуется
        return self.auth_controller.is_mfa_verified()

    def _request_mfa(self, operation: str) -> None:
        """Запрашивает MFA через AuthController."""
        if self.auth_controller is None:
            logger.warning(f"MFA требуется, но AuthController не настроен: {operation}")
            return

        def mfa_callback(success: bool) -> None:
            if success and self._pending_transition_state is not None:
                doc_id, target, reason = self._pending_transition_state
                self._execute_transition(
                    doc_id,
                    self.get_current_state(doc_id),
                    target,
                    reason,
                )
            else:
                self._pending_transition_state = None
                raise MFARequiredError(operation)

        self.auth_controller.require_mfa(operation, mfa_callback)

    def complete_mfa(self, success: bool) -> None:
        """Завершает MFA-поток (вызывается извне после диалога MFA).

        Args:
            success: Результат MFA-проверки.
        """
        if self._pending_mfa_callback is not None:
            self._pending_mfa_callback(success)
            self._pending_mfa_callback = None

    # -------------------------------------------------------------------------
    # Field Comments
    # -------------------------------------------------------------------------

    def add_comment(
        self,
        doc_id: UUID,
        field_id: str,
        comment: str,
        severity: Severity = Severity.INFO,
    ) -> FieldComment:
        """Добавляет комментарий к полю документа.

        Args:
            doc_id: Идентификатор документа.
            field_id: Идентификатор поля.
            comment: Текст комментария.
            severity: Уровень важности комментария.

        Returns:
            Созданный комментарий.
        """
        comment_obj = FieldComment(
            comment_id=f"{doc_id}_{field_id}_{datetime.now().isoformat()}",
            doc_id=doc_id,
            field_id=field_id,
            text=comment,
            author_role=self.current_role,
            severity=severity,
            created_at=datetime.now(),
            resolved=False,
        )

        if doc_id not in self._comments:
            self._comments[doc_id] = []
        self._comments[doc_id].append(comment_obj)

        logger.info(f"Добавлен комментарий к полю {field_id} документа {doc_id}")

        return comment_obj

    def resolve_comment(self, doc_id: UUID, comment_id: str) -> None:
        """Отмечает комментарий как решённый.

        Args:
            doc_id: Идентификатор документа.
            comment_id: Идентификатор комментария.

        Raises:
            ValueError: Если комментарий не найден.
        """
        if doc_id not in self._comments:
            raise ValueError(f"Комментарии для документа {doc_id} не найдены")

        for i, comment in enumerate(self._comments[doc_id]):
            if comment.comment_id == comment_id:
                # Create new resolved comment (immutable pattern)
                resolved_comment = FieldComment(
                    comment_id=comment.comment_id,
                    doc_id=comment.doc_id,
                    field_id=comment.field_id,
                    text=comment.text,
                    author_role=comment.author_role,
                    severity=comment.severity,
                    created_at=comment.created_at,
                    resolved=True,
                    resolved_at=datetime.now(),
                    resolved_by=self.current_role,
                )
                self._comments[doc_id][i] = resolved_comment
                logger.info(f"Комментарий {comment_id} отмечен как решённый")
                return

        raise ValueError(f"Комментарий {comment_id} не найден")

    def get_field_comments(self, doc_id: UUID, field_id: str) -> list[FieldComment]:
        """Возвращает все комментарии к полю.

        Args:
            doc_id: Идентификатор документа.
            field_id: Идентификатор поля.

        Returns:
            Список комментариев к полю.
        """
        if doc_id not in self._comments:
            return []

        return [c for c in self._comments[doc_id] if c.field_id == field_id]

    def get_all_comments(self, doc_id: UUID) -> list[FieldComment]:
        """Возвращает все комментарии к документу.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            Список всех комментариев документа.
        """
        return self._comments.get(doc_id, []).copy()

    def get_unresolved_comments(self, doc_id: UUID) -> list[FieldComment]:
        """Возвращает нерешённые комментарии документа.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            Список нерешённых комментариев.
        """
        if doc_id not in self._comments:
            return []
        return [c for c in self._comments[doc_id] if not c.resolved]

    def has_unresolved_comments(self, doc_id: UUID, field_id: str = "") -> bool:
        """Проверяет наличие нерешённых комментариев.

        Args:
            doc_id: Идентификатор документа.
            field_id: Идентификатор поля (если пусто — проверяет все поля).

        Returns:
            True если есть нерешённые комментарии.
        """
        if doc_id not in self._comments:
            return False

        comments = self._comments[doc_id]
        if field_id:
            comments = [c for c in comments if c.field_id == field_id]

        return any(not c.resolved for c in comments)

    # -------------------------------------------------------------------------
    # Approval/Rejection
    # -------------------------------------------------------------------------

    def approve(self, doc_id: UUID, reason: str = "") -> None:
        """Утверждает документ (переводит в APPROVED).

        Args:
            doc_id: Идентификатор документа.
            reason: Причина утверждения.

        Raises:
            WorkflowTransitionError: Если переход невозможен.
        """
        self.transition(doc_id, FormStatus.APPROVED, reason=reason or "Документ утверждён")

    def reject(
        self,
        doc_id: UUID,
        reason: str,
        target_state: FormStatus = FormStatus.REJECTED,
    ) -> None:
        """Отклоняет документ.

        Args:
            doc_id: Идентификатор документа.
            reason: Причина отклонения.
            target_state: Целевое состояние (по умолчанию REJECTED).

        Raises:
            WorkflowTransitionError: Если переход невозможен.
        """
        if target_state not in (
            FormStatus.REJECTED,
            FormStatus.DRAFT,
            FormStatus.FILLED,
        ):
            raise WorkflowTransitionError(
                from_state=self.get_current_state(doc_id),
                to_state=target_state,
                message="Недопустимое целевое состояние для отклонения",
            )
        self.transition(doc_id, target_state, reason=f"Отклонено: {reason}")

    def can_reject(self, doc_id: UUID) -> bool:
        """Проверяет, может ли текущая роль отклонить документ.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            True если отклонение возможно.
        """
        try:
            current = self.get_current_state(doc_id)
        except DocumentNotFoundError:
            return False

        # Отклонение доступно для SUPERVISOR и SIGNATORY
        if self.current_role not in (WorkflowRole.SUPERVISOR, WorkflowRole.SIGNATORY):
            return False

        # Нельзя отклонить уже отклонённый или архивированный документ
        if current in (FormStatus.REJECTED, FormStatus.ARCHIVED):
            return False

        return True

    # -------------------------------------------------------------------------
    # UI Integration Helpers
    # -------------------------------------------------------------------------

    def create_role_badge(
        self,
        parent: Any,
        size: str = "medium",
        on_click: Optional[Callable[[Role], None]] = None,
    ) -> RoleBadge:
        """Создаёт RoleBadge для текущей роли.

        Args:
            parent: Родительский виджет Tkinter.
            size: Размер бейджа (small, medium, large).
            on_click: Callback при клике на бейдж.

        Returns:
            RoleBadge widget.
        """
        # Map WorkflowRole to Role
        role_map: dict[WorkflowRole, Role] = {
            WorkflowRole.OPERATOR: Role.OPERATOR,
            WorkflowRole.EDITOR: Role.EDITOR,
            WorkflowRole.SUPERVISOR: Role.SUPERVISOR,
            WorkflowRole.SIGNATORY: Role.SIGNATORY,
        }
        view_role = role_map.get(self.current_role, Role.OPERATOR)
        return RoleBadge(parent, role=view_role, size=size, on_click=on_click)

    def create_workflow_timeline(
        self,
        parent: Any,
        doc_id: UUID,
        on_state_change: Optional[Callable[[WorkflowState], None]] = None,
    ) -> WorkflowTimeline:
        """Создаёт WorkflowTimeline для документа.

        Args:
            parent: Родительский виджет Tkinter.
            doc_id: Идентификатор документа.
            on_state_change: Callback при запросе смены состояния.

        Returns:
            WorkflowTimeline widget.
        """
        current_state = self.get_current_state(doc_id)
        view_state = _FORM_STATUS_TO_WORKFLOW_STATE.get(current_state, WorkflowState.DRAFT)
        view_role = self._map_role_to_view(self.current_role)

        return WorkflowTimeline(
            parent,
            current_state=view_state,
            current_role=view_role,
            on_state_change=on_state_change,
        )

    def create_field_comment_widget(
        self,
        parent: Any,
        doc_id: UUID,
        field_id: str,
        on_resolve: Optional[Callable[[bool], None]] = None,
    ) -> Optional[FieldCommentWidget]:
        """Создаёт FieldCommentWidget для поля.

        Args:
            parent: Родительский виджет Tkinter.
            doc_id: Идентификатор документа.
            field_id: Идентификатор поля.
            on_resolve: Callback при разрешении комментария.

        Returns:
            FieldCommentWidget или None если нет комментариев.
        """
        comments = self.get_field_comments(doc_id, field_id)
        if not comments:
            return None

        # Берём последний неразрешённый комментарий или последний разрешённый
        unresolved = [c for c in comments if not c.resolved]
        if unresolved:
            comment = unresolved[-1]
            severity = self._map_severity_to_view(comment.severity)
        else:
            comment = comments[-1]
            severity = CommentSeverity.INFO

        return FieldCommentWidget(
            parent,
            text=comment.text,
            author=self._map_role_to_view(comment.author_role),
            severity=severity,
            resolved=comment.resolved,
            on_resolve=on_resolve,
        )

    def _map_role_to_view(self, role: WorkflowRole) -> Role:
        """Маппит WorkflowRole на Role из view.workflow."""
        role_map: dict[WorkflowRole, Role] = {
            WorkflowRole.OPERATOR: Role.OPERATOR,
            WorkflowRole.EDITOR: Role.EDITOR,
            WorkflowRole.SUPERVISOR: Role.SUPERVISOR,
            WorkflowRole.SIGNATORY: Role.SIGNATORY,
        }
        return role_map.get(role, Role.OPERATOR)

    def _map_severity_to_view(self, severity: Severity) -> CommentSeverity:
        """Маппит Severity на CommentSeverity из view.workflow."""
        severity_map: dict[Severity, CommentSeverity] = {
            Severity.INFO: CommentSeverity.INFO,
            Severity.WARNING: CommentSeverity.WARNING,
            Severity.ERROR: CommentSeverity.ERROR,
        }
        return severity_map.get(severity, CommentSeverity.INFO)

    # -------------------------------------------------------------------------
    # Statistics and Reporting
    # -------------------------------------------------------------------------

    def get_statistics(self, doc_id: UUID) -> dict[str, Any]:
        """Возвращает статистику workflow для документа.

        Args:
            doc_id: Идентификатор документа.

        Returns:
            Словарь со статистикой.
        """
        history = self.get_workflow_history(doc_id)
        comments = self.get_all_comments(doc_id)
        unresolved = self.get_unresolved_comments(doc_id)
        current = self.get_current_state(doc_id)

        # Время проведённое в каждом состоянии (приблизительно)
        time_in_states: dict[str, float] = {}
        for i, event in enumerate(history):
            if i > 0:
                duration = (event.timestamp - history[i - 1].timestamp).total_seconds()
                state_name = event.from_state.value
                time_in_states[state_name] = time_in_states.get(state_name, 0) + duration

        return {
            "doc_id": str(doc_id),
            "current_state": current.value,
            "current_state_localized": current.localized_name,
            "total_transitions": len(history),
            "total_comments": len(comments),
            "unresolved_comments": len(unresolved),
            "current_role": self.current_role.value,
            "time_in_states_seconds": time_in_states,
            "is_editable": current.is_editable,
            "is_terminal": current.is_terminal,
        }

    def clear_document(self, doc_id: UUID) -> None:
        """Очищает все данные workflow для документа.

        Args:
            doc_id: Идентификатор документа.
        """
        if doc_id in self._history:
            del self._history[doc_id]
        if doc_id in self._comments:
            del self._comments[doc_id]
        logger.info(f"Очищены данные workflow для документа {doc_id}")
