"""Тесты для workflow events.

Проверяет корректность всех event dataclasses,
WorkflowEventBus и фабричную функцию create_transition_event.
"""

from __future__ import annotations

import logging
from datetime import datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.gui.workflow.events import (
    CommentEvent,
    MFAChallengeEvent,
    RoleChangeEvent,
    StateTransitionEvent,
    UndoRedoEvent,
    WorkflowErrorEvent,
    WorkflowEventBus,
    WorkflowUIEvent,
    create_transition_event,
)
from src.gui.workflow.constants import STATUS_ORDER


class TestWorkflowUIEvent:
    """Тесты базового события WorkflowUIEvent."""

    def test_create_event(self) -> None:
        """Базовое событие создаётся корректно."""
        doc_id = uuid4()
        event = WorkflowUIEvent(
            event_id="test_1",
            doc_id=doc_id,
            timestamp=datetime.now(),
            event_type="test",
        )
        assert event.event_id == "test_1"
        assert event.doc_id == doc_id
        assert event.event_type == "test"

    def test_empty_event_id_raises(self) -> None:
        """Пустой event_id вызывает ValueError."""
        doc_id = uuid4()
        with pytest.raises(ValueError, match="event_id"):
            WorkflowUIEvent(
                event_id="",
                doc_id=doc_id,
                timestamp=datetime.now(),
                event_type="test",
            )

    def test_frozen_event(self) -> None:
        """Event immutable (frozen=True)."""
        doc_id = uuid4()
        event = WorkflowUIEvent(
            event_id="test_1",
            doc_id=doc_id,
            timestamp=datetime.now(),
            event_type="test",
        )
        with pytest.raises(AttributeError):
            event.event_id = "changed"  # type: ignore[misc]


class TestStateTransitionEvent:
    """Тесты события перехода состояния."""

    def _make_transition_event(
        self,
        from_state: str = "draft",
        to_state: str = "filled",
    ) -> StateTransitionEvent:
        """Создаёт тестовое событие перехода."""
        from enum import Enum

        class FakeFormStatus(Enum):
            DRAFT = "draft"
            FILLED = "filled"
            VALIDATED = "validated"
            APPROVED = "approved"
            SIGNED = "signed"
            ARCHIVED = "archived"

        class FakeWorkflowRole(Enum):
            OPERATOR = "operator"

        return StateTransitionEvent(
            event_id="trans_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="transition",
            from_state=FakeFormStatus(from_state),
            to_state=FakeFormStatus(to_state),
            role=FakeWorkflowRole.OPERATOR,
        )

    def test_is_forward_transition(self) -> None:
        """Переход draft→filled считается прямым."""
        event = self._make_transition_event("draft", "filled")
        assert event.is_forward is True

    def test_is_backward_transition(self) -> None:
        """Переход filled→draft считается обратным."""
        event = self._make_transition_event("filled", "draft")
        assert event.is_backward is True

    def test_mfa_verified_default(self) -> None:
        """mfa_verified по умолчанию False."""
        event = self._make_transition_event()
        assert event.mfa_verified is False

    def test_undoable_default(self) -> None:
        """undoable по умолчанию True."""
        event = self._make_transition_event()
        assert event.undoable is True


class TestUndoRedoEvent:
    """Тесты события undo/redo."""

    def test_create_undo_event(self) -> None:
        """Событие undo создаётся корректно."""
        event = UndoRedoEvent(
            event_id="undo_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="undo",
            operation="undo",
        )
        assert event.operation == "undo"

    def test_create_redo_event(self) -> None:
        """Событие redo создаётся корректно."""
        event = UndoRedoEvent(
            event_id="redo_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="redo",
            operation="redo",
        )
        assert event.operation == "redo"

    def test_invalid_operation_raises(self) -> None:
        """Неверная операция вызывает ValueError."""
        with pytest.raises(ValueError, match="undo"):
            UndoRedoEvent(
                event_id="bad_1",
                doc_id=uuid4(),
                timestamp=datetime.now(),
                event_type="bad",
                operation="invalid",
            )


class TestRoleChangeEvent:
    """Тесты события смены роли."""

    def test_create_role_change(self) -> None:
        """Событие смены роли создаётся корректно."""
        from enum import Enum

        class FakeRole(Enum):
            OPERATOR = "operator"
            EDITOR = "editor"

        event = RoleChangeEvent(
            event_id="rc_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="role_change",
            from_role=FakeRole.OPERATOR,
            to_role=FakeRole.EDITOR,
        )
        assert event.from_role == FakeRole.OPERATOR
        assert event.to_role == FakeRole.EDITOR
        assert event.mfa_verified is False
        assert event.free_mode is False


class TestMFAChallengeEvent:
    """Тесты события MFA challenge."""

    def test_create_mfa_challenge(self) -> None:
        """Событие MFA challenge создаётся корректно."""
        event = MFAChallengeEvent(
            event_id="mfa_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="mfa_challenge",
            operation="Подписание документа",
        )
        assert event.operation == "Подписание документа"
        assert event.success is False
        assert event.error_message is None


class TestCommentEvent:
    """Тесты события комментария."""

    def test_create_comment_event(self) -> None:
        """Событие комментария создаётся корректно."""
        event = CommentEvent(
            event_id="cmt_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="comment",
            action="add",
            field_id="recipient",
            comment_id="c1",
            text="Проверить сумму",
        )
        assert event.action == "add"
        assert event.field_id == "recipient"
        assert event.severity == "info"


class TestWorkflowErrorEvent:
    """Тесты события ошибки workflow."""

    def test_create_error_event(self) -> None:
        """Событие ошибки создаётся корректно."""
        event = WorkflowErrorEvent(
            event_id="err_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="error",
            error_type="transition_failed",
            error_message="Недопустимый переход",
        )
        assert event.error_type == "transition_failed"
        assert event.recoverable is False
        assert event.context == {}


    def test_error_event_with_context(self) -> None:
        """Событие ошибки с контекстом."""
        event = WorkflowErrorEvent(
            event_id="err_2",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="error",
            error_type="mfa_failed",
            error_message="MFA не подтверждено",
            recoverable=True,
            context={"method": "totp"},
        )
        assert event.recoverable is True
        assert event.context["method"] == "totp"


class TestWorkflowEventBus:
    """Тесты шины событий."""

    def test_subscribe_and_publish(self) -> None:
        """Подписчик получает событие при публикации."""
        bus = WorkflowEventBus()
        received: list[WorkflowUIEvent] = []

        def handler(event: WorkflowUIEvent) -> None:
            received.append(event)

        bus.subscribe("test", handler)

        event = WorkflowUIEvent(
            event_id="bus_1",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="test",
        )
        bus.publish(event)
        assert len(received) == 1
        assert received[0].event_id == "bus_1"

    def test_unsubscribe(self) -> None:
        """Отписанный подписчик не получает события."""
        bus = WorkflowEventBus()
        received: list[WorkflowUIEvent] = []

        def handler(event: WorkflowUIEvent) -> None:
            received.append(event)

        bus.subscribe("test", handler)
        bus.unsubscribe("test", handler)

        event = WorkflowUIEvent(
            event_id="bus_2",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="test",
        )
        bus.publish(event)
        assert len(received) == 0

    def test_subscribe_all(self) -> None:
        """Глобальный подписчик получает все события."""
        bus = WorkflowEventBus()
        received: list[WorkflowUIEvent] = []

        def handler(event: WorkflowUIEvent) -> None:
            received.append(event)

        bus.subscribe_all(handler)

        event = WorkflowUIEvent(
            event_id="bus_3",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="any_type",
        )
        bus.publish(event)
        assert len(received) == 1

    def test_clear(self) -> None:
        """clear() удаляет все подписки."""
        bus = WorkflowEventBus()
        bus.subscribe("test", lambda e: None)
        bus.subscribe_all(lambda e: None)
        bus.clear()
        # После очистки публикация не вызывает обработчиков
        event = WorkflowUIEvent(
            event_id="bus_4",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="test",
        )
        bus.publish(event)  # Не должно быть ошибок

    def test_handler_exception_does_not_stop_others(self) -> None:
        """Исключение в одном обработчике не останавливает другие."""
        bus = WorkflowEventBus()
        received: list[WorkflowUIEvent] = []

        def bad_handler(event: WorkflowUIEvent) -> None:
            raise ValueError("test error")

        def good_handler(event: WorkflowUIEvent) -> None:
            received.append(event)

        bus.subscribe("test", bad_handler)
        bus.subscribe("test", good_handler)

        event = WorkflowUIEvent(
            event_id="bus_5",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="test",
        )
        bus.publish(event)
        assert len(received) == 1

    def test_no_subscribers_no_error(self) -> None:
        """Публикация без подписчиков не вызывает ошибок."""
        bus = WorkflowEventBus()
        event = WorkflowUIEvent(
            event_id="bus_6",
            doc_id=uuid4(),
            timestamp=datetime.now(),
            event_type="unknown",
        )
        bus.publish(event)  # Не должно быть ошибок


class TestCreateTransitionEvent:
    """Тесты фабричной функции create_transition_event."""

    def test_creates_transition_event(self) -> None:
        """Фабрика создаёт событие перехода."""
        from enum import Enum

        class FakeFormStatus(Enum):
            DRAFT = "draft"
            FILLED = "filled"

        class FakeWorkflowRole(Enum):
            OPERATOR = "operator"

        doc_id = uuid4()
        event = create_transition_event(
            doc_id=doc_id,
            from_state=FakeFormStatus.DRAFT,
            to_state=FakeFormStatus.FILLED,
            role=FakeWorkflowRole.OPERATOR,
        )
        assert isinstance(event, StateTransitionEvent)
        assert event.event_type == "transition"
        assert event.doc_id == doc_id

    def test_archived_not_undoable(self) -> None:
        """Переход в archived помечается как не undoable."""
        from enum import Enum

        class FakeFormStatus(Enum):
            SIGNED = "signed"
            ARCHIVED = "archived"

        class FakeWorkflowRole(Enum):
            SIGNATORY = "signatory"

        doc_id = uuid4()
        event = create_transition_event(
            doc_id=doc_id,
            from_state=FakeFormStatus.SIGNED,
            to_state=FakeFormStatus.ARCHIVED,
            role=FakeWorkflowRole.SIGNATORY,
            mfa_verified=True,
        )
        assert event.undoable is False