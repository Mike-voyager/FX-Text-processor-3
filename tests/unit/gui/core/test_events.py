"""Unit-тесты для системы событий GUI.

Проверяет:
- BaseEvent и все производные классы
- Соответствие EventProtocol
- Frozen dataclass поведение
- Методы get_data, stop_propagation, is_propagation_stopped
- Security: обрезка длинных widget_id

Coverage target: ≥90%
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from src.gui.core.events import (
    MAX_WIDGET_ID_LENGTH,
    ActionEvent,
    BaseEvent,
    FocusGainedEvent,
    FocusLostEvent,
    MountEvent,
    UnmountEvent,
    ValueChangedEvent,
)
from src.gui.core.protocols import EventProtocol

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def base_event() -> BaseEvent:
    """Fixture для BaseEvent."""
    return BaseEvent(widget_id="test_widget")


@pytest.fixture
def action_event() -> ActionEvent:
    """Fixture для ActionEvent."""
    return ActionEvent(
        widget_id="btn_save",
        action="save_document",
        handler_name="on_save",
    )


@pytest.fixture
def focus_gained_event() -> FocusGainedEvent:
    """Fixture для FocusGainedEvent."""
    return FocusGainedEvent(
        widget_id="entry_01",
        previous_widget_id="entry_00",
    )


@pytest.fixture
def focus_lost_event() -> FocusLostEvent:
    """Fixture для FocusLostEvent."""
    return FocusLostEvent(
        widget_id="entry_01",
        next_widget_id="entry_02",
    )


@pytest.fixture
def mount_event() -> MountEvent:
    """Fixture для MountEvent."""
    return MountEvent(widget_id="panel_01")


@pytest.fixture
def unmount_event() -> UnmountEvent:
    """Fixture для UnmountEvent."""
    return UnmountEvent(widget_id="panel_01")


@pytest.fixture
def value_changed_event() -> ValueChangedEvent:
    """Fixture для ValueChangedEvent."""
    return ValueChangedEvent(
        widget_id="field_01",
        old_value="old",
        new_value="new",
    )


# =============================================================================
# TEST: BaseEvent
# =============================================================================


class TestBaseEvent:
    """Тесты BaseEvent."""

    def test_creation(self, base_event: BaseEvent) -> None:
        """Создание BaseEvent с валидными параметрами."""
        assert base_event.widget_id == "test_widget"
        assert base_event.timestamp > 0

    def test_default_timestamp(self) -> None:
        """Timestamp автоматически устанавливается при создании."""
        import time

        before = time.time()
        event = BaseEvent(widget_id="test")
        after = time.time()

        assert before <= event.timestamp <= after

    def test_source_widget_id_matches_widget_id(self, base_event: BaseEvent) -> None:
        """source_widget_id соответствует widget_id."""
        assert base_event.source_widget_id == base_event.widget_id

    def test_event_type(self, base_event: BaseEvent) -> None:
        """event_type возвращает 'base'."""
        assert base_event.event_type == "base"

    def test_get_data_returns_dict(self, base_event: BaseEvent) -> None:
        """get_data() возвращает словарь."""
        data = base_event.get_data()

        assert isinstance(data, dict)
        assert data["widget_id"] == "test_widget"
        assert "timestamp" in data
        assert data["event_type"] == "base"

    def test_is_propagation_stopped_initial(self, base_event: BaseEvent) -> None:
        """Изначально распространение не остановлено."""
        assert base_event.is_propagation_stopped() is False

    def test_stop_propagation(self, base_event: BaseEvent) -> None:
        """stop_propagation() останавливает распространение."""
        base_event.stop_propagation()
        assert base_event.is_propagation_stopped() is True

    def test_isinstance_event_protocol(self, base_event: BaseEvent) -> None:
        """BaseEvent удовлетворяет EventProtocol."""
        assert isinstance(base_event, EventProtocol)

    def test_truncates_long_widget_id(self) -> None:
        """Длинный widget_id обрезается."""
        long_id = "x" * (MAX_WIDGET_ID_LENGTH + 50)
        event = BaseEvent(widget_id=long_id)

        assert len(event.widget_id) == MAX_WIDGET_ID_LENGTH

    def test_frozen_cannot_assign(self, base_event: BaseEvent) -> None:
        """Frozen dataclass не позволяет присваивание."""
        with pytest.raises(FrozenInstanceError):
            base_event.widget_id = "other"

    def test_repr(self, base_event: BaseEvent) -> None:
        """repr() содержит имя класса."""
        assert "BaseEvent" in repr(base_event)


# =============================================================================
# TEST: ActionEvent
# =============================================================================


class TestActionEvent:
    """Тесты ActionEvent."""

    def test_creation(self, action_event: ActionEvent) -> None:
        """Создание ActionEvent."""
        assert action_event.widget_id == "btn_save"
        assert action_event.action == "save_document"
        assert action_event.handler_name == "on_save"

    def test_event_type(self, action_event: ActionEvent) -> None:
        """event_type возвращает 'action'."""
        assert action_event.event_type == "action"

    def test_get_data(self, action_event: ActionEvent) -> None:
        """get_data() содержит action и handler_name."""
        data = action_event.get_data()

        assert data["action"] == "save_document"
        assert data["handler_name"] == "on_save"

    def test_isinstance_event_protocol(self, action_event: ActionEvent) -> None:
        """ActionEvent удовлетворяет EventProtocol."""
        assert isinstance(action_event, EventProtocol)

    def test_default_handler_name(self) -> None:
        """handler_name по умолчанию None."""
        event = ActionEvent(widget_id="btn", action="click")
        assert event.handler_name is None

    def test_default_action(self) -> None:
        """action по умолчанию пустая строка."""
        event = ActionEvent(widget_id="btn")
        assert event.action == ""


# =============================================================================
# TEST: FocusGainedEvent
# =============================================================================


class TestFocusGainedEvent:
    """Тесты FocusGainedEvent."""

    def test_creation(self, focus_gained_event: FocusGainedEvent) -> None:
        """Создание FocusGainedEvent."""
        assert focus_gained_event.widget_id == "entry_01"
        assert focus_gained_event.previous_widget_id == "entry_00"

    def test_event_type(self, focus_gained_event: FocusGainedEvent) -> None:
        """event_type возвращает 'focusgained'."""
        assert focus_gained_event.event_type == "focusgained"

    def test_get_data(self, focus_gained_event: FocusGainedEvent) -> None:
        """get_data() содержит previous_widget_id."""
        data = focus_gained_event.get_data()
        assert data["previous_widget_id"] == "entry_00"

    def test_isinstance_event_protocol(self, focus_gained_event: FocusGainedEvent) -> None:
        """FocusGainedEvent удовлетворяет EventProtocol."""
        assert isinstance(focus_gained_event, EventProtocol)

    def test_default_previous_widget_id(self) -> None:
        """previous_widget_id по умолчанию None."""
        event = FocusGainedEvent(widget_id="entry")
        assert event.previous_widget_id is None


# =============================================================================
# TEST: FocusLostEvent
# =============================================================================


class TestFocusLostEvent:
    """Тесты FocusLostEvent."""

    def test_creation(self, focus_lost_event: FocusLostEvent) -> None:
        """Создание FocusLostEvent."""
        assert focus_lost_event.widget_id == "entry_01"
        assert focus_lost_event.next_widget_id == "entry_02"

    def test_event_type(self, focus_lost_event: FocusLostEvent) -> None:
        """event_type возвращает 'focuslost'."""
        assert focus_lost_event.event_type == "focuslost"

    def test_get_data(self, focus_lost_event: FocusLostEvent) -> None:
        """get_data() содержит next_widget_id."""
        data = focus_lost_event.get_data()
        assert data["next_widget_id"] == "entry_02"

    def test_isinstance_event_protocol(self, focus_lost_event: FocusLostEvent) -> None:
        """FocusLostEvent удовлетворяет EventProtocol."""
        assert isinstance(focus_lost_event, EventProtocol)

    def test_default_next_widget_id(self) -> None:
        """next_widget_id по умолчанию None."""
        event = FocusLostEvent(widget_id="entry")
        assert event.next_widget_id is None


# =============================================================================
# TEST: MountEvent
# =============================================================================


class TestMountEvent:
    """Тесты MountEvent."""

    def test_creation(self, mount_event: MountEvent) -> None:
        """Создание MountEvent."""
        assert mount_event.widget_id == "panel_01"

    def test_event_type(self, mount_event: MountEvent) -> None:
        """event_type возвращает 'mount'."""
        assert mount_event.event_type == "mount"

    def test_isinstance_event_protocol(self, mount_event: MountEvent) -> None:
        """MountEvent удовлетворяет EventProtocol."""
        assert isinstance(mount_event, EventProtocol)

    def test_get_data(self, mount_event: MountEvent) -> None:
        """get_data() возвращает базовые поля."""
        data = mount_event.get_data()
        assert data["event_type"] == "mount"


# =============================================================================
# TEST: UnmountEvent
# =============================================================================


class TestUnmountEvent:
    """Тесты UnmountEvent."""

    def test_creation(self, unmount_event: UnmountEvent) -> None:
        """Создание UnmountEvent."""
        assert unmount_event.widget_id == "panel_01"

    def test_event_type(self, unmount_event: UnmountEvent) -> None:
        """event_type возвращает 'unmount'."""
        assert unmount_event.event_type == "unmount"

    def test_isinstance_event_protocol(self, unmount_event: UnmountEvent) -> None:
        """UnmountEvent удовлетворяет EventProtocol."""
        assert isinstance(unmount_event, EventProtocol)

    def test_get_data(self, unmount_event: UnmountEvent) -> None:
        """get_data() возвращает базовые поля."""
        data = unmount_event.get_data()
        assert data["event_type"] == "unmount"


# =============================================================================
# TEST: ValueChangedEvent
# =============================================================================


class TestValueChangedEvent:
    """Тесты ValueChangedEvent."""

    def test_creation(self, value_changed_event: ValueChangedEvent) -> None:
        """Создание ValueChangedEvent."""
        assert value_changed_event.widget_id == "field_01"
        assert value_changed_event.old_value == "old"
        assert value_changed_event.new_value == "new"

    def test_event_type(self, value_changed_event: ValueChangedEvent) -> None:
        """event_type возвращает 'valuechanged'."""
        assert value_changed_event.event_type == "valuechanged"

    def test_get_data(self, value_changed_event: ValueChangedEvent) -> None:
        """get_data() содержит old_value и new_value."""
        data = value_changed_event.get_data()
        assert data["old_value"] == "old"
        assert data["new_value"] == "new"

    def test_isinstance_event_protocol(self, value_changed_event: ValueChangedEvent) -> None:
        """ValueChangedEvent удовлетворяет EventProtocol."""
        assert isinstance(value_changed_event, EventProtocol)

    def test_default_values(self) -> None:
        """old_value и new_value по умолчанию None."""
        event = ValueChangedEvent(widget_id="field")
        assert event.old_value is None
        assert event.new_value is None


# =============================================================================
# TEST: EventProtocol Compliance
# =============================================================================


class TestEventProtocolCompliance:
    """Тесты соответствия EventProtocol."""

    def test_all_events_are_protocol_compliant(self) -> None:
        """Все события удовлетворяют EventProtocol."""
        events: list[Any] = [
            BaseEvent(widget_id="test"),
            ActionEvent(widget_id="btn", action="click"),
            FocusGainedEvent(widget_id="entry"),
            FocusLostEvent(widget_id="entry"),
            MountEvent(widget_id="panel"),
            UnmountEvent(widget_id="panel"),
            ValueChangedEvent(widget_id="field"),
        ]

        for event in events:
            assert isinstance(event, EventProtocol)
            assert hasattr(event, "timestamp")
            assert hasattr(event, "source_widget_id")
            assert hasattr(event, "event_type")
            assert callable(getattr(event, "get_data", None))
            assert callable(getattr(event, "is_propagation_stopped", None))
            assert callable(getattr(event, "stop_propagation", None))

    def test_stop_propagation_on_all_events(self) -> None:
        """stop_propagation() работает для всех типов событий."""
        events: list[BaseEvent] = [
            BaseEvent(widget_id="test"),
            ActionEvent(widget_id="btn", action="click"),
            FocusGainedEvent(widget_id="entry"),
            FocusLostEvent(widget_id="entry"),
            MountEvent(widget_id="panel"),
            UnmountEvent(widget_id="panel"),
            ValueChangedEvent(widget_id="field"),
        ]

        for event in events:
            event.stop_propagation()
            assert event.is_propagation_stopped() is True


# =============================================================================
# TEST: Security
# =============================================================================


class TestSecurity:
    """Тесты безопасности событий."""

    def test_max_widget_id_length_enforced(self) -> None:
        """MAX_WIDGET_ID_LENGTH соблюдается."""
        long_id = "a" * 200
        event = BaseEvent(widget_id=long_id)

        assert len(event.widget_id) <= MAX_WIDGET_ID_LENGTH

    def test_get_data_does_not_leak_internal_state(self) -> None:
        """get_data() не раскрывает внутреннее состояние."""
        event = BaseEvent(widget_id="test")
        data = event.get_data()

        assert "_propagation_stopped" not in data


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты экспорта модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены."""
        from src.gui.core import events

        assert hasattr(events, "__all__")
        assert "BaseEvent" in events.__all__
        assert "ActionEvent" in events.__all__
        assert "FocusGainedEvent" in events.__all__
        assert "FocusLostEvent" in events.__all__
        assert "MountEvent" in events.__all__
        assert "UnmountEvent" in events.__all__
        assert "ValueChangedEvent" in events.__all__
        assert "MAX_WIDGET_ID_LENGTH" in events.__all__


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.core.events"])
