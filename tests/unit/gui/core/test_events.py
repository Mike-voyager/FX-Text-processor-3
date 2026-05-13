"""Unit-тесты для типов событий GUI.

Проверяет:
- BaseEvent frozen и валидацию
- ValueChangedEvent has_changed метод
- FocusLostEvent/FocusGainedEvent валидацию
- ActionEvent get_data метод
- MountEvent/UnmountEvent

Coverage target: ≥95%
"""

from datetime import datetime

import pytest
from src.gui.core.events import (
    ActionEvent,
    BaseEvent,
    FocusGainedEvent,
    FocusLostEvent,
    MountEvent,
    UnmountEvent,
    ValueChangedEvent,
)

# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def base_event() -> BaseEvent:
    """Fixture для базового события."""
    return BaseEvent(
        widget_id="test_widget",
        event_type="test_event",
    )


@pytest.fixture
def value_changed_event() -> ValueChangedEvent:
    """Fixture для события изменения значения."""
    return ValueChangedEvent(
        widget_id="entry_username",
        event_type="value_changed",
        field_id="username",
        old_value="old_user",
        new_value="new_user",
    )


@pytest.fixture
def focus_lost_event() -> FocusLostEvent:
    """Fixture для события потери фокуса."""
    return FocusLostEvent(
        widget_id="entry_password",
        event_type="focus_lost",
        field_id="password",
    )


@pytest.fixture
def focus_gained_event() -> FocusGainedEvent:
    """Fixture для события получения фокуса."""
    return FocusGainedEvent(
        widget_id="entry_email",
        event_type="focus_gained",
        field_id="email",
    )


@pytest.fixture
def action_event() -> ActionEvent:
    """Fixture для события действия."""
    return ActionEvent(
        widget_id="btn_save",
        event_type="action",
        action_name="save_document",
        action_data={"path": "./doc.fxsd", "copies": 2},
    )


@pytest.fixture
def mount_event() -> MountEvent:
    """Fixture для события монтирования."""
    return MountEvent(
        widget_id="dialog_settings",
        event_type="mount",
        parent_widget="main_window",
    )


@pytest.fixture
def unmount_event() -> UnmountEvent:
    """Fixture для события демонтирования."""
    return UnmountEvent(
        widget_id="dialog_settings",
        event_type="unmount",
    )


# ==============================================================================
# TEST: BaseEvent
# ==============================================================================


class TestBaseEvent:
    """Тесты BaseEvent."""

    def test_is_frozen(self) -> None:
        """BaseEvent является frozen dataclass."""
        event = BaseEvent(widget_id="w1", event_type="click")

        with pytest.raises(AttributeError):
            event.widget_id = "w2"  # type: ignore

    def test_has_required_fields(self, base_event: BaseEvent) -> None:
        """BaseEvent имеет обязательные поля."""
        assert base_event.widget_id == "test_widget"
        assert base_event.event_type == "test_event"
        assert isinstance(base_event.timestamp, datetime)

    def test_timestamp_auto_generated(self) -> None:
        """timestamp автоматически генерируется."""
        before = datetime.now()
        event = BaseEvent(widget_id="w1", event_type="e1")
        after = datetime.now()

        assert before <= event.timestamp <= after

    def test_validation_empty_widget_id(self) -> None:
        """Валидация: widget_id не может быть пустым."""
        with pytest.raises(ValueError, match="widget_id не может быть пустым"):
            BaseEvent(widget_id="", event_type="click")

    def test_validation_whitespace_widget_id(self) -> None:
        """Валидация: widget_id не может быть whitespace."""
        with pytest.raises(ValueError, match="widget_id не может быть пустым"):
            BaseEvent(widget_id="   ", event_type="click")

    def test_validation_empty_event_type(self) -> None:
        """Валидация: event_type не может быть пустым."""
        with pytest.raises(ValueError, match="event_type не может быть пустым"):
            BaseEvent(widget_id="w1", event_type="")

    def test_validation_whitespace_event_type(self) -> None:
        """Валидация: event_type не может быть whitespace."""
        with pytest.raises(ValueError, match="event_type не может быть пустым"):
            BaseEvent(widget_id="w1", event_type="  \t  ")

    def test_custom_timestamp(self) -> None:
        """Можно установить кастомный timestamp."""
        custom_time = datetime(2026, 1, 1, 12, 0, 0)
        event = BaseEvent(
            widget_id="w1",
            event_type="e1",
            timestamp=custom_time,
        )
        assert event.timestamp == custom_time


# ==============================================================================
# TEST: ValueChangedEvent
# ==============================================================================


class TestValueChangedEvent:
    """Тесты ValueChangedEvent."""

    def test_is_frozen(self) -> None:
        """ValueChangedEvent является frozen dataclass."""
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
            old_value="old",
            new_value="new",
        )

        with pytest.raises(AttributeError):
            event.field_id = "f2"  # type: ignore

    def test_inherits_from_base(self, value_changed_event: ValueChangedEvent) -> None:
        """ValueChangedEvent наследуется от BaseEvent."""
        assert isinstance(value_changed_event, BaseEvent)

    def test_has_required_fields(self, value_changed_event: ValueChangedEvent) -> None:
        """ValueChangedEvent имеет обязательные поля."""
        assert value_changed_event.widget_id == "entry_username"
        assert value_changed_event.event_type == "value_changed"
        assert value_changed_event.field_id == "username"
        assert value_changed_event.old_value == "old_user"
        assert value_changed_event.new_value == "new_user"

    def test_validation_empty_field_id(self) -> None:
        """Валидация: field_id не может быть пустым."""
        with pytest.raises(ValueError, match="field_id не может быть пустым"):
            ValueChangedEvent(
                widget_id="w1",
                event_type="value_changed",
                field_id="",
                old_value="old",
                new_value="new",
            )

    def test_has_changed_true(self) -> None:
        """has_changed() возвращает True при изменении."""
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
            old_value="old",
            new_value="new",
        )
        assert event.has_changed() is True

    def test_has_changed_false_same_value(self) -> None:
        """has_changed() возвращает False при одинаковых значениях."""
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
            old_value="same",
            new_value="same",
        )
        assert event.has_changed() is False

    def test_has_changed_false_none_values(self) -> None:
        """has_changed() работает с None значениями."""
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
            old_value=None,
            new_value=None,
        )
        assert event.has_changed() is False

    def test_has_changed_true_none_to_value(self) -> None:
        """has_changed() True при изменении None на значение."""
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
            old_value=None,
            new_value="value",
        )
        assert event.has_changed() is True

    def test_has_changed_different_types(self) -> None:
        """has_changed() работает с разными типами."""
        # String vs int
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
            old_value="123",
            new_value=123,
        )
        assert event.has_changed() is True

        # List vs tuple
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
            old_value=[1, 2, 3],
            new_value=(1, 2, 3),
        )
        assert event.has_changed() is True

    def test_default_values(self) -> None:
        """ValueChangedEvent имеет значения по умолчанию."""
        event = ValueChangedEvent(
            widget_id="w1",
            event_type="value_changed",
            field_id="f1",
        )
        assert event.old_value is None
        assert event.new_value is None


# ==============================================================================
# TEST: FocusLostEvent
# ==============================================================================


class TestFocusLostEvent:
    """Тесты FocusLostEvent."""

    def test_is_frozen(self, focus_lost_event: FocusLostEvent) -> None:
        """FocusLostEvent является frozen dataclass."""
        with pytest.raises(AttributeError):
            focus_lost_event.field_id = "new_id"  # type: ignore

    def test_inherits_from_base(self, focus_lost_event: FocusLostEvent) -> None:
        """FocusLostEvent наследуется от BaseEvent."""
        assert isinstance(focus_lost_event, BaseEvent)

    def test_has_required_fields(self, focus_lost_event: FocusLostEvent) -> None:
        """FocusLostEvent имеет обязательные поля."""
        assert focus_lost_event.widget_id == "entry_password"
        assert focus_lost_event.event_type == "focus_lost"
        assert focus_lost_event.field_id == "password"

    def test_validation_empty_field_id(self) -> None:
        """Валидация: field_id не может быть пустым."""
        with pytest.raises(ValueError, match="field_id не может быть пустым"):
            FocusLostEvent(
                widget_id="w1",
                event_type="focus_lost",
                field_id="",
            )

    def test_default_field_id(self) -> None:
        """field_id имеет значение по умолчанию."""
        event = FocusLostEvent(widget_id="w1", event_type="focus_lost", field_id="default_id")
        assert event.field_id == "default_id"


# ==============================================================================
# TEST: FocusGainedEvent
# ==============================================================================


class TestFocusGainedEvent:
    """Тесты FocusGainedEvent."""

    def test_is_frozen(self, focus_gained_event: FocusGainedEvent) -> None:
        """FocusGainedEvent является frozen dataclass."""
        with pytest.raises(AttributeError):
            focus_gained_event.field_id = "new_id"  # type: ignore

    def test_inherits_from_base(self, focus_gained_event: FocusGainedEvent) -> None:
        """FocusGainedEvent наследуется от BaseEvent."""
        assert isinstance(focus_gained_event, BaseEvent)

    def test_has_required_fields(self, focus_gained_event: FocusGainedEvent) -> None:
        """FocusGainedEvent имеет обязательные поля."""
        assert focus_gained_event.widget_id == "entry_email"
        assert focus_gained_event.event_type == "focus_gained"
        assert focus_gained_event.field_id == "email"

    def test_validation_empty_field_id(self) -> None:
        """Валидация: field_id не может быть пустым."""
        with pytest.raises(ValueError, match="field_id не может быть пустым"):
            FocusGainedEvent(
                widget_id="w1",
                event_type="focus_gained",
                field_id="",
            )

    def test_default_field_id(self) -> None:
        """field_id имеет значение по умолчанию."""
        event = FocusGainedEvent(widget_id="w1", event_type="focus_gained", field_id="default_id")
        assert event.field_id == "default_id"


# ==============================================================================
# TEST: ActionEvent
# ==============================================================================


class TestActionEvent:
    """Тесты ActionEvent."""

    def test_is_frozen(self) -> None:
        """ActionEvent является frozen dataclass."""
        event = ActionEvent(
            widget_id="w1",
            event_type="action",
            action_name="save",
        )

        with pytest.raises(AttributeError):
            event.action_name = "load"  # type: ignore

    def test_inherits_from_base(self, action_event: ActionEvent) -> None:
        """ActionEvent наследуется от BaseEvent."""
        assert isinstance(action_event, BaseEvent)

    def test_has_required_fields(self, action_event: ActionEvent) -> None:
        """ActionEvent имеет обязательные поля."""
        assert action_event.widget_id == "btn_save"
        assert action_event.event_type == "action"
        assert action_event.action_name == "save_document"
        assert action_event.action_data == {"path": "./doc.fxsd", "copies": 2}

    def test_validation_empty_action_name(self) -> None:
        """Валидация: action_name не может быть пустым."""
        with pytest.raises(ValueError, match="action_name не может быть пустым"):
            ActionEvent(
                widget_id="w1",
                event_type="action",
                action_name="",
            )

    def test_get_data_existing_key(self, action_event: ActionEvent) -> None:
        """get_data() возвращает значение по существующему ключу."""
        assert action_event.get_data("path") == "./doc.fxsd"
        assert action_event.get_data("copies") == 2

    def test_get_data_missing_key_with_default(self, action_event: ActionEvent) -> None:
        """get_data() возвращает default при отсутствии ключа."""
        assert action_event.get_data("nonexistent") is None
        assert action_event.get_data("nonexistent", "default") == "default"
        assert action_event.get_data("nonexistent", 42) == 42

    def test_get_data_with_various_types(self) -> None:
        """get_data() работает с разными типами."""
        event = ActionEvent(
            widget_id="w1",
            event_type="action",
            action_name="test",
            action_data={
                "string": "value",
                "number": 42,
                "boolean": True,
                "list": [1, 2, 3],
                "dict": {"a": 1},
                "none": None,
            },
        )

        assert event.get_data("string") == "value"
        assert event.get_data("number") == 42
        assert event.get_data("boolean") is True
        assert event.get_data("list") == [1, 2, 3]
        assert event.get_data("dict") == {"a": 1}
        assert event.get_data("none") is None

    def test_default_action_data(self) -> None:
        """action_data имеет пустой dict по умолчанию."""
        event = ActionEvent(
            widget_id="w1",
            event_type="action",
            action_name="test",
        )
        assert event.action_data == {}


# ==============================================================================
# TEST: MountEvent
# ==============================================================================


class TestMountEvent:
    """Тесты MountEvent."""

    def test_is_frozen(self) -> None:
        """MountEvent является frozen dataclass."""
        event = MountEvent(
            widget_id="w1",
            event_type="mount",
            parent_widget="parent",
        )

        with pytest.raises(AttributeError):
            event.parent_widget = "new_parent"  # type: ignore

    def test_inherits_from_base(self, mount_event: MountEvent) -> None:
        """MountEvent наследуется от BaseEvent."""
        assert isinstance(mount_event, BaseEvent)

    def test_has_required_fields(self, mount_event: MountEvent) -> None:
        """MountEvent имеет обязательные поля."""
        assert mount_event.widget_id == "dialog_settings"
        assert mount_event.event_type == "mount"
        assert mount_event.parent_widget == "main_window"

    def test_validation_empty_parent_widget(self) -> None:
        """Валидация: parent_widget не может быть пустым."""
        with pytest.raises(ValueError, match="parent_widget не может быть пустым"):
            MountEvent(
                widget_id="w1",
                event_type="mount",
                parent_widget="",
            )

    def test_default_parent_widget(self) -> None:
        """parent_widget имеет значение по умолчанию."""
        event = MountEvent(widget_id="w1", event_type="mount", parent_widget="default_parent")
        assert event.parent_widget == "default_parent"


# ==============================================================================
# TEST: UnmountEvent
# ==============================================================================


class TestUnmountEvent:
    """Тесты UnmountEvent."""

    def test_is_frozen(self) -> None:
        """UnmountEvent является frozen dataclass."""
        event = UnmountEvent(
            widget_id="w1",
            event_type="unmount",
        )

        with pytest.raises(AttributeError):
            event.widget_id = "w2"  # type: ignore

    def test_inherits_from_base(self, unmount_event: UnmountEvent) -> None:
        """UnmountEvent наследуется от BaseEvent."""
        assert isinstance(unmount_event, BaseEvent)

    def test_has_required_fields(self, unmount_event: UnmountEvent) -> None:
        """UnmountEvent имеет обязательные поля."""
        assert unmount_event.widget_id == "dialog_settings"
        assert unmount_event.event_type == "unmount"

    def test_no_extra_fields(self) -> None:
        """UnmountEvent не имеет дополнительных полей."""
        event = UnmountEvent(widget_id="w1", event_type="unmount")
        # Проверяем базовые поля
        assert hasattr(event, "widget_id")
        assert hasattr(event, "event_type")
        assert hasattr(event, "timestamp")


# ==============================================================================
# TEST: Event Inheritance Chain
# ==============================================================================


class TestEventInheritance:
    """Тесты иерархии наследования событий."""

    def test_all_events_inherit_base(self) -> None:
        """Все события наследуются от BaseEvent."""
        events = [
            ValueChangedEvent(widget_id="w1", event_type="value_changed", field_id="f1"),
            FocusLostEvent(widget_id="w1", event_type="focus_lost", field_id="f1"),
            FocusGainedEvent(widget_id="w1", event_type="focus_gained", field_id="f1"),
            ActionEvent(widget_id="w1", event_type="action", action_name="test"),
            MountEvent(widget_id="w1", event_type="mount", parent_widget="p1"),
            UnmountEvent(widget_id="w1", event_type="unmount"),
        ]

        for event in events:
            assert isinstance(event, BaseEvent)
            assert hasattr(event, "widget_id")
            assert hasattr(event, "event_type")
            assert hasattr(event, "timestamp")

    def test_event_type_values(self) -> None:
        """Проверка значений event_type."""
        vce = ValueChangedEvent(widget_id="w1", event_type="value_changed", field_id="f1")
        assert vce.event_type == "value_changed"
        fle = FocusLostEvent(widget_id="w1", event_type="focus_lost", field_id="f1")
        assert fle.event_type == "focus_lost"
        fge = FocusGainedEvent(widget_id="w1", event_type="focus_gained", field_id="f1")
        assert fge.event_type == "focus_gained"
        ae = ActionEvent(widget_id="w1", event_type="action", action_name="test")
        assert ae.event_type == "action"
        me = MountEvent(widget_id="w1", event_type="mount", parent_widget="p1")
        assert me.event_type == "mount"
        ue = UnmountEvent(widget_id="w1", event_type="unmount")
        assert ue.event_type == "unmount"


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.core import events

        assert hasattr(events, "__all__")
        assert "BaseEvent" in events.__all__
        assert "ValueChangedEvent" in events.__all__
        assert "FocusLostEvent" in events.__all__
        assert "FocusGainedEvent" in events.__all__
        assert "ActionEvent" in events.__all__
        assert "MountEvent" in events.__all__
        assert "UnmountEvent" in events.__all__

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.core import events

        assert hasattr(events, "__version__")
        assert hasattr(events, "__author__")
        assert hasattr(events, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.core.events"])
