"""Unit-тесты для Protocol интерфейсов GUI.

Проверяет:
- EventProtocol runtime_checkable
- WidgetProtocol структурное подтипирование
- SmartWidgetProtocol наследование
- ControllerProtocol методы
- isinstance() проверки с runtime_checkable

Coverage target: ≥95%
"""

import tkinter as tk
from typing import Any, Callable, Optional
from unittest.mock import MagicMock

import pytest
from src.gui.core.protocols import (
    ControllerProtocol,
    DocumentControllerProtocol,
    EventProtocol,
    FormFieldProtocol,
    SmartWidgetProtocol,
    WidgetProtocol,
)

# ==============================================================================
# MOCK CLASSES (реализуют Protocol для тестов)
# ==============================================================================


class MockEvent:
    """Mock события, реализующий EventProtocol."""

    def __init__(self, widget_id: str, event_type: str) -> None:
        self.widget_id = widget_id
        self.event_type = event_type
        self.timestamp: float = 1234567890.0
        self.source_widget_id: str = widget_id
        self._propagation_stopped: bool = False

    def get_data(self) -> dict[str, Any]:
        return {"widget_id": self.widget_id, "event_type": self.event_type}

    def is_propagation_stopped(self) -> bool:
        return self._propagation_stopped

    def stop_propagation(self) -> None:
        self._propagation_stopped = True


class MockWidget:
    """Mock виджета, реализующий WidgetProtocol."""

    def __init__(self, widget_id: str) -> None:
        self.widget_id: str = widget_id
        self._mounted: bool = False
        self._tk_widget: Optional[tk.Widget] = None

    def mount(self, parent: Any) -> Any:
        self._mounted = True
        self._tk_widget = MagicMock()
        return self._tk_widget

    def unmount(self) -> None:
        self._mounted = False
        self._tk_widget = None

    def handle_event(self, event: EventProtocol) -> bool:
        return True

    def is_mounted(self) -> bool:
        return self._mounted


class MockSmartWidget(MockWidget):
    """Mock smart виджета, реализующий SmartWidgetProtocol."""

    def __init__(self, widget_id: str) -> None:
        super().__init__(widget_id)
        self.is_editing: bool = False
        self._edit_value: str = ""
        self._initial_value: str = ""

    def enter_edit_mode(self) -> None:
        self.is_editing = True
        self._initial_value = self._edit_value

    def exit_edit_mode(self) -> None:
        self.is_editing = False
        if self.has_changes():
            self.sync_to_model()

    def sync_to_model(self) -> bool:
        return self.has_changes()

    def get_edit_value(self) -> str:
        return self._edit_value

    def set_edit_value(self, value: str) -> None:
        self._edit_value = value

    def has_changes(self) -> bool:
        return self._edit_value != self._initial_value


class MockController:
    """Mock контроллера, реализующий ControllerProtocol."""

    def __init__(self, controller_id: str = "test_controller") -> None:
        self.controller_id: str = controller_id
        self._views: dict[str, Callable[..., None]] = {}
        self._dispatched: list[tuple[str, dict[str, Any]]] = []

    def dispatch(self, action: str, **kwargs: Any) -> Optional[Any]:
        self._dispatched.append((action, kwargs))
        return None

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        if widget_id in self._views:
            self._views[widget_id](data)

    def register_view(self, widget_id: str, callback: Callable[..., None]) -> None:
        self._views[widget_id] = callback

    def unregister_view(self, widget_id: str) -> None:
        if widget_id in self._views:
            del self._views[widget_id]


class MockDocumentController(MockController):
    """Mock документ-контроллера, реализующий DocumentControllerProtocol."""

    def __init__(self, controller_id: str = "doc_controller") -> None:
        super().__init__(controller_id)
        self._text: str = ""
        self._fields: dict[str, str] = {}

    def on_text_changed(self, text: str) -> None:
        self._text = text

    def on_field_changed(self, field_id: str, value: str) -> None:
        self._fields[field_id] = value

    def on_save(self) -> bool:
        return True

    def on_print(self) -> bool:
        return True

    def on_undo(self) -> bool:
        return False

    def on_redo(self) -> bool:
        return False


class InvalidWidget:
    """Невалидный виджет, НЕ реализующий WidgetProtocol."""

    # Нет widget_id, mount, unmount и т.д.
    pass


class PartialWidget:
    """Частично реализованный виджет (для негативных тестов)."""

    def __init__(self) -> None:
        self.widget_id: str = "partial"

    # Нет метода mount(), unmount(), handle_event(), is_mounted()


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def mock_event() -> MockEvent:
    """Fixture для mock события."""
    return MockEvent(widget_id="test_widget", event_type="test_event")


@pytest.fixture
def mock_widget() -> MockWidget:
    """Fixture для mock виджета."""
    return MockWidget(widget_id="test_widget")


@pytest.fixture
def mock_smart_widget() -> MockSmartWidget:
    """Fixture для mock smart виджета."""
    return MockSmartWidget(widget_id="smart_widget")


@pytest.fixture
def mock_controller() -> MockController:
    """Fixture для mock контроллера."""
    return MockController(controller_id="test_controller")


@pytest.fixture
def mock_doc_controller() -> MockDocumentController:
    """Fixture для mock документ-контроллера."""
    return MockDocumentController(controller_id="doc_controller")


# ==============================================================================
# TEST: EventProtocol
# ==============================================================================


class TestEventProtocol:
    """Тесты EventProtocol."""

    def test_is_runtime_checkable(self) -> None:
        """EventProtocol помечен @runtime_checkable."""
        # Проверяем что можно использовать isinstance

        event = MockEvent(widget_id="test", event_type="click")
        assert isinstance(event, EventProtocol)

    def test_has_required_attributes(self, mock_event: MockEvent) -> None:
        """EventProtocol требует timestamp, source_widget_id, event_type."""
        assert hasattr(mock_event, "timestamp")
        assert hasattr(mock_event, "source_widget_id")
        assert hasattr(mock_event, "event_type")

    def test_required_methods(self, mock_event: MockEvent) -> None:
        """EventProtocol требует get_data, is_propagation_stopped, stop_propagation."""
        assert callable(getattr(mock_event, "get_data", None))
        assert callable(getattr(mock_event, "is_propagation_stopped", None))
        assert callable(getattr(mock_event, "stop_propagation", None))

    def test_get_data_returns_dict(self, mock_event: MockEvent) -> None:
        """get_data() возвращает словарь."""
        data = mock_event.get_data()
        assert isinstance(data, dict)
        assert "widget_id" in data

    def test_stop_propagation_works(self, mock_event: MockEvent) -> None:
        """stop_propagation() останавливает распространение."""
        assert not mock_event.is_propagation_stopped()
        mock_event.stop_propagation()
        assert mock_event.is_propagation_stopped()

    def test_isinstance_with_valid_event(self) -> None:
        """isinstance работает с валидным событием."""
        event = MockEvent(widget_id="w1", event_type="e1")
        assert isinstance(event, EventProtocol)

    def test_isinstance_with_invalid_event(self) -> None:
        """isinstance возвращает False для невалидного события."""
        invalid_event = {"timestamp": 123, "source_widget_id": "w1"}
        assert not isinstance(invalid_event, EventProtocol)


# ==============================================================================
# TEST: WidgetProtocol
# ==============================================================================


class TestWidgetProtocol:
    """Тесты WidgetProtocol."""

    def test_is_runtime_checkable(self) -> None:
        """WidgetProtocol помечен @runtime_checkable."""
        widget = MockWidget(widget_id="test")
        assert isinstance(widget, WidgetProtocol)

    def test_requires_widget_id_attribute(self, mock_widget: MockWidget) -> None:
        """WidgetProtocol требует widget_id."""
        assert hasattr(mock_widget, "widget_id")
        assert isinstance(mock_widget.widget_id, str)

    def test_requires_mount_method(self, mock_widget: MockWidget) -> None:
        """WidgetProtocol требует mount()."""
        assert callable(getattr(mock_widget, "mount", None))

    def test_requires_unmount_method(self, mock_widget: MockWidget) -> None:
        """WidgetProtocol требует unmount()."""
        assert callable(getattr(mock_widget, "unmount", None))

    def test_requires_handle_event_method(self, mock_widget: MockWidget) -> None:
        """WidgetProtocol требует handle_event()."""
        assert callable(getattr(mock_widget, "handle_event", None))

    def test_requires_is_mounted_method(self, mock_widget: MockWidget) -> None:
        """WidgetProtocol требует is_mounted()."""
        assert callable(getattr(mock_widget, "is_mounted", None))

    def test_isinstance_with_valid_widget(self, mock_widget: MockWidget) -> None:
        """isinstance работает с валидным виджетом."""
        assert isinstance(mock_widget, WidgetProtocol)

    def test_isinstance_with_invalid_widget(self) -> None:
        """isinstance возвращает False для невалидного виджета."""
        invalid = InvalidWidget()
        assert not isinstance(invalid, WidgetProtocol)

    def test_isinstance_with_partial_widget(self) -> None:
        """isinstance возвращает False для частично реализованного виджета."""
        partial = PartialWidget()
        assert not isinstance(partial, WidgetProtocol)


# ==============================================================================
# TEST: SmartWidgetProtocol
# ==============================================================================


class TestSmartWidgetProtocol:
    """Тесты SmartWidgetProtocol."""

    def test_is_runtime_checkable(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol помечен @runtime_checkable."""
        assert isinstance(mock_smart_widget, SmartWidgetProtocol)

    def test_inherits_from_widget_protocol(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol наследуется от WidgetProtocol."""
        # Smart виджет также должен удовлетворять WidgetProtocol
        assert isinstance(mock_smart_widget, WidgetProtocol)

    def test_requires_is_editing_attribute(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol требует is_editing."""
        assert hasattr(mock_smart_widget, "is_editing")
        assert isinstance(mock_smart_widget.is_editing, bool)

    def test_requires_enter_edit_mode_method(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol требует enter_edit_mode()."""
        assert callable(getattr(mock_smart_widget, "enter_edit_mode", None))

    def test_requires_exit_edit_mode_method(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol требует exit_edit_mode()."""
        assert callable(getattr(mock_smart_widget, "exit_edit_mode", None))

    def test_requires_sync_to_model_method(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol требует sync_to_model()."""
        assert callable(getattr(mock_smart_widget, "sync_to_model", None))

    def test_requires_get_edit_value_method(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol требует get_edit_value()."""
        assert callable(getattr(mock_smart_widget, "get_edit_value", None))

    def test_requires_set_edit_value_method(self, mock_smart_widget: MockSmartWidget) -> None:
        """SmartWidgetProtocol требует set_edit_value()."""
        assert callable(getattr(mock_smart_widget, "set_edit_value", None))

    def test_smart_widget_lifecycle(self, mock_smart_widget: MockSmartWidget) -> None:
        """Smart виджет поддерживает режим редактирования."""
        # Начальное состояние
        assert not mock_smart_widget.is_editing

        # Вход в режим редактирования
        mock_smart_widget.enter_edit_mode()
        assert mock_smart_widget.is_editing

        # Выход из режима редактирования
        mock_smart_widget.exit_edit_mode()
        assert not mock_smart_widget.is_editing


# ==============================================================================
# TEST: ControllerProtocol
# ==============================================================================


class TestControllerProtocol:
    """Тесты ControllerProtocol."""

    def test_is_runtime_checkable(self, mock_controller: MockController) -> None:
        """ControllerProtocol помечен @runtime_checkable."""
        assert isinstance(mock_controller, ControllerProtocol)

    def test_requires_controller_id_attribute(self, mock_controller: MockController) -> None:
        """ControllerProtocol требует controller_id."""
        assert hasattr(mock_controller, "controller_id")
        assert isinstance(mock_controller.controller_id, str)

    def test_requires_dispatch_method(self, mock_controller: MockController) -> None:
        """ControllerProtocol требует dispatch()."""
        assert callable(getattr(mock_controller, "dispatch", None))

    def test_requires_notify_view_update_method(self, mock_controller: MockController) -> None:
        """ControllerProtocol требует notify_view_update()."""
        assert callable(getattr(mock_controller, "notify_view_update", None))

    def test_requires_register_view_method(self, mock_controller: MockController) -> None:
        """ControllerProtocol требует register_view()."""
        assert callable(getattr(mock_controller, "register_view", None))

    def test_requires_unregister_view_method(self, mock_controller: MockController) -> None:
        """ControllerProtocol требует unregister_view()."""
        assert callable(getattr(mock_controller, "unregister_view", None))

    def test_dispatch_method_works(self, mock_controller: MockController) -> None:
        """dispatch() корректно вызывается."""
        mock_controller.dispatch("test_action", value=123)
        assert len(mock_controller._dispatched) == 1
        assert mock_controller._dispatched[0] == ("test_action", {"value": 123})

    def test_view_registration(self, mock_controller: MockController) -> None:
        """register_view/unregister_view работают."""
        callback = MagicMock()

        # Регистрация
        mock_controller.register_view("widget_1", callback)
        assert "widget_1" in mock_controller._views

        # Уведомление
        mock_controller.notify_view_update("widget_1", {"data": "test"})
        callback.assert_called_once_with({"data": "test"})

        # Отмена регистрации
        mock_controller.unregister_view("widget_1")
        assert "widget_1" not in mock_controller._views


# ==============================================================================
# TEST: DocumentControllerProtocol
# ==============================================================================


class TestDocumentControllerProtocol:
    """Тесты DocumentControllerProtocol."""

    def test_is_runtime_checkable(self, mock_doc_controller: MockDocumentController) -> None:
        """DocumentControllerProtocol помечен @runtime_checkable."""
        assert isinstance(mock_doc_controller, DocumentControllerProtocol)

    def test_inherits_from_controller_protocol(
        self, mock_doc_controller: MockDocumentController
    ) -> None:
        """DocumentControllerProtocol наследуется от ControllerProtocol."""
        assert isinstance(mock_doc_controller, ControllerProtocol)

    def test_requires_on_text_changed_method(
        self, mock_doc_controller: MockDocumentController
    ) -> None:
        """DocumentControllerProtocol требует on_text_changed()."""
        assert callable(getattr(mock_doc_controller, "on_text_changed", None))

    def test_requires_on_field_changed_method(
        self, mock_doc_controller: MockDocumentController
    ) -> None:
        """DocumentControllerProtocol требует on_field_changed()."""
        assert callable(getattr(mock_doc_controller, "on_field_changed", None))

    def test_requires_on_save_method(self, mock_doc_controller: MockDocumentController) -> None:
        """DocumentControllerProtocol требует on_save()."""
        assert callable(getattr(mock_doc_controller, "on_save", None))

    def test_requires_on_print_method(self, mock_doc_controller: MockDocumentController) -> None:
        """DocumentControllerProtocol требует on_print()."""
        assert callable(getattr(mock_doc_controller, "on_print", None))

    def test_requires_on_undo_method(self, mock_doc_controller: MockDocumentController) -> None:
        """DocumentControllerProtocol требует on_undo()."""
        assert callable(getattr(mock_doc_controller, "on_undo", None))

    def test_requires_on_redo_method(self, mock_doc_controller: MockDocumentController) -> None:
        """DocumentControllerProtocol требует on_redo()."""
        assert callable(getattr(mock_doc_controller, "on_redo", None))

    def test_on_text_changed_works(self, mock_doc_controller: MockDocumentController) -> None:
        """on_text_changed() корректно обрабатывает изменения текста."""
        mock_doc_controller.on_text_changed("Hello World")
        assert mock_doc_controller._text == "Hello World"

    def test_on_field_changed_works(self, mock_doc_controller: MockDocumentController) -> None:
        """on_field_changed() корректно обрабатывает изменения полей."""
        mock_doc_controller.on_field_changed("username", "admin")
        assert mock_doc_controller._fields["username"] == "admin"

    def test_on_save_returns_bool(self, mock_doc_controller: MockDocumentController) -> None:
        """on_save() возвращает boolean."""
        result = mock_doc_controller.on_save()
        assert isinstance(result, bool)

    def test_on_print_returns_bool(self, mock_doc_controller: MockDocumentController) -> None:
        """on_print() возвращает boolean."""
        result = mock_doc_controller.on_print()
        assert isinstance(result, bool)


# ==============================================================================
# TEST: Protocol Combinations
# ==============================================================================


class TestProtocolCombinations:
    """Тесты комбинаций Protocol."""

    def test_smart_widget_is_both_protocols(self, mock_smart_widget: MockSmartWidget) -> None:
        """Smart виджет удовлетворяет обоим Protocol."""
        assert isinstance(mock_smart_widget, WidgetProtocol)
        assert isinstance(mock_smart_widget, SmartWidgetProtocol)

    def test_doc_controller_is_both_protocols(
        self, mock_doc_controller: MockDocumentController
    ) -> None:
        """Документ-контроллер удовлетворяет обоим Protocol."""
        assert isinstance(mock_doc_controller, ControllerProtocol)
        assert isinstance(mock_doc_controller, DocumentControllerProtocol)

    def test_event_with_widget(self, mock_event: MockEvent, mock_widget: MockWidget) -> None:
        """Виджет может обрабатывать событие."""
        assert isinstance(mock_event, EventProtocol)
        assert isinstance(mock_widget, WidgetProtocol)

        # Виджет обрабатывает событие
        result = mock_widget.handle_event(mock_event)
        assert isinstance(result, bool)


# ==============================================================================
# MOCK: FormField
# ==============================================================================


class MockFormField:
    """Mock FormField, реализующий FormFieldProtocol."""

    def __init__(self) -> None:
        self._value: Any = None
        self._error: Optional[str] = None

    def set_value(self, value: Any) -> None:
        self._value = value

    def get_value(self) -> Any:
        return self._value

    def validate(self) -> tuple[bool, Optional[str]]:
        if self._value is None or self._value == "":
            return False, "Поле обязательно"
        return True, None

    def set_error(self, message: Optional[str]) -> None:
        self._error = message

    def clear_error(self) -> None:
        self._error = None

    def wipe_sensitive_data(self) -> None:
        self._value = None
        self._error = None

    def pack(self, **kwargs: Any) -> None:
        pass


# ==============================================================================
# TEST: FormFieldProtocol
# ==============================================================================


class TestFormFieldProtocol:
    """Тесты FormFieldProtocol."""

    def test_mock_formfield_isinstance(self) -> None:
        """Mock FormField удовлетворяет FormFieldProtocol."""
        field = MockFormField()
        assert isinstance(field, FormFieldProtocol)

    def test_formfield_protocol_methods(self) -> None:
        """Проверяет что все методы протокола доступны."""
        field = MockFormField()
        field.set_value("test")
        assert field.get_value() == "test"
        is_valid, error = field.validate()
        assert isinstance(is_valid, bool)
        field.set_error("ошибка")
        field.clear_error()
        field.wipe_sensitive_data()

    def test_real_formfield_isinstance(self) -> None:
        """Реальный FormField удовлетворяет FormFieldProtocol."""
        import tkinter as tk
        from src.documents.types.type_schema import FieldDefinition, FieldType
        from src.gui.components.form_field import FormField

        root = tk.Tk()
        root.withdraw()
        try:
            field_def = FieldDefinition(
                field_id="protocol_test",
                field_type=FieldType.TEXT_INPUT,
                label="Тест",
                required=False,
            )
            field = FormField(parent=root, field_def=field_def, document_index="DVN-00-TEST-I")
            assert isinstance(field, FormFieldProtocol)
        finally:
            root.destroy()


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.core import protocols

        assert hasattr(protocols, "__all__")
        assert "EventProtocol" in protocols.__all__
        assert "WidgetProtocol" in protocols.__all__
        assert "SmartWidgetProtocol" in protocols.__all__
        assert "ControllerProtocol" in protocols.__all__
        assert "DocumentControllerProtocol" in protocols.__all__
        assert "FormFieldProtocol" in protocols.__all__

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.core import protocols

        assert hasattr(protocols, "__version__")
        assert hasattr(protocols, "__author__")
        assert hasattr(protocols, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.core.protocols"])
