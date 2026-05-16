"""Unit-тесты для иерархии исключений GUI.

Проверяет:
- Иерархию наследования (GUIError -> специфичные)
- Форматирование сообщений об ошибках
- Атрибуты исключений (widget_type, widget_id и т.д.)
- Корректность конструкторов

Coverage target: ≥95%
"""

import pytest
from src.gui.core.exceptions import (
    EventHandlingError,
    GUIError,
    LifecycleError,
    ProtocolValidationError,
    WidgetCreationError,
    WidgetNotFoundError,
    WidgetRegistryError,
)

# ==============================================================================
# TEST: GUIError (Base Exception)
# ==============================================================================


class TestGUIError:
    """Тесты базового исключения GUIError."""

    def test_is_base_exception(self) -> None:
        """GUIError является базовым для всех GUI исключений."""
        assert issubclass(WidgetRegistryError, GUIError)
        assert issubclass(ProtocolValidationError, GUIError)
        assert issubclass(LifecycleError, GUIError)
        assert issubclass(EventHandlingError, GUIError)

    def test_with_message(self) -> None:
        """GUIError с сообщением."""
        error = GUIError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"

    def test_without_message(self) -> None:
        """GUIError без сообщения."""
        error = GUIError()
        assert str(error) == "GUIError"
        assert error.message is None

    def test_empty_message(self) -> None:
        """GUIError с пустым сообщением."""
        error = GUIError("")
        assert str(error) == "GUIError"

    def test_str_method(self) -> None:
        """__str__ возвращает корректное значение."""
        error = GUIError("Custom message")
        assert str(error) == "Custom message"

    def test_repr_method(self) -> None:
        """__repr__ содержит имя класса."""
        error = GUIError("Test")
        assert "GUIError" in repr(error)


# ==============================================================================
# TEST: WidgetRegistryError
# ==============================================================================


class TestWidgetRegistryError:
    """Тесты WidgetRegistryError."""

    def test_inherits_from_gui_error(self) -> None:
        """WidgetRegistryError наследуется от GUIError."""
        error = WidgetRegistryError("Test")
        assert isinstance(error, GUIError)

    def test_with_message(self) -> None:
        """WidgetRegistryError с сообщением."""
        error = WidgetRegistryError("Registry error")
        assert str(error) == "Registry error"

    def test_without_message(self) -> None:
        """WidgetRegistryError без сообщения."""
        error = WidgetRegistryError()
        assert str(error) == "WidgetRegistryError"


# ==============================================================================
# TEST: WidgetNotFoundError
# ==============================================================================


class TestWidgetNotFoundError:
    """Тесты WidgetNotFoundError."""

    def test_inherits_from_widget_registry_error(self) -> None:
        """WidgetNotFoundError наследуется от WidgetRegistryError."""
        error = WidgetNotFoundError(widget_type="button")
        assert isinstance(error, WidgetRegistryError)
        assert isinstance(error, GUIError)

    def test_with_widget_type_and_id(self) -> None:
        """WidgetNotFoundError с widget_type и widget_id."""
        error = WidgetNotFoundError(widget_type="button", widget_id="submit_btn")
        assert error.widget_type == "button"
        assert error.widget_id == "submit_btn"
        assert "submit_btn" in str(error)
        assert "button" in str(error)
        assert "not found" in str(error)

    def test_with_widget_type_only(self) -> None:
        """WidgetNotFoundError только с widget_type."""
        error = WidgetNotFoundError(widget_type="label")
        assert error.widget_type == "label"
        assert error.widget_id is None
        assert "label" in str(error)
        assert "not found" in str(error)

    def test_with_widget_id_only(self) -> None:
        """WidgetNotFoundError только с widget_id."""
        error = WidgetNotFoundError(widget_id="my_widget")
        assert error.widget_type is None
        assert error.widget_id == "my_widget"
        assert "my_widget" in str(error)
        assert "not found" in str(error)

    def test_without_any_params(self) -> None:
        """WidgetNotFoundError без параметров."""
        error = WidgetNotFoundError()
        assert error.widget_type is None
        assert error.widget_id is None
        assert str(error) == "Widget not found in registry"

    def test_with_custom_message(self) -> None:
        """WidgetNotFoundError с кастомным сообщением."""
        error = WidgetNotFoundError(
            widget_type="button",
            widget_id="btn_1",
            message="Custom error message",
        )
        assert str(error) == "Custom error message"
        assert error.widget_type == "button"
        assert error.widget_id == "btn_1"

    def test_message_formatting(self) -> None:
        """Проверка форматирования сообщения."""
        # Полное сообщение
        error = WidgetNotFoundError(widget_type="input", widget_id="username")
        assert "Widget 'username' of type 'input' not found in registry" == str(error)

        # Только тип
        error = WidgetNotFoundError(widget_type="label")
        assert "Widget of type 'label' not found in registry" == str(error)

        # Только id
        error = WidgetNotFoundError(widget_id="my_id")
        assert "Widget 'my_id' not found in registry" == str(error)


# ==============================================================================
# TEST: WidgetCreationError
# ==============================================================================


class TestWidgetCreationError:
    """Тесты WidgetCreationError."""

    def test_inherits_from_widget_registry_error(self) -> None:
        """WidgetCreationError наследуется от WidgetRegistryError."""
        error = WidgetCreationError(widget_type="editor")
        assert isinstance(error, WidgetRegistryError)

    def test_with_all_params(self) -> None:
        """WidgetCreationError со всеми параметрами."""
        cause = ValueError("Original error")
        error = WidgetCreationError(
            widget_type="text_editor",
            factory_name="create_editor",
            message="Failed to create",
            cause=cause,
        )
        assert error.widget_type == "text_editor"
        assert error.factory_name == "create_editor"
        assert error.cause is cause
        assert str(error) == "Failed to create"

    def test_with_widget_type_and_factory(self) -> None:
        """WidgetCreationError с widget_type и factory_name."""
        error = WidgetCreationError(widget_type="button_primary", factory_name="ButtonFactory")
        assert error.widget_type == "button_primary"
        assert error.factory_name == "ButtonFactory"
        assert "button_primary" in str(error)
        assert "ButtonFactory" in str(error)
        assert "Failed to create widget" in str(error)

    def test_with_widget_type_only(self) -> None:
        """WidgetCreationError только с widget_type."""
        error = WidgetCreationError(widget_type="label")
        assert error.widget_type == "label"
        assert error.factory_name is None
        assert "label" in str(error)

    def test_without_any_params(self) -> None:
        """WidgetCreationError без параметров."""
        error = WidgetCreationError()
        assert error.widget_type is None
        assert error.factory_name is None
        assert str(error) == "Failed to create widget"

    def test_message_formatting(self) -> None:
        """Проверка форматирования сообщения."""
        # Полное сообщение
        error = WidgetCreationError(widget_type="editor", factory_name="Factory")
        assert "Failed to create widget 'editor' in factory 'Factory'" == str(error)

        # Только тип
        error = WidgetCreationError(widget_type="label")
        assert "Failed to create widget 'label'" == str(error)

        # Ничего
        error = WidgetCreationError()
        assert "Failed to create widget" == str(error)


# ==============================================================================
# TEST: ProtocolValidationError
# ==============================================================================


class TestProtocolValidationError:
    """Тесты ProtocolValidationError."""

    def test_inherits_from_gui_error(self) -> None:
        """ProtocolValidationError наследуется от GUIError."""
        error = ProtocolValidationError()
        assert isinstance(error, GUIError)

    def test_with_all_params(self) -> None:
        """ProtocolValidationError со всеми параметрами."""
        error = ProtocolValidationError(
            protocol_name="WidgetProtocol",
            implementation="MyWidget",
            message="Custom validation message",
        )
        assert error.protocol_name == "WidgetProtocol"
        assert error.implementation == "MyWidget"
        assert str(error) == "Custom validation message"

    def test_with_protocol_and_implementation(self) -> None:
        """ProtocolValidationError с protocol_name и implementation."""
        error = ProtocolValidationError(protocol_name="WidgetProtocol", implementation="MyWidget")
        assert error.protocol_name == "WidgetProtocol"
        assert error.implementation == "MyWidget"
        assert "MyWidget" in str(error)
        assert "WidgetProtocol" in str(error)
        assert "does not implement" in str(error)

    def test_with_implementation_only(self) -> None:
        """ProtocolValidationError только с implementation."""
        error = ProtocolValidationError(implementation="TestClass")
        assert error.protocol_name is None
        assert error.implementation == "TestClass"
        assert "TestClass" in str(error)

    def test_without_any_params(self) -> None:
        """ProtocolValidationError без параметров."""
        error = ProtocolValidationError()
        assert error.protocol_name is None
        assert error.implementation is None
        assert str(error) == "does not conform to Protocol interface"

    def test_message_formatting(self) -> None:
        """Проверка форматирования сообщения."""
        # Полное сообщение
        error = ProtocolValidationError(protocol_name="WidgetProtocol", implementation="MyClass")
        assert "'MyClass' does not implement Protocol 'WidgetProtocol'" == str(error)

        # Только implementation
        error = ProtocolValidationError(implementation="TestClass")
        assert "'TestClass' does not conform to Protocol interface" == str(error)


# ==============================================================================
# TEST: LifecycleError
# ==============================================================================


class TestLifecycleError:
    """Тесты LifecycleError."""

    def test_inherits_from_gui_error(self) -> None:
        """LifecycleError наследуется от GUIError."""
        error = LifecycleError()
        assert isinstance(error, GUIError)

    def test_with_all_params(self) -> None:
        """LifecycleError со всеми параметрами."""
        error = LifecycleError(
            widget_id="doc_view",
            operation="mount",
            message="Custom lifecycle error",
        )
        assert error.widget_id == "doc_view"
        assert error.operation == "mount"
        assert str(error) == "Custom lifecycle error"

    def test_with_widget_id_and_operation(self) -> None:
        """LifecycleError с widget_id и operation."""
        error = LifecycleError(widget_id="my_widget", operation="unmount")
        assert error.widget_id == "my_widget"
        assert error.operation == "unmount"
        assert "my_widget" in str(error)
        assert "unmount" in str(error)

    def test_with_widget_id_only(self) -> None:
        """LifecycleError только с widget_id."""
        error = LifecycleError(widget_id="test_widget")
        assert error.widget_id == "test_widget"
        assert error.operation is None
        assert "test_widget" in str(error)

    def test_with_operation_only(self) -> None:
        """LifecycleError только с operation."""
        error = LifecycleError(operation="mount")
        assert error.widget_id is None
        assert error.operation == "mount"
        assert "mount" in str(error)

    def test_without_any_params(self) -> None:
        """LifecycleError без параметров."""
        error = LifecycleError()
        assert error.widget_id is None
        assert error.operation is None
        assert str(error) == "Widget lifecycle error"

    def test_message_formatting(self) -> None:
        """Проверка форматирования сообщения."""
        # Полное сообщение
        error = LifecycleError(widget_id="view_1", operation="mount")
        assert "Error during mount for widget 'view_1'" == str(error)

        # Только operation
        error = LifecycleError(operation="unmount")
        assert "Error during operation unmount" == str(error)

        # Только widget_id
        error = LifecycleError(widget_id="widget_1")
        assert "Widget lifecycle error for 'widget_1'" == str(error)


# ==============================================================================
# TEST: EventHandlingError
# ==============================================================================


class TestEventHandlingError:
    """Тесты EventHandlingError."""

    def test_inherits_from_gui_error(self) -> None:
        """EventHandlingError наследуется от GUIError."""
        error = EventHandlingError()
        assert isinstance(error, GUIError)

    def test_with_all_params(self) -> None:
        """EventHandlingError со всеми параметрами."""
        cause = RuntimeError("Original error")
        error = EventHandlingError(
            event_type="click",
            widget_id="btn_submit",
            handler_name="on_click",
            message="Custom event error",
            cause=cause,
        )
        assert error.event_type == "click"
        assert error.widget_id == "btn_submit"
        assert error.handler_name == "on_click"
        assert error.cause is cause
        assert str(error) == "Custom event error"

    def test_with_event_type_widget_id_handler(self) -> None:
        """EventHandlingError с event_type, widget_id, handler_name."""
        error = EventHandlingError(
            event_type="click", widget_id="btn_1", handler_name="handle_click"
        )
        assert error.event_type == "click"
        assert error.widget_id == "btn_1"
        assert error.handler_name == "handle_click"
        assert "click" in str(error)
        assert "handle_click" in str(error)
        assert "btn_1" in str(error)

    def test_with_event_type_only(self) -> None:
        """EventHandlingError только с event_type."""
        error = EventHandlingError(event_type="focus")
        assert error.event_type == "focus"
        assert error.widget_id is None
        assert error.handler_name is None
        assert "focus" in str(error)

    def test_without_any_params(self) -> None:
        """EventHandlingError без параметров."""
        error = EventHandlingError()
        assert error.event_type is None
        assert error.widget_id is None
        assert error.handler_name is None
        assert str(error) == "Error handling event"

    def test_message_formatting(self) -> None:
        """Проверка форматирования сообщения."""
        # Полное сообщение
        error = EventHandlingError(event_type="click", widget_id="btn_1", handler_name="on_click")
        assert (
            "Error handling event 'click' in handler 'on_click' "
            "for widget 'btn_1'" == str(error)
        )

        # Только event_type и handler_name
        error = EventHandlingError(event_type="change", handler_name="on_change")
        assert "Error handling event 'change' in handler 'on_change'" == str(error)

        # Только event_type
        error = EventHandlingError(event_type="focus")
        assert "Error handling event 'focus'" == str(error)


# ==============================================================================
# TEST: Exception Hierarchy
# ==============================================================================


class TestExceptionHierarchy:
    """Тесты иерархии исключений."""

    def test_full_hierarchy(self) -> None:
        """Проверка полной иерархии наследования."""
        # Base -> Registry -> NotFound
        assert issubclass(WidgetNotFoundError, WidgetRegistryError)
        assert issubclass(WidgetNotFoundError, GUIError)

        # Base -> Registry -> Creation
        assert issubclass(WidgetCreationError, WidgetRegistryError)
        assert issubclass(WidgetCreationError, GUIError)

        # Base -> Protocol
        assert issubclass(ProtocolValidationError, GUIError)

        # Base -> Lifecycle
        assert issubclass(LifecycleError, GUIError)

        # Base -> Event
        assert issubclass(EventHandlingError, GUIError)

    def test_catch_as_base(self) -> None:
        """Все исключения можно поймать как GUIError."""
        exceptions = [
            WidgetNotFoundError("button"),
            WidgetCreationError("editor"),
            ProtocolValidationError("Protocol", "Impl"),
            LifecycleError("w1", "mount"),
            EventHandlingError("click", "btn"),
        ]

        for exc in exceptions:
            try:
                raise exc
            except GUIError as e:
                assert e is exc

    def test_catch_as_registry_error(self) -> None:
        """Registry исключения можно поймать как WidgetRegistryError."""
        registry_exceptions = [
            WidgetNotFoundError("button"),
            WidgetCreationError("editor"),
        ]

        for exc in registry_exceptions:
            try:
                raise exc
            except WidgetRegistryError as e:
                assert e is exc


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.core import exceptions

        assert hasattr(exceptions, "__all__")
        assert "GUIError" in exceptions.__all__
        assert "WidgetRegistryError" in exceptions.__all__
        assert "WidgetNotFoundError" in exceptions.__all__
        assert "WidgetCreationError" in exceptions.__all__
        assert "ProtocolValidationError" in exceptions.__all__
        assert "LifecycleError" in exceptions.__all__
        assert "EventHandlingError" in exceptions.__all__

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.core import exceptions

        assert hasattr(exceptions, "__version__")
        assert hasattr(exceptions, "__author__")
        assert hasattr(exceptions, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.core.exceptions"])
