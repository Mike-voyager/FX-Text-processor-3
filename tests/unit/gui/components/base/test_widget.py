"""Unit-тесты для базовых виджетов GUI.

Проверяет:
- BaseWidget инициализацию и lifecycle
- SmartBaseWidget режим редактирования
- Mount/Unmount события
- Ошибки lifecycle (double mount/unmount)
- Mock tk.Widget для изолированных тестов

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Any, Generator
from unittest.mock import MagicMock

import pytest
from src.gui.components.base.widget import BaseWidget, SmartBaseWidget
from src.gui.core.events import MountEvent, UnmountEvent
from src.gui.core.exceptions import LifecycleError

# ==============================================================================
# MOCK IMPLEMENTATIONS
# ==============================================================================


class MockTkWidget:
    """Mock Tkinter виджета для тестов."""

    def __init__(self) -> None:
        self.destroyed = False
        self.bindings: dict[str, Any] = {}

    def destroy(self) -> None:
        self.destroyed = True

    def bind(self, event: str, callback: Any) -> None:
        self.bindings[event] = callback

    def unbind(self, event: str) -> None:
        if event in self.bindings:
            del self.bindings[event]


class ConcreteWidget(BaseWidget):
    """Конкретная реализация BaseWidget для тестов."""

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт mock Tkinter виджет."""
        return MagicMock(spec=tk.Widget)


class ConcreteSmartWidget(SmartBaseWidget):
    """Конкретная реализация SmartBaseWidget для тестов."""

    def __init__(
        self,
        widget_id: str,
        controller: Any = None,
    ) -> None:
        super().__init__(widget_id=widget_id, controller=controller)
        self._edit_buffer: str = ""
        self._synced = False

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт mock Tkinter виджет."""
        mock_widget = MagicMock(spec=tk.Widget)
        # Симулируем Text widget
        mock_widget.get = MagicMock(return_value="initial text")
        mock_widget.delete = MagicMock()
        mock_widget.insert = MagicMock()
        return mock_widget

    def sync_to_model(self) -> bool:
        """Синхронизирует с моделью."""
        self._synced = True
        return self.has_changes()

    def get_edit_value(self) -> str:
        """Возвращает текущее значение."""
        return self._edit_buffer

    def set_edit_value(self, value: str) -> None:
        """Устанавливает значение."""
        self._edit_buffer = value


class MockController:
    """Mock контроллера для тестов."""

    def __init__(self) -> None:
        self.controller_id: str = "test_controller"
        self.dispatched_actions: list[tuple[str, dict[str, Any]]] = []

    def dispatch(self, action: str, **kwargs: Any) -> Any:
        """Записывает действие для проверки."""
        self.dispatched_actions.append((action, kwargs))
        return None

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        pass

    def register_view(self, widget_id: str, callback: Any) -> None:
        pass

    def unregister_view(self, widget_id: str) -> None:
        pass


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def mock_controller() -> MockController:
    """Fixture для mock контроллера."""
    return MockController()


@pytest.fixture
def base_widget(mock_controller: MockController) -> ConcreteWidget:
    """Fixture для базового виджета."""
    return ConcreteWidget(widget_id="test_widget", controller=mock_controller)


@pytest.fixture
def smart_widget(mock_controller: MockController) -> ConcreteSmartWidget:
    """Fixture для smart виджета."""
    return ConcreteSmartWidget(widget_id="smart_widget", controller=mock_controller)


@pytest.fixture
def mock_tk_parent() -> Generator[MagicMock, None, None]:
    """Fixture для mock Tkinter родителя."""
    parent = MagicMock(spec=tk.Widget)
    yield parent


# ==============================================================================
# TEST: BaseWidget Initialization
# ==============================================================================


class TestBaseWidgetInitialization:
    """Тесты инициализации BaseWidget."""

    def test_init_with_valid_widget_id(self) -> None:
        """Инициализация с валидным widget_id."""
        widget = ConcreteWidget(widget_id="my_widget")
        assert widget.widget_id == "my_widget"
        assert not widget.is_mounted()

    def test_init_empty_widget_id_raises_error(self) -> None:
        """Пустой widget_id выбрасывает ValueError."""
        with pytest.raises(ValueError, match="widget_id не может быть пустым"):
            ConcreteWidget(widget_id="")

    def test_init_whitespace_widget_id_raises_error(self) -> None:
        """Whitespace widget_id выбрасывает ValueError."""
        with pytest.raises(ValueError, match="widget_id не может быть пустым"):
            ConcreteWidget(widget_id="   \t  ")

    def test_init_with_controller(self, mock_controller: MockController) -> None:
        """Инициализация с контроллером."""
        widget = ConcreteWidget(
            widget_id="widget_with_controller",
            controller=mock_controller,
        )
        assert widget.widget_id == "widget_with_controller"

    def test_init_without_controller(self) -> None:
        """Инициализация без контроллера."""
        widget = ConcreteWidget(widget_id="standalone_widget")
        assert widget.widget_id == "standalone_widget"


# ==============================================================================
# TEST: BaseWidget Lifecycle
# ==============================================================================


class TestBaseWidgetLifecycle:
    """Тесты жизненного цикла BaseWidget."""

    def test_mount_creates_tk_widget(
        self, base_widget: ConcreteWidget, mock_tk_parent: MagicMock
    ) -> None:
        """mount() создаёт Tkinter виджет."""
        tk_widget = base_widget.mount(mock_tk_parent)

        assert tk_widget is not None
        assert base_widget.is_mounted()

    def test_mount_returns_tk_widget(
        self, base_widget: ConcreteWidget, mock_tk_parent: MagicMock
    ) -> None:
        """mount() возвращает созданный Tkinter виджет."""
        tk_widget = base_widget.mount(mock_tk_parent)

        assert isinstance(tk_widget, MagicMock)

    def test_double_mount_raises_error(
        self, base_widget: ConcreteWidget, mock_tk_parent: MagicMock
    ) -> None:
        """Повторный mount() выбрасывает LifecycleError."""
        base_widget.mount(mock_tk_parent)

        with pytest.raises(LifecycleError, match="уже смонтирован"):
            base_widget.mount(mock_tk_parent)

    def test_unmount_releases_resources(
        self, base_widget: ConcreteWidget, mock_tk_parent: MagicMock
    ) -> None:
        """unmount() освобождает ресурсы."""
        base_widget.mount(mock_tk_parent)
        assert base_widget.is_mounted()

        base_widget.unmount()
        assert not base_widget.is_mounted()

    def test_unmount_not_mounted_raises_error(self, base_widget: ConcreteWidget) -> None:
        """unmount() для не смонтированного виджета выбрасывает LifecycleError."""
        with pytest.raises(LifecycleError, match="не смонтирован"):
            base_widget.unmount()

    def test_mount_invalid_parent_type(self, base_widget: ConcreteWidget) -> None:
        """mount() с невалидным parent выбрасывает TypeError."""
        with pytest.raises(TypeError, match="parent должен быть Tk виджет"):
            base_widget.mount("not_a_widget")

    def test_mount_with_none_parent(self, base_widget: ConcreteWidget) -> None:
        """mount() с None parent выбрасывает TypeError."""
        with pytest.raises(TypeError, match="parent должен быть Tk виджет"):
            base_widget.mount(None)


# ==============================================================================
# TEST: BaseWidget Mount Event
# ==============================================================================


class TestBaseWidgetMountEvent:
    """Тесты события монтирования BaseWidget."""

    def test_mount_dispatches_event(
        self, base_widget: ConcreteWidget, mock_tk_parent: MagicMock
    ) -> None:
        """mount() отправляет MountEvent контроллеру."""
        controller = MockController()
        widget = ConcreteWidget(widget_id="event_test", controller=controller)

        widget.mount(mock_tk_parent)

        assert len(controller.dispatched_actions) == 1
        action, kwargs = controller.dispatched_actions[0]
        assert action == "widget_mounted"
        assert "event" in kwargs
        assert isinstance(kwargs["event"], MountEvent)
        assert kwargs["event"].widget_id == "event_test"

    def test_mount_without_controller_no_error(self, mock_tk_parent: MagicMock) -> None:
        """mount() без контроллера не вызывает ошибок."""
        widget = ConcreteWidget(widget_id="no_controller")

        # Не должно быть исключений
        widget.mount(mock_tk_parent)
        assert widget.is_mounted()


# ==============================================================================
# TEST: BaseWidget Unmount Event
# ==============================================================================


class TestBaseWidgetUnmountEvent:
    """Тесты события демонтирования BaseWidget."""

    def test_unmount_dispatches_event(
        self, base_widget: ConcreteWidget, mock_tk_parent: MagicMock
    ) -> None:
        """unmount() отправляет UnmountEvent контроллеру."""
        controller = MockController()
        widget = ConcreteWidget(widget_id="unmount_test", controller=controller)

        widget.mount(mock_tk_parent)
        widget.unmount()

        # Второе действие - unmount
        assert len(controller.dispatched_actions) == 2
        action, kwargs = controller.dispatched_actions[1]
        assert action == "widget_unmounted"
        assert "event" in kwargs
        assert isinstance(kwargs["event"], UnmountEvent)
        assert kwargs["event"].widget_id == "unmount_test"

    def test_unmount_without_controller_no_error(self, mock_tk_parent: MagicMock) -> None:
        """unmount() без контроллера не вызывает ошибок."""
        widget = ConcreteWidget(widget_id="no_controller")

        widget.mount(mock_tk_parent)
        # Не должно быть исключений
        widget.unmount()


# ==============================================================================
# TEST: BaseWidget Event Handling
# ==============================================================================


class TestBaseWidgetEventHandling:
    """Тесты обработки событий BaseWidget."""

    def test_handle_event_returns_false_by_default(
        self, base_widget: ConcreteWidget, mock_tk_parent: MagicMock
    ) -> None:
        """handle_event() возвращает False по умолчанию."""
        base_widget.mount(mock_tk_parent)

        mock_event = MagicMock()
        result = base_widget.handle_event(mock_event)

        assert result is False


# ==============================================================================
# TEST: SmartBaseWidget Edit Mode
# ==============================================================================


class TestSmartBaseWidgetEditMode:
    """Тесты режима редактирования SmartBaseWidget."""

    def test_is_editing_initially_false(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """is_editing изначально False."""
        smart_widget.mount(mock_tk_parent)
        assert not smart_widget.is_editing

    def test_enter_edit_mode_sets_flag(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """enter_edit_mode() устанавливает is_editing=True."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.enter_edit_mode()
        assert smart_widget.is_editing

    def test_exit_edit_mode_clears_flag(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """exit_edit_mode() устанавливает is_editing=False."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.enter_edit_mode()
        smart_widget.exit_edit_mode()
        assert not smart_widget.is_editing

    def test_enter_edit_mode_not_mounted_raises_error(
        self, smart_widget: ConcreteSmartWidget
    ) -> None:
        """enter_edit_mode() без mount() выбрасывает LifecycleError."""
        with pytest.raises(LifecycleError, match="не смонтирован"):
            smart_widget.enter_edit_mode()

    def test_exit_edit_mode_not_mounted_raises_error(
        self, smart_widget: ConcreteSmartWidget
    ) -> None:
        """exit_edit_mode() без mount() выбрасывает LifecycleError."""
        with pytest.raises(LifecycleError, match="не смонтирован"):
            smart_widget.exit_edit_mode()


# ==============================================================================
# TEST: SmartBaseWidget Value Changes
# ==============================================================================


class TestSmartBaseWidgetValueChanges:
    """Тесты отслеживания изменений SmartBaseWidget."""

    def test_has_changes_no_change(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """has_changes() возвращает False без изменений."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.enter_edit_mode()
        # Значение не изменялось
        assert not smart_widget.has_changes()

    def test_has_changes_with_change(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """has_changes() возвращает True после изменения."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.enter_edit_mode()
        smart_widget.set_edit_value("new value")
        assert smart_widget.has_changes()

    def test_enter_edit_mode_saves_initial_value(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """enter_edit_mode() сохраняет начальное значение."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.set_edit_value("initial")

        smart_widget.enter_edit_mode()
        assert smart_widget._initial_value == "initial"

    def test_exit_edit_mode_triggers_sync_on_changes(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """exit_edit_mode() вызывает sync_to_model() при изменениях."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.enter_edit_mode()
        smart_widget.set_edit_value("changed value")
        smart_widget.exit_edit_mode()

        assert smart_widget._synced

    def test_exit_edit_mode_no_sync_without_changes(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """exit_edit_mode() не вызывает sync_to_model() без изменений."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.enter_edit_mode()
        smart_widget._synced = False
        smart_widget.exit_edit_mode()

        # sync_to_model() не был вызван
        assert not smart_widget._synced


# ==============================================================================
# TEST: SmartBaseWidget Get/Set Edit Value
# ==============================================================================


class TestSmartBaseWidgetGetSetValue:
    """Тесты get_edit_value/set_edit_value SmartBaseWidget."""

    def test_set_get_edit_value(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """set_edit_value/get_edit_value работают корректно."""
        smart_widget.mount(mock_tk_parent)

        smart_widget.set_edit_value("test value")
        assert smart_widget.get_edit_value() == "test value"

    def test_get_edit_value_empty_initially(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """get_edit_value() возвращает пустую строку изначально."""
        smart_widget.mount(mock_tk_parent)
        assert smart_widget.get_edit_value() == ""

    def test_set_edit_value_overwrites(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """set_edit_value() перезаписывает предыдущее значение."""
        smart_widget.mount(mock_tk_parent)

        smart_widget.set_edit_value("first")
        assert smart_widget.get_edit_value() == "first"

        smart_widget.set_edit_value("second")
        assert smart_widget.get_edit_value() == "second"


# ==============================================================================
# TEST: SmartBaseWidget Complete Workflow
# ==============================================================================


class TestSmartBaseWidgetCompleteWorkflow:
    """Тесты полного workflow SmartBaseWidget."""

    def test_edit_workflow(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """Полный workflow редактирования."""
        # 1. Монтирование
        smart_widget.mount(mock_tk_parent)
        assert smart_widget.is_mounted()
        assert not smart_widget.is_editing

        # 2. Установка начального значения
        smart_widget.set_edit_value("original")

        # 3. Вход в режим редактирования
        smart_widget.enter_edit_mode()
        assert smart_widget.is_editing

        # 4. Редактирование
        smart_widget.set_edit_value("modified")
        assert smart_widget.has_changes()

        # 5. Выход из режима редактирования (с sync)
        smart_widget.exit_edit_mode()
        assert not smart_widget.is_editing
        assert smart_widget._synced

        # 6. Демонтирование
        smart_widget.unmount()
        assert not smart_widget.is_mounted()

    def test_view_mode_no_changes(
        self, smart_widget: ConcreteSmartWidget, mock_tk_parent: MagicMock
    ) -> None:
        """Workflow без изменений."""
        smart_widget.mount(mock_tk_parent)
        smart_widget.set_edit_value("value")

        smart_widget.enter_edit_mode()
        smart_widget.exit_edit_mode()

        # sync_to_model() не был вызван
        assert not smart_widget._synced


# ==============================================================================
# TEST: Abstract Methods
# ==============================================================================


class TestAbstractMethods:
    """Тесты абстрактных методов."""

    def test_base_widget_abstract_create_tk_widget(self) -> None:
        """BaseWidget требует реализации _create_tk_widget."""

        class IncompleteWidget(BaseWidget):
            pass

        with pytest.raises(TypeError):
            IncompleteWidget(widget_id="test")  # type: ignore[abstract]

    def test_smart_base_widget_abstract_methods(self) -> None:
        """SmartBaseWidget требует реализации абстрактных методов."""

        class IncompleteSmartWidget(SmartBaseWidget):
            def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
                return MagicMock()

        with pytest.raises(TypeError):
            IncompleteSmartWidget(widget_id="test")  # type: ignore[abstract]


# ==============================================================================
# TEST: Error Messages
# ==============================================================================


class TestErrorMessages:
    """Тесты сообщений об ошибках."""

    def test_lifecycle_error_message_double_mount(self) -> None:
        """Сообщение об ошибке при double mount."""
        widget = ConcreteWidget(widget_id="my_widget")
        parent = MagicMock(spec=tk.Widget)

        widget.mount(parent)

        with pytest.raises(LifecycleError) as exc_info:
            widget.mount(parent)

        assert "my_widget" in str(exc_info.value)
        # Проверяем что сообщение содержит ссылку на ошибку монтирования
        assert "уже смонтирован" in str(exc_info.value)

    def test_lifecycle_error_message_unmount_not_mounted(self) -> None:
        """Сообщение об ошибке при unmount не смонтированного."""
        widget = ConcreteWidget(widget_id="my_widget")

        with pytest.raises(LifecycleError) as exc_info:
            widget.unmount()

        assert "my_widget" in str(exc_info.value)
        # Проверяем что сообщение содержит ссылку на то что виджет не смонтирован
        assert "не смонтирован" in str(exc_info.value)


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.components.base import widget

        assert hasattr(widget, "__all__")
        assert "BaseWidget" in widget.__all__
        assert "SmartBaseWidget" in widget.__all__

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.components.base import widget

        assert hasattr(widget, "__version__")
        assert hasattr(widget, "__author__")
        assert hasattr(widget, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.base.widget"])
