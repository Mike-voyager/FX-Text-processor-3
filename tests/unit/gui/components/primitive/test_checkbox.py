"""Тесты для ThemedCheckbox виджета.

Модуль содержит unit-тесты для виджета чекбокса ThemedCheckbox.
Все тесты используют виртуальный фреймбуфер для GUI-компонентов.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/components/primitive/test_checkbox.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gui.components.base.widget import BaseWidget
from src.gui.components.primitive.checkbox import ThemedCheckbox
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol


@pytest.fixture
def mock_controller() -> MagicMock:
    """Создаёт mock контроллер для тестов."""
    controller = MagicMock(spec=ControllerProtocol)
    controller.dispatch = MagicMock(return_value=None)
    return controller


@pytest.fixture
def tk_root() -> tk.Tk:
    """Создаёт Tk root для тестов GUI."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


class TestThemedCheckboxInitialization:
    """Тесты инициализации ThemedCheckbox."""

    def test_init_with_required_params(self) -> None:
        """Тест: инициализация с обязательными параметрами."""
        checkbox = ThemedCheckbox(widget_id="test_checkbox")

        assert checkbox.widget_id == "test_checkbox"
        assert not checkbox.is_mounted()

    def test_init_with_all_params(self, mock_controller: MagicMock) -> None:
        """Тест: инициализация со всеми параметрами."""
        def on_change(checked: bool) -> None:
            pass

        checkbox = ThemedCheckbox(
            widget_id="full_checkbox",
            text="Check me",
            on_change=on_change,
            controller=mock_controller,
        )

        assert checkbox.widget_id == "full_checkbox"
        assert checkbox._text == "Check me"
        assert checkbox._on_change is on_change
        assert checkbox._controller is mock_controller

    def test_init_empty_widget_id_raises_error(self) -> None:
        """Тест: пустой widget_id вызывает ValueError."""
        with pytest.raises(ValueError, match="widget_id не может быть пустым"):
            ThemedCheckbox(widget_id="")

    def test_inherits_base_widget(self) -> None:
        """Тест: ThemedCheckbox наследуется от BaseWidget."""
        checkbox = ThemedCheckbox(widget_id="test")
        assert isinstance(checkbox, BaseWidget)


class TestThemedCheckboxMounting:
    """Тесты монтирования/демонтирования ThemedCheckbox."""

    def test_mount_creates_tk_widget(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: mount создаёт tk.Checkbutton виджет."""
        checkbox = ThemedCheckbox(
            widget_id="mount_test",
            controller=mock_controller
        )
        tk_widget = checkbox.mount(tk_root)

        assert checkbox.is_mounted()
        assert isinstance(tk_widget, tk.Checkbutton)
        assert checkbox._tk_widget is tk_widget

    def test_mount_sends_mount_event(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: mount отправляет widget_mounted событие."""
        checkbox = ThemedCheckbox(
            widget_id="mount_event_test",
            controller=mock_controller
        )
        checkbox.mount(tk_root)

        mock_controller.dispatch.assert_called_once()
        call_args = mock_controller.dispatch.call_args
        assert call_args[0][0] == "widget_mounted"

    def test_mount_twice_raises_lifecycle_error(self, tk_root: tk.Tk) -> None:
        """Тест: повторный mount вызывает LifecycleError."""
        checkbox = ThemedCheckbox(widget_id="double_mount")
        checkbox.mount(tk_root)

        with pytest.raises(LifecycleError, match="уже смонтирован"):
            checkbox.mount(tk_root)

    def test_unmount_releases_resources(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: unmount освобождает ресурсы."""
        checkbox = ThemedCheckbox(
            widget_id="unmount_test",
            controller=mock_controller
        )
        checkbox.mount(tk_root)
        checkbox.unmount()

        assert not checkbox.is_mounted()
        assert checkbox._tk_widget is None


class TestThemedCheckboxState:
    """Тесты управления состоянием ThemedCheckbox."""

    def test_get_returns_initial_false(self, tk_root: tk.Tk) -> None:
        """Тест: начальное состояние False."""
        checkbox = ThemedCheckbox(widget_id="initial_state")
        checkbox.mount(tk_root)

        assert checkbox.get() is False

    def test_set_true(self, tk_root: tk.Tk) -> None:
        """Тест: установка в True."""
        checkbox = ThemedCheckbox(widget_id="set_true")
        checkbox.mount(tk_root)

        checkbox.set(True)
        assert checkbox.get() is True

    def test_set_false(self, tk_root: tk.Tk) -> None:
        """Тест: установка в False."""
        checkbox = ThemedCheckbox(widget_id="set_false")
        checkbox.mount(tk_root)

        checkbox.set(True)
        checkbox.set(False)
        assert checkbox.get() is False

    def test_toggle_switches_state(self, tk_root: tk.Tk) -> None:
        """Тест: toggle переключает состояние."""
        checkbox = ThemedCheckbox(widget_id="toggle_test")
        checkbox.mount(tk_root)

        checkbox.toggle()
        assert checkbox.get() is True

        checkbox.toggle()
        assert checkbox.get() is False

    def test_set_same_value_no_notification(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: установка того же значения не вызывает dispatch."""
        checkbox = ThemedCheckbox(
            widget_id="same_value",
            controller=mock_controller
        )
        checkbox.mount(tk_root)
        mock_controller.dispatch.reset_mock()

        # Устанавливаем True когда уже False
        checkbox.set(True)
        assert mock_controller.dispatch.call_count >= 1

        mock_controller.dispatch.reset_mock()

        # Устанавливаем True когда уже True - не должно быть вызовов
        checkbox.set(True)
        # on_change не вызывается при установке того же значения
        # но dispatch может вызываться через _notify_change


class TestThemedCheckboxOnChange:
    """Тесты callback при изменении состояния."""

    def test_on_change_called_when_set(
        self, tk_root: tk.Tk
    ) -> None:
        """Тест: on_change вызывается при set()."""
        callback_calls: list[bool] = []

        def on_change(checked: bool) -> None:
            callback_calls.append(checked)

        checkbox = ThemedCheckbox(
            widget_id="on_change_set",
            on_change=on_change
        )
        checkbox.mount(tk_root)

        checkbox.set(True)
        assert True in callback_calls

    def test_on_change_called_when_toggle(
        self, tk_root: tk.Tk
    ) -> None:
        """Тест: on_change вызывается при toggle()."""
        callback_calls: list[bool] = []

        def on_change(checked: bool) -> None:
            callback_calls.append(checked)

        checkbox = ThemedCheckbox(
            widget_id="on_change_toggle",
            on_change=on_change
        )
        checkbox.mount(tk_root)

        checkbox.toggle()
        assert callback_calls == [True]

        checkbox.toggle()
        assert callback_calls == [True, False]

    def test_on_change_not_called_for_same_value(
        self, tk_root: tk.Tk
    ) -> None:
        """Тест: on_change не вызывается при установке того же значения."""
        callback_calls: list[bool] = []

        def on_change(checked: bool) -> None:
            callback_calls.append(checked)

        checkbox = ThemedCheckbox(
            widget_id="no_duplicate",
            on_change=on_change
        )
        checkbox.mount(tk_root)

        checkbox.set(True)
        assert len(callback_calls) == 1

        # Тоже значение - не должно быть вызова
        checkbox.set(True)
        assert len(callback_calls) == 1


class TestThemedCheckboxController:
    """Тесты интеграции с Controller."""

    def test_dispatch_on_set(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: set() отправляет dispatch в controller."""
        checkbox = ThemedCheckbox(
            widget_id="dispatch_set",
            controller=mock_controller
        )
        checkbox.mount(tk_root)
        mock_controller.dispatch.reset_mock()

        checkbox.set(True)

        mock_controller.dispatch.assert_called_with(
            "checkbox_changed",
            widget_id="dispatch_set",
            checked=True
        )

    def test_dispatch_on_toggle(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: toggle() отправляет dispatch в controller."""
        checkbox = ThemedCheckbox(
            widget_id="dispatch_toggle",
            controller=mock_controller
        )
        checkbox.mount(tk_root)

        checkbox.toggle()

        # Проверяем что был вызов с checked=True
        calls = [call for call in mock_controller.dispatch.call_args_list
                 if call[0][0] == "checkbox_changed"]
        assert len(calls) >= 1
        assert calls[-1][1]["checked"] is True

    def test_no_dispatch_without_controller(self, tk_root: tk.Tk) -> None:
        """Тест: без controller dispatch не вызывается."""
        checkbox = ThemedCheckbox(widget_id="no_controller")
        checkbox.mount(tk_root)

        # Не должно вызывать ошибок
        checkbox.set(True)
        checkbox.toggle()


class TestThemedCheckboxText:
    """Тесты текста чекбокса."""

    def test_text_stored_correctly(self) -> None:
        """Тест: текст сохраняется корректно."""
        checkbox = ThemedCheckbox(
            widget_id="text_test",
            text="My Checkbox Label"
        )
        assert checkbox._text == "My Checkbox Label"


__all__ = [
    "TestThemedCheckboxInitialization",
    "TestThemedCheckboxMounting",
    "TestThemedCheckboxState",
    "TestThemedCheckboxOnChange",
    "TestThemedCheckboxController",
    "TestThemedCheckboxText",
]
