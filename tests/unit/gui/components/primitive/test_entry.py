"""Тесты для ThemedEntry виджета.

Модуль содержит unit-тесты для виджета текстового ввода ThemedEntry.
Все тесты используют виртуальный фреймбуфер для GUI-компонентов.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/components/primitive/test_entry.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gui.components.base.widget import SmartBaseWidget
from src.gui.components.primitive.entry import ThemedEntry
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


class TestThemedEntryInitialization:
    """Тесты инициализации ThemedEntry."""

    def test_init_with_required_params(self) -> None:
        """Тест: инициализация с обязательными параметрами."""
        entry = ThemedEntry(widget_id="test_entry")

        assert entry.widget_id == "test_entry"
        assert not entry.is_mounted()
        assert not entry.is_editing

    def test_init_with_all_params(self, mock_controller: MagicMock) -> None:
        """Тест: инициализация со всеми параметрами."""
        def validator(text: str) -> bool:
            return len(text) > 0

        entry = ThemedEntry(
            widget_id="full_entry",
            placeholder="Введите текст",
            show="*",
            validator=validator,
            controller=mock_controller,
        )

        assert entry.widget_id == "full_entry"
        assert entry._placeholder == "Введите текст"
        assert entry._show == "*"
        assert entry._validator is validator
        assert entry._controller is mock_controller

    def test_init_empty_widget_id_raises_error(self) -> None:
        """Тест: пустой widget_id вызывает ValueError."""
        with pytest.raises(ValueError, match="widget_id не может быть пустым"):
            ThemedEntry(widget_id="")

    def test_init_whitespace_widget_id_raises_error(self) -> None:
        """Тест: widget_id из пробелов вызывает ValueError."""
        with pytest.raises(ValueError, match="widget_id не может быть пустым"):
            ThemedEntry(widget_id="   ")

    def test_inherits_smart_base_widget(self) -> None:
        """Тест: ThemedEntry наследуется от SmartBaseWidget."""
        entry = ThemedEntry(widget_id="test")
        assert isinstance(entry, SmartBaseWidget)


class TestThemedEntryMounting:
    """Тесты монтирования/демонтирования ThemedEntry."""

    def test_mount_creates_tk_widget(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: mount создаёт tk.Entry виджет."""
        entry = ThemedEntry(widget_id="mount_test", controller=mock_controller)
        tk_widget = entry.mount(tk_root)

        assert entry.is_mounted()
        assert isinstance(tk_widget, tk.Entry)
        assert entry._tk_widget is tk_widget

    def test_mount_sends_mount_event(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: mount отправляет widget_mounted событие."""
        entry = ThemedEntry(widget_id="mount_event_test", controller=mock_controller)
        entry.mount(tk_root)

        mock_controller.dispatch.assert_called_once()
        call_args = mock_controller.dispatch.call_args
        assert call_args[0][0] == "widget_mounted"

    def test_mount_twice_raises_lifecycle_error(self, tk_root: tk.Tk) -> None:
        """Тест: повторный mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="double_mount")
        entry.mount(tk_root)

        with pytest.raises(LifecycleError, match="уже смонтирован"):
            entry.mount(tk_root)

    def test_unmount_releases_resources(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: unmount освобождает ресурсы."""
        entry = ThemedEntry(widget_id="unmount_test", controller=mock_controller)
        entry.mount(tk_root)
        entry.unmount()

        assert not entry.is_mounted()
        assert entry._tk_widget is None

    def test_unmount_sends_unmount_event(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: unmount отправляет widget_unmounted событие."""
        entry = ThemedEntry(widget_id="unmount_event_test", controller=mock_controller)
        entry.mount(tk_root)
        mock_controller.dispatch.reset_mock()

        entry.unmount()

        mock_controller.dispatch.assert_called_once()
        call_args = mock_controller.dispatch.call_args
        assert call_args[0][0] == "widget_unmounted"

    def test_unmount_without_mount_raises_error(self) -> None:
        """Тест: unmount без mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="unmount_no_mount")

        with pytest.raises(LifecycleError, match="не смонтирован"):
            entry.unmount()


class TestThemedEntryTextOperations:
    """Тесты операций с текстом ThemedEntry."""

    def test_set_and_get_text(self, tk_root: tk.Tk) -> None:
        """Тест: установка и получение текста."""
        entry = ThemedEntry(widget_id="text_test")
        entry.mount(tk_root)

        entry.set_text("Hello World")
        assert entry.get_text() == "Hello World"

    def test_get_text_empty(self, tk_root: tk.Tk) -> None:
        """Тест: получение текста из пустого поля."""
        entry = ThemedEntry(widget_id="empty_test")
        entry.mount(tk_root)

        assert entry.get_text() == ""

    def test_set_text_clears_error(self, tk_root: tk.Tk) -> None:
        """Тест: установка текста очищает ошибку."""
        entry = ThemedEntry(widget_id="clear_error_test")
        entry.mount(tk_root)

        entry.show_error("Some error")
        assert entry._has_error

        entry.set_text("New text")
        assert not entry._has_error

    def test_get_text_unmounted_returns_empty(self) -> None:
        """Тест: get_text для несмонтированного виджета возвращает пустую строку."""
        entry = ThemedEntry(widget_id="unmounted_text")
        assert entry.get_text() == ""

    def test_set_text_unmounted_does_nothing(self, tk_root: tk.Tk) -> None:
        """Тест: set_text для несмонтированного виджета ничего не делает."""
        entry = ThemedEntry(widget_id="unmounted_set")

        # Не должно вызывать ошибок
        entry.set_text("Some text")
        assert entry.get_text() == ""


class TestThemedEntryPlaceholder:
    """Тесты placeholder функциональности ThemedEntry."""

    def test_placeholder_displayed_when_empty(self, tk_root: tk.Tk) -> None:
        """Тест: placeholder отображается при пустом поле."""
        entry = ThemedEntry(
            widget_id="placeholder_test",
            placeholder="Enter text here"
        )
        entry.mount(tk_root)

        # После потери фокуса с пустым значением должен показываться placeholder
        entry._on_focus_out()
        assert entry._placeholder_shown

    def test_set_placeholder_updates_text(self, tk_root: tk.Tk) -> None:
        """Тест: set_placeholder обновляет текст."""
        entry = ThemedEntry(widget_id="set_placeholder_test")
        entry.mount(tk_root)

        entry.set_placeholder("New placeholder")
        assert entry._placeholder == "New placeholder"


class TestThemedEntryValidation:
    """Тесты валидации ThemedEntry."""

    def test_validate_without_validator_returns_true(self, tk_root: tk.Tk) -> None:
        """Тест: валидация без validator всегда возвращает True."""
        entry = ThemedEntry(widget_id="no_validator")
        entry.mount(tk_root)

        entry.set_text("any text")
        assert entry.validate() is True

    def test_validate_with_valid_text(self, tk_root: tk.Tk) -> None:
        """Тест: валидация проходит с валидным текстом."""
        def validator(text: str) -> bool:
            return len(text) >= 3

        entry = ThemedEntry(
            widget_id="validator_test",
            validator=validator
        )
        entry.mount(tk_root)

        entry.set_text("valid")
        assert entry.validate() is True
        assert not entry._has_error

    def test_validate_with_invalid_text(self, tk_root: tk.Tk) -> None:
        """Тест: валидация не проходит с невалидным текстом."""
        def validator(text: str) -> bool:
            return len(text) >= 3

        entry = ThemedEntry(
            widget_id="invalid_test",
            validator=validator
        )
        entry.mount(tk_root)

        entry.set_text("ab")
        assert entry.validate() is False
        assert entry._has_error

    def test_show_error_sets_error_state(self, tk_root: tk.Tk) -> None:
        """Тест: show_error устанавливает состояние ошибки."""
        entry = ThemedEntry(widget_id="error_test")
        entry.mount(tk_root)

        entry.show_error("Test error")
        assert entry._has_error

    def test_clear_error_removes_error_state(self, tk_root: tk.Tk) -> None:
        """Тест: clear_error снимает состояние ошибки."""
        entry = ThemedEntry(widget_id="clear_error_test")
        entry.mount(tk_root)

        entry.show_error("Test error")
        entry.clear_error()
        assert not entry._has_error


class TestThemedEntryEditMode:
    """Тесты режима редактирования ThemedEntry."""

    def test_enter_edit_mode_sets_flag(self, tk_root: tk.Tk) -> None:
        """Тест: enter_edit_mode устанавливает is_editing=True."""
        entry = ThemedEntry(widget_id="enter_edit")
        entry.mount(tk_root)

        entry.enter_edit_mode()
        assert entry.is_editing

    def test_enter_edit_mode_saves_initial_value(self, tk_root: tk.Tk) -> None:
        """Тест: enter_edit_mode сохраняет начальное значение."""
        entry = ThemedEntry(widget_id="save_initial")
        entry.mount(tk_root)

        entry.set_text("initial")
        entry.enter_edit_mode()
        assert entry._initial_value == "initial"

    def test_enter_edit_mode_unmounted_raises_error(self) -> None:
        """Тест: enter_edit_mode без mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="edit_unmounted")

        with pytest.raises(LifecycleError, match="не смонтирован"):
            entry.enter_edit_mode()

    def test_exit_edit_mode_clears_flag(self, tk_root: tk.Tk) -> None:
        """Тест: exit_edit_mode сбрасывает is_editing."""
        entry = ThemedEntry(widget_id="exit_edit")
        entry.mount(tk_root)

        entry.enter_edit_mode()
        entry.exit_edit_mode()
        assert not entry.is_editing

    def test_exit_edit_mode_unmounted_raises_error(self) -> None:
        """Тест: exit_edit_mode без mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="exit_unmounted")

        with pytest.raises(LifecycleError, match="не смонтирован"):
            entry.exit_edit_mode()

    def test_has_changes_detects_modifications(self, tk_root: tk.Tk) -> None:
        """Тест: has_changes обнаруживает изменения."""
        entry = ThemedEntry(widget_id="has_changes")
        entry.mount(tk_root)

        entry.set_text("initial")
        entry.enter_edit_mode()

        entry.set_text("modified")
        assert entry.has_changes()

    def test_has_changes_no_modifications(self, tk_root: tk.Tk) -> None:
        """Тест: has_changes=false когда нет изменений."""
        entry = ThemedEntry(widget_id="no_changes")
        entry.mount(tk_root)

        entry.set_text("same")
        entry.enter_edit_mode()

        assert not entry.has_changes()


class TestThemedEntrySyncToModel:
    """Тесты синхронизации с моделью."""

    def test_sync_to_model_with_changes(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: sync_to_model отправляет событие при изменениях."""
        entry = ThemedEntry(
            widget_id="sync_test",
            controller=mock_controller
        )
        entry.mount(tk_root)

        entry.set_text("old")
        entry.enter_edit_mode()
        entry.set_text("new")

        result = entry.sync_to_model()

        assert result is True
        mock_controller.dispatch.assert_called_with(
            "entry_changed",
            value="new",
            widget_id="sync_test"
        )

    def test_sync_to_model_no_changes(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: sync_to_model не отправляет при отсутствии изменений."""
        entry = ThemedEntry(
            widget_id="no_sync_test",
            controller=mock_controller
        )
        entry.mount(tk_root)
        # Сбрасываем только вызовы связанные с widget_mounted
        mock_controller.dispatch.reset_mock()

        entry.set_text("same")
        entry.enter_edit_mode()

        result = entry.sync_to_model()

        assert result is False
        # Проверяем что dispatch не был вызван для entry_changed
        entry_changed_calls = [
            call for call in mock_controller.dispatch.call_args_list
            if call[0][0] == "entry_changed"
        ]
        assert len(entry_changed_calls) == 0

    def test_sync_to_model_unmounted_raises_error(
        self, mock_controller: MagicMock
    ) -> None:
        """Тест: sync_to_model без mount вызывает LifecycleError."""
        entry = ThemedEntry(
            widget_id="sync_unmounted",
            controller=mock_controller
        )

        with pytest.raises(LifecycleError, match="не смонтирован"):
            entry.sync_to_model()


class TestThemedEntryEditValue:
    """Тесты get_edit_value и set_edit_value."""

    def test_get_edit_value_returns_text(self, tk_root: tk.Tk) -> None:
        """Тест: get_edit_value возвращает текущий текст."""
        entry = ThemedEntry(widget_id="get_edit")
        entry.mount(tk_root)

        entry.set_text("edit value")
        assert entry.get_edit_value() == "edit value"

    def test_get_edit_value_unmounted_raises_error(self) -> None:
        """Тест: get_edit_value без mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="get_unmounted")

        with pytest.raises(LifecycleError, match="не смонтирован"):
            entry.get_edit_value()

    def test_set_edit_value_updates_text(self, tk_root: tk.Tk) -> None:
        """Тест: set_edit_value обновляет текст."""
        entry = ThemedEntry(widget_id="set_edit")
        entry.mount(tk_root)

        entry.set_edit_value("new value")
        assert entry.get_text() == "new value"

    def test_set_edit_value_unmounted_raises_error(self) -> None:
        """Тест: set_edit_value без mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="set_unmounted")

        with pytest.raises(LifecycleError, match="не смонтирован"):
            entry.set_edit_value("value")


class TestThemedEntryFocusHandling:
    """Тесты обработки фокуса."""

    def test_focus_in_enters_edit_mode(self, tk_root: tk.Tk) -> None:
        """Тест: FocusIn вызывает enter_edit_mode."""
        entry = ThemedEntry(widget_id="focus_in")
        entry.mount(tk_root)

        # Симулируем событие FocusIn
        entry._on_focus_in()
        assert entry.is_editing

    def test_focus_out_exits_edit_mode(self, tk_root: tk.Tk) -> None:
        """Тест: FocusOut вызывает exit_edit_mode."""
        entry = ThemedEntry(widget_id="focus_out")
        entry.mount(tk_root)

        entry.enter_edit_mode()
        entry._on_focus_out()
        assert not entry.is_editing

    def test_focus_out_syncs_changes(
        self, tk_root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """Тест: FocusOut синхронизирует изменения."""
        entry = ThemedEntry(
            widget_id="focus_sync",
            controller=mock_controller
        )
        entry.mount(tk_root)

        entry.set_text("initial")
        entry.enter_edit_mode()
        entry.set_text("changed")

        entry._on_focus_out()

        mock_controller.dispatch.assert_called_with(
            "entry_changed",
            value="changed",
            widget_id="focus_sync"
        )


class TestThemedEntryPasswordMode:
    """Тесты режима пароля."""

    def test_show_parameter_masks_input(self, tk_root: tk.Tk) -> None:
        """Тест: show='*' маскирует ввод."""
        entry = ThemedEntry(
            widget_id="password",
            show="*"
        )
        entry.mount(tk_root)

        assert entry._show == "*"


__all__ = [
    "TestThemedEntryInitialization",
    "TestThemedEntryMounting",
    "TestThemedEntryTextOperations",
    "TestThemedEntryPlaceholder",
    "TestThemedEntryValidation",
    "TestThemedEntryEditMode",
    "TestThemedEntrySyncToModel",
    "TestThemedEntryEditValue",
    "TestThemedEntryFocusHandling",
    "TestThemedEntryPasswordMode",
]
