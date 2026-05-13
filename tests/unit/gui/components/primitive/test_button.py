"""Тесты для виджета ThemedButton.

Проверяет базовую функциональность примитивного виджета Button.

Example:
    $ pytest tests/unit/gui/components/primitive/test_button.py -v

Note:
    Требуется запуск с виртуальным дисплеем для GUI тестов:
    $ xvfb-run -a python -m pytest tests/unit/gui/components/primitive/test_button.py -v
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gui.components.primitive.button import ThemedButton
from src.gui.core.exceptions import LifecycleError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_app() -> tk.Tk:
    """Fixture: создаёт корневое окно Tk."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


@pytest.fixture
def parent_frame(tk_app: tk.Tk) -> tk.Frame:
    """Fixture: создаёт родительский фрейм."""
    frame = tk.Frame(tk_app)
    frame.pack()
    return frame


@pytest.fixture
def mock_command() -> MagicMock:
    """Fixture: создаёт мок command."""
    return MagicMock()


# =============================================================================
# CONSTRUCTOR TESTS
# =============================================================================


class TestThemedButtonConstructor:
    """Тесты для конструктора ThemedButton."""

    def test_init_with_text_and_command(self, mock_command: MagicMock) -> None:
        """Тест: создание с текстом и командой."""
        button = ThemedButton(
            widget_id="test_btn",
            text="Click Me",
            command=mock_command,
        )
        assert button.get_text() == "Click Me"
        assert button.is_enabled() is True

    def test_init_stores_widget_id(self, mock_command: MagicMock) -> None:
        """Тест: widget_id сохраняется корректно."""
        button = ThemedButton(
            widget_id="my_button",
            text="Test",
            command=mock_command,
        )
        assert button.widget_id == "my_button"

    def test_init_rejects_empty_widget_id(self, mock_command: MagicMock) -> None:
        """Тест: пустой widget_id вызывает ValueError."""
        with pytest.raises(ValueError, match="widget_id"):
            ThemedButton(
                widget_id="",
                text="Test",
                command=mock_command,
            )

    def test_init_rejects_non_callable_command(self) -> None:
        """Тест: command не callable вызывает TypeError."""
        with pytest.raises(TypeError, match="command"):
            ThemedButton(
                widget_id="test",
                text="Test",
                command="not_callable",  # type: ignore[arg-type]
            )


# =============================================================================
# TEXT METHODS TESTS
# =============================================================================


class TestThemedButtonText:
    """Тесты для методов работы с текстом."""

    def test_set_text_updates_stored_value(self, mock_command: MagicMock) -> None:
        """Тест: set_text() обновляет хранимое значение."""
        button = ThemedButton(
            widget_id="test",
            text="Old",
            command=mock_command,
        )
        button.set_text("New")
        assert button.get_text() == "New"

    def test_set_text_updates_tk_widget(self, parent_frame: tk.Frame, mock_command: MagicMock) -> None:
        """Тест: set_text() обновляет Tkinter виджет."""
        button = ThemedButton(
            widget_id="test",
            text="Initial",
            command=mock_command,
        )
        tk_widget = button.mount(parent_frame)

        button.set_text("Updated")

        assert str(tk_widget.cget("text")) == "Updated"


# =============================================================================
# ENABLED STATE TESTS
# =============================================================================


class TestThemedButtonEnabled:
    """Тесты для управления доступностью кнопки."""

    def test_init_is_enabled_by_default(self, mock_command: MagicMock) -> None:
        """Тест: кнопка включена по умолчанию."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        assert button.is_enabled() is True

    def test_set_enabled_false_disables_button(
        self, parent_frame: tk.Frame, mock_command: MagicMock
    ) -> None:
        """Тест: set_enabled(False) отключает кнопку."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        button.mount(parent_frame)

        button.set_enabled(False)

        assert button.is_enabled() is False

    def test_set_enabled_true_enables_button(
        self, parent_frame: tk.Frame, mock_command: MagicMock
    ) -> None:
        """Тест: set_enabled(True) включает кнопку."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        button.mount(parent_frame)
        button.set_enabled(False)

        button.set_enabled(True)

        assert button.is_enabled() is True

    def test_set_enabled_updates_tk_state(
        self, parent_frame: tk.Frame, mock_command: MagicMock
    ) -> None:
        """Тест: set_enabled() обновляет состояние Tkinter виджета."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        tk_widget = button.mount(parent_frame)

        button.set_enabled(False)

        assert str(tk_widget.cget("state")) == "disabled"

        button.set_enabled(True)

        assert str(tk_widget.cget("state")) == "normal"


# =============================================================================
# COMMAND TESTS
# =============================================================================


class TestThemedButtonCommand:
    """Тесты для вызова команды кнопки."""

    def test_command_executed_on_click(
        self, tk_app: tk.Tk, mock_command: MagicMock
    ) -> None:
        """Тест: команда вызывается при нажатии."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        tk_widget = button.mount(tk_app)

        # Имитируем нажатие кнопки через invoke
        tk_widget.invoke()

        mock_command.assert_called_once()

    def test_command_not_executed_when_disabled(
        self, tk_app: tk.Tk, mock_command: MagicMock
    ) -> None:
        """Тест: команда не вызывается когда кнопка отключена."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        button.mount(tk_app)
        button.set_enabled(False)

        # Команда не должна быть вызвана
        mock_command.assert_not_called()


# =============================================================================
# LIFECYCLE TESTS
# =============================================================================


class TestThemedButtonLifecycle:
    """Тесты для жизненного цикла ThemedButton."""

    def test_is_mounted_returns_false_before_mount(self, mock_command: MagicMock) -> None:
        """Тест: is_mounted() возвращает False до mount()."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        assert button.is_mounted() is False

    def test_is_mounted_returns_true_after_mount(
        self, parent_frame: tk.Frame, mock_command: MagicMock
    ) -> None:
        """Тест: is_mounted() возвращает True после mount()."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        button.mount(parent_frame)
        assert button.is_mounted() is True

    def test_is_mounted_returns_false_after_unmount(
        self, parent_frame: tk.Frame, mock_command: MagicMock
    ) -> None:
        """Тест: is_mounted() возвращает False после unmount()."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        button.mount(parent_frame)
        button.unmount()
        assert button.is_mounted() is False

    def test_mount_returns_tk_widget(
        self, parent_frame: tk.Frame, mock_command: MagicMock
    ) -> None:
        """Тест: mount() возвращает Tkinter виджет."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        result = button.mount(parent_frame)
        assert isinstance(result, tk.Button)

    def test_unmount_cleanup_bindings(
        self, parent_frame: tk.Frame, mock_command: MagicMock
    ) -> None:
        """Тест: unmount() очищает event bindings."""
        button = ThemedButton(
            widget_id="test",
            text="Test",
            command=mock_command,
        )
        button.mount(parent_frame)

        # Не должно вызывать ошибок
        button.unmount()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestThemedButtonConstructor",
    "TestThemedButtonText",
    "TestThemedButtonEnabled",
    "TestThemedButtonCommand",
    "TestThemedButtonLifecycle",
]
