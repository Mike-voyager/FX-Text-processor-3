"""Тесты для composite виджета MainToolbar.

Проверяет функциональность главной панели инструментов.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/components/composite/test_main_toolbar.py -v
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Iterator
from typing import cast
from unittest.mock import MagicMock

import pytest
from src.gui.components.composite.main_toolbar import MainToolbar
from src.gui.components.primitive.button import ThemedButton
from src.gui.core.protocols import ControllerProtocol


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture  # type: ignore[misc]
def tk_app() -> Iterator[tk.Tk]:
    """Fixture: создаёт корневое окно Tk."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture  # type: ignore[misc]
def mock_controller() -> MagicMock:
    """Fixture: создаёт мок контроллера."""
    controller = MagicMock(spec=ControllerProtocol)
    controller.dispatch = MagicMock(return_value=None)
    return controller


# =============================================================================
# CONSTRUCTOR TESTS
# =============================================================================


class TestMainToolbarConstructor:
    """Тесты конструктора MainToolbar."""

    def test_init_stores_widget_id(self, mock_controller: MagicMock) -> None:
        """Тест: widget_id сохраняется корректно."""
        toolbar = MainToolbar(widget_id="toolbar", controller=mock_controller)
        assert toolbar.widget_id == "toolbar"

    def test_init_rejects_empty_widget_id(self) -> None:
        """Тест: пустой widget_id вызывает ValueError."""
        with pytest.raises(ValueError, match="widget_id"):
            MainToolbar(widget_id="")

    def test_init_stores_controller(self, mock_controller: MagicMock) -> None:
        """Тест: контроллер сохраняется."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        assert toolbar._controller is mock_controller

    def test_init_accepts_button_commands(self, mock_controller: MagicMock) -> None:
        """Тест: пользовательские команды сохраняются."""
        commands: dict[str, Callable[[], None]] = {"new": lambda: None}
        toolbar = MainToolbar(
            widget_id="t",
            controller=mock_controller,
            button_commands=commands,
        )
        assert toolbar._button_commands is commands

    def test_init_rejects_non_dict_button_commands(self) -> None:
        """Тест: button_commands не словарь вызывает TypeError."""
        with pytest.raises(TypeError, match="dict"):
            MainToolbar(widget_id="t", button_commands="bad")  # type: ignore[arg-type]


# =============================================================================
# MOUNT & BUTTON TESTS
# =============================================================================


class TestMainToolbarMount:
    """Тесты монтирования и кнопок."""

    def test_mount_returns_frame(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: mount возвращает Frame."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        result = toolbar.mount(tk_app)
        assert isinstance(result, tk.Frame)

    def test_mount_creates_four_buttons(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: создаётся 4 кнопки."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        assert len(toolbar._buttons) == 4
        assert set(toolbar._buttons.keys()) == {"new", "open", "save", "print"}

    def test_get_button_existing(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: get_button возвращает ThemedButton."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        btn = toolbar.get_button("save")
        assert isinstance(btn, ThemedButton)

    def test_get_button_missing(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: get_button для несуществующей кнопки возвращает None."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        assert toolbar.get_button("unknown") is None

    def test_mount_sets_is_mounted(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: после mount is_mounted True."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        assert toolbar.is_mounted() is True


# =============================================================================
# ENABLED STATE TESTS
# =============================================================================


class TestMainToolbarEnabled:
    """Тесты управления доступностью кнопок."""

    def test_set_button_enabled_false(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: set_button_enabled(False) отключает кнопку."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        toolbar.set_button_enabled("save", False)
        assert toolbar.get_button("save").is_enabled() is False

    def test_set_button_enabled_true(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: set_button_enabled(True) включает кнопку."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        toolbar.set_button_enabled("save", False)
        toolbar.set_button_enabled("save", True)
        assert toolbar.get_button("save").is_enabled() is True

    def test_set_button_enabled_bad_name(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: несуществующая кнопка вызывает ValueError."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        with pytest.raises(ValueError, match="Button 'bad' not found"):
            toolbar.set_button_enabled("bad", False)


# =============================================================================
# COMMAND TESTS
# =============================================================================


class TestMainToolbarCommands:
    """Тесты callback'ов кнопок."""

    def test_custom_command_called(self, tk_app: tk.Tk) -> None:
        """Тест: пользовательская команда вызывается."""
        cb = MagicMock()
        toolbar = MainToolbar(
            widget_id="t",
            button_commands={"new": cb},
        )
        toolbar.mount(tk_app)
        cmd = toolbar._get_button_command("file_new")
        cmd()
        cb.assert_called_once()

    def test_dispatch_command_called(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: при отсутствии custom command вызывается controller.dispatch()."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        cmd = toolbar._get_button_command("file_save")
        cmd()
        mock_controller.dispatch.assert_any_call("file_save")

    def test_button_invokes_command(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: нажатие кнопки вызывает dispatch."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        btn = toolbar.get_button("open")
        assert btn is not None
        tk_widget = cast(tk.Button, btn._tk_widget)
        tk_widget.invoke()
        mock_controller.dispatch.assert_called_with("file_open")


# =============================================================================
# LIFECYCLE TESTS
# =============================================================================


class TestMainToolbarLifecycle:
    """Тесты жизненного цикла."""

    def test_unmount_cleans_buttons(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: unmount очищает словарь кнопок."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        toolbar.unmount()
        assert toolbar._buttons == {}

    def test_unmount_sets_not_mounted(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: после unmount is_mounted False."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        toolbar.unmount()
        assert toolbar.is_mounted() is False

    def test_cleanup_unbinds_keys(self, tk_app: tk.Tk, mock_controller: MagicMock) -> None:
        """Тест: _cleanup отвязывает горячие клавиши без ошибок."""
        toolbar = MainToolbar(widget_id="t", controller=mock_controller)
        toolbar.mount(tk_app)
        # Не должно вызывать ошибок
        toolbar._cleanup()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestMainToolbarConstructor",
    "TestMainToolbarMount",
    "TestMainToolbarEnabled",
    "TestMainToolbarCommands",
    "TestMainToolbarLifecycle",
]
