"""Тесты для WorkflowToolbar.

Тестирует создание, динамическую видимость кнопок и callback вызовы.
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.documents.constructor.form_status import FormStatus
from src.gui.workflow.workflow_toolbar import (
    _BUTTON_CONFIG,
    _lighten_color,
    WorkflowToolbar,
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def toolbar(root: tk.Tk) -> WorkflowToolbar:
    """Фикстура для WorkflowToolbar."""
    return WorkflowToolbar(parent=root)


@pytest.fixture
def mock_callback() -> MagicMock:
    """Фикстура для mock callback."""
    return MagicMock()


class TestWorkflowToolbarInit:
    """Тесты инициализации WorkflowToolbar."""

    def test_init_creates_frame(self, root: tk.Tk) -> None:
        """Тест что инициализация создаёт Frame."""
        toolbar = WorkflowToolbar(parent=root)
        assert isinstance(toolbar, tk.Frame)

    def test_default_all_buttons_hidden(self, toolbar: WorkflowToolbar) -> None:
        """Тест что по умолчанию все кнопки скрыты."""
        for action in toolbar.get_available_actions():
            assert not toolbar.is_action_visible(action)

    def test_all_buttons_created(self, toolbar: WorkflowToolbar) -> None:
        """Тест что все кнопки созданы и зарегистрированы."""
        expected_actions = set(_BUTTON_CONFIG.keys())
        assert toolbar.get_available_actions() == expected_actions

    def test_button_retrieval(self, toolbar: WorkflowToolbar) -> None:
        """Тест получения кнопки по action name."""
        button = toolbar.get_button("save_draft")
        assert button is not None
        assert isinstance(button, tk.Button)

    def test_unknown_button_returns_none(self, toolbar: WorkflowToolbar) -> None:
        """Тест что неизвестный action возвращает None."""
        assert toolbar.get_button("nonexistent") is None


class TestWorkflowToolbarVisibility:
    """Тесты видимости кнопок через set_available_actions."""

    def test_show_single_button(self, toolbar: WorkflowToolbar) -> None:
        """Тест показа одной кнопки."""
        toolbar.set_available_actions({"save_draft"})

        assert toolbar.is_action_visible("save_draft")
        assert not toolbar.is_action_visible("validate")
        assert not toolbar.is_action_visible("approve")

    def test_show_multiple_buttons(self, toolbar: WorkflowToolbar) -> None:
        """Тест показа нескольких кнопок."""
        toolbar.set_available_actions({"save_draft", "validate"})

        assert toolbar.is_action_visible("save_draft")
        assert toolbar.is_action_visible("validate")
        assert not toolbar.is_action_visible("approve")
        assert not toolbar.is_action_visible("sign")

    def test_show_all_buttons(self, toolbar: WorkflowToolbar) -> None:
        """Тест показа всех кнопок."""
        all_actions = toolbar.get_available_actions()
        toolbar.set_available_actions(all_actions)

        for action in all_actions:
            assert toolbar.is_action_visible(action)

    def test_hide_all_buttons(self, toolbar: WorkflowToolbar) -> None:
        """Тест скрытия всех кнопок."""
        # Сначала показываем
        toolbar.set_available_actions({"save_draft", "validate"})
        assert toolbar.is_action_visible("save_draft")

        # Затем скрываем
        toolbar.set_available_actions(set())
        for action in toolbar.get_available_actions():
            assert not toolbar.is_action_visible(action)

    def test_switch_visible_buttons(self, toolbar: WorkflowToolbar) -> None:
        """Тест переключения видимых кнопок."""
        toolbar.set_available_actions({"save_draft"})
        assert toolbar.is_action_visible("save_draft")
        assert not toolbar.is_action_visible("validate")

        toolbar.set_available_actions({"validate"})
        assert not toolbar.is_action_visible("save_draft")
        assert toolbar.is_action_visible("validate")

    def test_unknown_action_ignored(self, toolbar: WorkflowToolbar) -> None:
        """Тест что неизвестные действия игнорируются."""
        toolbar.set_available_actions({"save_draft", "unknown_action"})

        assert toolbar.is_action_visible("save_draft")
        assert not toolbar.is_action_visible("unknown_action")


class TestWorkflowToolbarCallbacks:
    """Тесты callback вызовов."""

    def test_callback_called_with_action_name(
        self, toolbar: WorkflowToolbar, mock_callback: MagicMock
    ) -> None:
        """Тест что callback вызывается с правильным action_name."""
        toolbar.on_action(mock_callback)
        toolbar.set_available_actions({"save_draft"})

        button = toolbar.get_button("save_draft")
        assert button is not None
        button.invoke()

        mock_callback.assert_called_once_with("save_draft")

    def test_callback_called_for_different_actions(
        self, toolbar: WorkflowToolbar, mock_callback: MagicMock
    ) -> None:
        """Тест callback для разных действий."""
        toolbar.on_action(mock_callback)
        toolbar.set_available_actions({"validate", "reject"})

        toolbar.get_button("validate").invoke()  # type: ignore[union-attr]
        toolbar.get_button("reject").invoke()  # type: ignore[union-attr]

        assert mock_callback.call_count == 2
        mock_callback.assert_any_call("validate")
        mock_callback.assert_any_call("reject")

    def test_no_callback_no_error(self, toolbar: WorkflowToolbar) -> None:
        """Тест что нажатие без callback не вызывает ошибок."""
        toolbar.set_available_actions({"save_draft"})
        button = toolbar.get_button("save_draft")
        assert button is not None

        # Не должно вызывать ошибок
        button.invoke()

    def test_callback_replacement(self, toolbar: WorkflowToolbar) -> None:
        """Тест замены callback."""
        first = MagicMock()
        second = MagicMock()

        toolbar.on_action(first)
        toolbar.set_available_actions({"save_draft"})
        toolbar.get_button("save_draft").invoke()  # type: ignore[union-attr]
        first.assert_called_once()

        toolbar.on_action(second)
        toolbar.get_button("save_draft").invoke()  # type: ignore[union-attr]
        assert second.call_count == 1
        assert first.call_count == 1  # Не вызвался второй раз


class TestWorkflowToolbarState:
    """Тесты управления состоянием формы."""

    def test_set_current_state(self, toolbar: WorkflowToolbar) -> None:
        """Тест установки текущего состояния."""
        toolbar.set_current_state(FormStatus.DRAFT)
        assert toolbar.get_current_state() == FormStatus.DRAFT

    def test_set_current_state_signed(self, toolbar: WorkflowToolbar) -> None:
        """Тест установки состояния SIGNED."""
        toolbar.set_current_state(FormStatus.SIGNED)
        assert toolbar.get_current_state() == FormStatus.SIGNED

    def test_default_state_none(self, toolbar: WorkflowToolbar) -> None:
        """Тест что по умолчанию состояние None."""
        assert toolbar.get_current_state() is None

    def test_state_change(self, toolbar: WorkflowToolbar) -> None:
        """Тест изменения состояния."""
        toolbar.set_current_state(FormStatus.DRAFT)
        toolbar.set_current_state(FormStatus.VALIDATED)
        assert toolbar.get_current_state() == FormStatus.VALIDATED


class TestWorkflowToolbarColors:
    """Тесты цветов кнопок."""

    def test_button_colors(self, toolbar: WorkflowToolbar) -> None:
        """Тест что кнопки имеют заданный цвет из темы (fallback в тестах)."""
        for action in toolbar.get_available_actions():
            button = toolbar.get_button(action)
            assert button is not None
            bg = button.cget("bg")
            assert bg.startswith("#") and len(bg) == 7

    def test_button_text_color(self, toolbar: WorkflowToolbar) -> None:
        """Тест цвета текста кнопок."""
        for action in toolbar.get_available_actions():
            button = toolbar.get_button(action)
            assert button is not None
            assert button.cget("fg") == "white"

    def test_lighten_color(self) -> None:
        """Тест осветления цвета."""
        result = _lighten_color("#3498db")
        assert result.startswith("#")
        assert len(result) == 7
        # Осветлённый цвет должен быть ближе к белому
        r = int(result[1:3], 16)
        g = int(result[3:5], 16)
        b = int(result[5:7], 16)
        assert r >= int("34", 16)
        assert g >= int("98", 16)
        assert b >= int("db", 16)

    def test_lighten_color_clamping(self) -> None:
        """ТEST что _lighten_color ограничивает значения 255."""
        result = _lighten_color("#ffffff", factor=1.2)
        assert result == "#ffffff"


class TestWorkflowToolbarLifecycle:
    """Тесты жизненного цикла."""

    def test_destroy_clears_callback(
        self, root: tk.Tk, mock_callback: MagicMock
    ) -> None:
        """Тест что destroy очищает callback."""
        toolbar = WorkflowToolbar(parent=root)
        toolbar.on_action(mock_callback)
        toolbar.destroy()

        # После destroy callback должен быть очищен
        assert toolbar._action_callback is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
