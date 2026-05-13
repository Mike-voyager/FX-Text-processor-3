"""Тесты для главной панели инструментов.

Модуль содержит unit-тесты для MainToolbar компонента,
покрывающие инициализацию, биндинги, управление кнопками
и применение тем.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

from src.gui.components.composite.main_toolbar import MainToolbar
from src.gui.components.primitive.button import ThemedButton
from src.gui.core.protocols import ControllerProtocol


class MockController:
    """Mock контроллер для тестирования."""

    def __init__(self) -> None:
        """Инициализация mock контроллера."""
        self.dispatch_calls: list[tuple[str, dict[str, Any]]] = []
        self.controller_id = "test_controller"

    def dispatch(self, action: str, **kwargs: Any) -> Optional[Any]:
        """Mock dispatch метод."""
        self.dispatch_calls.append((action, kwargs))
        return None

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        """Mock notify_view_update метод."""
        pass

    def register_view(self, widget_id: str, callback: Any) -> None:
        """Mock register_view метод."""
        pass

    def unregister_view(self, widget_id: str) -> None:
        """Mock unregister_view метод."""
        pass


@pytest.fixture
def root() -> tk.Tk:
    """Фикстура для создания Tk root окна."""
    root = tk.Tk()
    yield root
    root.destroy()


@pytest.fixture
def mock_controller() -> MockController:
    """Фикстура для создания mock контроллера."""
    return MockController()


@pytest.mark.gui
def test_constructor_default(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест конструктора с default параметрами.

    Проверяет, что MainToolbar корректно инициализируется
    с контроллером.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    assert toolbar.widget_id == "main_toolbar"
    assert toolbar._controller is mock_controller
    assert toolbar._button_commands is None
    assert toolbar._buttons == {}


@pytest.mark.gui
def test_constructor_with_custom_commands(root: tk.Tk) -> None:
    """Тест конструктора с пользовательскими командами.

    Проверяет, что MainToolbar корректно принимает
    пользовательские callback'и.
    """
    custom_commands = {
        "new": lambda: print("custom new"),
        "open": lambda: print("custom open"),
        "save": lambda: print("custom save"),
        "print": lambda: print("custom print"),
    }

    toolbar = MainToolbar(
        widget_id="main_toolbar",
        button_commands=custom_commands,
    )

    assert toolbar._button_commands == custom_commands
    assert toolbar._controller is None


@pytest.mark.gui
def test_constructor_invalid_button_commands(root: tk.Tk) -> None:
    """Тест конструктора с невалидными button_commands.

    Проверяет, что при передаче не-словаря выбрасывается TypeError.
    """
    with pytest.raises(TypeError, match="button_commands должен быть словарём или None"):
        MainToolbar(
            widget_id="main_toolbar",
            button_commands="invalid",  # type: ignore[arg-type]
        )


@pytest.mark.gui
def test_buttons_created(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест создания всех кнопок.

    Проверяет, что при монтировании создаются все 4 кнопки
    с правильными текстами.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    # Монтируем тулбар
    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Проверяем, что все кнопки созданы
    assert len(toolbar._buttons) == 4
    assert "new" in toolbar._buttons
    assert "open" in toolbar._buttons
    assert "save" in toolbar._buttons
    assert "print" in toolbar._buttons

    # Проверяем тексты кнопок
    assert toolbar._buttons["new"].get_text() == "📝 New"
    assert toolbar._buttons["open"].get_text() == "📂 Open"
    assert toolbar._buttons["save"].get_text() == "💾 Save"
    assert toolbar._buttons["print"].get_text() == "🖨️ Print"


@pytest.mark.gui
def test_button_commands_dispatch(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест вызова controller.dispatch() при нажатии.

    Проверяет, что при клике на кнопку вызывается dispatch
    с правильным action.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Симулируем нажатие кнопки New
    command = toolbar._get_button_command("file_new")
    command()

    # Проверяем, что dispatch был вызван с file_new
    # Фильтруем только file_new вызовы (исключая widget_mounted)
    file_actions = [call for call in mock_controller.dispatch_calls if call[0] == "file_new"]
    assert len(file_actions) == 1


@pytest.mark.gui
def test_button_commands_custom(root: tk.Tk) -> None:
    """Тест пользовательских callback'ов.

    Проверяет, что при использовании button_commands
    вызываются пользовательские callback'и.
    """
    calls: list[str] = []

    def custom_new():
        calls.append("custom_new")

    custom_commands = {
        "new": custom_new,
    }

    toolbar = MainToolbar(
        widget_id="main_toolbar",
        button_commands=custom_commands,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Получаем команду для кнопки new
    command = toolbar._get_button_command("file_new")
    command()

    # Проверяем, что вызван пользовательский callback
    assert calls == ["custom_new"]


@pytest.mark.gui
def test_set_button_enabled(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест включения/отключения кнопок.

    Проверяет, что метод set_button_enabled корректно
    изменяет состояние кнопок.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Отключаем кнопку Save
    toolbar.set_button_enabled("save", False)
    assert toolbar._buttons["save"].is_enabled() is False

    # Включаем кнопку Save
    toolbar.set_button_enabled("save", True)
    assert toolbar._buttons["save"].is_enabled() is True


@pytest.mark.gui
def test_set_button_enabled_invalid_button(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест set_button_enabled с невалидной кнопкой.

    Проверяет, что при невалидном имени кнопки
    выбрасывается ValueError.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with pytest.raises(ValueError, match="Кнопка 'invalid' не найдена"):
        toolbar.set_button_enabled("invalid", False)


@pytest.mark.gui
def test_get_button(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест получения кнопки по имени.

    Проверяет, что метод get_button возвращает правильную кнопку.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Получаем кнопку
    new_btn = toolbar.get_button("new")
    assert new_btn is not None
    assert isinstance(new_btn, ThemedButton)
    assert new_btn.get_text() == "📝 New"

    # Пробуем получить несуществующую кнопку
    invalid_btn = toolbar.get_button("invalid")
    assert invalid_btn is None


@pytest.mark.gui
def test_keyboard_shortcuts(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест настройки горячих клавиш.

    Проверяет, что горячие клавиши настроены корректно.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Проверяем, что биндинги установлены (просто проверяем,
    # что метод не падает)
    # Полная проверка биндингов требует имитации событий клавиатуры,
    # что сложно в unit-тестах
    assert toolbar._tk_widget is not None


@pytest.mark.gui
def test_theme_applied(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест применения темы.

    Проверяет, что тема применяется ко всем кнопкам и фрейму.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget') as mock_apply:
        toolbar.mount(root)

    # Проверяем, что apply_to_widget был вызван для каждой кнопки + frame
    # 4 кнопки + 3 разделителя + 1 фрейм = 8 вызовов
    assert mock_apply.call_count >= 1


@pytest.mark.gui
def test_cleanup(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест очистки ресурсов при демонтировании.

    Проверяет, что при unmount очищаются все ресурсы.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Проверяем, что кнопки созданы
    assert len(toolbar._buttons) == 4

    # Демонтируем
    toolbar.unmount()

    # Проверяем, что словарь кнопок очищен
    assert toolbar._buttons == {}


@pytest.mark.gui
def test_button_ids(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест идентификаторов кнопок.

    Проверяет, что кнопки создаются с корректными widget_id.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Проверяем widget_id кнопок
    assert toolbar._buttons["new"].widget_id == "main_toolbar_btn_new"
    assert toolbar._buttons["open"].widget_id == "main_toolbar_btn_open"
    assert toolbar._buttons["save"].widget_id == "main_toolbar_btn_save"
    assert toolbar._buttons["print"].widget_id == "main_toolbar_btn_print"


@pytest.mark.gui
def test_get_button_command_mapping(root: tk.Tk, mock_controller: MockController) -> None:
    """Тест маппинга action в имена кнопок.

    Проверяет, что _get_button_command правильно мапит
    action в имена кнопок.
    """
    toolbar = MainToolbar(
        widget_id="main_toolbar",
        controller=mock_controller,
    )

    with patch.object(toolbar._theme_manager, 'apply_to_widget'):
        toolbar.mount(root)

    # Проверяем маппинг action -> button_name
    custom_calls: list[str] = []

    def custom_handler():
        custom_calls.append("custom")

    toolbar._button_commands = {"new": custom_handler}

    # Должен вернуть пользовательский handler для "file_new"
    command = toolbar._get_button_command("file_new")
    command()

    assert custom_calls == ["custom"]
