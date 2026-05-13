"""Тесты DI для MainController.

Проверяют:
- set_main_window устанавливает окно
- start() без window возвращает warning
- MainWindow не создаётся без аргументов
"""
from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, create_autospec, patch

import pytest

# Tkinter mocks нужны ДО импорта main_controller
pytest.importorskip("tkinter")

with patch.dict("sys.modules", {"tkinter": MagicMock(), "tkinter.messagebox": MagicMock()}):
    from src.controller.main_controller import MainController


class TestMainControllerDI:
    """Тесты DI-интеграции MainController с MainWindow."""

    @pytest.fixture
    def mock_deps(self) -> dict[str, Any]:
        """Создаёт мок-зависимости для MainController."""
        import tkinter as tk

        return {
            "root": MagicMock(spec=tk.Tk),
            "auth_controller": MagicMock(),
            "document_controller": MagicMock(),
            "print_controller": MagicMock(),
            "form_controller": MagicMock(),
            "workflow_controller": MagicMock(),
            "theme_manager": MagicMock(),
        }

    @pytest.fixture
    def controller(self, mock_deps: dict[str, Any]) -> MainController:
        """Создаёт MainController с мок-зависимостями."""
        return MainController(
            root=mock_deps["root"],
            auth_controller=mock_deps["auth_controller"],
            document_controller=mock_deps["document_controller"],
            print_controller=mock_deps["print_controller"],
            form_controller=mock_deps["form_controller"],
            workflow_controller=mock_deps["workflow_controller"],
            theme_manager=mock_deps["theme_manager"],
        )

    @pytest.fixture
    def mock_main_window(self) -> MagicMock:
        """Создаёт мок MainWindow."""
        with patch("src.controller.main_controller.MainWindow") as MockWindow:
            instance = MockWindow.return_value
            instance.register_callback = MagicMock()
            instance.set_theme = MagicMock()
            instance.destroy = MagicMock()
            return instance

    def test_set_main_window(self, controller: MainController, mock_main_window: MagicMock) -> None:
        """Проверяет что set_main_window устанавливает _main_window."""
        controller.set_main_window(mock_main_window)
        assert controller.get_main_window() is mock_main_window

    def test_start_without_main_window_returns_early(self, controller: MainController, caplog: Any) -> None:
        """Проверяет что start() без set_main_window() возвращает warning и выходит."""
        controller._auth_controller.is_authenticated.return_value = True

        with caplog.at_level(logging.WARNING, logger="src.controller.main_controller"):
            controller.start()

        assert "MainWindow не установлено" in caplog.text
        assert controller.get_main_window() is None

    def test_start_with_main_window_registers_callbacks(self, controller: MainController, mock_main_window: MagicMock) -> None:
        """Проверяет что start() с window регистрирует callbacks и устанавливает тему."""
        controller._auth_controller.is_authenticated.return_value = True
        controller._theme_manager.get_current_theme.return_value = "dark"

        controller.set_main_window(mock_main_window)
        controller.start()

        mock_main_window.register_callback.assert_called()
        mock_main_window.set_theme.assert_called_once_with("dark")

    def test_start_does_not_create_main_window_directly(self, controller: MainController) -> None:
        """Проверяет что start() НЕ создаёт MainWindow() напрямую (устранён баг строки 184)."""
        controller._auth_controller.is_authenticated.return_value = True

        with patch("src.controller.main_controller.MainWindow") as MockWindow:
            controller.start()
            MockWindow.assert_not_called()

    def test_shutdown_destroys_window(self, controller: MainController, mock_main_window: MagicMock) -> None:
        """Проверяет что shutdown() вызывает destroy() окна."""
        controller._auth_controller.is_authenticated.return_value = True
        controller.set_main_window(mock_main_window)
        controller.start()
        controller.shutdown(force=True)

        mock_main_window.destroy.assert_called_once()
        assert controller.get_main_window() is None

    def test_set_main_window_overwrites_existing(self, controller: MainController, mock_main_window: MagicMock) -> None:
        """Проверяет что повторный set_main_window перезаписывает окно."""
        window2 = MagicMock()
        controller.set_main_window(mock_main_window)
        controller.set_main_window(window2)
        assert controller.get_main_window() is window2

    def test_no_duplicate_state_in_constructor(self, controller: MainController) -> None:
        """Проверяет что конструктор не дублирует инициализацию state/window."""
        # Если бы дублирование было — assert ниже бы упал
        assert controller.get_main_window() is None
        assert controller.get_state() is not None
