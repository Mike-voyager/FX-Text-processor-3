# -*- coding: utf-8 -*-
"""Тесты для SettingsDialog.

Тестирует создание диалога настроек, инициализацию полей,
валидацию и формирование результата.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

TKINTER_AVAILABLE = False
SettingsDialog: Any = None
try:
    import tkinter as tk

    from src.gui.dialogs.settings_dialog import (
        DEFAULT_AUTO_SAVE,
        DEFAULT_PAPER_SIZE,
        DEFAULT_THEME,
        SettingsDialog,
    )

    TKINTER_AVAILABLE = True
except (ImportError, AttributeError, OSError, RuntimeError):
    pass


pytestmark = pytest.mark.skipif(
    not TKINTER_AVAILABLE,
    reason="Tkinter недоступен",
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Создаёт Tk root для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestSettingsDialog:
    """Тесты для SettingsDialog."""

    def test_constants(self) -> None:
        """Тест констант по умолчанию."""
        assert DEFAULT_AUTO_SAVE == 5
        assert DEFAULT_THEME == "classic_green"
        assert DEFAULT_PAPER_SIZE == "A4"

    @patch("src.gui.dialogs.settings_dialog.ThemeRegistry")
    @patch("src.gui.dialogs.settings_dialog.PaperSize")
    def test_init_with_defaults(
        self,
        mock_paper: MagicMock,
        mock_theme: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест инициализации с настройками по умолчанию."""
        mock_theme.get_instance().list_themes.return_value = ["classic_green"]
        mock_paper.__iter__ = lambda self: iter([])
        dialog = SettingsDialog(parent=root)
        assert dialog._settings == {}
        dialog.destroy()

    @patch("src.gui.dialogs.settings_dialog.ThemeRegistry")
    @patch("src.gui.dialogs.settings_dialog.PaperSize")
    def test_init_with_custom_settings(
        self,
        mock_paper: MagicMock,
        mock_theme: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест инициализации с пользовательскими настройками."""
        mock_theme.get_instance().list_themes.return_value = ["classic_green"]
        mock_paper.__iter__ = lambda self: iter([])
        settings = {"auto_save_interval": 10, "theme": "dark"}
        dialog = SettingsDialog(parent=root, current_settings=settings)
        assert dialog._settings.get("auto_save_interval") == 10
        dialog.destroy()

    @patch("src.gui.dialogs.settings_dialog.ThemeRegistry")
    @patch("src.gui.dialogs.settings_dialog.PaperSize")
    def test_on_cancel(
        self,
        mock_paper: MagicMock,
        mock_theme: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест отмены диалога."""
        mock_theme.get_instance().list_themes.return_value = ["classic_green"]
        mock_paper.__iter__ = lambda self: iter([])
        dialog = SettingsDialog(parent=root)
        dialog._on_cancel()
        dialog.destroy()