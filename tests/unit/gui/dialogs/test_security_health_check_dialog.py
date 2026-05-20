# -*- coding: utf-8 -*-
"""Тесты для SecurityHealthCheckDialog.

Тестирует создание диалога, цепочку проверок,
обновление статусов и результат.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

TKINTER_AVAILABLE = False
SecurityHealthCheckDialog: Any = None
try:
    import tkinter as tk

    from src.gui.dialogs.security_health_check_dialog import (
        COLOR_FAIL,
        COLOR_LOADING,
        COLOR_PASS,
        COLOR_WARNING,
        SecurityHealthCheckDialog,
        _CHECK_ITEMS,
        _COLOR_FAIL,
        _COLOR_LOADING,
        _COLOR_NEUTRAL,
        _COLOR_PASS,
        _COLOR_WARNING,
        _ICON_FAIL,
        _ICON_LOADING,
        _ICON_PASS,
        _ICON_PENDING,
        _ICON_WARNING,
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


class TestSecurityHealthCheckDialog:
    """Тесты для SecurityHealthCheckDialog."""

    def test_check_items_count(self) -> None:
        """Тест количества проверок."""
        assert len(_CHECK_ITEMS) == 6

    def test_check_items_names(self) -> None:
        """Тест имён проверок."""
        names = [name for name, _ in _CHECK_ITEMS]
        assert "entropy" in names
        assert "keystore" in names
        assert "hardware" in names
        assert "audit" in names
        assert "algorithms" in names
        assert "config" in names

    def test_icon_constants(self) -> None:
        """Тест констант иконок."""
        assert _ICON_PASS
        assert _ICON_FAIL
        assert _ICON_LOADING
        assert _ICON_PENDING
        assert _ICON_WARNING

    def test_init_without_health_checker(self, root: tk.Tk) -> None:
        """Тест инициализации без HealthChecker."""
        dialog = SecurityHealthCheckDialog(parent=root, health_checker=None)
        assert dialog._health_checker is None
        assert dialog._running is True
        dialog.destroy()

    def test_init_with_health_checker(self, root: tk.Tk) -> None:
        """Тест инициализации с HealthChecker."""
        mock_checker = MagicMock()
        dialog = SecurityHealthCheckDialog(parent=root, health_checker=mock_checker)
        assert dialog._health_checker is mock_checker
        dialog.destroy()

    def test_on_cancel(self, root: tk.Tk) -> None:
        """Тест отмены диалога."""
        dialog = SecurityHealthCheckDialog(parent=root, health_checker=None)
        dialog._on_cancel()
        assert dialog._running is False
        dialog.destroy()

    def test_on_enter(self, root: tk.Tk) -> None:
        """Тест кнопки Enter Special Mode."""
        dialog = SecurityHealthCheckDialog(parent=root, health_checker=None)
        dialog._on_enter()
        assert dialog._running is False
        dialog.destroy()