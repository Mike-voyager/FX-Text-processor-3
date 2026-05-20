# -*- coding: utf-8 -*-
"""Тесты для RoleSwitchDialog.

Тестирует создание диалога смены роли, отображение опций,
переключение free mode и формирование результата.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

TKINTER_AVAILABLE = False
RoleSwitchDialog: Any = None
try:
    import tkinter as tk

    from src.gui.dialogs.role_switch_dialog import (
        COLOR_BG,
        COLOR_FREE_MODE_BG,
        COLOR_FREE_MODE_BORDER,
        DIALOG_HEIGHT,
        DIALOG_WIDTH,
        MIN_DIALOG_HEIGHT,
        MIN_DIALOG_WIDTH,
        RoleSwitchDialog,
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


class TestRoleSwitchDialog:
    """Тесты для RoleSwitchDialog."""

    def test_constants(self) -> None:
        """Тест констант диалога."""
        assert DIALOG_WIDTH == 450
        assert DIALOG_HEIGHT == 400
        assert MIN_DIALOG_WIDTH == 380
        assert MIN_DIALOG_HEIGHT == 350

    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_role_selector")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_current_role_section")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_free_mode_section")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._update_ui_state")
    def test_init_with_defaults(
        self,
        mock_update_ui: MagicMock,
        mock_free: MagicMock,
        mock_current: MagicMock,
        mock_selector: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест инициализации диалога с параметрами по умолчанию."""
        mock_role = MagicMock()
        mock_role.value = "operator"
        dialog = RoleSwitchDialog(parent=root, current_role=mock_role)
        assert dialog._free_mode is False
        assert dialog._result is None
        dialog.destroy()

    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_role_selector")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_current_role_section")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_free_mode_section")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._update_ui_state")
    def test_init_with_free_mode(
        self,
        mock_update_ui: MagicMock,
        mock_free: MagicMock,
        mock_current: MagicMock,
        mock_selector: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест инициализации с включённым free mode."""
        mock_role = MagicMock()
        mock_role.value = "operator"
        dialog = RoleSwitchDialog(
            parent=root,
            current_role=mock_role,
            free_mode_enabled=True,
        )
        assert dialog._free_mode is True
        dialog.destroy()

    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_role_selector")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_current_role_section")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._create_free_mode_section")
    @patch("src.gui.dialogs.role_switch_dialog.RoleSwitchDialog._update_ui_state")
    def test_on_cancel_sets_result_none(
        self,
        mock_update_ui: MagicMock,
        mock_free: MagicMock,
        mock_current: MagicMock,
        mock_selector: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест что отмена устанавливает результат в None."""
        mock_role = MagicMock()
        mock_role.value = "operator"
        dialog = RoleSwitchDialog(parent=root, current_role=mock_role)
        dialog._on_cancel()
        assert dialog._result is None