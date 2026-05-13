# -*- coding: utf-8 -*-
"""Тесты для SpecialCharacterDialog.

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

try:
    import tkinter as tk
    from tkinter import ttk
    from src.gui.dialogs.special_character_dialog import (
        SpecialCharResult,
        SpecialCharacterDialog,
    )
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Создаёт real Tk окно для GUI тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestSpecialCharacterDialogCreation:
    """Тесты создания SpecialCharacterDialog."""

    def test_dialog_creation(self, root: tk.Tk) -> None:
        """Проверка создания диалога."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            assert dialog._parent is root
            assert dialog._selected_char == ""
            assert dialog._status_label is not None
        finally:
            dialog.destroy()

    def test_dialog_title(self, root: tk.Tk) -> None:
        """Проверка заголовка диалога."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            assert dialog.title() == "Специальные символы"
        finally:
            dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestSpecialCharacterDialogTabs:
    """Тесты вкладок диалога."""

    def test_notebook_has_pc866_tab(self, root: tk.Tk) -> None:
        """Проверка наличия вкладки PC866 Cyrillic."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            assert dialog._notebook is not None
            tab_texts = [
                dialog._notebook.tab(tab_id, option="text")
                for tab_id in dialog._notebook.tabs()  # type: ignore[no-untyped-call]
            ]
            assert "PC866 Cyrillic" in tab_texts
        finally:
            dialog.destroy()

    def test_notebook_has_box_drawing_tab(self, root: tk.Tk) -> None:
        """Проверка наличия вкладки Box Drawing."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            assert dialog._notebook is not None
            tab_texts = [
                dialog._notebook.tab(tab_id, option="text")
                for tab_id in dialog._notebook.tabs()  # type: ignore[no-untyped-call]
            ]
            assert "Box Drawing" in tab_texts
        finally:
            dialog.destroy()

    def test_notebook_has_math_tab(self, root: tk.Tk) -> None:
        """Проверка наличия вкладки Math & Symbols."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            assert dialog._notebook is not None
            tab_texts = [
                dialog._notebook.tab(tab_id, option="text")
                for tab_id in dialog._notebook.tabs()  # type: ignore[no-untyped-call]
            ]
            assert "Math & Symbols" in tab_texts
        finally:
            dialog.destroy()

    def test_notebook_has_typography_tab(self, root: tk.Tk) -> None:
        """Проверка наличия вкладки Typography."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            assert dialog._notebook is not None
            tab_texts = [
                dialog._notebook.tab(tab_id, option="text")
                for tab_id in dialog._notebook.tabs()  # type: ignore[no-untyped-call]
            ]
            assert "Typography" in tab_texts
        finally:
            dialog.destroy()

    def test_esc_p_tab_hidden_by_default(self, root: tk.Tk) -> None:
        """Проверка что ESC/P Controls скрыты по умолчанию."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            assert dialog.is_esc_tab_visible() is False
        finally:
            dialog.destroy()

    def test_esc_p_tab_shown_when_debug_enabled(self, root: tk.Tk) -> None:
        """Проверка отображения ESC/P Controls при initial_debug=True."""
        dialog = SpecialCharacterDialog(parent=root, initial_debug=True)
        try:
            assert dialog.is_esc_tab_visible() is True
        finally:
            dialog.destroy()

    def test_debug_toggle_show(self, root: tk.Tk) -> None:
        """Проверка включения debug-вкладки."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            dialog._debug_var.set(True)
            dialog._on_debug_toggle()
            assert dialog.is_esc_tab_visible() is True
        finally:
            dialog.destroy()

    def test_debug_toggle_hide(self, root: tk.Tk) -> None:
        """Проверка скрытия debug-вкладки."""
        dialog = SpecialCharacterDialog(parent=root, initial_debug=True)
        try:
            dialog._debug_var.set(False)
            dialog._on_debug_toggle()
            assert dialog.is_esc_tab_visible() is False
        finally:
            dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestSpecialCharacterDialogSelection:
    """Тесты выбора символа."""

    def test_char_selection_updates_status(self, root: tk.Tk) -> None:
        """Проверка обновления статуса при выборе символа."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            dialog._on_char_selected("Ё", "PC866 Cyrillic", "Cyrillic Ё", False)
            assert dialog._selected_char == "Ё"
            assert dialog._selected_category == "PC866 Cyrillic"
            assert dialog._selected_is_control is False
            assert dialog._status_label is not None
            text = dialog._status_label.cget("text")
            assert "Ё" in text
            assert "Cyrillic Ё" in text
        finally:
            dialog.destroy()

    def test_control_selection_updates_status(self, root: tk.Tk) -> None:
        """Проверка обновления статуса при выборе ESC/P control."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            dialog._on_char_selected("\x1b@", "ESC/P Controls", "Initialize", True)
            assert dialog._selected_char == "\x1b@"
            assert dialog._selected_is_control is True
            assert dialog._status_label is not None
            text = dialog._status_label.cget("text")
            assert "Initialize" in text
            assert "0x1B" in text
        finally:
            dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestSpecialCharacterDialogResult:
    """Тесты результата диалога."""

    def test_ok_without_selection_returns_none(self, root: tk.Tk) -> None:
        """Проверка что OK без выбора возвращает None."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            dialog._selected_char = ""
            dialog._on_ok()
            assert dialog.get_result() is None
        finally:
            dialog.destroy()

    def test_ok_with_selection_returns_result(self, root: tk.Tk) -> None:
        """Проверка что OK с выбором возвращает SpecialCharResult."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            dialog._selected_char = "°"
            dialog._selected_category = "Math & Symbols"
            dialog._selected_is_control = False
            dialog._on_ok()
            result = dialog.get_result()
            assert isinstance(result, SpecialCharResult)
            assert result.char == "°"
            assert result.category == "Math & Symbols"
            assert result.is_control is False
        finally:
            dialog.destroy()

    def test_cancel_returns_none(self, root: tk.Tk) -> None:
        """Проверка что Отмена возвращает None."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            dialog._selected_char = "°"
            dialog._on_cancel()
            assert dialog.get_result() is None
        finally:
            dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestSpecialCharacterDialogDataClasses:
    """Тесты dataclass SpecialCharResult."""

    def test_result_creation(self) -> None:
        """Проверка создания SpecialCharResult."""
        result = SpecialCharResult(char="°", category="Math", is_control=False)
        assert result.char == "°"
        assert result.category == "Math"
        assert result.is_control is False

    def test_result_default_is_control(self) -> None:
        """Проверка значения is_control по умолчанию."""
        result = SpecialCharResult(char="X", category="Test")
        assert result.is_control is False

    def test_result_is_frozen(self) -> None:
        """Проверка immutability SpecialCharResult."""
        result = SpecialCharResult(char="X", category="Test")
        with pytest.raises(AttributeError):
            result.char = "Y"  # type: ignore[misc]


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestSpecialCharacterDialogShow:
    """Тесты метода show()."""

    @patch.object(SpecialCharacterDialog, "wait_window")
    @patch.object(SpecialCharacterDialog, "wait_visibility")
    @patch.object(SpecialCharacterDialog, "deiconify")
    def test_show_returns_none_on_cancel(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_wait: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Проверка что show() возвращает None при отмене."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            dialog._result = None
            result = dialog.show()
            assert result is None
        finally:
            dialog.destroy()

    @patch.object(SpecialCharacterDialog, "wait_window")
    @patch.object(SpecialCharacterDialog, "wait_visibility")
    @patch.object(SpecialCharacterDialog, "deiconify")
    def test_show_returns_result_on_ok(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_wait: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Проверка что show() возвращает SpecialCharResult при OK."""
        dialog = SpecialCharacterDialog(parent=root)
        try:
            expected = SpecialCharResult(
                char="Ё", category="PC866 Cyrillic", is_control=False,
            )
            dialog._result = expected
            result = dialog.show()
            assert isinstance(result, SpecialCharResult)
            assert result.char == "Ё"
            assert result.category == "PC866 Cyrillic"
        finally:
            dialog.destroy()


__all__ = [
    "TestSpecialCharacterDialogCreation",
    "TestSpecialCharacterDialogTabs",
    "TestSpecialCharacterDialogSelection",
    "TestSpecialCharacterDialogResult",
    "TestSpecialCharacterDialogDataClasses",
    "TestSpecialCharacterDialogShow",
]
