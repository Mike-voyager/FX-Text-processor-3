"""Unit-тесты для фабрики диалогов.

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import Toplevel
from unittest.mock import patch

from src.gui.factories.dialog_factory import (
    create_choice_dialog,
    create_confirm_dialog,
    create_error_dialog,
    create_input_dialog,
    create_wait_dialog,
)


class TestCreateConfirmDialog:
    """Тесты для create_confirm_dialog."""

    def test_returns_bool_true(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.messagebox.askyesno", return_value=True):
            result = create_confirm_dialog(tk_root, "Title", "Message")
        assert result is True

    def test_returns_bool_false(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.messagebox.askyesno", return_value=False):
            result = create_confirm_dialog(tk_root, "Title", "Message")
        assert result is False


class TestCreateInputDialog:
    """Тесты для create_input_dialog."""

    def test_returns_string(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.simpledialog.askstring", return_value="hello"):
            result = create_input_dialog(tk_root, "Title", "Prompt")
        assert result == "hello"

    def test_returns_none_on_cancel(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.simpledialog.askstring", return_value=None):
            result = create_input_dialog(tk_root, "Title", "Prompt")
        assert result is None

    def test_default_value_passed(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.simpledialog.askstring", return_value="default") as mock:
            result = create_input_dialog(tk_root, "Title", "Prompt", default="default")
            assert result == "default"
            mock.assert_called_once()


class TestCreateChoiceDialog:
    """Тесты для create_choice_dialog."""

    def test_returns_valid_choice(self, tk_root: tk.Tk) -> None:
        choices = ["A", "B", "C"]
        with patch("tkinter.simpledialog.askstring", return_value="B"):
            result = create_choice_dialog(tk_root, "Title", "Pick", choices)
        assert result == "B"

    def test_returns_none_on_cancel(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.simpledialog.askstring", return_value=None):
            result = create_choice_dialog(tk_root, "Title", "Pick", ["A", "B"])
        assert result is None

    def test_returns_none_for_invalid(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.simpledialog.askstring", return_value="Z"):
            result = create_choice_dialog(tk_root, "Title", "Pick", ["A", "B"])
        assert result is None

    def test_empty_choices_returns_none(self, tk_root: tk.Tk) -> None:
        result = create_choice_dialog(tk_root, "Title", "Pick", [])
        assert result is None


class TestCreateErrorDialog:
    """Тесты для create_error_dialog."""

    def test_showerror_called(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.messagebox.showerror") as mock:
            create_error_dialog(tk_root, "Error", "Something failed")
            mock.assert_called_once()

    def test_detail_appended(self, tk_root: tk.Tk) -> None:
        with patch("tkinter.messagebox.showerror") as mock:
            create_error_dialog(tk_root, "Error", "Failed", detail="Trace...")
            _, kwargs = mock.call_args
            assert "Trace..." in kwargs.get("message", "")


class TestCreateWaitDialog:
    """Тесты для create_wait_dialog."""

    def test_returns_toplevel_and_close(self, tk_root: tk.Tk) -> None:
        window, close_fn = create_wait_dialog(tk_root, "Wait", "Loading...")
        assert isinstance(window, Toplevel)
        assert callable(close_fn)
        close_fn()
        # After destroy, window should not exist
        # Note: winfo_exists can throw TclError after destroy; just ensure callable works

    def test_close_callback(self, tk_root: tk.Tk) -> None:
        window, close_fn = create_wait_dialog(tk_root, "Wait", "Loading...")
        close_fn()
        try:
            exists = window.winfo_exists()
        except tk.TclError:
            exists = 0
        assert exists == 0
