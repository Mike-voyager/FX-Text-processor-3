"""Unit-тесты для фабрики виджетов.

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

import pytest
from src.gui.factories.widget_factory import (
    create_button,
    create_combobox,
    create_entry,
    create_frame,
    create_label,
    create_progressbar,
    create_scrollbar,
    create_separator,
    create_spacer,
    create_treeview,
)


@pytest.fixture
def callback() -> Any:
    """Возвращает dummy callback."""

    def _cb() -> None:
        pass

    return _cb


class TestCreateButton:
    """Тесты для create_button."""

    def test_returns_tk_button(self, tk_root: tk.Tk, callback: Any) -> None:
        btn = create_button(tk_root, text="Test", command=callback)
        assert isinstance(btn, tk.Button)
        assert btn.cget("text") == "Test"

    def test_kwargs_override(self, tk_root: tk.Tk, callback: Any) -> None:
        btn = create_button(tk_root, text="T", command=callback, bg="#123456")
        assert btn.cget("bg") == "#123456"


class TestCreateLabel:
    """Тесты для create_label."""

    def test_returns_tk_label(self, tk_root: tk.Tk) -> None:
        lbl = create_label(tk_root, text="Hello")
        assert isinstance(lbl, tk.Label)
        assert lbl.cget("text") == "Hello"

    def test_kwargs_override(self, tk_root: tk.Tk) -> None:
        lbl = create_label(tk_root, text="T", fg="#ABCDEF")
        assert lbl.cget("fg") == "#ABCDEF"


class TestCreateEntry:
    """Тесты для create_entry."""

    def test_returns_tk_entry(self, tk_root: tk.Tk) -> None:
        entry = create_entry(tk_root)
        assert isinstance(entry, tk.Entry)

    def test_kwargs_override(self, tk_root: tk.Tk) -> None:
        entry = create_entry(tk_root, width=50)
        assert entry.cget("width") == 50  # type: ignore[comparison-overlap]


class TestCreateFrame:
    """Тесты для create_frame."""

    def test_returns_tk_frame(self, tk_root: tk.Tk) -> None:
        frame = create_frame(tk_root)
        assert isinstance(frame, tk.Frame)

    def test_kwargs_override(self, tk_root: tk.Tk) -> None:
        frame = create_frame(tk_root, width=100)
        assert frame.cget("width") == 100  # type: ignore[comparison-overlap]


class TestCreateScrollbar:
    """Тесты для create_scrollbar."""

    def test_returns_ttk_scrollbar(self, tk_root: tk.Tk) -> None:
        sb = create_scrollbar(tk_root)
        assert isinstance(sb, ttk.Scrollbar)


class TestCreateTreeview:
    """Тесты для create_treeview."""

    def test_returns_ttk_treeview(self, tk_root: tk.Tk) -> None:
        tv = create_treeview(tk_root)
        assert isinstance(tv, ttk.Treeview)


class TestCreateCombobox:
    """Тесты для create_combobox."""

    def test_returns_ttk_combobox(self, tk_root: tk.Tk) -> None:
        cb = create_combobox(tk_root, values=("a", "b", "c"))
        assert isinstance(cb, ttk.Combobox)
        assert cb.cget("values") == ("a", "b", "c")


class TestCreateSeparator:
    """Тесты для create_separator."""

    def test_returns_ttk_separator(self, tk_root: tk.Tk) -> None:
        sep = create_separator(tk_root)
        assert isinstance(sep, ttk.Separator)

    def test_orient_vertical(self, tk_root: tk.Tk) -> None:
        sep = create_separator(tk_root, orient="vertical")
        assert isinstance(sep, ttk.Separator)


class TestCreateProgressbar:
    """Тесты для create_progressbar."""

    def test_returns_ttk_progressbar(self, tk_root: tk.Tk) -> None:
        pb = create_progressbar(tk_root, length=200)
        assert isinstance(pb, ttk.Progressbar)


class TestCreateSpacer:
    """Тесты для create_spacer."""

    def test_returns_tk_frame(self, tk_root: tk.Tk) -> None:
        sp = create_spacer(tk_root, width=20)
        assert isinstance(sp, tk.Frame)
        assert sp.cget("width") == 20  # type: ignore[comparison-overlap]

    def test_default_width(self, tk_root: tk.Tk) -> None:
        sp = create_spacer(tk_root)
        assert sp.cget("width") == 10  # type: ignore[comparison-overlap]
