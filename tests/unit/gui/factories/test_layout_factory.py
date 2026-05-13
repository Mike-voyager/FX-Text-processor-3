"""Unit-тесты для фабрики layout patterns.

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from src.gui.factories.layout_factory import (
    create_horizontal_divider,
    create_labeled_frame,
    create_padded_frame,
    create_scrollable_frame,
    pack_form_row,
    pack_toolbar,
)


class TestCreatePaddedFrame:
    """Тесты для create_padded_frame."""

    def test_returns_tk_frame(self, tk_root: tk.Tk) -> None:
        frame = create_padded_frame(tk_root, padding=20)
        assert isinstance(frame, tk.Frame)

    def test_padding_applied(self, tk_root: tk.Tk) -> None:
        frame = create_padded_frame(tk_root, padding=15)
        assert frame.cget("padx") == 15  # type: ignore[comparison-overlap]
        assert frame.cget("pady") == 15  # type: ignore[comparison-overlap]


class TestCreateHorizontalDivider:
    """Тесты для create_horizontal_divider."""

    def test_returns_ttk_separator(self, tk_root: tk.Tk) -> None:
        sep = create_horizontal_divider(tk_root)
        assert isinstance(sep, ttk.Separator)


class TestCreateScrollableFrame:
    """Тесты для create_scrollable_frame."""

    def test_returns_tuple(self, tk_root: tk.Tk) -> None:
        result = create_scrollable_frame(tk_root)
        assert isinstance(result, tuple)
        assert len(result) == 3
        outer, canvas, inner = result
        assert isinstance(outer, tk.Frame)
        assert isinstance(canvas, tk.Canvas)
        assert isinstance(inner, tk.Frame)

    def test_inner_frame_inside_canvas(self, tk_root: tk.Tk) -> None:
        outer, canvas, inner = create_scrollable_frame(tk_root)
        canvas.pack()
        inner.update_idletasks()
        assert inner.winfo_exists()


class TestCreateLabeledFrame:
    """Тесты для create_labeled_frame."""

    def test_returns_label_frame(self, tk_root: tk.Tk) -> None:
        lf = create_labeled_frame(tk_root, label_text="Section")
        assert isinstance(lf, tk.LabelFrame)
        assert lf.cget("text") == "Section"


class TestPackToolbar:
    """Тесты для pack_toolbar."""

    def test_widgets_packed(self, tk_root: tk.Tk) -> None:
        parent = tk.Frame(tk_root)
        btn1 = tk.Button(parent, text="A")
        btn2 = tk.Button(parent, text="B")
        pack_toolbar(parent, btn1, btn2)
        assert btn1.winfo_manager() == "pack"
        assert btn2.winfo_manager() == "pack"


class TestPackFormRow:
    """Тесты для pack_form_row."""

    def test_widgets_packed(self, tk_root: tk.Tk) -> None:
        parent = tk.Frame(tk_root)
        lbl = tk.Label(parent, text="Name")
        entry = tk.Entry(parent)
        pack_form_row(parent, lbl, entry)
        assert lbl.winfo_manager() == "pack"
        assert entry.winfo_manager() == "pack"

    def test_kwargs_passed(self, tk_root: tk.Tk) -> None:
        parent = tk.Frame(tk_root)
        lbl = tk.Label(parent, text="E")
        entry = tk.Entry(parent)
        pack_form_row(parent, lbl, entry, padx=10, pady=5)
        # Ensure pack worked (no exception)
        assert lbl.winfo_manager() == "pack"
