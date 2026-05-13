"""Unit-тесты для фабрики тем.

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk

import pytest
from src.gui.factories.theme_factory import (
    ThemeColors,
    apply_theme_to_widget,
    create_themed_button,
    get_theme_colors,
)
from src.gui.themes import ThemeNotFoundError


class TestThemeColors:
    """Тесты для ThemeColors dataclass."""

    def test_frozen(self) -> None:
        tc = ThemeColors(
            bg="#000",
            fg="#fff",
            accent="#0f0",
            error="#f00",
            warning="#ff0",
            success="#0f0",
        )
        with pytest.raises(AttributeError):
            tc.bg = "#111"  # type: ignore[misc]


class TestGetThemeColors:
    """Тесты для get_theme_colors."""

    def test_default_theme(self) -> None:
        colors = get_theme_colors("default")
        assert isinstance(colors, ThemeColors)
        assert colors.bg.startswith("#")

    def test_specific_theme(self) -> None:
        colors = get_theme_colors("classic_green")
        assert colors.bg == "#000000"
        assert colors.fg == "#00FF00"

    def test_invalid_theme(self) -> None:
        with pytest.raises(ThemeNotFoundError):
            get_theme_colors("this_theme_does_not_exist_12345")


class TestApplyThemeToWidget:
    """Тесты для apply_theme_to_widget."""

    def test_applies_colors(self, tk_root: tk.Tk) -> None:
        label = tk.Label(tk_root)
        colors = ThemeColors(
            bg="#111111",
            fg="#222222",
            accent="#333333",
            error="#444444",
            warning="#555555",
            success="#666666",
        )
        apply_theme_to_widget(label, colors)
        assert label.cget("bg") == "#111111"
        assert label.cget("fg") == "#222222"

    def test_no_exception_on_widget_without_configure(self) -> None:
        colors = ThemeColors(
            bg="#111",
            fg="#222",
            accent="#333",
            error="#444",
            warning="#555",
            success="#666",
        )
        apply_theme_to_widget(tk.Tk(), colors)


class TestCreateThemedButton:
    """Тесты для create_themed_button."""

    def test_primary_variant(self, tk_root: tk.Tk) -> None:
        btn = create_themed_button(tk_root, text="Go", variant="primary")
        assert isinstance(btn, tk.Button)
        assert btn.cget("text") == "Go"

    def test_secondary_variant(self, tk_root: tk.Tk) -> None:
        btn = create_themed_button(tk_root, text="Cancel", variant="secondary")
        assert isinstance(btn, tk.Button)

    def test_danger_variant(self, tk_root: tk.Tk) -> None:
        btn = create_themed_button(tk_root, text="Delete", variant="danger")
        assert isinstance(btn, tk.Button)

    def test_success_variant(self, tk_root: tk.Tk) -> None:
        btn = create_themed_button(tk_root, text="Done", variant="success")
        assert isinstance(btn, tk.Button)

    def test_ghost_variant(self, tk_root: tk.Tk) -> None:
        btn = create_themed_button(tk_root, text="Link", variant="ghost")
        assert isinstance(btn, tk.Button)
        assert btn.cget("relief") == tk.FLAT
        assert btn.cget("bd") == 0  # type: ignore[comparison-overlap]

    def test_kwargs_override(self, tk_root: tk.Tk) -> None:
        btn = create_themed_button(tk_root, text="X", variant="primary", bg="#999999")
        assert btn.cget("bg") == "#999999"

    def test_invalid_variant_fallback(self, tk_root: tk.Tk) -> None:
        btn = create_themed_button(tk_root, text="X", variant="unknown")
        assert isinstance(btn, tk.Button)
