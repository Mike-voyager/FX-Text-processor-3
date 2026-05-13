"""Tests for FieldPalette.

Tests drag-and-drop functionality and field type management.
"""

from __future__ import annotations

import tkinter as tk

import pytest

from src.view.form_designer.field_palette import FieldPalette


@pytest.fixture
def root():
    """Create a Tk root window for tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def palette(root):
    """Create a FieldPalette instance."""
    palette = FieldPalette(root, theme="classic_green")
    yield palette


class TestFieldPalette:
    """Test suite for FieldPalette."""

    def test_initialization(self, root):
        """Test palette initialization."""
        palette = FieldPalette(root, theme="classic_green")
        
        assert palette._theme == "classic_green"
        assert palette._drag_type is None
        
        # Check all field types are loaded
        assert len(palette._items) == len(palette.FIELD_TYPES)

    def test_field_types_count(self, palette):
        """Test all field types are present."""
        assert len(palette.FIELD_TYPES) == 12
        
        expected_types = [
            "TEXT_INPUT",
            "NUMBER_INPUT",
            "DATE_INPUT",
            "DROPDOWN",
            "CHECKBOX",
            "RADIO_GROUP",
            "TABLE",
            "CALCULATED",
            "SIGNATURE",
            "STAMP",
            "BARCODE",
            "QR",
        ]
        
        actual_types = [ft[0] for ft in palette.FIELD_TYPES]
        assert actual_types == expected_types

    def test_field_type_icons(self, palette):
        """Test field types have icons."""
        icons = [ft[1] for ft in palette.FIELD_TYPES]
        
        # Check all icons are non-empty
        for icon in icons:
            assert len(icon) > 0

    def test_field_type_labels(self, palette):
        """Test field types have labels."""
        labels = [ft[2] for ft in palette.FIELD_TYPES]
        
        # Check all labels are non-empty and in Russian
        for label in labels:
            assert len(label) > 0
            # Check for Cyrillic characters
            assert any('\u0400' <= c <= '\u04FF' for c in label)

    def test_highlight_field_type(self, palette):
        """Test highlighting field types."""
        # Highlight TEXT_INPUT
        palette.highlight_field_type("TEXT_INPUT", True)
        
        # Unhighlight
        palette.highlight_field_type("TEXT_INPUT", False)

    def test_clear_highlight(self, palette):
        """Test clearing all highlights."""
        # Highlight multiple
        palette.highlight_field_type("TEXT_INPUT", True)
        palette.highlight_field_type("NUMBER_INPUT", True)
        
        # Clear all
        palette.clear_highlight()

    def test_get_drag_type(self, palette):
        """Test getting drag type."""
        assert palette.get_drag_type() is None
        
        # Simulate setting drag type
        palette._drag_type = "TEXT_INPUT"
        assert palette.get_drag_type() == "TEXT_INPUT"

    def test_get_frame(self, palette):
        """Test getting frame widget."""
        frame = palette.get_frame()
        assert isinstance(frame, tk.Frame)

    def test_theme_colors(self, root):
        """Test theme color loading."""
        for theme in ["classic_green", "amber", "dos_blue", "paper_white", "matrix"]:
            palette = FieldPalette(root, theme=theme)
            assert "bg" in palette._colors
            assert "fg" in palette._colors
            assert "item_bg" in palette._colors

    def test_invalid_theme_defaults(self, root):
        """Test invalid theme defaults."""
        palette = FieldPalette(root, theme="invalid_theme")
        assert palette._colors["bg"] == "#000000"  # classic_green


class TestFieldPaletteCallbacks:
    """Test suite for FieldPalette callbacks."""

    def test_drag_start_callback(self, root):
        """Test drag start callback is invoked."""
        callback_invoked = False
        callback_type = None
        
        def on_drag_start(field_type: str) -> None:
            nonlocal callback_invoked, callback_type
            callback_invoked = True
            callback_type = field_type
        
        palette = FieldPalette(root, on_drag_start=on_drag_start)
        
        # Simulate drag start
        palette._drag_type = "TEXT_INPUT"
        palette._create_drag_window(100, 100)
        
        assert callback_invoked is True
        assert callback_type == "TEXT_INPUT"
        
        # Cleanup
        if palette._drag_window:
            palette._drag_window.destroy()

    def test_drag_window_creation(self, root):
        """Test drag window is created during drag."""
        palette = FieldPalette(root)
        
        assert palette._drag_window is None
        
        # Simulate drag
        palette._drag_type = "TEXT_INPUT"
        palette._create_drag_window(100, 100)
        
        assert palette._drag_window is not None
        
        # Cleanup
        palette._drag_window.destroy()
        palette._drag_window = None
