"""Tests for FieldWidget.

Tests field widget rendering, selection, and positioning.
"""

from __future__ import annotations

import tkinter as tk

import pytest

from src.view.form_designer import GridSize
from src.view.form_designer.canvas import ESCPGridCanvas
from src.view.form_designer.field_widget import FieldWidget


@pytest.fixture
def root():
    """Create a Tk root window for tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def canvas(root):
    """Create an ESCPGridCanvas instance."""
    canvas = ESCPGridCanvas(root, GridSize.A4, theme="classic_green")
    yield canvas
    canvas.destroy()


class TestFieldWidget:
    """Test suite for FieldWidget."""

    def test_initialization(self):
        """Test field widget initialization."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=10, y=5, width=20, height=1)
        
        assert widget.field_id == "field1"
        assert widget.x == 10
        assert widget.y == 5
        assert widget.width == 20
        assert widget.height == 1

    def test_field_type_icons(self):
        """Test all field types have icons."""
        for field_type in FieldWidget.ICONS.keys():
            widget = FieldWidget("f1", field_type)
            assert len(widget.ICONS[field_type]) > 0

    def test_move_to_grid_position(self, canvas):
        """Test moving to grid position."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=0, y=0, width=20, height=1)
        widget.render_on_canvas(canvas)
        
        widget.move_to(10, 5)
        
        assert widget.x == 10
        assert widget.y == 5
        # Check pixel positions
        expected_x = 10 * canvas._char_width
        expected_y = 5 * canvas._char_height
        assert widget.x_px == expected_x
        assert widget.y_px == expected_y

    def test_move_to_pixel_position(self, canvas):
        """Test moving to pixel position."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=0, y=0, width=20, height=1)
        widget.render_on_canvas(canvas)
        
        widget.move_to_pixel(100, 75)
        
        assert widget.x_px == 100
        assert widget.y_px == 75

    def test_set_size(self, canvas):
        """Test setting size."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=10, y=5, width=20, height=1)
        widget.render_on_canvas(canvas)
        
        widget.set_size(30, 2)
        
        assert widget.width == 30
        assert widget.height == 2

    def test_set_selected(self, canvas):
        """Test selection state."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=10, y=5, width=20, height=1)
        widget.render_on_canvas(canvas)
        
        assert widget._is_selected is False
        
        widget.set_selected(True)
        assert widget._is_selected is True
        
        widget.set_selected(False)
        assert widget._is_selected is False

    def test_set_overlap_warning(self, canvas):
        """Test overlap warning state."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=10, y=5, width=20, height=1)
        widget.render_on_canvas(canvas)
        
        assert widget._has_overlap_warning is False
        
        widget.set_overlap_warning(True)
        assert widget._has_overlap_warning is True
        
        widget.set_overlap_warning(False)
        assert widget._has_overlap_warning is False

    def test_set_label(self, canvas):
        """Test setting label."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=10, y=5, width=20, height=1)
        widget.render_on_canvas(canvas)
        
        widget.set_label("New Label")
        
        assert widget._label == "New Label"

    def test_destroy_cleanup(self, canvas):
        """Test destroy cleans up resources."""
        widget = FieldWidget("field1", "TEXT_INPUT", x=10, y=5, width=20, height=1)
        widget.render_on_canvas(canvas)
        
        widget.destroy()
        
        assert widget._canvas is None

    def test_check_overlap_no_overlap(self):
        """Test overlap detection - no overlap."""
        widget1 = FieldWidget("f1", "TEXT_INPUT", x=0, y=0, width=10, height=1)
        widget2 = FieldWidget("f2", "TEXT_INPUT", x=20, y=0, width=10, height=1)
        
        assert widget1.check_overlap(widget2) is False
        assert widget2.check_overlap(widget1) is False

    def test_check_overlap_with_overlap(self):
        """Test overlap detection - with overlap."""
        widget1 = FieldWidget("f1", "TEXT_INPUT", x=0, y=0, width=20, height=2)
        widget2 = FieldWidget("f2", "TEXT_INPUT", x=10, y=1, width=20, height=2)
        
        assert widget1.check_overlap(widget2) is True
        assert widget2.check_overlap(widget1) is True

    def test_check_overlap_touching_not_overlap(self):
        """Test that touching edges is not overlap."""
        widget1 = FieldWidget("f1", "TEXT_INPUT", x=0, y=0, width=10, height=1)
        widget2 = FieldWidget("f2", "TEXT_INPUT", x=10, y=0, width=10, height=1)
        
        # Touching at edge - not overlapping
        assert widget1.check_overlap(widget2) is False

    def test_theme_colors(self, root, canvas):
        """Test theme color loading."""
        for theme in ["classic_green", "amber", "dos_blue", "paper_white", "matrix"]:
            widget = FieldWidget("f1", "TEXT_INPUT", theme=theme)
            assert "bg" in widget._colors
            assert "border" in widget._colors
            assert "fg" in widget._colors

    def test_all_field_types(self):
        """Test creating widgets for all field types."""
        field_types = [
            "TEXT_INPUT", "NUMBER_INPUT", "DATE_INPUT", "DROPDOWN",
            "CHECKBOX", "RADIO_GROUP", "TABLE", "CALCULATED",
            "SIGNATURE", "STAMP", "BARCODE", "QR",
        ]
        
        for field_type in field_types:
            widget = FieldWidget("f1", field_type)
            assert widget._field_type == field_type

    def test_invalid_field_type_defaults(self):
        """Test invalid field type defaults to generic icon."""
        widget = FieldWidget("f1", "INVALID_TYPE")
        
        # Should have default icon
        assert "📝" in widget.ICONS.values()
