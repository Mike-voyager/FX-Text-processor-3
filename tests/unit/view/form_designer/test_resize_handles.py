"""Tests for ResizeHandles.

Tests 8-point resize functionality with snap-to-grid.
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest

from src.view.form_designer import GridSize
from src.view.form_designer.canvas import ESCPGridCanvas
from src.view.form_designer.resize_handles import ResizeHandles


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


class TestResizeHandles:
    """Test suite for ResizeHandles."""

    def test_initialization(self, canvas):
        """Test resize handles initialization."""
        handles = ResizeHandles(canvas, "test_field")
        
        assert handles._canvas == canvas
        assert handles._field_id == "test_field"
        assert handles._is_visible is False
        assert len(handles._handles) == 0

    def test_handle_size_constant(self):
        """Test handle size constant."""
        assert ResizeHandles.HANDLE_SIZE == 6

    def test_minimum_size_constant(self):
        """Test minimum size constant."""
        assert ResizeHandles.MIN_SIZE == 1

    def test_cursors_defined(self):
        """Test all handles have cursors defined."""
        expected_handles = ["nw", "n", "ne", "e", "se", "s", "sw", "w"]
        
        for handle in expected_handles:
            assert handle in ResizeHandles.CURSORS
            assert len(ResizeHandles.CURSORS[handle]) > 0

    def test_show_creates_handles(self, canvas):
        """Test show() creates 8 handles."""
        handles = ResizeHandles(canvas, "test_field")
        
        handles.show(100, 50, 180, 30)
        
        assert len(handles._handles) == 8
        assert handles._is_visible is True

    def test_hide_removes_handles(self, canvas):
        """Test hide() removes all handles."""
        handles = ResizeHandles(canvas, "test_field")
        handles.show(100, 50, 180, 30)
        
        handles.hide()
        
        assert len(handles._handles) == 0
        assert handles._is_visible is False

    def test_update_position(self, canvas):
        """Test position update moves handles."""
        handles = ResizeHandles(canvas, "test_field")
        handles.show(100, 50, 180, 30)
        
        handles.update_position(200, 100)
        
        assert handles._x == 200
        assert handles._y == 100

    def test_update_size(self, canvas):
        """Test size update resizes handles."""
        handles = ResizeHandles(canvas, "test_field")
        handles.show(100, 50, 180, 30)
        
        handles.update_size(200, 40)
        
        assert handles._width == 200
        assert handles._height == 40

    def test_is_visible(self, canvas):
        """Test is_visible returns correct state."""
        handles = ResizeHandles(canvas, "test_field")
        
        assert handles.is_visible() is False
        
        handles.show(100, 50, 180, 30)
        assert handles.is_visible() is True
        
        handles.hide()
        assert handles.is_visible() is False

    def test_resize_callback(self, canvas):
        """Test resize callback is invoked."""
        callback_invoked = False
        callback_args = None
        
        def on_resize(x, y, width, height):
            nonlocal callback_invoked, callback_args
            callback_invoked = True
            callback_args = (x, y, width, height)
        
        handles = ResizeHandles(canvas, "test_field", on_resize=on_resize)
        handles.show(100, 50, 180, 30)
        
        # Simulate resize
        handles._on_resize(200, 100, 200, 40)
        
        assert callback_invoked is True
        assert callback_args == (200, 100, 200, 40)

    def test_resize_done_callback(self, canvas):
        """Test resize done callback snaps to grid."""
        callback_invoked = False
        callback_args = None
        
        def on_resize_done(x, y, width, height):
            nonlocal callback_invoked, callback_args
            callback_invoked = True
            callback_args = (x, y, width, height)
        
        handles = ResizeHandles(canvas, "test_field", on_resize_done=on_resize_done)
        handles.show(100, 50, 180, 30)
        
        # Simulate resize complete with snap
        handles._active_handle = "se"
        handles._drag_start = (100, 50)
        handles._original_rect = (100, 50, 180, 30)
        handles._x = 105  # Not on grid
        handles._y = 53
        handles._width = 178
        handles._height = 32
        
        event = MagicMock()
        handles._on_handle_release(event)
        
        assert callback_invoked is True
        # Values should be snapped to grid
        assert callback_args[0] % canvas._char_width == 0
        assert callback_args[1] % canvas._char_height == 0

    def test_calculate_resize_nw(self, canvas):
        """Test resize calculation for NW handle."""
        handles = ResizeHandles(canvas, "test_field")
        
        result = handles._calculate_resize(100, 50, 180, 30, 10, 5, "nw")
        
        # NW: x increases, width decreases, y increases, height decreases
        assert result == (110, 55, 170, 25)

    def test_calculate_resize_se(self, canvas):
        """Test resize calculation for SE handle."""
        handles = ResizeHandles(canvas, "test_field")
        
        result = handles._calculate_resize(100, 50, 180, 30, 20, 10, "se")
        
        # SE: width increases, height increases
        assert result == (100, 50, 200, 40)

    def test_calculate_resize_e(self, canvas):
        """Test resize calculation for E handle."""
        handles = ResizeHandles(canvas, "test_field")
        
        result = handles._calculate_resize(100, 50, 180, 30, 20, 0, "e")
        
        # E: only width changes
        assert result == (100, 50, 200, 30)

    def test_calculate_resize_n(self, canvas):
        """Test resize calculation for N handle."""
        handles = ResizeHandles(canvas, "test_field")
        
        result = handles._calculate_resize(100, 50, 180, 30, 0, 10, "n")
        
        # N: y increases, height decreases
        assert result == (100, 60, 180, 20)

    def test_theme_colors(self, canvas):
        """Test theme color loading."""
        for theme in ["classic_green", "amber", "dos_blue", "paper_white", "matrix"]:
            handles = ResizeHandles(canvas, "test_field", theme=theme)
            assert "handle" in handles._colors
            assert "handle_active" in handles._colors
            assert "outline" in handles._colors


class TestResizeHandlePositions:
    """Test suite for resize handle positioning."""

    def test_handle_positions_after_show(self, canvas):
        """Test handles are positioned correctly."""
        handles = ResizeHandles(canvas, "test_field")
        handles.show(100, 50, 180, 30)
        
        # All 8 handles should exist
        expected_handles = ["nw", "n", "ne", "e", "se", "s", "sw", "w"]
        for handle_name in expected_handles:
            assert handle_name in handles._handles

    def test_center_calculations(self, canvas):
        """Test center point calculations."""
        handles = ResizeHandles(canvas, "test_field")
        handles.show(100, 50, 180, 30)  # x=100, y=50, w=180, h=30
        
        # Center should be at (100+90, 50+15) = (190, 65)
        center_x = handles._x + handles._width // 2
        center_y = handles._y + handles._height // 2
        
        assert center_x == 190
        assert center_y == 65

    def test_right_bottom_calculations(self, canvas):
        """Test right and bottom edge calculations."""
        handles = ResizeHandles(canvas, "test_field")
        handles.show(100, 50, 180, 30)
        
        right = handles._x + handles._width
        bottom = handles._y + handles._height
        
        assert right == 280
        assert bottom == 80
