"""Tests for ResizeHandles.

Tests 8 resize handles creation, handle dragging, snap-to-grid,
minimum size enforcement, and position calculations.

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.gui.form_designer.resize_handles import ResizeHandles


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def root():
    """Create a Tk root window for tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def canvas(root):
    """Create a Canvas for tests."""
    canvas = tk.Canvas(root, width=400, height=300)
    canvas.pack()
    yield canvas
    canvas.destroy()


@pytest.fixture
def resize_handles(canvas):
    """Create a ResizeHandles instance."""
    handles = ResizeHandles(canvas, "test_field")
    yield handles


# =============================================================================
# TEST: 8 Handles Creation
# =============================================================================


class TestEightHandlesCreated:
    """Test suite for handle creation."""

    def test_handles_list_has_8_positions(self):
        """Test HANDLES list has 8 positions."""
        assert len(ResizeHandles.HANDLES) == 8

    def test_all_8_handles_present(self):
        """Test all 8 handles are defined."""
        expected = ["nw", "n", "ne", "e", "se", "s", "sw", "w"]
        assert ResizeHandles.HANDLES == expected

    def test_show_creates_8_handles(self, resize_handles):
        """Test show() creates 8 handle items."""
        resize_handles.show(100, 50, 180, 30)

        assert len(resize_handles._handles) == 8

    def test_handles_have_correct_names(self, resize_handles):
        """Test created handles have correct names."""
        resize_handles.show(100, 50, 180, 30)

        expected_handles = {"nw", "n", "ne", "e", "se", "s", "sw", "w"}
        actual_handles = set(resize_handles._handles.keys())

        assert actual_handles == expected_handles


# =============================================================================
# TEST: Handle Drag North
# =============================================================================


class TestHandleDragNorth:
    """Test suite for dragging north handle."""

    def test_n_handle_decreases_y(self, resize_handles):
        """Test dragging N handle decreases Y and height."""
        resize_handles.show(100, 50, 180, 30)

        # Simulate drag: N handle moves down by 10
        result = resize_handles._calculate_resize(100, 50, 180, 30, 0, 10, "n")

        # y increases by 10, height decreases by 10
        assert result == (100, 60, 180, 20)

    def test_n_handle_respects_minimum(self, resize_handles):
        """Test N handle respects minimum size."""
        resize_handles.show(100, 50, 180, 30)

        # Try to drag N handle too far down
        result = resize_handles._calculate_resize(100, 50, 180, 30, 0, 50, "n")

        # Height should not go below minimum
        assert result[3] >= ResizeHandles.MIN_SIZE * 10  # Assuming 10px cell


# =============================================================================
# TEST: Handle Drag South-East
# =============================================================================


class TestHandleDragSouthEast:
    """Test suite for dragging south-east handle."""

    def test_se_handle_increases_size(self, resize_handles):
        """Test dragging SE handle increases width and height."""
        resize_handles.show(100, 50, 180, 30)

        # Simulate drag: SE handle moves down-right by 20, 10
        result = resize_handles._calculate_resize(100, 50, 180, 30, 20, 10, "se")

        # width increases by 20, height increases by 10
        assert result == (100, 50, 200, 40)

    def test_se_handle_does_not_change_position(self, resize_handles):
        """Test SE handle does not change x, y."""
        resize_handles.show(100, 50, 180, 30)

        result = resize_handles._calculate_resize(100, 50, 180, 30, 20, 10, "se")

        assert result[0] == 100  # x unchanged
        assert result[1] == 50  # y unchanged


# =============================================================================
# TEST: Snap to Grid
# =============================================================================


class TestSnapToGrid:
    """Test suite for snap-to-grid functionality."""

    def test_snap_to_grid_rounds_value(self, resize_handles):
        """Test _snap_to_grid rounds to nearest cell."""
        # Snap to 10-pixel grid
        result = resize_handles._snap_to_grid(47, 10)
        assert result == 50

        result = resize_handles._snap_to_grid(43, 10)
        assert result == 40

    def test_snap_to_grid_exact_value(self, resize_handles):
        """Test _snap_to_grid keeps exact values."""
        result = resize_handles._snap_to_grid(50, 10)
        assert result == 50


# =============================================================================
# TEST: Minimum Size
# =============================================================================


class TestMinimumSize:
    """Test suite for minimum size enforcement."""

    def test_minimum_size_constant(self):
        """Test MIN_SIZE constant."""
        assert ResizeHandles.MIN_SIZE == 1

    def test_width_respects_minimum(self, resize_handles):
        """Test width respects minimum size."""
        resize_handles.show(100, 50, 180, 30)

        # Try to resize W handle to make width very small
        result = resize_handles._calculate_resize(100, 50, 180, 30, 200, 0, "w")

        # Width should be at least MIN_SIZE
        assert result[2] >= ResizeHandles.MIN_SIZE

    def test_height_respects_minimum(self, resize_handles):
        """Test height respects minimum size."""
        resize_handles.show(100, 50, 180, 30)

        # Try to resize N handle to make height very small
        result = resize_handles._calculate_resize(100, 50, 180, 30, 0, 100, "n")

        # Height should be at least MIN_SIZE
        assert result[3] >= ResizeHandles.MIN_SIZE


# =============================================================================
# TEST: Handle Visibility
# =============================================================================


class TestHandleVisibility:
    """Test suite for handle visibility."""

    def test_is_visible_false_initially(self, resize_handles):
        """Test is_visible is False initially."""
        assert resize_handles.is_visible() is False

    def test_is_visible_true_after_show(self, resize_handles):
        """Test is_visible is True after show."""
        resize_handles.show(100, 50, 180, 30)
        assert resize_handles.is_visible() is True

    def test_is_visible_false_after_hide(self, resize_handles):
        """Test is_visible is False after hide."""
        resize_handles.show(100, 50, 180, 30)
        resize_handles.hide()

        assert resize_handles.is_visible() is False

    def test_hide_clears_handles(self, resize_handles):
        """Test hide clears all handles."""
        resize_handles.show(100, 50, 180, 30)
        resize_handles.hide()

        assert len(resize_handles._handles) == 0


# =============================================================================
# TEST: Position Update
# =============================================================================


class TestPositionUpdate:
    """Test suite for position update."""

    def test_update_position_changes_coordinates(self, resize_handles):
        """Test update_position changes coordinates."""
        resize_handles.show(100, 50, 180, 30)

        resize_handles.update_position(200, 100)

        assert resize_handles._x == 200
        assert resize_handles._y == 100

    def test_update_size_changes_dimensions(self, resize_handles):
        """Test update_size changes dimensions."""
        resize_handles.show(100, 50, 180, 30)

        resize_handles.update_size(200, 40)

        assert resize_handles._width == 200
        assert resize_handles._height == 40


# =============================================================================
# TEST: Resize Callbacks
# =============================================================================


class TestResizeCallbacks:
    """Test suite for resize callbacks."""

    def test_resize_callback_invoked(self, canvas):
        """Test on_resize callback is invoked."""
        callback_invoked = False
        callback_args = None

        def on_resize(x, y, width, height):
            nonlocal callback_invoked, callback_args
            callback_invoked = True
            callback_args = (x, y, width, height)

        handles = ResizeHandles(canvas, "test_field", on_resize=on_resize)
        handles.show(100, 50, 180, 30)

        # Simulate resize via _trigger_resize_callback
        handles._trigger_resize_callback(200, 100, 250, 50)

        assert callback_invoked is True
        assert callback_args == (200, 100, 250, 50)

    def test_resize_done_callback_invoked(self, canvas):
        """Test on_resize_done callback is invoked."""
        callback_invoked = False

        def on_resize_done(x, y, width, height):
            nonlocal callback_invoked
            callback_invoked = True

        handles = ResizeHandles(
            canvas, "test_field",
            on_resize_done=on_resize_done
        )
        handles.show(100, 50, 180, 30)

        # Setup drag state
        handles._active_handle = "se"
        handles._is_dragging = True
        handles._drag_start = (100, 50)
        handles._original_rect = (100, 50, 180, 30)

        # Mock event
        event = MagicMock()
        event.x = 200
        event.y = 100

        handles._on_handle_release(event)

        assert callback_invoked is True


# =============================================================================
# TEST: Handle Cursors
# =============================================================================


class TestHandleCursors:
    """Test suite for handle cursors."""

    def test_cursors_defined_for_all_handles(self):
        """Test cursors defined for all 8 handles."""
        for handle_name in ResizeHandles.HANDLES:
            assert handle_name in ResizeHandles.CURSORS
            assert len(ResizeHandles.CURSORS[handle_name]) > 0

    def test_nw_cursor_is_size_nw_se(self):
        """Test NW handle cursor."""
        assert ResizeHandles.CURSORS["nw"] == "size_nw_se"

    def test_n_cursor_is_size_ns(self):
        """Test N handle cursor."""
        assert ResizeHandles.CURSORS["n"] == "size_ns"


# =============================================================================
# TEST: Theme Colors
# =============================================================================


class TestThemeColors:
    """Test suite for theme colors."""

    def test_default_theme_loaded(self, resize_handles):
        """Test default theme colors are loaded."""
        assert "handle" in resize_handles._colors
        assert "handle_active" in resize_handles._colors
        assert "outline" in resize_handles._colors

    def test_theme_loading_valid_themes(self, canvas):
        """Test theme loading for valid themes."""
        valid_themes = ["classic_green", "amber", "dos_blue", "paper_white", "matrix"]

        for theme in valid_themes:
            handles = ResizeHandles(canvas, "test_field", theme=theme)
            assert "handle" in handles._colors
            assert "handle_active" in handles._colors


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.form_designer.resize_handles"])
