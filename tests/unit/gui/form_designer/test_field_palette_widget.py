"""Tests for FieldPaletteWidget.

Tests drag-and-drop, click-to-place modes, field categories,
and drag ghost window functionality.

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.gui.form_designer.field_palette_widget import (
    FieldPaletteWidget,
    DragMode,
    DragData,
)
from src.documents.types.type_schema import FieldType


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
def mock_callbacks():
    """Create mock callbacks for palette."""
    return {
        "on_field_drag_start": MagicMock(),
        "on_field_drag_end": MagicMock(),
        "on_field_place_mode": MagicMock(),
    }


@pytest.fixture
def palette_widget(root, mock_callbacks):
    """Create a mounted FieldPaletteWidget instance."""
    widget = FieldPaletteWidget(
        parent=root,
        on_field_drag_start=mock_callbacks["on_field_drag_start"],
        on_field_drag_end=mock_callbacks["on_field_drag_end"],
        on_field_place_mode=mock_callbacks["on_field_place_mode"],
        mode="drag_drop",
    )
    widget.mount(root)
    yield widget
    widget.unmount()


# =============================================================================
# TEST: Initialization
# =============================================================================


class TestInitialization:
    """Test suite for initialization."""

    def test_palette_creation(self, root, mock_callbacks):
        """Test palette widget creation."""
        widget = FieldPaletteWidget(
            parent=root,
            on_field_drag_start=mock_callbacks["on_field_drag_start"],
            on_field_drag_end=mock_callbacks["on_field_drag_end"],
            on_field_place_mode=mock_callbacks["on_field_place_mode"],
        )

        assert widget is not None
        assert widget._mode == "drag_drop"

    def test_invalid_mode_raises(self, root, mock_callbacks):
        """Test invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Неверный mode"):
            FieldPaletteWidget(
                parent=root,
                on_field_drag_start=mock_callbacks["on_field_drag_start"],
                on_field_drag_end=mock_callbacks["on_field_drag_end"],
                on_field_place_mode=mock_callbacks["on_field_place_mode"],
                mode="invalid_mode",
            )

    def test_modes_defined(self):
        """Test MODES are defined."""
        assert "drag_drop" in FieldPaletteWidget.MODES
        assert "click_place" in FieldPaletteWidget.MODES


# =============================================================================
# TEST: Drag Mode
# =============================================================================


class TestDragMode:
    """Test suite for drag-and-drop mode."""

    def test_drag_mode_selected_by_default(self, palette_widget):
        """Test drag mode is selected by default."""
        assert palette_widget._mode == "drag_drop"

    def test_set_mode_changes_mode(self, palette_widget):
        """Test set_mode changes the mode."""
        palette_widget.set_mode("click_place")
        assert palette_widget._mode == "click_place"

    def test_set_mode_invalid_raises(self, palette_widget):
        """Test set_mode with invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Неверный mode"):
            palette_widget.set_mode("invalid")

    def test_set_mode_updates_ui(self, root, mock_callbacks):
        """Test set_mode updates mode radio buttons."""
        # Create fresh palette to test UI update
        palette_widget = FieldPaletteWidget(
            parent=root,
            on_field_drag_start=mock_callbacks["on_field_drag_start"],
            on_field_drag_end=mock_callbacks["on_field_drag_end"],
            on_field_place_mode=mock_callbacks["on_field_place_mode"],
            mode="drag_drop",
        )
        palette_widget.mount(root)

        palette_widget.set_mode("click_place")

        assert palette_widget._mode_var is not None
        assert palette_widget._mode_var.get() == "click_place"
        
        palette_widget.unmount()


# =============================================================================
# TEST: Click Place Mode
# =============================================================================


class TestClickPlaceMode:
    """Test suite for click-to-place mode."""

    def test_click_place_activates(self, palette_widget, mock_callbacks):
        """Test click place mode activates field placement."""
        palette_widget.set_mode("click_place")
        palette_widget._on_click_place_activate(FieldType.TEXT_INPUT)

        assert palette_widget._selected_field_type == FieldType.TEXT_INPUT
        mock_callbacks["on_field_place_mode"].assert_called_once_with(FieldType.TEXT_INPUT)

    def test_click_place_clears_on_canvas_click(self, palette_widget):
        """Test click place clears selection after canvas click."""
        palette_widget.set_mode("click_place")
        palette_widget._selected_field_type = FieldType.TEXT_INPUT

        # Simulate canvas click
        with patch.object(palette_widget, "_on_field_drag_end") as mock_end:
            palette_widget.on_canvas_click_place(100, 50)

            mock_end.assert_called_once_with(FieldType.TEXT_INPUT, 100, 50)
            assert palette_widget._selected_field_type is None


# =============================================================================
# TEST: Field Categories
# =============================================================================


class TestFieldCategories:
    """Test suite for field categories."""

    def test_categories_defined(self, palette_widget):
        """Test CATEGORIES are defined."""
        assert len(palette_widget.CATEGORIES) > 0

    def test_basic_category_exists(self, palette_widget):
        """Test BASIC category exists."""
        assert "BASIC" in palette_widget.CATEGORIES

    def test_text_category_exists(self, palette_widget):
        """Test TEXT category exists."""
        assert "TEXT" in palette_widget.CATEGORIES

    def test_numeric_category_exists(self, palette_widget):
        """Test NUMERIC category exists."""
        assert "NUMERIC" in palette_widget.CATEGORIES

    def test_special_category_exists(self, palette_widget):
        """Test SPECIAL category exists."""
        assert "SPECIAL" in palette_widget.CATEGORIES

    def test_media_category_exists(self, palette_widget):
        """Test MEDIA category exists."""
        assert "MEDIA" in palette_widget.CATEGORIES

    def test_basic_contains_text_input(self, palette_widget):
        """Test BASIC category contains TEXT_INPUT."""
        assert FieldType.TEXT_INPUT in palette_widget.CATEGORIES["BASIC"]

    def test_icons_defined_for_all_types(self, palette_widget):
        """Test ICONS defined for all field types in categories."""
        for category, field_types in palette_widget.CATEGORIES.items():
            for field_type in field_types:
                assert field_type in palette_widget.ICONS
                assert len(palette_widget.ICONS[field_type]) > 0


# =============================================================================
# TEST: Drag Ghost Window
# =============================================================================


class TestDragGhostWindow:
    """Test suite for drag ghost window."""

    def test_ghost_window_created_on_drag_start(self, palette_widget, root):
        """Test ghost window is created on drag start."""
        with patch.object(palette_widget, "_create_ghost_window") as mock_create:
            event = MagicMock()
            event.x_root = 100
            event.y_root = 100

            palette_widget._start_drag(FieldType.TEXT_INPUT, event)

            mock_create.assert_called_once()

    def test_ghost_window_destroyed_on_drag_end(self, palette_widget):
        """Test ghost window is destroyed on drag end."""
        # Setup drag data
        palette_widget._drag_data = DragData(
            field_type=FieldType.TEXT_INPUT,
            start_x=100,
            start_y=100,
        )
        # Create a real mock ghost window
        mock_ghost = MagicMock()
        palette_widget._ghost_window = mock_ghost

        event = MagicMock()
        event.x_root = 100
        event.y_root = 100

        # Mock _cleanup_drag to not actually destroy
        with patch.object(palette_widget, "_find_canvas_at", return_value=None):
            # Call _cleanup_drag which should destroy the window
            palette_widget._cleanup_drag()

            mock_ghost.destroy.assert_called_once()

    def test_drag_data_cleared_on_end(self, palette_widget):
        """Test drag data is cleared on drag end."""
        palette_widget._drag_data = DragData(
            field_type=FieldType.TEXT_INPUT,
            start_x=100,
            start_y=100,
        )
        palette_widget._ghost_window = MagicMock()

        event = MagicMock()
        event.x_root = 100
        event.y_root = 100

        with patch.object(palette_widget, "_find_canvas_at", return_value=None):
            palette_widget._on_drag_end(event)

            assert palette_widget._drag_data is None


# =============================================================================
# TEST: Category Switching
# =============================================================================


class TestCategorySwitching:
    """Test suite for category switching."""

    def test_initial_category_is_basic(self, palette_widget):
        """Test initial category is BASIC."""
        assert palette_widget.get_current_category() == "BASIC"

    def test_switch_category_changes_current(self, palette_widget):
        """Test switch_category changes current category."""
        palette_widget._switch_category("TEXT")

        assert palette_widget.get_current_category() == "TEXT"


# =============================================================================
# TEST: Selection
# =============================================================================


class TestSelection:
    """Test suite for field selection."""

    def test_get_selected_field_type_initially_none(self, palette_widget):
        """Test selected field type is initially None."""
        assert palette_widget.get_selected_field_type() is None

    def test_clear_selection_clears_field(self, palette_widget):
        """Test clear_selection clears selected field."""
        palette_widget._selected_field_type = FieldType.TEXT_INPUT

        palette_widget.clear_selection()

        assert palette_widget.get_selected_field_type() is None


# =============================================================================
# TEST: Drag Callbacks
# =============================================================================


class TestDragCallbacks:
    """Test suite for drag callbacks."""

    def test_drag_start_callback_invoked(self, palette_widget, mock_callbacks):
        """Test on_field_drag_start callback is invoked."""
        event = MagicMock()
        event.x_root = 100
        event.y_root = 100

        with patch.object(palette_widget, "_create_ghost_window"):
            palette_widget._start_drag(FieldType.TEXT_INPUT, event)

            mock_callbacks["on_field_drag_start"].assert_called_once_with(FieldType.TEXT_INPUT)

    def test_drag_end_callback_invoked(self, palette_widget, mock_callbacks, root):
        """Test on_field_drag_end callback is invoked on canvas drop."""
        # Setup
        palette_widget._drag_data = DragData(
            field_type=FieldType.TEXT_INPUT,
            start_x=100,
            start_y=100,
        )

        # Create a mock canvas
        mock_canvas = MagicMock()
        mock_canvas.winfo_rootx.return_value = 0
        mock_canvas.winfo_rooty.return_value = 0

        event = MagicMock()
        event.x_root = 50
        event.y_root = 50

        with patch.object(palette_widget, "_find_canvas_at", return_value=mock_canvas):
            with patch.object(palette_widget, "_cleanup_drag"):
                palette_widget._on_drag_end(event)

                mock_callbacks["on_field_drag_end"].assert_called_once_with(FieldType.TEXT_INPUT, 50, 50)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.form_designer.field_palette_widget"])
