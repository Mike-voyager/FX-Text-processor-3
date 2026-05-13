"""Tests for ESCPGridCanvas.

Tests grid operations, snap-to-grid, zoom, and field management.
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest

from src.view.form_designer import GridSize
from src.view.form_designer.canvas import ESCPGridCanvas, GridCell


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


class TestESCPGridCanvas:
    """Test suite for ESCPGridCanvas."""

    def test_initialization(self, root):
        """Test canvas initialization with default values."""
        canvas = ESCPGridCanvas(root, GridSize.A4)
        
        assert canvas._grid_size == GridSize.A4
        assert canvas._zoom_level == 100
        assert canvas._snap_to_grid is True
        assert canvas._show_grid is True
        
        canvas.destroy()

    def test_grid_sizes(self):
        """Test GridSize enum values."""
        assert GridSize.A4.cols == 80
        assert GridSize.A4.rows == 66
        
        assert GridSize.WIDE_TRACTOR.cols == 132
        assert GridSize.WIDE_TRACTOR.rows == 66
        
        assert GridSize.ENVELOPE_DL.cols == 40
        assert GridSize.ENVELOPE_DL.rows == 15
        
        assert GridSize.ENVELOPE_C5.cols == 60
        assert GridSize.ENVELOPE_C5.rows == 25

    def test_pixel_to_grid_conversion(self, canvas):
        """Test pixel to grid coordinate conversion."""
        # At 100% zoom, char_width=9, char_height=15
        assert canvas.pixel_to_grid(0, 0) == (0, 0)
        assert canvas.pixel_to_grid(9, 15) == (1, 1)
        assert canvas.pixel_to_grid(18, 30) == (2, 2)
        assert canvas.pixel_to_grid(45, 75) == (5, 5)

    def test_grid_to_pixel_conversion(self, canvas):
        """Test grid to pixel coordinate conversion."""
        assert canvas.grid_to_pixel(0, 0) == (0, 0)
        assert canvas.grid_to_pixel(1, 1) == (9, 15)
        assert canvas.grid_to_pixel(5, 5) == (45, 75)

    def test_snap_pixel_to_grid(self, canvas):
        """Test snap-to-grid functionality."""
        # Should snap to nearest grid cell
        assert canvas.snap_pixel_to_grid(4, 7) == (0, 0)  # rounds down
        assert canvas.snap_pixel_to_grid(5, 8) == (9, 15)  # rounds up
        assert canvas.snap_pixel_to_grid(13, 22) == (9, 15)  # rounds down
        assert canvas.snap_pixel_to_grid(14, 23) == (18, 30)  # rounds up

    def test_zoom_increases_size(self, canvas):
        """Test zoom in increases character size."""
        original_zoom = canvas.get_zoom()
        original_char_width = canvas._char_width
        
        canvas.zoom_in()
        
        assert canvas.get_zoom() > original_zoom
        assert canvas._char_width > original_char_width

    def test_zoom_out_decreases_size(self, canvas):
        """Test zoom out decreases character size."""
        # First zoom in
        canvas.zoom_in()
        original_zoom = canvas.get_zoom()
        original_char_width = canvas._char_width
        
        canvas.zoom_out()
        
        assert canvas.get_zoom() < original_zoom
        assert canvas._char_width < original_char_width

    def test_zoom_reset(self, canvas):
        """Test zoom reset returns to 100%."""
        canvas.zoom_in()
        canvas.zoom_in()
        assert canvas.get_zoom() != 100
        
        canvas.zoom_reset()
        assert canvas.get_zoom() == 100

    def test_zoom_limits(self, canvas):
        """Test zoom respects min/max limits."""
        # Zoom out to minimum
        for _ in range(20):
            canvas.zoom_out()
        assert canvas.get_zoom() == ESCPGridCanvas.MIN_ZOOM
        
        # Zoom in to maximum
        for _ in range(40):
            canvas.zoom_in()
        assert canvas.get_zoom() == ESCPGridCanvas.MAX_ZOOM

    def test_toggle_grid(self, canvas):
        """Test grid visibility toggle."""
        assert canvas._show_grid is True
        
        result = canvas.toggle_grid()
        assert result is False
        assert canvas._show_grid is False
        
        result = canvas.toggle_grid(True)
        assert result is True
        assert canvas._show_grid is True

    def test_toggle_snap(self, canvas):
        """Test snap-to-grid toggle."""
        assert canvas._snap_to_grid is True
        
        result = canvas.toggle_snap()
        assert result is False
        assert canvas._snap_to_grid is False
        
        result = canvas.toggle_snap(True)
        assert result is True
        assert canvas._snap_to_grid is True

    def test_set_grid_size(self, canvas):
        """Test changing grid size."""
        canvas.set_grid_size(GridSize.WIDE_TRACTOR)
        
        assert canvas._grid_size == GridSize.WIDE_TRACTOR
        assert canvas._grid_size.cols == 132

    def test_field_widget_management(self, canvas):
        """Test adding and removing field widgets."""
        # Create a mock field widget
        mock_widget = MagicMock()
        mock_widget.field_id = "test_field"
        
        # Add field
        canvas.add_field_widget(mock_widget)
        assert canvas.get_field_widget("test_field") == mock_widget
        
        # Remove field
        result = canvas.remove_field_widget("test_field")
        assert result is True
        assert canvas.get_field_widget("test_field") is None
        
        # Remove non-existent field
        result = canvas.remove_field_widget("nonexistent")
        assert result is False

    def test_clear_removes_all_fields(self, canvas):
        """Test clear removes all field widgets."""
        # Add multiple fields
        for i in range(3):
            mock_widget = MagicMock()
            mock_widget.field_id = f"field_{i}"
            canvas.add_field_widget(mock_widget)
        
        canvas.clear()
        
        for i in range(3):
            assert canvas.get_field_widget(f"field_{i}") is None

    def test_selected_field(self, canvas):
        """Test field selection."""
        assert canvas.get_selected_field() is None
        
        canvas._select_field("test_field")
        assert canvas.get_selected_field() == "test_field"
        
        canvas._select_field(None)
        assert canvas.get_selected_field() is None

    def test_grid_cell_dataclass(self):
        """Test GridCell dataclass."""
        cell = GridCell(col=5, row=3, x_px=45, y_px=45)
        
        assert cell.col == 5
        assert cell.row == 3
        assert cell.x_px == 45
        assert cell.y_px == 45

    def test_theme_colors(self, root):
        """Test theme color loading."""
        canvas = ESCPGridCanvas(root, GridSize.A4, theme="amber")
        assert "bg" in canvas._colors
        assert "fg" in canvas._colors
        assert "grid" in canvas._colors
        canvas.destroy()

    def test_invalid_theme_defaults_to_classic_green(self, root):
        """Test invalid theme defaults to classic_green."""
        canvas = ESCPGridCanvas(root, GridSize.A4, theme="invalid_theme")
        assert canvas._colors["bg"] == "#001100"  # classic_green bg
        canvas.destroy()


@pytest.mark.security
def test_canvas_no_external_imports():
    """Test canvas doesn't import from security modules."""
    from src.view.form_designer import canvas as canvas_module
    
    # Check no security/crypto imports
    import ast
    import inspect
    
    source = inspect.getsource(canvas_module)
    tree = ast.parse(source)
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "security" not in alias.name
                assert "crypto" not in alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert "security" not in node.module
                assert "crypto" not in node.module
