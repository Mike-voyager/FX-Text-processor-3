"""Tests for GridSize enum and grid switching.

Tests all grid sizes and switching between them.
"""

from __future__ import annotations

import tkinter as tk

import pytest

from src.view.form_designer import GridSize
from src.view.form_designer.canvas import ESCPGridCanvas


@pytest.fixture
def root():
    """Create a Tk root window for tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestGridSize:
    """Test suite for GridSize enum."""

    def test_a4_dimensions(self):
        """Test A4 grid dimensions."""
        assert GridSize.A4.width == 80
        assert GridSize.A4.height == 66
        assert GridSize.A4.cols == 80
        assert GridSize.A4.rows == 66

    def test_wide_tractor_dimensions(self):
        """Test Wide Tractor grid dimensions."""
        assert GridSize.WIDE_TRACTOR.width == 132
        assert GridSize.WIDE_TRACTOR.height == 66
        assert GridSize.WIDE_TRACTOR.cols == 132
        assert GridSize.WIDE_TRACTOR.rows == 66

    def test_envelope_dl_dimensions(self):
        """Test Envelope DL grid dimensions."""
        assert GridSize.ENVELOPE_DL.width == 40
        assert GridSize.ENVELOPE_DL.height == 15
        assert GridSize.ENVELOPE_DL.cols == 40
        assert GridSize.ENVELOPE_DL.rows == 15

    def test_envelope_c5_dimensions(self):
        """Test Envelope C5 grid dimensions."""
        assert GridSize.ENVELOPE_C5.width == 60
        assert GridSize.ENVELOPE_C5.height == 25
        assert GridSize.ENVELOPE_C5.cols == 60
        assert GridSize.ENVELOPE_C5.rows == 25

    def test_grid_size_uniqueness(self):
        """Test all grid sizes have unique dimensions."""
        sizes = [
            (GridSize.A4.cols, GridSize.A4.rows),
            (GridSize.WIDE_TRACTOR.cols, GridSize.WIDE_TRACTOR.rows),
            (GridSize.ENVELOPE_DL.cols, GridSize.ENVELOPE_DL.rows),
            (GridSize.ENVELOPE_C5.cols, GridSize.ENVELOPE_C5.rows),
        ]
        
        # All tuples should be unique
        assert len(sizes) == len(set(sizes))

    def test_a4_is_default(self):
        """Test A4 is the standard paper size."""
        # A4 is the most common size
        assert GridSize.A4.cols == 80  # Standard column width
        assert GridSize.A4.rows == 66   # Standard for 6 LPI


class TestCanvasGridSwitching:
    """Test suite for canvas grid switching."""

    def test_switch_to_wide_tractor(self, root):
        """Test switching to Wide Tractor."""
        canvas = ESCPGridCanvas(root, GridSize.A4)
        
        canvas.set_grid_size(GridSize.WIDE_TRACTOR)
        
        assert canvas._grid_size == GridSize.WIDE_TRACTOR
        assert canvas._grid_size.cols == 132
        
        canvas.destroy()

    def test_switch_to_envelope_dl(self, root):
        """Test switching to Envelope DL."""
        canvas = ESCPGridCanvas(root, GridSize.A4)
        
        canvas.set_grid_size(GridSize.ENVELOPE_DL)
        
        assert canvas._grid_size == GridSize.ENVELOPE_DL
        assert canvas._grid_size.cols == 40
        
        canvas.destroy()

    def test_switch_to_envelope_c5(self, root):
        """Test switching to Envelope C5."""
        canvas = ESCPGridCanvas(root, GridSize.A4)
        
        canvas.set_grid_size(GridSize.ENVELOPE_C5)
        
        assert canvas._grid_size == GridSize.ENVELOPE_C5
        assert canvas._grid_size.cols == 60
        
        canvas.destroy()

    def test_multiple_switches(self, root):
        """Test multiple grid switches."""
        canvas = ESCPGridCanvas(root, GridSize.A4)
        
        # Switch through all sizes
        for size in [GridSize.WIDE_TRACTOR, GridSize.ENVELOPE_DL, 
                     GridSize.ENVELOPE_C5, GridSize.A4]:
            canvas.set_grid_size(size)
            assert canvas._grid_size == size
        
        canvas.destroy()

    def test_scroll_region_updates(self, root):
        """Test scroll region updates on grid switch."""
        canvas = ESCPGridCanvas(root, GridSize.A4)
        
        original_region = canvas.cget("scrollregion")
        
        canvas.set_grid_size(GridSize.WIDE_TRACTOR)
        
        new_region = canvas.cget("scrollregion")
        # Wider grid should have larger scroll region
        assert new_region != original_region
        
        canvas.destroy()


class TestGridSizeProperties:
    """Test suite for GridSize properties."""

    def test_all_sizes_have_positive_dimensions(self):
        """Test all grid sizes have positive dimensions."""
        for size in GridSize:
            assert size.cols > 0
            assert size.rows > 0

    def test_wide_tractor_is_widest(self):
        """Test Wide Tractor is the widest format."""
        widths = [size.cols for size in GridSize]
        assert GridSize.WIDE_TRACTOR.cols == max(widths)
        assert GridSize.WIDE_TRACTOR.cols == 132

    def test_envelope_dl_is_smallest(self):
        """Test Envelope DL is the smallest format."""
        areas = [(size.cols * size.rows, size) for size in GridSize]
        smallest = min(areas, key=lambda x: x[0])
        assert smallest[1] == GridSize.ENVELOPE_DL

    def test_all_sizes_same_height_except_envelopes(self):
        """Test height consistency."""
        standard_height = GridSize.A4.rows
        
        assert GridSize.WIDE_TRACTOR.rows == standard_height
        
        # Envelopes are smaller
        assert GridSize.ENVELOPE_DL.rows < standard_height
        assert GridSize.ENVELOPE_C5.rows < standard_height
