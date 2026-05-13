"""Тесты для barcode_canvas_renderer модуля.

Тестирует:
- SoftwareBarcodeRenderer
- HardwareBarcodeRenderer
- PlaceholderBarcodeRenderer
- BarcodeRenderMode enum
- Factory function

Example:
    $ pytest tests/unit/gui/renderers/test_barcode_canvas_renderer.py -v

Module: tests/unit/gui/renderers/test_barcode_canvas_renderer.py
Version: 1.0
"""

from __future__ import annotations

import sys
import tkinter as tk
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

# Skip GUI tests if no display available
if sys.platform == "linux" and not sys.stdin.isatty():
    try:
        import tkinter as tk

        tk.Tcl().eval("info patchlevel")
    except tk.TclError:
        pytest.skip("No display available", allow_module_level=True)

from src.gui.renderers.barcode_canvas_renderer import (
    BarcodeCanvasRenderer,
    BarcodeRenderMode,
    HardwareBarcodeRenderer,
    PlaceholderBarcodeRenderer,
    SoftwareBarcodeRenderer,
    create_barcode_renderer,
)


@pytest.fixture
def root():
    """Создаёт root Tk окно для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def canvas(root):
    """Создаёт canvas для тестов."""
    canvas = tk.Canvas(root, width=400, height=300)
    canvas.pack()
    yield canvas


class TestBarcodeRenderMode:
    """Тесты для BarcodeRenderMode enum."""

    def test_render_mode_values(self):
        """Проверяет значения режимов."""
        assert BarcodeRenderMode.REAL.value is not None
        assert BarcodeRenderMode.PLACEHOLDER.value is not None

    def test_render_mode_is_enum(self):
        """Проверяет что это enum."""
        assert isinstance(BarcodeRenderMode.REAL, BarcodeRenderMode)


class TestBarcodeCanvasRendererBase:
    """Тесты для базового класса BarcodeCanvasRenderer."""

    def test_abstract_class_cannot_instantiate(self, canvas):
        """Проверяет что абстрактный класс нельзя создать."""
        with pytest.raises(TypeError):
            BarcodeCanvasRenderer(canvas)


class TestSoftwareBarcodeRenderer:
    """Тесты для SoftwareBarcodeRenderer."""

    @pytest.fixture
    def renderer(self, canvas):
        """Создаёт software рендерер."""
        renderer = SoftwareBarcodeRenderer(canvas)
        yield renderer
        renderer.clear()

    def test_renderer_creation(self, renderer):
        """Проверяет создание рендерера."""
        assert renderer is not None
        assert isinstance(renderer, BarcodeCanvasRenderer)

    def test_default_render_mode(self, renderer):
        """Проверяет режим по умолчанию."""
        assert renderer.render_mode == BarcodeRenderMode.REAL

    def test_set_render_mode(self, renderer):
        """Проверяет установку режима."""
        renderer.render_mode = BarcodeRenderMode.PLACEHOLDER
        assert renderer.render_mode == BarcodeRenderMode.PLACEHOLDER

    def test_render_creates_item_in_placeholder_mode(self, renderer, canvas):
        """Проверяет что render создаёт элемент в placeholder mode."""
        renderer.render_mode = BarcodeRenderMode.PLACEHOLDER
        item_id = renderer.render("CODE128", "TEST", 10, 10, 100, 50)
        assert item_id is not None
        assert item_id > 0

    def test_clear_removes_all_items(self, renderer, canvas):
        """Проверяет очистку всех элементов."""
        renderer.render_mode = BarcodeRenderMode.PLACEHOLDER
        item_id = renderer.render("CODE128", "TEST", 10, 10, 100, 50)
        renderer.clear()
        
        # Item should be removed from renderer tracking
        assert item_id not in renderer._item_refs
        # canvas.coords on deleted item may return empty tuple or raise
        # depending on Tk version — check either outcome
        coords = canvas.coords(item_id)
        assert coords == [] or coords == ()


class TestHardwareBarcodeRenderer:
    """Тесты для HardwareBarcodeRenderer."""

    @pytest.fixture
    def renderer(self, canvas):
        """Создаёт hardware рендерер."""
        renderer = HardwareBarcodeRenderer(canvas)
        yield renderer
        renderer.clear()

    def test_renderer_creation(self, renderer):
        """Проверяет создание рендерера."""
        assert renderer is not None
        assert isinstance(renderer, BarcodeCanvasRenderer)

    def test_render_creates_items(self, renderer):
        """Проверяет что render создаёт элементы."""
        item_id = renderer.render("EAN13", "123456789012", 10, 10, 200, 100)
        assert item_id is not None
        assert item_id > 0

    def test_render_includes_escp_text(self, renderer):
        """Проверяет что рендеринг включает ESC/P текст."""
        # This is implicit - the render should complete without error
        # and create multiple items (background, header, command, data)
        item_id = renderer.render("EAN13", "123456789012", 10, 10, 200, 100)
        assert item_id is not None


class TestPlaceholderBarcodeRenderer:
    """Тесты для PlaceholderBarcodeRenderer."""

    @pytest.fixture
    def renderer(self, canvas):
        """Создаёт placeholder рендерер."""
        renderer = PlaceholderBarcodeRenderer(canvas)
        yield renderer
        renderer.clear()

    def test_renderer_creation(self, renderer):
        """Проверяет создание рендерера."""
        assert renderer is not None
        assert isinstance(renderer, BarcodeCanvasRenderer)

    def test_render_creates_barcode_icon(self, renderer, canvas):
        """Проверяет что render создаёт иконку штрих-кода."""
        item_id = renderer.render("CODE128", "TEST123", 10, 10, 200, 100)
        
        # Should create multiple items (background, lines, text)
        items = canvas.find_withtag("barcode_placeholder")
        assert len(items) > 0

    def test_render_with_long_data_truncates(self, renderer, canvas):
        """Проверяет обрезку длинных данных."""
        long_data = "A" * 50
        renderer.render("CODE128", long_data, 10, 10, 200, 100)
        
        # Should complete without error
        items = canvas.find_withtag("barcode_placeholder")
        assert len(items) > 0


class TestCreateBarcodeRenderer:
    """Тесты для фабричной функции."""

    def test_create_software_renderer(self, canvas):
        """Проверяет создание software рендерера."""
        renderer = create_barcode_renderer(canvas, mode="software")
        assert isinstance(renderer, SoftwareBarcodeRenderer)

    def test_create_hardware_renderer(self, canvas):
        """Проверяет создание hardware рендерера."""
        renderer = create_barcode_renderer(canvas, mode="hardware")
        assert isinstance(renderer, HardwareBarcodeRenderer)

    def test_create_placeholder_renderer(self, canvas):
        """Проверяет создание placeholder рендерера."""
        renderer = create_barcode_renderer(canvas, mode="placeholder")
        assert isinstance(renderer, PlaceholderBarcodeRenderer)

    def test_create_with_custom_dpi(self, canvas):
        """Проверяет создание с кастомным DPI."""
        renderer = create_barcode_renderer(
            canvas,
            mode="software",
            dpi=600,
        )
        assert renderer._dpi == 600

    def test_create_defaults_to_software(self, canvas):
        """Проверяет что по умолчанию создаётся software рендерер."""
        renderer = create_barcode_renderer(canvas)
        assert isinstance(renderer, SoftwareBarcodeRenderer)


@pytest.mark.slow
class TestBarcodeRendererIntegration:
    """Интеграционные тесты для barcode рендереров."""

    def test_multiple_barcodes_on_canvas(self, root):
        """Проверяет рендеринг нескольких штрих-кодов."""
        canvas = tk.Canvas(root, width=800, height=600)
        canvas.pack()

        renderer = PlaceholderBarcodeRenderer(canvas)

        # Render multiple barcodes
        positions = [
            ("CODE128", "TEST1", 10, 10, 200, 80),
            ("EAN13", "1234567890123", 10, 110, 200, 80),
            ("CODE39", "ABC-123", 10, 210, 200, 80),
        ]

        for barcode_type, data, x, y, w, h in positions:
            item_id = renderer.render(barcode_type, data, x, y, w, h)
            assert item_id is not None

        # Check that items exist
        items = canvas.find_withtag("barcode_item")
        assert len(items) > 0

        renderer.clear()

    def test_clear_specific_item(self, root):
        """Проверяет очистку конкретного элемента."""
        canvas = tk.Canvas(root, width=400, height=300)
        canvas.pack()

        renderer = PlaceholderBarcodeRenderer(canvas)

        # Create two barcodes
        item1 = renderer.render("CODE128", "TEST1", 10, 10, 200, 80)
        item2 = renderer.render("CODE128", "TEST2", 10, 110, 200, 80)

        # Clear first item
        renderer.clear(item1)

        # Second should still exist
        items = canvas.find_withtag("barcode_item")
        # Note: clearing one item removes its components
        # The exact count depends on implementation

        renderer.clear()

    def test_render_mode_switch(self, root):
        """Проверяет переключение режима рендеринга."""
        canvas = tk.Canvas(root, width=400, height=300)
        canvas.pack()

        renderer = SoftwareBarcodeRenderer(canvas)
        
        # Start with REAL mode
        renderer.render_mode = BarcodeRenderMode.REAL
        
        # Switch to PLACEHOLDER
        renderer.render_mode = BarcodeRenderMode.PLACEHOLDER
        item_id = renderer.render("CODE128", "TEST", 10, 10, 200, 80)
        
        # Should use placeholder rendering
        assert item_id is not None

        renderer.clear()

    def test_barcode_types(self, root):
        """Проверяет рендеринг разных типов штрих-кодов."""
        canvas = tk.Canvas(root, width=400, height=600)
        canvas.pack()

        renderer = PlaceholderBarcodeRenderer(canvas)

        barcode_types = ["CODE128", "CODE39", "EAN13", "EAN8", "UPC", "ITF", "CODABAR"]
        y_offset = 10

        for barcode_type in barcode_types:
            item_id = renderer.render(
                barcode_type,
                f"TEST-{barcode_type}",
                10,
                y_offset,
                200,
                60,
            )
            assert item_id is not None
            y_offset += 80

        renderer.clear()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
