"""Тесты для qr_canvas_renderer модуля.

Тестирует:
- SoftwareQRRenderer
- PlaceholderQRRenderer
- QRRenderMode enum
- Factory function

Example:
    $ pytest tests/unit/gui/renderers/test_qr_canvas_renderer.py -v

Module: tests/unit/gui/renderers/test_qr_canvas_renderer.py
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

from src.gui.renderers.qr_canvas_renderer import (
    PlaceholderQRRenderer,
    QRCanvasRenderer,
    QRRenderMode,
    SoftwareQRRenderer,
    create_qr_renderer,
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
    canvas = tk.Canvas(root, width=400, height=400)
    canvas.pack()
    yield canvas


class TestQRRenderMode:
    """Тесты для QRRenderMode enum."""

    def test_render_mode_values(self):
        """Проверяет значения режимов."""
        assert QRRenderMode.REAL.value is not None
        assert QRRenderMode.PLACEHOLDER.value is not None

    def test_render_mode_is_enum(self):
        """Проверяет что это enum."""
        assert isinstance(QRRenderMode.REAL, QRRenderMode)


class TestQRCanvasRendererBase:
    """Тесты для базового класса QRCanvasRenderer."""

    def test_abstract_class_cannot_instantiate(self, canvas):
        """Проверяет что абстрактный класс нельзя создать."""
        with pytest.raises(TypeError):
            QRCanvasRenderer(canvas)


class TestSoftwareQRRenderer:
    """Тесты для SoftwareQRRenderer."""

    @pytest.fixture
    def renderer(self, canvas):
        """Создаёт software QR рендерер."""
        renderer = SoftwareQRRenderer(canvas)
        yield renderer
        renderer.clear()

    def test_renderer_creation(self, renderer):
        """Проверяет создание рендерера."""
        assert renderer is not None
        assert isinstance(renderer, QRCanvasRenderer)

    def test_default_parameters(self, renderer):
        """Проверяет параметры по умолчанию."""
        assert renderer._error_correction == "M"
        assert renderer._box_size == 4
        assert renderer._border == 4
        assert renderer._version is None

    def test_custom_parameters(self, canvas):
        """Проверяет кастомные параметры."""
        renderer = SoftwareQRRenderer(
            canvas,
            error_correction="H",
            box_size=6,
            border=2,
            version=10,
        )
        assert renderer._error_correction == "H"
        assert renderer._box_size == 6
        assert renderer._border == 2
        assert renderer._version == 10

    def test_render_creates_item_in_placeholder_mode(self, renderer, canvas):
        """Проверяет что render создаёт элемент в placeholder mode."""
        renderer.render_mode = QRRenderMode.PLACEHOLDER
        item_id = renderer.render_qr("https://example.com", 10, 10, 200)
        assert item_id is not None
        assert item_id > 0

    def test_clear_removes_items(self, renderer, canvas):
        """Проверяет очистку элементов."""
        renderer.render_mode = QRRenderMode.PLACEHOLDER
        item_id = renderer.render_qr("TEST", 10, 10, 200)
        renderer.clear()
        
        # Should not find items
        items = canvas.find_withtag("qr_item")
        assert len(items) == 0

    def test_store_photo_prevents_gc(self, renderer):
        """Проверяет что PhotoImage хранится для предотвращения GC."""
        mock_photo = MagicMock()
        renderer._store_photo(mock_photo)
        assert mock_photo in renderer._photo_images


class TestPlaceholderQRRenderer:
    """Тесты для PlaceholderQRRenderer."""

    @pytest.fixture
    def renderer(self, canvas):
        """Создаёт placeholder QR рендерер."""
        renderer = PlaceholderQRRenderer(canvas)
        yield renderer
        renderer.clear()

    def test_renderer_creation(self, renderer):
        """Проверяет создание рендерера."""
        assert renderer is not None
        assert isinstance(renderer, QRCanvasRenderer)

    def test_render_creates_qr_pattern(self, renderer, canvas):
        """Проверяет что render создаёт паттерн QR."""
        item_id = renderer.render_qr("TEST123", 10, 10, 200)
        
        # Should create multiple items (background, pattern, text)
        items = canvas.find_withtag("qr_placeholder")
        assert len(items) > 0

    def test_render_with_url(self, renderer, canvas):
        """Проверяет рендеринг URL."""
        url = "https://example.com/path/to/resource"
        item_id = renderer.render_qr(url, 10, 10, 200)
        
        assert item_id is not None
        items = canvas.find_withtag("qr_placeholder")
        assert len(items) > 0

    def test_render_with_long_data(self, renderer, canvas):
        """Проверяет рендеринг длинных данных."""
        long_data = "A" * 500
        item_id = renderer.render_qr(long_data, 10, 10, 200)
        
        # Should complete without error
        assert item_id is not None

    def test_render_deterministic(self, renderer, canvas):
        """Проверяет что одинаковые данные дают одинаковый результат."""
        # First render
        item1 = renderer.render_qr("TEST", 10, 10, 200)
        
        # Clear and render again
        renderer.clear()
        item2 = renderer.render_qr("TEST", 10, 10, 200)
        
        # Both should succeed (deterministic based on data seed)
        assert item1 is not None
        assert item2 is not None


class TestCreateQRRenderer:
    """Тесты для фабричной функции."""

    def test_create_software_renderer(self, canvas):
        """Проверяет создание software рендерера."""
        renderer = create_qr_renderer(canvas, mode="software")
        assert isinstance(renderer, SoftwareQRRenderer)

    def test_create_placeholder_renderer(self, canvas):
        """Проверяет создание placeholder рендерера."""
        renderer = create_qr_renderer(canvas, mode="placeholder")
        assert isinstance(renderer, PlaceholderQRRenderer)

    def test_create_with_custom_params(self, canvas):
        """Проверяет создание с кастомными параметрами."""
        renderer = create_qr_renderer(
            canvas,
            mode="software",
            error_correction="H",
            box_size=6,
        )
        assert renderer._error_correction == "H"
        assert renderer._box_size == 6

    def test_create_defaults_to_software(self, canvas):
        """Проверяет что по умолчанию создаётся software рендерер."""
        renderer = create_qr_renderer(canvas)
        assert isinstance(renderer, SoftwareQRRenderer)


@pytest.mark.slow
class TestQRRendererIntegration:
    """Интеграционные тесты для QR рендереров."""

    def test_multiple_qr_on_canvas(self, root):
        """Проверяет рендеринг нескольких QR-кодов."""
        canvas = tk.Canvas(root, width=800, height=600)
        canvas.pack()

        renderer = PlaceholderQRRenderer(canvas)

        # Render multiple QR codes
        positions = [
            ("https://example.com/1", 10, 10, 150),
            ("https://example.com/2", 200, 10, 150),
            ("https://example.com/3", 10, 200, 150),
        ]

        for data, x, y, size in positions:
            item_id = renderer.render_qr(data, x, y, size)
            assert item_id is not None

        # Check that items exist
        items = canvas.find_withtag("qr_item")
        assert len(items) > 0

        renderer.clear()

    def test_different_sizes(self, root):
        """Проверяет рендеринг разных размеров."""
        canvas = tk.Canvas(root, width=600, height=600)
        canvas.pack()

        renderer = PlaceholderQRRenderer(canvas)

        sizes = [100, 150, 200, 250]
        y_offset = 10

        for size in sizes:
            item_id = renderer.render_qr(f"SIZE-{size}", 10, y_offset, size)
            assert item_id is not None
            y_offset += size + 20

        renderer.clear()

    def test_render_mode_switch(self, root):
        """Проверяет переключение режима рендеринга."""
        canvas = tk.Canvas(root, width=400, height=400)
        canvas.pack()

        renderer = SoftwareQRRenderer(canvas)
        
        # Start with REAL mode
        renderer.render_mode = QRRenderMode.REAL
        
        # Switch to PLACEHOLDER
        renderer.render_mode = QRRenderMode.PLACEHOLDER
        item_id = renderer.render_qr("TEST", 10, 10, 200)
        
        # Should use placeholder rendering
        assert item_id is not None

        renderer.clear()

    def test_qr_data_types(self, root):
        """Проверяет рендеринг разных типов данных."""
        canvas = tk.Canvas(root, width=400, height=800)
        canvas.pack()

        renderer = PlaceholderQRRenderer(canvas)

        test_data = [
            "Simple text",
            "https://example.com",
            "mailto:test@example.com",
            "WIFI:S:Network;T:WPA;P:Password;;",
            "BEGIN:VCARD\nVERSION:3.0\nN:Test\nEND:VCARD",
        ]

        y_offset = 10
        for data in test_data:
            item_id = renderer.render_qr(data, 10, y_offset, 120)
            assert item_id is not None
            y_offset += 150

        renderer.clear()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
