"""Интеграционный тест E2E для Barcode/QR flow.

Тестирует полный flow:
1. Открытие диалога
2. Настройка параметров
3. Вставка в DocumentView
4. Рендеринг на canvas

Example:
    $ pytest tests/integration/gui/test_barcode_flow.py -v

Module: tests/integration/gui/test_barcode_flow.py
Version: 1.0
"""

from __future__ import annotations

import sys
import tkinter as tk
from typing import Any
from unittest.mock import Mock

import pytest

# Skip GUI tests if no display available
if sys.platform == "linux" and not sys.stdin.isatty():
    try:
        import tkinter as tk

        tk.Tcl().eval("info patchlevel")
    except tk.TclError:
        pytest.skip("No display available", allow_module_level=True)

from src.gui.controllers.barcode_controller import BarcodeController
from src.gui.dialogs.barcode_dialog import (
    BarcodeMode,
    BarcodeSelectionResult,
    BarcodeSettings,
)
from src.gui.dialogs.qr_code_dialog import QRCodeResult, QRCodeSettings
from src.gui.renderers.barcode_canvas_renderer import (
    BarcodeRenderMode,
    create_barcode_renderer,
)
from src.gui.renderers.qr_canvas_renderer import (
    QRRenderMode,
    create_qr_renderer,
)


@pytest.fixture
def root():
    """Создаёт root Tk окно для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class MockView:
    """Мок View для интеграционного тестирования."""

    def __init__(self):
        self.inserted_barcodes: list[dict[str, Any]] = []
        self.inserted_qrs: list[dict[str, Any]] = []

    def insert_barcode_at_cursor(
        self,
        barcode_type: str,
        data: str,
        mode: str,
        settings: dict[str, Any] | None = None,
    ) -> bool:
        self.inserted_barcodes.append({
            "type": barcode_type,
            "data": data,
            "mode": mode,
            "settings": settings,
        })
        return True

    def insert_qr_at_cursor(
        self,
        data: str,
        settings: dict[str, Any] | None = None,
    ) -> bool:
        self.inserted_qrs.append({
            "data": data,
            "settings": settings,
        })
        return True


class TestBarcodeFlow:
    """Интеграционные тесты flow штрих-кодов."""

    def test_barcode_selection_to_insertion(self, root):
        """Тестирует полный flow выбора и вставки штрих-кода."""
        view = MockView()
        controller = BarcodeController(
            parent=root,
            view=view,
        )

        # Simulate barcode selection result
        result = BarcodeSelectionResult(
            barcode_type="CODE128",
            mode=BarcodeMode.SOFTWARE,
            data="TEST123",
        )

        # Insert through controller
        success = controller._insert_barcode(result)

        assert success
        assert len(view.inserted_barcodes) == 1
        assert view.inserted_barcodes[0]["type"] == "CODE128"
        assert view.inserted_barcodes[0]["data"] == "TEST123"
        assert view.inserted_barcodes[0]["mode"] == "software"

    def test_qr_configuration_to_insertion(self, root):
        """Тестирует полный flow настройки и вставки QR."""
        view = MockView()
        controller = BarcodeController(
            parent=root,
            view=view,
        )

        # Simulate QR result
        result = QRCodeResult(
            settings=QRCodeSettings(
                data="https://example.com",
                error_correction="H",
                version="10",
                box_size=6,
                border=4,
            )
        )

        # Insert through controller
        success = controller._insert_qr(result)

        assert success
        assert len(view.inserted_qrs) == 1
        assert view.inserted_qrs[0]["data"] == "https://example.com"
        assert view.inserted_qrs[0]["settings"]["error_correction"] == "H"

    def test_multiple_barcodes_sequence(self, root):
        """Тестирует последовательную вставку нескольких штрих-кодов."""
        view = MockView()
        controller = BarcodeController(
            parent=root,
            view=view,
        )

        # Insert multiple barcodes
        barcodes = [
            BarcodeSelectionResult("CODE128", BarcodeMode.SOFTWARE, "ABC"),
            BarcodeSelectionResult("EAN13", BarcodeMode.HARDWARE, "1234567890123"),
            BarcodeSelectionResult("CODE39", BarcodeMode.SOFTWARE, "XYZ-123"),
        ]

        for result in barcodes:
            controller._insert_barcode(result)

        assert len(view.inserted_barcodes) == 3

    def test_hardware_conflict_handling(self, root):
        """Тестирует обработку конфликта hardware/software."""
        view = MockView()
        controller = BarcodeController(
            parent=root,
            view=view,
        )

        # CODABAR is not hardware supported
        result = BarcodeSelectionResult(
            barcode_type="CODABAR",
            mode=BarcodeMode.HARDWARE,
            data="A12345B",
        )

        # Check conflict detection
        has_conflict = controller._check_hardware_conflict(result)
        assert has_conflict


class TestCanvasRenderingFlow:
    """Тесты рендеринга на canvas."""

    def test_barcode_canvas_rendering_placeholder(self, root):
        """Тестирует рендеринг штрих-кода в placeholder режиме."""
        canvas = tk.Canvas(root, width=400, height=300)
        canvas.pack()

        renderer = create_barcode_renderer(
            canvas,
            mode="software",
            render_mode=BarcodeRenderMode.PLACEHOLDER,
        )

        item_id = renderer.render(
            barcode_type="CODE128",
            data="TEST",
            x=10,
            y=10,
            width=200,
            height=100,
        )

        assert item_id is not None

        # Cleanup
        renderer.clear()

    def test_qr_canvas_rendering_placeholder(self, root):
        """Тестирует рендеринг QR в placeholder режиме."""
        canvas = tk.Canvas(root, width=400, height=400)
        canvas.pack()

        renderer = create_qr_renderer(
            canvas,
            mode="software",
            render_mode=QRRenderMode.PLACEHOLDER,
        )

        item_id = renderer.render_qr(
            data="https://example.com",
            x=10,
            y=10,
            size=200,
        )

        assert item_id is not None

        # Cleanup
        renderer.clear()


@pytest.mark.slow
class TestEndToEndBarcodeFlow:
    """End-to-end тесты для Barcode/QR flow."""

    def test_full_e2e_barcode_scenario(self, root):
        """Полный E2E сценарий с штрих-кодом."""
        # 1. Create canvas (simulating DocumentView)
        canvas = tk.Canvas(root, width=800, height=600)
        canvas.pack()

        # 2. Create controller with mock view
        view = MockView()
        controller = BarcodeController(
            parent=root,
            view=view,
        )

        # 3. Simulate barcode selection
        barcode_result = BarcodeSelectionResult(
            barcode_type="CODE128",
            mode=BarcodeMode.SOFTWARE,
            data="E2E-TEST-123",
        )

        # 4. Insert through controller
        controller._insert_barcode(barcode_result)

        # 5. Verify insertion
        assert len(view.inserted_barcodes) == 1
        inserted = view.inserted_barcodes[0]
        assert inserted["type"] == "CODE128"
        assert inserted["data"] == "E2E-TEST-123"

        # 6. Create renderer and render on canvas
        renderer = create_barcode_renderer(
            canvas,
            mode="software",
            render_mode=BarcodeRenderMode.PLACEHOLDER,
        )

        item_id = renderer.render(
            barcode_type=inserted["type"],
            data=inserted["data"],
            x=50,
            y=50,
            width=300,
            height=150,
        )

        assert item_id is not None

        # Cleanup
        renderer.clear()

    def test_full_e2e_qr_scenario(self, root):
        """Полный E2E сценарий с QR-кодом."""
        # 1. Create canvas
        canvas = tk.Canvas(root, width=800, height=600)
        canvas.pack()

        # 2. Create controller
        view = MockView()
        controller = BarcodeController(
            parent=root,
            view=view,
        )

        # 3. Simulate QR configuration
        qr_result = QRCodeResult(
            settings=QRCodeSettings(
                data="https://fx-processor.example.com/doc/123",
                error_correction="M",
                version="auto",
                box_size=4,
                border=4,
            )
        )

        # 4. Insert through controller
        controller._insert_qr(qr_result)

        # 5. Verify insertion
        assert len(view.inserted_qrs) == 1
        inserted = view.inserted_qrs[0]
        assert inserted["data"] == "https://fx-processor.example.com/doc/123"

        # 6. Create renderer and render on canvas
        renderer = create_qr_renderer(
            canvas,
            mode="software",
            render_mode=QRRenderMode.PLACEHOLDER,
        )

        item_id = renderer.render_qr(
            data=inserted["data"],
            x=100,
            y=100,
            size=250,
        )

        assert item_id is not None

        # Cleanup
        renderer.clear()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
