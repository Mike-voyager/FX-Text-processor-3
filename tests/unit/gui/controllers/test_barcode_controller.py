"""Тесты для barcode_controller модуля.

Тестирует:
- BarcodeController
- validate_barcode_data
- format_barcode_data

Example:
    $ pytest tests/unit/gui/controllers/test_barcode_controller.py -v

Module: tests/unit/gui/controllers/test_barcode_controller.py
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

from src.gui.controllers.barcode_controller import (
    BarcodeController,
    format_barcode_data,
    validate_barcode_data,
)
from src.gui.dialogs.barcode_dialog import BarcodeMode, BarcodeSettings
from src.model.enums import BarcodeType


@pytest.fixture
def root():
    """Создаёт root Tk окно для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class MockView:
    """Мок View для тестирования."""

    def __init__(self):
        self.insert_barcode_called = False
        self.insert_qr_called = False
        self.last_barcode_type = None
        self.last_data = None
        self.last_mode = None

    def insert_barcode_at_cursor(
        self,
        barcode_type: str,
        data: str,
        mode: str,
        settings: dict[str, Any] | None = None,
    ) -> bool:
        self.insert_barcode_called = True
        self.last_barcode_type = barcode_type
        self.last_data = data
        self.last_mode = mode
        return True

    def insert_qr_at_cursor(
        self,
        data: str,
        settings: dict[str, Any] | None = None,
    ) -> bool:
        self.insert_qr_called = True
        self.last_data = data
        return True

    def get_cursor_position(self) -> tuple[int, int]:
        return (1, 0)


class TestValidateBarcodeData:
    """Тесты для функции валидации."""

    def test_empty_data(self):
        """Проверяет валидацию пустых данных."""
        valid, msg = validate_barcode_data("CODE128", "")
        assert not valid
        assert "пустыми" in msg

    def test_ean13_valid(self):
        """Проверяет валидный EAN-13."""
        valid, msg = validate_barcode_data("EAN13", "1234567890123")
        assert valid
        assert msg == ""

    def test_ean13_invalid_length(self):
        """Проверяет EAN-13 с неверной длиной."""
        valid, msg = validate_barcode_data("EAN13", "1234567890")
        assert not valid
        assert "13 цифр" in msg

    def test_ean13_invalid_chars(self):
        """Проверяет EAN-13 с буквами."""
        valid, msg = validate_barcode_data("EAN13", "1234567890ABC")
        assert not valid
        assert "только цифры" in msg

    def test_ean8_valid(self):
        """Проверяет валидный EAN-8."""
        valid, msg = validate_barcode_data("EAN8", "12345678")
        assert valid

    def test_ean8_invalid_length(self):
        """Проверяет EAN-8 с неверной длиной."""
        valid, msg = validate_barcode_data("EAN8", "1234567")
        assert not valid
        assert "8 цифр" in msg

    def test_code39_valid(self):
        """Проверяет валидный CODE39."""
        valid, msg = validate_barcode_data("CODE39", "ABC-123")
        assert valid

    def test_code39_invalid_chars(self):
        """Проверяет CODE39 с недопустимыми символами."""
        valid, msg = validate_barcode_data("CODE39", "ABC@123")
        assert not valid
        assert "не поддерживает" in msg

    def test_upc_valid(self):
        """Проверяет валидный UPC."""
        valid, msg = validate_barcode_data("UPCA", "123456789012")
        assert valid

    def test_upc_invalid_length(self):
        """Проверяет UPC с неверной длиной."""
        valid, msg = validate_barcode_data("UPCA", "12345678901")
        assert not valid
        assert "12 цифр" in msg


class TestFormatBarcodeData:
    """Тесты для функции форматирования."""

    def test_ean13_remove_spaces(self):
        """Проверяет удаление пробелов из EAN-13."""
        result = format_barcode_data("EAN13", "123 456 789 012")
        assert result == "123456789012"

    def test_ean13_remove_dashes(self):
        """Проверяет удаление дефисов из EAN-13."""
        result = format_barcode_data("EAN13", "123-456-789-012")
        assert result == "123456789012"

    def test_code39_uppercase(self):
        """Проверяет uppercase для CODE39."""
        result = format_barcode_data("CODE39", "abc-123")
        assert result == "ABC-123"

    def test_code128_unchanged(self):
        """Проверяет что CODE128 не меняется."""
        result = format_barcode_data("CODE128", "Test-123@#$")
        assert result == "Test-123@#$"


class TestBarcodeController:
    """Тесты для BarcodeController."""

    @pytest.fixture
    def controller(self, root):
        """Создаёт контроллер с мок View."""
        view = MockView()
        controller = BarcodeController(
            parent=root,
            view=view,
            on_insert=lambda t, d: None,
        )
        return controller, view

    def test_controller_creation(self, root):
        """Проверяет создание контроллера."""
        controller = BarcodeController(root)
        assert controller is not None

    def test_controller_with_view(self, controller):
        """Проверяет что View сохраняется."""
        ctrl, view = controller
        assert ctrl._view is view

    def test_default_settings(self, controller):
        """Проверяет настройки по умолчанию."""
        ctrl, _ = controller
        settings = ctrl.get_last_barcode_settings()
        assert isinstance(settings, BarcodeSettings)
        assert settings.width_mm == 50.0
        assert settings.height_mm == 25.0

    def test_set_last_settings(self, controller):
        """Проверяет установку настроек."""
        ctrl, _ = controller
        new_settings = BarcodeSettings(width_mm=100.0, height_mm=50.0)
        ctrl.set_last_barcode_settings(new_settings)
        
        retrieved = ctrl.get_last_barcode_settings()
        assert retrieved.width_mm == 100.0
        assert retrieved.height_mm == 50.0

    def test_check_hardware_conflict_software(self, controller):
        """Проверяет отсутствие конфликта в software mode."""
        ctrl, _ = controller
        from src.gui.dialogs.barcode_dialog import BarcodeSelectionResult
        
        result = BarcodeSelectionResult(
            barcode_type="ITF",  # Not hardware supported
            mode=BarcodeMode.SOFTWARE,
            data="12345",
        )
        assert not ctrl._check_hardware_conflict(result)

    def test_check_hardware_conflict_hardware_supported(self, controller):
        """Проверяет отсутствие конфликта для поддерживаемого типа."""
        ctrl, _ = controller
        from src.gui.dialogs.barcode_dialog import BarcodeSelectionResult
        
        result = BarcodeSelectionResult(
            barcode_type="CODE128",  # Hardware supported
            mode=BarcodeMode.HARDWARE,
            data="12345",
        )
        assert not ctrl._check_hardware_conflict(result)

    def test_check_hardware_conflict_hardware_unsupported(self, controller):
        """Проверяет конфликт для неподдерживаемого типа."""
        ctrl, _ = controller
        from src.gui.dialogs.barcode_dialog import BarcodeSelectionResult
        
        result = BarcodeSelectionResult(
            barcode_type="CODABAR",  # Not hardware supported
            mode=BarcodeMode.HARDWARE,
            data="12345",
        )
        assert ctrl._check_hardware_conflict(result)

    def test_insert_barcode_without_view(self, root):
        """Проверяет вставку без View (fallback)."""
        controller = BarcodeController(root)
        from src.gui.dialogs.barcode_dialog import BarcodeSelectionResult
        
        result = BarcodeSelectionResult(
            barcode_type="CODE128",
            mode=BarcodeMode.SOFTWARE,
            data="TEST123",
        )
        
        # Should not raise
        success = controller._insert_barcode(result)
        assert success


@pytest.mark.slow
class TestBarcodeControllerIntegration:
    """Интеграционные тесты для контроллера."""

    def test_full_barcode_flow(self, root):
        """Тестирует полный flow вставки штрих-кода."""
        view = MockView()
        callback_called = False
        
        def on_insert(barcode_type, data):
            nonlocal callback_called
            callback_called = True
        
        controller = BarcodeController(
            parent=root,
            view=view,
            on_insert=on_insert,
        )
        
        from src.gui.dialogs.barcode_dialog import BarcodeSelectionResult
        
        result = BarcodeSelectionResult(
            barcode_type="CODE128",
            mode=BarcodeMode.SOFTWARE,
            data="TEST123",
        )
        
        success = controller._insert_barcode(result)
        
        assert success
        assert view.insert_barcode_called
        assert view.last_barcode_type == "CODE128"
        assert view.last_data == "TEST123"
        assert view.last_mode == "software"

    def test_full_qr_flow(self, root):
        """Тестирует полный flow вставки QR."""
        view = MockView()
        callback_called = False
        
        def on_insert(barcode_type, data):
            nonlocal callback_called
            callback_called = True
        
        controller = BarcodeController(
            parent=root,
            view=view,
            on_insert=on_insert,
        )
        
        from src.gui.dialogs.qr_code_dialog import QRCodeResult, QRCodeSettings
        
        result = QRCodeResult(
            settings=QRCodeSettings(
                data="https://example.com",
                error_correction="H",
            )
        )
        
        success = controller._insert_qr(result)
        
        assert success
        assert view.insert_qr_called
        assert view.last_data == "https://example.com"

    def test_validation_before_insert(self):
        """Тестирует валидацию перед вставкой."""
        # Valid EAN-13
        valid, _ = validate_barcode_data("EAN13", "1234567890123")
        assert valid
        
        # Invalid EAN-13
        valid, msg = validate_barcode_data("EAN13", "INVALID")
        assert not valid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
