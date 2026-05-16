"""Тесты для barcode_dialog модуля.

Тестирует:
- BarcodeTypeSelector
- BarcodeSettingsPanel
- BarcodeConflictDialog
- BarcodeMode enum

Example:
    $ pytest tests/unit/gui/dialogs/test_barcode_dialog.py -v

Module: tests/unit/gui/dialogs/test_barcode_dialog.py
Version: 1.0
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk
from unittest.mock import patch

import pytest

# Skip GUI tests if no display available
if sys.platform == "linux" and not sys.stdin.isatty():
    try:
        import tkinter as tk

        tk.Tcl().eval("info patchlevel")
    except tk.TclError:
        pytest.skip("No display available", allow_module_level=True)

from src.gui.dialogs.barcode_dialog import (
    HARDWARE_TYPES,
    BarcodeConflictDialog,
    BarcodeMode,
    BarcodeSelectionResult,
    BarcodeSettings,
    BarcodeSettingsPanel,
    BarcodeTypeSelector,
)
from src.model.enums import BarcodeType


@pytest.fixture
def root():
    """Создаёт root Tk окно для тестов."""
    root = tk.Tk()
    root.withdraw()  # Hide window
    yield root
    root.destroy()


class TestBarcodeMode:
    """Тесты для BarcodeMode enum."""

    def test_barcode_mode_values(self):
        """Проверяет значения режимов."""
        assert BarcodeMode.HARDWARE.value is not None
        assert BarcodeMode.SOFTWARE.value is not None

    def test_barcode_mode_labels(self):
        """Проверяет метки режимов."""
        assert "Hardware" in BarcodeMode.HARDWARE.label()
        assert "Software" in BarcodeMode.SOFTWARE.label()

    def test_barcode_mode_descriptions(self):
        """Проверяет описания режимов."""
        assert len(BarcodeMode.HARDWARE.description()) > 0
        assert len(BarcodeMode.SOFTWARE.description()) > 0


class TestBarcodeSelectionResult:
    """Тесты для BarcodeSelectionResult dataclass."""

    def test_result_creation(self):
        """Проверяет создание результата."""
        result = BarcodeSelectionResult(
            barcode_type="CODE128",
            mode=BarcodeMode.SOFTWARE,
            data="12345",
        )
        assert result.barcode_type == "CODE128"
        assert result.mode == BarcodeMode.SOFTWARE
        assert result.data == "12345"

    def test_result_immutability(self):
        """Проверяет неизменяемость результата."""
        result = BarcodeSelectionResult(
            barcode_type="CODE128",
            mode=BarcodeMode.SOFTWARE,
            data="12345",
        )
        with pytest.raises(AttributeError):
            result.barcode_type = "EAN13"


class TestBarcodeSettings:
    """Тесты для BarcodeSettings dataclass."""

    def test_default_settings(self):
        """Проверяет настройки по умолчанию."""
        settings = BarcodeSettings()
        assert settings.width_mm == 50.0
        assert settings.height_mm == 25.0
        assert settings.dpi == 300
        assert settings.show_text is True
        assert settings.hri_position == "Below"

    def test_custom_settings(self):
        """Проверяет создание с кастомными значениями."""
        settings = BarcodeSettings(
            width_mm=100.0,
            height_mm=50.0,
            dpi=600,
            show_text=False,
            hri_position="None",
        )
        assert settings.width_mm == 100.0
        assert settings.height_mm == 50.0
        assert settings.dpi == 600
        assert settings.show_text is False
        assert settings.hri_position == "None"


class TestHardwareTypes:
    """Тесты для константы HARDWARE_TYPES."""

    def test_hardware_types_is_set(self):
        """Проверяет что HARDWARE_TYPES - множество."""
        assert isinstance(HARDWARE_TYPES, set)

    def test_common_types_in_hardware(self):
        """Проверяет наличие типов для hardware."""
        assert BarcodeType.EAN13.value in HARDWARE_TYPES
        assert BarcodeType.EAN8.value in HARDWARE_TYPES
        assert BarcodeType.CODE39.value in HARDWARE_TYPES
        assert BarcodeType.CODE128.value in HARDWARE_TYPES

    def test_qr_not_in_hardware(self):
        """Проверяет что QR не в hardware."""
        assert BarcodeType.MSI.value not in HARDWARE_TYPES


class TestBarcodeSettingsPanel:
    """Тесты для BarcodeSettingsPanel."""

    @pytest.fixture
    def panel(self, root):
        """Создаёт панель настроек."""
        panel = BarcodeSettingsPanel(root)
        yield panel

    def test_panel_creation(self, panel):
        """Проверяет создание панели."""
        assert panel is not None
        assert isinstance(panel, ttk.Frame)

    def test_get_settings_default(self, panel):
        """Проверяет получение настроек по умолчанию."""
        settings = panel.get_settings()
        assert isinstance(settings, BarcodeSettings)
        assert settings.width_mm == 50.0

    def test_set_and_get_settings(self, panel):
        """Проверяет установку и получение настроек."""
        new_settings = BarcodeSettings(
            width_mm=75.0,
            height_mm=30.0,
            dpi=200,
        )
        panel.set_settings(new_settings)
        retrieved = panel.get_settings()
        assert retrieved.width_mm == 75.0
        assert retrieved.height_mm == 30.0
        assert retrieved.dpi == 200


class TestBarcodeConflictDialog:
    """Тесты для BarcodeConflictDialog."""

    @pytest.fixture
    def dialog(self, root):
        """Создаёт диалог конфликта."""
        dialog = BarcodeConflictDialog(
            parent=root,
            barcode_type="CODE128",
            reason="Not supported in hardware mode",
            suggested_type="CODE39",
        )
        yield dialog
        try:
            dialog.destroy()
        except tk.TclError:
            pass

    def test_dialog_creation(self, dialog):
        """Проверяет создание диалога."""
        assert dialog is not None

    def test_dialog_attributes(self, dialog):
        """Проверяет атрибуты диалога."""
        assert dialog._barcode_type == "CODE128"
        assert "hardware mode" in dialog._reason.lower()
        assert dialog._suggested_type == "CODE39"

    @patch.object(BarcodeConflictDialog, "wait_window")
    def test_show_returns_tuple(self, mock_wait, root):
        """Проверяет что show возвращает кортеж."""
        dialog = BarcodeConflictDialog(
            parent=root,
            barcode_type="TEST",
            reason="Test reason",
        )
        # Mock the wait_window to prevent blocking
        mock_wait.return_value = None

        # Set result before calling show
        dialog._result = True
        dialog._choice = "software"

        # Should return tuple when dialog finishes
        result = dialog.show()
        assert isinstance(result, tuple)


class TestBarcodeTypeSelector:
    """Тесты для BarcodeTypeSelector."""

    @pytest.fixture
    def selector(self, root):
        """Создаёт диалог выбора."""
        selector = BarcodeTypeSelector(root)
        yield selector
        try:
            selector.destroy()
        except tk.TclError:
            pass

    def test_selector_creation(self, selector):
        """Проверяет создание диалога."""
        assert selector is not None

    def test_selector_default_values(self, selector):
        """Проверяет значения по умолчанию."""
        assert selector._selected_type == BarcodeType.CODE128.value
        assert selector._selected_mode == BarcodeMode.SOFTWARE

    def test_selector_with_custom_values(self, root):
        """Проверяет создание с кастомными значениями."""
        selector = BarcodeTypeSelector(
            parent=root,
            current_type=BarcodeType.EAN13.value,
            current_mode=BarcodeMode.HARDWARE,
            default_data="1234567890123",
        )
        assert selector._current_type == BarcodeType.EAN13.value
        assert selector._selected_mode == BarcodeMode.HARDWARE
        assert selector._data == "1234567890123"
        selector.destroy()

    def test_ui_state_update_with_hardware_unsupported(self, selector):
        """Проверяет обновление UI для несовместимого hardware типа."""
        # Select a type not supported in hardware mode
        selector._selected_type = BarcodeType.ITF.value
        selector._selected_mode = BarcodeMode.HARDWARE
        selector._update_ui_state()

        # Warning should be shown
        warning = selector._warning_var.get()
        assert len(warning) > 0

    def test_ui_state_update_with_hardware_supported(self, selector):
        """Проверяет обновление UI для поддерживаемого hardware типа."""
        selector._selected_type = BarcodeType.CODE128.value
        selector._selected_mode = BarcodeMode.HARDWARE
        selector._data_var.set("TEST123")
        selector._update_ui_state()

        # Should show hardware message
        warning = selector._warning_var.get()
        assert "Hardware" in warning or "ESC/P" in warning

    @patch.object(BarcodeTypeSelector, "wait_window")
    def test_show_returns_result(self, mock_wait, root):
        """Проверяет что show возвращает результат."""
        selector = BarcodeTypeSelector(root)
        mock_wait.return_value = None

        # Simulate successful selection
        selector._result = BarcodeSelectionResult(
            barcode_type="CODE128",
            mode=BarcodeMode.SOFTWARE,
            data="test",
        )

        result = selector.show()
        assert result is not None
        assert isinstance(result, BarcodeSelectionResult)
        selector.destroy()

    @patch.object(BarcodeTypeSelector, "wait_window")
    def test_show_returns_none_on_cancel(self, mock_wait, root):
        """Проверяет что show возвращает None при отмене."""
        selector = BarcodeTypeSelector(root)
        mock_wait.return_value = None

        # Simulate cancellation
        selector._result = None

        result = selector.show()
        assert result is None
        selector.destroy()


@pytest.mark.slow
class TestBarcodeDialogIntegration:
    """Интеграционные тесты для barcode диалогов."""

    def test_full_selection_flow(self, root):
        """Тестирует полный flow выбора штрих-кода."""
        # Create selector
        selector = BarcodeTypeSelector(
            root,
            current_type=BarcodeType.CODE128.value,
            current_mode=BarcodeMode.SOFTWARE,
            default_data="TEST123",
        )

        # Verify initial state
        assert selector._selected_type == BarcodeType.CODE128.value
        assert selector._selected_mode == BarcodeMode.SOFTWARE
        assert selector._data == "TEST123"

        selector.destroy()

    def test_settings_panel_roundtrip(self, root):
        """Тестирует roundtrip настроек."""
        panel = BarcodeSettingsPanel(root)

        # Create custom settings
        original = BarcodeSettings(
            width_mm=100.0,
            height_mm=40.0,
            dpi=600,
            show_text=False,
            hri_position="Above",
        )

        # Set and retrieve
        panel.set_settings(original)
        retrieved = panel.get_settings()

        # Verify all fields
        assert original.width_mm == retrieved.width_mm
        assert original.height_mm == retrieved.height_mm
        assert original.dpi == retrieved.dpi
        assert original.show_text == retrieved.show_text
        assert original.hri_position == retrieved.hri_position

        panel.destroy()

    def test_conflict_dialog_with_suggestion(self, root):
        """Тестирует диалог конфликта с рекомендацией."""
        dialog = BarcodeConflictDialog(
            parent=root,
            barcode_type="ITF",
            reason="Not supported in hardware mode",
            suggested_type="CODE39",
        )

        # Verify suggestion is present
        assert dialog._suggested_type == "CODE39"

        dialog.destroy()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
