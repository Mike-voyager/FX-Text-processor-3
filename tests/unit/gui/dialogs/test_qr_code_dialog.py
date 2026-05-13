"""Тесты для qr_code_dialog модуля.

Тестирует:
- QRCodeSettingsDialog
- QRCodeSettings dataclass
- QRCodeResult dataclass

Example:
    $ pytest tests/unit/gui/dialogs/test_qr_code_dialog.py -v

Module: tests/unit/gui/dialogs/test_qr_code_dialog.py
Version: 1.0
"""

from __future__ import annotations

import sys
import tkinter as tk
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Skip GUI tests if no display available
if sys.platform == "linux" and not sys.stdin.isatty():
    try:
        import tkinter as tk

        tk.Tcl().eval("info patchlevel")
    except tk.TclError:
        pytest.skip("No display available", allow_module_level=True)

from src.gui.dialogs.qr_code_dialog import (
    QRCodeResult,
    QRCodeSettings,
    QRCodeSettingsDialog,
    ERROR_CORRECTION_LEVELS,
    QR_VERSIONS,
    BOX_SIZES,
)
from src.gui.dialogs.barcode_dialog import BarcodeMode


@pytest.fixture
def root():
    """Создаёт root Tk окно для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestQRCodeSettings:
    """Тесты для QRCodeSettings dataclass."""

    def test_default_settings(self):
        """Проверяет настройки по умолчанию."""
        settings = QRCodeSettings()
        assert settings.data == ""
        assert settings.error_correction == "M"
        assert settings.version == "auto"
        assert settings.box_size == 4
        assert settings.border == 4
        assert settings.mode == BarcodeMode.SOFTWARE

    def test_custom_settings(self):
        """Проверяет создание с кастомными значениями."""
        settings = QRCodeSettings(
            data="https://example.com",
            error_correction="H",
            version="10",
            box_size=6,
            border=2,
        )
        assert settings.data == "https://example.com"
        assert settings.error_correction == "H"
        assert settings.version == "10"
        assert settings.box_size == 6
        assert settings.border == 2

    def test_qr_always_software_mode(self):
        """Проверяет что QR всегда в software mode."""
        settings = QRCodeSettings()
        assert settings.mode == BarcodeMode.SOFTWARE


class TestQRCodeResult:
    """Тесты для QRCodeResult dataclass."""

    def test_result_creation(self):
        """Проверяет создание результата."""
        settings = QRCodeSettings(data="test")
        result = QRCodeResult(
            settings=settings,
            export_path="/tmp/qr.png",
        )
        assert result.settings == settings
        assert result.export_path == "/tmp/qr.png"

    def test_result_without_export(self):
        """Проверяет результат без пути экспорта."""
        settings = QRCodeSettings(data="test")
        result = QRCodeResult(settings=settings)
        assert result.export_path is None

    def test_result_immutability(self):
        """Проверяет неизменяемость результата."""
        settings = QRCodeSettings(data="test")
        result = QRCodeResult(settings=settings)
        with pytest.raises(AttributeError):
            result.export_path = "/new/path.png"


class TestErrorCorrectionLevels:
    """Тесты для константы ERROR_CORRECTION_LEVELS."""

    def test_all_levels_present(self):
        """Проверяет наличие всех уровней."""
        levels = [level[0] for level in ERROR_CORRECTION_LEVELS]
        assert "L" in levels
        assert "M" in levels
        assert "Q" in levels
        assert "H" in levels

    def test_levels_have_descriptions(self):
        """Проверяет что уровни имеют описания."""
        for level, name, desc in ERROR_CORRECTION_LEVELS:
            assert len(name) > 0
            assert len(desc) > 0
            assert "%" in desc  # Should contain percentage


class TestQRVersions:
    """Тесты для константы QR_VERSIONS."""

    def test_auto_version_present(self):
        """Проверяет наличие auto версии."""
        versions = [v[0] for v in QR_VERSIONS]
        assert "auto" in versions

    def test_numeric_versions_present(self):
        """Проверяет наличие числовых версий."""
        versions = [v[0] for v in QR_VERSIONS]
        assert "1" in versions
        assert "10" in versions
        assert "40" in versions

    def test_versions_have_descriptions(self):
        """Проверяет что версии имеют описания."""
        for version, desc in QR_VERSIONS:
            assert len(desc) > 0


class TestBoxSizes:
    """Тесты для константы BOX_SIZES."""

    def test_box_sizes_is_list(self):
        """Проверяет что BOX_SIZES - список."""
        assert isinstance(BOX_SIZES, list)

    def test_box_sizes_contains_expected_values(self):
        """Проверяет наличие ожидаемых значений."""
        assert 2 in BOX_SIZES
        assert 4 in BOX_SIZES
        assert 10 in BOX_SIZES

    def test_box_sizes_are_positive(self):
        """Проверяет что размеры положительные."""
        for size in BOX_SIZES:
            assert size > 0


class TestQRCodeSettingsDialog:
    """Тесты для QRCodeSettingsDialog."""

    @pytest.fixture
    def dialog(self, root):
        """Создаёт диалог настроек QR."""
        dialog = QRCodeSettingsDialog(root)
        yield dialog
        try:
            dialog.destroy()
        except tk.TclError:
            pass

    def test_dialog_creation(self, dialog):
        """Проверяет создание диалога."""
        assert dialog is not None

    def test_dialog_with_default_data(self, root):
        """Проверяет создание с данными по умолчанию."""
        dialog = QRCodeSettingsDialog(
            root,
            default_data="https://example.com",
        )
        assert dialog._settings.data == "https://example.com"
        dialog.destroy()

    def test_dialog_with_custom_settings(self, root):
        """Проверяет создание с кастомными настройками."""
        custom_settings = QRCodeSettings(
            data="test data",
            error_correction="H",
            box_size=8,
        )
        dialog = QRCodeSettingsDialog(
            root,
            default_settings=custom_settings,
        )
        assert dialog._settings.error_correction == "H"
        assert dialog._settings.box_size == 8
        dialog.destroy()

    @patch.object(QRCodeSettingsDialog, "wait_window")
    def test_show_returns_result(self, mock_wait, root):
        """Проверяет что show возвращает результат."""
        dialog = QRCodeSettingsDialog(root)
        mock_wait.return_value = None

        # Simulate successful settings
        settings = QRCodeSettings(data="test result")
        dialog._result = QRCodeResult(settings=settings)

        result = dialog.show()
        assert result is not None
        assert isinstance(result, QRCodeResult)
        dialog.destroy()

    @patch.object(QRCodeSettingsDialog, "wait_window")
    def test_show_returns_none_on_cancel(self, mock_wait, root):
        """Проверяет что show возвращает None при отмене."""
        dialog = QRCodeSettingsDialog(root)
        mock_wait.return_value = None

        # Simulate cancellation
        dialog._result = None

        result = dialog.show()
        assert result is None
        dialog.destroy()

    def test_data_length_tracking(self, dialog):
        """Проверяет отслеживание длины данных."""
        # Initially should show 0
        dialog._data_text.insert("1.0", "test")
        dialog._on_data_changed()
        
        # Check that length is tracked
        length_text = dialog._data_length_var.get()
        assert "символов" in length_text


class TestQRPreview:
    """Тесты для функциональности предпросмотра."""

    def test_placeholder_shown_without_data(self, root):
        """Проверяет что placeholder показывается без данных."""
        dialog = QRCodeSettingsDialog(root)
        dialog._show_placeholder("Test placeholder")
        
        # Should have cleared canvas and added text
        items = dialog._preview_canvas.find_all()
        assert len(items) > 0
        dialog.destroy()

    def test_show_placeholder_clears_image(self, root):
        """Проверяет что placeholder очищает изображение."""
        dialog = QRCodeSettingsDialog(root)
        dialog._preview_photo = MagicMock()
        dialog._show_placeholder("Test")
        
        # PhotoImage should be cleared
        assert dialog._preview_photo is None
        dialog.destroy()


@pytest.mark.slow
class TestQRDialogIntegration:
    """Интеграционные тесты для QR диалогов."""

    def test_full_qr_settings_flow(self, root):
        """Тестирует полный flow настроек QR."""
        # Create dialog with custom settings
        settings = QRCodeSettings(
            data="https://example.com/test",
            error_correction="Q",
            version="10",
            box_size=6,
            border=2,
        )
        
        dialog = QRCodeSettingsDialog(
            root,
            default_settings=settings,
        )

        # Verify settings are applied
        assert dialog._settings.data == "https://example.com/test"
        assert dialog._settings.error_correction == "Q"
        assert dialog._settings.version == "10"
        assert dialog._settings.box_size == 6

        dialog.destroy()

    def test_error_correction_change(self, root):
        """Тестирует изменение уровня коррекции ошибок."""
        dialog = QRCodeSettingsDialog(root)
        
        # Change error correction
        dialog._ec_var.set("H")
        assert dialog._ec_var.get() == "H"
        
        dialog.destroy()

    def test_version_selection(self, root):
        """Тестирует выбор версии."""
        dialog = QRCodeSettingsDialog(root)
        
        # Test changing version
        dialog._version_var.set("20")
        dialog._on_version_changed()
        
        # Description should be updated
        desc = dialog._version_desc.cget("text")
        assert "Version 20" in desc
        
        dialog.destroy()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
