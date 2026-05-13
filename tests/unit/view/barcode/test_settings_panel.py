"""Тесты для BarcodeSettingsPanel."""

from __future__ import annotations

import pytest
import tkinter as tk

from src.view.barcode.settings_panel import BarcodeSettingsPanel


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestBarcodeSettingsPanel:
    """Тесты для панели настроек штрих-кода."""

    def test_init_default(self, root):
        """Тест инициализации с дефолтными значениями."""
        panel = BarcodeSettingsPanel(root)
        settings = panel.get_settings()

        assert settings["width"] == 50
        assert settings["height"] == 20
        assert settings["hri_position"] == "Below"
        assert settings["auto_checksum"] is True

    def test_init_custom(self, root):
        """Тест инициализации с кастомными значениями."""
        panel = BarcodeSettingsPanel(
            root,
            width_mm=100,
            height_mm=30,
            hri_position="Above",
            auto_checksum=False,
        )
        settings = panel.get_settings()

        assert settings["width"] == 100
        assert settings["height"] == 30
        assert settings["hri_position"] == "Above"
        assert settings["auto_checksum"] is False

    def test_set_width(self, root):
        """Тест установки ширины."""
        panel = BarcodeSettingsPanel(root)
        panel.set_width(75)

        settings = panel.get_settings()
        assert settings["width"] == 75

    def test_set_height(self, root):
        """Тест установки высоты."""
        panel = BarcodeSettingsPanel(root)
        panel.set_height(25)

        settings = panel.get_settings()
        assert settings["height"] == 25

    def test_set_hri_position(self, root):
        """Тест установки HRI позиции."""
        panel = BarcodeSettingsPanel(root)

        for position in ["None", "Above", "Below", "Both"]:
            panel.set_hri_position(position)
            settings = panel.get_settings()
            assert settings["hri_position"] == position

    def test_get_settings_returns_dict(self, root):
        """Тест что get_settings возвращает словарь."""
        panel = BarcodeSettingsPanel(root)
        settings = panel.get_settings()

        assert isinstance(settings, dict)
        assert "width" in settings
        assert "height" in settings
        assert "hri_position" in settings
        assert "auto_checksum" in settings


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
