"""Тесты для BarcodeTypeSelector."""

from __future__ import annotations

import pytest
import tkinter as tk

from src.view.barcode import BarcodeType, BarcodeMode
from src.view.barcode.type_selector import BarcodeTypeSelector


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestBarcodeTypeSelector:
    """Тесты для селектора типа штрих-кода."""

    def test_init_default(self, root):
        """Тест инициализации с дефолтными значениями."""
        selector = BarcodeTypeSelector(root)
        assert selector.get_type() == BarcodeType.CODE_128
        assert selector.get_mode() == BarcodeMode.HARDWARE

    def test_init_custom(self, root):
        """Тест инициализации с кастомными значениями."""
        selector = BarcodeTypeSelector(
            root,
            barcode_type=BarcodeType.EAN_13,
            mode=BarcodeMode.SOFTWARE,
        )
        assert selector.get_type() == BarcodeType.EAN_13
        assert selector.get_mode() == BarcodeMode.SOFTWARE

    def test_set_type(self, root):
        """Тест установки типа."""
        selector = BarcodeTypeSelector(root)
        selector.set_type(BarcodeType.PDF417)
        assert selector.get_type() == BarcodeType.PDF417

    def test_set_mode(self, root):
        """Тест установки режима."""
        selector = BarcodeTypeSelector(root)
        selector.set_mode(BarcodeMode.SOFTWARE)
        assert selector.get_mode() == BarcodeMode.SOFTWARE

    def test_all_types(self, root):
        """Тест всех типов штрих-кодов."""
        for barcode_type in BarcodeType:
            selector = BarcodeTypeSelector(root, barcode_type=barcode_type)
            assert selector.get_type() == barcode_type

    def test_all_modes(self, root):
        """Тест всех режимов."""
        for mode in BarcodeMode:
            selector = BarcodeTypeSelector(root, mode=mode)
            assert selector.get_mode() == mode


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
