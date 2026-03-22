"""Тесты для модуля barcode_renderer.

Покрытие:
- BarcodeRenderer инициализация
- render() рендеринг штрихкода
- render_ean13() EAN-13
- render_code128() Code 128
- render_code39() Code 39
- Валидация параметров
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from src.documents.printing.barcode_renderer import BarcodeRenderer
from src.escp.commands.barcode import BarcodeHRI, ESCPBarcodeType


class TestBarcodeRendererInit:
    """Тесты инициализации BarcodeRenderer."""

    def test_create(self) -> None:
        """Создание рендерера."""
        renderer = BarcodeRenderer()
        assert renderer is not None


class TestRenderBarcode:
    """Тесты рендеринга штрихкода."""

    @pytest.fixture
    def renderer(self) -> BarcodeRenderer:
        """Рендерер штрихкодов."""
        return BarcodeRenderer()

    def test_render_ean13(self, renderer: BarcodeRenderer) -> None:
        """Рендеринг EAN-13."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            result = renderer.render("123456789012", ESCPBarcodeType.EAN13)
            assert result == b"barcode_data"
            mock_build.assert_called_once()

    def test_render_code128(self, renderer: BarcodeRenderer) -> None:
        """Рендеринг Code 128."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            renderer.render("ABC123", ESCPBarcodeType.CODE128)
            mock_build.assert_called_once()

    def test_render_empty_data(self, renderer: BarcodeRenderer) -> None:
        """Пустые данные."""
        result = renderer.render("", ESCPBarcodeType.EAN13)
        assert result == b""

    def test_render_invalid_module_width(self, renderer: BarcodeRenderer) -> None:
        """Неверная ширина модуля."""
        with pytest.raises(ValueError, match="Module width"):
            renderer.render("123", ESCPBarcodeType.EAN13, module_width=0)

    def test_render_invalid_module_width_high(self, renderer: BarcodeRenderer) -> None:
        """Ширина модуля больше максимума."""
        with pytest.raises(ValueError, match="Module width"):
            renderer.render("123", ESCPBarcodeType.EAN13, module_width=7)

    def test_render_invalid_height(self, renderer: BarcodeRenderer) -> None:
        """Неверная высота."""
        with pytest.raises(ValueError, match="Height"):
            renderer.render("123", ESCPBarcodeType.EAN13, height=0)

    def test_render_invalid_height_high(self, renderer: BarcodeRenderer) -> None:
        """Высота больше максимума."""
        with pytest.raises(ValueError, match="Height"):
            renderer.render("123", ESCPBarcodeType.EAN13, height=256)


class TestRenderEan13:
    """Тесты EAN-13."""

    @pytest.fixture
    def renderer(self) -> BarcodeRenderer:
        """Рендерер штрихкодов."""
        return BarcodeRenderer()

    def test_render_ean13(self, renderer: BarcodeRenderer) -> None:
        """Рендеринг EAN-13."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            result = renderer.render_ean13("123456789012")
            assert result == b"barcode_data"

    def test_render_ean13_with_params(self, renderer: BarcodeRenderer) -> None:
        """EAN-13 с параметрами."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            renderer.render_ean13("123456789012", module_width=3, height=100)
            call_kwargs = mock_build.call_args.kwargs
            assert call_kwargs["width"] == 3
            assert call_kwargs["height"] == 100


class TestRenderCode128:
    """Тесты Code 128."""

    @pytest.fixture
    def renderer(self) -> BarcodeRenderer:
        """Рендерер штрихкодов."""
        return BarcodeRenderer()

    def test_render_code128(self, renderer: BarcodeRenderer) -> None:
        """Рендеринг Code 128."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            result = renderer.render_code128("ABC123")
            assert result == b"barcode_data"

    def test_render_code128_with_params(self, renderer: BarcodeRenderer) -> None:
        """Code 128 с параметрами."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            renderer.render_code128("ABC123", module_width=2, height=50)
            call_kwargs = mock_build.call_args.kwargs
            assert call_kwargs["width"] == 2
            assert call_kwargs["height"] == 50


class TestRenderCode39:
    """Тесты Code 39."""

    @pytest.fixture
    def renderer(self) -> BarcodeRenderer:
        """Рендерер штрихкодов."""
        return BarcodeRenderer()

    def test_render_code39(self, renderer: BarcodeRenderer) -> None:
        """Рендеринг Code 39."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            result = renderer.render_code39("ABC-123")
            assert result == b"barcode_data"

    def test_render_code39_with_params(self, renderer: BarcodeRenderer) -> None:
        """Code 39 с параметрами."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            mock_build.return_value = b"barcode_data"
            renderer.render_code39("ABC-123", hri=BarcodeHRI.NONE)
            call_kwargs = mock_build.call_args.kwargs
            assert call_kwargs["hri"] == BarcodeHRI.NONE


class TestParameterValidation:
    """Тесты валидации параметров."""

    @pytest.fixture
    def renderer(self) -> BarcodeRenderer:
        """Рендерер штрихкодов."""
        return BarcodeRenderer()

    def test_valid_module_width_range(self, renderer: BarcodeRenderer) -> None:
        """Допустимый диапазон ширины."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command"):
            for width in range(1, 7):
                renderer.render("123", ESCPBarcodeType.CODE39, module_width=width)

    def test_valid_height_range(self, renderer: BarcodeRenderer) -> None:
        """Допустимый диапазон высоты."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command"):
            for height in [1, 50, 100, 255]:
                renderer.render("123", ESCPBarcodeType.CODE39, height=height)

    def test_hri_positions(self, renderer: BarcodeRenderer) -> None:
        """Позиции HRI текста."""
        with patch("src.documents.printing.barcode_renderer.build_barcode_command") as mock_build:
            for hri in BarcodeHRI:
                renderer.render("123", ESCPBarcodeType.CODE39, hri=hri)
            assert mock_build.call_count == len(BarcodeHRI)
