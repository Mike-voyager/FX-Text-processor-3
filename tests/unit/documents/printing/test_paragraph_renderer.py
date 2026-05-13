"""Тесты для модуля paragraph_renderer.

Покрытие:
- ParagraphRenderer инициализация
- render() рендеринг параграфа
- _render_alignment() выравнивание
- _render_indent() отступы
- Helper методы: _get_printable_width_chars, _get_units_per_char
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from src.documents.printing.paragraph_renderer import ParagraphRenderer
from src.model.enums import Alignment, CharactersPerInch, CodePage


class TestParagraphRendererInit:
    """Тесты инициализации ParagraphRenderer."""

    def test_create_default(self) -> None:
        """Создание с настройками по умолчанию."""
        renderer = ParagraphRenderer()
        assert renderer._codepage == CodePage.PC866

    def test_create_with_codepage(self) -> None:
        """Создание с указанной кодовой страницей."""
        renderer = ParagraphRenderer(codepage=CodePage.PC850)
        assert renderer._codepage == CodePage.PC850


class TestRenderParagraph:
    """Тесты рендеринга параграфа."""

    @pytest.fixture
    def mock_paragraph(self) -> MagicMock:
        """Мок параграфа."""
        para = MagicMock()
        para.alignment = Alignment.LEFT
        para.tabstops = None
        para.runs = []
        return para

    def test_render_empty_paragraph(self, mock_paragraph: MagicMock) -> None:
        """Рендеринг пустого параграфа."""
        renderer = ParagraphRenderer()
        result = renderer.render(mock_paragraph)
        assert isinstance(result, bytes)
        assert result.endswith(b"\n")  # LF в конце

    def test_render_line_feed_at_end(self, mock_paragraph: MagicMock) -> None:
        """LF в конце параграфа."""
        renderer = ParagraphRenderer()
        result = renderer.render(mock_paragraph)
        assert result[-1:] == b"\n"

    def test_render_with_left_alignment(self, mock_paragraph: MagicMock) -> None:
        """Выравнивание по левому краю."""
        mock_paragraph.alignment = Alignment.LEFT
        renderer = ParagraphRenderer()
        result = renderer.render(mock_paragraph)
        assert isinstance(result, bytes)

    def test_render_with_center_alignment(self, mock_paragraph: MagicMock) -> None:
        """Выравнивание по центру."""
        mock_paragraph.alignment = Alignment.CENTER
        renderer = ParagraphRenderer()
        result = renderer.render(mock_paragraph)
        assert isinstance(result, bytes)

    def test_render_with_right_alignment(self, mock_paragraph: MagicMock) -> None:
        """Выравнивание по правому краю."""
        mock_paragraph.alignment = Alignment.RIGHT
        renderer = ParagraphRenderer()
        result = renderer.render(mock_paragraph)
        assert isinstance(result, bytes)

    def test_render_with_tabstops(self, mock_paragraph: MagicMock) -> None:
        """Параграф с табуляторами."""
        mock_paragraph.tabstops = [10, 20, 30]
        renderer = ParagraphRenderer()
        result = renderer.render(mock_paragraph)
        # ESC D - установка табуляторов
        assert b"\x1bD" in result


class TestRenderAlignment:
    """Тесты выравнивания."""

    def test_left_alignment(self) -> None:
        """Левое выравнивание (по умолчанию)."""
        renderer = ParagraphRenderer()
        result = renderer._render_alignment(Alignment.LEFT, text_width_chars=10)
        assert result == b""

    def test_center_alignment(self) -> None:
        """Центральное выравнивание."""
        renderer = ParagraphRenderer()
        # При CENTER и тексте 10 символов, позиционирование должно быть
        result = renderer._render_alignment(Alignment.CENTER, text_width_chars=10)
        assert isinstance(result, bytes)
        # ESC $ command should be present
        assert b"\x1b$" in result

    def test_right_alignment(self) -> None:
        """Правое выравнивание."""
        renderer = ParagraphRenderer()
        # При RIGHT и тексте 10 символов
        result = renderer._render_alignment(Alignment.RIGHT, text_width_chars=10)
        assert isinstance(result, bytes)
        # ESC $ command should be present
        assert b"\x1b$" in result

    def test_justify_alignment(self) -> None:
        """Выравнивание по ширине (не поддерживается, fallback на LEFT)."""
        renderer = ParagraphRenderer()
        result = renderer._render_alignment(Alignment.JUSTIFY, text_width_chars=10)
        assert result == b""  # JUSTIFY не поддерживается

    def test_center_alignment_text_too_long(self) -> None:
        """CENTER при тексте длиннее строки — без позиционирования."""
        renderer = ParagraphRenderer()
        # Текст длиной 100 символов при ширине ~65 символов
        result = renderer._render_alignment(Alignment.CENTER, text_width_chars=100)
        # Должен вернуть пустой результат (текст не влезает)
        assert result == b""

    def test_right_alignment_text_too_long(self) -> None:
        """RIGHT при тексте длиннее строки — без позиционирования."""
        renderer = ParagraphRenderer()
        result = renderer._render_alignment(Alignment.RIGHT, text_width_chars=100)
        assert result == b""

    def test_center_with_page_settings(self) -> None:
        """CENTER с кастомными настройками страницы."""
        from src.model.section import Margins, PageSettings

        # Узкая страница с большими полями
        margins = Margins(left=2.0, right=2.0, top=1.0, bottom=1.0)
        page_settings = PageSettings(width=8.5, height=11.0, margins=margins)
        renderer = ParagraphRenderer(page_settings=page_settings)

        # Печатная ширина = 8.5 - 2 - 2 = 4.5 дюйма
        # При 10 CPI: ~45 символов
        result = renderer._render_alignment(Alignment.CENTER, text_width_chars=10)
        assert b"\x1b$" in result


class TestRenderIndent:
    """Тесты отступов."""

    def test_zero_indent(self) -> None:
        """Нулевой отступ."""
        renderer = ParagraphRenderer()
        result = renderer._render_indent(0)
        assert result == b""

    def test_positive_indent(self) -> None:
        """Положительный отступ."""
        renderer = ParagraphRenderer()
        result = renderer._render_indent(5)
        assert result == b"     "

    def test_negative_indent(self) -> None:
        """Отрицательный отступ."""
        renderer = ParagraphRenderer()
        result = renderer._render_indent(-1)
        assert result == b""

    def test_large_indent(self) -> None:
        """Большой отступ."""
        renderer = ParagraphRenderer()
        result = renderer._render_indent(10)
        assert len(result) == 10
        assert result == b" " * 10


class TestHelperMethods:
    """Тесты helper методов."""

    def test_get_printable_width_chars_default(self) -> None:
        """Ширина печатной области по умолчанию."""
        renderer = ParagraphRenderer()
        # Default: Letter 8.5", margins 1" each = 6.5" printable
        # At 10 CPI: 65 chars
        width = renderer._get_printable_width_chars()
        assert width == 65

    def test_get_printable_width_chars_custom_page(self) -> None:
        """Ширина печатной области с кастомными настройками."""
        from src.model.section import Margins, PageSettings

        margins = Margins(left=0.5, right=0.5, top=1.0, bottom=1.0)
        page_settings = PageSettings(width=8.5, height=11.0, margins=margins)
        renderer = ParagraphRenderer(page_settings=page_settings)

        # 8.5 - 0.5 - 0.5 = 7.5" printable
        # At 10 CPI: 75 chars
        width = renderer._get_printable_width_chars()
        assert width == 75

    def test_get_printable_width_chars_12_cpi(self) -> None:
        """Ширина при 12 CPI."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_12)
        # Default: 6.5" printable
        # At 12 CPI: 78 chars
        width = renderer._get_printable_width_chars()
        assert width == 78

    def test_get_units_per_char_10_cpi(self) -> None:
        """Units per char при 10 CPI."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_10)
        units = renderer._get_units_per_char()
        assert units == 6  # 60 / 10

    def test_get_units_per_char_12_cpi(self) -> None:
        """Units per char при 12 CPI."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_12)
        units = renderer._get_units_per_char()
        assert units == 5  # 60 / 12

    def test_get_text_width(self) -> None:
        """Вычисление ширины текста."""
        from src.model.paragraph import Paragraph
        from src.model.run import Run

        para = Paragraph(runs=[Run(text="Hello, World!")])
        renderer = ParagraphRenderer()
        width = renderer._get_text_width(para)
        assert width == 13


class TestCenterRightPositioning:
    """Тесты позиционирования CENTER/RIGHT."""

    def test_center_position_calculation(self) -> None:
        """Расчёт позиции для CENTER."""
        renderer = ParagraphRenderer()
        # Default: 65 chars width, 10 char text
        # Position: (65 - 10) / 2 = 27 chars
        # Units: 27 * 6 = 162 units
        result = renderer._render_alignment(Alignment.CENTER, text_width_chars=10)
        assert b"\x1b$" in result
        # Position 162 in little-endian: 0xA2 0x00
        # Check that position bytes are present
        assert len(result) == 4  # ESC $ + 2 bytes

    def test_right_position_calculation(self) -> None:
        """Расчёт позиции для RIGHT."""
        renderer = ParagraphRenderer()
        # Default: 65 chars width, 10 char text
        # Position: 65 - 10 = 55 chars
        # Units: 55 * 6 = 330 units
        result = renderer._render_alignment(Alignment.RIGHT, text_width_chars=10)
        assert b"\x1b$" in result
        assert len(result) == 4

    def test_center_with_12_cpi(self) -> None:
        """CENTER при 12 CPI (другие units per char)."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_12)
        # Default: 78 chars width (6.5" * 12)
        # Position: (78 - 10) / 2 = 34 chars
        # Units: 34 * 5 = 170 units
        result = renderer._render_alignment(Alignment.CENTER, text_width_chars=10)
        assert b"\x1b$" in result


class TestParagraphRendererWithCPI:
    """Тесты ParagraphRenderer с разными CPI."""

    def test_create_with_12_cpi(self) -> None:
        """Создание с 12 CPI."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_12)
        assert renderer._cpi == CharactersPerInch.CPI_12

    def test_create_with_15_cpi(self) -> None:
        """Создание с 15 CPI."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_15)
        assert renderer._cpi == CharactersPerInch.CPI_15

    def test_15_cpi_units_per_char(self) -> None:
        """Units per char при 15 CPI."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_15)
        units = renderer._get_units_per_char()
        assert units == 4  # 60 / 15

    def test_17_cpi_units_per_char(self) -> None:
        """Units per char при 17 CPI."""
        renderer = ParagraphRenderer(cpi=CharactersPerInch.CPI_17)
        units = renderer._get_units_per_char()
        assert units == 3  # 60 / 17 ≈ 3
