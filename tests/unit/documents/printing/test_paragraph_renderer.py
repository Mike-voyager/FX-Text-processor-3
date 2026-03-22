"""Тесты для модуля paragraph_renderer.

Покрытие:
- ParagraphRenderer инициализация
- render() рендеринг параграфа
- _render_alignment() выравнивание
- _render_indent() отступы
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from src.documents.printing.paragraph_renderer import ParagraphRenderer
from src.model.enums import Alignment, CodePage


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
        result = renderer._render_alignment(Alignment.LEFT)
        assert result == b""

    def test_center_alignment(self) -> None:
        """Центральное выравнивание."""
        renderer = ParagraphRenderer()
        result = renderer._render_alignment(Alignment.CENTER)
        assert isinstance(result, bytes)

    def test_right_alignment(self) -> None:
        """Правое выравнивание."""
        renderer = ParagraphRenderer()
        result = renderer._render_alignment(Alignment.RIGHT)
        assert isinstance(result, bytes)

    def test_justify_alignment(self) -> None:
        """Выравнивание по ширине."""
        renderer = ParagraphRenderer()
        result = renderer._render_alignment(Alignment.JUSTIFY)
        assert isinstance(result, bytes)


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
