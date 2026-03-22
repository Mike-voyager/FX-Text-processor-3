"""Тесты для модуля run_renderer.

Покрытие:
- RunRenderer инициализация
- render() рендеринг Run'а
- _render_styles_on() включение стилей
- _render_styles_off() выключение стилей
- Кодирование текста в CP866
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from src.documents.printing.run_renderer import RunRenderer
from src.model.enums import CodePage, TextStyle


class TestRunRendererInit:
    """Тесты инициализации RunRenderer."""

    def test_create_default(self) -> None:
        """Создание с настройками по умолчанию."""
        renderer = RunRenderer()
        assert renderer._codepage == CodePage.PC866

    def test_create_with_codepage(self) -> None:
        """Создание с указанной кодовой страницей."""
        renderer = RunRenderer(codepage=CodePage.PC850)
        assert renderer._codepage == CodePage.PC850


class TestRenderRun:
    """Тесты рендеринга Run'а."""

    @pytest.fixture
    def mock_run(self) -> MagicMock:
        """Мок Run'а."""
        run = MagicMock()
        run.text = "Hello"
        run.style = TextStyle(0)  # No style
        return run

    def test_render_plain_text(self, mock_run: MagicMock) -> None:
        """Рендеринг обычного текста."""
        renderer = RunRenderer()
        result = renderer.render(mock_run)
        assert b"Hello" in result

    def test_render_empty_text(self, mock_run: MagicMock) -> None:
        """Рендеринг пустого текста."""
        mock_run.text = ""
        renderer = RunRenderer()
        result = renderer.render(mock_run)
        assert result == b""

    def test_render_russian_text(self, mock_run: MagicMock) -> None:
        """Рендеринг русского текста (CP866)."""
        mock_run.text = "Привет"
        renderer = RunRenderer()
        result = renderer.render(mock_run)
        # Проверяем что результат не пустой и не равен UTF-8
        assert len(result) > 0
        assert result != "Привет".encode("utf-8")


class TestRenderStylesOn:
    """Тесты включения стилей."""

    def test_no_style(self) -> None:
        """Без стилей."""
        renderer = RunRenderer()
        result = renderer._render_styles_on(TextStyle(0))
        assert result == b""

    def test_bold_on(self) -> None:
        """Включение жирного."""
        renderer = RunRenderer()
        result = renderer._render_styles_on(TextStyle.BOLD)
        assert b"\x1bE" in result  # ESC E

    def test_italic_on(self) -> None:
        """Включение курсива."""
        renderer = RunRenderer()
        result = renderer._render_styles_on(TextStyle.ITALIC)
        assert b"\x1b4" in result  # ESC 4

    def test_underline_on(self) -> None:
        """Включение подчёркивания."""
        renderer = RunRenderer()
        result = renderer._render_styles_on(TextStyle.UNDERLINE)
        assert b"\x1b-" in result  # ESC -

    def test_bold_italic_on(self) -> None:
        """Включение жирного и курсива."""
        renderer = RunRenderer()
        result = renderer._render_styles_on(TextStyle.BOLD | TextStyle.ITALIC)
        assert b"\x1bE" in result  # ESC E
        assert b"\x1b4" in result  # ESC 4


class TestRenderStylesOff:
    """Тесты выключения стилей."""

    def test_no_style(self) -> None:
        """Без стилей."""
        renderer = RunRenderer()
        result = renderer._render_styles_off(TextStyle(0))
        assert result == b""

    def test_bold_off(self) -> None:
        """Выключение жирного."""
        renderer = RunRenderer()
        result = renderer._render_styles_off(TextStyle.BOLD)
        assert b"\x1bF" in result  # ESC F

    def test_italic_off(self) -> None:
        """Выключение курсива."""
        renderer = RunRenderer()
        result = renderer._render_styles_off(TextStyle.ITALIC)
        assert b"\x1b5" in result  # ESC 5

    def test_underline_off(self) -> None:
        """Выключение подчёркивания."""
        renderer = RunRenderer()
        result = renderer._render_styles_off(TextStyle.UNDERLINE)
        assert b"\x1b-" in result  # ESC - 0

    def test_bold_italic_off(self) -> None:
        """Выключение жирного и курсива."""
        renderer = RunRenderer()
        result = renderer._render_styles_off(TextStyle.BOLD | TextStyle.ITALIC)
        assert b"\x1bF" in result  # ESC F
        assert b"\x1b5" in result  # ESC 5
