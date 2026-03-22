"""Тесты для модуля document_renderer.

Покрытие:
- RenderOptions dataclass
- DocumentRenderer инициализация
- render() полный рендеринг
- _render_init() ESC @ и кодовая страница
- _render_section() рендеринг секций
- _render_finalize() FF (form feed)
- render_to_file() сохранение в файл
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from src.documents.printing.document_renderer import DocumentRenderer, RenderOptions
from src.model.enums import CodePage


class TestRenderOptions:
    """Тесты для RenderOptions."""

    def test_default_options(self) -> None:
        """Опции по умолчанию."""
        opts = RenderOptions()
        assert opts.reset_printer is True
        assert opts.form_feed_at_end is True
        assert opts.page_breaks is True

    def test_custom_options(self) -> None:
        """Пользовательские опции."""
        opts = RenderOptions(reset_printer=False, form_feed_at_end=False)
        assert opts.reset_printer is False
        assert opts.form_feed_at_end is False


class TestDocumentRendererInit:
    """Тесты инициализации DocumentRenderer."""

    def test_create_default(self) -> None:
        """Создание с настройками по умолчанию."""
        renderer = DocumentRenderer()
        assert renderer._codepage == CodePage.PC866
        assert renderer._options.reset_printer is True

    def test_create_with_codepage(self) -> None:
        """Создание с указанной кодовой страницей."""
        renderer = DocumentRenderer(codepage=CodePage.PC850)
        assert renderer._codepage == CodePage.PC850

    def test_create_with_options(self) -> None:
        """Создание с пользовательскими опциями."""
        opts = RenderOptions(reset_printer=False)
        renderer = DocumentRenderer(options=opts)
        assert renderer._options.reset_printer is False


class TestRenderDocument:
    """Тесты рендеринга документа."""

    @pytest.fixture
    def mock_document(self) -> MagicMock:
        """Мок документа с секциями."""
        doc = MagicMock()
        doc.sections = []
        doc.printer_settings = None
        return doc

    def test_render_empty_document(self, mock_document: MagicMock) -> None:
        """Рендеринг пустого документа."""
        renderer = DocumentRenderer()
        result = renderer.render(mock_document)
        assert isinstance(result, bytes)
        assert len(result) > 0  # ESC @ + FF

    def test_render_with_reset(self, mock_document: MagicMock) -> None:
        """Рендеринг с ESC @ (reset)."""
        renderer = DocumentRenderer()
        result = renderer.render(mock_document)
        assert b"\x1b@" in result  # ESC @

    def test_render_without_reset(self, mock_document: MagicMock) -> None:
        """Рендеринг без ESC @."""
        opts = RenderOptions(reset_printer=False)
        renderer = DocumentRenderer(options=opts)
        result = renderer.render(mock_document)
        assert b"\x1b@" not in result


class TestRenderInit:
    """Тесты инициализации принтера."""

    @pytest.fixture
    def mock_document(self) -> MagicMock:
        """Мок документа."""
        doc = MagicMock()
        doc.printer_settings = None
        return doc

    def test_esc_reset_sent(self, mock_document: MagicMock) -> None:
        """Отправка ESC @."""
        renderer = DocumentRenderer()
        result = renderer._render_init(mock_document)
        assert b"\x1b@" in result

    def test_character_table_set(self, mock_document: MagicMock) -> None:
        """Установка кодовой страницы."""
        renderer = DocumentRenderer(codepage=CodePage.PC866)
        result = renderer._render_init(mock_document)
        # ESC t - установка таблицы PC866
        assert b"\x1bt" in result

    def test_pc850_codepage(self, mock_document: MagicMock) -> None:
        """Установка PC850."""
        renderer = DocumentRenderer(codepage=CodePage.PC850)
        result = renderer._render_init(mock_document)
        assert b"\x1bt" in result


class TestRenderSection:
    """Тесты рендеринга секций."""

    def test_render_empty_section(self) -> None:
        """Рендеринг пустой секции."""
        renderer = DocumentRenderer()
        section = MagicMock()
        section.break_type = None
        section.paragraphs = []

        result = renderer._render_section(section)
        assert isinstance(result, bytes)

    def test_render_section_with_page_break(self) -> None:
        """Рендеринг секции с разрывом страницы."""
        opts = RenderOptions(page_breaks=True)
        renderer = DocumentRenderer(options=opts)
        section = MagicMock()
        section.break_type = "page"
        section.paragraphs = []

        result = renderer._render_section(section)
        assert b"\x0c" in result  # FF

    def test_render_section_without_page_break(self) -> None:
        """Рендеринг секции без разрыва."""
        opts = RenderOptions(page_breaks=False)
        renderer = DocumentRenderer(options=opts)
        section = MagicMock()
        section.break_type = "page"
        section.paragraphs = []

        result = renderer._render_section(section)
        assert b"\x0c" not in result


class TestRenderFinalize:
    """Тесты завершения рендеринга."""

    def test_form_feed_at_end(self) -> None:
        """FF в конце документа."""
        opts = RenderOptions(form_feed_at_end=True)
        renderer = DocumentRenderer(options=opts)
        result = renderer._render_finalize()
        assert result == b"\x0c"

    def test_no_form_feed(self) -> None:
        """Без FF."""
        opts = RenderOptions(form_feed_at_end=False)
        renderer = DocumentRenderer(options=opts)
        result = renderer._render_finalize()
        assert result == b""


class TestRenderToFile:
    """Тесты сохранения в файл."""

    def test_render_to_file(self, tmp_path: Path) -> None:
        """Сохранение в файл."""
        doc = MagicMock()
        doc.sections = []
        doc.printer_settings = None

        renderer = DocumentRenderer()
        path = tmp_path / "output.escp"
        renderer.render_to_file(doc, path)

        assert path.exists()
        assert path.read_bytes()  # Не пустой

    def test_render_to_file_creates_bytes(self, tmp_path: Path) -> None:
        """Файл содержит ESC/P данные."""
        doc = MagicMock()
        doc.sections = []
        doc.printer_settings = None

        renderer = DocumentRenderer()
        path = tmp_path / "output.escp"
        renderer.render_to_file(doc, path)

        content = path.read_bytes()
        assert b"\x1b@" in content  # ESC @


class TestRenderSectionWithTable:
    """Тесты рендеринга секций с таблицами."""

    def test_render_section_with_table(self) -> None:
        """Рендеринг секции с таблицей (mock)."""
        renderer = DocumentRenderer()
        section = MagicMock()
        section.break_type = None

        # Мок таблицы
        mock_table = MagicMock()
        section.paragraphs = [mock_table]

        # Просто проверяем что метод не падает
        result = renderer._render_section(section)
        assert isinstance(result, bytes)


class TestRenderWithPrinterSettings:
    """Тесты рендеринга с настройками принтера."""

    def test_render_with_printer_settings(self) -> None:
        """Рендеринг с printer_settings."""
        doc = MagicMock()
        doc.sections = []
        doc.printer_settings = MagicMock()
        doc.printer_settings.codepage = "pc866"

        renderer = DocumentRenderer()
        result = renderer._render_init(doc)
        assert isinstance(result, bytes)
