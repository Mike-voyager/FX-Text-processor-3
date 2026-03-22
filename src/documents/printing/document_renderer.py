"""Главный рендерер документов в ESC/P байты.

Предоставляет:
- DocumentRenderer: Обход дерева Document → ESC/P bytes

Example:
    >>> from src.documents.printing import DocumentRenderer
    >>> from src.model.document import Document
    >>> doc = Document(title="Test")
    >>> renderer = DocumentRenderer()
    >>> escp_data = renderer.render(doc)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from src.documents.printing.paragraph_renderer import ParagraphRenderer
from src.documents.printing.table_renderer import TableRenderer
from src.escp.commands.charset import CharacterTable, set_character_table
from src.escp.commands.hardware import ESC_INIT_PRINTER
from src.model.document import Document
from src.model.enums import CodePage
from src.model.paragraph import Paragraph
from src.model.section import Section
from src.model.table import Table

# Mapping from model CodePage to ESC/P CharacterTable
_CODEPAGE_MAPPING: dict[CodePage, CharacterTable] = {
    CodePage.PC437: CharacterTable.PC437,
    CodePage.PC850: CharacterTable.PC850,
    CodePage.PC860: CharacterTable.PC860,
    CodePage.PC863: CharacterTable.PC863,
    CodePage.PC865: CharacterTable.PC865,
    CodePage.PC866: CharacterTable.PC866,
    CodePage.PC852: CharacterTable.PC852,
    CodePage.PC858: CharacterTable.PC858,
}


def _get_character_table(codepage: CodePage) -> CharacterTable:
    """Convert model CodePage to ESC/P CharacterTable."""
    return _CODEPAGE_MAPPING.get(codepage, CharacterTable.PC866)


# ESC/P constants
ESC_RESET = ESC_INIT_PRINTER  # ESC @ - сброс принтера
FF = b"\x0c"  # Form feed - разрыв страницы

logger: Final = logging.getLogger(__name__)


@dataclass(frozen=True)
class RenderOptions:
    """Опции рендеринга документа.

    Attributes:
        reset_printer: Отправлять ESC @ в начале
        form_feed_at_end: Отправлять FF в конце
        page_breaks: Обрабатывать разрывы секций
    """

    reset_printer: bool = True
    form_feed_at_end: bool = True
    page_breaks: bool = True


class DocumentRenderer:
    """Главный renderer. Обходит дерево Document → ESC/P bytes.

    Document
      └── Section[]
            └── Paragraph[] | Table[]
                  └── Run[] | EmbeddedObject[]

    Example:
        >>> renderer = DocumentRenderer(codepage=CodePage.PC866)
        >>> escp_data = renderer.render(document)
        >>> renderer.render_to_file(document, Path("output.escp"))
    """

    def __init__(
        self,
        codepage: CodePage = CodePage.PC866,
        options: RenderOptions | None = None,
    ) -> None:
        """Инициализирует рендерер.

        Args:
            codepage: Кодовая страница для кодирования текста
            options: Опции рендеринга (reset, form feed, page breaks)
        """
        self._codepage = codepage
        self._options = options or RenderOptions()
        self._paragraph_renderer = ParagraphRenderer(codepage)
        self._table_renderer = TableRenderer(codepage)
        self._logger = logging.getLogger(__name__)

    def render(self, document: Document) -> bytes:
        """Рендерит весь документ в бинарные ESC/P данные.

        Args:
            document: Документ для рендеринга

        Returns:
            ESC/P байты готовые к отправке на принтер

        Example:
            >>> data = renderer.render(doc)
            >>> len(data) > 0
            True
        """
        result = bytearray()

        # Инициализация принтера
        result.extend(self._render_init(document))

        # Рендеринг всех секций
        for section in document.sections:
            result.extend(self._render_section(section))

        # Завершение
        result.extend(self._render_finalize())

        self._logger.debug(f"Rendered document: {len(result)} bytes")
        return bytes(result)

    def _render_init(self, document: Document) -> bytes:
        """Рендерит инициализацию принтера.

        Args:
            document: Документ с настройками

        Returns:
            ESC/P команды инициализации
        """
        result = bytearray()

        # Сброс принтера
        if self._options.reset_printer:
            result.extend(ESC_RESET)

        # Установка кодовой страницы
        result.extend(set_character_table(_get_character_table(self._codepage)))

        # Применение настроек принтера из документа
        if document.printer_settings:
            settings = document.printer_settings
            # TODO: Применить настройки шрифта, качества, CPI
            self._logger.debug(f"Applied printer settings: {settings.codepage}")

        return bytes(result)

    def _render_section(self, section: Section) -> bytes:
        """Рендерит одну секцию документа.

        Args:
            section: Секция для рендеринга

        Returns:
            ESC/P байты секции
        """
        result = bytearray()

        # Разрыв секции (form feed между секциями)
        if self._options.page_breaks and section.break_type:
            result.extend(FF)

        # Рендеринг элементов секции
        for item in section.paragraphs:
            if isinstance(item, Paragraph):
                result.extend(self._paragraph_renderer.render(item))
            elif isinstance(item, Table):
                result.extend(self._table_renderer.render(item))
            else:
                self._logger.warning(f"Unknown section item type: {type(item)}")

        return bytes(result)

    def _render_finalize(self) -> bytes:
        """Рендерит завершение документа.

        Returns:
            ESC/P команды завершения
        """
        result = bytearray()

        if self._options.form_feed_at_end:
            result.extend(FF)

        return bytes(result)

    def render_to_file(self, document: Document, path: Path) -> None:
        """Рендерит документ и сохраняет в файл.

        Args:
            document: Документ для рендеринга
            path: Путь к выходному файлу

        Raises:
            IOError: При ошибке записи файла

        Example:
            >>> renderer.render_to_file(doc, Path("output.escp"))
        """
        data = self.render(document)
        path.write_bytes(data)
        self._logger.info(f"Rendered document saved to: {path}")


__all__ = ["DocumentRenderer", "RenderOptions"]
