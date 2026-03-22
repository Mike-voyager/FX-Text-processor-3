"""Рендерер параграфов в ESC/P байты.

Предоставляет:
- ParagraphRenderer: Paragraph → ESC/P bytes

Example:
    >>> from src.documents.printing import ParagraphRenderer
    >>> from src.model.paragraph import Paragraph
    >>> renderer = ParagraphRenderer(CodePage.PC866)
    >>> para = Paragraph(text="Hello")
    >>> escp_data = renderer.render(para)
"""

from __future__ import annotations

import logging
from typing import Final

from src.documents.printing.run_renderer import RunRenderer
from src.escp.commands.page_control import set_horizontal_tabs
from src.model.enums import Alignment, CodePage
from src.model.paragraph import Paragraph

# Line feed constant
LF = b"\n"

logger: Final = logging.getLogger(__name__)


class ParagraphRenderer:
    """Рендерер параграфов.

    Преобразует Paragraph с Run'ами в ESC/P команды.
    Управляет выравниванием, отступами и форматированием.

    Example:
        >>> renderer = ParagraphRenderer(CodePage.PC866)
        >>> escp = renderer.render(paragraph)
    """

    def __init__(self, codepage: CodePage = CodePage.PC866) -> None:
        """Инициализирует рендерер.

        Args:
            codepage: Кодовая страница для кодирования текста
        """
        self._codepage = codepage
        self._run_renderer = RunRenderer(codepage)
        self._logger = logging.getLogger(__name__)

    def render(self, paragraph: Paragraph) -> bytes:
        """Рендерит параграф в ESC/P байты.

        Args:
            paragraph: Параграф для рендеринга

        Returns:
            ESC/P команды для параграфа

        Example:
            >>> para = Paragraph(text="Hello", alignment=Alignment.CENTER)
            >>> data = renderer.render(para)
            >>> len(data) > 0
            True
        """
        result = bytearray()

        # Установка выравнивания
        result.extend(self._render_alignment(paragraph.alignment))

        # Установка табуляторов если есть
        if paragraph.tabstops:
            # Convert float positions to int (columns)
            tab_positions = [int(pos) for pos in paragraph.tabstops]
            result.extend(set_horizontal_tabs(tab_positions))

        # Рендеринг всех Run'ов в параграфе
        for run in paragraph.runs:
            result.extend(self._run_renderer.render(run))

        # Перевод строки в конце параграфа
        result.extend(LF)

        return bytes(result)

    def _render_alignment(self, alignment: Alignment) -> bytes:
        """Рендерит выравнивание параграфа.

        Epson FX-890 не имеет встроенного выравнивания.
        Выравнивание достигается через пробелы и позиционирование.

        Args:
            alignment: Тип выравнивания

        Returns:
            ESC/P команды для выравнивания (может быть пустым)
        """
        # На FX-890 выравнивание реализуется через абсолютное позиционирование
        # или пробелы перед текстом. Для простоты — пока заглушка.
        # В полной реализации здесь нужно вычислять позицию по ширине страницы.

        result = bytearray()

        if alignment == Alignment.CENTER:
            # TODO: Вычислить центральную позицию и установить
            # result.extend(absolute_position(...))
            pass
        elif alignment == Alignment.RIGHT:
            # TODO: Вычислить правую позицию
            pass
        elif alignment == Alignment.JUSTIFY:
            # На матричном принтере сложно реализовать
            pass
        # Alignment.LEFT — по умолчанию, ничего не делаем

        return bytes(result)

    def _render_indent(self, indent_chars: int) -> bytes:
        """Рендерит отступ параграфа.

        Args:
            indent_chars: Количество символов отступа

        Returns:
            ESC/P команды для отступа
        """
        if indent_chars <= 0:
            return b""

        # Отступ через пробелы
        return b" " * indent_chars


__all__ = ["ParagraphRenderer"]
