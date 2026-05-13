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
from typing import TYPE_CHECKING, Final

from src.documents.printing.run_renderer import RunRenderer
from src.escp.commands.page_control import set_horizontal_tabs
from src.escp.commands.positioning import set_horizontal_position
from src.escp.commands.print_quality import ESC_LQ_MODE
from src.model.enums import (
    Alignment,
    CharactersPerInch,
    CharSize,
    CodePage,
    FontFamily,
    PrintQuality,
)
from src.model.paragraph import Paragraph

if TYPE_CHECKING:
    from src.model.document import PageSettings

# Line feed constant
LF = b"\n"

# ESC/P constants for positioning
UNITS_PER_INCH: Final[int] = 60  # ESC/P uses 1/60 inch units

logger: Final = logging.getLogger(__name__)


class ParagraphRenderer:
    """Рендерер параграфов.

    Преобразует Paragraph с Run'ами в ESC/P команды.
    Управляет выравниванием, отступами и форматированием.

    Attributes:
        _codepage: Кодовая страница для кодирования текста
        _page_settings: Настройки страницы (поля, размер)
        _cpi: Символов на дюйм (10 или 12 CPI)

    Example:
        >>> renderer = ParagraphRenderer(CodePage.PC866)
        >>> escp = renderer.render(paragraph)
    """

    def __init__(
        self,
        codepage: CodePage = CodePage.PC866,
        page_settings: "PageSettings | None" = None,
        cpi: CharactersPerInch = CharactersPerInch.CPI_10,
    ) -> None:
        """Инициализирует рендерер.

        Args:
            codepage: Кодовая страница для кодирования текста
            page_settings: Настройки страницы (поля, размер)
            cpi: Символов на дюйм (влияет на ширину символа)
        """
        self._codepage = codepage
        self._page_settings = page_settings
        self._cpi = cpi
        self._run_renderer = RunRenderer(codepage)
        self._logger = logging.getLogger(__name__)

    def render(self, paragraph: Paragraph) -> bytes:
        """Рендерит параграф в ESC/P байты с учётом LineStyle.

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

        # === LineStyle команды (порядок важен) ===

        # 1. ESC 3 n - установка межстрочного интервала
        # Используем getattr для совместимости с section.PageSettings (у него нет line_spacing)
        page_line_spacing = (
            getattr(self._page_settings, "line_spacing", 36) if self._page_settings else 36
        )
        line_spacing = paragraph.line_spacing or page_line_spacing
        result.extend(bytes([0x1B, 0x33, line_spacing]))

        # 2. ESC x n - качество (Draft/NLQ)
        result.extend(self._set_quality(paragraph.quality))

        # 3. ESC k n - шрифт (Roman/Sans Serif) только для NLQ
        if paragraph.quality == PrintQuality.NLQ:
            result.extend(self._set_font(paragraph.font_family))

        # 4. Размер символа (Double-width/height, Condensed)
        result.extend(self._set_char_size(paragraph.char_size))

        # 5. Установка выравнивания (с учётом ширины текста)
        text_width_chars = self._get_text_width(paragraph)
        result.extend(self._render_alignment(paragraph.alignment, text_width_chars))

        # Установка табуляторов если есть
        if paragraph.tabstops:
            # Convert float positions to int (columns)
            tab_positions = [int(pos) for pos in paragraph.tabstops]
            result.extend(set_horizontal_tabs(tab_positions))

        # Рендеринг всех Run'ов в параграфе
        for run in paragraph.runs:
            result.extend(self._run_renderer.render(run))

        # Сброс размеров символов в конце параграфа
        if paragraph.char_size != CharSize.NORMAL:
            result.extend(self._reset_char_size())

        # Перевод строки в конце параграфа
        result.extend(LF)

        return bytes(result)

    def _get_printable_width_chars(self) -> int:
        """Вычисляет ширину печатной области в символах.

        Returns:
            Количество символов в печатной области.

        Note:
            При отсутствии page_settings использует defaults:
            - Letter (8.5") с полями 1" с каждой стороны
            - При 10 CPI: (8.5 - 2) * 10 = 65 символов
        """
        if self._page_settings is None:
            # Defaults: Letter 8.5" x 11", margins 1" each side
            printable_width_inches = 8.5 - 2.0  # 6.5 inches
        else:
            printable_width_inches = self._page_settings.get_printable_width_inches()

        cpi_value = self._cpi.numeric_value
        if cpi_value is None:
            cpi_value = 10  # Default to 10 CPI for proportional

        return int(printable_width_inches * cpi_value)

    def _get_units_per_char(self) -> int:
        """Возвращает количество ESC/P units на символ.

        ESC/P использует 1/60 дюйма для абсолютного позиционирования.
        При 10 CPI: 1 символ = 60/10 = 6 units
        При 12 CPI: 1 символ = 60/12 = 5 units

        Returns:
            Количество units (6 для 10 CPI, 5 для 12 CPI)
        """
        cpi_value = self._cpi.numeric_value
        if cpi_value is None:
            return 6  # Default for proportional

        return UNITS_PER_INCH // cpi_value

    def _get_text_width(self, paragraph: Paragraph) -> int:
        """Вычисляет ширину текста параграфа в символах.

        Args:
            paragraph: Параграф для измерения

        Returns:
            Ширина текста в символах
        """
        return len(paragraph.get_text())

    def _render_alignment(self, alignment: Alignment, text_width_chars: int) -> bytes:
        """Рендерит выравнивание параграфа.

        Epson FX-890 не имеет встроенного выравнивания.
        Выравнивание достигается через абсолютное позиционирование ESC $.

        Args:
            alignment: Тип выравнивания
            text_width_chars: Ширина текста в символах

        Returns:
            ESC/P команды для выравнивания (может быть пустым для LEFT)

        Note:
            - LEFT: без команд (по умолчанию)
            - CENTER: позиционирование на (printable_width - text_width) / 2
            - RIGHT: позиционирование на (printable_width - text_width)
            - JUSTIFY: не поддерживается на матричном принтере
        """
        # LEFT — по умолчанию, никаких команд
        if alignment == Alignment.LEFT:
            return b""

        # JUSTIFY не поддерживается на FX-890
        if alignment == Alignment.JUSTIFY:
            self._logger.debug("JUSTIFY alignment not supported on FX-890, using LEFT")
            return b""

        # Для CENTER/RIGHT нужно позиционирование
        printable_width_chars = self._get_printable_width_chars()

        # Защита от текста длиннее строки
        if text_width_chars >= printable_width_chars:
            self._logger.debug(
                f"Text width {text_width_chars} >= printable width {printable_width_chars}, "
                "skipping alignment"
            )
            return b""

        # Вычисляем позицию в символах
        if alignment == Alignment.CENTER:
            start_pos_chars = (printable_width_chars - text_width_chars) // 2
        else:  # Alignment.RIGHT
            start_pos_chars = printable_width_chars - text_width_chars

        # Конвертируем в ESC/P units (1/60 дюйма)
        units_per_char = self._get_units_per_char()
        position_units = start_pos_chars * units_per_char

        self._logger.debug(
            f"{alignment.value} alignment: text_width={text_width_chars}, "
            f"printable_width={printable_width_chars}, "
            f"start_pos_chars={start_pos_chars}, units={position_units}"
        )

        return set_horizontal_position(position_units)

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

    def _set_quality(self, quality: PrintQuality) -> bytes:
        """Устанавливает качество печати (ESC x n).

        Args:
            quality: Качество печати

        Returns:
            ESC/P команды для установки качества
        """
        if quality == PrintQuality.NLQ:
            return ESC_LQ_MODE  # ESC x 1
        elif quality == PrintQuality.USD:
            # Draft + Ultra High Speed (ESC x 0 + ESC y 2)
            return b"\x1bx\x00\x1by\x02"
        elif quality == PrintQuality.HSD:
            # Draft + High Speed (ESC x 0 + ESC y 1)
            return b"\x1bx\x00\x1by\x01"
        else:
            # Normal Draft (ESC x 0 + ESC y 0)
            return b"\x1bx\x00\x1by\x00"

    def _set_font(self, font: FontFamily) -> bytes:
        """Устанавливает шрифт (ESC k n) - только для NLQ.

        Args:
            font: Семейство шрифтов

        Returns:
            ESC/P команды для установки шрифта
        """
        if font == FontFamily.ROMAN:
            return b"\x1bk\x00"  # ESC k 0 - Roman
        elif font == FontFamily.SANS_SERIF:
            return b"\x1bk\x01"  # ESC k 1 - Sans Serif
        else:
            # Draft fonts don't use ESC k
            return b""

    def _set_char_size(self, size: CharSize) -> bytes:
        """Устанавливает размер символа.

        Args:
            size: Размер символа

        Returns:
            ESC/P команды для установки размера
        """
        result = bytearray()

        if size == CharSize.NORMAL:
            # Сброс всех размеров
            result.extend(b"\x1bW\x00")  # Double width off
            result.extend(b"\x1bw\x00")  # Double height off
            result.extend(b"\x18")  # Cancel condensed (DC2)
        elif size == CharSize.DOUBLE_WIDTH:
            result.extend(b"\x1bW\x01")  # ESC W 1 - Double width on
            result.extend(b"\x1bw\x00")  # Double height off
        elif size == CharSize.DOUBLE_HEIGHT:
            result.extend(b"\x1bW\x00")  # Double width off
            result.extend(b"\x1bw\x01")  # ESC w 1 - Double height on
        elif size == CharSize.DOUBLE_WIDTH_HEIGHT:
            result.extend(b"\x1bW\x01")  # Double width on
            result.extend(b"\x1bw\x01")  # Double height on
        elif size == CharSize.CONDENSED:
            result.extend(b"\x0f")  # SI - Condensed on
            result.extend(b"\x1bW\x00")  # Double width off
            result.extend(b"\x1bw\x00")  # Double height off

        return bytes(result)

    def _reset_char_size(self) -> bytes:
        """Сбрасывает размер символа в нормальный.

        Returns:
            ESC/P команды для сброса размера
        """
        result = bytearray()
        result.extend(b"\x1bW\x00")  # Double width off
        result.extend(b"\x1bw\x00")  # Double height off
        result.extend(b"\x12")  # DC2 - Cancel condensed
        return bytes(result)


__all__ = ["ParagraphRenderer"]
