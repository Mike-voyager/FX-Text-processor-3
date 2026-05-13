"""Рендерер текстовых документов в ESC/P байты.

Предоставляет:
- TextRenderer: Рендеринг Paragraph и Run в ESC/P bytes
- CharacterStyle: Стили форматирования символов

Example:
    >>> from src.documents.printing.text_renderer import TextRenderer
    >>> from src.model.paragraph import Paragraph
    >>> from src.model.run import Run
    >>> renderer = TextRenderer()
    >>> para = Paragraph(runs=[Run(text="Hello")])
    >>> escp_data = renderer.render_paragraph(para, RenderSettings())
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from src.documents.printing.document_renderer import RenderSettings
from src.escp.commands.positioning import set_horizontal_position
from src.escp.commands.sizing import (
    ESC_CONDENSED_OFF,
    ESC_CONDENSED_ON,
    ESC_DOUBLE_HEIGHT_OFF,
    ESC_DOUBLE_HEIGHT_ON,
    ESC_DOUBLE_WIDTH_OFF,
    ESC_DOUBLE_WIDTH_ON,
)
from src.escp.commands.text_formatting import (
    ESC_BOLD_OFF,
    ESC_BOLD_ON,
    ESC_ITALIC_OFF,
    ESC_ITALIC_ON,
    ESC_UNDERLINE_OFF,
    ESC_UNDERLINE_ON,
)
from src.model.enums import (
    Alignment,
    CodePage,
    TextStyle,
)

if TYPE_CHECKING:
    from src.model.paragraph import Paragraph
    from src.model.run import Run

logger: Final = logging.getLogger(__name__)

# ESC/P constants
CRLF = b"\r\n"
LF = b"\n"


@dataclass(frozen=True)
class CharacterStyle:
    """Стили форматирования символов ESC/P.

    Attributes:
        bold: Жирный шрифт (ESC E/F)
        italic: Курсив (ESC 4/5)
        underline: Подчёркивание (ESC -)
        double_width: Двойная ширина (ESC W)
        double_height: Двойная высота (ESC w)
        condensed: Сжатый режим (SI/DC2)
    """

    bold: bool = False
    italic: bool = False
    underline: bool = False
    double_width: bool = False
    double_height: bool = False
    condensed: bool = False


class TextRenderer:
    """Рендерер текстовых документов.

    Преобразует Paragraph с Run'ами в ESC/P команды.
    Управляет выравниванием, отступами и форматированием текста.

    Example:
        >>> renderer = TextRenderer()
        >>> settings = RenderSettings(cpi=CharactersPerInch.CPI_10)
        >>> escp = renderer.render_paragraph(paragraph, settings)
    """

    def __init__(self, codepage: CodePage = CodePage.PC866) -> None:
        """Инициализирует рендерер.

        Args:
            codepage: Кодовая страница для кодирования текста
        """
        self._codepage = codepage
        self._logger = logging.getLogger(__name__)

    def render_paragraph(self, paragraph: Paragraph, settings: RenderSettings) -> bytes:
        """Рендерит параграф в ESC/P байты.

        Args:
            paragraph: Параграф для рендеринга
            settings: Настройки рендеринга

        Returns:
            ESC/P команды для параграфа

        Example:
            >>> para = Paragraph(runs=[Run(text="Hello")])
            >>> data = renderer.render_paragraph(para, settings)
        """
        result = bytearray()

        # Выравнивание параграфа
        text_width = self._calculate_text_width(paragraph)
        alignment_cmd = self._render_alignment(paragraph.alignment, text_width, settings)
        result.extend(alignment_cmd)

        # Рендеринг всех Run'ов
        for run in paragraph.runs:
            result.extend(self.render_text_run(run, settings))

        # Перевод строки в конце параграфа
        result.extend(CRLF)

        return bytes(result)

    def render_text_run(self, run: Run, settings: RenderSettings) -> bytes:
        """Рендерит текстовый Run с форматированием.

        Args:
            run: Текстовый фрагмент с форматированием
            settings: Настройки рендеринга

        Returns:
            ESC/P команды для Run'а

        Example:
            >>> run = Run(text="Bold", style=TextStyle.BOLD)
            >>> data = renderer.render_text_run(run, settings)
        """
        result = bytearray()

        # Преобразуем TextStyle в CharacterStyle
        char_style = self._text_style_to_character_style(run.style)

        # Применяем стили
        self.apply_character_style(result, char_style)

        # Кодируем текст
        if hasattr(run, "text"):
            try:
                encoded = run.text.encode("cp866", errors="replace")
                result.extend(encoded)
            except TypeError:
                result.extend(run.text.encode("ascii", errors="replace"))

        # Снимаем стили (в обратном порядке)
        self._remove_character_style(result, char_style)

        return bytes(result)

    def apply_character_style(self, cmd: bytearray, style: CharacterStyle) -> None:
        """Применяет ESC/P стили символов.

        Команды ESC/P:
        - ESC E (0x1B 0x45) - bold on
        - ESC F (0x1B 0x46) - bold off
        - ESC 4 (0x1B 0x34) - italic on
        - ESC 5 (0x1B 0x35) - italic off
        - ESC - 1 (0x1B 0x2D 0x01) - underline on
        - ESC - 0 (0x1B 0x2D 0x00) - underline off
        - ESC W 1 (0x1B 0x57 0x01) - double width on
        - ESC W 0 (0x1B 0x57 0x00) - double width off
        - ESC w 1 (0x1B 0x77 0x01) - double height on
        - ESC w 0 (0x1B 0x77 0x00) - double height off
        - SI (0x0F) - condensed on
        - DC2 (0x12) - condensed off

        Args:
            cmd: Буфер для добавления команд
            style: Стили для применения

        Example:
            >>> cmd = bytearray()
            >>> style = CharacterStyle(bold=True, italic=True)
            >>> renderer.apply_character_style(cmd, style)
            >>> # cmd содержит ESC E + ESC 4
        """
        if style.bold:
            cmd.extend(ESC_BOLD_ON)
        if style.italic:
            cmd.extend(ESC_ITALIC_ON)
        if style.underline:
            cmd.extend(ESC_UNDERLINE_ON)
        if style.double_width:
            cmd.extend(ESC_DOUBLE_WIDTH_ON)
        if style.double_height:
            cmd.extend(ESC_DOUBLE_HEIGHT_ON)
        if style.condensed:
            cmd.extend(ESC_CONDENSED_ON)

    def _remove_character_style(self, cmd: bytearray, style: CharacterStyle) -> None:
        """Снимает ESC/P стили символов.

        Args:
            cmd: Буфер для добавления команд
            style: Стили для снятия
        """
        # Снимаем в обратном порядке применения
        if style.condensed:
            cmd.extend(ESC_CONDENSED_OFF)
        if style.double_height:
            cmd.extend(ESC_DOUBLE_HEIGHT_OFF)
        if style.double_width:
            cmd.extend(ESC_DOUBLE_WIDTH_OFF)
        if style.underline:
            cmd.extend(ESC_UNDERLINE_OFF)
        if style.italic:
            cmd.extend(ESC_ITALIC_OFF)
        if style.bold:
            cmd.extend(ESC_BOLD_OFF)

    def _text_style_to_character_style(self, text_style: TextStyle | None) -> CharacterStyle:
        """Конвертирует TextStyle модели в CharacterStyle.

        Args:
            text_style: Флаги стиля из модели

        Returns:
            CharacterStyle для ESC/P
        """
        if text_style is None:
            return CharacterStyle()

        return CharacterStyle(
            bold=TextStyle.BOLD in text_style,
            italic=TextStyle.ITALIC in text_style,
            underline=TextStyle.UNDERLINE in text_style,
            double_width=TextStyle.DOUBLE_WIDTH in text_style,
            double_height=TextStyle.DOUBLE_HEIGHT in text_style,
            condensed=TextStyle.CONDENSED in text_style,
        )

    def _calculate_text_width(self, paragraph: Paragraph) -> int:
        """Вычисляет ширину текста параграфа в символах.

        Args:
            paragraph: Параграф для измерения

        Returns:
            Ширина текста в символах
        """
        total_width = 0
        for run in paragraph.runs:
            if hasattr(run, "text"):
                total_width += len(run.text)
        return total_width

    def _get_printable_width_chars(self, settings: RenderSettings) -> int:
        """Вычисляет ширину печатной области в символах.

        Args:
            settings: Настройки рендеринга

        Returns:
            Количество символов в печатной области
        """
        # Стандартная ширина страницы 8.5"
        printable_width = 8.5 - settings.margins.left - settings.margins.right
        cpi_value = settings.cpi.numeric_value or 10
        return int(printable_width * cpi_value)

    def _render_alignment(
        self, alignment: Alignment, text_width: int, settings: RenderSettings
    ) -> bytes:
        """Рендерит выравнивание параграфа.

        FX-890 не имеет встроенного выравнивания.
        Достигается через абсолютное позиционирование ESC $.

        Args:
            alignment: Тип выравнивания
            text_width: Ширина текста в символах
            settings: Настройки рендеринга

        Returns:
            ESC/P команды для выравнивания
        """
        # LEFT - по умолчанию, без команд
        if alignment == Alignment.LEFT:
            return b""

        # JUSTIFY не поддерживается на FX-890
        if alignment == Alignment.JUSTIFY:
            self._logger.debug("JUSTIFY не поддерживается, используем LEFT")
            return b""

        printable_width_chars = self._get_printable_width_chars(settings)

        # Текст длиннее строки - пропускаем позиционирование
        if text_width >= printable_width_chars:
            return b""

        # Вычисляем позицию
        if alignment == Alignment.CENTER:
            start_pos_chars = (printable_width_chars - text_width) // 2
        else:  # RIGHT
            start_pos_chars = printable_width_chars - text_width

        # Конвертируем в ESC/P units (1/60 дюйма)
        cpi_value = settings.cpi.numeric_value or 10
        units_per_char = 60 // cpi_value
        position_units = start_pos_chars * units_per_char

        return set_horizontal_position(position_units)


__all__ = ["TextRenderer", "CharacterStyle"]
