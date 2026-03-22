"""Рендерер текстовых фрагментов (Run) в ESC/P байты.

Предоставляет:
- RunRenderer: Run → ESC/P bytes

Example:
    >>> from src.documents.printing import RunRenderer
    >>> from src.model.run import Run
    >>> renderer = RunRenderer(CodePage.PC866)
    >>> run = Run(text="Hello", bold=True)
    >>> escp_data = renderer.render(run)
"""

from __future__ import annotations

import logging
from typing import Final

from src.escp.commands.special_effects import (
    ESC_SUBSCRIPT_ON,
    ESC_SUPER_SUB_OFF,
    ESC_SUPERSCRIPT_ON,
)
from src.escp.commands.text_formatting import (
    ESC_BOLD_OFF,
    ESC_BOLD_ON,
    ESC_ITALIC_OFF,
    ESC_ITALIC_ON,
    ESC_UNDERLINE_OFF,
    ESC_UNDERLINE_ON,
)
from src.model.enums import CodePage, TextStyle
from src.model.run import Run

logger: Final = logging.getLogger(__name__)


class RunRenderer:
    """Рендерер текстовых фрагментов (Run).

    Преобразует Run с форматированием в ESC/P команды.
    Применяет стили до текста и снимает после.

    Example:
        >>> renderer = RunRenderer(CodePage.PC866)
        >>> run = Run(text="Bold text", bold=True)
        >>> escp = renderer.render(run)
    """

    def __init__(self, codepage: CodePage = CodePage.PC866) -> None:
        """Инициализирует рендерер.

        Args:
            codepage: Кодовая страница для кодирования текста
        """
        self._codepage = codepage
        self._logger = logging.getLogger(__name__)

    def render(self, run: Run) -> bytes:
        """Рендерит Run в ESC/P байты.

        Args:
            run: Текстовый фрагмент с форматированием

        Returns:
            ESC/P команды для Run'а

        Example:
            >>> run = Run(text="Hello", bold=True, italic=True)
            >>> data = renderer.render(run)
            >>> len(data) > 0
            True
        """
        result = bytearray()

        # Применяем стили (включаем)
        result.extend(self._render_styles_on(run.style))

        # Кодируем текст
        encoded = run.text.encode("cp866", errors="replace")
        result.extend(encoded)

        # Снимаем стили (выключаем)
        result.extend(self._render_styles_off(run.style))

        return bytes(result)

    def _render_styles_on(self, style: TextStyle) -> bytes:
        """Рендерит включение стилей.

        Args:
            style: Комбинация стилей (TextStyle Flags)

        Returns:
            ESC/P команды включения стилей
        """
        result = bytearray()

        if not style:
            return bytes(result)

        if TextStyle.BOLD in style:
            result.extend(ESC_BOLD_ON)
        if TextStyle.ITALIC in style:
            result.extend(ESC_ITALIC_ON)
        if TextStyle.UNDERLINE in style:
            result.extend(ESC_UNDERLINE_ON)
        if TextStyle.SUPERSCRIPT in style:
            result.extend(ESC_SUPERSCRIPT_ON)
        if TextStyle.SUBSCRIPT in style:
            result.extend(ESC_SUBSCRIPT_ON)
        # Note: OUTLINE, SHADOW, STRIKETHROUGH не поддерживаются напрямую ESC/P
        # Требуют двухпроходной печати или эмуляции

        return bytes(result)

    def _render_styles_off(self, style: TextStyle) -> bytes:
        """Рендерит выключение стилей.

        Args:
            style: Комбинация стилей (TextStyle Flags)

        Returns:
            ESC/P команды выключения стилей
        """
        result = bytearray()

        if not style:
            return bytes(result)

        # Выключаем в обратном порядке включения
        # Note: OUTLINE, SHADOW, STRIKETHROUGH не поддерживаются напрямую
        # SUPERSCRIPT и SUBSCRIPT выключаются одной командой
        if TextStyle.SUBSCRIPT in style or TextStyle.SUPERSCRIPT in style:
            result.extend(ESC_SUPER_SUB_OFF)
        if TextStyle.UNDERLINE in style:
            result.extend(ESC_UNDERLINE_OFF)
        if TextStyle.ITALIC in style:
            result.extend(ESC_ITALIC_OFF)
        if TextStyle.BOLD in style:
            result.extend(ESC_BOLD_OFF)

        return bytes(result)


__all__ = ["RunRenderer"]
