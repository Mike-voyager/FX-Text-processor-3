"""Рендерер таблиц в ESC/P байты.

Предоставляет:
- TableRenderer: Table → ESC/P bytes

Example:
    >>> from src.documents.printing import TableRenderer
    >>> from src.model.table import Table, Cell
    >>> renderer = TableRenderer(CodePage.PC866)
    >>> table = Table(rows=2, cols=3)
    >>> table.set_cell(0, 0, Cell(text="A1"))
    >>> escp_data = renderer.render(table)
"""

from __future__ import annotations

import logging
from typing import Final

from src.documents.printing.run_renderer import RunRenderer
from src.model.enums import Alignment, CodePage
from src.model.table import Table, TableBorder

# Line feed constant
LF = b"\n"

logger: Final = logging.getLogger(__name__)

# Символы для отрисовки границ таблиц
_BORDER_CHARS: Final[dict[str, bytes]] = {
    "single_horizontal": b"\xc4",  # ─
    "single_vertical": b"\xb3",  # │
    "single_top_left": b"\xda",  # ┌
    "single_top_right": b"\xbf",  # ┐
    "single_bottom_left": b"\xc0",  # └
    "single_bottom_right": b"\xd9",  # ┘
    "single_t_down": b"\xc2",  # ┬
    "single_t_up": b"\xc1",  # ┴
    "single_t_right": b"\xc3",  # ├
    "single_t_left": b"\xb4",  # ┤
    "single_cross": b"\xc5",  # ┼
    "double_horizontal": b"\xcd",  # ═
    "double_vertical": b"\xba",  # ║
    "space": b" ",
}


class TableRenderer:
    """Рендерер таблиц.

    Преобразует Table с ячейками в ESC/P команды.
    Поддерживает различные стили границ и выравнивание.

    Example:
        >>> renderer = TableRenderer(CodePage.PC866)
        >>> table = Table(rows=3, cols=3)
        >>> table.set_cell(0, 0, Cell(text="Header"))
        >>> escp = renderer.render(table)
    """

    def __init__(self, codepage: CodePage = CodePage.PC866) -> None:
        """Инициализирует рендерер.

        Args:
            codepage: Кодовая страница для кодирования текста
        """
        self._codepage = codepage
        self._run_renderer = RunRenderer(codepage)
        self._logger = logging.getLogger(__name__)

    def render(self, table: Table) -> bytes:
        """Рендерит таблицу в ESC/P байты.

        Args:
            table: Таблица для рендеринга

        Returns:
            ESC/P команды для таблицы

        Example:
            >>> table = Table(rows=2, cols=2)
            >>> table.set_cell(0, 0, Cell(text="A"))
            >>> table.set_cell(0, 1, Cell(text="B"))
            >>> data = renderer.render(table)
            >>> len(data) > 0
            True
        """
        if table.border == TableBorder.NONE:
            return self._render_simple(table)
        else:
            return self._render_with_borders(table)

    def _render_simple(self, table: Table) -> bytes:
        """Рендерит таблицу без границ.

        Args:
            table: Таблица для рендеринга

        Returns:
            ESC/P байты
        """
        result = bytearray()

        num_rows = len(table.rows)
        num_cols = len(table.rows[0]) if table.rows else 0
        for row_idx in range(num_rows):
            for col_idx in range(num_cols):
                cell = table.get_cell(row_idx, col_idx)
                if cell:
                    # Ячейка с содержимым
                    encoded = cell.text.encode("cp866", errors="replace")
                    result.extend(encoded)

                # Разделитель колонок (табуляция)
                if col_idx < num_cols - 1:
                    result.extend(b"\t")

            # Перевод строки в конце ряда
            result.extend(LF)

        return bytes(result)

    def _render_with_borders(self, table: Table) -> bytes:
        """Рендерит таблицу с границами.

        Args:
            table: Таблица для рендеринга

        Returns:
            ESC/P байты
        """
        result = bytearray()

        # Вычисляем ширину колонок
        col_widths = self._calculate_column_widths(table)

        # Верхняя граница
        result.extend(self._render_border_top(table, col_widths))
        result.extend(LF)

        num_rows = len(table.rows)
        # Ряды с данными
        for row_idx in range(num_rows):
            # Линия с ячейками
            result.extend(self._render_row_content(table, row_idx, col_widths))
            result.extend(LF)

            # Граница между рядами (или нижняя)
            if row_idx < num_rows - 1:
                result.extend(self._render_border_middle(table, col_widths))
            else:
                result.extend(self._render_border_bottom(table, col_widths))
            result.extend(LF)

        return bytes(result)

    def _calculate_column_widths(self, table: Table) -> list[int]:
        """Вычисляет ширину каждой колонки.

        Args:
            table: Таблица

        Returns:
            Список ширин колонок
        """
        num_rows = len(table.rows)
        num_cols = len(table.rows[0]) if table.rows else 0
        widths = [0] * num_cols

        for row_idx in range(num_rows):
            for col_idx in range(num_cols):
                cell = table.get_cell(row_idx, col_idx)
                if cell:
                    text_width = len(cell.text)
                    widths[col_idx] = max(widths[col_idx], text_width)

        # Минимальная ширина + отступы
        min_width = 3
        return [max(w + 2, min_width) for w in widths]

    def _render_border_top(self, table: Table, col_widths: list[int]) -> bytes:
        """Рендерит верхнюю границу таблицы.

        Args:
            table: Таблица
            col_widths: Ширины колонок

        Returns:
            ESC/P байты
        """
        result = bytearray()
        result.extend(_BORDER_CHARS["single_top_left"])

        for i, width in enumerate(col_widths):
            result.extend(_BORDER_CHARS["single_horizontal"] * width)
            if i < len(col_widths) - 1:
                result.extend(_BORDER_CHARS["single_t_down"])

        result.extend(_BORDER_CHARS["single_top_right"])
        return bytes(result)

    def _render_border_middle(self, table: Table, col_widths: list[int]) -> bytes:
        """Рендерит среднюю границу таблицы.

        Args:
            table: Таблица
            col_widths: Ширины колонок

        Returns:
            ESC/P байты
        """
        result = bytearray()
        result.extend(_BORDER_CHARS["single_t_right"])

        for i, width in enumerate(col_widths):
            result.extend(_BORDER_CHARS["single_horizontal"] * width)
            if i < len(col_widths) - 1:
                result.extend(_BORDER_CHARS["single_cross"])

        result.extend(_BORDER_CHARS["single_t_left"])
        return bytes(result)

    def _render_border_bottom(self, table: Table, col_widths: list[int]) -> bytes:
        """Рендерит нижнюю границу таблицы.

        Args:
            table: Таблица
            col_widths: Ширины колонок

        Returns:
            ESC/P байты
        """
        result = bytearray()
        result.extend(_BORDER_CHARS["single_bottom_left"])

        for i, width in enumerate(col_widths):
            result.extend(_BORDER_CHARS["single_horizontal"] * width)
            if i < len(col_widths) - 1:
                result.extend(_BORDER_CHARS["single_t_up"])

        result.extend(_BORDER_CHARS["single_bottom_right"])
        return bytes(result)

    def _render_row_content(self, table: Table, row_idx: int, col_widths: list[int]) -> bytes:
        """Рендерит содержимое ряда.

        Args:
            table: Таблица
            row_idx: Индекс ряда
            col_widths: Ширины колонок

        Returns:
            ESC/P байты
        """
        result = bytearray()
        result.extend(_BORDER_CHARS["single_vertical"])

        num_cols = len(table.rows[0]) if table.rows else 0
        for col_idx in range(num_cols):
            cell = table.get_cell(row_idx, col_idx)
            text = cell.text if cell else ""

            # Выравнивание текста в ячейке
            width = col_widths[col_idx]
            padded = self._pad_text(text, width, Alignment.LEFT)

            encoded = padded.encode("cp866", errors="replace")
            result.extend(encoded)
            result.extend(_BORDER_CHARS["single_vertical"])

        return bytes(result)

    def _pad_text(self, text: str, width: int, alignment: Alignment) -> str:
        """Дополняет текст до нужной ширины.

        Args:
            text: Исходный текст
            width: Целевая ширина
            alignment: Выравнивание

        Returns:
            Дополненный текст
        """
        if len(text) >= width:
            return text[:width]

        if alignment == Alignment.CENTER:
            left_pad = (width - len(text)) // 2
            right_pad = width - len(text) - left_pad
            return " " * left_pad + text + " " * right_pad
        elif alignment == Alignment.RIGHT:
            return " " * (width - len(text)) + text
        else:  # LEFT
            return text + " " * (width - len(text))


__all__ = ["TableRenderer"]
