"""Тесты для модуля table_renderer.

Покрытие:
- TableRenderer инициализация
- render() рендеринг таблицы
- _render_simple() таблица без границ
- _render_with_borders() таблица с границами
- _calculate_column_widths() расчёт ширин
- _render_border_top/middle/bottom() границы
- _render_row_content() содержимое ряда
- _pad_text() выравнивание текста
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from src.documents.printing.table_renderer import _BORDER_CHARS, TableRenderer
from src.model.enums import Alignment, CodePage


class TestTableRendererInit:
    """Тесты инициализации TableRenderer."""

    def test_create_default(self) -> None:
        """Создание с настройками по умолчанию."""
        renderer = TableRenderer()
        assert renderer._codepage == CodePage.PC866

    def test_create_with_codepage(self) -> None:
        """Создание с указанной кодовой страницей."""
        renderer = TableRenderer(codepage=CodePage.PC850)
        assert renderer._codepage == CodePage.PC850


class TestRenderTable:
    """Тесты рендеринга таблицы."""

    @pytest.fixture
    def mock_table_simple(self) -> Any:
        """Мок таблицы без границ."""
        table = MagicMock()
        table.border = MagicMock()
        table.border.value = "NONE"
        table.rows = [
            [MagicMock(text="A1"), MagicMock(text="B1")],
            [MagicMock(text="A2"), MagicMock(text="B2")],
        ]

        def get_cell(row: int, col: int) -> Any:
            if 0 <= row < 2 and 0 <= col < 2:
                return table.rows[row][col]
            return None

        table.get_cell = get_cell
        return table

    @pytest.fixture
    def mock_table_bordered(self) -> Any:
        """Мок таблицы с границами."""
        table = MagicMock()
        table.border = MagicMock()
        table.border.value = "SINGLE"
        table.rows = [
            [MagicMock(text="Header1"), MagicMock(text="Header2")],
            [MagicMock(text="Cell1"), MagicMock(text="Cell2")],
        ]

        def get_cell(row: int, col: int) -> Any:
            if 0 <= row < 2 and 0 <= col < 2:
                return table.rows[row][col]
            return None

        table.get_cell = get_cell
        return table

    def test_render_simple_table(self, mock_table_simple: MagicMock) -> None:
        """Рендеринг простой таблицы."""
        renderer = TableRenderer()
        result = renderer.render(mock_table_simple)
        assert isinstance(result, bytes)
        assert b"A1" in result
        assert b"B1" in result

    def test_render_bordered_table(self, mock_table_bordered: MagicMock) -> None:
        """Рендеринг таблицы с границами."""
        renderer = TableRenderer()
        result = renderer.render(mock_table_bordered)
        assert isinstance(result, bytes)
        # Символы границ
        assert _BORDER_CHARS["single_vertical"] in result


class TestRenderSimpleMethod:
    """Прямые тесты метода _render_simple()."""

    def test_render_simple_single_row(self) -> None:
        """Рендеринг одной строки без границ."""
        renderer = TableRenderer()
        table = MagicMock()
        table.rows = [[MagicMock(text="Cell1"), MagicMock(text="Cell2")]]

        def get_cell(row: int, col: int) -> Any:
            if row == 0 and col < 2:
                return table.rows[0][col]
            return None

        table.get_cell = get_cell

        result = renderer._render_simple(table)
        assert b"Cell1" in result
        assert b"Cell2" in result
        assert b"\t" in result  # табуляция между колонками
        assert result.endswith(b"\n")  # перевод строки в конце

    def test_render_simple_empty_table(self) -> None:
        """Рендеринг пустой таблицы."""
        renderer = TableRenderer()
        table = MagicMock()
        table.rows = []

        result = renderer._render_simple(table)
        assert result == b"" or result == b"\n"

    def test_render_simple_multiple_rows(self) -> None:
        """Рендеринг нескольких строк без границ."""
        renderer = TableRenderer()
        table = MagicMock()
        table.rows = [
            [MagicMock(text="A1"), MagicMock(text="B1")],
            [MagicMock(text="A2"), MagicMock(text="B2")],
            [MagicMock(text="A3"), MagicMock(text="B3")],
        ]

        def get_cell(row: int, col: int) -> Any:
            if 0 <= row < 3 and col < 2:
                return table.rows[row][col]
            return None

        table.get_cell = get_cell

        result = renderer._render_simple(table)
        # Проверяем все ячейки
        assert b"A1" in result
        assert b"B1" in result
        assert b"A2" in result
        assert b"B2" in result
        assert b"A3" in result
        assert b"B3" in result
        # Проверяем разделители (табуляции и переводы строк)
        assert result.count(b"\n") == 3  # по одному на каждую строку

    def test_render_simple_with_none_cell(self) -> None:
        """Рендеринг с пустой ячейкой (None)."""
        renderer = TableRenderer()
        table = MagicMock()
        table.rows = [[MagicMock(text="Cell1"), None, MagicMock(text="Cell3")]]

        def get_cell(row: int, col: int) -> Any:
            if row == 0:
                return table.rows[0][col]
            return None

        table.get_cell = get_cell

        result = renderer._render_simple(table)
        assert b"Cell1" in result
        assert b"Cell3" in result
        # None не должен вызывать ошибку


class TestCalculateColumnWidths:
    """Тесты расчёта ширин колонок."""

    def test_empty_table(self) -> None:
        """Пустая таблица."""
        renderer = TableRenderer()
        table = MagicMock()
        table.rows = []
        result = renderer._calculate_column_widths(table)
        assert result == []

    def test_single_column(self) -> None:
        """Одна колонка."""
        renderer = TableRenderer()
        table = MagicMock()
        cell = MagicMock(text="Hello")
        table.rows = [[cell]]

        def get_cell(row: int, col: int) -> Any:
            return cell if col == 0 else None

        table.get_cell = get_cell

        result = renderer._calculate_column_widths(table)
        assert len(result) == 1
        assert result[0] >= 7  # len("Hello") + отступы

    def test_multiple_columns(self) -> None:
        """Несколько колонок."""
        renderer = TableRenderer()
        table = MagicMock()
        cell1 = MagicMock(text="Short")
        cell2 = MagicMock(text="VeryLongText")
        table.rows = [[cell1, cell2]]

        def get_cell(row: int, col: int) -> Any:
            return [cell1, cell2][col] if col < 2 else None

        table.get_cell = get_cell

        result = renderer._calculate_column_widths(table)
        assert len(result) == 2
        assert result[0] >= 7  # len("Short") + 2
        assert result[1] >= 14  # len("VeryLongText") + 2


class TestRenderBorderTop:
    """Тесты верхней границы."""

    def test_top_border(self) -> None:
        """Верхняя граница."""
        renderer = TableRenderer()
        table = MagicMock()
        col_widths = [5, 5]
        result = renderer._render_border_top(table, col_widths)
        assert _BORDER_CHARS["single_top_left"] in result
        assert _BORDER_CHARS["single_top_right"] in result
        assert _BORDER_CHARS["single_horizontal"] in result


class TestRenderBorderMiddle:
    """Тесты средней границы."""

    def test_middle_border(self) -> None:
        """Средняя граница."""
        renderer = TableRenderer()
        table = MagicMock()
        col_widths = [5, 5]
        result = renderer._render_border_middle(table, col_widths)
        assert _BORDER_CHARS["single_t_right"] in result
        assert _BORDER_CHARS["single_t_left"] in result
        assert _BORDER_CHARS["single_cross"] in result


class TestRenderBorderBottom:
    """Тесты нижней границы."""

    def test_bottom_border(self) -> None:
        """Нижняя граница."""
        renderer = TableRenderer()
        table = MagicMock()
        col_widths = [5, 5]
        result = renderer._render_border_bottom(table, col_widths)
        assert _BORDER_CHARS["single_bottom_left"] in result
        assert _BORDER_CHARS["single_bottom_right"] in result
        assert _BORDER_CHARS["single_horizontal"] in result


class TestRenderRowContent:
    """Тесты содержимого ряда."""

    def test_row_with_cells(self) -> None:
        """Ряд с ячейками."""
        renderer = TableRenderer()
        table = MagicMock()
        cell1 = MagicMock(text="A")
        cell2 = MagicMock(text="B")
        table.rows = [[cell1, cell2]]

        def get_cell(row: int, col: int) -> Any:
            return [cell1, cell2][col] if col < 2 else None

        table.get_cell = get_cell

        result = renderer._render_row_content(table, 0, [3, 3])
        assert _BORDER_CHARS["single_vertical"] in result
        assert b"A" in result
        assert b"B" in result


class TestPadText:
    """Тесты выравнивания текста."""

    def test_pad_left(self) -> None:
        """Выравнивание влево."""
        renderer = TableRenderer()
        result = renderer._pad_text("Hi", 5, Alignment.LEFT)
        assert result == "Hi   "

    def test_pad_right(self) -> None:
        """Выравнивание вправо."""
        renderer = TableRenderer()
        result = renderer._pad_text("Hi", 5, Alignment.RIGHT)
        assert result == "   Hi"

    def test_pad_center(self) -> None:
        """Выравнивание по центру."""
        renderer = TableRenderer()
        result = renderer._pad_text("Hi", 5, Alignment.CENTER)
        assert result == " Hi  " or result == "  Hi "

    def test_truncate_long_text(self) -> None:
        """Обрезка длинного текста."""
        renderer = TableRenderer()
        result = renderer._pad_text("VeryLongText", 5, Alignment.LEFT)
        assert result == "VeryL"


class TestTableWithManyColumns:
    """Тесты таблиц с множеством колонок."""

    def test_calculate_widths_empty(self) -> None:
        """Расчёт ширин для пустой таблицы."""
        renderer = TableRenderer()
        table = MagicMock()
        table.rows = []

        result = renderer._calculate_column_widths(table)
        assert result == []


class TestRenderBorderVariations:
    """Тесты разных стилей границ."""

    def test_render_border_single_column(self) -> None:
        """Граница для одной колонки."""
        renderer = TableRenderer()
        table = MagicMock()
        col_widths = [10]

        result = renderer._render_border_top(table, col_widths)
        assert _BORDER_CHARS["single_top_left"] in result
        assert _BORDER_CHARS["single_top_right"] in result

    def test_render_border_multiple(self) -> None:
        """Граница для множества колонок."""
        renderer = TableRenderer()
        table = MagicMock()
        col_widths = [5, 5, 5]

        result = renderer._render_border_middle(table, col_widths)
        assert _BORDER_CHARS["single_cross"] in result
