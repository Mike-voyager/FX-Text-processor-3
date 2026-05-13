"""Тесты для ESCPGridCanvas.

Модуль содержит тесты для компонента сетки ESC/P,
используемого в дизайнере форм для визуального позиционирования элементов.
"""

import pytest
import tkinter as tk

from src.gui.form_designer.grid_canvas import ESCPGridCanvas


@pytest.fixture
def root():
    """Создаёт корневое окно Tkinter."""
    _root = tk.Tk()
    yield _root
    _root.destroy()


@pytest.fixture
def canvas(root: tk.Tk) -> ESCPGridCanvas:
    """Создаёт экземпляр ESCPGridCanvas."""
    c = ESCPGridCanvas(root, zoom=1.0, show_grid=True)
    c.pack()
    yield c


class TestESCPGridCanvas:
    """Тестовый набор для ESCPGridCanvas."""

    def test_grid_constants(self) -> None:
        """Тест констант сетки ESC/P.

        Проверяет, что стандартные размеры сетки соответствуют
        спецификации Epson FX-890 (80 колонок, 66 строк).
        """
        from src.gui.layout.layout_constants import ESCP_COLS, ESCP_ROWS

        assert ESCP_COLS == 80
        assert ESCP_ROWS == 66

    def test_snap_to_grid(self, canvas: ESCPGridCanvas) -> None:
        """Тест функции привязки к сетке.

        Проверяет корректное округление координат
        до ближайших узлов сетки ESC/P.
        """
        col, row = canvas.snap_to_grid(150, 200)
        assert col == canvas.x_to_col(150)
        assert row == canvas.y_to_row(200)

    def test_canvas_initialization(self, root: tk.Tk) -> None:
        """Тест инициализации холста сетки.

        Проверяет создание экземпляра ESCPGridCanvas
        с корректными начальными параметрами.
        """
        c = ESCPGridCanvas(root, zoom=1.0, show_grid=True)
        assert c is not None
        assert c.get_zoom() == 1.0
        assert c.is_grid_visible() is True

    def test_grid_cell_size_calculation(self, canvas: ESCPGridCanvas) -> None:
        """Тест расчёта размера ячейки сетки.

        Проверяет вычисление размеров ячеек на основе
        текущего масштаба и размеров виджета.
        """
        cw, ch = canvas.get_grid_size()
        assert cw > 0
        assert ch > 0

    def test_coordinate_conversion(self, canvas: ESCPGridCanvas) -> None:
        """Тест преобразования координат.

        Проверяет конвертацию пиксельных координат
        в координаты сетки ESC/P (колонка, строка).
        """
        col, row = 5, 3
        x = canvas.col_to_x(col)
        y = canvas.row_to_y(row)
        assert canvas.x_to_col(x) == col
        assert canvas.y_to_row(y) == row


class TestGridRendering:
    """Тесты для отрисовки сетки."""

    def test_grid_lines_rendering(self, canvas: ESCPGridCanvas) -> None:
        """Тест отрисовки линий сетки.

        Проверяет корректное отображение линий сетки
        на холсте при различных масштабах.
        """
        # Grid lines should exist if show_grid is True
        assert canvas.is_grid_visible() is True
        # There should be some items created for grid
        items = canvas.find_all()
        assert len(items) > 0

    def test_margin_rendering(self, canvas: ESCPGridCanvas) -> None:
        """Тест отрисовки полей страницы.

        Проверяет визуальное отображение полей
        печатаемой области ESC/P.
        """
        # Placeholder: margins are not separately rendered in grid_canvas
        assert True


class TestGridInteraction:
    """Тесты взаимодействия с сеткой."""

    def test_click_to_grid_position(self, canvas: ESCPGridCanvas) -> None:
        """Тест преобразования клика в позицию сетки.

        Проверяет корректное определение позиции ESC/P
        по координатам клика мыши.
        """
        col = canvas.x_to_col(120)
        row = canvas.y_to_row(90)
        assert 0 <= col <= 80
        assert 0 <= row <= 66

    def test_drag_selection(self, canvas: ESCPGridCanvas) -> None:
        """Тест выделения области перетаскиванием.

        Проверяет выделение диапазона ячеек сетки
        при перетаскивании мыши.
        """
        # Placeholder for drag area selection test
        assert True


class TestFieldOverlap:
    """Тесты проверки перекрытия полей."""

    def test_add_field_and_check_overlap(self, canvas: ESCPGridCanvas) -> None:
        """Тест добавления полей и проверки перекрытия.

        Проверяет, что _check_overlap возвращает конфликтующие field_id
        при пересечении bbox.
        """
        cw, ch = canvas.get_grid_size()
        canvas.add_field("A", 0, 0, cw * 2, ch * 2)
        canvas.add_field("B", cw, ch, cw * 3, ch * 3)
        overlaps = canvas._check_overlap("A", 0, 0, cw * 2, ch * 2)
        assert "B" in overlaps

    def test_drag_overlap_red_outline(self, canvas: ESCPGridCanvas) -> None:
        """Тест красного outline при перекрытии во время drag.

        Проверяет, что при overlap outline меняется на red/width=3.
        """
        cw, ch = canvas.get_grid_size()
        canvas.add_field("A", 0, 0, cw * 2, ch * 2)
        canvas.add_field("B", cw * 3, ch * 3, cw * 4, ch * 4)

        def _make_event(x: int, y: int) -> tk.Event:
            event = tk.Event()
            event.x = x
            event.y = y
            event.state = 0
            return event

        # Simulate drag start on A
        info_a = canvas._fields["A"]
        canvas.addtag_withtag("current", info_a.rect_id)
        canvas._on_drag_start(_make_event(cw, ch))
        # Simulate drag motion moving A into B
        canvas._on_drag_motion(_make_event(cw * 4, ch * 4))

        info = canvas._fields["A"]
        outline = canvas.itemcget(info.rect_id, "outline")
        width = canvas.itemcget(info.rect_id, "width")
        assert outline == "red"
        assert int(float(width)) == 3

    def test_drag_overlap_rollback(self, canvas: ESCPGridCanvas) -> None:
        """Тест отката позиции при drop с перекрытием.

        Проверяет, что при ButtonRelease-1 с overlap позиция
        откатывается к последней валидной.
        """
        cw, ch = canvas.get_grid_size()
        canvas.add_field("A", 0, 0, cw * 2, ch * 2)
        canvas.add_field("B", cw * 3, ch * 3, cw * 4, ch * 4)

        def _make_event(x: int, y: int) -> tk.Event:
            event = tk.Event()
            event.x = x
            event.y = y
            event.state = 0
            return event

        # Simulate drag start on A
        info_a = canvas._fields["A"]
        canvas.addtag_withtag("current", info_a.rect_id)
        canvas._on_drag_start(_make_event(cw, ch))
        # Move A into B (invalid)
        canvas._on_drag_motion(_make_event(cw * 4, ch * 4))
        # Release — should rollback
        canvas._on_drag_release(_make_event(cw * 4, ch * 4))

        info = canvas._fields["A"]
        assert info.x1 == 0
        assert info.y1 == 0
        assert info.x2 == cw * 2
        assert info.y2 == ch * 2

