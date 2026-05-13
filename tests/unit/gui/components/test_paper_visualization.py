"""Тесты для paper_visualization.py.

Tests for:
- LineProperties dataclass
- PaperVisualizationWidget
- CodepageStatusWidget

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.gui.components.paper_visualization import (
    DOUBLE_HEIGHT_COLOR,
    ENVELOPE_BORDER_COLOR,
    ENVELOPE_COLOR,
    GUTTER_WIDTH_PX,
    ERROR_STATUS_COLOR,
    PAPER_BORDER_COLOR,
    PERFORATION_COLOR,
    VALID_STATUS_COLOR,
    WARN_STATUS_COLOR,
    CodepageStatusWidget,
    LineProperties,
    PaperVisualizationWidget,
)


class TestLineProperties:
    """Тесты LineProperties dataclass."""

    def test_default_values(self) -> None:
        """Тест значений по умолчанию."""
        props = LineProperties()
        assert props.is_double_height is False
        assert props.is_condensed is False
        assert props.is_bold is False
        assert props.is_italic is False

    def test_double_height_true(self) -> None:
        """Тест с is_double_height=True."""
        props = LineProperties(is_double_height=True)
        assert props.is_double_height is True
        assert props.is_condensed is False

    def test_all_properties(self) -> None:
        """Тест всех свойств."""
        props = LineProperties(
            is_double_height=True,
            is_condensed=True,
            is_bold=True,
            is_italic=True,
        )
        assert props.is_double_height is True
        assert props.is_condensed is True
        assert props.is_bold is True
        assert props.is_italic is True

    def test_frozen_immutable(self) -> None:
        """Тест что dataclass frozen."""
        props = LineProperties()
        with pytest.raises(AttributeError):
            props.is_double_height = True  # type: ignore[attr-defined]


class TestPaperVisualizationWidget:
    """Тесты PaperVisualizationWidget."""

    @pytest.fixture
    def mock_parent(self) -> tk.Tk:
        """Фикстура для родительского Tk окна."""
        root = tk.Tk()
        yield root
        try:
            root.destroy()
        except tk.TclError:
            pass

    @pytest.fixture
    def widget(self, mock_parent: tk.Tk) -> PaperVisualizationWidget:
        """Фикстура для виджета визуализации."""
        w = PaperVisualizationWidget(widget_id="test_paper_viz")
        w.mount(mock_parent)
        return w

    def test_mount_creates_canvas(self, widget: PaperVisualizationWidget) -> None:
        """Тест что mount создаёт canvas."""
        assert widget.is_mounted()
        assert widget._canvas is not None

    def test_set_paper_size(self, widget: PaperVisualizationWidget) -> None:
        """Тест установки размера бумаги."""
        widget.set_paper_size(595, 842)
        assert widget._paper_width_px == 595
        assert widget._paper_height_px == 842

    def test_set_character_size(self, widget: PaperVisualizationWidget) -> None:
        """Тест установки размера символа."""
        widget.set_character_size(9, 15)
        assert widget._char_width_px == 9
        assert widget._char_height_px == 15

    def test_set_document_size(self, widget: PaperVisualizationWidget) -> None:
        """Тест установки размера документа."""
        widget.set_document_size(lines=66, cols=80)
        assert widget._total_lines == 66
        assert widget._total_cols == 80

    def test_set_line_properties(self, widget: PaperVisualizationWidget) -> None:
        """Тест установки свойств строк."""
        properties = [
            LineProperties(is_double_height=True),
            LineProperties(),
            LineProperties(is_double_height=True, is_bold=True),
        ]
        widget.set_line_properties(properties)
        assert len(widget._line_properties) == 3
        assert widget._line_properties[0].is_double_height is True
        assert widget._line_properties[1].is_double_height is False
        assert widget._line_properties[2].is_bold is True

    def test_set_envelope_type_dl(self, widget: PaperVisualizationWidget) -> None:
        """Тест установки типа конверта DL."""
        widget.set_envelope_type("DL")
        assert widget._envelope_type == "DL"
        assert widget._show_envelope is True

    def test_set_envelope_type_c5(self, widget: PaperVisualizationWidget) -> None:
        """Тест установки типа конверта C5."""
        widget.set_envelope_type("C5")
        assert widget._envelope_type == "C5"

    def test_set_envelope_type_none(self, widget: PaperVisualizationWidget) -> None:
        """Тест сброса типа конверта."""
        widget.set_envelope_type("DL")
        widget.set_envelope_type(None)
        assert widget._envelope_type is None
        assert widget._show_envelope is False

    def test_update_with_envelope(self, widget: PaperVisualizationWidget) -> None:
        """Тест обновления с оверлеем конверта."""
        widget.set_paper_size(595, 842)
        widget.set_envelope_type("DL")
        widget.update()

    def test_update_with_envelope_c5(self, widget: PaperVisualizationWidget) -> None:
        """Тест обновления с конвертом C5."""
        widget.set_paper_size(595, 842)
        widget.set_envelope_type("C5")
        widget.update()

    def test_update_with_envelope_c4(self, widget: PaperVisualizationWidget) -> None:
        """Тест обновления с конвертом C4."""
        widget.set_paper_size(595, 842)
        widget.set_envelope_type("C4")
        widget.update()

    def test_set_show_perforation(
        self, widget: PaperVisualizationWidget
    ) -> None:
        """Тест управления видимостью перфорации."""
        widget.set_show_perforation(False)
        assert widget._show_perforation is False

        widget.set_show_perforation(True)
        assert widget._show_perforation is True

    def test_set_show_borders(self, widget: PaperVisualizationWidget) -> None:
        """Тест управления видимостью границ."""
        widget.set_show_borders(False)
        assert widget._show_borders is False

        widget.set_show_borders(True)
        assert widget._show_borders is True

    def test_update(self, widget: PaperVisualizationWidget) -> None:
        """Тест принудительного обновления."""
        widget.set_paper_size(595, 842)
        widget.set_line_properties([LineProperties(is_double_height=True)])
        widget.update()

    def test_unmount(self, widget: PaperVisualizationWidget) -> None:
        """Тест демонтирования."""
        widget.unmount()
        assert widget.is_mounted() is False
        assert widget._canvas is None


class TestCodepageStatusWidget:
    """Тесты CodepageStatusWidget."""

    @pytest.fixture
    def mock_parent(self) -> tk.Tk:
        """Фикстура для родительского Tk окна."""
        root = tk.Tk()
        yield root
        try:
            root.destroy()
        except tk.TclError:
            pass

    @pytest.fixture
    def widget(self, mock_parent: tk.Tk) -> CodepageStatusWidget:
        """Фикстура для виджета статуса Codepage."""
        w = CodepageStatusWidget(widget_id="test_cp_status")
        w.mount(mock_parent)
        return w

    def test_mount_creates_widgets(
        self, widget: CodepageStatusWidget
    ) -> None:
        """Тест что mount создаёт необходимые виджеты."""
        assert widget.is_mounted()
        assert widget._frame is not None
        assert widget._icon_label is not None
        assert widget._count_label is not None

    def test_validate_text_valid(self, widget: CodepageStatusWidget) -> None:
        """Тест валидации валидного текста."""
        widget.validate_text("Hello World")
        assert widget.get_status() == "ok"
        assert widget._invalid_count == 0

    def test_validate_text_invalid_char(
        self, widget: CodepageStatusWidget
    ) -> None:
        """Тест валидации текста с невалидным символом."""
        widget.validate_text("Hello — World")
        assert widget.get_status() in ("warning", "error")
        assert widget._invalid_count > 0

    def test_validate_text_cyrillic_valid(
        self, widget: CodepageStatusWidget
    ) -> None:
        """Тест валидации кириллицы (валидные символы)."""
        widget.validate_text("Привет мир")
        assert widget._invalid_count == 0

    def test_validate_text_yo(self, widget: CodepageStatusWidget) -> None:
        """Тест валидации символа ё (требует замены)."""
        widget.validate_text("ёлка")
        assert widget._invalid_count > 0

    def test_validate_text_em_dash(self, widget: CodepageStatusWidget) -> None:
        """Тест валидации em-dash (требует замены)."""
        widget.validate_text("тест — друг")
        assert widget._invalid_count > 0

    def test_validate_text_warning_status(self, widget: CodepageStatusWidget) -> None:
        """Тест статуса warning когда все символы заменяемы."""
        widget.validate_text("ёлка — мир")
        assert widget.get_status() == "warning"

    def test_get_counts(self, widget: CodepageStatusWidget) -> None:
        """Тест получения количества символов."""
        widget.validate_text("Hello World")
        valid, invalid = widget.get_counts()
        assert valid == 11
        assert invalid == 0

    def test_get_status_ok(self, widget: CodepageStatusWidget) -> None:
        """Тест статуса OK."""
        widget.validate_text("Hello")
        assert widget.get_status() == "ok"

    def test_unmount(self, widget: CodepageStatusWidget) -> None:
        """Тест демонтирования."""
        widget.unmount()
        assert widget.is_mounted() is False
        assert widget._frame is None


class TestConstants:
    """Тесты констант."""

    def test_perforation_color_format(self) -> None:
        """Тест формата цвета перфорации."""
        assert PERFORATION_COLOR == "#cccccc"
        assert isinstance(PERFORATION_COLOR, str)

    def test_paper_border_color_format(self) -> None:
        """Тест формата цвета границы."""
        assert PAPER_BORDER_COLOR == "#999999"

    def test_envelope_colors_format(self) -> None:
        """Тест формата цветов конверта."""
        assert ENVELOPE_COLOR == "#E6E6FA"
        assert ENVELOPE_BORDER_COLOR == "#9370DB"

    def test_double_height_color_format(self) -> None:
        """Тест формата цвета double-height."""
        assert DOUBLE_HEIGHT_COLOR == "#e0e0e0"

    def test_status_colors_format(self) -> None:
        """Тест формата цветов статуса."""
        assert VALID_STATUS_COLOR == "#90EE90"
        assert WARN_STATUS_COLOR == "#FFD700"
        assert ERROR_STATUS_COLOR == "#FF6B6B"

    def test_gutter_width_value(self) -> None:
        """Тест значения ширины gutter."""
        assert GUTTER_WIDTH_PX == 20