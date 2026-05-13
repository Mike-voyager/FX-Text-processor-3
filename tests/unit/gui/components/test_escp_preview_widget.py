"""Тесты для ESCPPreviewWidget.

Module: tests/unit/gui/components/test_escp_preview_widget.py
"""

from __future__ import annotations

from unittest.mock import MagicMock, Mock

import pytest
import tkinter as tk

from src.gui.components.escp_preview_widget import (
    ESCPPreviewWidget,
    PREVIEW_BG_COLOR,
    PREVIEW_FG_COLOR,
)


class TestESCPPreviewWidget:
    """Тесты для ESCPPreviewWidget."""

    @pytest.fixture
    def mock_renderer(self):
        """Мок для DocumentRenderer."""
        renderer = MagicMock()
        renderer.get_page_count.return_value = 3
        renderer.render_page.return_value = b"Hello World\x0c"
        return renderer

    @pytest.fixture
    def mock_document(self):
        """Мок для Document."""
        doc = MagicMock()
        return doc

    @pytest.fixture
    def root(self):
        """Корневой виджет Tkinter для тестов."""
        root = tk.Tk()
        root.withdraw()
        yield root
        root.destroy()

    def test_widget_initialization(self, root, mock_renderer):
        """Виджет инициализируется корректно."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        assert widget is not None
        assert widget._renderer == mock_renderer
        assert widget._current_page == 0
        assert widget._page_count == 1

    def test_escp_to_preview_conversion(self, root, mock_renderer):
        """_escp_to_preview корректно конвертирует ESC/P байты."""
        widget = ESCPPreviewWidget(root, mock_renderer)

        # Тестовые данные: текст + ESC команда + FF
        escp_data = b"Hello\x1b\x40World\x0c"
        result = widget._escp_to_preview(escp_data)

        # Проверяем что получили список кортежей
        assert isinstance(result, list)
        assert len(result) > 0

        # Собираем весь текст
        full_text = "".join(item[0] for item in result)
        assert "Hello" in full_text

        # Проверяем что ESC команда отмечена (с параметром)
        assert "[ESC 0x40" in full_text

    def test_escp_form_feed(self, root, mock_renderer):
        """_escp_to_preview корректно обрабатывает form feed."""
        widget = ESCPPreviewWidget(root, mock_renderer)

        escp_data = b"Text\x0cMore"
        result = widget._escp_to_preview(escp_data)

        texts = [item[0] for item in result]
        assert any("[FF - Разрыв страницы]" in t for t in texts)

    def test_escp_line_feed(self, root, mock_renderer):
        """_escp_to_preview обрабатывает CR+LF как newline."""
        widget = ESCPPreviewWidget(root, mock_renderer)

        escp_data = b"Line1\r\nLine2"
        result = widget._escp_to_preview(escp_data)

        texts = [item[0] for item in result]
        assert "\n" in texts

    def test_insert_with_tags(self, root, mock_renderer):
        """_insert_with_tags вставляет текст с тегами."""
        widget = ESCPPreviewWidget(root, mock_renderer)

        content = [
            ("Hello ", ""),
            ("[ESC]", "esc_command"),
            ("World", ""),
        ]
        widget._insert_with_tags(content)

        text = widget._text_widget.get("1.0", "end-1c")
        assert "Hello [ESC]World" in text

    def test_get_current_page(self, root, mock_renderer):
        """get_current_page возвращает текущую страницу."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        assert widget.get_current_page() == 0

    def test_get_page_count(self, root, mock_renderer):
        """get_page_count возвращает количество страниц."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        assert widget.get_page_count() == 1

    def test_clear_resets_state(self, root, mock_renderer, mock_document):
        """clear очищает виджет и сбрасывает состояние."""
        widget = ESCPPreviewWidget(root, mock_renderer)

        # Настраиваем мок для отображения документа
        mock_renderer.get_page_count.return_value = 5
        widget.show_document(mock_document)

        assert widget._current_page == 0
        assert widget._page_count == 5

        # Очищаем
        widget.clear()

        assert widget._current_document is None
        assert widget._current_page == 0
        assert widget._page_count == 1

    def test_widget_colors(self, root, mock_renderer):
        """Виджет использует правильные цвета."""
        widget = ESCPPreviewWidget(root, mock_renderer)

        bg = widget._text_widget.cget("background")
        fg = widget._text_widget.cget("foreground")

        assert bg == PREVIEW_BG_COLOR
        assert fg == PREVIEW_FG_COLOR


class TestESCPPreviewWidgetNavigation:
    """Тесты навигации по страницам."""

    @pytest.fixture
    def mock_renderer(self):
        """Мок для DocumentRenderer."""
        renderer = MagicMock()
        renderer.get_page_count.return_value = 3
        renderer.render_page.return_value = b"Page content"
        return renderer

    @pytest.fixture
    def mock_document(self):
        """Мок для Document."""
        doc = MagicMock()
        return doc

    @pytest.fixture
    def root(self):
        """Корневой виджет Tkinter для тестов."""
        root = tk.Tk()
        root.withdraw()
        yield root
        root.destroy()

    def test_show_document_sets_page_count(self, root, mock_renderer, mock_document):
        """show_document устанавливает количество страниц."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        widget.show_document(mock_document)

        assert widget._page_count == 3
        assert widget._current_page == 0

    def test_next_page_increments_page(self, root, mock_renderer, mock_document):
        """_next_page увеличивает номер страницы."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        widget.show_document(mock_document)

        widget._next_page()
        assert widget._current_page == 1

    def test_next_page_stops_at_last(self, root, mock_renderer, mock_document):
        """_next_page не переходит за последнюю страницу."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        widget.show_document(mock_document)

        widget._current_page = 2  # Last page (0, 1, 2)
        widget._next_page()
        assert widget._current_page == 2

    def test_prev_page_decrements_page(self, root, mock_renderer, mock_document):
        """_prev_page уменьшает номер страницы."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        widget.show_document(mock_document)

        widget._current_page = 2
        widget._prev_page()
        assert widget._current_page == 1

    def test_prev_page_stops_at_first(self, root, mock_renderer, mock_document):
        """_prev_page не переходит за первую страницу."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        widget.show_document(mock_document)

        widget._prev_page()
        assert widget._current_page == 0

    def test_first_page_goes_to_start(self, root, mock_renderer, mock_document):
        """_first_page переходит на первую страницу."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        widget.show_document(mock_document)

        widget._current_page = 2
        widget._first_page()
        assert widget._current_page == 0

    def test_last_page_goes_to_end(self, root, mock_renderer, mock_document):
        """_last_page переходит на последнюю страницу."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        widget.show_document(mock_document)

        widget._last_page()
        assert widget._current_page == 2


class TestESCPPreviewIntegration:
    """Интеграционные тесты."""

    @pytest.fixture
    def mock_renderer(self):
        """Мок для DocumentRenderer."""
        renderer = MagicMock()
        renderer.get_page_count.return_value = 1
        renderer.render_page.return_value = b"Document content"
        return renderer

    @pytest.fixture
    def root(self):
        """Корневой виджет Tkinter для тестов."""
        root = tk.Tk()
        root.withdraw()
        yield root
        root.destroy()

    def test_show_document_calls_renderer(self, root, mock_renderer):
        """show_document вызывает DocumentRenderer."""
        from src.documents.printing.document_renderer import RenderSettings

        widget = ESCPPreviewWidget(root, mock_renderer)
        mock_doc = MagicMock()
        settings = MagicMock()

        widget.show_document(mock_doc, settings)

        mock_renderer.get_page_count.assert_called_once_with(mock_doc, settings)
        mock_renderer.render_page.assert_called_once_with(mock_doc, 0, settings)

    def test_navigation_buttons_update(self, root, mock_renderer):
        """Кнопки навигации обновляют состояние."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        mock_doc = MagicMock()
        mock_renderer.get_page_count.return_value = 5

        widget.show_document(mock_doc)

        # Prev должна быть отключена на первой странице
        prev_state = str(widget._prev_btn.cget("state"))
        assert prev_state == "disabled"

        # Next должна быть активна
        next_state = str(widget._next_btn.cget("state"))
        assert next_state == "normal"

    def test_page_label_updates(self, root, mock_renderer):
        """Метка страницы обновляется."""
        widget = ESCPPreviewWidget(root, mock_renderer)
        mock_doc = MagicMock()
        mock_renderer.get_page_count.return_value = 3

        widget.show_document(mock_doc)

        label_text = widget._page_label.cget("text")
        assert "Страница 1/3" == label_text
