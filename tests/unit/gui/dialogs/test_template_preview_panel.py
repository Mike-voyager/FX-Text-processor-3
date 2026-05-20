# -*- coding: utf-8 -*-
"""Тесты для TemplatePreviewWidget.

Тестирует создание виджета предпросмотра шаблона,
загрузку данных и вызов callback-ов.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock

import pytest

TKINTER_AVAILABLE = False
TemplatePreviewWidget: Any = None
try:
    import tkinter as tk

    from src.gui.dialogs.template_preview_panel import (
        COLOR_BG,
        COLOR_ERROR,
        COLOR_SUCCESS,
        THUMB_HEIGHT,
        THUMB_WIDTH,
        TemplatePreviewWidget,
    )

    TKINTER_AVAILABLE = True
except (ImportError, AttributeError, OSError, RuntimeError):
    pass


pytestmark = pytest.mark.skipif(
    not TKINTER_AVAILABLE,
    reason="Tkinter недоступен",
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Создаёт Tk root для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestTemplatePreviewWidget:
    """Тесты для TemplatePreviewWidget."""

    def test_constants(self) -> None:
        """Тест констант виджета."""
        assert THUMB_WIDTH == 240
        assert THUMB_HEIGHT == 160

    def test_init_default(self, root: tk.Tk) -> None:
        """Тест инициализации виджета без данных."""
        widget = TemplatePreviewWidget(root)
        assert widget._new_doc_callback is None
        assert widget._print_blank_callback is None
        widget.destroy()

    def test_init_with_data(self, root: tk.Tk) -> None:
        """Тест инициализации виджета с данными шаблона."""
        data = {"name": "Invoice", "fields": 15, "signature_valid": True}
        widget = TemplatePreviewWidget(root, template_data=data)
        assert widget._template_data.get("name") == "Invoice"
        widget.destroy()

    def test_load_template(self, root: tk.Tk) -> None:
        """Тест загрузки шаблона."""
        widget = TemplatePreviewWidget(root)
        data = {"name": "Test Template", "fields": 10}
        widget.load_template(data)
        assert widget._template_data.get("name") == "Test Template"
        widget.destroy()

    def test_on_new_document_callback(self, root: tk.Tk) -> None:
        """Тест callback создания документа."""
        widget = TemplatePreviewWidget(root)
        callback = MagicMock()
        widget.on_new_document(callback)
        assert widget._new_doc_callback is callback
        widget._trigger_new_document()
        callback.assert_called_once()
        widget.destroy()

    def test_on_print_blank_callback(self, root: tk.Tk) -> None:
        """Тест callback печати бланка."""
        widget = TemplatePreviewWidget(root)
        callback = MagicMock()
        widget.on_print_blank(callback)
        assert widget._print_blank_callback is callback
        widget._trigger_print_blank()
        callback.assert_called_once()
        widget.destroy()

    def test_trigger_new_document_no_callback(self, root: tk.Tk) -> None:
        """Тест триггера без установленного callback."""
        widget = TemplatePreviewWidget(root)
        widget._trigger_new_document()  # Не должно вызывать ошибку
        widget.destroy()

    def test_trigger_print_blank_no_callback(self, root: tk.Tk) -> None:
        """Тест триггера без установленного callback."""
        widget = TemplatePreviewWidget(root)
        widget._trigger_print_blank()  # Не должно вызывать ошибку
        widget.destroy()