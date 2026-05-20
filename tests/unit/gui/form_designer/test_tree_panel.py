# -*- coding: utf-8 -*-
"""Тесты для TreePanel (Form Designer).

Тестирует создание панели дерева, добавление/удаление индексов,
drag-drop и контекстное меню.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock

import pytest

TKINTER_AVAILABLE = False
TreePanel: Any = None
try:
    import tkinter as tk

    from src.gui.form_designer.tree_panel import (
        COLOR_BG,
        COLOR_HOVER,
        COLOR_SELECTED,
        PANEL_MIN_HEIGHT,
        PANEL_WIDTH,
        TreePanel,
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


class TestTreePanel:
    """Тесты для TreePanel."""

    def test_constants(self) -> None:
        """Тест констант панели."""
        assert PANEL_WIDTH == 200
        assert PANEL_MIN_HEIGHT == 400

    def test_init_default(self, root: tk.Tk) -> None:
        """Тест инициализации панели по умолчанию."""
        panel = TreePanel(parent=root)
        assert panel._on_select is None
        assert panel._document_indices == {}

    def test_init_with_callbacks(self, root: tk.Tk) -> None:
        """Тест инициализации с callbacks."""
        on_select = MagicMock()
        panel = TreePanel(parent=root, on_select=on_select)
        assert panel._on_select is on_select

    def test_add_document_index(self, root: tk.Tk) -> None:
        """Тест добавления индекса документа."""
        panel = TreePanel(parent=root)
        panel.add_document_index("DVN-44-K53-IX")
        assert "DVN-44-K53-IX" in panel._document_indices

    def test_add_document_index_duplicate(self, root: tk.Tk) -> None:
        """Тест что дубликат не добавляется."""
        panel = TreePanel(parent=root)
        panel.add_document_index("DVN-44-K53-IX")
        panel.add_document_index("DVN-44-K53-IX")
        assert "DVN-44-K53-IX" in panel._document_indices

    def test_add_document_index_too_short(self, root: tk.Tk) -> None:
        """Тест что слишком короткий индекс игнорируется."""
        panel = TreePanel(parent=root)
        panel.add_document_index("X")
        assert "X" not in panel._document_indices

    def test_remove_document_index(self, root: tk.Tk) -> None:
        """Тест удаления индекса документа."""
        panel = TreePanel(parent=root)
        panel.add_document_index("DVN-44-K53-IX")
        panel.remove_document_index("DVN-44-K53-IX")
        assert "DVN-44-K53-IX" not in panel._document_indices

    def test_remove_nonexistent_index(self, root: tk.Tk) -> None:
        """Тест удаления несуществующего индекса."""
        panel = TreePanel(parent=root)
        panel.remove_document_index("NOT-EXIST")  # Не должно вызывать ошибку

    def test_get_selected_index_none(self, root: tk.Tk) -> None:
        """Тест получения выбранного индекса когда ничего не выбрано."""
        panel = TreePanel(parent=root)
        result = panel.get_selected_index()
        assert result is None

    def test_clear(self, root: tk.Tk) -> None:
        """Тест очистки дерева."""
        panel = TreePanel(parent=root)
        panel.add_document_index("DVN-44-K53-IX")
        panel.clear()
        assert panel._document_indices == {}
        assert panel._node_map == {}

    def test_widget_property(self, root: tk.Tk) -> None:
        """Тест свойства widget."""
        panel = TreePanel(parent=root)
        assert panel.widget is not None

    def test_parse_index(self, root: tk.Tk) -> None:
        """Тест парсинга индекса документа."""
        panel = TreePanel(parent=root)
        parts = panel._parse_index("DVN-44-K53-IX")
        assert parts == ["DVN", "44", "K53", "IX"]

    def test_is_valid_move_same_item(self, root: tk.Tk) -> None:
        """Тест что перемещение элемента в себя недопустимо."""
        panel = TreePanel(parent=root)
        result = panel._is_valid_move("item1", "item1")
        assert result is False

    def test_on_copy(self, root: tk.Tk) -> None:
        """Тест копирования в буфер."""
        panel = TreePanel(parent=root)
        panel.add_document_index("DVN-44-K53-IX")
        panel._on_select = MagicMock()
        panel._tree.selection_set(panel._node_map.get("DVN-44-K53-IX", ""))
        panel._on_copy()