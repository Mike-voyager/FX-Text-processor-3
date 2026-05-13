"""Тесты BookmarksDialog.

Module: tests/unit/view/test_bookmarks_dialog.py
"""

from __future__ import annotations

from datetime import datetime
from tkinter import Tk
from unittest.mock import MagicMock

import pytest

from src.view.dialogs.bookmarks_dialog import BookmarksDialog


@pytest.fixture
def root() -> Tk:
    """Root window для тестов."""
    root = Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def sample_bookmarks() -> list[tuple[str, int, int, int, datetime]]:
    """Пример списка закладок."""
    return [
        ("Глава 1", 0, 0, 0, datetime(2026, 3, 26, 10, 0, 0)),
        ("Важное место", 5, 2, 15, datetime(2026, 3, 26, 11, 30, 0)),
        ("Конец", 100, 0, 0, datetime(2026, 3, 26, 12, 0, 0)),
    ]


class TestBookmarksDialogInit:
    """Тесты инициализации диалога."""

    def test_create_default(self, root: Tk, sample_bookmarks: list) -> None:
        """Тест создания диалога."""
        dialog = BookmarksDialog(
            parent=root,
            bookmarks=sample_bookmarks,
        )

        assert dialog._parent == root
        assert dialog._bookmarks == sample_bookmarks
        assert dialog._theme == "classic_green"
        assert dialog._selected_name is None

    def test_create_with_theme(self, root: Tk, sample_bookmarks: list) -> None:
        """Тест создания с темой."""
        dialog = BookmarksDialog(
            parent=root,
            bookmarks=sample_bookmarks,
            theme="amber",
        )

        assert dialog._theme == "amber"

    def test_create_with_callbacks(self, root: Tk, sample_bookmarks: list) -> None:
        """Тест создания с callbacks."""
        on_goto = MagicMock()
        on_rename = MagicMock()
        on_delete = MagicMock()

        dialog = BookmarksDialog(
            parent=root,
            bookmarks=sample_bookmarks,
            on_goto=on_goto,
            on_rename=on_rename,
            on_delete=on_delete,
        )

        assert dialog._on_goto == on_goto
        assert dialog._on_rename == on_rename
        assert dialog._on_delete == on_delete


class TestBookmarksDialogColors:
    """Тесты цветовых схем."""

    def test_classic_green_colors(self, root: Tk) -> None:
        """Тест цветов classic_green."""
        dialog = BookmarksDialog(root, [])
        colors = dialog.COLORS["classic_green"]

        assert colors["bg"] == "#000000"
        assert colors["fg"] == "#00FF00"
        assert colors["accent"] == "#00AA00"

    def test_amber_colors(self, root: Tk) -> None:
        """Тест цветов amber."""
        dialog = BookmarksDialog(root, [])
        colors = dialog.COLORS["amber"]

        assert colors["bg"] == "#000000"
        assert colors["fg"] == "#FFB000"

    def test_dos_blue_colors(self, root: Tk) -> None:
        """Тест цветов dos_blue."""
        dialog = BookmarksDialog(root, [])
        colors = dialog.COLORS["dos_blue"]

        assert colors["bg"] == "#0000AA"
        assert colors["fg"] == "#FFFFFF"

    def test_paper_white_colors(self, root: Tk) -> None:
        """Тест цветов paper_white."""
        dialog = BookmarksDialog(root, [])
        colors = dialog.COLORS["paper_white"]

        assert colors["bg"] == "#FFFFFF"
        assert colors["fg"] == "#000000"

    def test_matrix_colors(self, root: Tk) -> None:
        """Тест цветов matrix."""
        dialog = BookmarksDialog(root, [])
        colors = dialog.COLORS["matrix"]

        assert colors["bg"] == "#000000"
        assert colors["fg"] == "#00FF41"


class TestBookmarksDialogEmpty:
    """Тесты пустого списка закладок."""

    def test_empty_bookmarks(self, root: Tk) -> None:
        """Тест отображения пустого списка."""
        dialog = BookmarksDialog(root, [])

        assert dialog._bookmarks == []


class TestBookmarksDialogAllExports:
    """Тесты экспорта из модуля."""

    def test_export_bookmarks_dialog(self) -> None:
        """Тест экспорта BookmarksDialog."""
        from src.view.dialogs import BookmarksDialog as ExportedDialog

        assert ExportedDialog is BookmarksDialog

    def test_all_exports(self) -> None:
        """Тест наличия в __all__."""
        from src.view.dialogs import __all__

        assert "BookmarksDialog" in __all__
