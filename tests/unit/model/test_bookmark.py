"""Тесты для модуля закладок.

Module: tests/unit/model/test_bookmark.py
"""

from __future__ import annotations

import pytest
from uuid import UUID, uuid4

from src.model.bookmark import Bookmark, BookmarkManager, DocumentPosition


class TestBookmark:
    """Тесты для Bookmark."""

    def test_create_bookmark(self) -> None:
        """Создание закладки."""
        bookmark = Bookmark(
            name="Глава 1",
            paragraph_index=0,
            run_index=0,
            offset=10,
        )

        assert bookmark.name == "Глава 1"
        assert bookmark.paragraph_index == 0
        assert bookmark.run_index == 0
        assert bookmark.offset == 10

    def test_bookmark_to_dict(self) -> None:
        """Конвертация закладки в словарь."""
        bookmark = Bookmark(
            name="Test",
            paragraph_index=1,
            run_index=2,
            offset=5,
        )

        data = bookmark.to_dict()

        assert data["name"] == "Test"
        assert data["paragraph_index"] == 1
        assert data["run_index"] == 2
        assert data["offset"] == 5
        assert "created_at" in data

    def test_bookmark_from_dict(self) -> None:
        """Создание закладки из словаря."""
        from datetime import datetime

        now = datetime.now()
        data = {
            "name": "Test",
            "paragraph_index": 1,
            "run_index": 2,
            "offset": 5,
            "created_at": now.isoformat(),
        }

        bookmark = Bookmark.from_dict(data)

        assert bookmark.name == "Test"
        assert bookmark.paragraph_index == 1
        assert bookmark.run_index == 2
        assert bookmark.offset == 5


class TestBookmarkManager:
    """Тесты для BookmarkManager."""

    def test_create_manager(self) -> None:
        """Создание менеджера закладок."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        assert len(manager.get_all_bookmarks()) == 0

    def test_add_bookmark(self) -> None:
        """Добавление закладки."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=10)
        bookmark = manager.add_bookmark("Введение", pos)

        assert bookmark.name == "Введение"
        assert bookmark.paragraph_index == 0
        assert len(manager.get_all_bookmarks()) == 1

    def test_add_duplicate_bookmark(self) -> None:
        """Попытка добавить закладку с существующим именем."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=10)
        manager.add_bookmark("Глава 1", pos)

        with pytest.raises(ValueError, match="уже существует"):
            manager.add_bookmark("Глава 1", pos)

    def test_remove_bookmark(self) -> None:
        """Удаление закладки."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=10)
        manager.add_bookmark("Удалить", pos)

        result = manager.remove_bookmark("Удалить")

        assert result is True
        assert len(manager.get_all_bookmarks()) == 0

    def test_remove_nonexistent_bookmark(self) -> None:
        """Удаление несуществующей закладки."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        result = manager.remove_bookmark("Не существует")

        assert result is False

    def test_get_bookmark(self) -> None:
        """Получение закладки по имени."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=1, run_index=2, offset=5)
        manager.add_bookmark("Найти", pos)

        bookmark = manager.get_bookmark("Найти")

        assert bookmark is not None
        assert bookmark.name == "Найти"
        assert bookmark.paragraph_index == 1

    def test_get_nonexistent_bookmark(self) -> None:
        """Получение несуществующей закладки."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        bookmark = manager.get_bookmark("Не существует")

        assert bookmark is None

    def test_clear_bookmarks(self) -> None:
        """Очистка всех закладок."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=0)
        manager.add_bookmark("1", pos)
        manager.add_bookmark("2", pos)

        manager.clear()

        assert len(manager.get_all_bookmarks()) == 0

    def test_to_dict_list(self) -> None:
        """Конвертация в список словарей."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=0)
        manager.add_bookmark("Test", pos)

        data = manager.to_dict_list()

        assert len(data) == 1
        assert data[0]["name"] == "Test"

    def test_from_dict_list(self) -> None:
        """Создание менеджера из списка словарей."""
        doc_id = uuid4()
        data = [
            {
                "name": "Bookmark1",
                "paragraph_index": 0,
                "run_index": 0,
                "offset": 10,
                "created_at": "2026-01-01T00:00:00",
            }
        ]

        manager = BookmarkManager.from_dict_list(doc_id, data)

        assert len(manager.get_all_bookmarks()) == 1
        assert manager.get_bookmark("Bookmark1") is not None

    def test_rename_bookmark(self) -> None:
        """Переименование закладки."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=10)
        manager.add_bookmark("OldName", pos)

        result = manager.rename_bookmark("OldName", "NewName")

        assert result is not None
        assert result.name == "NewName"
        assert manager.get_bookmark("OldName") is None
        assert manager.get_bookmark("NewName") is not None

    def test_rename_nonexistent_bookmark(self) -> None:
        """Переименование несуществующей закладки."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        result = manager.rename_bookmark("Missing", "New")

        assert result is None

    def test_rename_to_existing_name(self) -> None:
        """Переименование в уже существующее имя."""
        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=10)
        manager.add_bookmark("First", pos)
        manager.add_bookmark("Second", pos)

        with pytest.raises(ValueError, match="уже существует"):
            manager.rename_bookmark("First", "Second")

    def test_rename_preserves_created_at(self) -> None:
        """Переименование сохраняет created_at."""
        from datetime import datetime

        doc_id = uuid4()
        manager = BookmarkManager(doc_id)

        pos = DocumentPosition(paragraph_index=0, run_index=0, offset=10)
        bm = manager.add_bookmark("Original", pos)
        original_created = bm.created_at

        renamed = manager.rename_bookmark("Original", "Renamed")

        assert renamed is not None
        assert renamed.created_at == original_created


class TestDocumentPosition:
    """Тесты для DocumentPosition."""

    def test_create_position(self) -> None:
        """Создание позиции."""
        pos = DocumentPosition(paragraph_index=1, run_index=2, offset=5)

        assert pos.paragraph_index == 1
        assert pos.run_index == 2
        assert pos.offset == 5
