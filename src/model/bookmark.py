"""Модель закладок (Bookmarks).

Закладки позволяют сохранять позиции в документе для быстрого перехода.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True)
class Bookmark:
    """Закладка в документе.

    Attributes:
        name: Имя закладки
        paragraph_index: Индекс параграфа
        run_index: Индекс run в параграфе
        offset: Смещение в run
        created_at: Время создания
    """

    name: str
    paragraph_index: int
    run_index: int
    offset: int
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует закладку в словарь."""
        return {
            "name": self.name,
            "paragraph_index": self.paragraph_index,
            "run_index": self.run_index,
            "offset": self.offset,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Bookmark":
        """Создаёт закладку из словаря."""
        return cls(
            name=data["name"],
            paragraph_index=data["paragraph_index"],
            run_index=data["run_index"],
            offset=data["offset"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass
class DocumentPosition:
    """Позиция в документе.

    Attributes:
        paragraph_index: Индекс параграфа
        run_index: Индекс run
        offset: Смещение в run
    """

    paragraph_index: int
    run_index: int
    offset: int


class BookmarkManager:
    """Менеджер закладок для документа.

    Attributes:
        _bookmarks: Список закладок
        _document_id: ID документа
    """

    def __init__(self, document_id: "UUID") -> None:
        """Инициализирует менеджер закладок.

        Args:
            document_id: ID документа
        """
        self._document_id = document_id
        self._bookmarks: List[Bookmark] = []

    def add_bookmark(self, name: str, position: DocumentPosition) -> Bookmark:
        """Добавляет закладку.

        Args:
            name: Имя закладки
            position: Позиция в документе

        Returns:
            Созданная закладка

        Raises:
            ValueError: Если закладка с таким именем уже существует
        """
        # Проверяем уникальность имени
        for bm in self._bookmarks:
            if bm.name == name:
                raise ValueError(f"Закладка '{name}' уже существует")

        bookmark = Bookmark(
            name=name,
            paragraph_index=position.paragraph_index,
            run_index=position.run_index,
            offset=position.offset,
        )
        self._bookmarks.append(bookmark)
        return bookmark

    def remove_bookmark(self, name: str) -> bool:
        """Удаляет закладку.

        Args:
            name: Имя закладки

        Returns:
            True если закладка была удалена
        """
        for i, bm in enumerate(self._bookmarks):
            if bm.name == name:
                self._bookmarks.pop(i)
                return True
        return False

    def get_bookmark(self, name: str) -> Bookmark | None:
        """Возвращает закладку по имени.

        Args:
            name: Имя закладки

        Returns:
            Закладка или None
        """
        for bm in self._bookmarks:
            if bm.name == name:
                return bm
        return None

    def get_all_bookmarks(self) -> List[Bookmark]:
        """Возвращает все закладки.

        Returns:
            Список закладок
        """
        return list(self._bookmarks)

    def update_bookmark(self, name: str, new_position: DocumentPosition) -> Bookmark | None:
        """Обновляет позицию закладки.

        Args:
            name: Имя закладки
            new_position: Новая позиция

        Returns:
            Обновлённая закладка или None
        """
        for i, bm in enumerate(self._bookmarks):
            if bm.name == name:
                new_bookmark = Bookmark(
                    name=name,
                    paragraph_index=new_position.paragraph_index,
                    run_index=new_position.run_index,
                    offset=new_position.offset,
                    created_at=bm.created_at,
                )
                self._bookmarks[i] = new_bookmark
                return new_bookmark
        return None

    def clear(self) -> None:
        """Удаляет все закладки."""
        self._bookmarks.clear()

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """Конвертирует все закладки в список словарей."""
        return [bm.to_dict() for bm in self._bookmarks]

    @classmethod
    def from_dict_list(cls, document_id: "UUID", data: List[Dict[str, Any]]) -> "BookmarkManager":
        """Создаёт менеджер из списка словарей."""
        manager = cls(document_id)
        for item in data:
            manager._bookmarks.append(Bookmark.from_dict(item))
        return manager


__all__ = ["Bookmark", "BookmarkManager", "DocumentPosition"]
