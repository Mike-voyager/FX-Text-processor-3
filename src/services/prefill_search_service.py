"""Сервис поиска значений полей для автозаполнения.

Использует IndexSearchService для поиска документов,
затем извлекает значения полей.

Module: src/services/prefill_search_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final, Optional

from src.services.index_search_service import (
    IndexSearchService,
    SearchField,
    SearchQuery,
)

logger: Final = logging.getLogger(__name__)


@dataclass(frozen=True)
class PrefillMatch:
    """Результат поиска для автозаполнения.

    Attributes:
        document_id: ID документа-источника.
        document_name: Название документа.
        field_id: ID поля.
        field_value: Значение поля.
        confidence: Уверенность совпадения (0.0-1.0).
    """

    document_id: str
    document_name: str
    field_id: str
    field_value: str
    confidence: float


class PrefillSearchService:
    """Сервис поиска значений полей для автозаполнения.

    Args:
        index_service: Сервис индексного поиска.
    """

    def __init__(self, index_service: Optional[IndexSearchService] = None) -> None:
        """Инициализирует сервис.

        Args:
            index_service: Сервис индексного поиска (опционально).
        """
        self._index_service: IndexSearchService = index_service or IndexSearchService()

    def search_field_values(
        self,
        field_id: str,
        query: str,
        limit: int = 10,
    ) -> list[PrefillMatch]:
        """Ищет значения поля в проиндексированных документах.

        Args:
            field_id: ID поля для поиска.
            query: Поисковый запрос.
            limit: Максимум результатов.

        Returns:
            Список совпадений.
        """
        if not query.strip():
            return []

        search_query = SearchQuery(
            text=query,
            fields=[SearchField.ALL],
            limit=limit,
        )
        try:
            response = self._index_service.search(search_query)
        except Exception as exc:
            logger.warning("Ошибка поиска в индексе: %s", exc)
            return []

        if not response.success:
            logger.warning("Поиск вернул ошибку: %s", response.error)
            return []

        matches: list[PrefillMatch] = []
        for result in response.results:
            # confidence из score, ограничиваем [0,1] с fallback 0.5
            confidence = min(max(result.score if result.score is not None else 0.5, 0.0), 1.0)

            # field_value из metadata[field_id] или title
            field_value = ""
            if isinstance(result.metadata, dict):
                raw = result.metadata.get(field_id)
                if raw is not None:
                    field_value = str(raw)
            if not field_value:
                field_value = result.title or ""

            matches.append(
                PrefillMatch(
                    document_id=str(result.document_id),
                    document_name=result.title or "",
                    field_id=field_id,
                    field_value=field_value,
                    confidence=confidence,
                )
            )

        return matches[:limit]

    def suggest_field_values(
        self,
        field_id: str,
        prefix: str,
        limit: int = 10,
    ) -> list[PrefillMatch]:
        """Предлагает варианты автодополнения по префиксу.

        Args:
            field_id: ID поля.
            prefix: Префикс значения.
            limit: Максимум результатов.

        Returns:
            Список совпадений.
        """
        if not prefix.strip():
            return []

        try:
            suggestions = self._index_service.suggest(prefix, limit=limit)
        except Exception as exc:
            logger.warning("Ошибка подсказок из индекса: %s", exc)
            return []

        matches: list[PrefillMatch] = []
        for text in suggestions:
            matches.append(
                PrefillMatch(
                    document_id="",
                    document_name="",
                    field_id=field_id,
                    field_value=text,
                    confidence=0.8,
                )
            )

        return matches[:limit]


__all__ = [
    "PrefillMatch",
    "PrefillSearchService",
]
