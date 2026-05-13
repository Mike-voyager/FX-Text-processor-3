"""Сервис поиска по индексу.

Полнотекстовый поиск по документам с использованием составного индекса.
Поддерживает поиск по DVN-индексу, метаданным и содержимому.

Module: src/services/index_search_service.py
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, Set
from uuid import UUID

if TYPE_CHECKING:
    from src.model.document import Document

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы поиска
# ---------------------------------------------------------------------------


class SearchField(Enum):
    """Поля для поиска."""

    ALL = "all"  # Все поля
    INDEX = "index"  # DVN-индекс
    TITLE = "title"  # Заголовок
    CONTENT = "content"  # Содержимое
    METADATA = "metadata"  # Метаданные
    AUTHOR = "author"  # Автор
    DATE = "date"  # Дата


class SearchOperator(Enum):
    """Операторы поиска."""

    AND = "and"  # Все условия
    OR = "or"  # Любое условие
    NOT = "not"  # Исключение


class SortOrder(Enum):
    """Порядок сортировки."""

    RELEVANCE = "relevance"  # По релевантности
    DATE_ASC = "date_asc"  # По дате (возрастание)
    DATE_DESC = "date_desc"  # По дате (убывание)
    TITLE_ASC = "title_asc"  # По заголовку (А-Я)
    TITLE_DESC = "title_desc"  # По заголовку (Я-А)
    INDEX_ASC = "index_asc"  # По индексу
    INDEX_DESC = "index_desc"  # По индексу (обратный)


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SearchQuery:
    """Поисковый запрос.

    Attrs:
        text: Поисковый текст
        fields: Поля для поиска
        operator: Оператор объединения условий
        case_sensitive: Регистрозависимый поиск
        whole_word: Только целые слова
        use_regex: Использовать регулярные выражения
        date_from: Дата с (optional)
        date_to: Дата по (optional)
        index_prefix: Префикс индекса (optional)
        exclude_ids: Исключить документы (optional)
        limit: Максимум результатов
        offset: Смещение для пагинации
        sort_by: Порядок сортировки
    """

    text: str = ""
    fields: List[SearchField] = field(default_factory=lambda: [SearchField.ALL])
    operator: SearchOperator = SearchOperator.AND
    case_sensitive: bool = False
    whole_word: bool = False
    use_regex: bool = False
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    index_prefix: Optional[str] = None
    exclude_ids: Set[UUID] = field(default_factory=set)
    limit: int = 100
    offset: int = 0
    sort_by: SortOrder = SortOrder.RELEVANCE


@dataclass(frozen=True)
class SearchResult:
    """Результат поиска.

    Attrs:
        document_id: ID документа
        title: Заголовок
        index: DVN-индекс
        score: Оценка релевантности (0-1)
        snippets: Фрагменты с подсветкой
        matches: Позиции совпадений
        metadata: Метаданные документа
    """

    document_id: UUID
    title: str = ""
    index: str = ""
    score: float = 0.0
    snippets: List[str] = field(default_factory=list)
    matches: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SearchResponse:
    """Ответ на поисковый запрос.

    Attrs:
        success: Успешность поиска
        query: Исходный запрос
        results: Результаты поиска
        total_count: Общее количество результатов
        execution_time_ms: Время выполнения (мс)
        error: Сообщение об ошибке (optional)
    """

    success: bool
    query: SearchQuery
    results: List[SearchResult] = field(default_factory=list)
    total_count: int = 0
    execution_time_ms: float = 0.0
    error: Optional[str] = None


@dataclass(frozen=True)
class IndexEntry:
    """Запись в индексе.

    Attrs:
        document_id: ID документа
        index: DVN-индекс
        title: Заголовок
        content: Текст документа (для поиска)
        keywords: Ключевые слова
        author: Автор
        created_at: Дата создания
        modified_at: Дата изменения
        metadata: Дополнительные метаданные
    """

    document_id: UUID
    index: str = ""
    title: str = ""
    content: str = ""
    keywords: List[str] = field(default_factory=list)
    author: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    modified_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class IndexStorage(Protocol):
    """Протокол хранилища индекса."""

    def get_entry(self, document_id: UUID) -> Optional[IndexEntry]:
        """Возвращает запись индекса.

        Args:
            document_id: ID документа

        Returns:
            Запись или None
        """
        ...

    def save_entry(self, entry: IndexEntry) -> bool:
        """Сохраняет запись индекса.

        Args:
            entry: Запись

        Returns:
            True если успешно
        """
        ...

    def delete_entry(self, document_id: UUID) -> bool:
        """Удаляет запись индекса.

        Args:
            document_id: ID документа

        Returns:
            True если успешно
        """
        ...

    def search(
        self,
        query: str,
        fields: List[SearchField],
        limit: int,
    ) -> List[IndexEntry]:
        """Ищет записи по запросу.

        Args:
            query: Поисковый запрос
            fields: Поля для поиска
            limit: Максимум результатов

        Returns:
            Список записей
        """
        ...


# ---------------------------------------------------------------------------
# IndexSearchService
# ---------------------------------------------------------------------------


class IndexSearchService:
    """Сервис полнотекстового поиска.

    Предоставляет:
    - Индексацию документов
    - Полнотекстовый поиск
    - Поиск по DVN-индексу
    - Фильтрация по метаданным
    - Подсветка совпадений

    Пример:
        >>> service = IndexSearchService()
        >>> service.index_document(document)
        >>> response = service.search(SearchQuery(text="pattern"))
        >>> for result in response.results:
        ...     print(f"{result.title}: {result.score}")
    """

    def __init__(self, storage: Optional[IndexStorage] = None) -> None:
        """Инициализирует сервис.

        Args:
            storage: Хранилище индекса (optional)
        """
        self._storage = storage
        self._index: Dict[UUID, IndexEntry] = {}
        self._keyword_index: Dict[str, Set[UUID]] = {}  # keyword -> document IDs

    # ---------- Индексация ----------

    def index_document(self, document: "Document") -> bool:
        """Индексирует документ.

        Args:
            document: Документ для индексации

        Returns:
            True если успешно
        """
        try:
            # Извлекаем данные из документа
            entry = self._extract_entry(document)

            # Добавляем в индекс
            self._index[entry.document_id] = entry

            # Индексируем ключевые слова
            for keyword in entry.keywords:
                keyword_lower = keyword.lower()
                if keyword_lower not in self._keyword_index:
                    self._keyword_index[keyword_lower] = set()
                self._keyword_index[keyword_lower].add(entry.document_id)

            # Сохраняем в хранилище
            if self._storage:
                self._storage.save_entry(entry)

            logger.debug("Документ проиндексирован: %s", entry.document_id)
            return True

        except Exception as exc:
            logger.error("Ошибка индексации: %s", exc)
            return False

    def reindex_document(self, document: "Document") -> bool:
        """Переиндексирует документ.

        Args:
            document: Документ

        Returns:
            True если успешно
        """
        self.remove_from_index(document.id)
        return self.index_document(document)

    def remove_from_index(self, document_id: UUID) -> bool:
        """Удаляет документ из индекса.

        Args:
            document_id: ID документа

        Returns:
            True если успешно
        """
        entry = self._index.get(document_id)
        if entry is None:
            return False

        # Удаляем из ключевого индекса
        for keyword in entry.keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in self._keyword_index:
                self._keyword_index[keyword_lower].discard(document_id)

        # Удаляем из основного индекса
        del self._index[document_id]

        # Удаляем из хранилища
        if self._storage:
            self._storage.delete_entry(document_id)

        logger.debug("Документ удалён из индекса: %s", document_id)
        return True

    def clear_index(self) -> int:
        """Очищает весь индекс.

        Returns:
            Количество удалённых записей
        """
        count = len(self._index)
        self._index.clear()
        self._keyword_index.clear()

        logger.info("Индекс очищен: %d записей", count)
        return count

    # ---------- Поиск ----------

    def search(self, query: SearchQuery) -> SearchResponse:
        """Выполняет поиск.

        Args:
            query: Поисковый запрос

        Returns:
            Результаты поиска
        """
        import time

        start_time = time.time()

        try:
            # Находим кандидатов
            candidates = self._find_candidates(query)

            # Фильтруем и ранжируем
            results = self._rank_results(candidates, query)

            # Применяем пагинацию
            total_count = len(results)
            results = results[query.offset : query.offset + query.limit]

            execution_time = (time.time() - start_time) * 1000

            return SearchResponse(
                success=True,
                query=query,
                results=results,
                total_count=total_count,
                execution_time_ms=execution_time,
            )

        except Exception as exc:
            logger.error("Ошибка поиска: %s", exc)
            return SearchResponse(
                success=False,
                query=query,
                error=str(exc),
            )

    def search_by_index(self, index_pattern: str) -> SearchResponse:
        """Ищет по DVN-индексу.

        Args:
            index_pattern: Шаблон индекса (например, "DVN-44-*")

        Returns:
            Результаты поиска
        """
        # Конвертируем wildcard в regex
        regex_pattern = index_pattern.replace("*", ".*").replace("?", ".")
        regex = re.compile(f"^{regex_pattern}$", re.IGNORECASE)

        results: List[SearchResult] = []

        for entry in self._index.values():
            if regex.match(entry.index):
                results.append(
                    SearchResult(
                        document_id=entry.document_id,
                        title=entry.title,
                        index=entry.index,
                        score=1.0,
                    )
                )

        return SearchResponse(
            success=True,
            query=SearchQuery(text=index_pattern, fields=[SearchField.INDEX]),
            results=results,
            total_count=len(results),
        )

    def search_by_keyword(self, keyword: str) -> SearchResponse:
        """Ищет по ключевому слову.

        Args:
            keyword: Ключевое слово

        Returns:
            Результаты поиска
        """
        keyword_lower = keyword.lower()
        document_ids = self._keyword_index.get(keyword_lower, set())

        results: List[SearchResult] = []

        for doc_id in document_ids:
            entry = self._index.get(doc_id)
            if entry:
                results.append(
                    SearchResult(
                        document_id=entry.document_id,
                        title=entry.title,
                        index=entry.index,
                        score=1.0,
                    )
                )

        return SearchResponse(
            success=True,
            query=SearchQuery(text=keyword),
            results=results,
            total_count=len(results),
        )

    # ---------- Утилиты ----------

    def get_entry(self, document_id: UUID) -> Optional[IndexEntry]:
        """Возвращает запись индекса.

        Args:
            document_id: ID документа

        Returns:
            Запись или None
        """
        return self._index.get(document_id)

    def get_index_count(self) -> int:
        """Возвращает количество проиндексированных документов."""
        return len(self._index)

    def get_keywords(self) -> List[str]:
        """Возвращает все ключевые слова."""
        return list(self._keyword_index.keys())

    def suggest(self, prefix: str, limit: int = 10) -> List[str]:
        """Предлагает варианты автодополнения.

        Args:
            prefix: Префикс для поиска
            limit: Максимум вариантов

        Returns:
            Список предложений
        """
        prefix_lower = prefix.lower()
        suggestions: List[str] = []

        # Ищем по ключевым словам
        for keyword in self._keyword_index:
            if keyword.startswith(prefix_lower):
                suggestions.append(keyword)
                if len(suggestions) >= limit:
                    break

        return suggestions

    # ---------- Внутренние методы ----------

    def _extract_entry(self, document: "Document") -> IndexEntry:
        """Извлекает данные из документа для индексации.

        Args:
            document: Документ

        Returns:
            Запись индекса
        """
        # Извлекаем текст документа
        content = ""
        if hasattr(document, "get_text_content"):
            content = document.get_text_content()
        elif hasattr(document, "sections"):
            for section in document.sections:
                if hasattr(section, "paragraphs"):
                    for para in section.paragraphs:
                        if hasattr(para, "get_text"):
                            content += para.get_text() + "\n"

        # Извлекаем ключевые слова
        keywords: List[str] = []
        if hasattr(document, "metadata"):
            if hasattr(document.metadata, "keywords"):
                keywords = list(document.metadata.keywords)

        # Извлекаем DVN-индекс
        index = ""
        if hasattr(document, "document_type"):
            if hasattr(document.document_type, "format_index"):
                raw_attr = getattr(document.document_type, "format_index")
                raw_index = str(raw_attr() if callable(raw_attr) else raw_attr)
                if "-" in raw_index:
                    segments = raw_index.split("-")
                    formatted_segments: List[str] = []
                    for seg in segments:
                        stripped = seg.strip()
                        if "-" in stripped:
                            formatted_segments.append(stripped)
                        else:
                            formatted_segments.append(stripped.upper())
                    index = "-".join(formatted_segments)
                else:
                    index = raw_index.upper().strip()

        return IndexEntry(
            document_id=document.id,
            index=index,
            title=document.metadata.title if hasattr(document, "metadata") else "",
            content=content,
            keywords=keywords,
            author=document.metadata.author if hasattr(document, "metadata") else "",
            created_at=document.metadata.created
            if hasattr(document, "metadata")
            else datetime.now(),
            modified_at=document.metadata.modified
            if hasattr(document, "metadata")
            else datetime.now(),
            metadata={
                "title": document.metadata.title if hasattr(document, "metadata") else "",
                "created_at": (
                    document.metadata.created.isoformat()
                    if hasattr(document, "metadata")
                    else datetime.now().isoformat()
                ),
                "author": document.metadata.author if hasattr(document, "metadata") else "",
                "category": (
                    document.document_type.name
                    if hasattr(document, "document_type")
                    and document.document_type is not None
                    and hasattr(document.document_type, "name")
                    else ""
                ),
            },
        )

    def _find_candidates(self, query: SearchQuery) -> List[IndexEntry]:
        """Находит кандидатов для поиска.

        Args:
            query: Поисковый запрос

        Returns:
            Список кандидатов
        """
        if not query.text:
            # Пустой запрос - возвращаем все
            return list(self._index.values())

        # Подготавливаем regex
        flags = 0 if query.case_sensitive else re.IGNORECASE

        if query.use_regex:
            pattern = query.text
        else:
            escaped = re.escape(query.text)
            if query.whole_word:
                pattern = rf"\b{escaped}\b"
            else:
                pattern = escaped

        try:
            regex = re.compile(pattern, flags)
        except re.error:
            # Невалидный regex - ищем как текст
            regex = re.compile(re.escape(query.text), flags)

        candidates: List[IndexEntry] = []

        for entry in self._index.values():
            # Проверяем исключения
            if entry.document_id in query.exclude_ids:
                continue

            # Проверяем даты
            if query.date_from and entry.created_at < query.date_from:
                continue
            if query.date_to and entry.created_at > query.date_to:
                continue

            # Проверяем префикс индекса
            if query.index_prefix and not entry.index.startswith(query.index_prefix):
                continue

            # Ищем в указанных полях
            matched = False

            for field in query.fields:
                if field == SearchField.ALL or field == SearchField.TITLE:
                    if regex.search(entry.title):
                        matched = True
                        break

                if field == SearchField.ALL or field == SearchField.CONTENT:
                    if regex.search(entry.content):
                        matched = True
                        break

                if field == SearchField.ALL or field == SearchField.INDEX:
                    if regex.search(entry.index):
                        matched = True
                        break

                if field == SearchField.ALL or field == SearchField.AUTHOR:
                    if regex.search(entry.author):
                        matched = True
                        break

            if matched:
                candidates.append(entry)

        return candidates

    def _rank_results(
        self,
        candidates: List[IndexEntry],
        query: SearchQuery,
    ) -> List[SearchResult]:
        """Ранжирует результаты.

        Args:
            candidates: Кандидаты
            query: Запрос

        Returns:
            Ранжированные результаты
        """
        results: List[SearchResult] = []

        # Подготавливаем regex для подсветки
        flags = 0 if query.case_sensitive else re.IGNORECASE

        if query.use_regex:
            pattern = query.text
        else:
            escaped = re.escape(query.text)
            if query.whole_word:
                pattern = rf"\b{escaped}\b"
            else:
                pattern = escaped

        try:
            regex = re.compile(pattern, flags)
        except re.error:
            regex = re.compile(re.escape(query.text), flags)

        for entry in candidates:
            # Вычисляем score
            score = self._calculate_score(entry, query, regex)

            # Извлекаем фрагменты
            snippets = self._extract_snippets(entry.content, regex, 50, 3)

            # Находим позиции совпадений
            matches = self._find_matches(entry, regex)

            results.append(
                SearchResult(
                    document_id=entry.document_id,
                    title=entry.title,
                    index=entry.index,
                    score=score,
                    snippets=snippets,
                    matches=matches,
                    metadata=entry.metadata,
                )
            )

        # Сортируем
        if query.sort_by == SortOrder.RELEVANCE:
            results.sort(key=lambda r: r.score, reverse=True)
        elif query.sort_by == SortOrder.DATE_ASC:
            results.sort(
                key=lambda r: (
                    self._index.get(r.document_id, IndexEntry(document_id=r.document_id)).created_at
                    if r.document_id in self._index
                    else datetime.min
                )
            )
        elif query.sort_by == SortOrder.DATE_DESC:
            results.sort(
                key=lambda r: (
                    self._index.get(r.document_id, IndexEntry(document_id=r.document_id)).created_at
                    if r.document_id in self._index
                    else datetime.max
                ),
                reverse=True,
            )
        elif query.sort_by == SortOrder.TITLE_ASC:
            results.sort(key=lambda r: r.title.lower())
        elif query.sort_by == SortOrder.TITLE_DESC:
            results.sort(key=lambda r: r.title.lower(), reverse=True)
        elif query.sort_by == SortOrder.INDEX_ASC:
            results.sort(key=lambda r: r.index)
        elif query.sort_by == SortOrder.INDEX_DESC:
            results.sort(key=lambda r: r.index, reverse=True)

        return results

    def _calculate_score(
        self,
        entry: IndexEntry,
        query: SearchQuery,
        regex: re.Pattern[str],
    ) -> float:
        """Вычисляет оценку релевантности.

        Args:
            entry: Запись индекса
            query: Запрос
            regex: Регулярное выражение

        Returns:
            Оценка (0-1)
        """
        score = 0.0

        # Title matches are more important
        title_matches = len(regex.findall(entry.title))
        score += min(0.5, title_matches * 0.1)

        # Content matches
        content_matches = len(regex.findall(entry.content))
        score += min(0.3, content_matches * 0.01)

        # Keyword matches
        for keyword in entry.keywords:
            if regex.search(keyword):
                score += 0.1

        # Exact index match
        if query.index_prefix and entry.index.startswith(query.index_prefix):
            score += 0.2

        return min(1.0, score)

    def _extract_snippets(
        self,
        text: str,
        regex: re.Pattern[str],
        context_chars: int,
        max_snippets: int,
    ) -> List[str]:
        """Извлекает фрагменты с совпадениями.

        Args:
            text: Текст
            regex: Регулярное выражение
            context_chars: Символы контекста
            max_snippets: Максимум фрагментов

        Returns:
            Список фрагментов
        """
        snippets: List[str] = []

        for match in regex.finditer(text):
            if len(snippets) >= max_snippets:
                break

            start = max(0, match.start() - context_chars)
            end = min(len(text), match.end() + context_chars)

            snippet = text[start:end]

            # Добавляем многоточия
            if start > 0:
                snippet = "..." + snippet
            if end < len(text):
                snippet = snippet + "..."

            # Подсвечиваем совпадение
            highlighted = regex.sub(r"**\g<0>**", snippet)
            snippets.append(highlighted)

        return snippets

    def _find_matches(self, entry: IndexEntry, regex: re.Pattern[str]) -> List[Dict[str, Any]]:
        """Находит позиции совпадений.

        Args:
            entry: Запись индекса
            regex: Регулярное выражение

        Returns:
            Список совпадений
        """
        matches: List[Dict[str, Any]] = []

        for match in regex.finditer(entry.content):
            matches.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "text": match.group(0),
                    "groups": match.groups(),
                }
            )

        return matches


__all__ = [
    "IndexSearchService",
    "SearchQuery",
    "SearchResult",
    "SearchResponse",
    "SearchField",
    "SearchOperator",
    "SortOrder",
    "IndexEntry",
    "IndexStorage",
]
