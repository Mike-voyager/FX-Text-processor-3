"""Тесты PrefillSearchService.

Модуль содержит unit-тесты для сервиса поиска значений полей
с использованием mock IndexSearchService.

Module: tests/unit/services/test_prefill_search_service.py
"""

from __future__ import annotations

from typing import Any, Final
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.services.index_search_service import (
    SearchField,
    SearchQuery,
    SearchResponse,
    SearchResult,
)
from src.services.prefill_search_service import PrefillMatch, PrefillSearchService


LIMIT: Final[int] = 5


@pytest.fixture
def mock_index_service() -> MagicMock:
    """MagicMock для IndexSearchService."""
    return MagicMock()


@pytest.fixture
def prefill_service(mock_index_service: MagicMock) -> PrefillSearchService:
    """Экземпляр сервиса с инжектированным mock."""
    return PrefillSearchService(index_service=mock_index_service)


# ---------------------------------------------------------------------------
# Тесты search_field_values
# ---------------------------------------------------------------------------


class TestSearchFieldValues:
    """Тесты метода search_field_values."""

    def test_empty_query(self, prefill_service: PrefillSearchService) -> None:
        """Пустой запрос возвращает пустой список."""
        results = prefill_service.search_field_values("field1", "", limit=10)
        assert results == []

    def test_whitespace_query(self, prefill_service: PrefillSearchService) -> None:
        """Запрос из пробелов возвращает пустой список."""
        results = prefill_service.search_field_values("field1", "   ", limit=10)
        assert results == []

    def test_service_search_called(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Поиск делегируется IndexSearchService."""
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = True
        mock_response.results = []
        mock_index_service.search.return_value = mock_response

        prefill_service.search_field_values("field1", "test", limit=LIMIT)

        call_args = mock_index_service.search.call_args
        assert call_args is not None
        query: SearchQuery = call_args[0][0]
        assert query.text == "test"
        assert query.fields == [SearchField.ALL]
        assert query.limit == LIMIT

    def test_result_mapping(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """SearchResult корректно преобразуется в PrefillMatch."""
        doc_id = uuid4()
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = True
        mock_response.results = [
            SearchResult(
                document_id=doc_id,
                title="Title A",
                score=0.75,
                metadata={"field1": "Value A"},
            )
        ]
        mock_index_service.search.return_value = mock_response

        results = prefill_service.search_field_values("field1", "test", limit=10)

        assert len(results) == 1
        match = results[0]
        assert match.document_id == str(doc_id)
        assert match.document_name == "Title A"
        assert match.field_id == "field1"
        assert match.field_value == "Value A"
        assert match.confidence == 0.75

    def test_fallback_field_value_from_title(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Если metadata[field_id] отсутствует, используется title."""
        doc_id = uuid4()
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = True
        mock_response.results = [
            SearchResult(
                document_id=doc_id,
                title="Title B",
                score=0.5,
                metadata={},
            )
        ]
        mock_index_service.search.return_value = mock_response

        results = prefill_service.search_field_values("field1", "test")

        assert len(results) == 1
        assert results[0].field_value == "Title B"

    def test_score_bounds_zero(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Score ниже 0 обрезается до 0."""
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = True
        mock_response.results = [
            SearchResult(
                document_id=uuid4(),
                title="",
                score=-0.5,
                metadata={"field1": "Value"},
            )
        ]
        mock_index_service.search.return_value = mock_response

        results = prefill_service.search_field_values("field1", "test")
        assert results[0].confidence == 0.0

    def test_score_bounds_above_one(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Score выше 1 обрезается до 1."""
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = True
        mock_response.results = [
            SearchResult(
                document_id=uuid4(),
                title="",
                score=1.5,
                metadata={"field1": "Value"},
            )
        ]
        mock_index_service.search.return_value = mock_response

        results = prefill_service.search_field_values("field1", "test")
        assert results[0].confidence == 1.0

    def test_score_none_fallback(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Если score is None, confidence становится 0.5."""
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = True
        mock_response.results = [
            SearchResult(
                document_id=uuid4(),
                title="",
                score=0.0,  # реальный SearchResult(score=0.0) при None не получится без field default, т.к. score:float=0.0. Создадим через MagicMock
            )
        ]
        # Пересоздаём через MagicMock для симуляции отсутствия score
        result = MagicMock(spec=SearchResult)
        result.document_id = uuid4()
        result.title = None
        result.score = None
        result.metadata = {"field1": "Value"}
        mock_response.results = [result]
        mock_index_service.search.return_value = mock_response

        results = prefill_service.search_field_values("field1", "test")
        assert results[0].confidence == 0.5

    def test_limit_respected(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Не возвращается больше элементов, чем limit."""
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = True
        mock_response.results = [
            SearchResult(document_id=uuid4(), title=f"Doc {i}")
            for i in range(20)
        ]
        mock_index_service.search.return_value = mock_response

        results = prefill_service.search_field_values("field1", "test", limit=LIMIT)
        assert len(results) == LIMIT

    def test_error_handling(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Исключение от индекс-сервиса возвращает пустой список."""
        mock_index_service.search.side_effect = RuntimeError("Index failure")

        results = prefill_service.search_field_values("field1", "test")
        assert results == []

    def test_response_error_flag(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Если success=False — пустой список."""
        mock_response = MagicMock(spec=SearchResponse)
        mock_response.success = False
        mock_response.error = "Some error"
        mock_response.results = []
        mock_index_service.search.return_value = mock_response

        results = prefill_service.search_field_values("field1", "test")
        assert results == []


# ---------------------------------------------------------------------------
# Тесты suggest_field_values
# ---------------------------------------------------------------------------


class TestSuggestFieldValues:
    """Тесты метода suggest_field_values."""

    def test_empty_prefix(self, prefill_service: PrefillSearchService) -> None:
        """Пустой префикс возвращает пустой список."""
        assert prefill_service.suggest_field_values("field1", "") == []

    def test_suggest_calls_index_service(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """suggest делегирует вызов IndexSearchService.suggest."""
        mock_index_service.suggest.return_value = ["alpha", "alphabet"]

        results = prefill_service.suggest_field_values("field1", "alp", limit=2)

        mock_index_service.suggest.assert_called_once_with("alp", limit=2)
        assert len(results) == 2
        assert results[0].field_value == "alpha"
        assert results[0].confidence == 0.8

    def test_suggest_error_handling(
        self,
        prefill_service: PrefillSearchService,
        mock_index_service: MagicMock,
    ) -> None:
        """Исключение от suggest возвращает пустой список."""
        mock_index_service.suggest.side_effect = Exception("fail")

        assert prefill_service.suggest_field_values("field1", "x") == []


# ---------------------------------------------------------------------------
# Тесты dataclass
# ---------------------------------------------------------------------------


class TestPrefillMatch:
    """Тесты модели PrefillMatch."""

    def test_creation(self) -> None:
        """Создание экземпляра."""
        match = PrefillMatch(
            document_id="1", document_name="Doc", field_id="f", field_value="val", confidence=0.9
        )
        assert match.document_id == "1"
        assert match.confidence == 0.9

    def test_confidence_bounds(self) -> None:
        """Значение confidence может быть в пределах 0..1."""
        match = PrefillMatch(
            document_id="2", document_name="Doc", field_id="f", field_value="v", confidence=1.0
        )
        assert match.confidence == 1.0


__all__ = [
    "TestSearchFieldValues",
    "TestSuggestFieldValues",
    "TestPrefillMatch",
]
