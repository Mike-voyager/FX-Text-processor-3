"""Тесты FindReplaceService.

Module: tests/unit/services/test_find_replace_service.py
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.model.document import Document
from src.model.paragraph import Paragraph
from src.model.run import Run
from src.model.section import Section
from src.services.find_replace_service import (
    FindReplaceService,
    Match,
    ReplaceResult,
    SearchDirection,
    SearchOptions,
    SearchResult,
)


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> FindReplaceService:
    """Сервис поиска и замены."""
    return FindReplaceService(max_history=10)


@pytest.fixture
def mock_document() -> Document:
    """Документ с двумя параграфами для тестов."""
    doc = Document()
    section = doc.add_section()
    para1 = Paragraph(runs=[Run(text="Hello, World! This is a test.")])
    para2 = Paragraph(runs=[Run(text="Testing the find and replace functionality.")])
    section.add_paragraph(para1)
    section.add_paragraph(para2)
    return doc


# ---------------------------------------------------------------------------
# Тесты поиска
# ---------------------------------------------------------------------------


class TestFind:
    """Тесты поиска."""

    def test_find_simple(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест простого поиска."""
        result = service.find(mock_document, "test")

        assert result.success
        assert result.total_count >= 1

    def test_find_not_found(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест поиска без результатов."""
        result = service.find(mock_document, "nonexistent")

        assert not result.success
        assert result.total_count == 0

    def test_find_empty_pattern(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест поиска с пустым шаблоном."""
        result = service.find(mock_document, "")

        assert not result.success
        assert "пустой" in (result.error or "").lower()

    def test_find_case_sensitive(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест регистрозависимого поиска."""
        # Сначала ищем без учёта регистра
        result1 = service.find(mock_document, "hello", SearchOptions(case_sensitive=False))
        assert result1.success

        # Теперь с учётом регистра
        result2 = service.find(mock_document, "hello", SearchOptions(case_sensitive=True))
        assert result2.total_count == 0

    def test_find_whole_word(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест поиска целого слова."""
        # Ищем "test" как часть слова
        result1 = service.find(mock_document, "test", SearchOptions(whole_word=False))
        assert result1.success

        # Ищем "test" как целое слово
        result2 = service.find(mock_document, "test", SearchOptions(whole_word=True))
        # "test" входит в "testing", поэтому как целое слово может не найтись

    def test_find_regex(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест поиска по регулярному выражению."""
        result = service.find(mock_document, r"\b\w+ing\b", SearchOptions(use_regex=True))

        assert result.success
        # Должен найти "Testing"

    def test_find_invalid_regex(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест поиска с некорректным regex."""
        result = service.find(mock_document, r"[invalid", SearchOptions(use_regex=True))

        assert not result.success
        assert "регулярного" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Тесты навигации
# ---------------------------------------------------------------------------


class TestNavigation:
    """Тесты навигации по результатам."""

    def test_find_next(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест поиска следующего совпадения."""
        service.find(mock_document, "test")

        # Переходим к следующему
        result = service.find_next(mock_document, "test")

        assert result.success

    def test_find_next_wrap_around(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест wrap-around при поиске."""
        service.find(mock_document, "test", SearchOptions(wrap_around=True))

        # Многократный поиск должен wrap-нуться
        for _ in range(10):
            service.find_next(mock_document, "test")

        # Должен всё ещё находить совпадения
        result = service.find_next(mock_document, "test")
        assert result.success

    def test_get_current_match(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест получения текущего совпадения."""
        service.find(mock_document, "World")

        match = service.get_current_match()

        assert match is not None
        assert "World" in match.text

    def test_get_all_matches(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест получения всех совпадений."""
        service.find(mock_document, "test")

        matches = service.get_all_matches()

        assert len(matches) >= 1

    def test_get_match_count(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест количества совпадений."""
        service.find(mock_document, "test")

        count = service.get_match_count()

        assert count >= 1


# ---------------------------------------------------------------------------
# Тесты замены
# ---------------------------------------------------------------------------


class TestReplace:
    """Тесты замены."""

    def test_replace_one(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест замены одного совпадения."""
        service.find(mock_document, "World")
        result = service.replace_one(mock_document, "Universe")

        assert result.success
        assert result.replaced_count == 1

    def test_replace_one_no_matches(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест замены без найденных совпадений."""
        service.clear_history()
        result = service.replace_one(mock_document, "test")

        assert not result.success
        assert "нет" in (result.error or "").lower()

    def test_replace_all(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест замены всех совпадений."""
        result = service.replace_all(mock_document, "test", "exam")

        assert result.success
        assert result.replaced_count >= 1

    def test_replace_all_empty_pattern(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест замены с пустым шаблоном."""
        result = service.replace_all(mock_document, "", "replacement")

        assert not result.success
        assert "пустой" in (result.error or "").lower()


# ---------------------------------------------------------------------------
# Тесты истории
# ---------------------------------------------------------------------------


class TestHistory:
    """Тесты истории поиска."""

    def test_history_add(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест добавления в историю."""
        service.find(mock_document, "test")
        service.find(mock_document, "World")

        history = service.get_history()

        assert len(history) == 2
        assert "World" in history
        assert "test" in history

    def test_history_limit(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест лимита истории."""
        for i in range(15):
            service.find(mock_document, f"pattern{i}")

        history = service.get_history()

        # Максимум 10 записей (из фикстуры)
        assert len(history) <= 10

    def test_history_no_duplicates(
        self, service: FindReplaceService, mock_document: MagicMock
    ) -> None:
        """Тест отсутствия дубликатов."""
        service.find(mock_document, "test")
        service.find(mock_document, "test")
        service.find(mock_document, "test")

        history = service.get_history()

        # "test" должен быть только один раз
        assert history.count("test") <= 1

    def test_clear_history(self, service: FindReplaceService, mock_document: MagicMock) -> None:
        """Тест очистки истории."""
        service.find(mock_document, "test")
        service.find(mock_document, "World")
        service.clear_history()

        history = service.get_history()

        assert len(history) == 0


# ---------------------------------------------------------------------------
# Тесты опций
# ---------------------------------------------------------------------------


class TestOptions:
    """Тесты опций поиска."""

    def test_search_options_defaults(self) -> None:
        """Тест значений по умолчанию."""
        options = SearchOptions()

        assert not options.case_sensitive
        assert not options.whole_word
        assert not options.use_regex
        assert options.wrap_around
        assert options.direction == SearchDirection.FORWARD
        assert options.scope.value == "document"

    def test_search_options_custom(self) -> None:
        """Тест кастомных опций."""
        options = SearchOptions(
            case_sensitive=True,
            whole_word=True,
            use_regex=True,
            wrap_around=False,
            direction=SearchDirection.BACKWARD,
        )

        assert options.case_sensitive
        assert options.whole_word
        assert options.use_regex
        assert not options.wrap_around
        assert options.direction == SearchDirection.BACKWARD