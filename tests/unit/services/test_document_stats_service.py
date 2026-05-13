"""Тесты DocumentStatsService.

Module: tests/unit/services/test_document_stats_service.py
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.services.document_stats_service import (
    CharacterStats,
    DocumentStats,
    DocumentStatsService,
    LineStats,
    PageStats,
    ParagraphStats,
    WordStats,
)


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> DocumentStatsService:
    """Сервис статистики."""
    return DocumentStatsService(lines_per_page=66, chars_per_line=80)


@pytest.fixture
def mock_document() -> MagicMock:
    """Мок документа."""
    doc = MagicMock()
    doc.id = uuid4()
    doc.metadata = MagicMock()
    doc.metadata.title = "Test Document"

    # Создаём секции с параграфами
    section1 = MagicMock()
    para1 = MagicMock()
    para1.get_text.return_value = "Hello, World! This is a test document."
    para2 = MagicMock()
    para2.get_text.return_value = "It has multiple paragraphs and lines."

    section2 = MagicMock()
    para3 = MagicMock()
    para3.get_text.return_value = "Third paragraph in second section."

    section1.paragraphs = [para1, para2]
    section2.paragraphs = [para3]
    doc.sections = [section1, section2]

    # Текст для get_text_content
    doc.get_text_content.return_value = (
        "Hello, World! This is a test document.\n"
        "It has multiple paragraphs and lines.\n"
        "Third paragraph in second section."
    )

    return doc


# ---------------------------------------------------------------------------
# Тесты основной статистики
# ---------------------------------------------------------------------------


class TestCalculate:
    """Тесты вычисления статистики."""

    def test_calculate_basic(self, service: DocumentStatsService, mock_document: MagicMock) -> None:
        """Тест базового вычисления."""
        stats = service.calculate(mock_document)

        assert stats.document_id == mock_document.id
        assert stats.title == "Test Document"
        assert stats.sections == 2
        assert stats.characters.total > 0
        assert stats.words.total > 0

    def test_get_word_count(self, service: DocumentStatsService, mock_document: MagicMock) -> None:
        """Тест подсчёта слов."""
        count = service.get_word_count(mock_document)

        assert count > 0

    def test_get_character_count_with_spaces(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест подсчёта символов с пробелами."""
        count = service.get_character_count(mock_document, include_spaces=True)

        assert count > 0

    def test_get_character_count_without_spaces(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест подсчёта символов без пробелов."""
        count_with = service.get_character_count(mock_document, include_spaces=True)
        count_without = service.get_character_count(mock_document, include_spaces=False)

        assert count_without < count_with

    def test_get_line_count(self, service: DocumentStatsService, mock_document: MagicMock) -> None:
        """Тест подсчёта строк."""
        count = service.get_line_count(mock_document)

        assert count >= 1

    def test_get_paragraph_count(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест подсчёта параграфов."""
        count = service.get_paragraph_count(mock_document)

        assert count == 3  # 2 в первой секции + 1 во второй

    def test_get_estimated_pages(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест оценки страниц."""
        pages = service.get_estimated_pages(mock_document)

        assert pages >= 1


# ---------------------------------------------------------------------------
# Тесты статистики символов
# ---------------------------------------------------------------------------


class TestCharacterStats:
    """Тесты статистики символов."""

    def test_characters_total(self, service: DocumentStatsService) -> None:
        """Тест общего количества символов."""
        char_stats = service._calculate_characters("Hello World!")

        assert char_stats.total == 12
        assert char_stats.with_spaces == 12
        assert char_stats.without_spaces == 11  # Без пробела

    def test_characters_letters(self, service: DocumentStatsService) -> None:
        """Тест подсчёта букв."""
        char_stats = service._calculate_characters("Hello123")

        assert char_stats.letters == 5  # Hello
        assert char_stats.digits == 3  # 123

    def test_characters_punctuation(self, service: DocumentStatsService) -> None:
        """Тест подсчёта знаков препинания."""
        char_stats = service._calculate_characters("Hello, World!")

        assert char_stats.punctuation == 2  # , !


# ---------------------------------------------------------------------------
# Тесты статистики слов
# ---------------------------------------------------------------------------


class TestWordStats:
    """Тесты статистики слов."""

    def test_words_total(self, service: DocumentStatsService) -> None:
        """Тест подсчёта слов."""
        word_stats = service._calculate_words("Hello World Test")

        assert word_stats.total == 3

    def test_words_unique(self, service: DocumentStatsService) -> None:
        """Тест уникальных слов."""
        word_stats = service._calculate_words("test test test hello")

        assert word_stats.total == 4
        assert word_stats.unique == 2  # test, hello

    def test_words_longest_shortest(self, service: DocumentStatsService) -> None:
        """Тест самого длинного и короткого слова."""
        word_stats = service._calculate_words("a bb ccc dddd")

        assert word_stats.longest_word == "dddd"
        assert word_stats.shortest_word == "a"

    def test_words_average_length(self, service: DocumentStatsService) -> None:
        """Тест средней длины слова."""
        word_stats = service._calculate_words("abc defg hi")

        # abc(3) + defg(4) + hi(2) = 9 / 3 = 3.0
        assert word_stats.average_length == 3.0


# ---------------------------------------------------------------------------
# Тесты статистики параграфов
# ---------------------------------------------------------------------------


class TestParagraphStats:
    """Тесты статистики параграфов."""

    def test_empty_document(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест пустого документа."""
        mock_document.sections = []
        mock_document.get_text_content.return_value = ""

        para_stats = service._calculate_paragraphs(mock_document)

        assert para_stats.total == 0
        assert para_stats.empty == 0


# ---------------------------------------------------------------------------
# Тесты статистики строк
# ---------------------------------------------------------------------------


class TestLineStats:
    """Тесты статистики строк."""

    def test_lines_total(self, service: DocumentStatsService) -> None:
        """Тест подсчёта строк."""
        line_stats = service._calculate_lines("Line 1\nLine 2\nLine 3")

        assert line_stats.total == 3

    def test_lines_average_length(self, service: DocumentStatsService) -> None:
        """Тест средней длины строки."""
        line_stats = service._calculate_lines("abc\ndefgh\nij")

        # abc(3) + defgh(5) + ij(2) = 10 / 3 = 3.33
        assert abs(line_stats.average_length - 3.33) < 0.1


# ---------------------------------------------------------------------------
# Тесты оценки страниц
# ---------------------------------------------------------------------------


class TestPageStats:
    """Тесты оценки страниц."""

    def test_pages_minimum(self, service: DocumentStatsService) -> None:
        """Тест минимума страниц."""
        char_stats = CharacterStats(total=100, without_spaces=80)
        line_stats = LineStats(total=5)

        page_stats = service._calculate_pages(char_stats, line_stats)

        assert page_stats.estimated_pages >= 1

    def test_pages_calculation(self, service: DocumentStatsService) -> None:
        """Тест расчёта страниц."""
        # Создаём статистику для нескольких страниц
        char_stats = CharacterStats(total=10000, without_spaces=8000)
        line_stats = LineStats(total=200)

        page_stats = service._calculate_pages(char_stats, line_stats)

        # При 66 строках на страницу, 200 строк ~= 3-4 страницы
        assert page_stats.estimated_pages >= 3


# ---------------------------------------------------------------------------
# Тесты секций
# ---------------------------------------------------------------------------


class TestSectionStats:
    """Тесты статистики по секциям."""

    def test_get_section_stats(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест получения статистики по секциям."""
        section_stats = service.get_section_stats(mock_document)

        assert len(section_stats) == 2
        assert section_stats[0].sections == 1
        assert section_stats[1].sections == 1


# ---------------------------------------------------------------------------
# Тесты частотного анализа
# ---------------------------------------------------------------------------


class TestWordFrequency:
    """Тесты частотного анализа."""

    def test_word_frequency(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест частоты слов."""
        freq = service.get_word_frequency(mock_document, limit=10)

        assert isinstance(freq, dict)
        assert len(freq) <= 10

    def test_word_frequency_min_length(
        self, service: DocumentStatsService, mock_document: MagicMock
    ) -> None:
        """Тест минимальной длины слова."""
        freq = service.get_word_frequency(mock_document, min_length=5)

        # Все слова должны быть длиной >= 5
        for word in freq.keys():
            assert len(word) >= 5


# ---------------------------------------------------------------------------
# Тесты времени чтения
# ---------------------------------------------------------------------------


class TestReadingTime:
    """Тесты времени чтения."""

    def test_reading_time(self, service: DocumentStatsService, mock_document: MagicMock) -> None:
        """Тест оценки времени чтения."""
        stats = service.calculate(mock_document)

        # Время чтения должно быть положительным
        assert stats.reading_time_minutes >= 0
        # Время говорения обычно больше времени чтения
        assert stats.speaking_time_minutes >= stats.reading_time_minutes


# ---------------------------------------------------------------------------
# Тесты пустого документа
# ---------------------------------------------------------------------------


class TestEmptyDocument:
    """Тесты пустого документа."""

    def test_empty_document(self, service: DocumentStatsService) -> None:
        """Тест пустого документа."""
        doc = MagicMock()
        doc.id = uuid4()
        doc.metadata = MagicMock()
        doc.metadata.title = ""
        doc.sections = []
        doc.get_text_content.return_value = ""

        stats = service.calculate(doc)

        assert stats.characters.total == 0
        assert stats.words.total == 0
        assert stats.paragraphs.total == 0
        assert stats.lines.total == 0
        assert stats.pages.estimated_pages == 1  # Минимум 1 страница