"""Сервис статистики документа.

Вычисляет статистику документа: слова, символы, страницы, параграфы.

Module: src/services/document_stats_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List
from uuid import UUID

if TYPE_CHECKING:
    from src.model.document import Document
    from src.model.paragraph import Paragraph
    from src.model.section import Section

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Модели статистики
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CharacterStats:
    """Статистика символов.

    Attrs:
        total: Общее количество символов
        with_spaces: С символами пробелов
        without_spaces: Без пробелов
        letters: Только буквы
        digits: Только цифры
        punctuation: Знаки препинания
        whitespace: Пробельные символы
    """

    total: int = 0
    with_spaces: int = 0
    without_spaces: int = 0
    letters: int = 0
    digits: int = 0
    punctuation: int = 0
    whitespace: int = 0


@dataclass(frozen=True)
class WordStats:
    """Статистика слов.

    Attrs:
        total: Общее количество слов
        unique: Количество уникальных слов
        average_length: Средняя длина слова
        longest_word: Самое длинное слово
        shortest_word: Самое короткое слово
    """

    total: int = 0
    unique: int = 0
    average_length: float = 0.0
    longest_word: str = ""
    shortest_word: str = ""


@dataclass(frozen=True)
class ParagraphStats:
    """Статистика параграфов.

    Attrs:
        total: Общее количество параграфов
        empty: Количество пустых параграфов
        average_length: Средняя длина параграфа (в символах)
        longest_paragraph: Индекс самого длинного параграфа
    """

    total: int = 0
    empty: int = 0
    average_length: float = 0.0
    longest_paragraph: int = -1


@dataclass(frozen=True)
class LineStats:
    """Статистика строк.

    Attrs:
        total: Общее количество строк
        average_length: Средняя длина строки
        longest_line: Индекс самой длинной строки
    """

    total: int = 0
    average_length: float = 0.0
    longest_line: int = -1


@dataclass(frozen=True)
class PageStats:
    """Статистика страниц.

    Attrs:
        estimated_pages: Оценочное количество страниц
        lines_per_page: Строк на страницу
        characters_per_line: Символов в строке
        printable_area: Печатная область (в символах)
    """

    estimated_pages: int = 0
    lines_per_page: int = 66
    characters_per_line: int = 80
    printable_area: int = 5280  # 66 * 80


@dataclass(frozen=True)
class DocumentStats:
    """Полная статистика документа.

    Attrs:
        document_id: ID документа
        title: Заголовок документа
        characters: Статистика символов
        words: Статистика слов
        paragraphs: Статистика параграфов
        lines: Статистика строк
        pages: Статистика страниц
        sections: Количество секций
        reading_time_minutes: Оценочное время чтения (минуты)
        speaking_time_minutes: Оценочное время говорения (минуты)
    """

    document_id: UUID
    title: str = ""
    characters: CharacterStats = field(default_factory=CharacterStats)
    words: WordStats = field(default_factory=WordStats)
    paragraphs: ParagraphStats = field(default_factory=ParagraphStats)
    lines: LineStats = field(default_factory=LineStats)
    pages: PageStats = field(default_factory=PageStats)
    sections: int = 0
    reading_time_minutes: float = 0.0
    speaking_time_minutes: float = 0.0


# ---------------------------------------------------------------------------
# DocumentStatsService
# ---------------------------------------------------------------------------


class DocumentStatsService:
    """Сервис вычисления статистики документа.

    Предоставляет:
    - Подсчёт символов, слов, строк
    - Оценку количества страниц
    - Статистику по секциям и параграфам
    - Оценку времени чтения

    Пример:
        >>> service = DocumentStatsService()
        >>> stats = service.calculate(document)
        >>> print(f"Слов: {stats.words.total}")
    """

    # Константы для расчётов
    WORDS_PER_MINUTE_READING = 200  # Скорость чтения (слов/мин)
    WORDS_PER_MINUTE_SPEAKING = 150  # Скорость говорения (слов/мин)
    DEFAULT_LINES_PER_PAGE = 66
    DEFAULT_CHARS_PER_LINE = 80

    def __init__(
        self,
        lines_per_page: int = DEFAULT_LINES_PER_PAGE,
        chars_per_line: int = DEFAULT_CHARS_PER_LINE,
    ) -> None:
        """Инициализирует сервис статистики.

        Args:
            lines_per_page: Строк на страницу
            chars_per_line: Символов в строке
        """
        self._lines_per_page = lines_per_page
        self._chars_per_line = chars_per_line

    # ---------- Основной метод ----------

    def calculate(self, document: "Document") -> DocumentStats:
        """Вычисляет полную статистику документа.

        Args:
            document: Документ для анализа

        Returns:
            DocumentStats с полной статистикой
        """
        # Получаем текст документа
        text = self._get_document_text(document)

        # Вычисляем статистику
        char_stats = self._calculate_characters(text)
        word_stats = self._calculate_words(text)
        para_stats = self._calculate_paragraphs(document)
        line_stats = self._calculate_lines(text)
        page_stats = self._calculate_pages(char_stats, line_stats)

        # Время чтения/говорения
        reading_time = word_stats.total / self.WORDS_PER_MINUTE_READING
        speaking_time = word_stats.total / self.WORDS_PER_MINUTE_SPEAKING

        return DocumentStats(
            document_id=document.id,
            title=document.metadata.title,
            characters=char_stats,
            words=word_stats,
            paragraphs=para_stats,
            lines=line_stats,
            pages=page_stats,
            sections=len(document.sections),
            reading_time_minutes=reading_time,
            speaking_time_minutes=speaking_time,
        )

    # ---------- Быстрые методы ----------

    def get_word_count(self, document: "Document") -> int:
        """Возвращает количество слов в документе.

        Args:
            document: Документ

        Returns:
            Количество слов
        """
        text = self._get_document_text(document)
        return len(text.split())

    def get_character_count(self, document: "Document", include_spaces: bool = True) -> int:
        """Возвращает количество символов в документе.

        Args:
            document: Документ
            include_spaces: Включать пробелы

        Returns:
            Количество символов
        """
        text = self._get_document_text(document)
        if include_spaces:
            return len(text)
        return len(text.replace(" ", "").replace("\n", "").replace("\t", ""))

    def get_line_count(self, document: "Document") -> int:
        """Возвращает количество строк в документе.

        Args:
            document: Документ

        Returns:
            Количество строк
        """
        text = self._get_document_text(document)
        return text.count("\n") + 1 if text else 0

    def get_paragraph_count(self, document: "Document") -> int:
        """Возвращает количество параграфов в документе.

        Args:
            document: Документ

        Returns:
            Количество параграфов
        """
        count = 0
        for section in document.sections:
            count += len(section.paragraphs)
        return count

    def get_estimated_pages(self, document: "Document") -> int:
        """Возвращает оценочное количество страниц.

        Args:
            document: Документ

        Returns:
            Количество страниц
        """
        char_stats = self._calculate_characters(self._get_document_text(document))
        line_stats = self._calculate_lines(self._get_document_text(document))
        page_stats = self._calculate_pages(char_stats, line_stats)
        return page_stats.estimated_pages

    # ---------- Детальная статистика по секциям ----------

    def get_section_stats(self, document: "Document") -> List[DocumentStats]:
        """Возвращает статистику по каждой секции.

        Args:
            document: Документ

        Returns:
            Список статистики секций
        """
        stats_list: List[DocumentStats] = []

        for section in document.sections:
            text = self._get_section_text(section)

            char_stats = self._calculate_characters(text)
            word_stats = self._calculate_words(text)
            line_stats = self._calculate_lines(text)
            page_stats = self._calculate_pages(char_stats, line_stats)

            reading_time = word_stats.total / self.WORDS_PER_MINUTE_READING

            stats_list.append(
                DocumentStats(
                    document_id=document.id,
                    title=f"Section {section.name}" if hasattr(section, "name") else "",
                    characters=char_stats,
                    words=word_stats,
                    paragraphs=ParagraphStats(
                        total=len(section.paragraphs),
                        empty=sum(1 for p in section.paragraphs if self._is_paragraph_empty(p)),
                    ),
                    lines=line_stats,
                    pages=page_stats,
                    sections=1,
                    reading_time_minutes=reading_time,
                    speaking_time_minutes=word_stats.total / self.WORDS_PER_MINUTE_SPEAKING,
                )
            )

        return stats_list

    # ---------- Частотный анализ ----------

    def get_word_frequency(
        self,
        document: "Document",
        limit: int = 50,
        min_length: int = 1,
    ) -> Dict[str, int]:
        """Возвращает частоту слов в документе.

        Args:
            document: Документ
            limit: Максимум слов в результате
            min_length: Минимальная длина слова

        Returns:
            Словарь {слово: частота}
        """
        import re
        from collections import Counter

        text = self._get_document_text(document)
        words = re.findall(r"\b[а-яёa-z]+\b", text.lower(), re.IGNORECASE)

        # Фильтруем по длине
        words = [w for w in words if len(w) >= min_length]

        # Подсчитываем частоту
        counter = Counter(words)
        return dict(counter.most_common(limit))

    # ---------- Внутренние методы ----------

    def _get_document_text(self, document: "Document") -> str:
        """Получает полный текст документа.

        Args:
            document: Документ

        Returns:
            Текст документа
        """
        return document.get_text_content()

    def _get_section_text(self, section: "Section") -> str:
        """Получает текст секции.

        Args:
            section: Секция

        Returns:
            Текст секции
        """
        texts = []
        for paragraph in section.paragraphs:
            if hasattr(paragraph, "get_text"):
                texts.append(paragraph.get_text())
            elif hasattr(paragraph, "runs"):
                texts.append("".join(r.text for r in paragraph.runs if hasattr(r, "text")))
        return "\n".join(texts)

    def _is_paragraph_empty(self, paragraph: "Paragraph") -> bool:
        """Проверяет, пуст ли параграф.

        Args:
            paragraph: Параграф

        Returns:
            True если пустой
        """
        if hasattr(paragraph, "get_text"):
            return not paragraph.get_text().strip()
        if hasattr(paragraph, "runs"):
            return not any(r.text.strip() for r in paragraph.runs if hasattr(r, "text"))
        return True

    def _calculate_characters(self, text: str) -> CharacterStats:
        """Вычисляет статистику символов.

        Args:
            text: Текст

        Returns:
            CharacterStats
        """
        import re

        total = len(text)
        with_spaces = total
        without_spaces = len(text.replace(" ", "").replace("\n", "").replace("\t", ""))

        letters = len(re.findall(r"[а-яёa-z]", text, re.IGNORECASE))
        digits = len(re.findall(r"\d", text))
        punctuation = len(re.findall(r"[!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]", text))
        whitespace = len(re.findall(r"\s", text))

        return CharacterStats(
            total=total,
            with_spaces=with_spaces,
            without_spaces=without_spaces,
            letters=letters,
            digits=digits,
            punctuation=punctuation,
            whitespace=whitespace,
        )

    def _calculate_words(self, text: str) -> WordStats:
        """Вычисляет статистику слов.

        Args:
            text: Текст

        Returns:
            WordStats
        """
        import re

        words = re.findall(r"\b[а-яёa-z]+\b", text.lower(), re.IGNORECASE)

        if not words:
            return WordStats()

        total = len(words)
        unique = len(set(words))
        avg_length = sum(len(w) for w in words) / total if total > 0 else 0

        longest = max(words, key=len)
        shortest = min(words, key=len)

        return WordStats(
            total=total,
            unique=unique,
            average_length=round(avg_length, 2),
            longest_word=longest,
            shortest_word=shortest,
        )

    def _calculate_paragraphs(self, document: "Document") -> ParagraphStats:
        """Вычисляет статистику параграфов.

        Args:
            document: Документ

        Returns:
            ParagraphStats
        """
        total = 0
        empty = 0
        lengths: List[int] = []
        longest_idx = -1
        longest_len = 0

        for section in document.sections:
            for idx, paragraph in enumerate(section.paragraphs):
                total += 1

                # Длина параграфа
                if hasattr(paragraph, "get_text"):
                    text = paragraph.get_text()
                elif hasattr(paragraph, "runs"):
                    text = "".join(r.text for r in paragraph.runs if hasattr(r, "text"))
                else:
                    text = ""

                length = len(text)
                lengths.append(length)

                if not text.strip():
                    empty += 1

                if length > longest_len:
                    longest_len = length
                    longest_idx = idx

        avg_length = sum(lengths) / len(lengths) if lengths else 0

        return ParagraphStats(
            total=total,
            empty=empty,
            average_length=round(avg_length, 2),
            longest_paragraph=longest_idx,
        )

    def _calculate_lines(self, text: str) -> LineStats:
        """Вычисляет статистику строк.

        Args:
            text: Текст

        Returns:
            LineStats
        """
        lines = text.split("\n") if text else []

        if not lines:
            return LineStats()

        total = len(lines)
        lengths = [len(line) for line in lines]
        avg_length = sum(lengths) / total if total > 0 else 0
        longest_idx = lengths.index(max(lengths)) if lengths else -1

        return LineStats(
            total=total,
            average_length=round(avg_length, 2),
            longest_line=longest_idx,
        )

    def _calculate_pages(
        self,
        char_stats: CharacterStats,
        line_stats: LineStats,
    ) -> PageStats:
        """Оценивает количество страниц.

        Args:
            char_stats: Статистика символов
            line_stats: Статистика строк

        Returns:
            PageStats
        """
        # Оценка по строкам
        pages_by_lines = line_stats.total / self._lines_per_page if line_stats.total > 0 else 1

        # Оценка по символам
        chars_per_page = self._lines_per_page * self._chars_per_line
        pages_by_chars = (
            char_stats.without_spaces / chars_per_page if char_stats.without_spaces > 0 else 1
        )

        # Берём максимум
        estimated = max(1, int(max(pages_by_lines, pages_by_chars)))

        return PageStats(
            estimated_pages=estimated,
            lines_per_page=self._lines_per_page,
            characters_per_line=self._chars_per_line,
            printable_area=chars_per_page,
        )


__all__ = [
    "DocumentStatsService",
    "DocumentStats",
    "CharacterStats",
    "WordStats",
    "ParagraphStats",
    "LineStats",
    "PageStats",
]
