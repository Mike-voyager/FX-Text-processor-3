"""Сервис поиска и замены.

Предоставляет функциональность поиска и замены текста в документах.
Поддерживает регулярные выражения, регистрозависимый поиск, замены.

Module: src/services/find_replace_service.py
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Iterator, List, Optional
from uuid import UUID

if TYPE_CHECKING:
    from src.model.document import Document
    from src.model.paragraph import Paragraph

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы поиска
# ---------------------------------------------------------------------------


class SearchDirection(Enum):
    """Направление поиска."""

    FORWARD = "forward"
    BACKWARD = "backward"


class SearchScope(Enum):
    """Область поиска."""

    DOCUMENT = "document"  # Весь документ
    SELECTION = "selection"  # Выделенный фрагмент
    SECTION = "section"  # Текущая секция


@dataclass(frozen=True)
class SearchOptions:
    """Опции поиска.

    Attrs:
        case_sensitive: Регистрозависимый поиск
        whole_word: Только целые слова
        use_regex: Использовать регулярные выражения
        wrap_around: Продолжить с начала при достижении конца
        direction: Направление поиска
        scope: Область поиска
    """

    case_sensitive: bool = False
    whole_word: bool = False
    use_regex: bool = False
    wrap_around: bool = True
    direction: SearchDirection = SearchDirection.FORWARD
    scope: SearchScope = SearchScope.DOCUMENT


@dataclass(frozen=True)
class Match:
    """Результат поиска совпадения.

    Attrs:
        document_id: ID документа
        section_index: Индекс секции
        paragraph_index: Индекс параграфа
        start_offset: Начальная позиция в тексте
        end_offset: Конечная позиция в тексте
        text: Найденный текст
        groups: Группы регулярного выражения (если use_regex)
    """

    document_id: UUID
    section_index: int
    paragraph_index: int
    start_offset: int
    end_offset: int
    text: str
    groups: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SearchResult:
    """Результат операции поиска.

    Attrs:
        success: True если найдено
        matches: Список найденных совпадений
        total_count: Общее количество совпадений
        current_index: Индекс текущего совпадения (-1 если нет)
        wrapped: True если поиск продолжился с начала/конца
        error: Сообщение об ошибке или None
    """

    success: bool
    matches: List[Match] = field(default_factory=list)
    total_count: int = 0
    current_index: int = -1
    wrapped: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class ReplaceResult:
    """Результат операции замены.

    Attrs:
        success: True если замена выполнена
        replaced_count: Количество выполненных замен
        matches_remaining: Оставшиеся совпадения
        error: Сообщение об ошибке или None
    """

    success: bool
    replaced_count: int = 0
    matches_remaining: int = 0
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# FindReplaceService
# ---------------------------------------------------------------------------


class FindReplaceService:
    """Сервис поиска и замены текста.

    Предоставляет:
    - Поиск текста с опциями (регистр, целые слова, regex)
    - Замена (одно и все)
    - Навигация по результатам
    - История поиска

    Пример:
        >>> service = FindReplaceService()
        >>> result = service.find(document, "pattern")
        >>> if result.success:
        ...     replace_result = service.replace_one(document, "replacement")
    """

    def __init__(self, max_history: int = 50) -> None:
        """Инициализирует сервис поиска.

        Args:
            max_history: Максимум записей в истории поиска
        """
        self._max_history = max_history
        self._history: List[str] = []
        self._current_matches: List[Match] = []
        self._current_index: int = -1
        self._last_pattern: Optional[str] = None
        self._last_options: Optional[SearchOptions] = None

    # ---------- Поиск ----------

    def find(
        self,
        document: "Document",
        pattern: str,
        options: Optional[SearchOptions] = None,
    ) -> SearchResult:
        """Ищет все совпадения в документе.

        Args:
            document: Документ для поиска
            pattern: Шаблон для поиска
            options: Опции поиска (optional)

        Returns:
            SearchResult с результатами поиска
        """
        if not pattern:
            return SearchResult(success=False, error="Пустой шаблон поиска")

        options = options or SearchOptions()
        self._add_to_history(pattern)

        try:
            matches = list(self._find_all(document, pattern, options))
            self._current_matches = matches
            self._current_index = 0 if matches else -1
            self._last_pattern = pattern
            self._last_options = options

            return SearchResult(
                success=len(matches) > 0,
                matches=matches,
                total_count=len(matches),
                current_index=self._current_index,
            )

        except re.error as exc:
            return SearchResult(success=False, error=f"Ошибка регулярного выражения: {exc}")

    def find_next(
        self,
        document: "Document",
        pattern: str,
        options: Optional[SearchOptions] = None,
    ) -> SearchResult:
        """Ищет следующее совпадение.

        Args:
            document: Документ для поиска
            pattern: Шаблон для поиска
            options: Опции поиска (optional)

        Returns:
            SearchResult с найденным совпадением
        """
        options = options or SearchOptions()

        # Если новый поиск, выполняем полный
        if pattern != self._last_pattern or not self._current_matches:
            result = self.find(document, pattern, options)
            return result

        # Иначе переходим к следующему
        if self._current_index < len(self._current_matches) - 1:
            self._current_index += 1
        elif options.wrap_around and self._current_matches:
            self._current_index = 0
            wrapped = True
        else:
            wrapped = False
            return SearchResult(
                success=False,
                matches=self._current_matches,
                total_count=len(self._current_matches),
                current_index=self._current_index,
            )

        return SearchResult(
            success=True,
            matches=self._current_matches,
            total_count=len(self._current_matches),
            current_index=self._current_index,
            wrapped=wrapped if "wrapped" in dir() else False,
        )

    def find_previous(
        self,
        document: "Document",
        pattern: str,
        options: Optional[SearchOptions] = None,
    ) -> SearchResult:
        """Ищет предыдущее совпадение.

        Args:
            document: Документ для поиска
            pattern: Шаблон для поиска
            options: Опции поиска (optional)

        Returns:
            SearchResult с найденным совпадением
        """
        options = options or SearchOptions()
        options = SearchOptions(
            case_sensitive=options.case_sensitive,
            whole_word=options.whole_word,
            use_regex=options.use_regex,
            wrap_around=options.wrap_around,
            direction=SearchDirection.BACKWARD,
            scope=options.scope,
        )

        return self.find_next(document, pattern, options)

    # ---------- Замена ----------

    def replace_one(
        self,
        document: "Document",
        replacement: str,
        match: Optional[Match] = None,
    ) -> ReplaceResult:
        """Заменяет одно совпадение.

        Args:
            document: Документ для замены
            replacement: Текст замены
            match: Совпадение для замены (если None, использует текущее)

        Returns:
            ReplaceResult с результатом
        """
        if not self._current_matches:
            return ReplaceResult(success=False, error="Нет найденных совпадений")

        # Используем текущее совпадение если не указано
        if match is None:
            if self._current_index < 0 or self._current_index >= len(self._current_matches):
                return ReplaceResult(success=False, error="Нет текущего совпадения")
            match = self._current_matches[self._current_index]

        try:
            # Выполняем замену
            replaced = self._replace_in_document(document, match, replacement)

            if replaced:
                # Обновляем список совпадений
                self._current_matches.pop(self._current_index)
                if self._current_index >= len(self._current_matches) and self._current_index > 0:
                    self._current_index -= 1

                return ReplaceResult(
                    success=True,
                    replaced_count=1,
                    matches_remaining=len(self._current_matches),
                )

            return ReplaceResult(success=False, error="Не удалось выполнить замену")

        except Exception as exc:
            logger.error("Ошибка замены: %s", exc)
            return ReplaceResult(success=False, error=str(exc))

    def replace_all(
        self,
        document: "Document",
        pattern: str,
        replacement: str,
        options: Optional[SearchOptions] = None,
    ) -> ReplaceResult:
        """Заменяет все совпадения.

        Args:
            document: Документ для замены
            pattern: Шаблон для поиска
            replacement: Текст замены
            options: Опции поиска (optional)

        Returns:
            ReplaceResult с результатом
        """
        if not pattern:
            return ReplaceResult(success=False, error="Пустой шаблон поиска")

        options = options or SearchOptions()

        try:
            # Сначала находим все совпадения
            result = self.find(document, pattern, options)
            if not result.success:
                return ReplaceResult(success=True, replaced_count=0)

            replaced_count = 0
            # Заменяем с конца, чтобы не сбить индексы
            for match in reversed(self._current_matches):
                if self._replace_in_document(document, match, replacement):
                    replaced_count += 1

            # Очищаем список совпадений
            self._current_matches.clear()
            self._current_index = -1

            return ReplaceResult(success=True, replaced_count=replaced_count)

        except Exception as exc:
            logger.error("Ошибка замены всех: %s", exc)
            return ReplaceResult(success=False, error=str(exc))

    # ---------- История поиска ----------

    def get_history(self, limit: int = 10) -> List[str]:
        """Возвращает историю поиска.

        Args:
            limit: Максимум записей

        Returns:
            Список шаблонов (последние сначала)
        """
        return list(reversed(self._history[-limit:]))

    def clear_history(self) -> None:
        """Очищает историю поиска."""
        self._history.clear()

    # ---------- Текущее состояние ----------

    def get_current_match(self) -> Optional[Match]:
        """Возвращает текущее совпадение."""
        if 0 <= self._current_index < len(self._current_matches):
            return self._current_matches[self._current_index]
        return None

    def get_all_matches(self) -> List[Match]:
        """Возвращает все найденные совпадения."""
        return list(self._current_matches)

    def get_match_count(self) -> int:
        """Возвращает количество найденных совпадений."""
        return len(self._current_matches)

    # ---------- Внутренние методы ----------

    def _find_all(
        self,
        document: "Document",
        pattern: str,
        options: SearchOptions,
    ) -> Iterator[Match]:
        """Ищет все совпадения в документе.

        Args:
            document: Документ для поиска
            pattern: Шаблон для поиска
            options: Опции поиска

        Yields:
            Найденные совпадения
        """
        # Компилируем регулярное выражение
        flags = 0
        if not options.case_sensitive:
            flags |= re.IGNORECASE

        if options.use_regex:
            regex = re.compile(pattern, flags)
        else:
            # Экранируем специальные символы
            escaped = re.escape(pattern)
            if options.whole_word:
                escaped = rf"\b{escaped}\b"
            regex = re.compile(escaped, flags)

        # Ищем в каждой секции и параграфе
        for section_idx, section in enumerate(document.sections):
            for para_idx, paragraph in enumerate(section.paragraphs):
                # Получаем текст параграфа
                text = self._get_paragraph_text(paragraph)

                # Ищем совпадения
                for match in regex.finditer(text):
                    yield Match(
                        document_id=document.id,
                        section_index=section_idx,
                        paragraph_index=para_idx,
                        start_offset=match.start(),
                        end_offset=match.end(),
                        text=match.group(0),
                        groups=match.groups(),
                    )

    def _get_paragraph_text(self, paragraph: "Paragraph") -> str:
        """Получает текст параграфа.

        Args:
            paragraph: Параграф

        Returns:
            Текст параграфа
        """
        if hasattr(paragraph, "get_text"):
            return paragraph.get_text()
        if hasattr(paragraph, "runs"):
            return "".join(run.text for run in paragraph.runs if hasattr(run, "text"))
        return ""

    def _replace_in_document(
        self,
        document: "Document",
        match: Match,
        replacement: str,
    ) -> bool:
        """Выполняет замену в документе.

        Args:
            document: Документ
            match: Совпадение
            replacement: Текст замены

        Returns:
            True если замена выполнена
        """
        try:
            section = document.sections[match.section_index]
            paragraph = section.paragraphs[match.paragraph_index]
        except (IndexError, AttributeError) as exc:
            logger.error(
                "Невалидные индексы для замены: section=%d, paragraph=%d (%s)",
                match.section_index,
                match.paragraph_index,
                exc,
            )
            return False

        text = self._get_paragraph_text(paragraph)

        if not (0 <= match.start_offset <= match.end_offset <= len(text)):
            logger.error(
                "Смещение совпадения вне диапазона текста: start=%d, end=%d, len=%d",
                match.start_offset,
                match.end_offset,
                len(text),
            )
            return False

        new_text = text[: match.start_offset] + replacement + text[match.end_offset :]

        # Если параграф immutable — заменяем в секции
        is_frozen = (
            hasattr(paragraph, "__dataclass_params__")
            and getattr(paragraph.__dataclass_params__, "frozen", False)
        )
        if is_frozen:
            from src.model.paragraph import Paragraph as ParagraphClass
            from src.model.run import Run

            new_paragraph = ParagraphClass(runs=[Run(text=new_text)])
            section.paragraphs[match.paragraph_index] = new_paragraph
            self._notify_view_update()
            return True

        # Mutable API через runs
        if not hasattr(paragraph, "runs"):
            if hasattr(paragraph, "set_text"):
                paragraph.set_text(new_text)  # type: ignore[attr-defined]
                self._notify_view_update()
                return True
            logger.error("Параграф не поддерживает редактирование текста")
            return False

        runs = paragraph.runs
        if not isinstance(runs, list):
            logger.error("Некорректная структура runs в параграфе")
            return False

        if not runs:
            from src.model.run import Run

            paragraph.add_run(Run(text=new_text))
            self._notify_view_update()
            return True

        # Находим run, содержащий start_offset
        current_pos = 0
        start_run_index = 0
        while (
            start_run_index < len(runs)
            and current_pos + len(runs[start_run_index].text) <= match.start_offset
        ):
            current_pos += len(runs[start_run_index].text)
            start_run_index += 1

        if start_run_index >= len(runs):
            # Замена в конце текста — дописываем к последнему run
            last_run = runs[-1]
            updated_run = last_run.copy()
            updated_run.text = last_run.text + replacement
            paragraph.runs = runs[:-1] + [updated_run]
            self._notify_view_update()
            return True

        start_run_local_start = match.start_offset - current_pos

        # Находим run, содержащий end_offset
        end_run_index = start_run_index
        while end_run_index < len(runs) and current_pos < match.end_offset:
            current_pos += len(runs[end_run_index].text)
            end_run_index += 1

        end_run_index -= 1
        if end_run_index < start_run_index:
            end_run_index = start_run_index
            end_run_local_end = start_run_local_start
        else:
            end_run_local_end = match.end_offset - (
                current_pos - len(runs[end_run_index].text)
            )

        # Собираем новые runs
        new_runs: list = list(runs[:start_run_index])

        start_run = runs[start_run_index]
        left_text = start_run.text[:start_run_local_start]

        end_run = runs[end_run_index]
        right_text = end_run.text[end_run_local_end:]

        merged_text = left_text + replacement + right_text
        if merged_text:
            merged_run = start_run.copy()
            merged_run.text = merged_text
            new_runs.append(merged_run)

        new_runs.extend(runs[end_run_index + 1 :])

        paragraph.runs = new_runs

        logger.debug(
            "Замена выполнена в документе %s, секция %d, параграф %d: '%s' -> '%s'",
            match.document_id,
            match.section_index,
            match.paragraph_index,
            match.text,
            replacement,
        )

        self._notify_view_update()
        return True

    def _notify_view_update(self) -> None:
        """Уведомляет DocumentView об изменении документа."""
        callback = getattr(self, "_update_view_callback", None)
        if callable(callback):
            try:
                callback()
            except Exception as exc:
                logger.debug("Ошибка callback обновления view: %s", exc)

    def _add_to_history(self, pattern: str) -> None:
        """Добавляет шаблон в историю.

        Args:
            pattern: Шаблон поиска
        """
        # Удаляем дубликаты
        if pattern in self._history:
            self._history.remove(pattern)

        self._history.append(pattern)

        # Ограничиваем размер
        if len(self._history) > self._max_history:
            self._history.pop(0)


__all__ = [
    "FindReplaceService",
    "SearchOptions",
    "SearchDirection",
    "SearchScope",
    "Match",
    "SearchResult",
    "ReplaceResult",
]
