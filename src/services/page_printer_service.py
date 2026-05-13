"""Сервис постраничной печати.

Управляет процессом постраничной печати многостраничных документов.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.model.document import Document


@dataclass(frozen=True)
class PageProgress:
    """Прогресс постраничной печати.

    Attributes:
        current_page: Текущая страница (1-indexed)
        total_pages: Всего страниц
        current_copy: Текущая копия (1-indexed)
        total_copies: Всего копий
        is_complete: Завершена ли печать
    """

    current_page: int
    total_pages: int
    current_copy: int
    total_copies: int
    is_complete: bool = False

    def __str__(self) -> str:
        """Строковое представление прогресса."""
        if self.is_complete:
            return "Печать завершена"
        return (
            f"Страница {self.current_page} из {self.total_pages} │ "
            f"Копия {self.current_copy} из {self.total_copies}"
        )


class PagePrinter:
    """Сервис постраничной печати.

    Управляет процессом печати с обычной колляцией.
    Порядок печати: копия 1 (стр 1,2,3...), копия 2 (стр 1,2,3...), etc.

    Example:
        >>> printer = PagePrinter(document, copies=3)
        >>> progress = printer.get_progress()
        >>> print(progress)
        "Страница 1 из 10 │ Копия 1 из 3"
        >>> data = printer.render_current_page()
        >>> printer.advance()  # Переход к следующей странице
    """

    def __init__(
        self,
        document: "Document",
        copies: int = 1,
    ) -> None:
        """Инициализирует постраничную печать.

        Args:
            document: Документ для печати
            copies: Количество копий
        """
        self._document = document
        self._copies = max(1, copies)
        self._logger = logging.getLogger(__name__)

        # Состояние печати (обычная колляция)
        self._current_copy: int = 1
        self._current_page: int = 1
        self._is_complete: bool = False

        # Вычисляем количество страниц
        self._total_pages = self._calculate_page_count()

    def _calculate_page_count(self) -> int:
        """Вычисляет количество страниц в документе.

        Returns:
            Количество страниц
        """
        # Простая оценка: количество строк / строк на страницу
        lines_per_page = self._document.page_settings.lines_per_page
        total_lines = self._document.get_line_count()

        if lines_per_page <= 0:
            lines_per_page = 66  # Default

        # Округляем вверх
        return max(1, (total_lines + lines_per_page - 1) // lines_per_page)

    def get_progress(self) -> PageProgress:
        """Возвращает текущий прогресс печати.

        Returns:
            PageProgress с текущей страницей и копией
        """
        return PageProgress(
            current_page=self._current_page,
            total_pages=self._total_pages,
            current_copy=self._current_copy,
            total_copies=self._copies,
            is_complete=self._is_complete,
        )

    def advance(self) -> PageProgress:
        """Переходит к следующей странице или копии.

        Порядок колляции: копия 1 (все стр), копия 2 (все стр), etc.

        Returns:
            Новый PageProgress
        """
        if self._is_complete:
            return self.get_progress()

        # Переходим к следующей странице
        self._current_page += 1

        if self._current_page > self._total_pages:
            # Все страницы текущей копии напечатаны
            self._current_copy += 1
            if self._current_copy > self._copies:
                self._is_complete = True
            else:
                # Начинаем новую копию
                self._current_page = 1

        return self.get_progress()

    def skip_page(self) -> PageProgress:
        """Пропускает текущую страницу во всех оставшихся копиях.

        При обычной колляции просто переходит к следующей странице.

        Returns:
            Новый PageProgress
        """
        return self.advance()

    def reset(self) -> None:
        """Сбрасывает состояние печати в начало."""
        self._current_page = 1
        self._current_copy = 1
        self._is_complete = False

    def start_new_copy(self) -> None:
        """Начинает новый экземпляр печати (после завершения)."""
        self.reset()

    def render_current_page(self) -> bytes:
        """Рендерит текущую страницу в ESC/P байты.

        Returns:
            ESC/P команды для текущей страницы
        """
        from src.documents.printing.document_renderer import DocumentRenderer, RenderSettings
        from src.model.section import Section

        # Параметры страницы
        lines_per_page = self._document.page_settings.lines_per_page
        if lines_per_page <= 0:
            lines_per_page = 66

        chars_per_line = self._document.page_settings.characters_per_line
        if chars_per_line <= 0:
            chars_per_line = 80

        # Собираем все параграфы из всех секций
        all_paragraphs = []
        for section in self._document.sections:
            all_paragraphs.extend(section.paragraphs)

        if not all_paragraphs:
            self._logger.warning(
                "Нет параграфов для рендеринга страницы %d", self._current_page
            )
            return b""

        # Распределяем параграфы по страницам
        page_paragraphs = []
        current_page = 1
        current_lines = 0
        for para in all_paragraphs:
            para_text = para.get_text()
            para_lines = max(1, (len(para_text) + chars_per_line - 1) // chars_per_line)
            if current_lines + para_lines > lines_per_page and current_lines > 0:
                current_page += 1
                current_lines = 0
            if current_page == self._current_page:
                page_paragraphs.append(para)
            elif current_page > self._current_page:
                break
            current_lines += para_lines

        if not page_paragraphs:
            self._logger.warning(
                "Страница %d не содержит параграфов после распределения",
                self._current_page,
            )
            return b""

        # Создаём временный документ с параграфами текущей страницы
        temp_doc = type(self._document)(
            metadata=self._document.metadata,
            page_settings=self._document.page_settings,
            printer_settings=self._document.printer_settings,
        )
        section = Section()
        for para in page_paragraphs:
            section.add_paragraph(para)
        temp_doc.sections.append(section)

        # Рендерим через DocumentRenderer
        renderer = DocumentRenderer()
        settings = RenderSettings(
            paper_type=self._document.printer_settings.paper_type,
            cpi=self._document.printer_settings.characters_per_inch,
            codepage=self._document.printer_settings.codepage,
            quality=self._document.printer_settings.print_quality,
        )

        return renderer.render(temp_doc, settings)

    def is_complete(self) -> bool:
        """Проверяет, завершена ли печать.

        Returns:
            True если печать завершена
        """
        return self._is_complete

    def get_document_name(self) -> str:
        """Возвращает имя документа.

        Returns:
            Имя документа или "Без названия"
        """
        return self._document.metadata.title or "Без названия"


__all__ = ["PagePrinter", "PageProgress"]
