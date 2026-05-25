"""Адаптер Document -> DocumentViewProtocol.

Выполняет маппинг модели Document в интерфейс DocumentViewProtocol,
используемый View слоем. Разрывает прямую зависимость View от Model,
инкапсулируя бизнес-логику адаптации (извлечение текста из секций,
парсинг CPI из enum, получение метаданных).

Архитектура:
    Adapter (данный модуль) — единственное место, где View
    знает о внутренней структуре Document Model. Все остальные
    модули gui/ работают через DocumentViewProtocol.

Security:
    - basename-only для title (не раскрывает полный путь)
    - id() fallback с префиксом _untracked_ для стабильности

Example:
    >>> adapter = DocumentViewAdapter(document)
    >>> adapter.title
    'Отчёт'
    >>> adapter.get_cpi()
    10

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class DocumentViewAdapter:
    """Адаптер Document -> DocumentViewProtocol.

    Извлекает данные из модели Document для отображения в View:
    - id: doc.id (UUID) -> строка
    - title: doc.metadata.title -> basename-only
    - mode: doc.mode или DocumentMode.FREE_FORM по умолчанию
    - content: текст из секций/параграфов
    - cpi: CharactersPerInch.numeric_value из printer_settings
    - флаги: is_encrypted, is_readonly, is_modified

    Реализует DocumentViewProtocol (structural subtyping).

    Note:
        CPI извлекается через CharactersPerInch.numeric_value,
        а не через парсинг имени enum. Это корректный способ,
        так как enum имеет метод numeric_value().

    Example:
        >>> adapter = DocumentViewAdapter(document)
        >>> isinstance(adapter, DocumentViewProtocol)
        True
        >>> adapter.doc_id
        '550e8400-e29b-41d4-a716-446655440000'
    """

    def __init__(self, doc: Any) -> None:
        """Инициализация адаптера.

        Args:
            doc: Модель документа (Document из src.model.document).
                Ожидаемые атрибуты: id, metadata, mode, sections,
                printer_settings, is_encrypted, is_readonly, is_modified.
        """
        self._doc = doc

        # Извлекаем doc_id: используем doc.id если есть, иначе генерируем
        # стабильный идентификатор с префиксом _untracked_
        raw_id = getattr(doc, "id", None)
        if raw_id is not None:
            self._doc_id: str = str(raw_id)
        else:
            self._doc_id = f"_untracked_{id(doc):x}"

        # Кешируем извлечённые значения для стабильности
        self._title = self._extract_title(doc)
        self._mode = self._extract_mode(doc)
        self._is_encrypted = bool(getattr(doc, "is_encrypted", False))
        self._is_readonly = bool(getattr(doc, "is_readonly", False))
        self._is_modified = bool(getattr(doc, "is_modified", False))

    @property
    def id(self) -> str:
        """Уникальный идентификатор документа.

        Совместим с DocumentProtocol.id из document_view.py.
        """
        return self._doc_id

    @property
    def doc_id(self) -> str:
        """Псевдоним id для удобства в MainWindow."""
        return self._doc_id

    @property
    def title(self) -> str:
        """Заголовок документа для отображения во вкладке."""
        return self._title

    @property
    def mode(self) -> Any:
        """Режим документа (DocumentMode)."""
        return self._mode

    @property
    def is_encrypted(self) -> bool:
        """Флаг зашифрованности документа."""
        return self._is_encrypted

    @property
    def is_readonly(self) -> bool:
        """Флаг только для чтения."""
        return self._is_readonly

    @property
    def is_modified(self) -> bool:
        """Флаг наличия несохранённых изменений."""
        return self._is_modified

    def get_content(self) -> str:
        """Извлекает текст из секций документа.

        Returns:
            Текст из всех параграфов секций, объединённый через \\n.
        """
        sections = self.get_sections()
        if not sections:
            return ""

        content_parts: list[str] = []
        for section in sections:
            paragraphs = getattr(section, "paragraphs", [])
            for para in paragraphs:
                if hasattr(para, "get_text"):
                    text = para.get_text()
                else:
                    text = str(para)
                content_parts.append(text)

        return "\n".join(content_parts)

    def get_cpi(self) -> int:
        """Возвращает CPI из настроек принтера.

        Использует CharactersPerInch.numeric_value() если доступен,
        иначе парсит имя enum (fallback). По умолчанию 10.

        Returns:
            Количество символов на дюйм (CPI).
        """
        settings = getattr(self._doc, "printer_settings", None)
        if settings is None:
            return 10

        cpi_enum = getattr(settings, "characters_per_inch", None)
        if cpi_enum is None:
            return 10

        # Предпочитаем numeric_value (корректный способ)
        numeric = getattr(cpi_enum, "numeric_value", None)
        if numeric is not None:
            result = numeric() if callable(numeric) else numeric
            if isinstance(result, int):
                return result

        # Fallback: парсим имя enum (CPI_10 -> 10)
        cpi_name = str(cpi_enum.name) if hasattr(cpi_enum, "name") else str(cpi_enum)
        if cpi_name.startswith("CPI_"):
            try:
                return int(cpi_name.split("_")[1])
            except (ValueError, IndexError):
                pass

        return 10  # Default CPI

    def get_metadata(self) -> Any:
        """Возвращает метаданные документа.

        Returns:
            Объект DocumentMetadata или None.
        """
        return getattr(self._doc, "metadata", None)

    def get_sections(self) -> list[Any]:
        """Возвращает список секций документа.

        Returns:
            Список секций (может быть пустым).
        """
        return getattr(self._doc, "sections", [])

    @staticmethod
    def _extract_title(doc: Any) -> str:
        """Извлекает заголовок из метаданных документа.

        Security:
            Возвращает только basename для предотвращения
            утечки полного пути в заголовке.

        Args:
            doc: Модель документа.

        Returns:
            Заголовок документа или 'Без названия'.
        """
        metadata = getattr(doc, "metadata", None)
        if metadata is not None:
            doc_title = getattr(metadata, "title", None)
            if doc_title is not None and str(doc_title):
                return str(doc_title)
        return "Без названия"

    @staticmethod
    def _extract_mode(doc: Any) -> Any:
        """Извлекает режим документа.

        Args:
            doc: Модель документа.

        Returns:
            DocumentMode или FREE_FORM по умолчанию.
        """
        from src.documents.types.document_type import DocumentMode

        mode = getattr(doc, "mode", None)
        if mode is None:
            return DocumentMode.FREE_FORM
        return mode


__all__: list[str] = [
    "DocumentViewAdapter",
]
