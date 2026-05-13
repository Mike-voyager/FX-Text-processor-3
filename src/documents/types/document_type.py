"""Модель иерархических типов документов.

Определяет структуру типов документов: DocumentType → DocumentSubtype.
Все классы immutable (frozen=True) для безопасности в многопоточной среде.

Example:
    >>> from src.documents.types.document_type import (
    ...     DocumentType, DocumentSubtype, DocumentMode
    ... )
    >>> from src.documents.types.type_schema import TypeSchema
    >>> doc_type = DocumentType(
    ...     code="DVN",
    ...     name="Verbal Note",
    ...     parent_code=None,
    ...     document_mode=DocumentMode.FREE_FORM,
    ...     index_template=None,
    ...     field_schema=TypeSchema(fields=()),
    ... )
    >>> print(doc_type.code)
    DVN
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Literal, Optional, Tuple

from src.documents.types.index_template import IndexTemplate
from src.documents.types.type_schema import FieldDefinition, TypeSchema


class DocumentMode(str, Enum):
    """Режимы документа.

    Attributes:
        FREE_FORM: Свободная форма (любые поля).
        STRUCTURED_FORM: Структурированная форма (по шаблону).
    """

    FREE_FORM = "free_form"
    STRUCTURED_FORM = "structured_form"


@dataclass(frozen=True)
class DocumentSubtype:
    """Подтип документа.

    Attributes:
        code: Код подтипа.
        name: Название подтипа.
        extra_fields: Дополнительные поля подтипа.

    Example:
        >>> subtype = DocumentSubtype(
        ...     code="01",
        ...     name="Обычный",
        ... )
        >>> print(subtype.code)
        01
    """

    code: str
    name: str
    extra_fields: Tuple[FieldDefinition, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        if not self.code or not self.code.strip():
            raise ValueError("code cannot be empty")
        if not self.name or not self.name.strip():
            raise ValueError("name cannot be empty")


@dataclass(frozen=True)
class DocumentType:
    """Тип документа.

    Attributes:
        code: Код типа документа.
        name: Название типа документа.
        parent_code: Код родительского типа (None для корневых).
        document_mode: Режим документа (free_form или structured_form).
        index_template: Шаблон индекса документа.
        field_schema: Схема полей документа.
        subtypes: Подтипы документа.
        metadata: Метаданные типа (кортеж пар ключ-значение).

    Example:
        >>> from src.documents.types.type_schema import TypeSchema
        >>> doc_type = DocumentType(
        ...     code="DVN",
        ...     name="Verbal Note",
        ...     parent_code=None,
        ...     document_mode=DocumentMode.FREE_FORM,
        ...     index_template=None,
        ...     field_schema=TypeSchema(fields=()),
        ... )
        >>> print(doc_type.code)
        DVN
    """

    code: str
    name: str
    parent_code: Optional[str]
    document_mode: DocumentMode
    index_template: Optional[IndexTemplate]
    field_schema: TypeSchema
    subtypes: Tuple[DocumentSubtype, ...] = field(default_factory=tuple)
    metadata: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        if not self.code or not self.code.strip():
            raise ValueError("code cannot be empty")
        if not self.name or not self.name.strip():
            raise ValueError("name cannot be empty")

    @property
    def is_root(self) -> bool:
        """Проверяет, является ли тип корневым.

        Returns:
            True если parent_code is None.
        """
        return self.parent_code is None

    @property
    def has_subtypes(self) -> bool:
        """Проверяет, есть ли у типа подтипы.

        Returns:
            True если есть подтипы.
        """
        return len(self.subtypes) > 0

    def get_subtype(self, code: str) -> Optional[DocumentSubtype]:
        """Получить подтип по коду.

        Args:
            code: Код подтипа.

        Returns:
            DocumentSubtype или None если не найден.
        """
        for subtype in self.subtypes:
            if subtype.code == code:
                return subtype
        return None

    def get_metadata(self, key: str) -> Optional[Any]:
        """Получить значение метаданных по ключу.

        Args:
            key: Ключ метаданных.

        Returns:
            Значение метаданных или None если не найдено.
        """
        for k, v in self.metadata:
            if k == key:
                return v
        return None

    def with_field_schema(self, field_schema: TypeSchema) -> DocumentType:
        """Создать новый экземпляр с новой схемой полей.

        Args:
            field_schema: Новая схема полей.

        Returns:
            Новый экземпляр DocumentType.
        """
        return DocumentType(
            code=self.code,
            name=self.name,
            parent_code=self.parent_code,
            document_mode=self.document_mode,
            index_template=self.index_template,
            field_schema=field_schema,
            subtypes=self.subtypes,
            metadata=self.metadata,
        )

    def with_index_template(self, index_template: Optional[IndexTemplate]) -> DocumentType:
        """Создать новый экземпляр с новым шаблоном индекса.

        Args:
            index_template: Новый шаблон индекса.

        Returns:
            Новый экземпляр DocumentType.
        """
        return DocumentType(
            code=self.code,
            name=self.name,
            parent_code=self.parent_code,
            document_mode=self.document_mode,
            index_template=index_template,
            field_schema=self.field_schema,
            subtypes=self.subtypes,
            metadata=self.metadata,
        )


# Legacy classes for backward compatibility


@dataclass(frozen=True)
class Series:
    """Серия документа (устаревший класс - используется только для обратной совместимости).

    Attributes:
        code: Код серии.
        name: Название серии.
        custom_allowed: Разрешены ли пользовательские сегменты.
        sequence_format: Формат нумерации.
    """

    code: str
    name: str
    custom_allowed: bool = False
    sequence_format: Literal["ROMAN", "ARABIC"] = "ROMAN"

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        if not self.code or not self.code.strip():
            raise ValueError("Код серии не может быть пустым")
        if not self.name or not self.name.strip():
            raise ValueError("Название серии не может быть пустым")


@dataclass(frozen=True)
class Subtype:
    """Подтип документа (устаревший класс - используется только для обратной совместимости).

    Attributes:
        code: Код подтипа.
        name: Название подтипа.
        series: Список серий.
    """

    code: str
    name: str
    series: List[Series] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        if not self.code or not self.code.strip():
            raise ValueError("Код подтипа не может быть пустым")
        if not self.name or not self.name.strip():
            raise ValueError("Название подтипа не может быть пустым")

    def get_series(self, series_code: str) -> Optional[Series]:
        """Получить серию по коду.

        Args:
            series_code: Код серии.

        Returns:
            Series или None если не найдена.
        """
        code_upper = series_code.upper()
        for s in self.series:
            if s.code == code_upper:
                return s
        return None
