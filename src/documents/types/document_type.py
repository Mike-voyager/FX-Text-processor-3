"""Document type definitions.

Provides:
- DocumentType: Main document type definition
- DocumentSubtype: Subtype definition for document types
"""

from dataclasses import dataclass, field
from typing import Any

from src.documents.types.index_template import IndexTemplate
from src.documents.types.type_schema import TypeSchema


@dataclass(frozen=True)
class DocumentSubtype:
    """Подтип документа.

    Подтип наследует схему полей от родительского типа
    и может добавлять собственные поля.

    Attributes:
        code: Код подтипа (например, "44", "01").
        name: Человеко-читаемое название подтипа.
        extra_fields: Дополнительные поля, специфичные для подтипа.
    """

    code: str
    name: str
    extra_fields: tuple[Any, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DocumentType:
    """Тип документа.

    Определяет структуру документа определённого типа,
    включая схему индекса и схему полей.

    Attributes:
        code: Уникальный код типа (например, "DVN", "INV", "DOC").
        name: Человеко-читаемое название типа на русском.
        parent_code: Код родительского типа (None для корневых).
        index_template: Шаблон генерации индекса.
        field_schema: Схема полей документа.
        subtypes: Кортеж подтипов данного типа.
        metadata: Дополнительные метаданные.
    """

    code: str
    name: str
    parent_code: str | None
    index_template: IndexTemplate
    field_schema: TypeSchema
    subtypes: tuple[DocumentSubtype, ...] = field(default_factory=tuple)
    metadata: tuple[tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.code:
            raise ValueError("DocumentType code cannot be empty")
        if not self.name:
            raise ValueError("DocumentType name cannot be empty")

    @property
    def is_root(self) -> bool:
        """Является ли тип корневым (нет родителя)."""
        return self.parent_code is None

    @property
    def has_subtypes(self) -> bool:
        """Есть ли у типа подтипы."""
        return len(self.subtypes) > 0

    def get_subtype(self, code: str) -> DocumentSubtype | None:
        """Возвращает подтип по коду."""
        for subtype in self.subtypes:
            if subtype.code == code:
                return subtype
        return None

    def get_metadata(self, key: str) -> Any:
        """Возвращает значение метаданных по ключу."""
        for k, v in self.metadata:
            if k == key:
                return v
        return None

    def with_field_schema(self, schema: TypeSchema) -> "DocumentType":
        """Создаёт копию с новой схемой полей.

        Это immutable dataclass, поэтому для изменения
        нужно создавать новый экземпляр.

        Args:
            schema: Новая схема полей.

        Returns:
            Новый экземпляр DocumentType с обновлённой схемой.
        """
        # Создаём новый экземпляр с изменённой схемой
        # Используем object.__setattr__ для frozen dataclass
        new_instance = DocumentType(
            code=self.code,
            name=self.name,
            parent_code=self.parent_code,
            index_template=self.index_template,
            field_schema=schema,
            subtypes=self.subtypes,
            metadata=self.metadata,
        )
        return new_instance

    def with_index_template(
        self, template: IndexTemplate
    ) -> "DocumentType":
        """Создаёт копию с новым шаблоном индекса."""
        new_instance = DocumentType(
            code=self.code,
            name=self.name,
            parent_code=self.parent_code,
            index_template=template,
            field_schema=self.field_schema,
            subtypes=self.subtypes,
            metadata=self.metadata,
        )
        return new_instance