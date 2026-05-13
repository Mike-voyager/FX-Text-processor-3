"""Модуль типов документов и индексации для FX Text Processor 3.

Предоставляет иерархическую систему типов документов с составными индексами
в формате DVN-44-K53-IX, реестр типов (TypeRegistry) и шаблоны полей.

Example:
    >>> from src.documents.types import TypeRegistry, DocumentType, Subtype, Series
    >>> registry = TypeRegistry.get_instance()
    >>> doc_type = registry.get_type("DVN")
    >>> print(doc_type.name)
    Verbal Note
    >>> index = registry.generate_index("DVN", "44", "K53")
    >>> print(index)
    DVN-44-K53-I

Architecture:
    - DocumentType: Корневой тип документа (DVN, INV)
    - Subtype: Подтип (44, 45)
    - Series: Серия (K53, K54)
    - TypeRegistry: Singleton реестр всех типов (thread-safe)
    - IndexTemplate: Шаблон полей для типа документа

Thread Safety:
    TypeRegistry thread-safe благодаря RLock.
"""

from __future__ import annotations

from src.documents.types.document_type import (
    DocumentType,
    Series,
    Subtype,
)
from src.documents.types.index_template import (
    FieldType,
    IndexTemplate,
    TemplateField,
    ValidationRule,
)
from src.documents.types.type_registry import (
    IndexComponents,
    RegistryError,
    TypeRegistry,
    TypeRegistryError,
    UnknownTypeError,
)
from src.documents.types.type_schema import (
    FieldDefinition,
    OverflowBehavior,
    TypeSchema,
)
from src.documents.types.type_schema import (
    FieldType as TypeSchemaFieldType,
)

__version__ = "1.0.0"
__author__ = "Mike Voyager"

__all__ = [
    # Document Type Hierarchy
    "DocumentType",
    "Subtype",
    "Series",
    # Index Template
    "IndexTemplate",
    "TemplateField",
    "FieldType",
    "ValidationRule",
    # Type Schema
    "TypeSchema",
    "FieldDefinition",
    "TypeSchemaFieldType",  # Alias for FieldType from type_schema
    "OverflowBehavior",
    # Registry
    "TypeRegistry",
    "IndexComponents",
    # Exceptions
    "RegistryError",
    "TypeRegistryError",
    "UnknownTypeError",
]
