"""Document types module - type registry, schemas, and indexing.

Provides:
- TypeRegistry: Singleton registry for document types
- DocumentType, DocumentSubtype: Document type definitions
- IndexTemplate, IndexSegmentDef: Index structure definitions
- TypeSchema, FieldDefinition: Field schema definitions
- SegmentType, FieldType: Enumerations for types and fields
"""

from src.documents.types.registry import TypeRegistry
from src.documents.types.document_type import DocumentType, DocumentSubtype
from src.documents.types.index_template import (
    IndexTemplate,
    IndexSegmentDef,
    SegmentType,
)
from src.documents.types.type_schema import (
    TypeSchema,
    FieldDefinition,
    FieldType,
)
from src.documents.types.index_formatter import (
    format_index,
    parse_index,
    int_to_roman,
    roman_to_int,
)
from src.documents.types.inheritance import resolve_schema

__all__ = [
    "TypeRegistry",
    "DocumentType",
    "DocumentSubtype",
    "IndexTemplate",
    "IndexSegmentDef",
    "SegmentType",
    "TypeSchema",
    "FieldDefinition",
    "FieldType",
    "format_index",
    "parse_index",
    "int_to_roman",
    "roman_to_int",
    "resolve_schema",
]