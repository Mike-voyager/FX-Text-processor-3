"""Document types module - type registry, schemas, and indexing.

Provides:
- TypeRegistry: Singleton registry for document types
- DocumentType, DocumentSubtype: Document type definitions
- IndexTemplate, IndexSegmentDef: Index structure definitions
- TypeSchema, FieldDefinition: Field schema definitions
- SegmentType, FieldType: Enumerations for types and fields
"""

from src.documents.types.document_type import DocumentSubtype, DocumentType
from src.documents.types.index_formatter import (
    format_index,
    int_to_roman,
    parse_index,
    roman_to_int,
)
from src.documents.types.index_template import (
    IndexSegmentDef,
    IndexTemplate,
    SegmentType,
)
from src.documents.types.inheritance import resolve_schema
from src.documents.types.registry import TypeRegistry
from src.documents.types.type_schema import (
    FieldDefinition,
    FieldType,
    TypeSchema,
)

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
