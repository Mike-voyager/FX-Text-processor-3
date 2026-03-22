"""Documents module - document types, schemas, and construction.

This module provides:
- documents/types/: Type registry, document types, index templates, field schemas
- documents/constructor/: Form construction, Excel import, variable parsing

Architecture:
- TypeRegistry: Singleton registry for all document types
- DocumentType: Defines document type with index template and field schema
- IndexTemplate: Defines hierarchical composite index format (e.g., DVN-44-K53-IX)
- TypeSchema: Defines fields for a document type
- FormConstructor: Creates Document from DocumentType
"""

from src.documents.types.registry import TypeRegistry

__all__ = [
    "TypeRegistry",
]
