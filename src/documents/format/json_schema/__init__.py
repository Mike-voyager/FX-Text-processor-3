"""JSON Schema для валидации документов и шаблонов.

Предоставляет:
- JSON Schema файлы для документов и шаблонов
- SchemaValidator: Валидация данных по схеме
- SchemaRegistry: Реестр схем

Example:
    >>> from src.documents.format.json_schema import SchemaValidator
    >>> from pathlib import Path
    >>> validator = SchemaValidator()
    >>> result = validator.validate_document(document_dict)
"""

from __future__ import annotations

from src.documents.format.json_schema.validator import (
    SchemaRegistry,
    SchemaValidator,
    ValidationError,
)

__all__ = [
    "SchemaValidator",
    "SchemaRegistry",
    "ValidationError",
]
