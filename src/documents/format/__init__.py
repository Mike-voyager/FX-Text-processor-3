"""Модуль форматов сериализации документов.

Предоставляет:
- DocumentFormat: Сериализация/десериализация .fxsd и .fxsd.enc
- TemplateFormat: Сериализация/десериализация .fxstpl
- FormatMigration: Миграция между версиями формата
- JSON Schema: Валидация документов и шаблонов

Example:
    >>> from src.documents.format import DocumentFormat
    >>> from src.model.document import Document
    >>> doc = Document(title="Test")
    >>> fmt = DocumentFormat()
    >>> fmt.save(doc, Path("test.fxsd"))
    >>> loaded = fmt.load(Path("test.fxsd"))
"""

from src.documents.format.document_format import (
    DocumentFormat,
    DocumentFormatHeader,
)
from src.documents.format.document_format import (
    FormatError as DocumentFormatError,
)
from src.documents.format.migration import (
    DocumentMigrator,
    FormatMigration,
    MigrationChain,
    MigrationResult,
    MigrationStep,
    TemplateMigrator,
)
from src.documents.format.template_format import (
    FormatError as TemplateFormatError,
)
from src.documents.format.template_format import (
    TemplateFormat,
    TemplateFormatHeader,
)

__all__ = [
    "DocumentFormat",
    "DocumentFormatHeader",
    "DocumentFormatError",
    "DocumentMigrator",
    "FormatMigration",
    "MigrationChain",
    "MigrationResult",
    "MigrationStep",
    "TemplateFormat",
    "TemplateFormatHeader",
    "TemplateFormatError",
    "TemplateMigrator",
]
