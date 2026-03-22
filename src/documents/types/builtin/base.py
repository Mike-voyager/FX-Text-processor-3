"""Base document type - DOC.

This is the root document type that other types can inherit from.
FREE_FORM documents have no predefined field schema - they are built freely.
"""

from src.documents.types.document_type import DocumentMode, DocumentType
from src.documents.types.type_schema import TypeSchema

# Базовый документ - FREE_FORM (свободное редактирование текста)
# Нет предопределённых полей, нет индекса - документ строится свободно
DOC = DocumentType(
    code="DOC",
    name="Базовый документ",
    parent_code=None,
    document_mode=DocumentMode.FREE_FORM,
    index_template=None,
    field_schema=TypeSchema(
        fields=(),
        version="1.0",
    ),
)
