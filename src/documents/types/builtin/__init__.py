"""Built-in document types.

Provides pre-registered document types:
- DOC: Base document
- INV: Invoice (Счёт)
- DVN: Verbal note (Вербальная нота)
"""

from src.documents.types.document_type import DocumentType

# Re-export for convenience
__all__ = ["DOC", "INV", "DVN"]

# Import to trigger registration
from src.documents.types.builtin import base, invoice, verbal_note  # noqa: F401, E402