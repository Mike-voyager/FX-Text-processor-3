"""Built-in document types.

Provides pre-registered document types:
- DOC: Base document
- INV: Invoice (Счёт)
- DVN: Verbal note (Вербальная нота)
"""

# Import to trigger registration and get constants
from src.documents.types.builtin.base import DOC
from src.documents.types.builtin.invoice import INV
from src.documents.types.builtin.verbal_note import DVN
from src.documents.types.document_type import DocumentType

# Re-export for convenience
__all__ = ["DocumentType", "DOC", "INV", "DVN"]
