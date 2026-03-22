"""Модуль рендеринга документов в ESC/P байты.

Предоставляет renderers для преобразования моделей документов
в бинарные данные для матричного принтера Epson FX-890.

Example:
    >>> from src.documents.printing import DocumentRenderer
    >>> from src.model.document import Document
    >>> doc = Document(title="Test")
    >>> renderer = DocumentRenderer(codepage=CodePage.PC866)
    >>> escp_data = renderer.render(doc)
    >>> with open("output.escp", "wb") as f:
    ...     f.write(escp_data)
"""

from __future__ import annotations

from src.documents.printing.barcode_renderer import BarcodeRenderer
from src.documents.printing.document_renderer import DocumentRenderer
from src.documents.printing.paragraph_renderer import ParagraphRenderer
from src.documents.printing.run_renderer import RunRenderer
from src.documents.printing.table_renderer import TableRenderer

__all__ = [
    "DocumentRenderer",
    "ParagraphRenderer",
    "TableRenderer",
    "RunRenderer",
    "BarcodeRenderer",
]
