"""Модуль рендеринга документов в ESC/P байты.

Предоставляет renderers для преобразования моделей документов
в бинарные данные для матричного принтера Epson FX-890.

Example:
    >>> from src.documents.printing import DocumentRenderer
    >>> from src.model.document import Document
    >>> doc = Document(title="Test")
    >>> renderer = DocumentRenderer()
    >>> escp_data = renderer.render(doc)
"""

from __future__ import annotations

from src.documents.printing.document_renderer import DocumentRenderer, RenderSettings
from src.documents.printing.form_renderer import FormField, FormInstance, FormRenderer
from src.documents.printing.text_renderer import TextRenderer

__all__ = [
    "DocumentRenderer",
    "RenderSettings",
    "TextRenderer",
    "FormRenderer",
    "FormInstance",
    "FormField",
]
