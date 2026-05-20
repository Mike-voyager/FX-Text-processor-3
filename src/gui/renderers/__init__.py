"""Рендереры документов для FX Text Processor 3.

Модуль предоставляет рендереры для отображения различных типов документов:
- FreeFormRenderer: свободное текстовое редактирование
- StructuredFormRenderer: структурированные формы

Example:
    >>> from src.gui.renderers import FreeFormRenderer, FreeFormDocument
    >>> renderer = FreeFormRenderer(widget_id="editor", command_stack=stack)
    >>> doc = FreeFormDocument(content="Hello", cpi=12)
    >>> renderer.render(doc)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

# Barcode/QR canvas renderers
from src.gui.renderers.barcode_canvas_renderer import (
    BarcodeCanvasRenderer,
    BarcodeRenderMode,
    HardwareBarcodeRenderer,
    PlaceholderBarcodeRenderer,
    SoftwareBarcodeRenderer,
    create_barcode_renderer,
)
from src.gui.renderers.factory import RendererFactory
from src.gui.renderers.form_canvas import (
    FieldPosition,
    FormCanvas,
    FormFieldWidget,
)
from src.gui.renderers.free_form_renderer import (
    FormatRange,
    FreeFormDocument,
    FreeFormRenderer,
)
from src.gui.renderers.protocols import (
    DocumentRendererProtocol,
    RendererCleanupProtocol,
    implements,
)
from src.gui.renderers.qr_canvas_renderer import (
    PlaceholderQRRenderer,
    QRCanvasRenderer,
    QRRenderMode,
    SoftwareQRRenderer,
    create_qr_renderer,
)
from src.gui.renderers.structured_form_renderer import (
    HeaderFooterConfig,
    PageData,
    StructuredFormDocument,
    StructuredFormRenderer,
)

# Module exports
__all__: list[str] = [
    # Protocols
    "DocumentRendererProtocol",
    "RendererCleanupProtocol",
    "implements",
    # Factory
    "RendererFactory",
    # Renderers and Documents
    "FreeFormRenderer",
    "FreeFormDocument",
    "StructuredFormRenderer",
    "StructuredFormDocument",
    # Supporting types
    "FormatRange",
    "FormCanvas",
    "FormFieldWidget",
    "FieldPosition",
    "PageData",
    "HeaderFooterConfig",
    # Barcode canvas renderers
    "BarcodeCanvasRenderer",
    "BarcodeRenderMode",
    "SoftwareBarcodeRenderer",
    "HardwareBarcodeRenderer",
    "PlaceholderBarcodeRenderer",
    "create_barcode_renderer",
    # QR canvas renderers
    "QRCanvasRenderer",
    "QRRenderMode",
    "SoftwareQRRenderer",
    "PlaceholderQRRenderer",
    "create_qr_renderer",
]
