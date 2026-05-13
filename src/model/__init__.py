"""Модуль моделей данных FX Text Processor 3.

Предоставляет модели для:
- Document: основная модель документа
- Paragraph: параграфы с LineStyle
- Section: секции документа
- Run: текстовые фрагменты с форматированием
- Bookmark: закладки в документе
- Enums: перечисления для ESC/P
"""

from src.model.bookmark import Bookmark, BookmarkManager, DocumentPosition
from src.model.document import (
    Document,
    DocumentMetadata,
    PageSettings,
    PrinterSettings,
    create_blank_document,
    create_form_document,
    create_letter_document,
)
from src.model.enums import (
    Alignment,
    BarcodeType,
    CharactersPerInch,
    CharSize,
    CodePage,
    Color,
    DitheringAlgorithm,
    FileExtension,
    FileType,
    FontFamily,
    GraphicsMode,
    ImagePosition,
    LineSpacing,
    ListType,
    MarginUnits,
    Matrix2DCodeType,
    Orientation,
    PageSize,
    PaperSource,
    PaperType,
    PrintDirection,
    PrintQuality,
    TabAlignment,
    TableStyle,
    TextStyle,
)
from src.model.paragraph import EmbeddedObject, Paragraph
from src.model.run import EmbeddedObject as RunEmbeddedObject
from src.model.run import Run
from src.model.section import Section
from src.model.tab_stop import TabStop, TabStopType
from src.model.tab_stop_manager import TabStopManager

__all__ = [
    # Document
    "Document",
    "DocumentMetadata",
    "PageSettings",
    "PrinterSettings",
    "create_blank_document",
    "create_letter_document",
    "create_form_document",
    # Bookmark
    "Bookmark",
    "BookmarkManager",
    "DocumentPosition",
    # Paragraph
    "Paragraph",
    "EmbeddedObject",
    # Section
    "Section",
    # Run
    "Run",
    "RunEmbeddedObject",
    # Enums
    "Alignment",
    "BarcodeType",
    "CharactersPerInch",
    "CharSize",
    "CodePage",
    "Color",
    "DitheringAlgorithm",
    "FileExtension",
    "FileType",
    "FontFamily",
    "GraphicsMode",
    "ImagePosition",
    "LineSpacing",
    "ListType",
    "MarginUnits",
    "Matrix2DCodeType",
    "Orientation",
    "PageSize",
    "PaperSource",
    "PaperType",
    "PrintDirection",
    "PrintQuality",
    "TabAlignment",
    "TableStyle",
    "TextStyle",
    # TabStop
    "TabStop",
    "TabStopType",
    "TabStopManager",
]
