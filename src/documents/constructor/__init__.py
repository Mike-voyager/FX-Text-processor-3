"""Document constructor module.

Provides:
- FormConstructor: Creates Document from DocumentType
- FieldBuilder: Builds fields for visual editor
- FieldPalette: Available field types for editor
- VariableParser: Variable substitution in templates
- ExcelImporter: Import data from Excel
- StyleManager: Style inheritance for elements
"""

from src.documents.constructor.form_constructor import FormConstructor
from src.documents.constructor.field_builder import FieldBuilder
from src.documents.constructor.field_palette import FieldPalette
from src.documents.constructor.variable_parser import VariableParser
from src.documents.constructor.excel_import import ExcelImporter, ExcelFieldMapping
from src.documents.constructor.style_manager import StyleManager

__all__ = [
    "FormConstructor",
    "FieldBuilder",
    "FieldPalette",
    "VariableParser",
    "ExcelImporter",
    "ExcelFieldMapping",
    "StyleManager",
]