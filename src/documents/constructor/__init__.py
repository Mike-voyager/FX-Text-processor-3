"""Documents constructor module for FX Text Processor 3.

Provides form construction, field building, and Excel import capabilities
for creating structured forms from templates.

Modules:
    form_constructor: FormConstructor class for creating form instances
    field_builder: FieldBuilder class using Builder pattern
    excel_importer: ExcelImporter class for importing from Excel files
    form_validator: FormValidator class with three-level validation
    form_status: Form status management and transitions
    table_schema: Table schema definitions for TABLE fields

Example:
    >>> from src.documents.constructor import FormConstructor, FieldBuilder
    >>> constructor = FormConstructor()
    >>> form = constructor.create_form("DVN", "44", "K53")
"""

from src.documents.constructor.field_builder import FieldBuilder, FieldPosition
from src.documents.constructor.form_constructor import (
    FormConstructor,
    FormInstance,
    FormTemplate,
    ValidationReport,
)
from src.documents.constructor.form_validator import (
    FormValidationError,
    FormValidator,
    ValidationConfig,
)
from src.documents.constructor.validation_result import (
    FieldValidationError,
    ValidationPolicy,
    ValidationResult,
    ValidationSeverity,
)

__all__ = [
    # Form Constructor
    "FormConstructor",
    "FormInstance",
    "FormTemplate",
    "ValidationReport",
    # Form Validator
    "FormValidator",
    "FormValidationError",
    "ValidationConfig",
    # Validation Result
    "ValidationResult",
    "FieldValidationError",
    "ValidationSeverity",
    "ValidationPolicy",
    # Field Builder
    "FieldBuilder",
    "FieldPosition",
    # Excel Importer
    "ExcelImporter",
]

# ExcelImporter imported conditionally to avoid optional dependency issues
try:
    from src.documents.constructor.excel_importer import ExcelImporter
except ImportError:
    ExcelImporter = None  # type: ignore[misc,assignment]
