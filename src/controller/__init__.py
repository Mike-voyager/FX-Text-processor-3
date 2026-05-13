"""Контроллеры FX Text Processor 3.

Модуль содержит контроллеры для координации между View и Service слоями.
Каждый контроллер отвечает за определённую область функциональности.

Example:
    >>> from src.controller import MainController
    >>> from src.controller.auth_controller import AuthController
    >>>
    >>> controller = MainController(auth_service, document_service)
    >>> controller.start()

Architecture:
    ```
    View (GUI) → Controller → Service Layer
         ↓           ↓
    Callbacks    Protocols
    ```

Note:
    Контроллеры используют Dependency Injection через Protocol-интерфейсы
    для развязки от конкретных реализаций сервисов.
"""

from __future__ import annotations

# AuthController
from src.controller.auth_controller import (
    AuthContext,
    AuthController,
    AuthErrorCode,
    AuthResult,
    AuthState,
    FactorType,
    WorkflowRole,
)

# DocumentController
from src.controller.document_controller import (
    DocumentController,
    DocumentControllerError,
    DocumentMode,
    DocumentNotFoundError,
    DocumentTabInfo,
    OpenError,
    SaveError,
)

# FormController
from src.controller.form_controller import (
    BlankIssuanceError,
    FieldType,
    FormController,
    FormControllerError,
    FormControllerResult,
    FormInstance,
    FormNotFoundError,
    FormSigningError,
    FormStatus,
    FormTemplate,
    FormValidationError,
    InvalidTemplateError,
    Severity,
    TemplateNotFoundError,
    ValidationReport,
    ValidationResult,
)

# MainController
from src.controller.main_controller import (
    ApplicationState,
    MainController,
)

# PrintController
from src.controller.print_controller import (
    BlankNotReadyError,
    CharactersPerInch,
    ExportError,
    PageRange,
    PaperType,
    PrintController,
    PrintControllerError,
    PrinterInfo,
    PrinterNotAvailableError,
    PrintJob,
    PrintPreviewData,
    PrintQuality,
    PrintSettings,
    RenderError,
    create_print_controller,
)
from src.controller.print_controller import (
    DocumentNotFoundError as PrintDocumentNotFoundError,
)
from src.controller.workflow_controller import (
    DocumentNotFoundError as WorkflowDocumentNotFoundError,
)

# WorkflowController
from src.controller.workflow_controller import (
    FieldComment,
    InvalidStateError,
    MFARequiredError,
    WorkflowController,
    WorkflowEvent,
    WorkflowTransitionError,
)
from src.controller.workflow_controller import (
    FormStatus as WorkflowFormStatus,
)
from src.controller.workflow_controller import (
    PermissionError as WorkflowPermissionError,
)
from src.controller.workflow_controller import (
    Severity as WorkflowSeverity,
)
from src.controller.workflow_controller import (
    WorkflowRole as WorkflowRoleEnum,
)

__version__ = "1.0.0"
__author__ = "FX Text Processor Team"

__all__ = [
    # MainController
    "MainController",
    "ApplicationState",
    # AuthController
    "AuthController",
    "WorkflowRole",
    "AuthState",
    "FactorType",
    "AuthContext",
    "AuthResult",
    "AuthErrorCode",
    # DocumentController
    "DocumentController",
    "DocumentMode",
    "DocumentTabInfo",
    "DocumentControllerError",
    "DocumentNotFoundError",
    "SaveError",
    "OpenError",
    # PrintController
    "PrintController",
    "PrintSettings",
    "PrintPreviewData",
    "PrinterInfo",
    "PrintJob",
    "PageRange",
    "PaperType",
    "PrintQuality",
    "CharactersPerInch",
    "PrintControllerError",
    "PrintDocumentNotFoundError",
    "PrinterNotAvailableError",
    "BlankNotReadyError",
    "ExportError",
    "RenderError",
    "create_print_controller",
    # FormController
    "FormController",
    "FormTemplate",
    "FormInstance",
    "FormStatus",
    "Severity",
    "FieldType",
    "ValidationResult",
    "ValidationReport",
    "FormControllerResult",
    "FormControllerError",
    "TemplateNotFoundError",
    "InvalidTemplateError",
    "FormNotFoundError",
    "FormValidationError",
    "FormSigningError",
    "BlankIssuanceError",
    "FormEventType",
    # WorkflowController
    "WorkflowController",
    "WorkflowRoleEnum",
    "WorkflowFormStatus",
    "WorkflowSeverity",
    "FieldComment",
    "WorkflowEvent",
    "WorkflowTransitionError",
    "MFARequiredError",
    "WorkflowDocumentNotFoundError",
    "InvalidStateError",
    "WorkflowPermissionError",
]
