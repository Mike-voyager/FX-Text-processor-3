"""Core GUI infrastructure.

Provides:
- protocols: WidgetProtocol, SmartWidgetProtocol, ControllerProtocol
- events: Event types (ValueChanged, FocusLost, etc.)
- exceptions: GUIError hierarchy
- error_handler: GUIErrorHandler for centralized error handling
- registry: WidgetRegistry (Singleton, thread-safe)

Example:
    >>> from src.gui.core.registry import WidgetRegistry
    >>> from src.gui.core.events import ValueChangedEvent
    >>> from src.gui.core.error_handler import GUIErrorHandler

Version: 1.0
"""

# Bindings
from src.gui.core.bindings import (
    Binding,
    ObservableValue,
    TwoWayBinding,
)
from src.gui.core.error_handler import (
    ErrorContext,
    GUIErrorHandler,
)
from src.gui.core.events import (
    ActionEvent,
    BaseEvent,
    FocusGainedEvent,
    FocusLostEvent,
    MountEvent,
    UnmountEvent,
    ValueChangedEvent,
)
from src.gui.core.exceptions import (
    AuditError,
    AuthenticationError,
    AuthorizationError,
    EventHandlingError,
    GUIError,
    LifecycleError,
    MFAError,
    ProtocolValidationError,
    RendererError,
    SecurityError,
    WidgetCreationError,
    WidgetNotFoundError,
    WidgetRegistryError,
)
from src.gui.core.protocols import (
    ControllerProtocol,
    DocumentControllerProtocol,
    EventProtocol,
    SmartWidgetProtocol,
    WidgetProtocol,
)
from src.gui.core.registry import (
    WidgetCategory,
    WidgetComplexity,
    WidgetMetadata,
    WidgetRegistry,
    WidgetRegistryEntry,
    WidgetRegistryStatistics,
)

__all__ = [
    # Bindings
    "ObservableValue",
    "Binding",
    "TwoWayBinding",
    # Protocols
    "EventProtocol",
    "WidgetProtocol",
    "SmartWidgetProtocol",
    "ControllerProtocol",
    "DocumentControllerProtocol",
    # Events
    "BaseEvent",
    "ValueChangedEvent",
    "FocusLostEvent",
    "FocusGainedEvent",
    "ActionEvent",
    "MountEvent",
    "UnmountEvent",
    # Exceptions
    "GUIError",
    "WidgetRegistryError",
    "WidgetNotFoundError",
    "WidgetCreationError",
    "ProtocolValidationError",
    "LifecycleError",
    "EventHandlingError",
    # Security Exceptions
    "SecurityError",
    "MFAError",
    "AuthenticationError",
    "AuthorizationError",
    # Audit Exceptions
    "AuditError",
    # Renderer Exceptions
    "RendererError",
    # Error Handler
    "GUIErrorHandler",
    "ErrorContext",
    # Registry
    "WidgetRegistry",
    "WidgetRegistryEntry",
    "WidgetRegistryStatistics",
    "WidgetMetadata",
    "WidgetCategory",
    "WidgetComplexity",
]
