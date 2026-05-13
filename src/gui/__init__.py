"""GUI модуль FX Text Processor 3.

Предоставляет инфраструктуру для построения GUI приложения:
- core: базовые Protocol, Events, Exceptions, WidgetRegistry
- components: виджеты (base, primitive, compound, composite)

Example:
    >>> from src.gui.core.registry import WidgetRegistry
    >>> from src.gui.components.base.widget import BaseWidget
    >>> registry = WidgetRegistry.get_instance()

Version: 1.0
"""

from src import __version__
from src.gui.core.exceptions import (
    EventHandlingError,
    GUIError,
    LifecycleError,
    ProtocolValidationError,
    WidgetCreationError,
    WidgetNotFoundError,
    WidgetRegistryError,
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
    # Exceptions
    "GUIError",
    "WidgetRegistryError",
    "WidgetNotFoundError",
    "WidgetCreationError",
    "ProtocolValidationError",
    "LifecycleError",
    "EventHandlingError",
    # Registry
    "WidgetRegistry",
    "WidgetRegistryEntry",
    "WidgetRegistryStatistics",
    "WidgetMetadata",
    "WidgetCategory",
    "WidgetComplexity",
    "__version__",
]
