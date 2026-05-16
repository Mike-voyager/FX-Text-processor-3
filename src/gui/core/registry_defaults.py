"""Регистрация стандартных виджетов в WidgetRegistry.

Модуль предоставляет `register_default_widgets()` для регистрации всех
виджетов FX Text Processor 3, реализующих WidgetProtocol, в центральном
реестре `WidgetRegistry`.

Виджеты:
    - ThemedButton (primitive/input)
    - ThemedLabel (primitive/display)
    - ThemedEntry (primitive/input)
    - ThemedCheckbox (primitive/input)
    - StatusBar (composite/display)

Example:
    >>> from src.gui.core.registry_defaults import register_default_widgets
    >>> register_default_widgets()
    >>> from src.gui.core.registry import WidgetRegistry
    >>> registry = WidgetRegistry.get_instance()
    >>> registry.is_registered("themed_button")
    True

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from src.gui.components.primitive.button import ThemedButton
from src.gui.components.primitive.checkbox import ThemedCheckbox
from src.gui.components.primitive.entry import ThemedEntry
from src.gui.components.primitive.label import ThemedLabel
from src.gui.core.registry import (
    WidgetCategory,
    WidgetComplexity,
    WidgetMetadata,
    WidgetRegistry,
)
from src.gui.views.status_bar import StatusBar

if TYPE_CHECKING:
    from src.gui.core.protocols import ControllerProtocol


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def _themed_button_factory(
    widget_id: str,
    text: str = "",
    command: Callable[[], None] = lambda: None,
    controller: "ControllerProtocol | None" = None,
) -> ThemedButton:
    """Фабрика для ThemedButton."""
    return ThemedButton(
        widget_id=widget_id,
        text=text,
        command=command,
        controller=controller,
    )


def _themed_label_factory(
    widget_id: str,
    text: str = "",
    controller: "ControllerProtocol | None" = None,
) -> ThemedLabel:
    """Фабрика для ThemedLabel."""
    return ThemedLabel(
        widget_id=widget_id,
        text=text,
        controller=controller,
    )


def _themed_entry_factory(
    widget_id: str,
    placeholder: str = "",
    controller: "ControllerProtocol | None" = None,
) -> ThemedEntry:
    """Фабрика для ThemedEntry."""
    return ThemedEntry(
        widget_id=widget_id,
        placeholder=placeholder,
        controller=controller,
    )


def _themed_checkbox_factory(
    widget_id: str,
    text: str = "",
    on_change: Callable[[bool], None] | None = None,
    controller: "ControllerProtocol | None" = None,
) -> ThemedCheckbox:
    """Фабрика для ThemedCheckbox."""
    return ThemedCheckbox(
        widget_id=widget_id,
        text=text,
        on_change=on_change,
        controller=controller,
    )


def _status_bar_factory(
    widget_id: str = "statusbar",
    controller: "ControllerProtocol | None" = None,
) -> StatusBar:
    """Фабрика для StatusBar."""
    return StatusBar(
        widget_id=widget_id,
        controller=controller,
    )


# =============================================================================
# METADATA
# =============================================================================


_THEMED_BUTTON_METADATA = WidgetMetadata(
    category=WidgetCategory.INPUT,
    complexity=WidgetComplexity.PRIMITIVE,
    version="1.0.0",
    author="FX Team",
    description="Стилизованная кнопка с поддержкой тем оформления и hover-эффектов",
    supported_events={"click", "hover"},
    requires_mfa=False,
)

_THEMED_LABEL_METADATA = WidgetMetadata(
    category=WidgetCategory.DISPLAY,
    complexity=WidgetComplexity.PRIMITIVE,
    version="1.0.0",
    author="FX Team",
    description="Стилизованная метка с поддержкой тем оформления",
    supported_events={"click"},
    requires_mfa=False,
)

_THEMED_ENTRY_METADATA = WidgetMetadata(
    category=WidgetCategory.INPUT,
    complexity=WidgetComplexity.PRIMITIVE,
    version="1.0.0",
    author="FX Team",
    description="Themeтизированное поле ввода текста с локальным состоянием",
    supported_events={"focus", "change", "blur"},
    requires_mfa=False,
)

_THEMED_CHECKBOX_METADATA = WidgetMetadata(
    category=WidgetCategory.INPUT,
    complexity=WidgetComplexity.PRIMITIVE,
    version="1.0.0",
    author="FX Team",
    description="Themeтизированный чекбокс с callback при изменении состояния",
    supported_events={"change", "click"},
    requires_mfa=False,
)

_STATUS_BAR_METADATA = WidgetMetadata(
    category=WidgetCategory.DISPLAY,
    complexity=WidgetComplexity.COMPOSITE,
    version="1.3.0",
    author="FX Team",
    description="Адаптивный статусбар с индикаторами состояния и уведомлений",
    supported_events={"click", "hover"},
    requires_mfa=False,
)


# =============================================================================
# REGISTRATION
# =============================================================================


def register_default_widgets(
    registry: WidgetRegistry | None = None,
    *,
    validate: bool = True,
) -> None:
    """Регистрирует стандартные виджеты в WidgetRegistry.

    Регистрирует все виджеты FX Text Processor 3, реализующие
    WidgetProtocol, в центральном реестре.

    Args:
        registry: Экземпляр реестра (None = WidgetRegistry.get_instance()).
        validate: Валидировать соответствие WidgetProtocol.

    Example:
        >>> register_default_widgets()
        >>> registry = WidgetRegistry.get_instance()
        >>> registry.is_registered("themed_button")
        True
    """
    if registry is None:
        registry = WidgetRegistry.get_instance()

    entries: dict[str, tuple[Callable[..., Any], WidgetMetadata]] = {
        "themed_button": (_themed_button_factory, _THEMED_BUTTON_METADATA),
        "themed_label": (_themed_label_factory, _THEMED_LABEL_METADATA),
        "themed_entry": (_themed_entry_factory, _THEMED_ENTRY_METADATA),
        "themed_checkbox": (_themed_checkbox_factory, _THEMED_CHECKBOX_METADATA),
        "status_bar": (_status_bar_factory, _STATUS_BAR_METADATA),
    }

    for widget_type, (factory, metadata) in entries.items():
        if not registry.is_registered(widget_type):
            registry.register(
                widget_type=widget_type,
                factory=factory,
                metadata=metadata,
                validate=validate,
            )


__all__: list[str] = [
    "register_default_widgets",
]
