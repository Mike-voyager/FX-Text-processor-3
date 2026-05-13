"""StructuredForm Mode Extension для FX Text Processor 3.

Предоставляет GUI компоненты для режима редактирования структурированных форм:
- StructuredFormModeRenderer: адаптер для рендеринга форм с Grid Canvas интеграцией
- StructuredFormToolbar: панель инструментов с field palette, workflow и role индикаторами

Example:
    >>> from src.gui.modes.structured_form import (
    ...     StructuredFormModeRenderer,
    ...     StructuredFormToolbar,
    ... )
    >>> renderer = StructuredFormModeRenderer(parent=root, controller=ctrl)
    >>> toolbar = StructuredFormToolbar(parent=root, controller=ctrl)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Avoid circular imports - these will be imported lazily
if TYPE_CHECKING:
    from src.gui.modes.structured_form.renderer import StructuredFormModeRenderer
    from src.gui.modes.structured_form.toolbar import StructuredFormToolbar


def __getattr__(name: str) -> type:
    """Lazy imports to avoid circular dependency issues."""
    if name == "StructuredFormModeRenderer":
        from src.gui.modes.structured_form.renderer import StructuredFormModeRenderer

        return StructuredFormModeRenderer
    elif name == "StructuredFormToolbar":
        from src.gui.modes.structured_form.toolbar import StructuredFormToolbar

        return StructuredFormToolbar
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__: list[str] = [
    "StructuredFormModeRenderer",
    "StructuredFormToolbar",
]
