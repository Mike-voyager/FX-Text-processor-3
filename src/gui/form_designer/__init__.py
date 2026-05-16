"""Form designer module for FX Text Processor 3.

Provides visual form designer components:
- ESCPGridCanvas: Strict ESC/P 80×66 grid canvas with snap-to-grid
- FieldPaletteWidget: Visual field palette for drag-and-drop
- PropertyPanel: Property editing panel for form fields
- SectionFrame: Collapsible section container
- PreviewPanel: ESC/P preview panel with hex dump view
- PreviewData: Data class for preview information

Example:
    >>> from src.gui.form_designer import FieldPaletteWidget, PropertyPanel
    >>> palette = FieldPaletteWidget(parent, callbacks...)
    >>> panel = PropertyPanel(parent, on_change, on_delete, on_duplicate)

Version: 1.0
Date: April 2026
"""

from src.gui.form_designer.field_palette_widget import (
    DragData,
    DragMode,
    FieldPaletteWidget,
)
from src.gui.form_designer.grid_canvas import (
    DEFAULT_CELL_HEIGHT,
    DEFAULT_CELL_WIDTH,
    DEFAULT_ZOOM,
    MAX_ZOOM,
    MIN_ZOOM,
    ESCPGridCanvas,
    FieldInfo,
)
from src.gui.form_designer.preview_panel import (
    PreviewData,
    PreviewPanel,
)
from src.gui.form_designer.property_panel import (
    PropertyPanel,
    SectionFrame,
)

__all__: list[str] = [
    "ESCPGridCanvas",
    "DEFAULT_CELL_WIDTH",
    "DEFAULT_CELL_HEIGHT",
    "MIN_ZOOM",
    "MAX_ZOOM",
    "DEFAULT_ZOOM",
    "FieldInfo",
    "FieldPaletteWidget",
    "DragMode",
    "DragData",
    "PreviewPanel",
    "PreviewData",
    "PropertyPanel",
    "SectionFrame",
]
