"""FreeForm Mode пакет для FX Text Processor 3.

Пакет реализует режим свободного редактирования текста (FreeForm) для Form Designer.
Содержит адаптированный рендерер и панель инструментов.

Classes:
    FreeFormModeRenderer: Адаптер/обёртка над FreeFormRenderer для интеграции с Grid Canvas.
    FreeFormToolbar: Панель инструментов с CPI selector, formatting buttons и font selector.

Example:
    >>> from src.gui.modes.free_form import FreeFormModeRenderer, FreeFormToolbar
    >>> renderer = FreeFormModeRenderer(widget_id="ff_renderer")
    >>> toolbar = FreeFormToolbar(widget_id="ff_toolbar")

Version: 1.0
Date: April 2026
"""

from src.gui.modes.free_form.renderer import FreeFormModeRenderer
from src.gui.modes.free_form.toolbar import FreeFormToolbar

__all__: list[str] = [
    "FreeFormModeRenderer",
    "FreeFormToolbar",
]
