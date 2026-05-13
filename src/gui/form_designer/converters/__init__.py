"""Конвертеры для Form Designer.

Модуль предоставляет конвертеры для преобразования между DesignerPage и FormTemplate:
- DesignerToTemplateConverter: конвертирует DesignerPage в FormTemplate
- TemplateToDesignerConverter: конвертирует FormTemplate в DesignerPage

Example:
    >>> from src.gui.form_designer.converters import DesignerToTemplateConverter
    >>> converter = DesignerToTemplateConverter()
    >>> template = converter.convert(pages, metadata)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from src.gui.form_designer.converters.designer_to_template import (
    DesignerToTemplateConverter,
)
from src.gui.form_designer.converters.template_to_designer import (
    TemplateToDesignerConverter,
)

__all__ = [
    "DesignerToTemplateConverter",
    "TemplateToDesignerConverter",
]
