"""GUI Components module.

Provides UI components organized by complexity:
- base: BaseWidget, SmartBaseWidget
- primitive: ThemedButton, ThemedLabel, ThemedEntry, ThemedCheckbox
- composite: ToolbarSection, ToolbarButtonGroup, MainToolbar,
  FormatToolbar, Ruler, Navigator, FormField, PaperVisualizationWidget,
  CodepageStatusWidget, ESCPPreviewWidget, MFAForm, TooltipManager,
  CodepageValidator, PaperToolbar, PaperConfig, PageSidebar, SidebarPageInfo

Version: 2.1
"""

from __future__ import annotations

from src.gui.components.base.widget import BaseWidget, SmartBaseWidget
from src.gui.components.codepage_validator import CodepageValidator
from src.gui.components.composite.main_toolbar import MainToolbar
from src.gui.components.escp_preview_widget import ESCPPreviewWidget
from src.gui.components.factories.form_field_factory import create_form_field
from src.gui.components.form_field import FormField
from src.gui.components.format_toolbar import FormatToolbar
from src.gui.components.mfa_form import MFAForm
from src.gui.components.navigator import Navigator
from src.gui.components.page_sidebar import PageSidebar, SidebarPageInfo
from src.gui.components.paper_toolbar import PaperConfig, PaperToolbar
from src.gui.components.paper_visualization import (
    CodepageStatusWidget,
    PaperVisualizationWidget,
)
from src.gui.components.primitive.button import ThemedButton
from src.gui.components.primitive.checkbox import ThemedCheckbox
from src.gui.components.primitive.entry import ThemedEntry
from src.gui.components.primitive.label import ThemedLabel
from src.gui.components.ruler import Ruler
from src.gui.components.toolbar_section import ToolbarButtonGroup, ToolbarSection
from src.gui.components.tooltip import TooltipManager
from src.gui.core.protocols import FormFieldProtocol

__all__ = [
    "BaseWidget",
    "SmartBaseWidget",
    # Primitive widgets
    "ThemedButton",
    "ThemedCheckbox",
    "ThemedEntry",
    "ThemedLabel",
    # Composite widgets
    "CodepageStatusWidget",
    "CodepageValidator",
    "ESCPPreviewWidget",
    "FormatToolbar",
    "FormField",
    "FormFieldProtocol",
    "MainToolbar",
    "MFAForm",
    "Navigator",
    "PageSidebar",
    "PaperConfig",
    "PaperToolbar",
    "PaperVisualizationWidget",
    "Ruler",
    "SidebarPageInfo",
    "ToolbarButtonGroup",
    "ToolbarSection",
    "TooltipManager",
    # Factories
    "create_form_field",
]

__version__ = "2.1.0"
__author__ = "FX Text Processor Team"
__date__ = "May 2026"
