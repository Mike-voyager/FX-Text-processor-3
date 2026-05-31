"""GUI Components module.

Provides UI components organized by complexity:
- base: BaseWidget, SmartBaseWidget
- primitive: ThemedButton, ThemedLabel, ThemedEntry, ThemedCheckbox
- compound: ExpandablePanel, IconButton, InputGroup, ListTile,
  ProgressIndicator, SearchBox, StatusBadge
- composite: ToolbarSection, ToolbarButtonGroup, MainToolbar,
  FormatToolbar, Ruler, Navigator, FormField, PaperVisualizationWidget,
  CodepageStatusWidget, ESCPPreviewWidget, MFAForm, TooltipManager,
  CodepageValidator, PaperToolbar, PaperConfig, PageSidebar, SidebarPageInfo
- sync: SyncStatus, WindowSyncIndicator, TabSyncIndicator,
  TitleBarSyncDecorator, TreeItemSyncIndicator, SideBarSyncManager,
  TreeItemDragHandle

Version: 2.3
"""

from __future__ import annotations

from src.gui.components.base.widget import BaseWidget, SmartBaseWidget
from src.gui.components.codepage_validator import CodepageValidator, ValidationResult
from src.gui.components.composite.main_toolbar import MainToolbar
from src.gui.components.compound.expandable_panel import ExpandablePanel
from src.gui.components.compound.icon_button import IconButton
from src.gui.components.compound.input_group import InputGroup
from src.gui.components.compound.list_tile import ListTile
from src.gui.components.compound.progress_indicator import ProgressIndicator
from src.gui.components.compound.search_box import SearchBox
from src.gui.components.compound.status_badge import StatusBadge
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
    LineProperties,
    PaperVisualizationWidget,
)
from src.gui.components.primitive.button import ThemedButton
from src.gui.components.primitive.checkbox import ThemedCheckbox
from src.gui.components.primitive.entry import ThemedEntry
from src.gui.components.primitive.label import ThemedLabel
from src.gui.components.ruler import Ruler
from src.gui.components.sync.side_bar_sync_ui import (
    SideBarSyncManager,
    TreeItemDragHandle,
    TreeItemSyncIndicator,
)
from src.gui.components.sync.window_sync_indicator import (
    SYNC_STATUS_COLORS,
    SYNC_STATUS_ICONS,
    SYNC_STATUS_LABELS,
    SyncStatus,
    TabSyncIndicator,
    TitleBarSyncDecorator,
    WindowSyncIndicator,
)
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
    # Compound widgets
    "ExpandablePanel",
    "IconButton",
    "InputGroup",
    "ListTile",
    "ProgressIndicator",
    "SearchBox",
    "StatusBadge",
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
    # Data classes
    "LineProperties",
    "ValidationResult",
    # Sync components
    "SyncStatus",
    "WindowSyncIndicator",
    "TabSyncIndicator",
    "TitleBarSyncDecorator",
    "SYNC_STATUS_COLORS",
    "SYNC_STATUS_ICONS",
    "SYNC_STATUS_LABELS",
    "TreeItemSyncIndicator",
    "SideBarSyncManager",
    "TreeItemDragHandle",
    # Factories
    "create_form_field",
]

__version__ = "2.3.0"
__author__ = "FX Text Processor Team"
__date__ = "May 2026"
