"""Layout модуль для GUI.

Предоставляет менеджеры layout и константы для организации UI.

Example:
    >>> from src.gui.layout.layout_constants import SIDEBAR_WIDTH
    >>> from src.gui.layout.paned_layout import PanedLayout
    >>> from src.gui.layout.main_layout import MainLayout
"""

from src.gui.layout.layout_constants import (
    MIN_WINDOW_HEIGHT,
    MIN_WINDOW_WIDTH,
    PANEL_RATIO_DEFAULT,
    SIDEBAR_COLLAPSED_WIDTH,
    SIDEBAR_WIDTH,
    STATUSBAR_HEIGHT,
    TABBAR_HEIGHT,
)
from src.gui.layout.main_layout import (
    MainLayout,
    SidebarToggleCallback,
)
from src.gui.layout.paned_layout import (
    CollapseStateCallback,
    PanedLayout,
    PanedLayoutState,
    SashChangeCallback,
)

__all__ = [
    # Constants
    "MIN_WINDOW_WIDTH",
    "MIN_WINDOW_HEIGHT",
    "SIDEBAR_WIDTH",
    "SIDEBAR_COLLAPSED_WIDTH",
    "STATUSBAR_HEIGHT",
    "TABBAR_HEIGHT",
    "PANEL_RATIO_DEFAULT",
    # Classes
    "PanedLayout",
    "PanedLayoutState",
    "MainLayout",
    # Callbacks
    "SashChangeCallback",
    "CollapseStateCallback",
    "SidebarToggleCallback",
]
