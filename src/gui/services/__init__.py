"""GUI Services package for FX Text Processor 3."""

from src.gui.services.autocomplete_service import AutocompleteServiceGui
from src.gui.services.drag_drop_service import (
    DATA_TYPE_DOCUMENT,
    DATA_TYPE_FIELD,
    DATA_TYPE_TEMPLATE,
    DATA_TYPE_TEXT,
    DragData,
    DragDropService,
    DropOperation,
    DropTarget,
)
from src.gui.services.key_bindings import KeyBindingsService
from src.gui.services.notification_service import (
    CATEGORY_SECURITY,
    CATEGORY_SYNC,
    CATEGORY_SYSTEM,
    CATEGORY_WORKFLOW,
    Notification,
    NotificationPriority,
    NotificationService,
)
from src.gui.services.sync_service import (
    DATA_BOOKMARK_CHANGE,
    DATA_DOCUMENT_UPDATE,
    DATA_MODE_CHANGE,
    DATA_SELECTION_CHANGE,
    DATA_SIDEBAR_STATE,
    DATA_WINDOW_LIST_CHANGED,
    ConflictResolution,
    SyncMessage,
    SyncService,
)
from src.gui.services.toast_service import ToastService
from src.gui.services.window_manager import WindowInfo, WindowManager

__all__ = [
    "WindowManager",
    "WindowInfo",
    "NotificationService",
    "Notification",
    "NotificationPriority",
    "CATEGORY_SECURITY",
    "CATEGORY_WORKFLOW",
    "CATEGORY_SYSTEM",
    "CATEGORY_SYNC",
    "DragDropService",
    "DragData",
    "DropTarget",
    "DropOperation",
    "DATA_TYPE_FIELD",
    "DATA_TYPE_DOCUMENT",
    "DATA_TYPE_TEMPLATE",
    "DATA_TYPE_TEXT",
    "SyncService",
    "SyncMessage",
    "ConflictResolution",
    "DATA_SIDEBAR_STATE",
    "DATA_BOOKMARK_CHANGE",
    "DATA_DOCUMENT_UPDATE",
    "DATA_SELECTION_CHANGE",
    "DATA_MODE_CHANGE",
    "DATA_WINDOW_LIST_CHANGED",
    "ToastService",
    "KeyBindingsService",
    "AutocompleteServiceGui",
]
