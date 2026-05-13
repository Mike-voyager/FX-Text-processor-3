"""Shared fixtures for GUI integration tests."""

import pytest
import tkinter as tk
from unittest.mock import Mock, MagicMock

from src.gui.services import (
    WindowManager,
    SyncService,
    NotificationService,
    DragDropService,
    DATA_WINDOW_LIST_CHANGED,
    DATA_DOCUMENT_UPDATE,
)


@pytest.fixture
def tk_root():
    """Create and destroy Tk root for tests."""
    root = tk.Tk()
    root.withdraw()  # Hide during tests
    yield root
    root.destroy()


@pytest.fixture
def window_manager(tk_root):
    """Create WindowManager with root."""
    wm = WindowManager(tk_root)
    yield wm


@pytest.fixture
def sync_service(window_manager):
    """Create SyncService with WindowManager."""
    return SyncService(window_manager)


@pytest.fixture
def notification_service(tk_root, window_manager):
    """Create NotificationService."""
    return NotificationService(tk_root, window_manager)


@pytest.fixture
def drag_drop_service(tk_root, window_manager, sync_service):
    """Create DragDropService with dependencies."""
    return DragDropService(tk_root, window_manager, sync_service)


@pytest.fixture
def mock_window_info():
    """Factory for mock WindowInfo objects."""
    def _create(window_id="win_001", title="Test", doc_path=None, is_modal=False):
        from src.gui.services.window_manager import WindowInfo
        return WindowInfo(
            window_id=window_id,
            toplevel=Mock(),
            title=title,
            document_path=doc_path,
            is_modal=is_modal,
            created_at=1234567890.0,
            z_order=0,
        )
    return _create
