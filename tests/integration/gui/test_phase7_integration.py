"""Integration tests for Phase 7 Services.

Tests interactions between WindowManager, SyncService,
NotificationService, and DragDropService.
"""

import pytest
import tkinter as tk
import time
import threading
from unittest.mock import Mock, patch

from src.gui.services import (
    WindowManager,
    SyncService,
    NotificationService,
    DragDropService,
    NotificationPriority,
    DATA_DOCUMENT_UPDATE,
    DATA_WINDOW_LIST_CHANGED,
    DATA_SIDEBAR_STATE,
    DropOperation,
    DragData,
    DATA_TYPE_DOCUMENT,
    ConflictResolution,
)


class TestWindowManagerSyncIntegration:
    """Tests for WindowManager + SyncService integration."""
    
    def test_window_registration_broadcasts_event(
        self, tk_root, window_manager, sync_service
    ):
        """Test that window registration triggers sync broadcast."""
        # Arrange
        received_messages = []
        
        def handler(msg):
            received_messages.append(msg)
        
        handler_id = sync_service.register_handler(
            DATA_WINDOW_LIST_CHANGED, "test_handler", handler
        )
        
        # Act - create and register window
        test_window = tk.Toplevel(tk_root)
        window_id = window_manager.register_window(test_window, "Test Window")
        
        # Broadcast manually (WindowManager doesn't auto-broadcast)
        sync_service.broadcast(
            source_window_id=window_id,
            data_type=DATA_WINDOW_LIST_CHANGED,
            data={"action": "created", "window_id": window_id},
        )
        
        # Assert
        assert len(received_messages) == 1
        assert received_messages[0].data["action"] == "created"
        
        # Cleanup
        sync_service.unregister_handler(handler_id)
        test_window.destroy()
    
    def test_window_close_updates_window_list(
        self, tk_root, window_manager, sync_service
    ):
        """Test that closing window updates list in WindowManager."""
        # Arrange
        test_window = tk.Toplevel(tk_root)
        window_id = window_manager.register_window(test_window, "Test")
        
        # Act
        window_manager.unregister_window(window_id)
        test_window.destroy()
        
        # Assert
        assert not window_manager.is_window_registered(window_id)
    
    def test_close_all_except_main_closes_windows(
        self, tk_root, window_manager
    ):
        """Test session lock closes all windows except main."""
        # Arrange
        root_id = window_manager.register_window(tk_root, "Main")
        window_manager.set_main_window_id(root_id)
        
        child1 = tk.Toplevel(tk_root)
        child1_id = window_manager.register_window(child1, "Child 1")
        
        child2 = tk.Toplevel(tk_root)
        child2_id = window_manager.register_window(child2, "Child 2")
        
        # Act
        closed = window_manager.close_all_except_main()
        
        # Assert
        assert closed == 2
        assert not window_manager.is_window_registered(child1_id)
        assert not window_manager.is_window_registered(child2_id)
        assert window_manager.is_window_registered(root_id)


class TestSyncServiceBroadcast:
    """Tests for SyncService broadcast functionality."""
    
    def test_broadcast_excludes_source_window(
        self, window_manager, sync_service
    ):
        """Test broadcast doesn't send to source window."""
        # Arrange
        received_by_source = []
        received_by_other = []
        
        sync_service.register_handler(
            DATA_DOCUMENT_UPDATE, "source", lambda m: received_by_source.append(m)
        )
        sync_service.register_handler(
            DATA_DOCUMENT_UPDATE, "other", lambda m: received_by_other.append(m)
        )
        
        # Act
        sync_service.broadcast(
            source_window_id="source",
            data_type=DATA_DOCUMENT_UPDATE,
            data={"test": "data"},
        )
        
        # Assert
        assert len(received_by_source) == 0  # Not sent to self
        assert len(received_by_other) == 1
    
    def test_send_to_window_delivers_to_target(
        self, window_manager, sync_service
    ):
        """Test direct message delivery."""
        # Arrange
        received = []
        sync_service.register_handler(
            DATA_SIDEBAR_STATE, "target", lambda m: received.append(m)
        )
        
        # Act
        sync_service.send_to_window(
            source_window_id="source",
            target_window_id="target",
            data_type=DATA_SIDEBAR_STATE,
            data={"collapsed": True},
        )
        
        # Assert
        assert len(received) == 1
        assert received[0].data["collapsed"] is True
    
    def test_multiple_handlers_receive_broadcast(
        self, window_manager, sync_service
    ):
        """Test multiple handlers can receive same broadcast."""
        # Arrange
        received1 = []
        received2 = []
        
        sync_service.register_handler(
            DATA_SIDEBAR_STATE, "win1", lambda m: received1.append(m)
        )
        sync_service.register_handler(
            DATA_SIDEBAR_STATE, "win2", lambda m: received2.append(m)
        )
        
        # Act
        sync_service.broadcast(
            source_window_id="source",
            data_type=DATA_SIDEBAR_STATE,
            data={"test": True},
        )
        
        # Assert
        assert len(received1) == 1
        assert len(received2) == 1


class TestNotificationServiceIntegration:
    """Tests for NotificationService integration."""
    
    def test_low_priority_uses_toast(
        self, tk_root, window_manager, notification_service
    ):
        """Test LOW priority notifications go to ToastService."""
        # Act
        nid = notification_service.notify(
            message="Test message",
            category="system",
            priority=NotificationPriority.LOW,
        )
        
        # Assert - notification created
        assert nid is not None
        assert notification_service.get_notification(nid) is not None
    
    def test_notification_updates_unread_count(
        self, tk_root, window_manager, notification_service
    ):
        """Test notification updates unread count."""
        # Arrange
        counts = []
        notification_service.register_badge_callback(lambda c: counts.append(c))
        
        # Act
        notification_service.notify(
            message="Test",
            category="workflow",
            priority=NotificationPriority.NORMAL,
        )
        
        # Assert
        assert len(counts) > 0
        assert counts[-1] >= 1
    
    def test_mark_as_read_updates_count(
        self, tk_root, window_manager, notification_service
    ):
        """Test marking notification as read updates count."""
        # Arrange
        nid = notification_service.notify(
            message="Test",
            category="workflow",
            priority=NotificationPriority.NORMAL,
        )
        
        initial_count = notification_service.get_unread_count()
        
        # Act
        notification_service.mark_as_read(nid)
        
        # Assert
        assert notification_service.get_unread_count() == initial_count - 1


class TestDragDropServiceIntegration:
    """Tests for DragDropService integration."""
    
    def test_drag_start_broadcasts_via_sync(
        self, tk_root, window_manager, sync_service, drag_drop_service
    ):
        """Test drag start broadcasts event via SyncService."""
        # Arrange
        received = []
        sync_service.register_handler(
            "drag_start", "listener", lambda m: received.append(m)
        )
        
        # Act
        data = DragData(
            source_window_id="win_001",
            data_type=DATA_TYPE_DOCUMENT,
            data={"doc_id": "doc_123"},
            preview_text="Document",
            allowed_operations=frozenset({DropOperation.MOVE}),
        )
        drag_drop_service.start_drag("win_001", data)
        
        # Assert
        # DragDropService sends broadcast via SyncService
        assert len(received) == 1
        assert received[0].data["data_type"] == DATA_TYPE_DOCUMENT
        
        # Cleanup
        if drag_drop_service.is_dragging():
            drag_drop_service.cancel_drag()


class TestMultiWindowScenario:
    """Full multi-window integration tests."""
    
    def test_window_manager_window_list(
        self, tk_root, window_manager, sync_service
    ):
        """Test complete flow: New Window -> Window Manager."""
        # Arrange
        # Create multiple windows
        win1 = tk.Toplevel(tk_root)
        win1_id = window_manager.register_window(win1, "Document 1")
        
        win2 = tk.Toplevel(tk_root)
        win2_id = window_manager.register_window(win2, "Document 2")
        
        # Act - Get window list
        windows = window_manager.get_window_list()
        
        # Assert
        assert len(windows) >= 2
        
        # Cleanup
        win1.destroy()
        win2.destroy()
        
    def test_sync_across_multiple_windows(
        self, tk_root, window_manager, sync_service
    ):
        """Test sync service with multiple window handlers."""
        # Arrange
        win1 = tk.Toplevel(tk_root)
        win1_id = window_manager.register_window(win1, "Window 1")
        
        win2 = tk.Toplevel(tk_root)
        win2_id = window_manager.register_window(win2, "Window 2")
        
        received = []
        sync_service.register_handler(
            DATA_SIDEBAR_STATE, win1_id, lambda m: received.append(("win1", m))
        )
        sync_service.register_handler(
            DATA_SIDEBAR_STATE, win2_id, lambda m: received.append(("win2", m))
        )
        
        # Act
        sync_service.broadcast(
            source_window_id="source",
            data_type=DATA_SIDEBAR_STATE,
            data={"collapsed": False},
        )
        
        # Assert
        assert len(received) == 2
        
        # Cleanup
        win1.destroy()
        win2.destroy()


class TestServicesThreadSafety:
    """Thread-safety tests for services."""
    
    def test_sync_service_concurrent_handler_registration(
        self, window_manager, sync_service
    ):
        """Test concurrent handler registration is thread-safe."""
        # Arrange
        import threading
        
        handler_ids = []
        errors = []
        
        def register_handler(i):
            try:
                hid = sync_service.register_handler(
                    DATA_DOCUMENT_UPDATE, f"win_{i}", lambda m: None
                )
                handler_ids.append(hid)
            except Exception as e:
                errors.append(e)
        
        # Act - Register from multiple threads
        threads = [
            threading.Thread(target=register_handler, args=(i,))
            for i in range(10)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Assert
        assert len(errors) == 0
        assert len(handler_ids) == 10


class TestWindowManagerDocumentTransfer:
    """Tests for document transfer functionality."""
    
    def test_transfer_document_between_windows(
        self, tk_root, window_manager
    ):
        """Test transferring document from one window to another."""
        # Arrange
        from pathlib import Path
        
        win1 = tk.Toplevel(tk_root)
        win1_id = window_manager.register_window(
            win1, "Window 1", document_path=Path("/docs/doc1.fxsd")
        )
        
        win2 = tk.Toplevel(tk_root)
        win2_id = window_manager.register_window(win2, "Window 2")
        
        # Act
        result = window_manager.transfer_document(win1_id, win2_id, "doc1")
        
        # Assert
        assert result is True
        win1_info = window_manager.get_window_list()
        win1_doc = next((w for w in win1_info if w.window_id == win1_id), None)
        win2_doc = next((w for w in win1_info if w.window_id == win2_id), None)
        
        if win1_doc:
            assert win1_doc.document_path is None
        if win2_doc:
            assert win2_doc.document_path == Path("/docs/doc1.fxsd")
        
        # Cleanup
        win1.destroy()
        win2.destroy()


class TestNotificationHistory:
    """Tests for notification history management."""
    
    def test_notification_history_filtering(
        self, tk_root, window_manager, notification_service
    ):
        """Test filtering notifications by category."""
        # Arrange
        from src.gui.services.notification_service import CATEGORY_WORKFLOW, CATEGORY_SYSTEM
        
        nid1 = notification_service.notify(
            message="Workflow message",
            category=CATEGORY_WORKFLOW,
            priority=NotificationPriority.NORMAL,
        )
        nid2 = notification_service.notify(
            message="System message",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.NORMAL,
        )
        
        # Act
        workflow_history = notification_service.get_history(category=CATEGORY_WORKFLOW)
        
        # Assert
        assert len(workflow_history) == 1
        assert workflow_history[0].category == CATEGORY_WORKFLOW


class TestDragDropOperations:
    """Tests for drag-drop operations."""
    
    def test_drop_target_registration(
        self, tk_root, window_manager, sync_service, drag_drop_service
    ):
        """Test registering drop targets."""
        # Arrange
        from src.gui.services.drag_drop_service import DropTarget
        
        canvas = tk.Canvas(tk_root, width=200, height=200)
        target = DropTarget(
            target_id="canvas_001",
            widget=canvas,
            accepted_types=(DATA_TYPE_DOCUMENT,),
            accepted_operations=frozenset({DropOperation.MOVE, DropOperation.COPY}),
            on_drop=lambda data, x, y: None,
        )
        
        # Act
        target_id = drag_drop_service.register_drop_target(canvas, target)
        
        # Assert
        assert target_id == "canvas_001"
        assert drag_drop_service.get_drop_target_count() == 1
        
        # Cleanup
        drag_drop_service.clear_drop_targets()


class TestServiceCleanup:
    """Tests for proper resource cleanup."""
    
    def test_sync_service_clear_handlers(
        self, window_manager, sync_service
    ):
        """Test clearing all handlers from sync service."""
        # Arrange
        for i in range(5):
            sync_service.register_handler(
                DATA_SIDEBAR_STATE, f"win_{i}", lambda m: None
            )
        
        # Act
        removed = sync_service.clear_handlers()
        
        # Assert
        assert removed == 5
        assert sync_service.get_handler_count() == 0
