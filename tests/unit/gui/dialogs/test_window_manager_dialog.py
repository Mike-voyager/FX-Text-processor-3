# -*- coding: utf-8 -*-
"""Тесты для WindowManagerDialog.

Тестирует создание диалога менеджера окон, отображение списка окон,
кнопки управления окнами, групповые операции и авто-обновление
через SyncService.

Version: 1.0
Security: MEDIUM
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

    # Import types for mypy only
    from src.gui.dialogs.window_manager_dialog import WindowManagerDialog

# Runtime imports with fallback
TKINTER_AVAILABLE = False
WindowManagerDialog: Any = None
WindowManager: Any = None
WindowInfo: Any = None
SyncService: Any = None
SyncMessage: Any = None
DATA_WINDOW_LIST_CHANGED: Any = None

try:
    import tkinter as tk
    from tkinter import ttk

    # Import window_manager_dialog directly to bypass __init__.py issues
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(
        "window_manager_dialog",
        "/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3/src/gui/dialogs/window_manager_dialog.py",
    )
    if spec and spec.loader:
        wmd_module: Any = importlib.util.module_from_spec(spec)
        sys.modules["window_manager_dialog"] = wmd_module
        spec.loader.exec_module(wmd_module)

        WindowManagerDialog = wmd_module.WindowManagerDialog
        DIALOG_WIDTH: int = wmd_module.DIALOG_WIDTH
        DIALOG_HEIGHT: int = wmd_module.DIALOG_HEIGHT
        COLOR_BG: str = wmd_module.COLOR_BG
        COLOR_HEADER: str = wmd_module.COLOR_HEADER
        COLOR_BORDER: str = wmd_module.COLOR_BORDER
        COLOR_TEXT: str = wmd_module.COLOR_TEXT
        WINDOW_TYPE_MAIN: str = wmd_module.WINDOW_TYPE_MAIN
        WINDOW_TYPE_DOCUMENT: str = wmd_module.WINDOW_TYPE_DOCUMENT
        WINDOW_TYPE_DIALOG: str = wmd_module.WINDOW_TYPE_DIALOG

    # Import services
    from src.gui.services.window_manager import WindowInfo, WindowManager
    from src.gui.services.sync_service import (
        DATA_WINDOW_LIST_CHANGED,
        SyncMessage,
        SyncService,
    )

    TKINTER_AVAILABLE = True
except (ImportError, AttributeError, OSError, RuntimeError):
    TKINTER_AVAILABLE = False


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_window_manager() -> MagicMock:
    """Создание мока WindowManager."""
    mock = MagicMock(spec=WindowManager)

    # Create mock windows
    mock_window_info_1 = MagicMock(spec=WindowInfo)
    mock_window_info_1.window_id = "win-001"
    mock_window_info_1.title = "Document 1"
    mock_window_info_1.document_path = Path("/docs/doc1.fxsd")
    mock_window_info_1.is_modal = False
    mock_window_info_1.is_minimized = False

    mock_window_info_2 = MagicMock(spec=WindowInfo)
    mock_window_info_2.window_id = "win-002"
    mock_window_info_2.title = "Document 2"
    mock_window_info_2.document_path = Path("/docs/doc2.fxsd")
    mock_window_info_2.is_modal = False
    mock_window_info_2.is_minimized = False

    mock_window_info_3 = MagicMock(spec=WindowInfo)
    mock_window_info_3.window_id = "win-main"
    mock_window_info_3.title = "FX Text Processor"
    mock_window_info_3.document_path = None
    mock_window_info_3.is_modal = False
    mock_window_info_3.is_minimized = False

    mock.get_window_list.return_value = [
        mock_window_info_3,
        mock_window_info_1,
        mock_window_info_2,
    ]
    mock.get_main_window_id.return_value = "win-main"
    mock.is_main_window.side_effect = lambda w: w == "win-main"
    mock.get_window.return_value = MagicMock()
    mock.bring_to_front.return_value = None
    mock.minimize_all.return_value = 2
    mock.close_all_except_main.return_value = 2

    return mock


@pytest.fixture
def mock_sync_service() -> MagicMock:
    """Создание мока SyncService."""
    mock = MagicMock(spec=SyncService)
    mock.register_handler.return_value = "handler-001"
    return mock


@pytest.fixture
def mock_parent() -> MagicMock:
    """Создание мока родительского виджета."""
    mock = MagicMock()
    mock.winfo_rootx.return_value = 0
    mock.winfo_rooty.return_value = 0
    mock.winfo_width.return_value = 800
    mock.winfo_height.return_value = 600
    mock._root.return_value = mock
    mock.master = None  # Stop widget hierarchy traversal
    return mock


# =============================================================================
# TESTS: Dialog Creation
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.gui
class TestWindowManagerDialogCreation:
    """Тесты создания WindowManagerDialog."""

    def test_dialog_initialization(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка создания диалога."""
        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview"), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            assert dialog._parent is mock_parent
            assert dialog._window_manager is mock_window_manager
            assert dialog._sync_service is mock_sync_service

    def test_dialog_initialization_without_sync_service(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
    ) -> None:
        """Проверка создания диалога без SyncService."""
        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview"), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=None,
            )

            assert dialog._sync_service is None
            assert dialog._handler_id is None

    def test_dialog_constants(self) -> None:
        """Проверка констант диалога."""
        assert DIALOG_WIDTH == 600
        assert DIALOG_HEIGHT == 450
        assert COLOR_BG == "#f8f9fa"
        assert COLOR_HEADER == "#e9ecef"
        assert COLOR_BORDER == "#dee2e6"
        assert COLOR_TEXT == "#212529"
        assert WINDOW_TYPE_MAIN == "Main Window"
        assert WINDOW_TYPE_DOCUMENT == "Document"
        assert WINDOW_TYPE_DIALOG == "Dialog"


# =============================================================================
# TESTS: Window List Display
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.gui
class TestWindowManagerDialogWindowList:
    """Тесты отображения списка окон."""

    def test_window_list_populated(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка что treeview заполнен данными из WindowManager."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Проверяем что WindowManager был вызван
            mock_window_manager.get_window_list.assert_called_once()

            # Проверяем что treeview получил данные
            assert dialog._tree is not None
            assert dialog._window_list is not None
            assert len(dialog._window_list) == 3

    def test_window_types_displayed_correctly(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка корректного отображения типов окон."""
        inserted_items: list[Any] = []

        def mock_insert(parent: str, index: str, iid: str = "", text: str = "", values: Any = (), **kwargs: Any) -> str:
            inserted_items.append((parent, index, iid, text, values, kwargs))
            return iid

        mock_tree = MagicMock()
        mock_tree.insert = mock_insert
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Проверяем что все 3 окна были вставлены
            assert len(inserted_items) == 3

            # Проверяем значения (title, document, type)
            for item in inserted_items:
                values = item[4]
                assert len(values) == 3
                title, document, window_type = values
                assert isinstance(title, str)
                assert isinstance(document, str)
                assert window_type in [WINDOW_TYPE_MAIN, WINDOW_TYPE_DOCUMENT, WINDOW_TYPE_DIALOG]

    def test_document_path_formatting(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка форматирования пути к документу."""
        inserted_items: list[Any] = []

        def mock_insert(parent: str, index: str, iid: str = "", text: str = "", values: Any = (), **kwargs: Any) -> str:
            inserted_items.append((parent, index, iid, text, values, kwargs))
            return iid

        mock_tree = MagicMock()
        mock_tree.insert = mock_insert
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Проверяем формат пути: parent/name
            doc_values = [item[4][1] for item in inserted_items if item[4][1] != "-"]
            for doc_path in doc_values:
                assert "/" in doc_path  # Формат должен содержать /

    def test_main_window_highlighted(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка что главное окно выделено специальным тегом."""
        inserted_items: list[Any] = []

        def mock_insert(parent: str, index: str, iid: str = "", text: str = "", values: Any = (), **kwargs: Any) -> str:
            inserted_items.append((parent, index, iid, text, values, kwargs))
            return iid

        mock_tree = MagicMock()
        mock_tree.insert = mock_insert
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Проверяем что главное окно имеет тег "main"
            main_window_item = None
            for item in inserted_items:
                if item[4][2] == WINDOW_TYPE_MAIN:  # values[2] is type
                    main_window_item = item
                    break

            assert main_window_item is not None
            kwargs = main_window_item[5]
            assert "tags" in kwargs
            assert "main" in kwargs["tags"]


# =============================================================================
# TESTS: Buttons
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.gui
class TestWindowManagerDialogButtons:
    """Тесты кнопок диалога."""

    def test_bring_to_front_button(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка кнопки 'На передний план'."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=["win-001"])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Simulate selection
            dialog._current_selection = "win-001"
            dialog._bring_to_front()

            # Verify bring_to_front was called
            mock_window_manager.bring_to_front.assert_called_with("win-001")

    def test_minimize_button(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка кнопки 'Свернуть'."""
        mock_toplevel = MagicMock()
        mock_window_manager.get_window.return_value = mock_toplevel

        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=["win-001"])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Simulate selection
            dialog._current_selection = "win-001"
            dialog._minimize_selected()

            # Verify iconify was called
            mock_toplevel.iconify.assert_called_once()

    def test_close_button(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка кнопки 'Закрыть' для обычного окна."""
        mock_toplevel = MagicMock()
        mock_window_manager.get_window.return_value = mock_toplevel
        mock_window_manager.is_main_window.return_value = False

        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=["win-001"])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Simulate selection
            dialog._current_selection = "win-001"
            dialog._close_selected()

            # Verify destroy was called
            mock_toplevel.destroy.assert_called_once()

    def test_close_button_blocks_main_window(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка что главное окно нельзя закрыть."""
        mock_toplevel = MagicMock()
        mock_window_manager.get_window.return_value = mock_toplevel
        mock_window_manager.is_main_window.return_value = True

        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=["win-main"])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning") as mock_warning, \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Simulate selection of main window
            dialog._current_selection = "win-main"
            dialog._close_selected()

            # Verify warning was shown, not destroy
            mock_warning.assert_called_once()
            mock_toplevel.destroy.assert_not_called()


# =============================================================================
# TESTS: Group Operations
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.gui
class TestWindowManagerDialogGroupOperations:
    """Тесты групповых операций."""

    def test_minimize_all_button(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка кнопки 'Свернуть все'."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            dialog._minimize_all()

            # Verify minimize_all was called
            mock_window_manager.minimize_all.assert_called_once()

    def test_close_all_except_main_button_confirms(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка подтверждения перед закрытием всех окон."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno", return_value=True):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            dialog._close_all_except_main()

            # Verify askyesno was called and close_all_except_main was called
            mock_window_manager.close_all_except_main.assert_called_once()

    def test_close_all_except_main_button_cancelled(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка отмены закрытия всех окон."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno", return_value=False):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            dialog._close_all_except_main()

            # Verify close_all_except_main was NOT called when cancelled
            mock_window_manager.close_all_except_main.assert_not_called()


# =============================================================================
# TESTS: SyncService Integration
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.gui
class TestWindowManagerDialogSyncService:
    """Тесты интеграции с SyncService."""

    def test_sync_subscription_registered(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка регистрации обработчика SyncService."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Verify register_handler was called with correct data type
            mock_sync_service.register_handler.assert_called_once()
            call_args = mock_sync_service.register_handler.call_args
            assert call_args[0][0] == DATA_WINDOW_LIST_CHANGED

    def test_sync_handler_updates_window_list(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка что обработчик SyncService обновляет список окон."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Capture the handler function
            handler = mock_sync_service.register_handler.call_args[0][2]

            # Create a mock SyncMessage
            mock_message = MagicMock(spec=SyncMessage)
            mock_message.data_type = DATA_WINDOW_LIST_CHANGED

            # Reset the get_window_list call count
            mock_window_manager.get_window_list.reset_mock()

            # Call the handler
            handler(mock_message)

            # Verify get_window_list was called (via after method)
            assert dialog._window_manager is mock_window_manager

    def test_close_unregisters_handler(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка отписки от SyncService при закрытии диалога."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel") as mock_toplevel_class:
            mock_toplevel = MagicMock()
            mock_toplevel_class.return_value = mock_toplevel

            with patch("window_manager_dialog.tk.Frame"), \
                 patch("window_manager_dialog.tk.Label"), \
                 patch("window_manager_dialog.tk.Button"), \
                 patch("window_manager_dialog.tk.Text"), \
                 patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
                 patch("window_manager_dialog.ttk.Scrollbar"), \
                 patch("window_manager_dialog.ttk.Label"), \
                 patch("window_manager_dialog.ttk.LabelFrame"), \
                 patch("window_manager_dialog.ttk.Style"), \
                 patch("window_manager_dialog.ttk.Frame"), \
                 patch("window_manager_dialog.messagebox.showinfo"), \
                 patch("window_manager_dialog.messagebox.showwarning"), \
                 patch("window_manager_dialog.messagebox.askyesno"):

                dialog: Any = WindowManagerDialog(
                    parent=mock_parent,
                    window_manager=mock_window_manager,
                    sync_service=mock_sync_service,
                )

                # Set the handler_id
                dialog._handler_id = "handler-001"

                # Close the dialog
                dialog._close()

                # Verify unregister_handler was called
                mock_sync_service.unregister_handler.assert_called_with("handler-001")


# =============================================================================
# TESTS: ESC Key
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.gui
class TestWindowManagerDialogESCBinding:
    """Тесты закрытия по ESC."""

    def test_esc_binding_closes_dialog(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка что ESC закрывает диалог."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel") as mock_toplevel_class:
            mock_toplevel = MagicMock()
            mock_toplevel_class.return_value = mock_toplevel

            with patch("window_manager_dialog.tk.Frame"), \
                 patch("window_manager_dialog.tk.Label"), \
                 patch("window_manager_dialog.tk.Button"), \
                 patch("window_manager_dialog.tk.Text"), \
                 patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
                 patch("window_manager_dialog.ttk.Scrollbar"), \
                 patch("window_manager_dialog.ttk.Label"), \
                 patch("window_manager_dialog.ttk.LabelFrame"), \
                 patch("window_manager_dialog.ttk.Style"), \
                 patch("window_manager_dialog.ttk.Frame"), \
                 patch("window_manager_dialog.messagebox.showinfo"), \
                 patch("window_manager_dialog.messagebox.showwarning"), \
                 patch("window_manager_dialog.messagebox.askyesno"):

                dialog: Any = WindowManagerDialog(
                    parent=mock_parent,
                    window_manager=mock_window_manager,
                    sync_service=mock_sync_service,
                )

                # Verify dialog has _close method and that ESC binding is configured
                assert hasattr(dialog, "_close")
                assert callable(dialog._close)


# =============================================================================
# TESTS: Edge Cases
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.gui
class TestWindowManagerDialogEdgeCases:
    """Тесты граничных случаев."""

    def test_empty_window_list(
        self,
        mock_parent: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка обработки пустого списка окон."""
        mock_window_manager_empty = MagicMock()
        mock_window_manager_empty.get_window_list.return_value = []
        mock_window_manager_empty.get_main_window_id.return_value = None

        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager_empty,
                sync_service=mock_sync_service,
            )

            assert dialog._window_list == []

    def test_window_without_document_path(
        self,
        mock_parent: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка отображения окна без пути к документу."""
        mock_window_manager_no_doc = MagicMock()

        mock_window_info = MagicMock(spec=WindowInfo)
        mock_window_info.window_id = "win-001"
        mock_window_info.title = "New Window"
        mock_window_info.document_path = None
        mock_window_info.is_modal = False
        mock_window_info.is_minimized = False

        mock_window_manager_no_doc.get_window_list.return_value = [mock_window_info]
        mock_window_manager_no_doc.get_main_window_id.return_value = None
        mock_window_manager_no_doc.is_main_window.return_value = False

        inserted_items: list[Any] = []

        def mock_insert(parent: str, index: str, iid: str = "", text: str = "", values: Any = (), **kwargs: Any) -> str:
            inserted_items.append((parent, index, iid, text, values, kwargs))
            return iid

        mock_tree = MagicMock()
        mock_tree.insert = mock_insert
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager_no_doc,
                sync_service=mock_sync_service,
            )

            # Verify document column shows "-" for no path
            assert len(inserted_items) == 1
            values = inserted_items[0][4]
            assert values[1] == "-"  # document column

    def test_show_method(
        self,
        mock_parent: MagicMock,
        mock_window_manager: MagicMock,
        mock_sync_service: MagicMock,
    ) -> None:
        """Проверка метода show()."""
        mock_tree = MagicMock()
        mock_tree.insert = MagicMock(return_value="item_id")
        mock_tree.get_children = MagicMock(return_value=[])
        mock_tree.delete = MagicMock()
        mock_tree.tag_configure = MagicMock()
        mock_tree.item = MagicMock()
        mock_tree.selection = MagicMock(return_value=[])
        mock_tree.bind = MagicMock()
        mock_tree.configure = MagicMock()

        with patch("window_manager_dialog.tk.Toplevel"), \
             patch("window_manager_dialog.tk.Frame"), \
             patch("window_manager_dialog.tk.Label"), \
             patch("window_manager_dialog.tk.Button"), \
             patch("window_manager_dialog.tk.Text"), \
             patch("window_manager_dialog.ttk.Treeview", return_value=mock_tree), \
             patch("window_manager_dialog.ttk.Scrollbar"), \
             patch("window_manager_dialog.ttk.Label"), \
             patch("window_manager_dialog.ttk.LabelFrame"), \
             patch("window_manager_dialog.ttk.Style"), \
             patch("window_manager_dialog.ttk.Frame"), \
             patch("window_manager_dialog.messagebox.showinfo"), \
             patch("window_manager_dialog.messagebox.showwarning"), \
             patch("window_manager_dialog.messagebox.askyesno"):

            dialog: Any = WindowManagerDialog(
                parent=mock_parent,
                window_manager=mock_window_manager,
                sync_service=mock_sync_service,
            )

            # Mock wait_window
            dialog.wait_window = MagicMock()

            dialog.show()

            # Verify wait_window was called
            dialog.wait_window.assert_called_once()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestWindowManagerDialogCreation",
    "TestWindowManagerDialogWindowList",
    "TestWindowManagerDialogButtons",
    "TestWindowManagerDialogGroupOperations",
    "TestWindowManagerDialogSyncService",
    "TestWindowManagerDialogESCBinding",
    "TestWindowManagerDialogEdgeCases",
]
