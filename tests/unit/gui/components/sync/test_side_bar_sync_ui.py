"""Unit-тесты для side_bar_sync_ui компонентов.

Проверяет:
- TreeItemSyncIndicator (статус, анимация, теги)
- SideBarSyncManager (регистрация, обновление, handle)
- TreeItemDragHandle (hover, callback)

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.sync.side_bar_sync_ui import (
    SideBarSyncManager,
    TreeItemDragHandle,
    TreeItemSyncIndicator,
    _SYNC_TOOLTIPS,
    _DRAG_HANDLE_ICON,
    SYNC_ANIMATION_INTERVAL,
)

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def tree(tk_root: tk.Tk) -> ttk.Treeview:
    """Fixture для ttk.Treeview (unmounted внутри frame)."""
    frame = tk.Frame(tk_root)
    frame.pack()
    tv = ttk.Treeview(frame, show="tree")
    tv.pack()
    return tv


@pytest.fixture
def dummy_colors() -> dict[str, str]:
    return {
        "synced": "#4CAF50",
        "syncing": "#2196F3",
        "conflict": "#FF9800",
        "offline": "#9E9E9E",
    }


@pytest.fixture
def dummy_icons() -> dict[str, str]:
    return {
        "synced": "●",
        "syncing": "⟳",
        "conflict": "⚠",
        "offline": "✗",
    }


@pytest.fixture
def base_item(tree: ttk.Treeview) -> str:
    """Вставляет один элемент в дерево."""
    tree.insert("", "end", iid="doc_1", text="📄 Doc1")
    return "doc_1"


# =============================================================================
# TEST: TreeItemSyncIndicator
# =============================================================================


@pytest.mark.gui
class TestTreeItemSyncIndicator:
    """Тесты индикатора синхронизации."""

    def test_creation(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """Создание индикатора с начальным статусом."""
        ind = TreeItemSyncIndicator(
            tree, base_item, "📄 Doc1", "synced", dummy_colors, dummy_icons
        )
        assert ind.status == "synced"
        assert ind.current_icon == "●"
        ind.destroy()

    def test_set_status(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """set_status() меняет иконку."""
        ind = TreeItemSyncIndicator(
            tree, base_item, "📄 Doc1", "synced", dummy_colors, dummy_icons
        )
        ind.set_status("conflict")
        assert ind.status == "conflict"
        assert ind.current_icon == "⚠"
        ind.destroy()

    def test_syncing_animation_step(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """Анимация SYNCING: _step_animation() меняет иконку."""
        ind = TreeItemSyncIndicator(
            tree, base_item, "📄 Doc1", "syncing", dummy_colors, dummy_icons
        )
        initial = ind.current_icon
        ind._step_animation()
        assert ind.current_icon != initial
        assert ind._anim_frame == 1
        ind.destroy()

    def test_destroy_cancels_after(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """destroy() отменяет after()."""
        ind = TreeItemSyncIndicator(
            tree, base_item, "📄 Doc1", "syncing", dummy_colors, dummy_icons
        )
        # after_id устанавливается после _step_animation
        assert ind._after_id is not None
        ind.destroy()
        assert ind._after_id is None

    def test_animation_callback(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """Callback вызывается при шаге анимации."""
        cb = MagicMock()
        ind = TreeItemSyncIndicator(
            tree, base_item, "📄 Doc1", "syncing", dummy_colors, dummy_icons,
            on_animation_step=cb,
        )
        ind._step_animation()
        cb.assert_called_once_with(base_item)
        ind.destroy()


# =============================================================================
# TEST: SideBarSyncManager
# =============================================================================


@pytest.mark.gui
class TestSideBarSyncManager:
    """Тесты SideBarSyncManager."""

    def test_register_item(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """register_item() добавляет элемент и обновляет текст."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "synced")
        text = tree.item(base_item, "text")
        assert "●" in text
        assert "📄 Doc1" in text
        tags = tree.item(base_item, "tags")
        assert "sync_synced" in tags
        mgr.unmount()

    def test_set_item_status(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """set_item_status() меняет статус и текст."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "synced")
        mgr.set_item_status(base_item, "conflict")
        text = tree.item(base_item, "text")
        assert "⚠" in text
        tags = tree.item(base_item, "tags")
        assert "sync_conflict" in tags
        mgr.unmount()

    def test_clear_item_status(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """clear_item_status() устанавливает offline."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "synced")
        mgr.clear_item_status(base_item)
        text = tree.item(base_item, "text")
        assert "✗" in text
        tags = tree.item(base_item, "tags")
        assert "sync_offline" in tags
        mgr.unmount()

    def test_update_all(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
    ) -> None:
        """update_all() применяет статус ко всем элементам."""
        tree.insert("", "end", iid="doc_1", text="📄 Doc1")
        tree.insert("", "end", iid="doc_2", text="📄 Doc2")
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item("doc_1", "📄 Doc1", "synced")
        mgr.register_item("doc_2", "📄 Doc2", "synced")
        mgr.update_all("offline")
        assert "sync_offline" in tree.item("doc_1", "tags")
        assert "sync_offline" in tree.item("doc_2", "tags")
        mgr.unmount()

    def test_set_handle_visible(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """set_handle_visible() добавляет иконку handle в текст."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "synced")
        mgr.set_handle_visible(base_item, True)
        text = tree.item(base_item, "text")
        assert _DRAG_HANDLE_ICON in text
        mgr.set_handle_visible(base_item, False)
        text = tree.item(base_item, "text")
        assert _DRAG_HANDLE_ICON not in text
        mgr.unmount()

    def test_recompose_text_without_handle(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """Текст формируется корректно без видимого handle."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "synced")
        text = tree.item(base_item, "text")
        assert text == "📄 Doc1  ●"
        mgr.unmount()

    def test_recompose_text_with_handle(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """Текст формируется корректно с видимым handle."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "synced")
        mgr.set_handle_visible(base_item, True)
        text = tree.item(base_item, "text")
        assert text == f"{_DRAG_HANDLE_ICON} 📄 Doc1  ●"
        mgr.unmount()

    def test_unmount_clears(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """unmount() удаляет индикаторы и tooltip."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "syncing")
        mgr.unmount()
        assert len(mgr._indicators) == 0

    def test_register_existing_item_updates_text(
        self,
        tree: ttk.Treeview,
        dummy_colors: dict[str, str],
        dummy_icons: dict[str, str],
        base_item: str,
    ) -> None:
        """Повторный register_item обновляет base_text и статус."""
        mgr = SideBarSyncManager(tree, dummy_colors, dummy_icons)
        mgr.register_item(base_item, "📄 Doc1", "synced")
        mgr.register_item(base_item, "🔒 Doc1.enc", "offline")
        text = tree.item(base_item, "text")
        assert "🔒 Doc1.enc" in text
        assert "✗" in text
        mgr.unmount()


# =============================================================================
# TEST: TreeItemDragHandle
# =============================================================================


@pytest.mark.gui
class TestTreeItemDragHandle:
    """Тесты drag handle."""

    def test_motion_callback(
        self,
        tree: ttk.Treeview,
    ) -> None:
        """При движении мыши над элементом callback вызывается."""
        cb = MagicMock()
        tree.insert("", "end", iid="doc_1", text="📄 Doc1")
        drag = TreeItemDragHandle(tree, on_handle_state_change=cb)
        # Имитируем движение мыши над элементом
        bbox = tree.bbox("doc_1")
        if bbox:
            ev = MagicMock()
            ev.x = bbox[0] + bbox[2] // 2
            ev.y = bbox[1] + bbox[3] // 2
            drag._on_tree_motion(ev)  # type: ignore[arg-type]
            cb.assert_called_with("doc_1", True)
        drag.unmount()

    def test_is_handle_active(
        self,
        tree: ttk.Treeview,
    ) -> None:
        """is_handle_active() возвращает True для hovered элемента."""
        cb = MagicMock()
        tree.insert("", "end", iid="doc_1", text="📄 Doc1")
        drag = TreeItemDragHandle(tree, on_handle_state_change=cb)
        # simulate hover
        drag._hovered_item_id = "doc_1"
        assert drag.is_handle_active("doc_1") is True
        assert drag.is_handle_active("doc_2") is False
        drag.unmount()

    def test_leave_callback(
        self,
        tree: ttk.Treeview,
    ) -> None:
        """При уходе мыши из дерева handle скрывается."""
        cb = MagicMock()
        tree.insert("", "end", iid="doc_1", text="📄 Doc1")
        drag = TreeItemDragHandle(tree, on_handle_state_change=cb)
        drag._hovered_item_id = "doc_1"
        drag._on_tree_leave()
        assert drag._hovered_item_id is None
        cb.assert_called_with("doc_1", False)
        drag.unmount()

    def test_unmount_resets_state(
        self,
        tree: ttk.Treeview,
    ) -> None:
        """unmount() сбрасывает hovered_item_id."""
        cb = MagicMock()
        drag = TreeItemDragHandle(tree, on_handle_state_change=cb)
        drag._hovered_item_id = "doc_1"
        drag.unmount()
        assert drag._hovered_item_id is None


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты常量 и tooltip."""

    def test_sync_tooltips_exist(self) -> None:
        """Все статусы имеют tooltip."""
        for status in ("synced", "syncing", "conflict", "offline"):
            assert status in _SYNC_TOOLTIPS

    def test_drag_handle_icon_defined(self) -> None:
        """DRAG_HANDLE_ICON определён."""
        assert _DRAG_HANDLE_ICON == "⋮⋮"

    def test_animation_interval(self) -> None:
        """Интервал анимации положительный."""
        assert SYNC_ANIMATION_INTERVAL > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.sync.side_bar_sync_ui"])
