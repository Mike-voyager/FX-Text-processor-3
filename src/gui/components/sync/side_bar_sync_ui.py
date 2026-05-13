"""SideBar Synchronization UI components.

Реализует визуальные индикаторы синхронизации и drag-and-drop
handle для элементов дерева SideBar.

Components:
    TreeItemSyncIndicator: индикатор статуса синхронизации для
        одного элемента ttk.Treeview с анимацией.
    SideBarSyncManager: управляет индикаторами для всех элементов
        дерева, обновляет текст и теги.
    TreeItemDragHandle: hover-handle "⋮⋮" для элементов дерева.

Example:
    >>> manager = SideBarSyncManager(tree, colors, icons)
    >>> manager.register_item("doc_1", base_text="📄 Doc1")
    >>> manager.set_item_status("doc_1", "synced")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Final, Optional

# =============================================================================
# CONSTANTS
# =============================================================================

SYNC_ANIMATION_INTERVAL: Final[int] = 400
"""Интервал анимации статуса SYNCING (мс)."""

_SYNC_TOOLTIPS: Final[dict[str, str]] = {
    "synced": "Синхронизировано",
    "syncing": "Синхронизация...",
    "conflict": "Конфликт",
    "offline": "Оффлайн",
}
"""Тексты tooltip для статусов синхронизации."""

_DRAG_HANDLE_ICON: Final[str] = "⋮⋮"
"""Иконка drag handle."""


# =============================================================================
# TREE ITEM SYNC INDICATOR
# =============================================================================


class TreeItemSyncIndicator:
    """Индикатор статуса синхронизации для элемента Treeview.

    Управляет отображаемой иконкой и анимацией для статуса SYNCING.
    Не обновляет текст напрямую — делегирует рекомпозицию текста
    через callback `on_animation_step`.

    Attributes:
        status: Текущий статус синхронизации (строка).
        base_text: Базовый текст элемента без иконок.
        current_icon: Текущая отображаемая иконка (может меняться при анимации).

    Example:
        >>> indicator = TreeItemSyncIndicator(
        ...     tree, "doc_1", "📄 Doc1", "synced", colors, icons
        ... )
    """

    def __init__(
        self,
        tree: ttk.Treeview,
        item_id: str,
        base_text: str,
        status: str,
        colors: dict[str, str],
        icons: dict[str, str],
        on_animation_step: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Инициализация индикатора.

        Args:
            tree: Виджет ttk.Treeview.
            item_id: Идентификатор элемента дерева.
            base_text: Базовый текст (без иконок статуса).
            status: Начальный статус синхронизации.
            colors: Словарь {статус: цвет} для тегов.
            icons: Словарь {статус: иконка} для отображения.
            on_animation_step: Callback при смене кадра анимации.
        """
        self._tree = tree
        self._item_id = item_id
        self._base_text = base_text
        self._status = status
        self._colors = colors
        self._icons = icons
        self._on_animation_step = on_animation_step
        self._after_id: Optional[str] = None
        self._anim_frame = 0
        self._current_icon = self._icons.get(status, "")
        self._apply(status)

    @property
    def status(self) -> str:
        """Текущий статус синхронизации."""
        return self._status

    @property
    def base_text(self) -> str:
        """Базовый текст элемента."""
        return self._base_text

    @property
    def current_icon(self) -> str:
        """Текущая иконка (с учётом анимации)."""
        return self._current_icon

    def set_status(self, status: str) -> None:
        """Устанавливает новый статус синхронизации.

        Args:
            status: Новый статус.
        """
        if self._status == status:
            return
        self._cancel_animation()
        self._status = status
        self._current_icon = self._icons.get(status, "")
        self._apply(status)

    def _apply(self, status: str) -> None:
        """Применяет статус (запускает анимацию при необходимости)."""
        if status == "syncing":
            self._start_animation()

    def _start_animation(self) -> None:
        """Запускает цикл анимации SYNCING (отложенный первый шаг)."""
        self._cancel_animation()
        self._current_icon = ""
        self._anim_frame = 0
        self._after_id = self._tree.after(0, self._step_animation)

    def _step_animation(self) -> None:
        """Шаг анимации — смена иконки и планирование следующего шага."""
        if self._status != "syncing":
            return
        frames = ("⟳", "⟲")
        self._current_icon = frames[self._anim_frame % len(frames)]
        self._anim_frame += 1
        if self._on_animation_step is not None:
            self._on_animation_step(self._item_id)
        self._after_id = self._tree.after(
            SYNC_ANIMATION_INTERVAL, self._step_animation
        )

    def _cancel_animation(self) -> None:
        """Отменяет текущую анимацию и сбрасывает счётчик кадров."""
        if self._after_id is not None:
            try:
                self._tree.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        self._anim_frame = 0

    def destroy(self) -> None:
        """Очищает ресурсы индикатора.

        Отменяет отложенные вызовы after().
        """
        self._cancel_animation()


# =============================================================================
# SIDEBAR SYNC MANAGER
# =============================================================================


class SideBarSyncManager:
    """Управляет индикаторами синхронизации для всех элементов дерева.

    Регистрирует элементы, обновляет их статусы и рекомпозирует
    отображаемый текст (sync icon + drag handle).

    Attributes:
        tree: Виджет ttk.Treeview.

    Example:
        >>> manager = SideBarSyncManager(tree, colors, icons)
        >>> manager.register_item("doc_1", "📄 Doc1")
        >>> manager.set_item_status("doc_1", "syncing")
    """

    def __init__(
        self,
        tree: ttk.Treeview,
        colors: dict[str, str],
        icons: dict[str, str],
    ) -> None:
        """Инициализация менеджера.

        Args:
            tree: Виджет ttk.Treeview.
            colors: Словарь {статус: цвет}.
            icons: Словарь {статус: иконка}.
        """
        self._tree = tree
        self._colors = colors
        self._icons = icons
        self._indicators: dict[str, TreeItemSyncIndicator] = {}
        self._handles_visible: dict[str, bool] = {}
        self._tooltip_window: Optional[tk.Toplevel] = None
        self._motion_bind_id: Optional[str] = None
        self._leave_bind_id: Optional[str] = None
        self._configure_tree_tags()
        self._bind_tooltip_tags()

    def _configure_tree_tags(self) -> None:
        """Настраивает теги Treeview с цветами для каждого статуса."""
        if self._tree is None:
            return
        for status, color in self._colors.items():
            tag = f"sync_{status}"
            self._tree.tag_configure(tag, foreground=color)

    def _bind_tooltip_tags(self) -> None:
        """Привязывает tooltip к движению мыши над деревом."""
        if self._tree is None:
            return
        self._motion_bind_id = self._tree.bind("<Motion>", self._on_tooltip_show, add="+")
        self._leave_bind_id = self._tree.bind("<Leave>", self._on_tooltip_hide, add="+")

    def register_item(
        self,
        item_id: str,
        base_text: str,
        status: str = "offline",
    ) -> None:
        """Регистрирует элемент дерева в менеджере.

        Args:
            item_id: Идентификатор элемента.
            base_text: Базовый текст (без иконок).
            status: Начальный статус (default: offline).
        """
        if item_id in self._indicators:
            self._indicators[item_id]._base_text = base_text
            self.set_item_status(item_id, status)
            return
        indicator = TreeItemSyncIndicator(
            self._tree,
            item_id,
            base_text,
            status,
            self._colors,
            self._icons,
            on_animation_step=self._recompose_text,
        )
        self._indicators[item_id] = indicator
        self._recompose_text(item_id)

    def set_item_status(self, item_id: str, status: str) -> None:
        """Устанавливает статус для элемента.

        Args:
            item_id: Идентификатор элемента.
            status: Новый статус.
        """
        if item_id not in self._indicators:
            return
        self._indicators[item_id].set_status(status)
        self._recompose_text(item_id)

    def clear_item_status(self, item_id: str) -> None:
        """Сбрасывает статус элемента в offline.

        Args:
            item_id: Идентификатор элемента.
        """
        self.set_item_status(item_id, "offline")

    def update_all(self, status: str) -> None:
        """Обновляет статус всех зарегистрированных элементов.

        Args:
            status: Новый статус.
        """
        for item_id in list(self._indicators.keys()):
            self.set_item_status(item_id, status)

    def set_handle_visible(self, item_id: str, visible: bool) -> None:
        """Устанавливает видимость drag handle для элемента.

        Args:
            item_id: Идентификатор элемента.
            visible: True для отображения handle.
        """
        current = self._handles_visible.get(item_id, False)
        if current == visible:
            return
        self._handles_visible[item_id] = visible
        self._recompose_text(item_id)

    def _recompose_text(self, item_id: str) -> None:
        """Рекомпозирует текст элемента дерева.

        Args:
            item_id: Идентификатор элемента.
        """
        if self._tree is None or item_id not in self._indicators:
            return
        indicator = self._indicators[item_id]
        handle = f"{_DRAG_HANDLE_ICON} " if self._handles_visible.get(item_id) else ""
        icon = indicator.current_icon
        if icon:
            text = f"{handle}{indicator.base_text}  {icon}"
            tag = f"sync_{indicator.status}"
        else:
            text = f"{handle}{indicator.base_text}"
            tag = ""
        tags = (tag,) if tag else ()
        self._tree.item(item_id, text=text, tags=tags)

    def _on_tooltip_show(self, event: tk.Event[Any]) -> None:
        """Показывает tooltip при наведении на элемент со статусом."""
        if self._tooltip_window is not None:
            return
        if self._tree is None:
            return
        item_id = self._tree.identify_row(event.y)
        if not item_id or item_id not in self._indicators:
            return
        status = self._indicators[item_id].status
        if status == "offline":
            return
        tip_text = _SYNC_TOOLTIPS.get(status, status)
        toplevel = self._tree.winfo_toplevel()
        self._tooltip_window = tk.Toplevel(toplevel)
        self._tooltip_window.wm_overrideredirect(True)
        # event.x/y относительно tree; переводим в абсолютные
        x = self._tree.winfo_rootx() + event.x + 12
        y = self._tree.winfo_rooty() + event.y + 12
        self._tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self._tooltip_window,
            text=tip_text,
            bg="white",
            fg="black",
            relief="solid",
            bd=1,
            font=("Helvetica", 9),
        )
        label.pack()

    def _on_tooltip_hide(self, event: Optional[tk.Event[Any]] = None) -> None:
        """Скрывает tooltip."""
        if self._tooltip_window is not None:
            self._tooltip_window.destroy()
            self._tooltip_window = None

    def clear(self) -> None:
        """Очищает все зарегистрированные элементы и ресурсы."""
        for indicator in list(self._indicators.values()):
            indicator.destroy()
        self._indicators.clear()
        self._handles_visible.clear()
        self._on_tooltip_hide()

    def unmount(self) -> None:
        """Демонтирует менеджер, очищая все after() и tooltip."""
        self.clear()
        if self._tree is not None:
            if self._motion_bind_id is not None:
                try:
                    self._tree.unbind("<Motion>", self._motion_bind_id)
                except (tk.TclError, TypeError):
                    pass
                self._motion_bind_id = None
            if self._leave_bind_id is not None:
                try:
                    self._tree.unbind("<Leave>", self._leave_bind_id)
                except (tk.TclError, TypeError):
                    pass
                self._leave_bind_id = None


# =============================================================================
# TREE ITEM DRAG HANDLE
# =============================================================================


class TreeItemDragHandle:
    """Визуальный drag handle "⋮⋮" для элементов Treeview.

    Отслеживает hover-состояние и уведомляет через callback
    `on_handle_state_change`. Сам не запускает drag — решение
    принимает вызывающая сторона (SideBar).

    Attributes:
        hovered_item_id: Идентификатор элемента под курсором (или None).

    Example:
        >>> handle = TreeItemDragHandle(tree, on_handle_state_change=cb)
    """

    def __init__(
        self,
        tree: ttk.Treeview,
        on_handle_state_change: Callable[[str, bool], None],
    ) -> None:
        """Инициализация drag handle.

        Args:
            tree: Виджет ttk.Treeview.
            on_handle_state_change: Callback(item_id, visible).
        """
        self._tree = tree
        self._on_handle_state_change = on_handle_state_change
        self._hovered_item_id: Optional[str] = None
        self._tree.bind("<Motion>", self._on_tree_motion)
        self._tree.bind("<Leave>", self._on_tree_leave)

    def is_handle_active(self, item_id: str) -> bool:
        """Проверяет, активен ли handle для элемента.

        Args:
            item_id: Идентификатор элемента.

        Returns:
            True если курсор находится над handle-зоной элемента.
        """
        return self._hovered_item_id == item_id

    def _on_tree_motion(self, event: tk.Event[Any]) -> None:
        """Обрабатывает движение мыши над деревом."""
        if self._tree is None:
            return
        item_id = self._tree.identify_row(event.y)
        if item_id == self._hovered_item_id:
            return
        old_id = self._hovered_item_id
        self._hovered_item_id = item_id if item_id else None
        if old_id is not None:
            self._on_handle_state_change(old_id, False)
        if self._hovered_item_id is not None:
            self._on_handle_state_change(self._hovered_item_id, True)

    def _on_tree_leave(self, event: Optional[tk.Event[Any]] = None) -> None:
        """Обрабатывает выход мыши из области дерева."""
        old_id = self._hovered_item_id
        self._hovered_item_id = None
        if old_id is not None:
            self._on_handle_state_change(old_id, False)

    def unmount(self) -> None:
        """Снимает bindings и очищает состояние."""
        if self._tree is not None:
            self._tree.unbind("<Motion>")
            self._tree.unbind("<Leave>")
        self._hovered_item_id = None


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "SYNC_ANIMATION_INTERVAL",
    "_SYNC_TOOLTIPS",
    "_DRAG_HANDLE_ICON",
    "TreeItemSyncIndicator",
    "SideBarSyncManager",
    "TreeItemDragHandle",
]

__version__: Final[str] = "1.0"
__author__: Final[str] = "FX Text Processor Team"
__date__: Final[str] = "May 2026"
