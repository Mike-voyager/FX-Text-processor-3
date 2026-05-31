"""GUI Factories package for FX Text Processor 3.

Фабричные функции для создания GUI-компонентов с поддержкой DI.
Компоненты создаются через фабрики для обеспечения корректного
внедрения зависимостей и единой конфигурации.

Архитектура:
    Фабрики следуют паттерну Service Layer:
    - Фабрики получают сервисы через DI
    - Фабрики создают Views/Components с внедрёнными сервисами
    - Views НИКОГДА не создают сервисы напрямую

Фабрики в этом модуле:
    - create_sync_indicator: создание индикатора синхронизации
    - create_side_bar_sync_manager: создание SideBar sync менеджера

См. также:
    - src/gui/components/factories/ — фабрики виджетов (FormField и др.)
    - src/gui/workflow/integration.py — WorkflowUIFactory, WorkflowUIBuilder

Version: 1.1
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import tkinter as tk

    from src.gui.components.sync.side_bar_sync_ui import SideBarSyncManager
    from src.gui.components.sync.window_sync_indicator import (
        WindowSyncIndicator,
    )


def create_sync_indicator(
    parent: "tk.Widget",
    widget_id: str = "sync_indicator",
    initial_status: str = "offline",
) -> "WindowSyncIndicator":
    """Создаёт индикатор синхронизации для вкладки или панели.

    Фабричная функция для WindowSyncIndicator с автоматическим
    монтированием в родительский виджет.

    Args:
        parent: Родительский виджет Tkinter.
        widget_id: Идентификатор виджета.
        initial_status: Начальный статус ('synced', 'syncing',
            'conflict', 'offline'). По умолчанию 'offline'.

    Returns:
        WindowSyncIndicator — виджет индикатора синхронизации.

    Example:
        >>> from src.gui.components.sync.window_sync_indicator import SyncStatus
        >>> indicator = create_sync_indicator(parent=frame)
        >>> indicator.set_status(SyncStatus.SYNCED)
    """
    from src.gui.components.sync.window_sync_indicator import (
        SyncStatus,
        WindowSyncIndicator,
    )

    status = initial_status
    if status not in ("synced", "syncing", "conflict", "offline"):
        status = SyncStatus.OFFLINE

    indicator = WindowSyncIndicator(widget_id=widget_id, status=status)
    indicator.mount(parent)
    return indicator


def create_side_bar_sync_manager(
    tree: "tk.ttk.Treeview",
    colors: Optional[dict[str, str]] = None,
    icons: Optional[dict[str, str]] = None,
) -> "SideBarSyncManager":
    """Создаёт менеджер синхронизации для SideBar TreeView.

    Фабричная функция для SideBarSyncManager с настройкой
    цветов и иконок по умолчанию.

    Args:
        tree: Treeview виджет для управления индикаторами.
        colors: Цвета для статусов (synced/syncing/conflict/offline).
        icons: Иконки для статусов.

    Returns:
        SideBarSyncManager — менеджер синхронизации.

    Example:
        >>> manager = create_side_bar_sync_manager(tree)
        >>> manager.register_item("doc_1", base_text="Document 1")
        >>> manager.set_item_status("doc_1", "synced")
    """
    from src.gui.components.sync.side_bar_sync_ui import SideBarSyncManager

    # Стандартные цвета и иконки если не указаны
    if colors is None:
        colors = {
            "synced": "#4CAF50",
            "syncing": "#2196F3",
            "conflict": "#FF9800",
            "offline": "#9E9E9E",
        }
    if icons is None:
        icons = {
            "synced": "●",  # ●
            "syncing": "⟳",  # ⟳
            "conflict": "⚠",  # ⚠
            "offline": "✗",  # ✗
        }

    return SideBarSyncManager(
        tree=tree,
        colors=colors,
        icons=icons,
    )


__all__: list[str] = [
    "create_sync_indicator",
    "create_side_bar_sync_manager",
]

__version__ = "1.1.0"
__author__ = "FX Text Processor Team"
