"""Drag-and-drop сервис для GUI.

Предоставляет централизованное управление операциями перетаскивания
между виджетами и окнами.

Classes:
    DragData: Данные drag-операции.
    DropOperation: Возможные операции drop.
    DropTarget: Целевая зона для drop.
    DragDropService: Сервис drag-and-drop.

Example:
    >>> dds = DragDropService(window_manager, sync_service)
    >>> dds.start_drag("win_001", {"type": "text"})

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Collection, Final, Optional

from src.gui.services.sync_service import SyncService
from src.gui.services.window_manager import WindowManager

# =============================================================================
# CONSTANTS
# =============================================================================

DATA_TYPE_DOCUMENT: Final[str] = "document"
DATA_TYPE_FIELD: Final[str] = "field"
DATA_TYPE_TEMPLATE: Final[str] = "template"
DATA_TYPE_TEXT: Final[str] = "text"

# =============================================================================
# ENUMS
# =============================================================================


class DropOperation(str, Enum):
    """Операции, доступные при drop."""

    COPY = "copy"
    MOVE = "move"
    LINK = "link"


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class DragData:
    """Данные drag-операции.

    Attributes:
        source_window_id: ID окна-источника.
        data_type: Тип данных (DATA_TYPE_*).
        data: Полезная нагрузка.
        preview_text: Текст превью.
        allowed_operations: Разрешённые операции.
        field_type: Тип поля (legacy).
        start_x: Начальная X-координата (legacy).
        start_y: Начальная Y-координата (legacy).
    """

    source_window_id: Optional[str] = None
    data_type: Optional[str] = None
    data: Optional[dict[str, Any]] = None
    preview_text: Optional[str] = None
    allowed_operations: Optional[list[DropOperation]] = None
    field_type: Optional[Any] = None
    start_x: Optional[int] = None
    start_y: Optional[int] = None


@dataclass
class DropTarget:
    """Целевая зона для drop.

    Attributes:
        target_id: Уникальный идентификатор цели.
        widget: Виджет Tkinter.
        accepted_types: Коллекция принимаемых типов данных.
        accepted_operations: Коллекция принимаемых операций.
        on_drop: Callback при drop.
    """

    target_id: str
    widget: tk.Widget
    accepted_types: Collection[str] = field(default_factory=list)
    accepted_operations: Collection[DropOperation] = field(default_factory=list)
    on_drop: Callable[..., None] = field(default_factory=lambda: lambda *args, **kwargs: None)


# =============================================================================
# SERVICE
# =============================================================================


class DragDropService:
    """Сервис drag-and-drop операций.

    Управляет началом drag, регистрацией целей drop и отменой операций.

    Example:
        >>> dds = DragDropService(window_manager, sync_service)
        >>> dds.is_dragging()
        False
    """

    def __init__(
        self,
        root: Optional[tk.Tk] = None,
        window_manager: Optional[WindowManager] = None,
        sync_service: Optional[SyncService] = None,
    ) -> None:
        """Инициализация сервиса.

        Args:
            root: Корневое окно Tkinter (опционально).
            window_manager: Менеджер окон (опционально).
            sync_service: Сервис синхронизации (опционально).
        """
        self._root: Optional[tk.Tk] = root
        self._window_manager: Optional[WindowManager] = window_manager
        self._sync_service: Optional[SyncService] = sync_service
        self._dragging: bool = False
        self._drag_data: Optional[Any] = None
        self._source_window_id: Optional[str] = None
        self._drop_targets: dict[str, DropTarget] = {}
        self._ghost_window: Optional[tk.Toplevel] = None
        self._current_target_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def start_drag(self, source_window_id: str, data: Any) -> None:
        """Начинает операцию перетаскивания.

        Args:
            source_window_id: ID окна-источника.
            data: Данные drag-операции.
        """
        if self._dragging:
            self.cancel_drag()
        self._dragging = True
        self._source_window_id = source_window_id
        self._drag_data = data
        self._create_ghost_window()
        if self._sync_service is not None:
            self._sync_service.broadcast(
                source_window_id,
                "drag_start",
                {"data_type": getattr(data, "data_type", None)},
            )

    def register_drop_target(self, widget: tk.Widget, target: DropTarget) -> str:
        """Регистрирует виджет как целевую зону.

        Args:
            widget: Виджет Tkinter.
            target: Объект цели drop.

        Returns:
            Идентификатор целевой зоны.
        """
        target_id = target.target_id or f"drop_target_{id(target)}"
        self._drop_targets[target_id] = target
        return target_id

    def unregister_drop_target(self, target_id: str) -> None:
        """Удаляет регистрацию целевой зоны.

        Args:
            target_id: Идентификатор цели.

        Raises:
            KeyError: Если цель с указанным ID не найдена.
        """
        if target_id not in self._drop_targets:
            raise KeyError(f"target '{target_id}' not found")
        del self._drop_targets[target_id]

    def is_dragging(self) -> bool:
        """Проверяет, выполняется ли drag.

        Returns:
            True если drag активен.
        """
        return self._dragging

    def cancel_drag(self) -> None:
        """Отменяет текущую drag-операцию."""
        if not self._dragging:
            return
        self._destroy_ghost_window()
        source_window_id = self._source_window_id
        self._dragging = False
        self._drag_data = None
        self._source_window_id = None
        self._current_target_id = None
        if self._sync_service is not None and source_window_id is not None:
            self._sync_service.broadcast(
                source_window_id,
                "drag_cancel",
                {},
            )

    def get_drag_data(self) -> Optional[Any]:
        """Возвращает текущие данные drag-операции.

        Returns:
            Данные drag или None если drag не активен.
        """
        return self._drag_data if self._dragging else None

    def is_target_registered(self, target_id: str) -> bool:
        """Проверяет, зарегистрирована ли целевая зона.

        Args:
            target_id: Идентификатор цели.

        Returns:
            True если цель зарегистрирована.
        """
        return target_id in self._drop_targets

    def drop(self, target_id: str) -> bool:
        """Выполняет drop на указанную цель.

        Args:
            target_id: Идентификатор целевой зоны.

        Returns:
            True если drop выполнен успешно.
        """
        if not self._dragging:
            return False

        target = self._drop_targets.get(target_id)
        if target is None:
            return False

        if not self._can_drop_on_target(target):
            return False

        on_drop: Any = getattr(target, "on_drop", None)
        if on_drop is None:
            return False

        try:
            result = on_drop(self._drag_data)
        except TypeError:
            dummy_event: Any = type(
                "DummyEvent",
                (),
                {"x": 0, "y": 0, "x_root": 0, "y_root": 0},
            )()
            try:
                result = on_drop(self._drag_data, target.widget, dummy_event)
            except TypeError:
                return False

        self._dragging = False
        self._drag_data = None
        self._destroy_ghost_window()
        source_window_id = self._source_window_id
        self._source_window_id = None
        self._current_target_id = None

        if self._sync_service is not None and source_window_id is not None:
            self._sync_service.broadcast(
                source_window_id,
                "drag_drop",
                {"target_id": target_id},
            )

        return bool(result) if result is not None else True

    def update_feedback(self, x: int, y: int, target_widget: tk.Widget) -> None:
        """Обновляет визуальную обратную связь при перемещении курсора.

        Args:
            x: X-координата курсора.
            y: Y-координата курсора.
            target_widget: Виджет под курсором.
        """
        target: Optional[DropTarget] = None
        for t in self._drop_targets.values():
            if t.widget is target_widget:
                target = t
                break

        if target is None:
            self._show_drop_denied_indicator()
            self._set_cursor("no")
            return

        if self._can_drop_on_target(target):
            self._show_drop_allowed_indicator()
            self._set_cursor("hand2")
        else:
            self._show_drop_denied_indicator()
            self._set_cursor("no")

    def get_drop_target_count(self) -> int:
        """Возвращает количество зарегистрированных целей drop.

        Returns:
            Количество целей.
        """
        return len(self._drop_targets)

    def clear_drop_targets(self) -> None:
        """Удаляет все зарегистрированные цели drop."""
        self._drop_targets.clear()

    # ------------------------------------------------------------------
    # Внутренние методы
    # ------------------------------------------------------------------

    def _can_drop_on_target(self, target: DropTarget) -> bool:
        """Проверяет, можно ли выполнить drop на указанную цель.

        Args:
            target: Целевая зона.

        Returns:
            True если drop возможен.
        """
        if not self._dragging or self._drag_data is None:
            return False

        data_type = getattr(self._drag_data, "data_type", None)
        accepted_types = getattr(target, "accepted_types", None)
        if accepted_types is not None and data_type is not None:
            if data_type not in accepted_types:
                return False

        operations = getattr(self._drag_data, "operations", None)
        if operations is None:
            operations = getattr(self._drag_data, "allowed_operations", None)
        accepted_operations = getattr(target, "accepted_operations", None)
        if accepted_operations is not None and operations is not None:
            if not any(op in accepted_operations for op in operations):
                return False

        return True

    def _create_ghost_window(self) -> None:
        """Создаёт ghost окно для визуальной обратной связи."""
        pass

    def _destroy_ghost_window(self) -> None:
        """Уничтожает ghost окно."""
        pass

    def _set_cursor(self, cursor: str) -> None:
        """Устанавливает курсор мыши.

        Args:
            cursor: Имя курсора Tkinter.
        """
        pass

    def _show_drop_allowed_indicator(self) -> None:
        """Показывает индикатор разрешённого drop."""
        pass

    def _show_drop_denied_indicator(self) -> None:
        """Показывает индикатор запрещённого drop."""
        pass

    def _on_target_enter(self, target_id: str) -> None:
        """Вызывает callback при входе курсора в целевую зону.

        Args:
            target_id: Идентификатор цели.
        """
        target = self._drop_targets.get(target_id)
        if target is not None:
            on_enter: Any = getattr(target, "on_enter", None)
            if on_enter is not None:
                on_enter()

    def _on_target_leave(self, target_id: str) -> None:
        """Вызывает callback при выходе курсора из целевой зоны.

        Args:
            target_id: Идентификатор цели.
        """
        target = self._drop_targets.get(target_id)
        if target is not None:
            on_leave: Any = getattr(target, "on_leave", None)
            if on_leave is not None:
                on_leave()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "DATA_TYPE_DOCUMENT",
    "DATA_TYPE_FIELD",
    "DATA_TYPE_TEMPLATE",
    "DATA_TYPE_TEXT",
    "DragData",
    "DragDropService",
    "DropOperation",
    "DropTarget",
]
