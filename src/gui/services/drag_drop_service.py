"""Сервис drag-and-drop для межоконных операций FX Text Processor 3.

Реализует inter-window drag-and-drop с поддержкой ghost window,
реестра целевых зон и типизированных данных. Обеспечивает визуальную
обратную связь и отмену операции.

Data Types:
    - DATA_TYPE_FIELD: Поле формы для конструктора
    - DATA_TYPE_DOCUMENT: Документ для открытия/переноса
    - DATA_TYPE_TEMPLATE: Шаблон документа
    - DATA_TYPE_TEXT: Текстовые данные

Operations:
    - OPERATION_MOVE: Перемещение данных
    - OPERATION_COPY: Копирование данных
    - OPERATION_LINK: Создание ссылки на данные

Example:
    >>> from src.gui.services.drag_drop_service import (
    ...     DragDropService, DragData, DropTarget,
    ...     DATA_TYPE_FIELD, OPERATION_MOVE
    ... )
    >>> from src.gui.services.window_manager import WindowManager
    >>> from src.gui.services.sync_service import SyncService
    >>> wm = WindowManager(root)
    >>> sync = SyncService(wm)
    >>> dds = DragDropService(root, wm, sync)
    >>> # Регистрация целевой зоны
    >>> target = DropTarget(
    ...     target_id="canvas_main",
    ...     widget=canvas,
    ...     accepted_types=(DATA_TYPE_FIELD,),
    ...     accepted_operations=(OPERATION_MOVE, OPERATION_COPY),
    ...     on_drop=lambda data, x, y: print(f"Drop at ({x}, {y})")
    ... )
    >>> tid = dds.register_drop_target(canvas, target)
    >>> # Начало drag
    >>> data = DragData(
    ...     source_window_id="win_001",
    ...     data_type=DATA_TYPE_FIELD,
    ...     data={"field_type": "text"},
    ...     preview_text="Текстовое поле",
    ...     allowed_operations=(OPERATION_MOVE, OPERATION_COPY)
    ... )
    >>> dds.start_drag("win_001", data)

Version: 1.0
Date: April 11, 2026
Priority: MEDIUM (Phase 7)
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Final, Optional

from src.gui.services.sync_service import SyncService
from src.gui.services.window_manager import WindowManager

# =============================================================================
# DROP OPERATION ENUM
# =============================================================================


class DropOperation(Enum):
    """Операции перетаскивания.

    Определяет, что должно произойти с данными при drop:
    перемещение, копирование или создание ссылки.

    Attributes:
        MOVE: Переместить данные из источника в цель.
        COPY: Скопировать данные (источник сохраняет оригинал).
        LINK: Создать ссылку на данные (без копирования).

    Example:
        >>> ops = {DropOperation.MOVE, DropOperation.COPY}
        >>> if DropOperation.MOVE in ops:
        ...     print("Move allowed")
    """

    MOVE = "move"
    COPY = "copy"
    LINK = "link"


# =============================================================================
# DATA TYPE CONSTANTS
# =============================================================================

DATA_TYPE_FIELD: Final[str] = "field"
"""Тип данных: поле формы (для FormConstructor)."""

DATA_TYPE_DOCUMENT: Final[str] = "document"
"""Тип данных: документ (.fxsd файл)."""

DATA_TYPE_TEMPLATE: Final[str] = "template"
"""Тип данных: шаблон документа (.fxstpl файл)."""

DATA_TYPE_TEXT: Final[str] = "text"
"""Тип данных: произвольный текст."""

# =============================================================================
# OPERATION CONSTANTS
# =============================================================================

# Операции теперь определены через DropOperation Enum
# DropOperation.MOVE, DropOperation.COPY, DropOperation.LINK

# =============================================================================
# DRAG DATA
# =============================================================================


@dataclass(frozen=True)
class DragData:
    """Данные для операции перетаскивания.

    Immutable dataclass, создаётся при старте drag и передаётся
    в целевую зону при drop. Содержит всю информацию о перетаскиваемых
    данных и разрешённых операциях.

    Attributes:
        source_window_id: Идентификатор окна-источника.
        data_type: Тип данных (DATA_TYPE_* константа).
        data: Полезная нагрузка (специфична для типа данных).
        preview_text: Текст для отображения в ghost window.
        allowed_operations: frozenset разрешённых операций (DropOperation).

    Example:
        >>> data = DragData(
        ...     source_window_id="win_001",
        ...     data_type=DATA_TYPE_FIELD,
        ...     data={"field_type": "text", "label": "Имя"},
        ...     preview_text="Поле: Имя",
        ...     allowed_operations=frozenset({DropOperation.MOVE, DropOperation.COPY})
        ... )
    """

    source_window_id: str = ""
    data_type: str = ""
    data: Any = None
    preview_text: str = ""
    allowed_operations: frozenset[DropOperation] = field(
        default_factory=lambda: frozenset({DropOperation.MOVE})
    )
    # Legacy attributes for field palette compatibility
    field_type: Any = None
    start_x: int = 0
    start_y: int = 0


# =============================================================================
# DROP TARGET
# =============================================================================


@dataclass(frozen=True)
class DropTarget:
    """Целевая зона для операции drop.

    Immutable dataclass, регистрируется виджетом как потенциальная
    цель для перетаскивания. Содержит критерии приёма и callback
    для обработки drop.

    Attributes:
        target_id: Уникальный идентификатор целевой зоны.
        widget: Ссылка на Tkinter виджет-цель.
        accepted_types: Кортеж принимаемых типов данных (DATA_TYPE_*).
        accepted_operations: frozenset принимаемых операций (DropOperation).
        on_drop: Callback для обработки drop (data, x, y).

    Example:
        >>> target = DropTarget(
        ...     target_id="canvas_001",
        ...     widget=canvas_widget,
        ...     accepted_types=(DATA_TYPE_FIELD, DATA_TYPE_TEXT),
        ...     accepted_operations=(OPERATION_MOVE, OPERATION_COPY),
        ...     on_drop=lambda data, x, y: print(f"Dropped at ({x}, {y})")
        ... )
    """

    target_id: str
    widget: tk.Widget
    accepted_types: tuple[str, ...]
    accepted_operations: frozenset[DropOperation]
    on_drop: Callable[[DragData, int, int], None]


# =============================================================================
# DRAG-DROP SERVICE
# =============================================================================


class DragDropService:
    """Сервис межоконного drag-and-drop.

    Управляет операциями перетаскивания между виджетами и окнами.
    Создаёт ghost window для визуальной обратной связи, отслеживает
    положение курсора и обрабатывает drop на зарегистрированные цели.

    Attributes:
        _root: Главное окно приложения (tk.Tk).
        _window_manager: Менеджер окон для получения информации об окнах.
        _sync_service: Сервис синхронизации для broadcast событий.
        _drag_data: Текущие данные drag (None если не активен).
        _ghost_window: Ghost window для визуализации drag.
        _drop_targets: Словарь зарегистрированных целей {target_id: DropTarget}.
        _current_operation: Текущая выбранная операция (move/copy/link).
        _is_dragging: Флаг активности drag операции.
        _drag_bindings: Сохранённые binding ID для последующего unbind.

    Example:
        >>> wm = WindowManager(root)
        >>> sync = SyncService(wm)
        >>> dds = DragDropService(root, wm, sync)
        >>> # Регистрация цели
        >>> target = DropTarget(...)
        >>> tid = dds.register_drop_target(widget, target)
        >>> # Drag
        >>> dds.start_drag("win_001", drag_data)
        >>> dds.is_dragging()
        True
        >>> dds.cancel_drag()
    """

    def __init__(
        self,
        root: tk.Tk,
        window_manager: WindowManager,
        sync_service: SyncService,
    ) -> None:
        """Инициализирует сервис drag-and-drop.

        Args:
            root: Главное окно приложения (tk.Tk).
            window_manager: Менеджер окон для межоконных операций.
            sync_service: Сервис синхронизации для broadcast событий.

        Example:
            >>> wm = WindowManager(root)
            >>> sync = SyncService(wm)
            >>> dds = DragDropService(root, wm, sync)
        """
        self._root: tk.Tk = root
        self._window_manager: WindowManager = window_manager
        self._sync_service: SyncService = sync_service

        self._drag_data: Optional[DragData] = None
        self._ghost_window: Optional[tk.Toplevel] = None
        self._drop_targets: dict[str, DropTarget] = {}
        self._current_operation: DropOperation = DropOperation.MOVE
        self._is_dragging: bool = False

        # Binding IDs для последующего unbind
        self._motion_binding: Optional[str] = None
        self._release_binding: Optional[str] = None
        self._escape_binding: Optional[str] = None

    def start_drag(self, source_window_id: str, data: DragData) -> None:
        """Начинает операцию перетаскивания.

        Создаёт ghost window, регистрирует глобальные обработчики
        событий и устанавливает режим drag. Отправляет broadcast
        событие о начале drag через SyncService.

        Args:
            source_window_id: Идентификатор окна-источника.
            data: Данные для перетаскивания (DragData).

        Raises:
            RuntimeError: Если drag уже активен.

        Example:
            >>> data = DragData(
            ...     source_window_id="win_001",
            ...     data_type=DATA_TYPE_FIELD,
            ...     data={"field_type": "text"},
            ...     preview_text="Поле ввода",
            ...     allowed_operations=(OPERATION_MOVE, OPERATION_COPY)
            ... )
            >>> dds.start_drag("win_001", data)

        Security:
            Данные drag-and-drop не шифруются в процессе перетаскивания.
            Не используйте для передачи sensitive данных без шифрования.
        """
        if self._is_dragging:
            raise RuntimeError("Drag операция уже активна, используйте cancel_drag()")

        self._drag_data = data
        default_op = DropOperation.MOVE
        self._current_operation = (
            next(iter(data.allowed_operations)) if data.allowed_operations else default_op
        )
        self._is_dragging = True

        # Создаём ghost window
        self._create_ghost_window(data.preview_text)

        # Регистрируем глобальные обработчики
        self._bind_drag_events()

        # Обновляем курсор
        self._root.config(cursor="fleur")

        # Broadcast через SyncService
        self._sync_service.broadcast(
            source_window_id=source_window_id,
            data_type="drag_start",
            data={
                "data_type": data.data_type,
                "preview_text": data.preview_text,
                "allowed_operations": data.allowed_operations,
            },
        )

    def register_drop_target(self, widget: tk.Widget, target: DropTarget) -> str:
        """Регистрирует виджет как целевую зону для drop.

        Добавляет DropTarget в реестр сервиса. Целевая зона будет
        проверяться при каждом drop событии на соответствие типа
        данных и операции.

        Args:
            widget: Tkinter виджет для регистрации (хранится в target).
            target: Объект DropTarget с критериями приёма и callback.

        Returns:
            Идентификатор целевой зоны (target_id).

        Raises:
            ValueError: Если target_id уже существует.

        Example:
            >>> target = DropTarget(
            ...     target_id="canvas_001",
            ...     widget=canvas,
            ...     accepted_types=(DATA_TYPE_FIELD,),
            ...     accepted_operations=(OPERATION_MOVE,),
            ...     on_drop=on_field_dropped
            ... )
            >>> tid = dds.register_drop_target(canvas, target)
        """
        if target.target_id in self._drop_targets:
            raise ValueError(f"Целевая зона с ID '{target.target_id}' уже существует")

        self._drop_targets[target.target_id] = target
        return target.target_id

    def unregister_drop_target(self, target_id: str) -> None:
        """Удаляет регистрацию целевой зоны.

        Args:
            target_id: Идентификатор целевой зоны.

        Raises:
            KeyError: Если target_id не найден.

        Example:
            >>> dds.unregister_drop_target("canvas_001")
        """
        if target_id not in self._drop_targets:
            raise KeyError(f"Целевая зона с ID '{target_id}' не найдена")

        del self._drop_targets[target_id]

    def is_dragging(self) -> bool:
        """Проверяет, выполняется ли операция перетаскивания.

        Returns:
            True если drag активен.

        Example:
            >>> if dds.is_dragging():
            ...     print("Drag in progress...")
        """
        return self._is_dragging

    def get_drag_data(self) -> Optional[DragData]:
        """Возвращает текущие данные drag.

        Returns:
            Текущие DragData или None если drag не активен.

        Example:
            >>> data = dds.get_drag_data()
            >>> if data:
            ...     print(f"Dragging: {data.preview_text}")
        """
        return self._drag_data

    def cancel_drag(self) -> None:
        """Отменяет текущую операцию перетаскивания.

        Очищает ресурсы ghost window, снимает обработчики событий
        и сбрасывает состояние drag. Отправляет broadcast событие
        об отмене через SyncService.

        Example:
            >>> dds.cancel_drag()
            >>> assert not dds.is_dragging()
        """
        if not self._is_dragging:
            return

        # Broadcast отмены
        if self._drag_data is not None:
            self._sync_service.broadcast(
                source_window_id=self._drag_data.source_window_id,
                data_type="drag_cancel",
                data={"data_type": self._drag_data.data_type},
            )

        self._cleanup_drag()

    def update_feedback(self, can_drop: bool) -> None:
        """Обновляет визуальную обратную связь (курсор).

        Изменяет форму курсора в зависимости от возможности drop
        в текущей позиции.

        Args:
            can_drop: True если drop возможен в текущей позиции.

        Example:
            >>> # При проверке целевой зоны
            >>> can_drop = self._check_can_drop(target)
            >>> dds.update_feedback(can_drop)
        """
        if not self._is_dragging:
            return

        cursor = "exchange" if can_drop else "no"
        self._root.config(cursor=cursor)

    def set_operation(self, operation: DropOperation) -> None:
        """Устанавливает текущую операцию перетаскивания.

        Проверяет, что операция разрешена для текущих drag данных.

        Args:
            operation: Операция (DropOperation.MOVE, DropOperation.COPY, DropOperation.LINK).

        Raises:
            RuntimeError: Если нет активного drag.
            ValueError: Если операция не разрешена.

        Example:
            >>> dds.set_operation(DropOperation.COPY)
        """
        if not self._is_dragging:
            raise RuntimeError("Нет активного drag для установки операции")

        if self._drag_data is None:
            raise RuntimeError("Drag данные отсутствуют")

        if operation not in self._drag_data.allowed_operations:
            raise ValueError(f"Операция '{operation}' не разрешена для текущих данных")

        self._current_operation = operation

    def get_current_operation(self) -> DropOperation:
        """Возвращает текущую операцию перетаскивания.

        Returns:
            Текущая операция (DropOperation.MOVE, DropOperation.COPY, DropOperation.LINK).

        Example:
            >>> op = dds.get_current_operation()
            >>> print(f"Current operation: {op}")
        """
        return self._current_operation

    def _create_ghost_window(self, preview_text: str) -> None:
        """Создаёт ghost window для визуализации drag.

        Args:
            preview_text: Текст для отображения в ghost window.
        """
        self._ghost_window = tk.Toplevel(self._root)
        self._ghost_window.wm_overrideredirect(True)
        self._ghost_window.attributes("-alpha", 0.7)
        self._ghost_window.attributes("-topmost", True)

        # Фрейм с содержимым
        frame = tk.Frame(
            self._ghost_window,
            bg="#4a90d9",
            padx=15,
            pady=10,
            relief=tk.RAISED,
            bd=2,
        )
        frame.pack()

        # Иконка drag
        icon_label = tk.Label(
            frame,
            text="🖐️",
            font=("Segoe UI Emoji", 20),
            bg="#4a90d9",
        )
        icon_label.pack()

        # Текст превью
        text_label = tk.Label(
            frame,
            text=preview_text,
            font=("Helvetica", 9, "bold"),
            bg="#4a90d9",
            fg="white",
            wraplength=150,
        )
        text_label.pack()

        # Начальная позиция (скрыто)
        self._ghost_window.wm_geometry("+0+0")
        self._ghost_window.withdraw()

    def _bind_drag_events(self) -> None:
        """Регистрирует глобальные обработчики событий для drag."""
        self._motion_binding = self._root.bind("<Motion>", self._on_drag_motion, add="+")
        self._release_binding = self._root.bind("<ButtonRelease-1>", self._on_drag_release, add="+")
        self._escape_binding = self._root.bind("<Escape>", self._on_escape, add="+")

    def _unbind_drag_events(self) -> None:
        """Снимает глобальные обработчики событий drag."""
        if self._motion_binding is not None:
            self._root.unbind("<Motion>", self._motion_binding)
            self._motion_binding = None

        if self._release_binding is not None:
            self._root.unbind("<ButtonRelease-1>", self._release_binding)
            self._release_binding = None

        if self._escape_binding is not None:
            self._root.unbind("<Escape>", self._escape_binding)
            self._escape_binding = None

    def _on_drag_motion(self, event: tk.Event[Any]) -> None:
        """Обработчик движения мыши во время drag.

        Args:
            event: Событие движения мыши.
        """
        if self._ghost_window is None:
            return

        # Показываем окно при первом движении
        if self._ghost_window.state() == "withdrawn":
            self._ghost_window.deiconify()

        # Обновляем позицию ghost window (смещаем для центрирования)
        x = event.x_root - 40
        y = event.y_root - 40
        self._ghost_window.wm_geometry(f"+{x}+{y}")

        # Проверяем возможность drop под курсором для обратной связи
        target = self._find_target_at(event.x_root, event.y_root)
        if target is not None:
            self.update_feedback(True)
        else:
            self.update_feedback(False)

    def _on_drag_release(self, event: tk.Event[Any]) -> None:
        """Обработчик отпускания кнопки мыши (drop).

        Args:
            event: Событие отпускания кнопки мыши.
        """
        if not self._is_dragging or self._drag_data is None:
            return

        # Ищем целевую зону под курсором
        target = self._find_target_at(event.x_root, event.y_root)

        if target is not None:
            # Проверяем соответствие типа данных
            if self._drag_data.data_type not in target.accepted_types:
                target = None
            # Проверяем соответствие операции
            elif self._current_operation not in target.accepted_operations:
                target = None

        if target is not None:
            # Вычисляем относительные координаты для целевого виджета
            rel_x = event.x_root - target.widget.winfo_rootx()
            rel_y = event.y_root - target.widget.winfo_rooty()

            # Вызываем callback целевой зоны
            try:
                target.on_drop(self._drag_data, rel_x, rel_y)
            except (KeyError, ValueError, TypeError) as e:  # noqa: S110
                # Игнорируем ошибки callback для стабильности
                logging.getLogger(__name__).exception("Exception ignored in drop callback: %s", e)


            # Broadcast успешного drop
            self._sync_service.broadcast(
                source_window_id=self._drag_data.source_window_id,
                data_type="drag_drop",
                data={
                    "data_type": self._drag_data.data_type,
                    "target_id": target.target_id,
                    "operation": self._current_operation,
                },
            )

        self._cleanup_drag()

    def _on_escape(self, event: tk.Event[Any]) -> None:
        """Обработчик нажатия Escape для отмены drag.

        Args:
            event: Событие нажатия клавиши.
        """
        self.cancel_drag()

    def _find_target_at(self, x: int, y: int) -> Optional[DropTarget]:
        """Находит целевую зону под указанными координатами.

        Args:
            x: X координата экрана.
            y: Y координата экрана.

        Returns:
            DropTarget или None если цель не найдена.
        """
        # Находим виджет под курсором
        try:
            widget = self._root.winfo_containing(x, y)
        except tk.TclError:
            return None

        if widget is None:
            return None

        # Ищем зарегистрированную цель
        for target in self._drop_targets.values():
            # Прямое совпадение
            if target.widget == widget:
                return target

            # Проверяем, является ли виджет потомком цели
            parent: Any = widget
            while parent is not None and isinstance(parent, tk.Widget):
                if parent == target.widget:
                    return target
                try:
                    parent_name = parent.winfo_parent()
                    if parent_name:
                        parent = parent.nametowidget(parent_name)
                    else:
                        break
                except (tk.TclError, AttributeError):
                    break

        return None

    def _cleanup_drag(self) -> None:
        """Очищает ресурсы drag операции."""
        self._unbind_drag_events()

        # Уничтожаем ghost window
        if self._ghost_window is not None:
            try:
                self._ghost_window.destroy()
            except tk.TclError:
                pass
            self._ghost_window = None

        # Сбрасываем курсор
        self._root.config(cursor="")

        # Сбрасываем состояние
        self._drag_data = None
        self._is_dragging = False
        self._current_operation = DropOperation.MOVE

    def get_drop_target(self, target_id: str) -> Optional[DropTarget]:
        """Возвращает целевую зону по ID.

        Args:
            target_id: Идентификатор целевой зоны.

        Returns:
            DropTarget или None если не найдена.

        Example:
            >>> target = dds.get_drop_target("canvas_001")
            >>> if target:
            ...     print(f"Target widget: {target.widget}")
        """
        return self._drop_targets.get(target_id)

    def get_drop_target_count(self) -> int:
        """Возвращает количество зарегистрированных целевых зон.

        Returns:
            Количество целей в реестре.

        Example:
            >>> count = dds.get_drop_target_count()
            >>> print(f"Registered targets: {count}")
        """
        return len(self._drop_targets)

    def clear_drop_targets(self) -> int:
        """Удаляет все зарегистрированные целевые зоны.

        Returns:
            Количество удалённых целей.

        Example:
            >>> removed = dds.clear_drop_targets()
            >>> print(f"Removed {removed} targets")
        """
        count = len(self._drop_targets)
        self._drop_targets.clear()
        return count


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    # Constants
    "DATA_TYPE_FIELD",
    "DATA_TYPE_DOCUMENT",
    "DATA_TYPE_TEMPLATE",
    "DATA_TYPE_TEXT",
    # Drop operations
    "DropOperation",
    # Dataclasses
    "DragData",
    "DropTarget",
    # Service
    "DragDropService",
]
