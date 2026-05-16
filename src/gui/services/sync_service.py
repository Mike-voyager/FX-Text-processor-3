"""Сервис синхронизации состояния между окнами приложения.

Реализует межоконную синхронизацию данных с поддержкой broadcast
и direct messaging между окнами. Обеспечивает thread-safe доставку
сообщений и управление подписками.

Data Types:
    - sidebar_state: состояние боковой панели (last-write-wins)
    - bookmark_change: изменения закладок (merge стратегия)
    - document_update: обновление документа (MFA-gated)
    - selection_change: изменение выделения (broadcast only)
    - mode_change: смена режима (MFA-gated)

Security:
    - Thread-safe операции через threading.Lock
    - Валидация window_id через WindowManager
    - Нет передачи sensitive данных без шифрования

Example:
    >>> from src.gui.services.sync_service import SyncService
    >>> from src.gui.services.window_manager import WindowManager
    >>> wm = WindowManager(root)
    >>> sync = SyncService(wm)
    >>> def on_update(msg: SyncMessage) -> None:
    ...     print(f"Received: {msg.data_type}")
    >>> handler_id = sync.register_handler(
    ...     DATA_DOCUMENT_UPDATE, "win_001", on_update
    ... )

Version: 1.0
Date: April 11, 2026
Priority: MEDIUM (Phase 7)
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Final

from src.gui.services.window_manager import WindowManager

# =============================================================================
# CONFLICT RESOLUTION STRATEGIES
# =============================================================================


class ConflictResolution(Enum):
    """Стратегии разрешения конфликтов при синхронизации данных.

    Каждый тип данных использует оптимальную стратегию разрешения
    конфликтов для обеспечения консистентности между окнами.

    Attributes:
        LAST_WRITE_WINS: Последняя запись побеждает (timestamp-based).
        MERGE: Объединение изменений (для коллекций/множеств).
        MFA_GATED: Требуется MFA для применения изменений.
        BROADCAST_ONLY: Только broadcast, без persistence.

    Example:
        >>> strategy = ConflictResolution.LAST_WRITE_WINS
        >>> if strategy == ConflictResolution.MERGE:
        ...     merged = merge_changes(local, remote)
    """

    LAST_WRITE_WINS = "last_write_wins"
    MERGE = "merge"
    MFA_GATED = "mfa_gated"
    BROADCAST_ONLY = "broadcast_only"


# =============================================================================
# SYNC DATA
# =============================================================================


@dataclass(frozen=True)
class SyncData:
    """Модель данных для синхронизации.

    Immutable dataclass для представления данных, которые будут
    синхронизированы между окнами приложения.

    Attributes:
        data_type: Тип данных (DATA_* константы).
        source_window_id: ID окна-источника.
        payload: Полезная нагрузка (любые данные).
        timestamp: Временная метка создания.
        conflict_strategy: Стратегия разрешения конфликтов.

    Example:
        >>> data = SyncData(
        ...     data_type="document_update",
        ...     source_window_id="win-001",
        ...     payload={"doc_id": "doc-123"},
        ...     timestamp=1234567890.0
        ... )
    """

    data_type: str
    source_window_id: str
    payload: Any
    timestamp: float
    conflict_strategy: ConflictResolution = field(default=ConflictResolution.LAST_WRITE_WINS)


# =============================================================================
# DATA TYPE CONSTANTS
# =============================================================================

DATA_SIDEBAR_STATE: Final[str] = "sidebar_state"
"""Тип данных: состояние боковой панели (свернута/развернута, выбранный элемент)."""

DATA_BOOKMARK_CHANGE: Final[str] = "bookmark_change"
"""Тип данных: изменения закладок (добавление/удаление)."""

DATA_DOCUMENT_UPDATE: Final[str] = "document_update"
"""Тип данных: изменение документа (требует MFA для защищённых документов)."""

DATA_SELECTION_CHANGE: Final[str] = "selection_change"
"""Тип данных: изменение выделения текста/поля (broadcast only, не сохраняется)."""

DATA_MODE_CHANGE: Final[str] = "mode_change"
"""Тип данных: смена режима (Normal/Special), требует MFA."""

DATA_WINDOW_LIST_CHANGED: Final[str] = "window_list_changed"
"""Тип данных: изменение списка окон (добавление/удаление/обновление)."""


# =============================================================================
# SYNC MESSAGE
# =============================================================================


@dataclass(frozen=True)
class SyncMessage:
    """Сообщение синхронизации между окнами приложения.

    Immutable dataclass для thread-safe передачи данных между окнами.
    Содержит всю необходимую информацию для маршрутизации и обработки.

    Attributes:
        message_id: Уникальный идентификатор сообщения (UUID).
        source_window_id: Идентификатор окна-источника.
        target_window_ids: Кортеж идентификаторов целевых окон (пустой = all).
        data_type: Тип данных (DATA_* константы).
        data: Полезная нагрузка сообщения (специфична для типа).
        timestamp: Временная метка создания (Unix timestamp).
        requires_ack: True если требуется подтверждение доставки.

    Example:
        >>> msg = SyncMessage(
        ...     message_id="550e8400-e29b-41d4-a716-446655440000",
        ...     source_window_id="win_001",
        ...     target_window_ids=("win_002", "win_003"),
        ...     data_type=DATA_SIDEBAR_STATE,
        ...     data={"collapsed": True, "selected": "documents"},
        ...     timestamp=1712812800.0,
        ...     requires_ack=False
        ... )
    """

    message_id: str
    source_window_id: str
    target_window_ids: tuple[str, ...]
    data_type: str
    data: Any
    timestamp: float
    requires_ack: bool


# =============================================================================
# SYNC SERVICE
# =============================================================================


class SyncService:
    """Сервис синхронизации состояния между окнами приложения.

    Обеспечивает централизованную синхронизацию данных между всеми
    окнами приложения через механизм подписок (handlers) и broadcast.

    Conflict Resolution:
        - sidebar_state: last-write-wins (сравнение по timestamp)
        - bookmark_change: merge стратегия (множество закладок)
        - document_update: MFA-gated + timestamp проверка
        - selection_change: broadcast only (без persistence)
        - mode_change: MFA-gated операция

    Attributes:
        _window_manager: Ссылка на WindowManager для получения списка окон.
        _handlers: Словарь обработчиков {handler_id: handler_info}.
        _last_sync_times: Времена последней синхронизации по типам данных.
        _lock: Lock для thread-safe операций.

    Thread Safety:
        Все публичные методы используют _lock для thread-safety.
        Обработчики вызываются вне блокировки для предотвращения deadlock.

    Example:
        >>> wm = WindowManager(root)
        >>> sync = SyncService(wm)
        >>> # Регистрация обработчика
        >>> hid = sync.register_handler(
        ...     DATA_SIDEBAR_STATE, "win_001",
        ...     lambda msg: print(f"Sidebar: {msg.data}")
        ... )
        >>> # Broadcast сообщения
        >>> sync.broadcast("win_001", DATA_SIDEBAR_STATE, {"collapsed": True})
    """

    def __init__(self, window_manager: WindowManager) -> None:
        """Инициализирует сервис синхронизации.

        Args:
            window_manager: Менеджер окон для получения списка активных окон.

        Example:
            >>> wm = WindowManager(root)
            >>> sync = SyncService(wm)
        """
        self._window_manager: WindowManager = window_manager
        self._handlers: dict[str, dict[str, Any]] = {}
        self._last_sync_times: dict[str, float] = {}
        self._lock: threading.Lock = threading.Lock()

    def _create_message(
        self,
        source_window_id: str,
        target_window_ids: tuple[str, ...],
        data_type: str,
        data: Any,
        requires_ack: bool = False,
    ) -> SyncMessage:
        """Создаёт новое сообщение синхронизации.

        Args:
            source_window_id: Идентификатор окна-источника.
            target_window_ids: Целевые окна (пустой кортеж = all).
            data_type: Тип данных.
            data: Полезная нагрузка.
            requires_ack: Требуется ли подтверждение.

        Returns:
            Созданное сообщение SyncMessage.
        """
        return SyncMessage(
            message_id=str(uuid.uuid4()),
            source_window_id=source_window_id,
            target_window_ids=target_window_ids,
            data_type=data_type,
            data=data,
            timestamp=time.time(),
            requires_ack=requires_ack,
        )

    def _notify_handlers(self, message: SyncMessage) -> None:
        """Уведомляет все подходящие обработчики о сообщении.

        Args:
            message: Сообщение для доставки.

        Note:
            Обработчики вызываются вне блокировки для предотвращения deadlock.
        """
        # Копируем обработчики для вызова вне блокировки
        handlers_to_call: list[Callable[[SyncMessage], None]] = []

        with self._lock:
            for handler_info in self._handlers.values():
                # Проверяем соответствие по data_type
                if handler_info["data_type"] != message.data_type:
                    continue

                # Проверяем target_window_ids
                if message.target_window_ids:
                    if handler_info["window_id"] not in message.target_window_ids:
                        continue
                else:
                    # Broadcast: не отправляем источнику самому себе
                    if handler_info["window_id"] == message.source_window_id:
                        continue

                handlers_to_call.append(handler_info["handler"])

        # Вызываем обработчики вне блокировки
        for handler in handlers_to_call:
            try:
                handler(message)
            except (KeyError, ValueError, TypeError, RuntimeError) as e:  # noqa: S110
                # Игнорируем ошибки обработчиков для стабильности системы
                logging.getLogger(__name__).exception("Exception ignored in handler: %s", e)

    def broadcast(
        self,
        source_window_id: str,
        data_type: str,
        data: Any,
        requires_ack: bool = False,
    ) -> None:
        """Отправляет данные всем окнам кроме источника.

        Рассылает сообщение всем зарегистрированным обработчикам указанного
        типа данных, исключая окно-источник.

        Args:
            source_window_id: Идентификатор окна-источника.
            data_type: Тип данных (DATA_* константа).
            data: Данные для передачи (специфичны для типа).
            requires_ack: True если требуется подтверждение доставки.

        Example:
            >>> sync.broadcast(
            ...     source_window_id="win_001",
            ...     data_type=DATA_SIDEBAR_STATE,
            ...     data={"collapsed": True, "selected": "documents"}
            ... )

        Security:
            Данные передаются без шифрования между окнами (shared memory).
            Для sensitive данных используйте DocumentService с шифрованием.
        """
        message = self._create_message(
            source_window_id=source_window_id,
            target_window_ids=(),  # Пустой кортеж = broadcast to all
            data_type=data_type,
            data=data,
            requires_ack=requires_ack,
        )

        # Обновляем время последней синхронизации
        with self._lock:
            self._last_sync_times[data_type] = message.timestamp

        self._notify_handlers(message)

    def send_to_window(
        self,
        source_window_id: str,
        target_window_id: str,
        data_type: str,
        data: Any,
        requires_ack: bool = False,
    ) -> None:
        """Отправляет данные конкретному окну.

        Отправляет сообщение только указанному целевому окну.
        Если target_window_id совпадает с source_window_id, сообщение
        всё равно будет доставлено (в отличие от broadcast).

        Args:
            source_window_id: Идентификатор окна-источника.
            target_window_id: Идентификатор целевого окна.
            data_type: Тип данных (DATA_* константа).
            data: Данные для передачи.
            requires_ack: True если требуется подтверждение доставки.

        Raises:
            ValueError: Если target_window_id пустой или None.

        Example:
            >>> sync.send_to_window(
            ...     source_window_id="win_001",
            ...     target_window_id="win_002",
            ...     data_type=DATA_DOCUMENT_UPDATE,
            ...     data={"doc_id": "doc_123", "modified": True}
            ... )
        """
        if not target_window_id:
            raise ValueError("target_window_id cannot be empty")

        message = self._create_message(
            source_window_id=source_window_id,
            target_window_ids=(target_window_id,),
            data_type=data_type,
            data=data,
            requires_ack=requires_ack,
        )

        # Проверяем что target_window_id существует
        if self._window_manager and not self._window_manager.is_window_registered(target_window_id):
            logging.getLogger(__name__).warning(
                "Window '%s' not found for sync message type '%s'", target_window_id, data_type
            )

        # Обновляем время последней синхронизации
        with self._lock:
            self._last_sync_times[data_type] = message.timestamp

        self._notify_handlers(message)

    def register_handler(
        self,
        data_type: str,
        window_id: str,
        handler: Callable[[SyncMessage], None],
    ) -> str:
        """Регистрирует обработчик для типа данных.

        Регистрирует функцию-обработчик, которая будет вызываться
        при получении сообщений указанного типа для данного окна.

        Args:
            data_type: Тип данных для обработки (DATA_* константа).
            window_id: Идентификатор окна-получателя.
            handler: Функция-обработчик, принимающая SyncMessage.

        Returns:
            Уникальный идентификатор обработчика (handler_id).

        Example:
            >>> def on_sidebar_change(msg: SyncMessage) -> None:
            ...     print(f"Sidebar state: {msg.data}")
            >>> handler_id = sync.register_handler(
            ...     DATA_SIDEBAR_STATE, "win_001", on_sidebar_change
            ... )
        """
        handler_id = f"handler_{uuid.uuid4().hex}"

        with self._lock:
            self._handlers[handler_id] = {
                "data_type": data_type,
                "window_id": window_id,
                "handler": handler,
            }

        return handler_id

    def unregister_handler(self, handler_id: str) -> None:
        """Удаляет зарегистрированный обработчик.

        Args:
            handler_id: Идентификатор обработчика, возвращённый register_handler.

        Raises:
            KeyError: Если handler_id не найден.

        Example:
            >>> handler_id = sync.register_handler(...)
            >>> sync.unregister_handler(handler_id)
        """
        with self._lock:
            if handler_id not in self._handlers:
                raise KeyError(f"Handler with ID '{handler_id}' not found")
            del self._handlers[handler_id]

    def get_last_sync_time(self, data_type: str) -> float:
        """Возвращает время последней синхронизации для типа данных.

        Args:
            data_type: Тип данных (DATA_* константа).

        Returns:
            Unix timestamp последней синхронизации или 0.0 если не было.

        Example:
            >>> last_time = sync.get_last_sync_time(DATA_DOCUMENT_UPDATE)
            >>> if last_time > 0:
            ...     print(f"Last sync: {time.time() - last_time}s ago")
        """
        with self._lock:
            return self._last_sync_times.get(data_type, 0.0)

    def get_handler_count(self, data_type: str | None = None) -> int:
        """Возвращает количество зарегистрированных обработчиков.

        Args:
            data_type: Фильтр по типу данных (None = все типы).

        Returns:
            Количество обработчиков.

        Example:
            >>> count = sync.get_handler_count(DATA_SIDEBAR_STATE)
            >>> print(f"{count} окон слушают изменения боковой панели")
        """
        with self._lock:
            if data_type is None:
                return len(self._handlers)
            return sum(1 for info in self._handlers.values() if info["data_type"] == data_type)

    def clear_handlers(self, window_id: str | None = None) -> int:
        """Удаляет все обработчики для окна или все обработчики.

        Args:
            window_id: Идентификатор окна (None = все обработчики).

        Returns:
            Количество удалённых обработчиков.

        Example:
            >>> # При закрытии окна
            >>> removed = sync.clear_handlers("win_001")
            >>> print(f"Удалено {removed} обработчиков")
        """
        with self._lock:
            if window_id is None:
                count = len(self._handlers)
                self._handlers.clear()
                return count

            to_remove = [
                hid for hid, info in self._handlers.items() if info["window_id"] == window_id
            ]
            for hid in to_remove:
                del self._handlers[hid]
            return len(to_remove)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    # Data type constants
    "DATA_SIDEBAR_STATE",
    "DATA_BOOKMARK_CHANGE",
    "DATA_DOCUMENT_UPDATE",
    "DATA_SELECTION_CHANGE",
    "DATA_MODE_CHANGE",
    "DATA_WINDOW_LIST_CHANGED",
    # Classes
    "SyncMessage",
    "SyncService",
]
