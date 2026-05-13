"""Сервис уведомлений (Toast Notifications).

Предоставляет API для отображения уведомлений в GUI.
Поддерживает разные типы: info, success, warning, error.

Module: src/services/notification_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы уведомлений
# ---------------------------------------------------------------------------


class NotificationType(Enum):
    """Тип уведомления."""

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    PROGRESS = "progress"


class NotificationPriority(Enum):
    """Приоритет уведомления."""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class NotificationCallback(Protocol):
    """Протокол callback для отображения уведомления."""

    def __call__(self, notification: "Notification") -> None:
        """Вызывается при появлении уведомления.

        Args:
            notification: Объект уведомления
        """
        ...


class DismissCallback(Protocol):
    """Протокол callback при закрытии уведомления."""

    def __call__(self, notification_id: UUID, action: Optional[str]) -> None:
        """Вызывается при закрытии уведомления.

        Args:
            notification_id: ID уведомления
            action: Выбранное действие (если есть)
        """
        ...


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NotificationAction:
    """Действие в уведомлении.

    Attrs:
        id: Идентификатор действия
        label: Текст кнопки
        style: Стиль кнопки (default, primary, danger)
    """

    id: str
    label: str
    style: str = "default"  # default, primary, danger


@dataclass
class Notification:
    """Уведомление.

    Attrs:
        id: Уникальный идентификатор
        type: Тип уведомления
        title: Заголовок
        message: Сообщение
        priority: Приоритет
        created_at: Время создания
        expires_at: Время истечения (optional)
        actions: Доступные действия
        data: Дополнительные данные
        progress: Прогресс (для типа PROGRESS)
        dismissible: Можно ли закрыть
        persistent: Не исчезает автоматически
    """

    id: UUID = field(default_factory=uuid4)
    type: NotificationType = NotificationType.INFO
    title: str = ""
    message: str = ""
    priority: NotificationPriority = NotificationPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    actions: List[NotificationAction] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    progress: Optional[float] = None  # 0.0 - 1.0 для PROGRESS
    dismissible: bool = True
    persistent: bool = False

    def is_expired(self) -> bool:
        """Проверяет, истекло ли уведомление."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def with_action(
        self,
        action_id: str,
        label: str,
        style: str = "default",
    ) -> "Notification":
        """Добавляет действие к уведомлению.

        Args:
            action_id: ID действия
            label: Текст кнопки
            style: Стиль кнопки

        Returns:
            Новое уведомление с действием
        """
        actions = list(self.actions)
        actions.append(NotificationAction(id=action_id, label=label, style=style))
        return Notification(
            id=self.id,
            type=self.type,
            title=self.title,
            message=self.message,
            priority=self.priority,
            created_at=self.created_at,
            expires_at=self.expires_at,
            actions=actions,
            data=self.data,
            progress=self.progress,
            dismissible=self.dismissible,
            persistent=self.persistent,
        )


# ---------------------------------------------------------------------------
# Результаты
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShowResult:
    """Результат показа уведомления.

    Attrs:
        success: True при успехе
        notification_id: ID созданного уведомления
        error: Сообщение об ошибке или None
    """

    success: bool
    notification_id: Optional[UUID] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# NotificationService
# ---------------------------------------------------------------------------


class NotificationService:
    """Сервис управления уведомлениями.

    Предоставляет API для:
    - Показа уведомлений разных типов
    - Управления очередью уведомлений
    - Callback при отображении/закрытии
    - Фильтрации по приоритету

    Пример:
        >>> notifications = NotificationService()
        >>> notifications.subscribe(my_callback)
        >>> notifications.info("Файл сохранён", "Документ успешно сохранён")
        >>> notifications.error("Ошибка", "Не удалось открыть файл")
        >>> notifications.success("Успех", "Операция выполнена")
    """

    def __init__(
        self,
        max_notifications: int = 100,
        default_timeout_seconds: int = 5,
        error_timeout_seconds: int = 10,
    ) -> None:
        """Инициализирует сервис уведомлений.

        Args:
            max_notifications: Максимум уведомлений в истории
            default_timeout_seconds: Таймаут по умолчанию
            error_timeout_seconds: Таймаут для ошибок
        """
        self._max_notifications = max_notifications
        self._default_timeout = default_timeout_seconds
        self._error_timeout = error_timeout_seconds

        # Состояние
        self._notifications: Dict[UUID, Notification] = {}
        self._history: List[UUID] = []  # Порядок добавления
        self._callbacks: List[NotificationCallback] = []
        self._dismiss_callbacks: List[DismissCallback] = []
        self._lock = False  # Для потокобезопасности в GUI

    # ---------- Подписка на события ----------

    def subscribe(self, callback: NotificationCallback) -> None:
        """Подписывается на новые уведомления.

        Args:
            callback: Функция, вызываемая при появлении уведомления
        """
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def unsubscribe(self, callback: NotificationCallback) -> None:
        """Отписывается от уведомлений.

        Args:
            callback: Функция для отписки
        """
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def on_dismiss(self, callback: DismissCallback) -> None:
        """Подписывается на закрытие уведомлений.

        Args:
            callback: Функция, вызываемая при закрытии
        """
        if callback not in self._dismiss_callbacks:
            self._dismiss_callbacks.append(callback)

    # ---------- Показ уведомлений ----------

    def show(
        self,
        title: str,
        message: str,
        type: NotificationType = NotificationType.INFO,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        duration: Optional[int] = None,
        actions: Optional[List[NotificationAction]] = None,
        data: Optional[Dict[str, Any]] = None,
        persistent: bool = False,
    ) -> ShowResult:
        """Показывает уведомление.

        Args:
            title: Заголовок
            message: Сообщение
            type: Тип уведомления
            priority: Приоритет
            duration: Длительность в секундах (None = default)
            actions: Доступные действия
            data: Дополнительные данные
            persistent: Не исчезает автоматически

        Returns:
            ShowResult с ID уведомления
        """
        from datetime import timedelta

        # Определяем таймаут
        if duration is None:
            duration = (
                self._error_timeout if type == NotificationType.ERROR else self._default_timeout
            )

        # Создаём уведомление
        expires_at = None if persistent else datetime.now() + timedelta(seconds=duration)

        notification = Notification(
            type=type,
            title=title,
            message=message,
            priority=priority,
            expires_at=expires_at,
            actions=actions or [],
            data=data or {},
            persistent=persistent,
        )

        # Добавляем в очередь
        self._add_notification(notification)

        # Уведомляем подписчиков
        self._notify_callbacks(notification)

        logger.debug(
            "Уведомление: [%s] %s - %s",
            type.value.upper(),
            title,
            message,
        )

        return ShowResult(success=True, notification_id=notification.id)

    def info(
        self,
        title: str,
        message: str,
        duration: Optional[int] = None,
        **kwargs: Any,
    ) -> ShowResult:
        """Показывает информационное уведомление."""
        return self.show(
            title=title,
            message=message,
            type=NotificationType.INFO,
            duration=duration,
            **kwargs,
        )

    def success(
        self,
        title: str,
        message: str,
        duration: Optional[int] = None,
        **kwargs: Any,
    ) -> ShowResult:
        """Показывает уведомление об успехе."""
        return self.show(
            title=title,
            message=message,
            type=NotificationType.SUCCESS,
            duration=duration,
            **kwargs,
        )

    def warning(
        self,
        title: str,
        message: str,
        duration: Optional[int] = None,
        **kwargs: Any,
    ) -> ShowResult:
        """Показывает предупреждение."""
        return self.show(
            title=title,
            message=message,
            type=NotificationType.WARNING,
            priority=NotificationPriority.HIGH,
            duration=duration,
            **kwargs,
        )

    def error(
        self,
        title: str,
        message: str,
        duration: Optional[int] = None,
        **kwargs: Any,
    ) -> ShowResult:
        """Показывает уведомление об ошибке."""
        return self.show(
            title=title,
            message=message,
            type=NotificationType.ERROR,
            priority=NotificationPriority.HIGH,
            duration=duration or self._error_timeout,
            **kwargs,
        )

    def progress(
        self,
        title: str,
        message: str,
        progress: float,
        **kwargs: Any,
    ) -> ShowResult:
        """Показывает уведомление с прогрессом.

        Args:
            title: Заголовок
            message: Сообщение
            progress: Прогресс (0.0 - 1.0)
            **kwargs: Дополнительные параметры

        Returns:
            ShowResult
        """
        if not 0.0 <= progress <= 1.0:
            progress = max(0.0, min(1.0, progress))

        return self.show(
            title=title,
            message=message,
            type=NotificationType.PROGRESS,
            data={"progress": progress},
            **kwargs,
        )

    # ---------- Управление уведомлениями ----------

    def dismiss(self, notification_id: UUID, action: Optional[str] = None) -> bool:
        """Закрывает уведомление.

        Args:
            notification_id: ID уведомления
            action: Выбранное действие (если есть)

        Returns:
            True если уведомление было закрыто
        """
        if notification_id not in self._notifications:
            return False

        # Уведомляем подписчиков
        for callback in self._dismiss_callbacks:
            try:
                callback(notification_id, action)
            except Exception as exc:
                logger.error("Ошибка dismiss callback: %s", exc)

        # Удаляем
        del self._notifications[notification_id]
        if notification_id in self._history:
            self._history.remove(notification_id)

        logger.debug("Уведомление закрыто: %s", notification_id)
        return True

    def dismiss_all(self) -> int:
        """Закрывает все уведомления.

        Returns:
            Количество закрытых уведомлений
        """
        count = len(self._notifications)
        self._notifications.clear()
        self._history.clear()
        return count

    def dismiss_by_type(self, type: NotificationType) -> int:
        """Закрывает все уведомления указанного типа.

        Args:
            type: Тип уведомлений для закрытия

        Returns:
            Количество закрытых уведомлений
        """
        to_dismiss = [nid for nid, n in self._notifications.items() if n.type == type]
        for nid in to_dismiss:
            self.dismiss(nid)
        return len(to_dismiss)

    # ---------- Запросы ----------

    def get(self, notification_id: UUID) -> Optional[Notification]:
        """Возвращает уведомление по ID.

        Args:
            notification_id: ID уведомления

        Returns:
            Уведомление или None
        """
        return self._notifications.get(notification_id)

    def get_all(self) -> List[Notification]:
        """Возвращает все активные уведомления."""
        # Удаляем истёкшие
        self._cleanup_expired()
        return list(self._notifications.values())

    def get_by_type(self, type: NotificationType) -> List[Notification]:
        """Возвращает уведомления указанного типа.

        Args:
            type: Тип уведомлений

        Returns:
            Список уведомлений
        """
        return [n for n in self._notifications.values() if n.type == type]

    def get_by_priority(
        self,
        min_priority: NotificationPriority,
    ) -> List[Notification]:
        """Возвращает уведомления с приоритетом >= min.

        Args:
            min_priority: Минимальный приоритет

        Returns:
            Список уведомлений
        """
        return [n for n in self._notifications.values() if n.priority.value >= min_priority.value]

    def count(self) -> int:
        """Возвращает количество активных уведомлений."""
        return len(self._notifications)

    def has_errors(self) -> bool:
        """Проверяет, есть ли активные ошибки."""
        return any(n.type == NotificationType.ERROR for n in self._notifications.values())

    def has_warnings(self) -> bool:
        """Проверяет, есть ли активные предупреждения."""
        return any(n.type == NotificationType.WARNING for n in self._notifications.values())

    # ---------- Внутренние методы ----------

    def _add_notification(self, notification: Notification) -> None:
        """Добавляет уведомление в очередь."""
        # Проверяем лимит
        if len(self._notifications) >= self._max_notifications:
            # Удаляем старейшее
            oldest_id = self._history.pop(0) if self._history else None
            if oldest_id and oldest_id in self._notifications:
                del self._notifications[oldest_id]

        self._notifications[notification.id] = notification
        self._history.append(notification.id)

    def _notify_callbacks(self, notification: Notification) -> None:
        """Уведомляет всех подписчиков о новом уведомлении."""
        for callback in self._callbacks:
            try:
                callback(notification)
            except Exception as exc:
                logger.error("Ошибка notification callback: %s", exc)

    def _cleanup_expired(self) -> None:
        """Удаляет истёкшие уведомления."""
        expired = [
            nid for nid, n in self._notifications.items() if n.is_expired() and not n.persistent
        ]
        for nid in expired:
            self.dismiss(nid)


__all__ = [
    "NotificationService",
    "Notification",
    "NotificationAction",
    "NotificationType",
    "NotificationPriority",
    "NotificationCallback",
    "DismissCallback",
    "ShowResult",
]
