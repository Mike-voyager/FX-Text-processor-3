"""Сервис уведомлений для FX Text Processor 3.

Реализует расширенную систему уведомлений с историей, приоритетами,
группировкой по категориям и интеграцией с ToastService и WindowManager.

Features:
    - История уведомлений с ограничением размера (MAX_HISTORY)
    - Четыре уровня приоритета: LOW, NORMAL, HIGH, CRITICAL
    - Группировка по категориям (security, workflow, system, sync)
    - Автоматическая маршрутизация: LOW/NORMAL → ToastService, HIGH/CRITICAL → модальные диалоги
    - Отслеживание статуса прочтения

Security:
    - Ограничение длины сообщения (MAX_MESSAGE_LENGTH) для предотвращения DoS.
    - UUID для идентификаторов уведомлений.
    - Нет eval/exec в метаданных — проверка типов.
    - Ограничение размера истории (MAX_HISTORY) для защиты от исчерпания памяти.

Example:
    >>> from src.gui.services.notification_service import (
    ...     NotificationService, NotificationPriority, CATEGORY_SECURITY
    ... )
    >>> root = tk.Tk()
    >>> wm = WindowManager(root)
    >>> service = NotificationService(root, wm)
    >>> nid = service.notify(
    ...     message="Документ сохранён",
    ...     category=CATEGORY_WORKFLOW,
    ...     priority=NotificationPriority.NORMAL
    ... )
    >>> history = service.get_history()
    >>> service.mark_as_read(nid)
"""

from __future__ import annotations

import logging
import time
import tkinter as tk
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Final, Optional

from src.gui.core.protocols import NotificationServiceProtocol
from src.gui.services.toast_service import MAX_MESSAGE_LENGTH, ToastService
from src.gui.services.window_manager import WindowManager
from src.gui.views import ToastLevel

# ==============================================================================
# SECURITY CONSTRAINTS
# ==============================================================================

MAX_HISTORY: Final[int] = 100

# Reuse the same constraint from ToastService for consistency
# (imported directly as MAX_MESSAGE_LENGTH)

# ==============================================================================
# CATEGORY CONSTANTS
# ==============================================================================

CATEGORY_SECURITY: Final[str] = "security"
CATEGORY_WORKFLOW: Final[str] = "workflow"
CATEGORY_SYSTEM: Final[str] = "system"
CATEGORY_SYNC: Final[str] = "sync"

VALID_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        CATEGORY_SECURITY,
        CATEGORY_WORKFLOW,
        CATEGORY_SYSTEM,
        CATEGORY_SYNC,
    }
)

# ==============================================================================
# PRIORITY ENUM
# ==============================================================================


class NotificationPriority(int, Enum):
    """Уровни приоритета уведомлений.

    Наследует int для поддержки операций сравнения (<, >, <=, >=).

    Attributes:
        LOW: Фоновые уведомления, минимальное внимание
        NORMAL: Обычные уведомления, требуют прочтения
        HIGH: Важные уведомления, требуют немедленного внимания
        CRITICAL: Критические уведомления, блокируют работу до подтверждения

    Example:
        >>> NotificationPriority.LOW
        <NotificationPriority.LOW: 1>
        >>> NotificationPriority.CRITICAL.value
        4
        >>> NotificationPriority.LOW < NotificationPriority.NORMAL
        True
    """

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


# ==============================================================================
# NOTIFICATION DATA CLASS
# ==============================================================================


@dataclass(frozen=True)
class Notification:
    """Непизменяемая запись уведомления.

    Attributes:
        notification_id: Уникальный идентификатор уведомления (UUID).
        message: Текст уведомления.
        category: Категория уведомления (security, workflow, system, sync).
        priority: Уровень приоритета уведомления.
        created_at: Временная метка создания (Unix timestamp).
        read: Флаг прочтения (True если прочитано).
        metadata: Дополнительные данные уведомления (dict или None).

    Note:
        Класс использует frozen=True для иммутабельности и потокобезопасности.
        Для изменения статуса прочтения создаётся новый экземпляр.

    Example:
        >>> notification = Notification(
        ...     notification_id="550e8400-e29b-41d4-a716-446655440000",
        ...     message="Документ сохранён",
        ...     category="workflow",
        ...     priority=NotificationPriority.NORMAL,
        ...     created_at=1712812800.0,
        ...     read=False,
        ...     metadata={"document_id": "doc_123"}
        ... )
    """

    notification_id: str
    message: str
    category: str
    priority: NotificationPriority
    created_at: float
    read: bool
    metadata: Optional[dict[str, Any]]


# ==============================================================================
# NOTIFICATION SERVICE
# ==============================================================================


class NotificationService(NotificationServiceProtocol):
    """Сервис уведомлений с историей и приоритетами.

    Реализует NotificationServiceProtocol с поддержкой четырёх уровней
    приоритета, категоризации и интеграцией с ToastService и WindowManager.

    Приоритеты и обработка:
        - LOW: Toast уведомление (ToastLevel.INFO), без блокировки
        - NORMAL: Toast уведомление (ToastLevel.SUCCESS) + обновление badge
        - HIGH: Модальное диалоговое окно через WindowManager
        - CRITICAL: Модальное диалоговое окно с остановкой работы

    Attributes:
        _root: Главное окно приложения.
        _window_manager: Менеджер окон для модальных диалогов.
        _toast_service: Сервис toast уведомлений для LOW/NORMAL приоритетов.
        _history: Словарь истории уведомлений {notification_id: Notification}.
        _badge_callbacks: Список callback для обновления badge счётчика.

    Security:
        - Валидация длины сообщения (MAX_MESSAGE_LENGTH).
        - Проверка метаданных на отсутствие вызываемых объектов.
        - Автоматическая очистка старых уведомлений при превышении MAX_HISTORY.

    Example:
        >>> root = tk.Tk()
        >>> wm = WindowManager(root)
        >>> service = NotificationService(root, wm)
        >>> nid = service.notify("MFA верификация успешна", "security", NotificationPriority.HIGH)
        >>> service.get_unread_count("security")
        1
        >>> service.mark_as_read(nid)
    """

    def __init__(self, root: tk.Tk, window_manager: WindowManager) -> None:
        """Инициализирует сервис уведомлений.

        Args:
            root: Главное окно приложения для создания диалогов.
            window_manager: Менеджер окон для модальных диалогов HIGH/CRITICAL.
        """
        self._root: tk.Tk = root
        self._window_manager: WindowManager = window_manager
        self._toast_service: ToastService = ToastService(root)
        self._history: dict[str, Notification] = {}
        self._badge_callbacks: list[Callable[[int], None]] = []

    def _validate_message(self, message: str) -> None:
        """Валидирует длину сообщения.

        Args:
            message: Сообщение для проверки.

        Raises:
            ValueError: Если длина сообщения превышает MAX_MESSAGE_LENGTH.
        """
        if len(message) > MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"Message exceeds maximum length ({MAX_MESSAGE_LENGTH} chars): {len(message)}"
            )

    def _validate_metadata(self, metadata: Optional[dict[str, Any]]) -> None:
        """Валидирует метаданные на отсутствие небезопасных типов.

        Проверяет что метаданные не содержат вызываемых объектов
        (функции, лямбды) для предотвращения инъекции кода.

        Args:
            metadata: Метаданные для проверки.

        Raises:
            ValueError: Если метаданные содержат callable объекты.
            TypeError: Если метаданные не словарь и не None.
        """
        if metadata is None:
            return

        if not isinstance(metadata, dict):
            raise TypeError(f"Metadata must be dict or None, got: {type(metadata)}")

        for key, value in metadata.items():
            if callable(value):
                raise ValueError(
                    f"Metadata contains callable value for key '{key}'. "
                    f"Storing functions or lambdas is not allowed."
                )
            if isinstance(value, str) and ("eval(" in value or "exec(" in value):
                raise ValueError(
                    f"Metadata contains potentially dangerous string for key '{key}'. "
                    f"eval/exec is not allowed."
                )

    def _validate_category(self, category: str) -> None:
        """Валидирует категорию уведомления.

        Args:
            category: Категория для проверки.

        Raises:
            ValueError: Если категория не входит в VALID_CATEGORIES.
        """
        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. Allowed: {', '.join(sorted(VALID_CATEGORIES))}"
            )

    def _cleanup_history(self) -> None:
        """Удаляет старые уведомления при превышении MAX_HISTORY.

        Сортирует по времени создания и удаляет самые старые уведомления
        до тех пор, пока размер истории не станет ≤ MAX_HISTORY.
        """
        while len(self._history) >= MAX_HISTORY:
            # Находим самое старое уведомление
            oldest_id = min(
                self._history.keys(),
                key=lambda nid: self._history[nid].created_at,
            )
            del self._history[oldest_id]

    def _map_priority_to_toast_level(self, priority: NotificationPriority) -> ToastLevel:
        """Сопоставляет приоритет уведомления с уровнем toast.

        Args:
            priority: Приоритет уведомления.

        Returns:
            Соответствующий ToastLevel.
        """
        mapping = {
            NotificationPriority.LOW: ToastLevel.INFO,
            NotificationPriority.NORMAL: ToastLevel.SUCCESS,
            NotificationPriority.HIGH: ToastLevel.WARNING,
            NotificationPriority.CRITICAL: ToastLevel.ERROR,
        }
        return mapping.get(priority, ToastLevel.INFO)

    def _show_modal_dialog(self, message: str, priority: NotificationPriority) -> None:
        """Показывает модальный диалог для HIGH/CRITICAL уведомлений.

        Использует tkinter.messagebox для отображения модального окна
        с остановкой выполнения до подтверждения пользователем.

        Args:
            message: Текст уведомления.
            priority: Приоритет (HIGH или CRITICAL).
        """
        import tkinter.messagebox as messagebox

        title = (
            "Важное уведомление"
            if priority == NotificationPriority.HIGH
            else "КРИТИЧЕСКОЕ УВЕДОМЛЕНИЕ"
        )

        # Для CRITICAL используем showerror, для HIGH — showwarning
        if priority == NotificationPriority.CRITICAL:
            messagebox.showerror(title, message, parent=self._root)
        else:
            messagebox.showwarning(title, message, parent=self._root)

    def _notify_badge_update(self) -> None:
        """Уведомляет все зарегистрированные callback об изменении badge счётчика."""
        count = self.get_unread_count()
        for callback in self._badge_callbacks:
            try:
                callback(count)
            except Exception as e:  # noqa: S110
                # Игнорируем ошибки в callback для стабильности
                logging.getLogger(__name__).exception("Exception ignored in badge callback: %s", e)

    def register_badge_callback(self, callback: Callable[[int], None]) -> None:
        """Регистрирует callback для обновления badge счётчика.

        Вызывается при изменении количества непрочитанных уведомлений.
        Позволяет View слою обновлять UI индикатор.

        Args:
            callback: Функция принимающая количество непрочитанных уведомлений.

        Example:
            >>> def update_badge(count: int) -> None:
            ...     label.config(text=str(count))
            >>> service.register_badge_callback(update_badge)
        """
        self._badge_callbacks.append(callback)

    def unregister_badge_callback(self, callback: Callable[[int], None]) -> None:
        """Удаляет регистрацию callback для badge обновления.

        Args:
            callback: Ранее зарегистрированный callback.
        """
        if callback in self._badge_callbacks:
            self._badge_callbacks.remove(callback)

    def notify(
        self,
        message: str,
        category: str,
        priority: NotificationPriority,
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """Создаёт и отображает уведомление.

        Создаёт запись уведомления, добавляет в историю, выполняет маршрутизацию
        в зависимости от приоритета: LOW/NORMAL → ToastService, HIGH/CRITICAL → модальный диалог.

        Args:
            message: Текст уведомления (макс. MAX_MESSAGE_LENGTH символов).
            category: Категория уведомления (security, workflow, system, sync).
            priority: Уровень приоритета (LOW, NORMAL, HIGH, CRITICAL).
            metadata: Дополнительные данные (опционально, без callable).

        Returns:
            Уникальный идентификатор созданного уведомления (UUID).

        Raises:
            ValueError: Если сообщение слишком длинное или категория недопустима.
            TypeError: Если метаданные имеют неверный тип.

        Example:
            >>> nid = service.notify(
            ...     message="Файл сохранён",
            ...     category=CATEGORY_WORKFLOW,
            ...     priority=NotificationPriority.NORMAL
            ... )
            >>> print(f"Уведомление создано: {nid}")
        """
        # Валидация входных данных
        self._validate_message(message)
        self._validate_category(category)
        self._validate_metadata(metadata)

        # Очистка старой истории при необходимости
        self._cleanup_history()

        # Генерация уникального ID
        notification_id = str(uuid.uuid4())

        # Создание записи уведомления
        notification = Notification(
            notification_id=notification_id,
            message=message,
            category=category,
            priority=priority,
            created_at=time.time(),
            read=False,
            metadata=metadata,
        )

        # Сохранение в историю
        self._history[notification_id] = notification

        # Маршрутизация в зависимости от приоритета
        if priority in (NotificationPriority.LOW, NotificationPriority.NORMAL):
            # Низкий и нормальный приоритет → ToastService
            toast_level = self._map_priority_to_toast_level(priority)
            self._toast_service.show(message, level=toast_level)

            # Для NORMAL обновляем badge счётчик
            if priority == NotificationPriority.NORMAL:
                self._notify_badge_update()
        else:
            # Высокий и критический приоритет → модальный диалог
            self._show_modal_dialog(message, priority)

        return notification_id

    def get_history(
        self,
        category: Optional[str] = None,
        unread_only: bool = False,
    ) -> list[Notification]:
        """Возвращает историю уведомлений.

        Args:
            category: Фильтр по категории (None = все категории).
            unread_only: Если True, возвращает только непрочитанные.

        Returns:
            Список уведомлений в хронологическом порядке (новые сначала).

        Raises:
            ValueError: Если указана недопустимая категория.

        Example:
            >>> # Все уведомления
            >>> history = service.get_history()
            >>> # Только security
            >>> security = service.get_history(category=CATEGORY_SECURITY)
            >>> # Непрочитанные workflow
            >>> unread = service.get_history(category=CATEGORY_WORKFLOW, unread_only=True)
        """
        if category is not None and category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. Allowed: {', '.join(sorted(VALID_CATEGORIES))}"
            )

        # Фильтрация уведомлений
        notifications: list[Notification] = []
        for notification in self._history.values():
            if category is not None and notification.category != category:
                continue
            if unread_only and notification.read:
                continue
            notifications.append(notification)

        # Сортировка по времени (новые сначала)
        notifications.sort(key=lambda n: n.created_at, reverse=True)

        return notifications

    def mark_as_read(self, notification_id: str) -> None:
        """Отмечает уведомление как прочитанное.

        Создаёт новую иммутабельную запись с read=True.

        Args:
            notification_id: Идентификатор уведомления.

        Raises:
            KeyError: Если уведомление с таким ID not found.

        Example:
            >>> service.mark_as_read("550e8400-e29b-41d4-a716-446655440000")
        """
        if notification_id not in self._history:
            raise KeyError(f"Notification with ID '{notification_id}' not found")

        old_notification = self._history[notification_id]

        # Создаём новую иммутабельную запись с read=True
        new_notification = Notification(
            notification_id=old_notification.notification_id,
            message=old_notification.message,
            category=old_notification.category,
            priority=old_notification.priority,
            created_at=old_notification.created_at,
            read=True,
            metadata=old_notification.metadata,
        )

        self._history[notification_id] = new_notification

        # Уведомляем о возможном изменении badge счётчика
        self._notify_badge_update()

    def mark_all_as_read(self, category: Optional[str] = None) -> None:
        """Отмечает все уведомления как прочитанные.

        Args:
            category: Если указан, отмечает только уведомления этой категории.

        Raises:
            ValueError: Если указана недопустимая категория.

        Example:
            >>> # Отметить все
            >>> service.mark_all_as_read()
            >>> # Отметить только security
            >>> service.mark_all_as_read(category=CATEGORY_SECURITY)
        """
        if category is not None and category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. Allowed: {', '.join(sorted(VALID_CATEGORIES))}"
            )

        modified = False
        for notification_id, notification in list(self._history.items()):
            if notification.read:
                continue
            if category is not None and notification.category != category:
                continue

            # Создаём новую запись с read=True
            new_notification = Notification(
                notification_id=notification.notification_id,
                message=notification.message,
                category=notification.category,
                priority=notification.priority,
                created_at=notification.created_at,
                read=True,
                metadata=notification.metadata,
            )
            self._history[notification_id] = new_notification
            modified = True

        # Уведомляем о изменении badge счётчика
        if modified:
            self._notify_badge_update()

    def get_unread_count(self, category: Optional[str] = None) -> int:
        """Возвращает количество непрочитанных уведомлений.

        Args:
            category: Фильтр по категории (None = все категории).

        Returns:
            Количество непрочитанных уведомлений.

        Raises:
            ValueError: Если указана недопустимая категория.

        Example:
            >>> # Всего непрочитанных
            >>> count = service.get_unread_count()
            >>> # Непрочитанные security
            >>> security_count = service.get_unread_count(category=CATEGORY_SECURITY)
        """
        if category is not None and category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. Allowed: {', '.join(sorted(VALID_CATEGORIES))}"
            )

        count = 0
        for notification in self._history.values():
            if notification.read:
                continue
            if category is not None and notification.category != category:
                continue
            count += 1

        return count

    def clear_history(self, older_than_days: Optional[int] = None) -> None:
        """Очищает историю уведомлений.

        Args:
            older_than_days: Если указано, удаляет только уведомления
                старше указанного количества дней.

        Example:
            >>> # Очистить всю историю
            >>> service.clear_history()
            >>> # Очистить уведомления старше 7 дней
            >>> service.clear_history(older_than_days=7)
        """
        if older_than_days is None:
            # Очистка всей истории
            had_notifications = bool(self._history)
            self._history.clear()
            if had_notifications:
                self._notify_badge_update()
        else:
            # Очистка старых уведомлений
            cutoff_time = time.time() - (older_than_days * 24 * 60 * 60)
            modified = False

            ids_to_remove = [nid for nid, n in self._history.items() if n.created_at < cutoff_time]

            for notification_id in ids_to_remove:
                del self._history[notification_id]
                modified = True

            if modified:
                self._notify_badge_update()

    def get_notification(self, notification_id: str) -> Optional[Notification]:
        """Возвращает конкретное уведомление по ID.

        Args:
            notification_id: Идентификатор уведомления.

        Returns:
            Уведомление или None если not found.

        Example:
            >>> notification = service.get_notification("550e8400-e29b-41d4-a716-446655440000")
            >>> if notification:
            ...     print(notification.message)
        """
        return self._history.get(notification_id)

    def close_all_toasts(self) -> None:
        """Закрывает все открытые toast уведомления.

        Делегирует вызов в ToastService.

        Example:
            >>> service.close_all_toasts()
        """
        self._toast_service.close_all()

    def dismiss_all(self) -> None:
        """Закрывает все уведомления и очищает историю.

        Используется при shutdown для освобождения ресурсов.

        Example:
            >>> service.dismiss_all()
        """
        self._toast_service.close_all()
        self._history.clear()
        self._notify_badge_update()

    def count(self, category: Optional[str] = None) -> int:
        """Возвращает количество уведомлений (синоним get_unread_count).

        Args:
            category: Фильтр по категории (None = все категории).

        Returns:
            Количество непрочитанных уведомлений.

        Example:
            >>> count = service.count()
        """
        return self.get_unread_count(category)

    def show(
        self,
        message: str,
        category: str = CATEGORY_SYSTEM,
        priority: NotificationPriority = NotificationPriority.NORMAL,
    ) -> str:
        """Создаёт и отображает уведомление (синоним notify).

        Совместимость с другими сервисами уведомлений.

        Args:
            message: Текст уведомления.
            category: Категория (default: system).
            priority: Приоритет (default: NORMAL).

        Returns:
            UUID уведомления.
        """
        return self.notify(message, category, priority)


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__: list[str] = [
    "NotificationService",
    "Notification",
    "NotificationPriority",
    "CATEGORY_SECURITY",
    "CATEGORY_WORKFLOW",
    "CATEGORY_SYSTEM",
    "CATEGORY_SYNC",
    "MAX_HISTORY",
    "MAX_MESSAGE_LENGTH",
]
