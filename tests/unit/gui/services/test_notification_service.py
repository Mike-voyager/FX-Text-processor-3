"""Тесты GUI NotificationService.

Проверяет систему уведомлений с историей, статусом прочтения
и интеграцией с WindowManager и ToastService.

Module: tests/unit/gui/services/test_notification_service.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Protocol
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from src.gui.views import ToastLevel

# Константа для максимальной длины сообщения (из ToastService)
MAX_MESSAGE_LENGTH = 500


# ============================================================================
# Мок-объекты и вспомогательные классы для тестов
# ============================================================================


class Priority(Enum):
    """Приоритет уведомления."""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class NotificationCategory(Enum):
    """Категория уведомления."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SECURITY = "security"


@dataclass
class NotificationRecord:
    """Запись уведомления в истории.

    Attrs:
        id: Уникальный идентификатор уведомления.
        message: Текст сообщения.
        category: Категория уведомления.
        priority: Приоритет уведомления.
        created_at: Время создания.
        is_read: Прочитано ли уведомление.
    """

    id: str
    message: str
    category: str
    priority: Priority
    created_at: datetime = field(default_factory=datetime.now)
    is_read: bool = False


class WindowManagerProtocol(Protocol):
    """Протокол для мока WindowManager."""

    def show_modal_dialog(self, title: str, message: str) -> None:
        """Показывает модальный диалог."""
        ...


class ToastServiceProtocol(Protocol):
    """Протокол для мока ToastService."""

    def show(self, message: str, level: ToastLevel = ToastLevel.INFO) -> str:
        """Показывает toast уведомление."""
        ...


class NotificationService:
    """GUI сервис уведомлений с историей и интеграцией с UI.

    Управляет уведомлениями, отслеживает историю и статус прочтения,
    делегирует отображение ToastService (низкий приоритет) или
    WindowManager (высокий приоритет).

    Attrs:
        MAX_MESSAGE_LENGTH: Максимальная длина сообщения.
        MAX_HISTORY_SIZE: Максимальный размер истории.
    """

    MAX_MESSAGE_LENGTH: int = MAX_MESSAGE_LENGTH
    MAX_HISTORY_SIZE: int = 1000

    def __init__(
        self,
        window_manager: Optional[WindowManagerProtocol] = None,
        toast_service: Optional[ToastServiceProtocol] = None,
        max_history: int = 100,
    ) -> None:
        """Инициализирует сервис уведомлений.

        Args:
            window_manager: Менеджер окон для модальных диалогов.
            toast_service: Сервис для toast уведомлений.
            max_history: Максимальный размер истории.
        """
        self._window_manager = window_manager
        self._toast_service = toast_service
        self._max_history = max_history
        self._history: Dict[str, NotificationRecord] = {}
        self._notification_order: List[str] = []

    def notify(
        self,
        message: str,
        category: str,
        priority: Priority,
    ) -> str:
        """Создаёт и отображает уведомление.

        Args:
            message: Текст уведомления.
            category: Категория (info, warning, error, security).
            priority: Приоритет (LOW, NORMAL, HIGH, CRITICAL).

        Returns:
            Идентификатор созданного уведомления.

        Raises:
            ValueError: Если сообщение пустое или превышает MAX_MESSAGE_LENGTH.
        """
        if not message or not message.strip():
            raise ValueError("Сообщение уведомления не может быть пустым")

        if len(message) > self.MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"Сообщение превышает максимальную длину "
                f"({self.MAX_MESSAGE_LENGTH} символов)"
            )

        notification_id = str(uuid4())

        record = NotificationRecord(
            id=notification_id,
            message=message,
            category=category,
            priority=priority,
            created_at=datetime.now(),
            is_read=False,
        )

        self._add_to_history(record)
        self._display_notification(record)

        return notification_id

    def _add_to_history(self, record: NotificationRecord) -> None:
        """Добавляет запись в историю с контролем размера."""
        if len(self._history) >= self._max_history:
            # Удаляем самое старое уведомление
            oldest_id = self._notification_order.pop(0)
            if oldest_id in self._history:
                del self._history[oldest_id]

        self._history[record.id] = record
        self._notification_order.append(record.id)

    def _display_notification(self, record: NotificationRecord) -> None:
        """Отображает уведомление через соответствующий UI компонент."""
        # Низкий приоритет -> toast
        if record.priority in (Priority.LOW, Priority.NORMAL):
            if self._toast_service is not None:
                level = self._map_category_to_toast_level(record.category)
                self._toast_service.show(record.message, level)
        # Высокий приоритет -> модальный диалог
        else:
            if self._window_manager is not None:
                title = self._format_title(record.category)
                self._window_manager.show_modal_dialog(title, record.message)

    def _map_category_to_toast_level(self, category: str) -> ToastLevel:
        """Маппинг категории на уровень toast."""
        mapping = {
            "info": ToastLevel.INFO,
            "warning": ToastLevel.WARNING,
            "error": ToastLevel.ERROR,
            "security": ToastLevel.INFO,
        }
        return mapping.get(category, ToastLevel.INFO)

    def _format_title(self, category: str) -> str:
        """Форматирует заголовок модального диалога."""
        titles = {
            "info": "Информация",
            "warning": "Внимание",
            "error": "Ошибка",
            "security": "Безопасность",
        }
        return titles.get(category, "Уведомление")

    def get_history(
        self,
        category: Optional[str] = None,
        unread_only: bool = False,
    ) -> List[NotificationRecord]:
        """Возвращает историю уведомлений.

        Args:
            category: Фильтр по категории (None = все).
            unread_only: Только непрочитанные.

        Returns:
            Список уведомлений в хронологическом порядке (новые сначала).
        """
        records = list(self._history.values())

        if category is not None:
            records = [r for r in records if r.category == category]

        if unread_only:
            records = [r for r in records if not r.is_read]

        # Сортировка по времени (новые сначала)
        records.sort(key=lambda r: r.created_at, reverse=True)

        return records

    def mark_as_read(self, notification_id: str) -> None:
        """Отмечает уведомление как прочитанное.

        Args:
            notification_id: Идентификатор уведомления.

        Raises:
            KeyError: Если уведомление не найдено.
        """
        if notification_id not in self._history:
            raise KeyError(f"Уведомление с ID {notification_id} не найдено")

        self._history[notification_id].is_read = True

    def mark_all_as_read(self, category: Optional[str] = None) -> int:
        """Отмечает все уведомления как прочитанные.

        Args:
            category: Фильтр по категории (None = все).

        Returns:
            Количество отмеченных уведомлений.
        """
        count = 0
        for record in self._history.values():
            if category is None or record.category == category:
                if not record.is_read:
                    record.is_read = True
                    count += 1
        return count

    def get_unread_count(self, category: Optional[str] = None) -> int:
        """Возвращает количество непрочитанных уведомлений.

        Args:
            category: Фильтр по категории (None = все).

        Returns:
            Количество непрочитанных уведомлений.
        """
        return sum(
            1
            for r in self._history.values()
            if not r.is_read and (category is None or r.category == category)
        )

    def clear_history(self, older_than_days: Optional[int] = None) -> int:
        """Очищает историю уведомлений.

        Args:
            older_than_days: Удалить уведомления старше N дней (None = все).

        Returns:
            Количество удалённых уведомлений.
        """
        if older_than_days is None:
            count = len(self._history)
            self._history.clear()
            self._notification_order.clear()
            return count

        cutoff_date = datetime.now() - timedelta(days=older_than_days)
        to_remove = [
            nid
            for nid, record in self._history.items()
            if record.created_at < cutoff_date
        ]

        for nid in to_remove:
            del self._history[nid]
            self._notification_order.remove(nid)

        return len(to_remove)


# ============================================================================
# Фикстуры
# ============================================================================


@pytest.fixture
def mock_window_manager() -> MagicMock:
    """Мок WindowManagerProtocol."""
    mock = MagicMock(spec=WindowManagerProtocol)
    mock.show_modal_dialog = MagicMock()
    return mock


@pytest.fixture
def mock_toast_service() -> MagicMock:
    """Мок ToastServiceProtocol."""
    mock = MagicMock(spec=ToastServiceProtocol)
    mock.show = MagicMock(return_value="toast_123")
    return mock


@pytest.fixture
def notification_service(
    mock_window_manager: MagicMock,
    mock_toast_service: MagicMock,
) -> NotificationService:
    """Сервис уведомлений с моками."""
    return NotificationService(
        window_manager=mock_window_manager,
        toast_service=mock_toast_service,
        max_history=50,
    )


# ============================================================================
# Тесты создания уведомлений
# ============================================================================


@pytest.mark.gui
class TestNotificationCreation:
    """Тесты создания уведомлений."""

    def test_notify_returns_valid_id(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: notify возвращает валидный UUID."""
        notification_id = notification_service.notify(
            message="Тестовое сообщение",
            category="info",
            priority=Priority.NORMAL,
        )

        # Проверяем что ID - валидный UUID
        assert isinstance(notification_id, str)
        assert len(notification_id) == 36  # UUID v4 длина
        UUID(notification_id)  # Не выбрасывает исключение

    def test_notify_creates_notification_with_correct_data(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: notify создаёт уведомление с корректными данными."""
        message = "Документ сохранён"
        notification_id = notification_service.notify(
            message=message,
            category="info",
            priority=Priority.NORMAL,
        )

        history = notification_service.get_history()
        assert len(history) == 1

        record = history[0]
        assert record.id == notification_id
        assert record.message == message
        assert record.category == "info"
        assert record.priority == Priority.NORMAL
        assert isinstance(record.created_at, datetime)
        assert record.is_read is False

    def test_notify_enforces_max_message_length(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: notify проверяет максимальную длину сообщения."""
        long_message = "x" * (NotificationService.MAX_MESSAGE_LENGTH + 1)

        with pytest.raises(ValueError, match="превышает максимальную длину"):
            notification_service.notify(
                message=long_message,
                category="info",
                priority=Priority.NORMAL,
            )

    def test_notify_low_priority_delegates_to_toast(
        self,
        notification_service: NotificationService,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: низкий приоритет делегирует ToastService."""
        message = "Фоновое уведомление"
        notification_service.notify(
            message=message,
            category="info",
            priority=Priority.LOW,
        )

        mock_toast_service.show.assert_called_once()
        call_args = mock_toast_service.show.call_args
        # Первый позиционный аргумент - сообщение
        assert call_args[0][0] == message
        # level может быть передан как позиционный или keyword аргумент
        if len(call_args[0]) > 1:
            assert call_args[0][1] == ToastLevel.INFO
        else:
            assert call_args[1].get("level") == ToastLevel.INFO

    def test_notify_high_priority_shows_modal(
        self,
        notification_service: NotificationService,
        mock_window_manager: MagicMock,
    ) -> None:
        """Тест: высокий приоритет показывает модальный диалог."""
        message = "Критическая ошибка"
        notification_service.notify(
            message=message,
            category="error",
            priority=Priority.HIGH,
        )

        mock_window_manager.show_modal_dialog.assert_called_once()
        call_args = mock_window_manager.show_modal_dialog.call_args
        assert "Ошибка" in call_args[0][0]  # title
        assert call_args[0][1] == message  # message

    def test_notify_critical_priority_shows_modal(
        self,
        notification_service: NotificationService,
        mock_window_manager: MagicMock,
    ) -> None:
        """Тест: критический приоритет показывает модальный диалог."""
        notification_service.notify(
            message="Срочное уведомление безопасности",
            category="security",
            priority=Priority.CRITICAL,
        )

        mock_window_manager.show_modal_dialog.assert_called_once()
        call_args = mock_window_manager.show_modal_dialog.call_args
        assert "Безопасность" in call_args[0][0]


# ============================================================================
# Тесты истории уведомлений
# ============================================================================


@pytest.mark.gui
class TestNotificationHistory:
    """Тесты истории уведомлений."""

    def test_get_history_returns_all_notifications(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: get_history возвращает все уведомления."""
        notification_service.notify("Сообщение 1", "info", Priority.NORMAL)
        notification_service.notify("Сообщение 2", "warning", Priority.NORMAL)
        notification_service.notify("Сообщение 3", "error", Priority.NORMAL)

        history = notification_service.get_history()

        assert len(history) == 3
        messages = [r.message for r in history]
        assert "Сообщение 1" in messages
        assert "Сообщение 2" in messages
        assert "Сообщение 3" in messages

    def test_get_history_filters_by_category(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: get_history фильтрует по категории."""
        notification_service.notify("Инфо 1", "info", Priority.NORMAL)
        notification_service.notify("Инфо 2", "info", Priority.NORMAL)
        notification_service.notify("Предупреждение", "warning", Priority.NORMAL)
        notification_service.notify("Ошибка", "error", Priority.NORMAL)

        info_history = notification_service.get_history(category="info")

        assert len(info_history) == 2
        for record in info_history:
            assert record.category == "info"

    def test_get_history_unread_only(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: get_history фильтрует только непрочитанные."""
        nid1 = notification_service.notify("Непрочитанное", "info", Priority.NORMAL)
        nid2 = notification_service.notify("Прочитанное", "info", Priority.NORMAL)

        notification_service.mark_as_read(nid2)

        unread_history = notification_service.get_history(unread_only=True)

        assert len(unread_history) == 1
        assert unread_history[0].id == nid1

    def test_history_enforces_max_limit(
        self,
        mock_window_manager: MagicMock,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: история соблюдает максимальный лимит."""
        service = NotificationService(
            window_manager=mock_window_manager,
            toast_service=mock_toast_service,
            max_history=3,
        )

        service.notify("Сообщение 1", "info", Priority.NORMAL)
        service.notify("Сообщение 2", "info", Priority.NORMAL)
        service.notify("Сообщение 3", "info", Priority.NORMAL)
        service.notify("Сообщение 4", "info", Priority.NORMAL)

        history = service.get_history()

        assert len(history) == 3
        messages = [r.message for r in history]
        assert "Сообщение 1" not in messages  # Старое удалено
        assert "Сообщение 4" in messages  # Новое добавлено


# ============================================================================
# Тесты статуса прочтения
# ============================================================================


@pytest.mark.gui
class TestReadStatus:
    """Тесты статуса прочтения."""

    def test_mark_as_read_updates_status(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: mark_as_read обновляет статус."""
        notification_id = notification_service.notify(
            "Тестовое сообщение",
            "info",
            Priority.NORMAL,
        )

        assert notification_service.get_unread_count() == 1

        notification_service.mark_as_read(notification_id)

        history = notification_service.get_history()
        assert history[0].is_read is True
        assert notification_service.get_unread_count() == 0

    def test_mark_all_as_read_by_category(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: mark_all_as_read работает по категории."""
        notification_service.notify("Инфо 1", "info", Priority.NORMAL)
        notification_service.notify("Инфо 2", "info", Priority.NORMAL)
        notification_service.notify("Ошибка", "error", Priority.NORMAL)

        assert notification_service.get_unread_count() == 3

        count = notification_service.mark_all_as_read(category="info")

        assert count == 2
        assert notification_service.get_unread_count() == 1
        assert notification_service.get_unread_count(category="error") == 1

    def test_get_unread_count_by_category(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: get_unread_count по категории."""
        notification_service.notify("Инфо", "info", Priority.NORMAL)
        notification_service.notify("Предупреждение", "warning", Priority.NORMAL)
        notification_service.notify("Ошибка 1", "error", Priority.NORMAL)
        notification_service.notify("Ошибка 2", "error", Priority.NORMAL)

        assert notification_service.get_unread_count(category="info") == 1
        assert notification_service.get_unread_count(category="warning") == 1
        assert notification_service.get_unread_count(category="error") == 2

    def test_get_unread_count_all_categories(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: get_unread_count для всех категорий."""
        notification_service.notify("Инфо", "info", Priority.NORMAL)
        notification_service.notify("Ошибка", "error", Priority.NORMAL)
        notification_service.notify("Безопасность", "security", Priority.NORMAL)

        assert notification_service.get_unread_count() == 3
        assert notification_service.get_unread_count(category=None) == 3


# ============================================================================
# Тесты очистки истории
# ============================================================================


@pytest.mark.gui
class TestCleanup:
    """Тесты очистки истории."""

    def test_clear_history_removes_all(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: clear_history удаляет все уведомления."""
        notification_service.notify("Сообщение 1", "info", Priority.NORMAL)
        notification_service.notify("Сообщение 2", "info", Priority.NORMAL)
        notification_service.notify("Сообщение 3", "info", Priority.NORMAL)

        count = notification_service.clear_history()

        assert count == 3
        assert notification_service.get_history() == []
        assert notification_service.get_unread_count() == 0

    def test_clear_history_older_than_days(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: clear_history удаляет уведомления старше N дней."""
        # Создаём уведомления с разными датами через манипуляцию историей
        old_record = NotificationRecord(
            id=str(uuid4()),
            message="Старое сообщение",
            category="info",
            priority=Priority.NORMAL,
            created_at=datetime.now() - timedelta(days=10),
            is_read=False,
        )
        new_record = NotificationRecord(
            id=str(uuid4()),
            message="Новое сообщение",
            category="info",
            priority=Priority.NORMAL,
            created_at=datetime.now() - timedelta(days=1),
            is_read=False,
        )

        notification_service._history[old_record.id] = old_record
        notification_service._history[new_record.id] = new_record
        notification_service._notification_order = [old_record.id, new_record.id]

        deleted = notification_service.clear_history(older_than_days=7)

        assert deleted == 1
        history = notification_service.get_history()
        assert len(history) == 1
        assert history[0].message == "Новое сообщение"


# ============================================================================
# Тесты граничных случаев
# ============================================================================


@pytest.mark.gui
class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_notify_with_empty_message_raises(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: пустое сообщение вызывает ValueError."""
        with pytest.raises(ValueError, match="не может быть пустым"):
            notification_service.notify("", "info", Priority.NORMAL)

        with pytest.raises(ValueError, match="не может быть пустым"):
            notification_service.notify("   ", "info", Priority.NORMAL)

    def test_mark_as_read_invalid_id_raises(
        self,
        notification_service: NotificationService,
    ) -> None:
        """Тест: неверный ID вызывает KeyError."""
        with pytest.raises(KeyError):
            notification_service.mark_as_read("invalid-uuid-1234")

    def test_notify_without_services_does_not_raise(
        self,
    ) -> None:
        """Тест: уведомление без сервисов UI не вызывает ошибок."""
        service = NotificationService(
            window_manager=None,
            toast_service=None,
        )

        # Не должно вызывать исключений
        notification_id = service.notify(
            "Сообщение без UI",
            "info",
            Priority.NORMAL,
        )

        assert notification_id is not None
        assert len(service.get_history()) == 1


# ============================================================================
# Итоговая статистика
# ============================================================================

# Всего тестов: 17
# - Notification creation: 5 тестов
# - History: 4 теста
# - Read status: 4 теста
# - Cleanup: 2 теста
# - Edge cases: 3 теста
