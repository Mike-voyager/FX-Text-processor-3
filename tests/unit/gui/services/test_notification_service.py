"""Unit-тесты для NotificationService.

Проверяет:
- Создание NotificationService
- Создание уведомлений с валидацией
- Уровни приоритета и маршрутизацию
- Историю уведомлений (get_history, mark_as_read, get_unread_count)
- Группировку по категориям
- Очистку истории
- Badge callbacks
- Валидацию метаданных (безопасность)
- Ограничение длины сообщения

Coverage target: ≥90%
"""

from __future__ import annotations

import time
import tkinter as tk
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.services.notification_service import (
    CATEGORY_SECURITY,
    CATEGORY_SYNC,
    CATEGORY_SYSTEM,
    CATEGORY_WORKFLOW,
    MAX_HISTORY,
    Notification,
    NotificationPriority,
    NotificationService,
)
from src.gui.services.window_manager import WindowManager


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture  # type: ignore[misc]
def tk_root() -> Iterator[tk.Tk]:
    """Fixture: создаёт корневое окно Tk."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture  # type: ignore[misc]
def window_manager(tk_root: tk.Tk) -> WindowManager:
    """Fixture: создаёт WindowManager."""
    return WindowManager(tk_root)


@pytest.fixture  # type: ignore[misc]
def notification_service(
    tk_root: tk.Tk, window_manager: WindowManager
) -> NotificationService:
    """Fixture: создаёт NotificationService."""
    return NotificationService(tk_root, window_manager)


# =============================================================================
# TEST: NotificationPriority Enum
# =============================================================================


@pytest.mark.gui
class TestNotificationPriority:
    """Тесты для перечисления NotificationPriority."""

    def test_priority_values(self) -> None:
        """Тест: значения приоритетов корректны."""
        assert NotificationPriority.LOW.value == 1
        assert NotificationPriority.NORMAL.value == 2
        assert NotificationPriority.HIGH.value == 3
        assert NotificationPriority.CRITICAL.value == 4

    def test_priority_ordering(self) -> None:
        """Тест: приоритеты упорядочены по возрастанию."""
        assert NotificationPriority.LOW < NotificationPriority.NORMAL
        assert NotificationPriority.NORMAL < NotificationPriority.HIGH
        assert NotificationPriority.HIGH < NotificationPriority.CRITICAL


# =============================================================================
# TEST: Notification Dataclass
# =============================================================================


@pytest.mark.gui
class TestNotification:
    """Тесты для дата-класса Notification."""

    def test_notification_creation(self) -> None:
        """Тест: создание уведомления."""
        notification = Notification(
            notification_id="test-id",
            message="Тестовое сообщение",
            category=CATEGORY_WORKFLOW,
            priority=NotificationPriority.NORMAL,
            created_at=time.time(),
            read=False,
            metadata=None,
        )
        assert notification.notification_id == "test-id"
        assert notification.message == "Тестовое сообщение"
        assert notification.category == CATEGORY_WORKFLOW
        assert notification.priority == NotificationPriority.NORMAL
        assert notification.read is False

    def test_notification_frozen(self) -> None:
        """Тест: уведомление иммутабельно (frozen=True)."""
        notification = Notification(
            notification_id="frozen-id",
            message="Заморожено",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
            created_at=time.time(),
            read=False,
            metadata=None,
        )
        with pytest.raises(AttributeError):
            notification.read = True  # type: ignore[misc]

    def test_notification_with_metadata(self) -> None:
        """Тест: создание уведомления с метаданными."""
        metadata = {"key": "value", "count": 42}
        notification = Notification(
            notification_id="meta-id",
            message="С метаданными",
            category=CATEGORY_SECURITY,
            priority=NotificationPriority.HIGH,
            created_at=time.time(),
            read=False,
            metadata=metadata,
        )
        assert notification.metadata == metadata


# =============================================================================
# TEST: NotificationService Creation
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceCreation:
    """Тесты для создания NotificationService."""

    def test_service_creation(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: создание сервиса уведомлений."""
        assert notification_service is not None
        assert len(notification_service._history) == 0

    def test_service_has_toast_service(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: сервис имеет ToastService."""
        assert notification_service._toast_service is not None

    def test_service_has_window_manager(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: сервис имеет WindowManager."""
        assert notification_service._window_manager is not None


# =============================================================================
# TEST: Notify (Low/Normal Priority — Toast)
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceNotify:
    """Тесты для метода notify."""

    def test_notify_low_priority(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: LOW приоритет создаёт уведомление и возвращает UUID."""
        nid = notification_service.notify(
            message="Низкий приоритет",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        assert nid is not None
        assert len(nid) > 0

    def test_notify_normal_priority(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: NORMAL приоритет создаёт уведомление."""
        nid = notification_service.notify(
            message="Нормальный приоритет",
            category=CATEGORY_WORKFLOW,
            priority=NotificationPriority.NORMAL,
        )
        assert nid is not None
        assert nid in notification_service._history

    def test_notify_stores_in_history(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: уведомление сохраняется в истории."""
        nid = notification_service.notify(
            message="Тест истории",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        assert nid in notification_service._history
        notification = notification_service._history[nid]
        assert notification.message == "Тест истории"

    def test_notify_invalid_category_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: недопустимая категория вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid category"):
            notification_service.notify(
                message="Тест",
                category="invalid_category",
                priority=NotificationPriority.LOW,
            )

    def test_notify_message_too_long_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: слишком длинное сообщение вызывает ValueError."""
        from src.gui.services.toast_service import MAX_MESSAGE_LENGTH

        with pytest.raises(ValueError, match="exceeds maximum length"):
            notification_service.notify(
                message="x" * (MAX_MESSAGE_LENGTH + 1),
                category=CATEGORY_SYSTEM,
                priority=NotificationPriority.LOW,
            )


# =============================================================================
# TEST: Validation
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceValidation:
    """Тесты для валидации входных данных."""

    def test_validate_metadata_none_ok(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: None метаданные допустимы."""
        notification_service._validate_metadata(None)

    def test_validate_metadata_dict_ok(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: валидные метаданные допустимы."""
        notification_service._validate_metadata({"key": "value"})

    def test_validate_metadata_callable_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: callable в метаданных вызывает ValueError."""
        with pytest.raises(ValueError, match="callable"):
            notification_service._validate_metadata({"func": lambda: None})

    def test_validate_metadata_eval_string_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: строка с eval() вызывает ValueError."""
        with pytest.raises(ValueError, match="dangerous"):
            notification_service._validate_metadata(
                {"code": "eval(expression)"}
            )

    def test_validate_metadata_exec_string_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: строка с exec() вызывает ValueError."""
        with pytest.raises(ValueError, match="dangerous"):
            notification_service._validate_metadata(
                {"code": "exec(command)"}
            )

    def test_validate_metadata_non_dict_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: не-словарь метаданных вызывает TypeError."""
        with pytest.raises(TypeError, match="dict or None"):
            notification_service._validate_metadata("not a dict")  # type: ignore[arg-type]

    def test_validate_category_invalid_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: невалидная категория вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid category"):
            notification_service._validate_category("invalid")

    def test_validate_category_valid_passes(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: валидные категории проходят проверку."""
        for category in (CATEGORY_SECURITY, CATEGORY_WORKFLOW, CATEGORY_SYSTEM, CATEGORY_SYNC):
            notification_service._validate_category(category)


# =============================================================================
# TEST: History Operations
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceHistory:
    """Тесты для операций с историей уведомлений."""

    def test_get_history_empty(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: пустая история возвращает пустой список."""
        history = notification_service.get_history()
        assert history == []

    def test_get_history_returns_notifications(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: история возвращает список уведомлений."""
        notification_service.notify(
            message="Первое",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        notification_service.notify(
            message="Второе",
            category=CATEGORY_WORKFLOW,
            priority=NotificationPriority.NORMAL,
        )
        history = notification_service.get_history()
        assert len(history) == 2

    def test_get_history_filter_by_category(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: фильтрация истории по категории."""
        notification_service.notify(
            message="Security",
            category=CATEGORY_SECURITY,
            priority=NotificationPriority.LOW,
        )
        notification_service.notify(
            message="Workflow",
            category=CATEGORY_WORKFLOW,
            priority=NotificationPriority.LOW,
        )
        security = notification_service.get_history(category=CATEGORY_SECURITY)
        assert len(security) == 1
        assert security[0].category == CATEGORY_SECURITY

    def test_get_history_filter_invalid_category_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: фильтрация по невалидной категории вызывает ошибку."""
        with pytest.raises(ValueError, match="Invalid category"):
            notification_service.get_history(category="invalid")

    def test_get_history_unread_only(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: фильтрация только непрочитанных."""
        nid = notification_service.notify(
            message="Прочитанное",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        notification_service.notify(
            message="Непрочитанное",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        notification_service.mark_as_read(nid)
        unread = notification_service.get_history(unread_only=True)
        assert len(unread) == 1
        assert unread[0].message == "Непрочитанное"


# =============================================================================
# TEST: Read/Unread
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceReadUnread:
    """Тесты для отметки прочитанных уведомлений."""

    def test_mark_as_read(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: отметка уведомления как прочитанного."""
        nid = notification_service.notify(
            message="Для прочтения",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        assert notification_service._history[nid].read is False
        notification_service.mark_as_read(nid)
        assert notification_service._history[nid].read is True

    def test_mark_as_read_unknown_id_raises(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: отметка несуществующего ID вызывает KeyError."""
        with pytest.raises(KeyError, match="not found"):
            notification_service.mark_as_read("nonexistent-id")

    def test_get_unread_count(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: подсчёт непрочитанных уведомлений."""
        notification_service.notify(
            message="Первое",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        notification_service.notify(
            message="Второе",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        assert notification_service.get_unread_count() == 2

    def test_get_unread_count_after_marking(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: подсчёт после отметки прочитанных."""
        nid1 = notification_service.notify(
            message="Первое",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        notification_service.notify(
            message="Второе",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        notification_service.mark_as_read(nid1)
        assert notification_service.get_unread_count() == 1

    def test_get_unread_count_by_category(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: подсчёт непрочитанных по категории."""
        notification_service.notify(
            message="Sec 1",
            category=CATEGORY_SECURITY,
            priority=NotificationPriority.LOW,
        )
        notification_service.notify(
            message="Sys 1",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        assert notification_service.get_unread_count(CATEGORY_SECURITY) == 1
        assert notification_service.get_unread_count(CATEGORY_SYSTEM) == 1

    def test_mark_all_as_read(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: отметка всех уведомлений как прочитанных."""
        notification_service.notify(
            message="A", category=CATEGORY_SYSTEM, priority=NotificationPriority.LOW
        )
        notification_service.notify(
            message="B", category=CATEGORY_SECURITY, priority=NotificationPriority.LOW
        )
        notification_service.mark_all_as_read()
        assert notification_service.get_unread_count() == 0

    def test_mark_all_as_read_by_category(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: отметка всех уведомлений категории как прочитанных."""
        notification_service.notify(
            message="Sec", category=CATEGORY_SECURITY, priority=NotificationPriority.LOW
        )
        notification_service.notify(
            message="Sys", category=CATEGORY_SYSTEM, priority=NotificationPriority.LOW
        )
        notification_service.mark_all_as_read(category=CATEGORY_SECURITY)
        assert notification_service.get_unread_count(CATEGORY_SECURITY) == 0
        assert notification_service.get_unread_count(CATEGORY_SYSTEM) == 1


# =============================================================================
# TEST: History Cleanup
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceCleanup:
    """Тесты для очистки истории уведомлений."""

    def test_clear_history(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: полная очистка истории."""
        notification_service.notify(
            message="Удалить", category=CATEGORY_SYSTEM, priority=NotificationPriority.LOW
        )
        notification_service.clear_history()
        assert len(notification_service._history) == 0

    def test_clear_history_older_than_days(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: очистка старых уведомлений по возрасту."""
        nid_old = notification_service.notify(
            message="Старое", category=CATEGORY_SYSTEM, priority=NotificationPriority.LOW
        )
        # Искусственно устанавливаем старое время
        old_notification = notification_service._history[nid_old]
        old_time = time.time() - 30 * 24 * 60 * 60  # 30 дней назад
        notification_service._history[nid_old] = Notification(
            notification_id=old_notification.notification_id,
            message=old_notification.message,
            category=old_notification.category,
            priority=old_notification.priority,
            created_at=old_time,
            read=old_notification.read,
            metadata=old_notification.metadata,
        )
        # Добавляем свежее уведомление
        notification_service.notify(
            message="Новое", category=CATEGORY_SYSTEM, priority=NotificationPriority.LOW
        )
        notification_service.clear_history(older_than_days=7)
        assert len(notification_service._history) == 1

    def test_max_history_enforcement(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: история автоматически очищается при превышении MAX_HISTORY."""
        for i in range(MAX_HISTORY + 10):
            notification_service.notify(
                message=f"Уведомление {i}",
                category=CATEGORY_SYSTEM,
                priority=NotificationPriority.LOW,
            )
        assert len(notification_service._history) <= MAX_HISTORY


# =============================================================================
# TEST: Badge Callbacks
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceBadge:
    """Тесты для badge callbacks."""

    def test_register_badge_callback(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: регистрация badge callback."""
        callback = MagicMock()
        notification_service.register_badge_callback(callback)
        assert callback in notification_service._badge_callbacks

    def test_unregister_badge_callback(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: удаление badge callback."""
        callback = MagicMock()
        notification_service.register_badge_callback(callback)
        notification_service.unregister_badge_callback(callback)
        assert callback not in notification_service._badge_callbacks

    def test_badge_callback_called_on_notify(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: badge callback вызывается при NORMAL уведомлении."""
        callback = MagicMock()
        notification_service.register_badge_callback(callback)
        notification_service.notify(
            message="Тест badge",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.NORMAL,
        )
        callback.assert_called()

    def test_badge_callback_error_ignored(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: ошибка в badge callback не прерывает работу."""
        failing_callback = MagicMock(side_effect=RuntimeError("callback error"))
        notification_service.register_badge_callback(failing_callback)
        # Не должно падать
        notification_service.notify(
            message="Тест ошибки",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.NORMAL,
        )


# =============================================================================
# TEST: show() Convenience Method
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceShow:
    """Тесты для удобного метода show."""

    def test_show_creates_notification(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: show() создаёт уведомление с параметрами по умолчанию."""
        nid = notification_service.show("Тестовое сообщение")
        assert nid is not None
        assert nid in notification_service._history

    def test_show_with_custom_params(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: show() с кастомными параметрами."""
        nid = notification_service.show(
            message="Безопасность",
            category=CATEGORY_SECURITY,
            priority=NotificationPriority.HIGH,
        )
        assert nid is not None
        notification = notification_service._history[nid]
        assert notification.category == CATEGORY_SECURITY
        assert notification.priority == NotificationPriority.HIGH


# =============================================================================
# TEST: get_notification
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceGetNotification:
    """Тесты для получения уведомления по ID."""

    def test_get_notification_existing(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: получение существующего уведомления."""
        nid = notification_service.notify(
            message="Найти",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        result = notification_service.get_notification(nid)
        assert result is not None
        assert result.message == "Найти"

    def test_get_notification_nonexistent(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: получение несуществующего уведомления возвращает None."""
        result = notification_service.get_notification("nonexistent-id")
        assert result is None


# =============================================================================
# TEST: dismiss_all
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceDismissAll:
    """Тесты для полного закрытия уведомлений."""

    def test_dismiss_all(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: dismiss_all очищает историю и закрывает тосты."""
        notification_service.notify(
            message="Для удаления",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        notification_service.dismiss_all()
        assert len(notification_service._history) == 0

    def test_count_method(
        self, notification_service: NotificationService
    ) -> None:
        """Тест: count() — синоним get_unread_count."""
        notification_service.notify(
            message="Подсчёт",
            category=CATEGORY_SYSTEM,
            priority=NotificationPriority.LOW,
        )
        assert notification_service.count() == notification_service.get_unread_count()


# =============================================================================
# TEST: HIGH/CRITICAL Priority (Modal Dialog)
# =============================================================================


@pytest.mark.gui
class TestNotificationServiceHighPriority:
    """Тесты для HIGH/CRITICAL приоритетов (модальные диалоги)."""

    @patch("src.gui.services.notification_service.tkinter.messagebox")
    def test_high_priority_shows_warning(
        self, mock_messagebox: MagicMock, notification_service: NotificationService
    ) -> None:
        """Тест: HIGH приоритет показывает предупреждение."""
        notification_service.notify(
            message="Важное уведомление",
            category=CATEGORY_SECURITY,
            priority=NotificationPriority.HIGH,
        )
        mock_messagebox.showwarning.assert_called_once()

    @patch("src.gui.services.notification_service.tkinter.messagebox")
    def test_critical_priority_shows_error(
        self, mock_messagebox: MagicMock, notification_service: NotificationService
    ) -> None:
        """Тест: CRITICAL приоритет показывает ошибку."""
        notification_service.notify(
            message="Критическое уведомление",
            category=CATEGORY_SECURITY,
            priority=NotificationPriority.CRITICAL,
        )
        mock_messagebox.showerror.assert_called_once()