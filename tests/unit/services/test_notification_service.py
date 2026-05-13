"""Тесты NotificationService.

Module: tests/unit/services/test_notification_service.py
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

import pytest

from src.services.notification_service import (
    DismissCallback,
    Notification,
    NotificationAction,
    NotificationCallback,
    NotificationPriority,
    NotificationService,
    NotificationType,
    ShowResult,
)


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> NotificationService:
    """Сервис уведомлений."""
    return NotificationService(
        max_notifications=10,
        default_timeout_seconds=5,
        error_timeout_seconds=10,
    )


@pytest.fixture
def received_notifications() -> List[Notification]:
    """Список полученных уведомлений."""
    return []


@pytest.fixture
def dismissed_notifications() -> List[tuple[UUID, Optional[str]]]:
    """Список закрытых уведомлений."""
    return []


@pytest.fixture
def subscribed_service(
    service: NotificationService,
    received_notifications: List[Notification],
) -> NotificationService:
    """Сервис с подпиской на уведомления."""
    def callback(notification: Notification) -> None:
        received_notifications.append(notification)

    service.subscribe(callback)
    return service


# ---------------------------------------------------------------------------
# Тесты моделей
# ---------------------------------------------------------------------------


class TestNotification:
    """Тесты модели Notification."""

    def test_create_notification(self) -> None:
        """Тест создания уведомления."""
        notification = Notification(
            type=NotificationType.INFO,
            title="Test",
            message="Test message",
        )

        assert notification.type == NotificationType.INFO
        assert notification.title == "Test"
        assert notification.message == "Test message"
        assert notification.dismissible is True
        assert notification.persistent is False

    def test_notification_with_actions(self) -> None:
        """Тест уведомления с действиями."""
        notification = Notification(
            title="Confirm",
            message="Are you sure?",
            actions=[
                NotificationAction(id="yes", label="Yes", style="primary"),
                NotificationAction(id="no", label="No", style="danger"),
            ],
        )

        assert len(notification.actions) == 2
        assert notification.actions[0].id == "yes"

    def test_is_expired(self) -> None:
        """Тест проверки истечения."""
        # Не истёкшее
        notification = Notification(
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert not notification.is_expired()

        # Истёкшее
        notification = Notification(
            expires_at=datetime.now() - timedelta(hours=1),
        )
        assert notification.is_expired()

        # Без срока
        notification = Notification()
        assert not notification.is_expired()

    def test_with_action(self) -> None:
        """Тест добавления действия."""
        notification = Notification(title="Test", message="Test")
        new_notification = notification.with_action("confirm", "Confirm", "primary")

        assert len(new_notification.actions) == 1
        assert new_notification.actions[0].id == "confirm"


# ---------------------------------------------------------------------------
# Тесты показа уведомлений
# ---------------------------------------------------------------------------


class TestShowNotifications:
    """Тесты показа уведомлений."""

    def test_show_info(self, service: NotificationService) -> None:
        """Тест показа информационного уведомления."""
        result = service.info("Info", "Information message")

        assert result.success
        assert result.notification_id is not None
        assert service.count() == 1

    def test_show_success(self, service: NotificationService) -> None:
        """Тест показа успешного уведомления."""
        result = service.success("Success", "Operation completed")

        assert result.success
        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert notification.type == NotificationType.SUCCESS

    def test_show_warning(self, service: NotificationService) -> None:
        """Тест показа предупреждения."""
        result = service.warning("Warning", "Attention required")

        assert result.success
        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert notification.type == NotificationType.WARNING
        assert notification.priority == NotificationPriority.HIGH

    def test_show_error(self, service: NotificationService) -> None:
        """Тест показа ошибки."""
        result = service.error("Error", "Something went wrong")

        assert result.success
        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert notification.type == NotificationType.ERROR
        assert notification.priority == NotificationPriority.HIGH

    def test_show_progress(self, service: NotificationService) -> None:
        """Тест показа прогресса."""
        result = service.progress("Progress", "Processing...", 0.5)

        assert result.success
        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert notification.type == NotificationType.PROGRESS
        assert notification.data.get("progress") == 0.5

    def test_progress_clamping(self, service: NotificationService) -> None:
        """Тест ограничения прогресса."""
        result = service.progress("Progress", "Processing...", 1.5)

        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert notification.data.get("progress") == 1.0

        result = service.progress("Progress", "Processing...", -0.5)

        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert notification.data.get("progress") == 0.0

    def test_show_with_actions(self, service: NotificationService) -> None:
        """Тест показа с действиями."""
        actions = [
            NotificationAction(id="save", label="Save", style="primary"),
            NotificationAction(id="discard", label="Discard", style="danger"),
        ]

        result = service.show(
            title="Save changes?",
            message="You have unsaved changes",
            type=NotificationType.WARNING,
            actions=actions,
        )

        assert result.success
        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert len(notification.actions) == 2

    def test_show_persistent(self, service: NotificationService) -> None:
        """Тест показа постоянного уведомления."""
        result = service.show(
            title="Important",
            message="Do not close",
            persistent=True,
        )

        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert notification.persistent
        assert notification.expires_at is None


# ---------------------------------------------------------------------------
# Тесты подписки
# ---------------------------------------------------------------------------


class TestSubscription:
    """Тесты подписки на уведомления."""

    def test_subscribe(
        self,
        subscribed_service: NotificationService,
        received_notifications: List[Notification],
    ) -> None:
        """Тест подписки на уведомления."""
        subscribed_service.info("Test", "Message")

        assert len(received_notifications) == 1
        assert received_notifications[0].title == "Test"

    def test_unsubscribe(self, service: NotificationService) -> None:
        """Тест отписки от уведомлений."""
        received: List[Notification] = []

        def callback(notification: Notification) -> None:
            received.append(notification)

        service.subscribe(callback)
        service.info("First", "Message 1")

        assert len(received) == 1

        service.unsubscribe(callback)
        service.info("Second", "Message 2")

        assert len(received) == 1  # Не изменилось

    def test_on_dismiss(
        self,
        service: NotificationService,
        dismissed_notifications: List[tuple[UUID, Optional[str]]],
    ) -> None:
        """Тест callback при закрытии."""
        def on_dismiss(notification_id: UUID, action: Optional[str]) -> None:
            dismissed_notifications.append((notification_id, action))

        service.on_dismiss(on_dismiss)

        result = service.info("Test", "Message")
        service.dismiss(result.notification_id)  # type: ignore

        assert len(dismissed_notifications) == 1


# ---------------------------------------------------------------------------
# Тесты закрытия
# ---------------------------------------------------------------------------


class TestDismiss:
    """Тесты закрытия уведомлений."""

    def test_dismiss(self, service: NotificationService) -> None:
        """Тест закрытия уведомления."""
        result = service.info("Test", "Message")
        notification_id = result.notification_id

        assert service.count() == 1

        dismissed = service.dismiss(notification_id)  # type: ignore

        assert dismissed
        assert service.count() == 0

    def test_dismiss_nonexistent(self, service: NotificationService) -> None:
        """Тест закрытия несуществующего уведомления."""
        from uuid import uuid4

        dismissed = service.dismiss(uuid4())

        assert not dismissed

    def test_dismiss_all(self, service: NotificationService) -> None:
        """Тест закрытия всех уведомлений."""
        service.info("Test 1", "Message 1")
        service.info("Test 2", "Message 2")
        service.info("Test 3", "Message 3")

        assert service.count() == 3

        count = service.dismiss_all()

        assert count == 3
        assert service.count() == 0

    def test_dismiss_by_type(self, service: NotificationService) -> None:
        """Тест закрытия по типу."""
        service.info("Info", "Message")
        service.error("Error", "Message")
        service.warning("Warning", "Message")

        count = service.dismiss_by_type(NotificationType.ERROR)

        assert count == 1
        assert service.count() == 2
        assert not service.has_errors()


# ---------------------------------------------------------------------------
# Тесты запросов
# ---------------------------------------------------------------------------


class TestQueries:
    """Тесты запросов."""

    def test_get(self, service: NotificationService) -> None:
        """Тест получения уведомления."""
        result = service.info("Test", "Message")
        notification = service.get(result.notification_id)  # type: ignore

        assert notification is not None
        assert notification.title == "Test"

    def test_get_all(self, service: NotificationService) -> None:
        """Тест получения всех уведомлений."""
        service.info("Test 1", "Message")
        service.info("Test 2", "Message")

        all_notifications = service.get_all()

        assert len(all_notifications) == 2

    def test_get_by_type(self, service: NotificationService) -> None:
        """Тест получения по типу."""
        service.info("Info", "Message")
        service.error("Error", "Message")
        service.error("Error 2", "Message")

        errors = service.get_by_type(NotificationType.ERROR)

        assert len(errors) == 2

    def test_get_by_priority(self, service: NotificationService) -> None:
        """Тест получения по приоритету."""
        service.info("Low", "Message")  # NORMAL
        service.warning("High", "Message")  # HIGH
        service.error("Critical", "Message")  # HIGH

        high_priority = service.get_by_priority(NotificationPriority.HIGH)

        assert len(high_priority) == 2

    def test_has_errors(self, service: NotificationService) -> None:
        """Тест проверки наличия ошибок."""
        assert not service.has_errors()

        service.error("Error", "Message")

        assert service.has_errors()

    def test_has_warnings(self, service: NotificationService) -> None:
        """Тест проверки наличия предупреждений."""
        assert not service.has_warnings()

        service.warning("Warning", "Message")

        assert service.has_warnings()


# ---------------------------------------------------------------------------
# Тесты лимитов
# ---------------------------------------------------------------------------


class TestLimits:
    """Тесты лимитов."""

    def test_max_notifications(self) -> None:
        """Тест максимального количества уведомлений."""
        service = NotificationService(max_notifications=3)

        service.info("Test 1", "Message")
        service.info("Test 2", "Message")
        service.info("Test 3", "Message")
        service.info("Test 4", "Message")  # Должно вытеснить первое

        assert service.count() == 3


# ---------------------------------------------------------------------------
# Тесты истечения срока
# ---------------------------------------------------------------------------


class TestExpiration:
    """Тесты истечения срока."""

    def test_cleanup_expired(self, service: NotificationService) -> None:
        """Тест очистки истёкших уведомлений."""
        # Создаём истёкшее уведомление вручную
        notification = Notification(
            type=NotificationType.INFO,
            title="Expired",
            message="This is expired",
            expires_at=datetime.now() - timedelta(hours=1),
        )
        service._notifications[notification.id] = notification
        service._history.append(notification.id)

        assert service.count() == 1

        # Очистка должна удалить истёкшие
        all_notifications = service.get_all()

        assert len(all_notifications) == 0

    def test_persistent_not_expired(self, service: NotificationService) -> None:
        """Тест, что постоянные уведомления не удаляются."""
        notification = Notification(
            type=NotificationType.INFO,
            title="Persistent",
            message="This stays",
            expires_at=datetime.now() - timedelta(hours=1),
            persistent=True,
        )
        service._notifications[notification.id] = notification
        service._history.append(notification.id)

        all_notifications = service.get_all()

        # Постоянное уведомление не должно быть удалено
        assert len(all_notifications) == 1


# ---------------------------------------------------------------------------
# Тесты интеграции
# ---------------------------------------------------------------------------


class TestIntegration:
    """Интеграционные тесты."""

    def test_full_lifecycle(self, service: NotificationService) -> None:
        """Тест полного жизненного цикла."""
        # Показ уведомления
        result = service.warning(
            "Warning",
            "Please confirm",
            actions=[
                NotificationAction(id="yes", label="Yes"),
                NotificationAction(id="no", label="No"),
            ],
        )

        assert result.success
        assert service.count() == 1

        # Получение
        notification = service.get(result.notification_id)  # type: ignore
        assert notification is not None
        assert len(notification.actions) == 2

        # Закрытие с действием
        dismissed = service.dismiss(result.notification_id, action="yes")  # type: ignore

        assert dismissed
        assert service.count() == 0

    def test_multiple_types(self, service: NotificationService) -> None:
        """Тест разных типов уведомлений."""
        service.info("Info", "Information")
        service.success("Success", "Completed")
        service.warning("Warning", "Attention")
        service.error("Error", "Failed")

        assert service.count() == 4
        assert service.has_errors()
        assert service.has_warnings()

        # Закрытие всех ошибок
        service.dismiss_by_type(NotificationType.ERROR)

        assert service.count() == 3
        assert not service.has_errors()
        assert service.has_warnings()