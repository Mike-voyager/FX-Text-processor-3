"""Unit-тесты для GUIErrorHandler и ErrorContext.

Проверяет:
- Обработку SecurityError (audit logging)
- Обработку AuditError (graceful degradation)
- Обработку LifecycleError, RendererError, GUIError
- Обработку неизвестных исключений
- ErrorContext как контекстный менеджер
- Регистрацию кастомных обработчиков
- Тихую обработку (handle_silent)

Coverage target: >=90%
"""

import pytest

from src.gui.core.error_handler import ErrorContext, GUIErrorHandler
from src.gui.core.exceptions import (
    AuditError,
    GUIError,
    LifecycleError,
    RendererError,
    SecurityError,
)


# ==============================================================================
# TEST: GUIErrorHandler
# ==============================================================================


class TestGUIErrorHandler:
    """Тесты централизованного обработчика ошибок GUI."""

    def test_handle_security_error(self) -> None:
        """SecurityError вызывает _handle_security_error."""
        handler = GUIErrorHandler()
        notifications: list[tuple[str, str]] = []

        def ui_callback(title: str, message: str) -> None:
            notifications.append((title, message))

        error = SecurityError("Access denied")
        handler.handle(error, {"operation": "save"}, ui_callback=ui_callback)
        assert len(notifications) == 1
        assert "Security" in notifications[0][0]

    def test_handle_audit_error(self) -> None:
        """AuditError обрабатывается без UI уведомления."""
        handler = GUIErrorHandler()
        error = AuditError("Audit log failed", event_type="security_event")
        # Не должно вызывать ui_callback
        handler.handle(error, {"operation": "test"})

    def test_handle_lifecycle_error(self) -> None:
        """LifecycleError вызывает UI уведомление."""
        handler = GUIErrorHandler()
        notifications: list[tuple[str, str]] = []

        def ui_callback(title: str, message: str) -> None:
            notifications.append((title, message))

        error = LifecycleError("btn_01", "mount")
        handler.handle(error, {"operation": "init"}, ui_callback=ui_callback)
        assert len(notifications) == 1
        assert "UI" in notifications[0][0]

    def test_handle_renderer_error(self) -> None:
        """RendererError вызывает UI уведомление."""
        handler = GUIErrorHandler()
        notifications: list[tuple[str, str]] = []

        def ui_callback(title: str, message: str) -> None:
            notifications.append((title, message))

        error = RendererError("Render failed", renderer_type="FreeFormRenderer")
        handler.handle(error, {"operation": "render"}, ui_callback=ui_callback)
        assert len(notifications) == 1
        assert "Document" in notifications[0][0]

    def test_handle_gui_error(self) -> None:
        """GUIError вызывает UI уведомление с сообщением."""
        handler = GUIErrorHandler()
        notifications: list[tuple[str, str]] = []

        def ui_callback(title: str, message: str) -> None:
            notifications.append((title, message))

        error = GUIError("Something went wrong")
        handler.handle(error, {"operation": "test"}, ui_callback=ui_callback)
        assert len(notifications) == 1
        assert "Something went wrong" in notifications[0][1]

    def test_handle_unknown_error(self) -> None:
        """Неизвестное исключение обрабатывается как Unexpected Error."""
        handler = GUIErrorHandler()
        notifications: list[tuple[str, str]] = []

        def ui_callback(title: str, message: str) -> None:
            notifications.append((title, message))

        error = ValueError("Unexpected value")
        handler.handle(error, {"operation": "test"}, ui_callback=ui_callback)
        assert len(notifications) == 1
        assert "Unexpected" in notifications[0][0]

    def test_handler_priority(self) -> None:
        """Обработчики проверяются в порядке специфичности (SecurityError перед GUIError)."""
        handler = GUIErrorHandler()
        notifications: list[str] = []

        def ui_callback(title: str, message: str) -> None:
            notifications.append(title)

        # SecurityError — более специфичный, должен быть обработан первым
        error = SecurityError("test")
        handler.handle(error, {"operation": "test"}, ui_callback=ui_callback)
        assert "Security Error" in notifications[0]

    def test_register_custom_handler(self) -> None:
        """Регистрация кастомного обработчика для типа ошибки."""
        handler = GUIErrorHandler()
        handled_errors: list[str] = []

        def custom_handler(error: Exception, context: dict) -> None:
            handled_errors.append("custom")

        handler.register_handler(ValueError, custom_handler)
        handler.handle(ValueError("test"), {"operation": "test"})
        assert "custom" in handled_errors

    def test_handle_silent_logs_security(self) -> None:
        """handle_silent логирует SecurityError в audit service."""
        audit_events: list[dict] = []

        class MockAuditService:
            def log_security_event(self, **kwargs: object) -> None:
                audit_events.append(kwargs)

        handler = GUIErrorHandler(audit_service=MockAuditService())
        error = SecurityError("Silent security error")
        handler.handle_silent(error, {"operation": "test"})
        assert len(audit_events) == 1
        assert audit_events[0]["event_type"] == "security_error"

    def test_handle_silent_non_security(self) -> None:
        """handle_silent не логирует обычные ошибки в audit."""
        audit_events: list[dict] = []

        class MockAuditService:
            def log_security_event(self, **kwargs: object) -> None:
                audit_events.append(kwargs)

        handler = GUIErrorHandler(audit_service=MockAuditService())
        error = GUIError("Regular error")
        handler.handle_silent(error, {"operation": "test"})
        assert len(audit_events) == 0

    def test_handle_silent_no_audit_service(self) -> None:
        """handle_silent не падает без audit_service."""
        handler = GUIErrorHandler()
        error = SecurityError("test")
        handler.handle_silent(error, {"operation": "test"})

    def test_audit_service_failure(self) -> None:
        """Ошибка audit service не блокирует обработку SecurityError."""
        handler = GUIErrorHandler()
        notifications: list[tuple[str, str]] = []

        def ui_callback(title: str, message: str) -> None:
            notifications.append((title, message))

        class FailingAuditService:
            def log_security_event(self, **kwargs: object) -> None:
                raise OSError("Audit service down")

        handler_with_audit = GUIErrorHandler(audit_service=FailingAuditService())
        error = SecurityError("test")
        # Не должно упасть, даже если audit service падает
        handler_with_audit.handle(error, {"operation": "test"}, ui_callback=ui_callback)
        # UI уведомление всё ещё должно быть отправлено
        assert len(notifications) == 1

    def test_ui_callback_failure(self) -> None:
        """Ошибка UI callback не прерывает обработку."""
        handler = GUIErrorHandler()

        def failing_callback(title: str, message: str) -> None:
            raise RuntimeError("UI callback failed")

        error = GUIError("test")
        # Не должно упасть
        handler.handle(error, {"operation": "test"}, ui_callback=failing_callback)

    def test_no_ui_callback_fallback(self) -> None:
        """Без ui_callback ошибки логируются через logger."""
        handler = GUIErrorHandler()
        error = GUIError("test error")
        # Не должно упасть — логируется через logger.info
        handler.handle(error, {"operation": "test"})

    def test_audit_error_attributes(self) -> None:
        """AuditError сохраняет атрибуты event_type и log_destination."""
        handler = GUIErrorHandler()
        error = AuditError("Log failed", event_type="security", log_destination="file")
        handler.handle(error, {"operation": "test"})
        assert error.event_type == "security"
        assert error.log_destination == "file"


# ==============================================================================
# TEST: ErrorContext
# ==============================================================================


class TestErrorContext:
    """Тесты контекстного менеджера ErrorContext."""

    def test_catches_exception(self) -> None:
        """ErrorContext ловит исключение и обрабатывает."""
        handler = GUIErrorHandler()
        with ErrorContext(handler, {"operation": "test"}):
            raise GUIError("Test error")
        # Контекстный менеджер не пробрасывает исключение

    def test_reraise_option(self) -> None:
        """ErrorContext с reraise=True пробрасывает исключение."""
        handler = GUIErrorHandler()
        with pytest.raises(GUIError, match="Test error"):
            with ErrorContext(handler, {"operation": "test"}, reraise=True):
                raise GUIError("Test error")

    def test_no_exception(self) -> None:
        """ErrorContext без исключения не вызывает обработчик."""
        handler = GUIErrorHandler()
        with ErrorContext(handler, {"operation": "test"}):
            pass  # Без исключения

    def test_context_passed_to_handler(self) -> None:
        """Контекст передаётся в обработчик."""
        handler = GUIErrorHandler()
        handled: list[dict] = []

        def custom_handler(error: Exception, context: dict) -> None:
            handled.append(context)

        handler.register_handler(ValueError, custom_handler)
        with ErrorContext(handler, {"operation": "custom_op"}):
            raise ValueError("test")
        assert len(handled) == 1
        assert handled[0]["operation"] == "custom_op"

    def test_returns_self(self) -> None:
        """__enter__ возвращает self."""
        handler = GUIErrorHandler()
        ctx = ErrorContext(handler, {"operation": "test"})
        with ctx as result:
            assert result is ctx