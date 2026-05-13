"""GUIErrorHandler — централизованная обработка ошибок для FX Text Processor 3.

Модуль предоставляет единую точку обработки исключений в GUI слое
с интеграцией AuditService для security событий и graceful degradation
для пользовательских ошибок.

Example:
    >>> from src.gui.core.error_handler import GUIErrorHandler
    >>> handler = GUIErrorHandler(audit_service)
    >>> try:
    ...     risky_operation()
    ... except SecurityError as e:
    ...     handler.handle(e, context={"operation": "delete"})

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from src.gui.core.exceptions import (
    AuditError,
    GUIError,
    LifecycleError,
    RendererError,
    SecurityError,
)

logger = logging.getLogger(__name__)


class GUIErrorHandler:
    """Централизованный обработчик ошибок GUI.

    Реализует паттерн Chain of Responsibility для обработки
    различных типов ошибок с соответствующей логикой:
    - SecurityError → audit logging + user notification
    - AuditError → graceful degradation (продолжаем работу)
    - GUIError → user notification
    - Exception → graceful degradation

    Attributes:
        _audit_service: Сервис аудита для security событий
        _error_callbacks: Callback-функции для различных типов ошибок

    Example:
        >>> handler = GUIErrorHandler(audit_service)
        >>> handler.handle(error, context={"widget_id": "btn_save"})
    """

    def __init__(
        self,
        audit_service: Optional[Any] = None,
        ui_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """Инициализация обработчика ошибок.

        Args:
            audit_service: Опциональный сервис аудита
            ui_callback: Callback для отображения ошибок пользователю
                        (title: str, message: str) -> None
        """
        self._audit_service = audit_service
        self._ui_callback = ui_callback
        self._error_callbacks: dict[type[Exception], Callable[[Any, dict[str, Any]], None]] = {
            SecurityError: self._handle_security_error,
            AuditError: self._handle_audit_error,
            LifecycleError: self._handle_lifecycle_error,
            RendererError: self._handle_renderer_error,
            GUIError: self._handle_gui_error,
        }

    def handle(
        self,
        error: Exception,
        context: dict[str, Any],
        ui_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """Обрабатывает исключение согласно его типу.

        Args:
            error: Исключение для обработки
            context: Контекст ошибки (widget_id, operation и т.д.)
            ui_callback: Опциональный callback для UI уведомления

        Example:
            >>> try:
            ...     operation()
            ... except (GUIError, SecurityError, AuditError, LifecycleError, RendererError) as e:
            ...     handler.handle(e, {"operation": "save"})
        """
        # Find most specific handler
        for error_type, handler in self._error_callbacks.items():
            if isinstance(error, error_type):
                handler(error, context)
                return

        # Default handler for unknown exceptions
        self._handle_unknown_error(error, context)

    def handle_silent(
        self,
        error: Exception,
        context: dict[str, Any],
    ) -> None:
        """Обрабатывает ошибку "тихо" (без UI уведомления).

        Используется для замены except: pass паттернов.
        Ошибка логируется, но пользователю не показывается.

        Args:
            error: Исключение для обработки
            context: Контекст ошибки

        Example:
            >>> try:
            ...     cleanup()
            ... except (GUIError, SecurityError, AuditError, LifecycleError, RendererError) as e:
            ...     handler.handle_silent(e, {"operation": "cleanup"})
        """
        # Log the error
        logger.debug(
            "Silent error in %s: %s",
            context.get("operation", "unknown"),
            str(error),
        )

        # Audit log for security errors even in silent mode
        if isinstance(error, SecurityError):
            self._audit_security_error(error, context)

    def register_handler(
        self,
        error_type: type[Exception],
        handler: Callable[[Exception, dict[str, Any]], None],
    ) -> None:
        """Регистрирует кастомный обработчик для типа ошибки.

        Args:
            error_type: Тип исключения
            handler: Функция-обработчик

        Example:
            >>> handler.register_handler(MyCustomError, my_handler)
        """
        self._error_callbacks[error_type] = handler

    def _handle_security_error(
        self,
        error: SecurityError,
        context: dict[str, Any],
    ) -> None:
        """Обрабатывает SecurityError.

        Args:
            error: Ошибка безопасности
            context: Контекст
        """
        # Log to audit service
        self._audit_security_error(error, context)

        # Log to application logger
        logger.warning(
            "Security error in %s: %s",
            context.get("operation", "unknown"),
            str(error),
        )

        # Notify user
        self._notify_user(
            "Security Error",
            "A security error occurred. Please contact support.",
        )

    def _handle_audit_error(
        self,
        error: AuditError,
        context: dict[str, Any],
    ) -> None:
        """Обрабатывает AuditError.

        Args:
            error: Ошибка аудита
            context: Контекст
        """
        # Log but don't show to user (graceful degradation)
        logger.warning(
            "Audit error in %s (event_type=%s): %s",
            context.get("operation", "unknown"),
            error.event_type,
            str(error),
        )

        # Continue operation - audit failure shouldn't block user

    def _handle_lifecycle_error(
        self,
        error: LifecycleError,
        context: dict[str, Any],
    ) -> None:
        """Обрабатывает LifecycleError.

        Args:
            error: Ошибка жизненного цикла
            context: Контекст
        """
        logger.error(
            "Lifecycle error for widget %s during %s: %s",
            error.widget_id,
            error.operation,
            str(error),
        )

        self._notify_user(
            "UI Error",
            "An internal UI error occurred. Please try again.",
        )

    def _handle_renderer_error(
        self,
        error: RendererError,
        context: dict[str, Any],
    ) -> None:
        """Обрабатывает RendererError.

        Args:
            error: Ошибка рендерера
            context: Контекст
        """
        logger.error(
            "Renderer error (%s, mode=%s): %s",
            error.renderer_type,
            error.document_mode,
            str(error),
        )

        self._notify_user(
            "Document Error",
            "Failed to display document. Please try again.",
        )

    def _handle_gui_error(
        self,
        error: GUIError,
        context: dict[str, Any],
    ) -> None:
        """Обрабатывает GUIError.

        Args:
            error: GUI ошибка
            context: Контекст
        """
        logger.error(
            "GUI error in %s: %s",
            context.get("operation", "unknown"),
            str(error),
        )

        self._notify_user(
            "Error",
            str(error) if error.message else "An error occurred.",
        )

    def _handle_unknown_error(
        self,
        error: Exception,
        context: dict[str, Any],
    ) -> None:
        """Обрабатывает неизвестное исключение.

        Args:
            error: Неизвестное исключение
            context: Контекст
        """
        logger.exception(
            "Unexpected error in %s: %s",
            context.get("operation", "unknown"),
            str(error),
        )

        self._notify_user(
            "Unexpected Error",
            "An unexpected error occurred. Please try again.",
        )

    def _audit_security_error(
        self,
        error: SecurityError,
        context: dict[str, Any],
    ) -> None:
        """Логирует security ошибку в audit service.

        Args:
            error: Ошибка безопасности
            context: Контекст
        """
        if self._audit_service is None:
            return

        try:
            self._audit_service.log_security_event(
                event_type="security_error",
                context=context,
                error=str(error),
            )
        except (OSError, IOError, ValueError, TypeError) as e:
            # Silent fail - don't let audit errors break the app
            logger.debug("Failed to log security event to audit service: %s", e)

    def _notify_user(self, title: str, message: str) -> None:
        """Уведомляет пользователя об ошибке.

        Args:
            title: Заголовок сообщения
            message: Текст сообщения
        """
        callback = self._ui_callback
        if callback is not None:
            try:
                callback(title, message)
            except (TypeError, ValueError, RuntimeError) as e:
                logger.debug("UI callback failed for error notification: %s", e)
        else:
            # Fallback to logger
            logger.info("User notification: [%s] %s", title, message)


class ErrorContext:
    """Контекстный менеджер для обработки ошибок.

    Example:
        >>> handler = GUIErrorHandler()
        >>> with ErrorContext(handler, {"operation": "save"}):
        ...     risky_operation()
    """

    def __init__(
        self,
        handler: GUIErrorHandler,
        context: dict[str, Any],
        reraise: bool = False,
    ) -> None:
        """Инициализация контекста.

        Args:
            handler: Обработчик ошибок
            context: Контекст операции
            reraise: Перевыбрасывать ли исключение после обработки
        """
        self._handler = handler
        self._context = context
        self._reraise = reraise

    def __enter__(self) -> "ErrorContext":
        """Вход в контекст."""
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Any,
    ) -> bool:
        """Выход из контекста с обработкой ошибки.

        Returns:
            True если ошибка обработана (не прокидывать дальше)
        """
        if exc_val is not None:
            self._handler.handle(exc_val, self._context)
            return not self._reraise
        return False


# Module exports
__all__ = [
    "GUIErrorHandler",
    "ErrorContext",
]
