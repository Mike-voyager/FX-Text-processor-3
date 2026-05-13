"""Иерархия исключений для GUI.

Модуль определяет структуру исключений для GUI слоя FX Text Processor 3.
Все исключения наследуются от GUIError и используются в WidgetRegistry,
lifecycle management, Protocol validation и event handling.

Example:
    >>> from src.gui.core.exceptions import WidgetNotFoundError
    >>> raise WidgetNotFoundError("widget_type", "button_primary")
    WidgetNotFoundError: Виджет 'button_primary' типа 'widget_type' не найден

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import Any, Optional

__author__ = "FX Text Processor Team"
__date__ = "April 2026"
__version__ = "1.0"

# ==============================================================================
# BASE EXCEPTION
# ==============================================================================


class GUIError(Exception):
    """Базовая ошибка GUI слоя.

    Attributes:
        message: Описание ошибки (опционально)

    Example:
        >>> raise GUIError("Общая ошибка GUI")
        GUIError: Общая ошибка GUI

        >>> raise GUIError()
        GUIError
    """

    def __init__(self, message: Optional[str] = None) -> None:
        """Инициализация базового исключения GUI.

        Args:
            message: Описание ошибки (опционально)
        """
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        """Строковое представление исключения."""
        return self.message if self.message else self.__class__.__name__


# ==============================================================================
# WIDGET REGISTRY EXCEPTIONS
# ==============================================================================


class WidgetRegistryError(GUIError):
    """Ошибка реестра виджетов.

    Attributes:
        message: Описание ошибки (опционально)

    Example:
        >>> raise WidgetRegistryError("Дубликат регистрации виджета")
        WidgetRegistryError: Дубликат регистрации виджета
    """

    pass


class WidgetNotFoundError(WidgetRegistryError):
    """Виджет не найден в реестре.

    Attributes:
        widget_type: Тип запрашиваемого виджета
        widget_id: Идентификатор запрашиваемого виджета
        message: Описание ошибки (опционально)

    Example:
        >>> raise WidgetNotFoundError("button", "submit_btn")
        WidgetNotFoundError: Виджет 'submit_btn' типа 'button' не найден
    """

    def __init__(
        self,
        widget_type: Optional[str] = None,
        widget_id: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """Инициализация исключения.

        Args:
            widget_type: Тип виджета (опционально)
            widget_id: Идентификатор виджета (опционально)
            message: Пользовательское сообщение (опционально)
        """
        self.widget_type = widget_type
        self.widget_id = widget_id

        if message is None:
            parts = []
            if widget_id:
                parts.append(f"'{widget_id}'")
            if widget_type:
                parts.append(f"типа '{widget_type}'")
            msg = f"Виджет {' '.join(parts)} не найден в реестре"
            message = msg if parts else "Виджет не найден в реестре"

        super().__init__(message)


class WidgetCreationError(WidgetRegistryError):
    """Ошибка создания виджета фабрикой.

    Attributes:
        widget_type: Тип создаваемого виджета
        factory_name: Имя фабричной функции
        message: Описание ошибки (опционально)
        cause: Исходное исключение (опционально)

    Example:
        >>> raise WidgetCreationError("text_editor", factory="create_editor")
        WidgetCreationError: Не удалось создать виджет 'text_editor'
    """

    def __init__(
        self,
        widget_type: Optional[str] = None,
        factory_name: Optional[str] = None,
        message: Optional[str] = None,
        cause: Optional[Exception] = None,
    ) -> None:
        """Инициализация исключения.

        Args:
            widget_type: Тип виджета (опционально)
            factory_name: Имя фабрики (опционально)
            message: Пользовательское сообщение (опционально)
            cause: Исходное исключение (опционально)
        """
        self.widget_type = widget_type
        self.factory_name = factory_name
        self.cause = cause

        if message is None:
            parts = ["Не удалось создать виджет"]
            if widget_type:
                parts.append(f"'{widget_type}'")
            if factory_name:
                parts.append(f"в фабрике '{factory_name}'")
            message = " ".join(parts)

        super().__init__(message)


# ==============================================================================
# PROTOCOL VALIDATION EXCEPTIONS
# ==============================================================================


class ProtocolValidationError(GUIError):
    """Ошибка валидации соответствия Protocol интерфейсу.

    Attributes:
        protocol_name: Имя Protocol интерфейса
        implementation: Класс, не прошедший валидацию
        message: Описание ошибки (опционально)

    Example:
        >>> raise ProtocolValidationError("WidgetProtocol", "MyWidget")
        ProtocolValidationError: 'MyWidget' не реализует 'WidgetProtocol'
    """

    def __init__(
        self,
        protocol_name: Optional[str] = None,
        implementation: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """Инициализация исключения.

        Args:
            protocol_name: Имя Protocol (опционально)
            implementation: Имя класса (опционально)
            message: Пользовательское сообщение (опционально)
        """
        self.protocol_name = protocol_name
        self.implementation = implementation

        if message is None:
            parts = []
            if implementation:
                parts.append(f"'{implementation}'")
            if protocol_name:
                parts.append(f"не реализует Protocol '{protocol_name}'")
            else:
                parts.append("не соответствует Protocol интерфейсу")
            message = " ".join(parts) if parts else "Ошибка валидации Protocol"

        super().__init__(message)


# ==============================================================================
# LIFECYCLE EXCEPTIONS
# ==============================================================================


class LifecycleError(GUIError):
    """Ошибка жизненного цикла виджета (mount/unmount).

    Attributes:
        widget_id: Идентификатор виджета
        operation: Операция жизненного цикла (mount/unmount)
        message: Описание ошибки (опционально)

    Example:
        >>> raise LifecycleError("doc_view", "mount")
        LifecycleError: Ошибка mount для виджета 'doc_view'
    """

    def __init__(
        self,
        widget_id: Optional[str] = None,
        operation: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """Инициализация исключения.

        Args:
            widget_id: ID виджета (опционально)
            operation: Операция lifecycle (опционально)
            message: Пользовательское сообщение (опционально)
        """
        self.widget_id = widget_id
        self.operation = operation

        if message is None:
            if operation and widget_id:
                message = f"Ошибка {operation} для виджета '{widget_id}'"
            elif operation:
                message = f"Ошибка операции {operation}"
            elif widget_id:
                message = f"Ошибка жизненного цикла виджета '{widget_id}'"
            else:
                message = "Ошибка жизненного цикла виджета"

        super().__init__(message)


# ==============================================================================
# EVENT HANDLING EXCEPTIONS
# ==============================================================================


class EventHandlingError(GUIError):
    """Ошибка обработки события.

    Attributes:
        event_type: Тип события
        widget_id: Идентификатор виджета-источника
        handler_name: Имя обработчика
        message: Описание ошибки (опционально)
        cause: Исходное исключение (опционально)

    Example:
        >>> raise EventHandlingError("click", "btn_submit", "on_click")
        EventHandlingError: Ошибка обработки 'click' в 'on_click' для 'btn_submit'
    """

    def __init__(
        self,
        event_type: Optional[str] = None,
        widget_id: Optional[str] = None,
        handler_name: Optional[str] = None,
        message: Optional[str] = None,
        cause: Optional[Exception] = None,
    ) -> None:
        """Инициализация исключения.

        Args:
            event_type: Тип события (опционально)
            widget_id: ID виджета (опционально)
            handler_name: Имя обработчика (опционально)
            message: Пользовательское сообщение (опционально)
            cause: Исходное исключение (опционально)
        """
        self.event_type = event_type
        self.widget_id = widget_id
        self.handler_name = handler_name
        self.cause = cause

        if message is None:
            parts = ["Ошибка обработки события"]
            if event_type:
                parts.append(f"'{event_type}'")
            if handler_name:
                parts.append(f"в обработчике '{handler_name}'")
            if widget_id:
                parts.append(f"для виджета '{widget_id}'")
            message = " ".join(parts)

        super().__init__(message)


# ==============================================================================
# SECURITY EXCEPTIONS
# ==============================================================================


class SecurityError(GUIError):
    """Базовая ошибка безопасности.

    Attributes:
        message: Описание ошибки
        audit_context: Контекст для audit logging

    Example:
        >>> raise SecurityError("Access denied", audit_context={"user_id": "123"})
    """

    def __init__(
        self,
        message: Optional[str] = None,
        audit_context: Optional[dict[str, Any]] = None,
    ) -> None:
        """Инициализация исключения безопасности.

        Args:
            message: Описание ошибки
            audit_context: Контекст для audit logging
        """
        self.audit_context = audit_context or {}
        super().__init__(message)


class MFAError(SecurityError):
    """Ошибка MFA верификации.

    Attributes:
        method: Метод MFA, который вызвал ошибку
        failure_reason: Причина отказа
        user_id: ID пользователя

    Example:
        >>> raise MFAError("totp", "Invalid code", user_id="123")
    """

    def __init__(
        self,
        method: str,
        failure_reason: str,
        user_id: Optional[str] = None,
        audit_context: Optional[dict[str, Any]] = None,
    ) -> None:
        """Инициализация ошибки MFA.

        Args:
            method: Метод MFA
            failure_reason: Причина отказа
            user_id: ID пользователя
            audit_context: Контекст для audit
        """
        self.method = method
        self.failure_reason = failure_reason
        self.user_id = user_id

        message = f"MFA {method} failed: {failure_reason}"
        super().__init__(message, audit_context)


class AuthenticationError(SecurityError):
    """Ошибка аутентификации.

    Attributes:
        username: Имя пользователя (если известно)
        auth_method: Метод аутентификации

    Example:
        >>> raise AuthenticationError("Invalid credentials", username="john")
    """

    def __init__(
        self,
        message: str,
        username: Optional[str] = None,
        auth_method: Optional[str] = None,
        audit_context: Optional[dict[str, Any]] = None,
    ) -> None:
        """Инициализация ошибки аутентификации.

        Args:
            message: Описание ошибки
            username: Имя пользователя
            auth_method: Метод аутентификации
            audit_context: Контекст для audit
        """
        self.username = username
        self.auth_method = auth_method
        super().__init__(message, audit_context)


class AuthorizationError(SecurityError):
    """Ошибка авторизации (доступ запрещён).

    Attributes:
        user_id: ID пользователя
        required_permission: Требуемое разрешение
        resource: Ресурс, к которому был запрос

    Example:
        >>> raise AuthorizationError("Access denied", user_id="123", required_permission="admin")
    """

    def __init__(
        self,
        message: str,
        user_id: Optional[str] = None,
        required_permission: Optional[str] = None,
        resource: Optional[str] = None,
        audit_context: Optional[dict[str, Any]] = None,
    ) -> None:
        """Инициализация ошибки авторизации.

        Args:
            message: Описание ошибки
            user_id: ID пользователя
            required_permission: Требуемое разрешение
            resource: Ресурс
            audit_context: Контекст для audit
        """
        self.user_id = user_id
        self.required_permission = required_permission
        self.resource = resource
        super().__init__(message, audit_context)


# ==============================================================================
# AUDIT EXCEPTIONS
# ==============================================================================


class AuditError(GUIError):
    """Ошибка аудита/логирования.

    Attributes:
        event_type: Тип события
        log_destination: Назначение лога (файл, БД и т.д.)

    Example:
        >>> raise AuditError("Failed to write audit log", event_type="security_event")
    """

    def __init__(
        self,
        message: str,
        event_type: Optional[str] = None,
        log_destination: Optional[str] = None,
    ) -> None:
        """Инициализация ошибки аудита.

        Args:
            message: Описание ошибки
            event_type: Тип события
            log_destination: Назначение лога
        """
        self.event_type = event_type
        self.log_destination = log_destination
        super().__init__(message)


# ==============================================================================
# RENDERER EXCEPTIONS
# ==============================================================================


class RendererError(GUIError):
    """Ошибка рендерера документа.

    Attributes:
        renderer_type: Тип рендерера
        document_mode: Режим документа
        document_id: ID документа

    Example:
        >>> raise RendererError("Failed to render", renderer_type="FreeFormRenderer")
    """

    def __init__(
        self,
        message: str,
        renderer_type: Optional[str] = None,
        document_mode: Optional[str] = None,
        document_id: Optional[str] = None,
    ) -> None:
        """Инициализация ошибки рендерера.

        Args:
            message: Описание ошибки
            renderer_type: Тип рендерера
            document_mode: Режим документа
            document_id: ID документа
        """
        self.renderer_type = renderer_type
        self.document_mode = document_mode
        self.document_id = document_id
        super().__init__(message)


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__ = [
    # Base
    "GUIError",
    # Widget Registry
    "WidgetRegistryError",
    "WidgetNotFoundError",
    "WidgetCreationError",
    # Protocol
    "ProtocolValidationError",
    # Lifecycle
    "LifecycleError",
    # Events
    "EventHandlingError",
    # Security
    "SecurityError",
    "MFAError",
    "AuthenticationError",
    "AuthorizationError",
    # Audit
    "AuditError",
    # Renderer
    "RendererError",
]
