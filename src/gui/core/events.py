"""Система событий GUI для FX Text Processor 3.

Модуль определяет иерархию событий, используемых для коммуникации
между виджетами и контроллерами. Все события реализуют EventProtocol
и являются неизменяемыми (frozen dataclasses).

Classes:
    BaseEvent: Базовое событие с widget_id и timestamp.
    ActionEvent: Событие действия (например, нажатие кнопки).
    FocusGainedEvent: Событие получения фокуса.
    FocusLostEvent: Событие потери фокуса.
    MountEvent: Событие монтирования виджета.
    UnmountEvent: Событие демонтирования виджета.
    ValueChangedEvent: Событие изменения значения.

Example:
    >>> event = ValueChangedEvent(
    ...     widget_id="field_01",
    ...     old_value="old",
    ...     new_value="new"
    ... )
    >>> isinstance(event, EventProtocol)
    True

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import time
from typing import Any, Final

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_WIDGET_ID_LENGTH: Final[int] = 100
"""Максимальная длина идентификатора виджета (security: UI DoS protection)."""


# =============================================================================
# BASE EVENT
# =============================================================================


@dataclass(frozen=True)
class BaseEvent:
    """Базовый класс для всех событий GUI.

    Реализует EventProtocol через структурное подтипирование.
    Все события неизменяемы (frozen=True) для предотвращения
    случайных модификаций при распространении.

    Attributes:
        widget_id: Идентификатор виджета-источника события.
            Соответствует source_widget_id в EventProtocol.
        timestamp: Временная метка создания события (Unix timestamp).

    Example:
        >>> event = BaseEvent(widget_id="btn_01")
        >>> event.timestamp > 0
        True
        >>> isinstance(event, BaseEvent)
        True

    Security:
        - widget_id обрезается до MAX_WIDGET_ID_LENGTH символов.
        - timestamp автоматически устанавливается при создании.
    """

    widget_id: str
    timestamp: float = field(default_factory=time)

    def __post_init__(self) -> None:
        """Пост-инициализация: обрезка widget_id и установка event_type."""
        # Security: truncate long widget_id
        object.__setattr__(self, "widget_id", self.widget_id[:MAX_WIDGET_ID_LENGTH])
        object.__setattr__(self, "_propagation_stopped", False)

    @property
    def source_widget_id(self) -> str:
        """Идентификатор виджета-источника (совместимость с EventProtocol).

        Returns:
            Значение widget_id.
        """
        return self.widget_id

    @property
    def event_type(self) -> str:
        """Тип события (совместимость с EventProtocol).

        Returns:
            Название класса в нижнем регистре.
        """
        return self.__class__.__name__.lower().replace("event", "")

    def get_data(self) -> dict[str, Any]:
        """Возвращает данные события в виде словаря.

        Returns:
            Словарь с полями события.

        Example:
            >>> event = BaseEvent(widget_id="test")
            >>> data = event.get_data()
            >>> "widget_id" in data
            True
        """
        return {
            "widget_id": self.widget_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
        }

    def is_propagation_stopped(self) -> bool:
        """Проверяет, остановлено ли распространение события.

        Returns:
            True если событие не должно передаваться дальше.
        """
        return bool(getattr(self, "_propagation_stopped", False))

    def stop_propagation(self) -> None:
        """Останавливает распространение события.

        После вызова событие не будет передано родительским
        виджетам или контроллерам.

        Note:
            Использует object.__setattr__ т.к. dataclass frozen=True.

        Example:
            >>> event = BaseEvent(widget_id="test")
            >>> event.stop_propagation()
            >>> event.is_propagation_stopped()
            True
        """
        object.__setattr__(self, "_propagation_stopped", True)


# =============================================================================
# CONCRETE EVENTS
# =============================================================================


@dataclass(frozen=True)
class ActionEvent(BaseEvent):
    """Событие действия (например, нажатие кнопки или выбор меню).

    Attributes:
        action: Идентификатор действия (например, "save", "open").
        handler_name: Имя обработчика или None.

    Example:
        >>> event = ActionEvent(
        ...     widget_id="btn_save",
        ...     action="save_document"
        ... )
        >>> event.action
        'save_document'
    """

    action: str = ""
    handler_name: str | None = None

    def get_data(self) -> dict[str, Any]:
        """Возвращает данные события действия."""
        data = super().get_data()
        data["action"] = self.action
        data["handler_name"] = self.handler_name
        return data


@dataclass(frozen=True)
class FocusGainedEvent(BaseEvent):
    """Событие получения фокуса виджетом.

    Attributes:
        previous_widget_id: Идентификатор виджета, который потерял фокус.

    Example:
        >>> event = FocusGainedEvent(
        ...     widget_id="entry_01",
        ...     previous_widget_id="entry_00"
        ... )
        >>> event.previous_widget_id
        'entry_00'
    """

    previous_widget_id: str | None = None

    def get_data(self) -> dict[str, Any]:
        """Возвращает данные события фокуса."""
        data = super().get_data()
        data["previous_widget_id"] = self.previous_widget_id
        return data


@dataclass(frozen=True)
class FocusLostEvent(BaseEvent):
    """Событие потери фокуса виджетом.

    Attributes:
        next_widget_id: Идентификатор виджета, который получил фокус.

    Example:
        >>> event = FocusLostEvent(
        ...     widget_id="entry_01",
        ...     next_widget_id="entry_02"
        ... )
        >>> event.next_widget_id
        'entry_02'
    """

    next_widget_id: str | None = None

    def get_data(self) -> dict[str, Any]:
        """Возвращает данные события потери фокуса."""
        data = super().get_data()
        data["next_widget_id"] = self.next_widget_id
        return data


@dataclass(frozen=True)
class MountEvent(BaseEvent):
    """Событие монтирования виджета в родительский контейнер.

    Example:
        >>> event = MountEvent(widget_id="panel_01")
        >>> event.event_type
        'mount'
    """

    # Нет дополнительных полей


@dataclass(frozen=True)
class UnmountEvent(BaseEvent):
    """Событие демонтирования виджета и освобождения ресурсов.

    Example:
        >>> event = UnmountEvent(widget_id="panel_01")
        >>> event.event_type
        'unmount'
    """

    # Нет дополнительных полей


@dataclass(frozen=True)
class ValueChangedEvent(BaseEvent):
    """Событие изменения значения виджета.

    Attributes:
        old_value: Предыдущее значение.
        new_value: Новое значение.

    Example:
        >>> event = ValueChangedEvent(
        ...     widget_id="field_01",
        ...     old_value="old",
        ...     new_value="new"
        ... )
        >>> event.old_value
        'old'
    """

    old_value: Any = None
    new_value: Any = None

    def get_data(self) -> dict[str, Any]:
        """Возвращает данные события изменения значения."""
        data = super().get_data()
        data["old_value"] = self.old_value
        data["new_value"] = self.new_value
        return data


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "BaseEvent",
    "ActionEvent",
    "FocusGainedEvent",
    "FocusLostEvent",
    "MountEvent",
    "UnmountEvent",
    "ValueChangedEvent",
    "MAX_WIDGET_ID_LENGTH",
]
