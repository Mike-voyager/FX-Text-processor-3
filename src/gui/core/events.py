"""
Типы событий GUI.

Определяет иерархию событий для внутренней коммуникации GUI-компонентов.
Все события immutable (frozen dataclasses) для thread-safety и предсказуемости.

Иерархия событий:
    BaseEvent
    ├── ValueChangedEvent  # Изменение значения поля
    ├── FocusLostEvent     # Потеря фокуса
    ├── FocusGainedEvent   # Получение фокуса
    ├── ActionEvent        # Действие пользователя
    ├── MountEvent         # Монтирование виджета
    └── UnmountEvent       # Демонтирование виджета

Usage:
    >>> from src.gui.core.events import ValueChangedEvent
    >>> event = ValueChangedEvent(
    ...     widget_id="entry_1",
    ...     event_type="value_changed",
    ...     field_id="username",
    ...     old_value="",
    ...     new_value="admin"
    ... )

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field

__author__ = "FX Text Processor Team"
__date__ = "April 2026"
__version__ = "1.0"
from datetime import datetime
from typing import Any, Dict, Optional

# =============================================================================
# BASE EVENT
# =============================================================================


@dataclass(frozen=True)
class BaseEvent:
    """
    Базовый класс для всех событий GUI.

    Attributes:
        widget_id: Уникальный идентификатор виджета-источника события.
        event_type: Строковый тип события для маршрутизации.
        timestamp: Время создания события (UTC, автоматически).

    Example:
        >>> event = BaseEvent(
        ...     widget_id="button_1",
        ...     event_type="click",
        ...     timestamp=datetime.now()
        ... )
        >>> event.widget_id
        'button_1'
    """

    widget_id: str
    event_type: str
    timestamp: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        if not self.widget_id or not self.widget_id.strip():
            raise ValueError("widget_id не может быть пустым")
        if not self.event_type or not self.event_type.strip():
            raise ValueError("event_type не может быть пустым")


# =============================================================================
# VALUE EVENTS
# =============================================================================


@dataclass(frozen=True)
class ValueChangedEvent(BaseEvent):
    """
    Событие изменения значения поля.

    Генерируется когда пользователь изменяет значение поля ввода
    и покидает его (FocusOut) или явно подтверждает изменение.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        event_type: Тип события (всегда 'value_changed').
        timestamp: Время создания события.
        field_id: Идентификатор поля в схеме документа.
        old_value: Предыдущее значение поля.
        new_value: Новое значение поля.

    Example:
        >>> event = ValueChangedEvent(
        ...     widget_id="entry_username",
        ...     field_id="username",
        ...     old_value="",
        ...     new_value="admin"
        ... )
        >>> event.old_value
        ''
        >>> event.new_value
        'admin'
    """

    field_id: str = field(default="")
    old_value: Any = field(default=None)
    new_value: Any = field(default=None)

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        super().__post_init__()
        if not self.field_id or not self.field_id.strip():
            raise ValueError("field_id не может быть пустым")

    def has_changed(self) -> bool:
        """
        Проверяет, действительно ли значение изменилось.

        Returns:
            True если old_value != new_value, иначе False.

        Example:
            >>> event = ValueChangedEvent(
            ...     widget_id="e1", field_id="f1",
            ...     old_value="a", new_value="a"
            ... )
            >>> event.has_changed()
            False
        """
        return bool(self.old_value != self.new_value)


# =============================================================================
# FOCUS EVENTS
# =============================================================================


@dataclass(frozen=True)
class FocusLostEvent(BaseEvent):
    """
    Событие потери фокуса виджетом.

    Генерируется когда виджет теряет фокус ввода (например, пользователь
    переключился на другое поле или нажал Tab).

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        event_type: Тип события (всегда 'focus_lost').
        timestamp: Время создания события.
        field_id: Идентификатор поля в схеме документа.

    Example:
        >>> event = FocusLostEvent(
        ...     widget_id="entry_username",
        ...     field_id="username"
        ... )
        >>> event.field_id
        'username'
    """

    field_id: str = field(default="")

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        super().__post_init__()
        if not self.field_id or not self.field_id.strip():
            raise ValueError("field_id не может быть пустым")


@dataclass(frozen=True)
class FocusGainedEvent(BaseEvent):
    """
    Событие получения фокуса виджетом.

    Генерируется когда виджет получает фокус ввода (например, пользователь
    кликнул на поле или переключился Tab-ом).

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        event_type: Тип события (всегда 'focus_gained').
        timestamp: Время создания события.
        field_id: Идентификатор поля в схеме документа.

    Example:
        >>> event = FocusGainedEvent(
        ...     widget_id="entry_username",
        ...     field_id="username"
        ... )
        >>> event.field_id
        'username'
    """

    field_id: str = field(default="")

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        super().__post_init__()
        if not self.field_id or not self.field_id.strip():
            raise ValueError("field_id не может быть пустым")


# =============================================================================
# ACTION EVENTS
# =============================================================================


@dataclass(frozen=True)
class ActionEvent(BaseEvent):
    """
    Событие действия пользователя.

    Генерируется при явных действиях: нажатие кнопки, выбор пункта меню,
    горячая клавиша и т.д.

    Attributes:
        widget_id: Уникальный идентификатор виджета-источника.
        event_type: Тип события (всегда 'action').
        timestamp: Время создания события.
        action_name: Имя действия (например, 'save_document', 'print').
        action_data: Дополнительные данные действия (контекст).

    Example:
        >>> event = ActionEvent(
        ...     widget_id="btn_save",
        ...     action_name="save_document",
        ...     action_data={"path": "/tmp/doc.fxsd"}
        ... )
        >>> event.action_name
        'save_document'
        >>> event.action_data.get("path")
        '/tmp/doc.fxsd'
    """

    action_name: str = field(default="")
    action_data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        super().__post_init__()
        if not self.action_name or not self.action_name.strip():
            raise ValueError("action_name не может быть пустым")

    def get_data(self, key: str, default: Optional[Any] = None) -> Any:
        """
        Получает значение из action_data по ключу.

        Args:
            key: Ключ для поиска.
            default: Значение по умолчанию, если ключ не найден.

        Returns:
            Значение из action_data или default.

        Example:
            >>> event = ActionEvent(
            ...     widget_id="btn1", action_name="print",
            ...     action_data={"copies": 2}
            ... )
            >>> event.get_data("copies")
            2
            >>> event.get_data("color", False)
            False
        """
        return self.action_data.get(key, default)


# =============================================================================
# LIFECYCLE EVENTS
# =============================================================================


@dataclass(frozen=True)
class MountEvent(BaseEvent):
    """
    Событие монтирования виджета в дерево GUI.

    Генерируется когда виджет добавляется в родительский контейнер
    и становится частью иерархии GUI.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        event_type: Тип события (всегда 'mount').
        timestamp: Время создания события.
        parent_widget: Идентификатор родительского виджета.

    Example:
        >>> event = MountEvent(
        ...     widget_id="dialog_settings",
        ...     parent_widget="main_window"
        ... )
        >>> event.parent_widget
        'main_window'
    """

    parent_widget: str = field(default="")

    def __post_init__(self) -> None:
        """Валидация полей после инициализации."""
        super().__post_init__()
        if not self.parent_widget or not self.parent_widget.strip():
            raise ValueError("parent_widget не может быть пустым")


@dataclass(frozen=True)
class UnmountEvent(BaseEvent):
    """
    Событие демонтирования виджета из дерева GUI.

    Генерируется когда виджет удаляется из родительского контейнера.
    Используется для cleanup ресурсов (unbind, удаление ссылок).

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        event_type: Тип события (всегда 'unmount').
        timestamp: Время создания события.

    Example:
        >>> event = UnmountEvent(
        ...     widget_id="dialog_settings"
        ... )
        >>> event.event_type
        'unmount'
    """

    pass


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    # Base class
    "BaseEvent",
    # Value events
    "ValueChangedEvent",
    # Focus events
    "FocusLostEvent",
    "FocusGainedEvent",
    # Action events
    "ActionEvent",
    # Lifecycle events
    "MountEvent",
    "UnmountEvent",
]
