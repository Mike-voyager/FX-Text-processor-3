"""Базовый контроллер GUI для FX Text Processor 3.

Определяет базовый класс BaseController, реализующий ControllerProtocol.
Обеспечивает_DI через конструктор и унифицированную маршрутизацию действий.

Module: src/gui/controllers/base_controller.py
Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional, Protocol

from src.gui.core.protocols import ControllerProtocol

logger = logging.getLogger(__name__)


class BaseViewModel(Protocol):
    """Протокол для View, управляемого контроллером."""

    def on_notify(self, widget_id: str, data: Any) -> None:
        """Обрабатывает уведомление от контроллера.

        Args:
            widget_id: Идентификатор виджета.
            data: Данные для обновления.
        """
        ...


class BaseController(ControllerProtocol):
    """Базовый контроллер для GUI компонентов.

    Реализует ControllerProtocol с DI через конструктор.
    НЕ содержит бизнес-логики — только маршрутизация между View и Service.

    Attributes:
        controller_id: Уникальный идентификатор контроллера.
        _views: Словарь зарегистрированных View {widget_id: callback}.
        _service: Сервисный объект для обработки действий.

    Example:
        >>> class MyController(BaseController):
        ...     def __init__(self, service: MyService):
        ...         super().__init__("my_controller")
        ...         self._service = service
        ...
        ...     def dispatch(self, action: str, **kwargs) -> Any:
        ...         if action == "save":
        ...             return self._service.save(**kwargs)
        ...         return super().dispatch(action, **kwargs)
    """

    def __init__(self, controller_id: str) -> None:
        """Инициализирует базовый контроллер.

        Args:
            controller_id: Уникальный идентификатор контроллера.
        """
        self.controller_id: str = controller_id
        self._views: Dict[str, Callable[[str, Any], None]] = {}
        self._service: Optional[Any] = None

    def dispatch(self, action: str, **kwargs: Any) -> Optional[Any]:
        """Диспетчирует действие в Service Layer.

        Должен быть переопределён в подклассах для конкретных действий.

        Args:
            action: Идентификатор действия (например, "save", "open").
            **kwargs: Параметры действия.

        Returns:
            Результат выполнения действия или None.

        Raises:
            NotImplementedError: Если действие не реализовано в подклассе.
        """
        if self._service is not None:
            if hasattr(self._service, action):
                method = getattr(self._service, action)
                return method(**kwargs)
        return None

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        """Уведомляет View об изменениях в Model.

        Вызывается Service Layer для обновления отображения.
        Следует маршрутизировать уведомление соответствующему виджету.

        Args:
            widget_id: Идентификатор виджета для обновления.
            data: Данные для обновления (специфичны для виджета).

        Example:
            >>> controller.notify_view_update(
            ...     "status_bar",
            ...     {"modified": True}
            ... )
        """
        callback = self._views.get(widget_id)
        if callback is not None:
            try:
                callback(widget_id, data)
            except Exception as e:
                logger.error(
                    "Error notify view update for widget %s: %s",
                    widget_id,
                    e,
                    exc_info=True,
                )

    def register_view(self, widget_id: str, callback: Callable[[str, Any], None]) -> None:
        """Регистрирует callback для обновления View.

        Args:
            widget_id: Идентификатор виджета.
            callback: Функция обратного вызова для уведомлений.

        Example:
            >>> controller.register_view("editor", editor.update_callback)
        """
        self._views[widget_id] = callback

    def unregister_view(self, widget_id: str) -> None:
        """Отменяет регистрацию View callback.

        Args:
            widget_id: Идентификатор виджета.

        Example:
            >>> controller.unregister_view("editor")
        """
        if widget_id in self._views:
            del self._views[widget_id]

    def set_service(self, service: Any) -> None:
        """Устанавливает сервис для DI.

        Args:
            service: Сервисный объект.

        Note:
            Метод должен вызываться после инициализации контроллера.
        """
        self._service = service
