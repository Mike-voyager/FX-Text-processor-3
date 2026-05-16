"""Базовые классы виджетов GUI для FX Text Processor 3.

Предоставляет:
- BaseWidget: "глупый" виджет с явным жизненным циклом mount/unmount.
- SmartBaseWidget: виджет с локальным состоянием редактирования.

Example:
    >>> from src.gui.components.base.widget import BaseWidget
    >>> class MyButton(BaseWidget):
    ...     def _create_tk_widget(self, parent):
    ...         return tk.Button(parent, text="Click")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from abc import ABC, abstractmethod
from typing import Any, Optional

from src.gui.core.events import MountEvent, UnmountEvent
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol, EventProtocol

__author__ = "FX Text Processor Team"
__date__ = "May 2026"
__version__ = "1.0"

__all__ = [
    "BaseWidget",
    "SmartBaseWidget",
]


# =============================================================================
# BASE WIDGET
# =============================================================================


class BaseWidget(ABC):
    """Базовый "глупый" виджет с явным жизненным циклом.

    Реализует :class:`WidgetProtocol` через структурное подтипирование.
    Все конкретные виджеты должны реализовать абстрактный метод
    :meth:`_create_tk_widget`.

    Attributes:
        widget_id: Уникальный идентификатор виджета в иерархии GUI.

    Example:
        >>> class MyLabel(BaseWidget):
        ...     def _create_tk_widget(self, parent):
        ...         return tk.Label(parent, text="Hello")
        >>> w = MyLabel(widget_id="lbl_01")
        >>> isinstance(w, BaseWidget)
        True
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация базового виджета.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            **kwargs: Дополнительные параметры (зарезервированы).

        Raises:
            ValueError: Если ``widget_id`` пустой или содержит только пробелы.
        """
        if not widget_id or not widget_id.strip():
            raise ValueError("widget_id cannot be empty")

        self._widget_id: str = widget_id
        self._controller: Optional[ControllerProtocol] = controller
        self._tk_widget: Optional[tk.Widget] = None
        self._is_mounted: bool = False

    @property
    def widget_id(self) -> str:
        """Уникальный идентификатор виджета.

        Returns:
            Строка идентификатора.
        """
        return self._widget_id

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует виджет в родительский контейнер.

        Создаёт Tkinter виджет через :meth:`_create_tk_widget`,
        настраивает привязки событий и отправляет
        :class:`MountEvent` через контроллер.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.

        Raises:
            TypeError: Если ``parent`` не является Tkinter виджетом.
            LifecycleError: Если виджет уже смонтирован.
        """
        if self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="mount",
                message=f"Widget '{self._widget_id}' already mounted",
            )

        if parent is None or not hasattr(parent, "winfo_exists"):
            raise TypeError("parent must be a Tk widget")

        self._tk_widget = self._create_tk_widget(parent)
        self._setup_bindings()
        self._is_mounted = True

        if self._controller is not None:
            event = MountEvent(widget_id=self._widget_id)
            self._controller.dispatch("widget_mounted", event=event)

        return self._tk_widget

    def unmount(self) -> None:
        """Демонтирует виджет и освобождает ресурсы.

        Вызывает :meth:`_cleanup`, уничтожает Tkinter виджет и отправляет
        :class:`UnmountEvent` через контроллер.

        Raises:
            LifecycleError: Если виджет не был смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="unmount",
                message=f"Widget '{self._widget_id}' not mounted",
            )

        self._cleanup()

        if self._tk_widget is not None:
            try:
                self._tk_widget.destroy()
            except tk.TclError:
                pass
            self._tk_widget = None

        self._is_mounted = False

        if self._controller is not None:
            event = UnmountEvent(widget_id=self._widget_id)
            self._controller.dispatch("widget_unmounted", event=event)

    def handle_event(self, event: EventProtocol) -> bool:
        """Обрабатывает входящее событие.

        Базовая реализация всегда возвращает ``False`` — событие
        передаётся дальше по цепочке.

        Args:
            event: Событие для обработки.

        Returns:
            ``True`` если событие обработано, иначе ``False``.
        """
        return False

    def is_mounted(self) -> bool:
        """Проверяет, смонтирован ли виджет.

        Returns:
            ``True`` если виджет смонтирован и активен.
        """
        return self._is_mounted

    def apply_theme(self) -> None:  # noqa: B027
        """Применяет текущую тему оформления к виджету.

        Базовая реализация — пустой хук.
        Переопределяется в наследниках для применения тем.
        """
        pass

    @abstractmethod
    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter виджет.

        Абстрактный метод, который должен быть реализован
        в каждом конкретном виджете.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.
        """

    def _setup_bindings(self) -> None:  # noqa: B027
        """Настраивает привязки событий после создания виджета.

        Базовая реализация — пустой хук.
        Переопределяется в наследниках для подключения обработчиков.
        """
        pass

    def _cleanup(self) -> None:  # noqa: B027
        """Очищает ресурсы перед демонтированием.

        Базовая реализация — пустой хук.
        Переопределяется в наследниках для освобождения
        дополнительных ресурсов (отписка от событий, очистка ссылок).
        """
        pass


# =============================================================================
# SMART BASE WIDGET
# =============================================================================


class SmartBaseWidget(BaseWidget, ABC):
    """Виджет с локальным состоянием редактирования.

    Расширяет :class:`BaseWidget`, добавляя режим редактирования
    с явным входом/выходом и синхронизацией с моделью.
    Реализует :class:`SmartWidgetProtocol` через структурное подтипирование.

    Attributes:
        is_editing: Флаг режима редактирования (``True`` = EDIT_MODE).

    Example:
        >>> class SmartEntry(SmartBaseWidget):
        ...     def _create_tk_widget(self, parent): ...
        ...     def sync_to_model(self): ...
        ...     def get_edit_value(self): ...
        ...     def set_edit_value(self, value): ...
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация smart-виджета.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            **kwargs: Дополнительные параметры.
        """
        super().__init__(widget_id=widget_id, controller=controller, **kwargs)
        self._is_editing: bool = False
        self._initial_value: str = ""

    @property
    def is_editing(self) -> bool:
        """Флаг режима редактирования.

        Returns:
            ``True`` если виджет находится в режиме редактирования.
        """
        return self._is_editing

    def enter_edit_mode(self) -> None:
        """Входит в режим редактирования.

        Сохраняет начальное значение для последующего сравнения
        при выходе из режима.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="enter_edit_mode",
                message=f"Widget '{self._widget_id}' not mounted",
            )

        self._is_editing = True
        self._initial_value = self.get_edit_value()

    def exit_edit_mode(self) -> None:
        """Выходит из режима редактирования.

        При наличии изменений вызывает :meth:`sync_to_model`.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="exit_edit_mode",
                message=f"Widget '{self._widget_id}' not mounted",
            )

        self._is_editing = False

        if self.has_changes():
            self.sync_to_model()

    def has_changes(self) -> bool:
        """Проверяет, изменилось ли значение с момента входа в edit mode.

        Returns:
            ``True`` если значение изменилось, иначе ``False``.
        """
        return self.get_edit_value() != self._initial_value

    @abstractmethod
    def sync_to_model(self) -> bool:
        """Синхронизирует локальное состояние с моделью.

        Передаёт текущее значение виджета в контроллер/модель.

        Returns:
            ``True`` если синхронизация выполнена (значение изменилось),
            ``False`` если изменений не было.
        """

    @abstractmethod
    def get_edit_value(self) -> str:
        """Возвращает текущее значение в режиме редактирования.

        Returns:
            Текущее значение виджета.
        """

    @abstractmethod
    def set_edit_value(self, value: str) -> None:
        """Устанавливает значение в режиме редактирования.

        Args:
            value: Новое значение для виджета.
        """
