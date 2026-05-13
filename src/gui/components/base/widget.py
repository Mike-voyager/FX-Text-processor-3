"""Базовые виджеты GUI.

Модуль определяет базовые классы для всех GUI компонентов FX Text Processor 3:
- BaseWidget: "глупый" виджет без локального состояния
- SmartBaseWidget: виджет с локальным состоянием редактирования

Все виджеты используют explicit lifecycle management (mount/unmount) и
не содержат бизнес-логики — только callbacks к Controller.

Example:
    >>> widget = BaseWidget(widget_id="btn_save", controller=my_controller)
    >>> tk_widget = widget.mount(parent_frame)
    >>> widget.is_mounted()
    True
    >>> widget.unmount()
    >>> widget.is_mounted()
    False

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from abc import ABC, abstractmethod
from typing import Any, Optional

from src.gui.core.events import MountEvent, UnmountEvent
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import (
    ControllerProtocol,
    EventProtocol,
)

# =============================================================================
# BASE WIDGET
# =============================================================================


class BaseWidget(ABC):
    """Базовый "глупый" виджет без локального состояния.

    Реализует WidgetProtocol, обеспечивая explicit lifecycle management:
    mount() → handle_event() → unmount().

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.

    Example:
        >>> class MyButton(BaseWidget):
        ...     def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        ...         return tk.Button(parent, text="Click")
        >>> button = MyButton(widget_id="btn_1", controller=ctrl)
        >>> button.mount(parent)
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация базового виджета.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер для callbacks.

        Raises:
            ValueError: Если widget_id пустой или None.
        """
        if not widget_id or not widget_id.strip():
            raise ValueError("widget_id не может быть пустым")

        self._widget_id: str = widget_id
        self._controller: Optional[ControllerProtocol] = controller
        self._tk_widget: Optional[tk.Widget] = None
        self._is_mounted: bool = False

    @property
    def widget_id(self) -> str:
        """Уникальный идентификатор виджета.

        Returns:
            Строковый идентификатор виджета.
        """
        return self._widget_id

    def is_mounted(self) -> bool:
        """Проверяет, смонтирован ли виджет.

        Returns:
            True если виджет смонтирован и активен.

        Example:
            >>> widget.is_mounted()
            False
            >>> widget.mount(parent)
            >>> widget.is_mounted()
            True
        """
        return self._is_mounted

    def mount(self, parent: Any) -> tk.Widget:
        """Монтирует виджет в родительский контейнер.

        Создаёт Tkinter виджет, настраивает bindings, отправляет MountEvent.
        Вызывается один раз при создании виджета.

        Args:
            parent: Родительский Tkinter виджет или Tk root.

        Returns:
            Созданный Tkinter виджет.

        Raises:
            LifecycleError: Если виджет уже смонтирован.
            TypeError: Если parent не является валидным Tk виджетом.

        Example:
            >>> root = tk.Tk()
            >>> frame = tk.Frame(root)
            >>> tk_widget = widget.mount(frame)
            >>> tk_widget.pack()
        """
        if self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="mount",
                message=f"Виджет '{self._widget_id}' уже смонтирован",
            )

        # Check if parent is a valid tk widget (including Tk root)
        if not hasattr(parent, "winfo_exists"):
            raise TypeError(f"parent должен быть Tk виджет, получен {type(parent).__name__}")

        # Создаём Tkinter виджет через абстрактный метод
        self._tk_widget = self._create_tk_widget(parent)

        # Настраиваем event bindings
        self._setup_bindings()

        self._is_mounted = True

        # Отправляем MountEvent если есть контроллер
        if self._controller is not None:
            mount_event = MountEvent(
                widget_id=self._widget_id,
                event_type="mount",
                parent_widget=str(parent),
            )
            self._controller.dispatch("widget_mounted", event=mount_event)

        return self._tk_widget

    def unmount(self) -> None:
        """Демонтирует виджет и освобождает ресурсы.

        Удаляет Tkinter виджет, отписывается от событий, очищает ссылки.
        После вызова виджет не может быть использован повторно.

        Security:
            При демонтировании sensitive виджетов выполняется
            очистка ссылок и ресурсов через _cleanup().

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> widget.unmount()
            >>> # Виджет больше не доступен
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="unmount",
                message=f"Виджет '{self._widget_id}' не смонтирован",
            )

        # Выполняем cleanup перед уничтожением
        self._cleanup()

        # Отправляем UnmountEvent если есть контроллер
        if self._controller is not None:
            unmount_event = UnmountEvent(
                widget_id=self._widget_id,
                event_type="unmount",
            )
            self._controller.dispatch("widget_unmounted", event=unmount_event)

        # Уничтожаем Tkinter виджет
        if self._tk_widget is not None:
            try:
                self._tk_widget.destroy()
            except tk.TclError:
                # Виджет уже уничтожен
                pass
            self._tk_widget = None

        self._is_mounted = False

    def handle_event(self, event: EventProtocol) -> bool:
        """Обрабатывает входящее событие.

        Args:
            event: Событие для обработки (реализует EventProtocol).

        Returns:
            True если событие было обработано (consumed),
            False для передачи события дальше.

        Example:
            >>> result = widget.handle_event(click_event)
            >>> if result:
            ...     print("Событие обработано")
        """
        # Базовая реализация — передаём событие дальше
        # Подклассы могут переопределить для обработки
        return False

    @abstractmethod
    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Абстрактный метод, который должен быть реализован подклассами.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.

        Example:
            >>> def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
            ...     return tk.Button(parent, text="Click")
        """
        ...

    def _setup_bindings(self) -> None:  # noqa: B027
        """Настраивает event bindings для Tkinter виджета.

        Вызывается после создания виджета в mount().
        Подклассы могут переопределить для добавления специфичных bindings.

        Example:
            >>> def _setup_bindings(self) -> None:
            ...     if self._tk_widget is not None:
            ...         self._tk_widget.bind('<Button-1>', self._on_click)
        """
        # Базовая реализация — ничего не делает
        # Подклассы добавляют свои bindings
        pass

    def _cleanup(self) -> None:  # noqa: B027
        """Выполняет очистку ресурсов перед демонтированием.

        Вызывается в unmount() перед уничтожением Tkinter виджета.
        Подклассы должны переопределить для очистки:
        - Отписка от событий
        - Очистка sensitive данных
        - Освобождение внешних ресурсов

        Security:
            При работе с чувствительными данными должен выполняться
            secure_zero для очистки памяти.

        Example:
            >>> def _cleanup(self) -> None:
            ...     if self._tk_widget is not None:
            ...         self._tk_widget.unbind('<Button-1>')
            ...     self._secret_data = None
        """
        # Базовая реализация — ничего не делает
        # Подклассы добавляют свою очистку
        pass


# =============================================================================
# SMART BASE WIDGET
# =============================================================================


class SmartBaseWidget(BaseWidget):
    """Базовый "умный" виджет с локальным состоянием редактирования.

    Реализует SmartWidgetProtocol, добавляя режим редактирования:
    - VIEW_MODE: отображение значения из модели
    - EDIT_MODE: локальное редактирование, sync отключен

    Используется для компонентов, требующих локального состояния
    (Text, Entry и т.д.) с явным входом/выходом в режим редактирования.

    Attributes:
        widget_id: Унаследован от BaseWidget.
        controller: Унаследован от BaseWidget.
        is_editing: Флаг режима редактирования (True = EDIT_MODE).

    Example:
        >>> class SmartTextEditor(SmartBaseWidget):
        ...     def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        ...         return tk.Text(parent)
        ...     def get_edit_value(self) -> str:
        ...         return self._tk_widget.get('1.0', tk.END) if self._tk_widget else ""
        ...     def set_edit_value(self, value: str) -> None:
        ...         if self._tk_widget:
        ...             self._tk_widget.delete('1.0', tk.END)
        ...             self._tk_widget.insert('1.0', value)
        ...     def sync_to_model(self) -> bool:
        ...         if self.has_changes():
        ...             value = self.get_edit_value()
        ...             self._controller.dispatch("text_changed", text=value)
        ...             return True
        ...         return False
        >>> editor = SmartTextEditor(widget_id="doc_editor", controller=ctrl)
        >>> editor.enter_edit_mode()
        >>> editor.is_editing
        True
        >>> editor.set_edit_value("Hello")
        >>> editor.exit_edit_mode()
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация smart виджета.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер для callbacks.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._is_editing: bool = False
        self._initial_value: str = ""

    @property
    def is_editing(self) -> bool:
        """Флаг режима редактирования.

        Returns:
            True если виджет находится в режиме редактирования (EDIT_MODE),
            False если в режиме просмотра (VIEW_MODE).
        """
        return self._is_editing

    def enter_edit_mode(self) -> None:
        """Входит в режим редактирования.

        В этом режиме виджет работает автономно:
        - Сохраняется начальное значение для сравнения
        - Отключается синхронизация с моделью
        - Пользователь может свободно редактировать

        Note:
            Метод вызывается при FocusIn или явном входе в редактирование.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> editor.enter_edit_mode()
            >>> # Пользователь редактирует текст
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="enter_edit_mode",
                message=f"Виджет '{self._widget_id}' не смонтирован",
            )

        self._is_editing = True
        self._initial_value = self.get_edit_value()

    def exit_edit_mode(self) -> None:
        """Выходит из режима редактирования.

        При выходе из режима:
        - Сравнивается текущее значение с начальным
        - Если есть изменения — вызывается sync_to_model()
        - Возобновляется синхронизация с моделью

        Note:
            Метод вызывается при FocusOut или явном выходе из редактирования.
            Если значение изменилось — автоматически вызывается sync_to_model().

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> editor.exit_edit_mode()
            >>> # Если текст изменился, sync_to_model() вызван автоматически
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="exit_edit_mode",
                message=f"Виджет '{self._widget_id}' не смонтирован",
            )

        self._is_editing = False

        # Синхронизируем с моделью если были изменения
        if self.has_changes():
            self.sync_to_model()

    @abstractmethod
    def sync_to_model(self) -> bool:
        """Синхронизирует локальное состояние с моделью.

        Передаёт текущее значение виджета в Controller через callback.
        Создаёт Command для undo/redo менеджера.

        Returns:
            True если синхронизация выполнена (значение изменилось),
            False если изменений не было.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> changed = editor.sync_to_model()
            >>> if changed:
            ...     print("Модель обновлена, undo добавлен в историю")
        """
        ...

    @abstractmethod
    def get_edit_value(self) -> str:
        """Возвращает текущее значение в режиме редактирования.

        Returns:
            Текущее значение виджета (строка).

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Example:
            >>> editor.enter_edit_mode()
            >>> # Пользователь ввёл "Hello"
            >>> editor.get_edit_value()
            'Hello'
        """
        ...

    @abstractmethod
    def set_edit_value(self, value: str) -> None:
        """Устанавливает значение в режиме редактирования.

        Args:
            value: Новое значение для виджета.

        Raises:
            LifecycleError: Если виджет не смонтирован.

        Note:
            Метод не синхронизируется с моделью — только локальное изменение.

        Example:
            >>> editor.set_edit_value("New text")
            >>> editor.get_edit_value()
            'New text'
        """
        ...

    def has_changes(self) -> bool:
        """Проверяет, изменилось ли значение с момента входа в edit mode.

        Сравнивает текущее значение с начальным значением, сохранённым
        при вызове enter_edit_mode().

        Returns:
            True если значение изменилось, иначе False.

        Example:
            >>> editor.enter_edit_mode()
            >>> editor.set_edit_value("New value")
            >>> editor.has_changes()
            True
        """
        current_value = self.get_edit_value()
        return current_value != self._initial_value


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "BaseWidget",
    "SmartBaseWidget",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-01"
