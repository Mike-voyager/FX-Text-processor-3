"""Lifecycle Manager для GUI компонентов.

Модуль предоставляет систему управления жизненным циклом GUI компонентов:
- LifecycleAware Protocol для типизации
- LifecycleManager для отслеживания состояния компонентов
- SafeMount контекстный менеджер для безопасного mount/unmount
- Lifecycle events для отслеживания изменений состояния

Example:
    >>> from src.gui.core.lifecycle import LifecycleManager, SafeMount
    >>> manager = LifecycleManager()
    >>> widget = BaseWidget(widget_id="test")
    >>> with SafeMount(widget, parent) as tk_widget:
    ...     # widget смонтирован
    ...     pass
    >>> # widget размонтирован автоматически

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Callable,
    Generator,
    Optional,
    Protocol,
    TypeVar,
    runtime_checkable,
)

# Events module - imported for potential future use
# from src.gui.core.events import MountEvent, UnmountEvent

if TYPE_CHECKING:
    pass


# =============================================================================
# LIFECYCLE STATE
# =============================================================================


class LifecycleState(Enum):
    """Состояния жизненного цикла компонента.

    States:
        UNMOUNTED: Компонент не смонтирован
        MOUNTING: Процесс монтирования в progress
        MOUNTED: Компонент активен и отображается
        UNMOUNTING: Процесс размонтирования в progress
        ERROR: Ошибка в жизненном цикле

    Example:
        >>> state = LifecycleState.MOUNTED
        >>> state.is_active
        True
    """

    UNMOUNTED = auto()
    MOUNTING = auto()
    MOUNTED = auto()
    UNMOUNTING = auto()
    ERROR = auto()

    @property
    def is_active(self) -> bool:
        """Проверяет, активно ли состояние (компонент смонтирован).

        Returns:
            True если компонент смонтирован и готов к использованию.
        """
        return self == LifecycleState.MOUNTED

    @property
    def is_transition(self) -> bool:
        """Проверяет, является ли состояние переходным.

        Returns:
            True если компонент в процессе монтирования/размонтирования.
        """
        return self in (LifecycleState.MOUNTING, LifecycleState.UNMOUNTING)


# =============================================================================
# COMPONENT INFO
# =============================================================================


@dataclass(frozen=True)
class ComponentInfo:
    """Информация о зарегистрированном компоненте.

    Attributes:
        widget_id: Уникальный идентификатор компонента.
        state: Текущее состояние жизненного цикла.
        widget: Ссылка на Tkinter виджет (если смонтирован).
        parent_id: Идентификатор родительского виджета.
        callbacks: Список зарегистрированных callbacks.

    Example:
        >>> info = ComponentInfo(
        ...     widget_id="btn_1",
        ...     state=LifecycleState.MOUNTED,
        ...     widget=tk_button,
        ...     parent_id="main_frame"
        ... )
    """

    widget_id: str
    state: LifecycleState = LifecycleState.UNMOUNTED
    widget: Optional[tk.Widget] = None
    parent_id: Optional[str] = None
    callbacks: list[str] = field(default_factory=list)


# =============================================================================
# LIFECYCLE AWARE PROTOCOL
# =============================================================================


T = TypeVar("T", bound=tk.Widget)


@runtime_checkable
class LifecycleAware(Protocol):
    """Protocol для компонентов с управляемым жизненным циклом.

    Компоненты, реализующие этот протокол, могут использоваться
    с LifecycleManager и SafeMount для автоматического управления
    жизненным циклом.

    Methods:
        mount: Монтирует компонент в родительский контейнер
        unmount: Демонтирует компонент и освобождает ресурсы

    Example:
        >>> class MyWidget(LifecycleAware):
        ...     def mount(self, parent: tk.Widget) -> tk.Widget:
        ...         return tk.Button(parent, text="Click")
        ...     def unmount(self) -> None:
        ...         pass
    """

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует компонент в родительский контейнер.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.

        Raises:
            ValueError: Если widget_id пустой или уже зарегистрирован.
        """
        ...

    def unmount(self) -> None:
        """Демонтирует компонент и освобождает ресурсы.

        Вызывается SafeMount при выходе из контекста для гарантии
        корректной очистки ресурсов компонента.

        Security:
            При демонтировании sensitive виджетов должна выполняться
            очистка памяти (secure_zero) для чувствительных данных.
        """
        ...


# =============================================================================
# LIFECYCLE MANAGER
# =============================================================================


class LifecycleManager:
    """Менеджер жизненного цикла GUI компонентов.

    Отслеживает состояние всех компонентов, обеспечивает thread-safe
    регистрацию/дерегистрацию и предоставляет события для мониторинга
    жизненного цикла.

    Attributes:
        _components: Словарь зарегистрированных компонентов.
        _lock: Lock для thread-safe операций.
        _event_handlers: Обработчики событий жизненного цикла.

    Example:
        >>> manager = LifecycleManager()
        >>> manager.register("btn_1", on_mount=lambda: print("mounted"))
        >>> manager.transition_to("btn_1", LifecycleState.MOUNTED)
        >>> info = manager.get_state("btn_1")
        >>> info.state.is_active
        True
    """

    def __init__(self) -> None:
        """Инициализация менеджера жизненного цикла."""
        self._components: dict[str, ComponentInfo] = {}
        self._lock = threading.RLock()
        self._event_handlers: dict[str, list[Callable[[ComponentInfo], None]]] = {
            "mount": [],
            "unmount": [],
            "state_changed": [],
            "error": [],
        }

    def register(
        self,
        widget_id: str,
        on_mount: Optional[Callable[[], None]] = None,
        on_unmount: Optional[Callable[[], None]] = None,
        on_state_changed: Optional[Callable[[ComponentInfo], None]] = None,
    ) -> ComponentInfo:
        """Регистрирует компонент в менеджере.

        Args:
            widget_id: Уникальный идентификатор компонента.
            on_mount: Callback при монтировании.
            on_unmount: Callback при размонтировании.
            on_state_changed: Callback при изменении состояния.

        Returns:
            Информация о зарегистрированном компоненте.

        Raises:
            ValueError: Если widget_id пустой или уже зарегистрирован.

        Example:
            >>> info = manager.register("btn_1", on_mount=lambda: print("mounted"))
        """
        if not widget_id or not widget_id.strip():
            raise ValueError("widget_id cannot be empty")

        with self._lock:
            if widget_id in self._components:
                raise ValueError(f"Component '{widget_id}' already registered")

            info = ComponentInfo(widget_id=widget_id)
            self._components[widget_id] = info

            # Регистрируем callbacks
            if on_mount:
                self._event_handlers["mount"].append(lambda _: on_mount())
            if on_unmount:
                self._event_handlers["unmount"].append(lambda _: on_unmount())
            if on_state_changed:
                self._event_handlers["state_changed"].append(on_state_changed)

            return info

    def unregister(self, widget_id: str) -> None:
        """Удаляет регистрацию компонента.

        Args:
            widget_id: Идентификатор компонента.

        Raises:
            KeyError: Если компонент не найден.

        Example:
            >>> manager.unregister("btn_1")
        """
        with self._lock:
            if widget_id not in self._components:
                raise KeyError(f"Component '{widget_id}' not found")

            info = self._components[widget_id]

            # Демонтируем если активен
            if info.state.is_active:
                self._trigger_unmount(info)

            del self._components[widget_id]

    def transition_to(self, widget_id: str, new_state: LifecycleState) -> ComponentInfo:
        """Переводит компонент в новое состояние.

        Args:
            widget_id: Идентификатор компонента.
            new_state: Новое состояние жизненного цикла.

        Returns:
            Обновленная информация о компоненте.

        Raises:
            KeyError: Если компонент не найден.

        Example:
            >>> info = manager.transition_to("btn_1", LifecycleState.MOUNTED)
        """
        with self._lock:
            if widget_id not in self._components:
                raise KeyError(f"Component '{widget_id}' not found")

            info = self._components[widget_id]
            old_state = info.state

            # Обновляем состояние через создание нового объекта
            new_info = ComponentInfo(
                widget_id=info.widget_id,
                state=new_state,
                widget=info.widget,
                parent_id=info.parent_id,
                callbacks=info.callbacks.copy(),
            )
            self._components[widget_id] = new_info

            # Триггерим события
            self._trigger_state_change(new_info, old_state)

            if new_state == LifecycleState.MOUNTED:
                self._trigger_mount(new_info)
            elif new_state == LifecycleState.UNMOUNTED:
                self._trigger_unmount(new_info)

            return new_info

    def get_state(self, widget_id: str) -> ComponentInfo:
        """Возвращает текущее состояние компонента.

        Args:
            widget_id: Идентификатор компонента.

        Returns:
            Информация о компоненте.

        Raises:
            KeyError: Если компонент не найден.

        Example:
            >>> info = manager.get_state("btn_1")
            >>> print(info.state)
        """
        with self._lock:
            if widget_id not in self._components:
                raise KeyError(f"Component '{widget_id}' not found")
            return self._components[widget_id]

    def is_registered(self, widget_id: str) -> bool:
        """Проверяет, зарегистрирован ли компонент.

        Args:
            widget_id: Идентификатор компонента.

        Returns:
            True если компонент зарегистрирован.

        Example:
            >>> if manager.is_registered("btn_1"):
            ...     print("Зарегистрирован")
        """
        with self._lock:
            return widget_id in self._components

    def is_active(self, widget_id: str) -> bool:
        """Проверяет, активен ли компонент.

        Args:
            widget_id: Идентификатор компонента.

        Returns:
            True если компонент смонтирован и активен.

        Raises:
            KeyError: Если компонент не найден.

        Example:
            >>> if manager.is_active("btn_1"):
            ...     print("Активен")
        """
        with self._lock:
            info = self.get_state(widget_id)
            return info.state.is_active

    def get_all_active(self) -> list[ComponentInfo]:
        """Возвращает список всех активных компонентов.

        Returns:
            Список активных компонентов.

        Example:
            >>> active = manager.get_all_active()
            >>> print(f"Активных компонентов: {len(active)}")
        """
        with self._lock:
            return [info for info in self._components.values() if info.state.is_active]

    def update_widget(
        self, widget_id: str, widget: tk.Widget, parent_id: Optional[str] = None
    ) -> ComponentInfo:
        """Обновляет ссылку на Tkinter виджет.

        Args:
            widget_id: Идентификатор компонента.
            widget: Tkinter виджет.
            parent_id: Идентификатор родительского виджета.

        Returns:
            Обновленная информация о компоненте.

        Raises:
            KeyError: Если компонент не найден.

        Example:
            >>> info = manager.update_widget("btn_1", tk_button, "main_frame")
        """
        with self._lock:
            if widget_id not in self._components:
                raise KeyError(f"Component '{widget_id}' not found")

            info = self._components[widget_id]
            new_info = ComponentInfo(
                widget_id=info.widget_id,
                state=info.state,
                widget=widget,
                parent_id=parent_id or info.parent_id,
                callbacks=info.callbacks.copy(),
            )
            self._components[widget_id] = new_info
            return new_info

    def clear(self) -> None:
        """Очищает все регистрации.

        Warning:
            Размонтирует все активные компоненты перед очисткой.

        Example:
            >>> manager.clear()
        """
        with self._lock:
            # Демонтируем все активные
            for info in self._components.values():
                if info.state.is_active:
                    self._trigger_unmount(info)
            self._components.clear()
            self._event_handlers.clear()

    def _trigger_mount(self, info: ComponentInfo) -> None:
        """Триггерит событие монтирования."""
        for handler in self._event_handlers.get("mount", []):
            try:
                handler(info)
            except Exception as e:  # nosec B110 - callbacks should not crash manager  # noqa: S110, BLE001
                logging.exception(f"Error during mount callback: {e}")
                pass  # noqa: S110

    def _trigger_unmount(self, info: ComponentInfo) -> None:
        """Триггерит событие размонтирования."""
        for handler in self._event_handlers.get("unmount", []):
            try:
                handler(info)
            except Exception as e:  # nosec B110 - callbacks should not crash manager  # noqa: S110, BLE001
                logging.exception(f"Error during unmount callback: {e}")
                pass  # noqa: S110

    def _trigger_state_change(self, info: ComponentInfo, old_state: LifecycleState) -> None:
        """Триггерит событие изменения состояния."""
        for handler in self._event_handlers.get("state_changed", []):
            try:
                handler(info)
            except Exception as e:  # nosec B110 - callbacks should not crash manager  # noqa: S110, BLE001
                logging.exception(f"Error during state change callback: {e}")
                pass  # noqa: S110


# =============================================================================
# SAFE MOUNT CONTEXT MANAGER
# =============================================================================


@contextmanager
def SafeMount(
    component: LifecycleAware,
    parent: tk.Widget,
    manager: Optional["LifecycleManager"] = None,
) -> Generator[Optional[tk.Widget], None, None]:
    """Контекстный менеджер для безопасного mount/unmount.

    Автоматически монтирует компонент при входе в контекст
    и демонтирует при выходе (даже при исключении).

    Args:
        component: Компонент для монтирования (LifecycleAware).
        parent: Родительский Tkinter виджет.
        manager: Опциональный LifecycleManager для регистрации.

    Yields:
        Tkinter виджет созданный компонентом.

    Raises:
        ValueError: Если компонент уже смонтирован.
        Exception: Пробрасывает исключения из component.mount().

    Example:
        >>> widget = BaseWidget(widget_id="test")
        >>> with SafeMount(widget, parent) as tk_widget:
        ...     # widget смонтирован
        ...     tk_widget.pack()
        >>> # widget размонтирован автоматически
    """
    widget: Optional[tk.Widget] = None
    registered = False
    widget_id: str = ""

    try:
        # Монтируем компонент
        widget = component.mount(parent)

        # Регистрируем в менеджере если передан
        if manager is not None:
            try:
                widget_id = getattr(component, "widget_id", str(id(component)))
                manager.register(widget_id)
                manager.update_widget(widget_id, widget, str(parent))
                manager.transition_to(widget_id, LifecycleState.MOUNTED)
                registered = True
            except Exception as e:  # nosec B110 - registration errors should not block mount  # noqa: S110, BLE001
                logging.exception(f"Registration error for {widget_id or 'unknown'}: {e}")
                pass  # noqa: S110

        yield widget

    except Exception as e:  # noqa: BLE001
        # При ошибке пробрасываем исключение
        logging.exception(f"Critical lifecycle error: {e}")
        raise
    finally:
        # Всегда демонтируем при выходе из контекста
        try:
            if registered and manager is not None:
                try:
                    widget_id = getattr(component, "widget_id", str(id(component)))
                    manager.transition_to(widget_id, LifecycleState.UNMOUNTED)
                    manager.unregister(widget_id)
                except Exception as e:  # nosec B110 - cleanup errors should not block  # noqa: S110, BLE001
                    logging.exception(f"Cleanup error for {widget_id or 'unknown'}: {e}")
                    pass  # noqa: S110

            component.unmount()
        except Exception as e:  # nosec B110 - cleanup errors should not block  # noqa: S110, BLE001
            logging.exception(f"Critical cleanup error: {e}")
            pass  # Игнорируем ошибки при cleanup  # noqa: S110


# =============================================================================
# LIFECYCLE CALLBACKS DECORATOR
# =============================================================================


class LifecycleCallbacks:
    """Декораторы для lifecycle callbacks.

    Предоставляет декораторы для автоматической регистрации
    callbacks при монтировании/размонтировании компонентов.

    Example:
        >>> callbacks = LifecycleCallbacks()
        >>>
        >>> @callbacks.on_mount
        ... def init_data():
        ...     print("Data initialized")
        >>>
        >>> @callbacks.on_unmount
        ... def cleanup():
        ...     print("Cleanup done")
    """

    def __init__(self) -> None:
        """Инициализация коллекции callbacks."""
        self._mount_handlers: list[Callable[[], None]] = []
        self._unmount_handlers: list[Callable[[], None]] = []

    def on_mount(self, func: Callable[[], None]) -> Callable[[], None]:
        """Декоратор для callback при монтировании.

        Args:
            func: Функция для вызова при монтировании.

        Returns:
            Оригинальная функция.

        Example:
            >>> @callbacks.on_mount
            ... def init():
            ...     print("Initialized")
        """
        self._mount_handlers.append(func)
        return func

    def on_unmount(self, func: Callable[[], None]) -> Callable[[], None]:
        """Декоратор для callback при размонтировании.

        Args:
            func: Функция для вызова при размонтировании.

        Returns:
            Оригинальная функция.

        Example:
            >>> @callbacks.on_unmount
            ... def cleanup():
            ...     print("Cleaned up")
        """
        self._unmount_handlers.append(func)
        return func

    def trigger_mount(self) -> None:
        """Вызывает все mount callbacks."""
        for handler in self._mount_handlers:
            try:
                handler()
            except Exception as e:  # nosec B110 - callbacks should not crash trigger  # noqa: S110, BLE001
                logging.exception(f"Mount callback failed: {e}")
                pass  # noqa: S110

    def trigger_unmount(self) -> None:
        """Вызывает все unmount callbacks."""
        for handler in self._unmount_handlers:
            try:
                handler()
            except Exception as e:  # nosec B110 - callbacks should not crash trigger  # noqa: S110, BLE001
                logging.exception(f"Unmount callback failed: {e}")
                pass  # noqa: S110
                pass  # noqa: S110


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    # Enums
    "LifecycleState",
    # Dataclasses
    "ComponentInfo",
    # Protocols
    "LifecycleAware",
    # Classes
    "LifecycleManager",
    "LifecycleCallbacks",
    # Context managers
    "SafeMount",
]
