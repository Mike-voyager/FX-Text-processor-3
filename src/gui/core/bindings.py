"""Model-View binding system для GUI.

Предоставляет двустороннюю привязку данных между моделью и виджетами.
Реализует паттерн Observable для реактивного обновления UI.

Classes:
    ObservableValue: Наблюдаемое значение с возможностью подписки.
    Binding: Односторонняя привязка к ObservableValue.
    TwoWayBinding: Двусторонняя привязка между моделью и виджетом.

Example:
    >>> observable = ObservableValue("initial")
    >>> binding = Binding(observable)
    >>> def on_change(value: str) -> None:
    ...     print(f"Value changed to: {value}")
    >>> observable.bind(on_change)
    >>> binding.set("new value")  # on_change будет вызван

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class ObservableValue(Generic[T]):
    """Наблюдаемое значение с поддержкой подписчиков.

    Реализует паттерн Observable для реактивного обновления UI.
    При изменении значения вызывает все зарегистрированные callbacks.

    Attributes:
        _value: Текущее значение.
        _callbacks: Множество подписчиков на изменения.

    Example:
        >>> observable = ObservableValue(42)
        >>> def callback(value: int) -> None:
        ...     print(f"New value: {value}")
        >>> observable.bind(callback)
        >>> observable.set(100)  # выводит: New value: 100
    """

    def __init__(self, value: T) -> None:
        """Инициализация наблюдаемого значения.

        Args:
            value: Начальное значение.
        """
        self._value: T = value
        self._callbacks: set[Callable[[T], None]] = set()

    def get(self) -> T:
        """Возвращает текущее значение.

        Returns:
            Текущее значение типа T.

        Example:
            >>> observable = ObservableValue("test")
            >>> observable.get()
            'test'
        """
        return self._value

    def set(self, value: T) -> None:
        """Устанавливает новое значение и уведомляет подписчиков.

        Args:
            value: Новое значение.

        Note:
            Подписчики вызываются только если значение изменилось.

        Example:
            >>> observable = ObservableValue(0)
            >>> observable.set(42)  # Подписчики уведомлены
            >>> observable.set(42)  # Подписчики не вызваны (значение не изменилось)
        """
        if value != self._value:
            self._value = value
            self._notify()

    def bind(self, callback: Callable[[T], None]) -> None:
        """Подписывает callback на изменения значения.

        Args:
            callback: Функция, вызываемая при изменении значения.

        Example:
            >>> observable = ObservableValue("")
            >>> observable.bind(lambda v: print(f"Changed: {v}"))
        """
        self._callbacks.add(callback)

    def unbind(self, callback: Callable[[T], None]) -> None:
        """Отписывает callback от изменений значения.

        Args:
            callback: Функция для удаления из подписчиков.

        Example:
            >>> def handler(value: str) -> None:
            ...     pass
            >>> observable.bind(handler)
            >>> observable.unbind(handler)  # Отписка
        """
        self._callbacks.discard(callback)

    def _notify(self) -> None:
        """Уведомляет всех подписчиков об изменении.

        Вызывает все зарегистрированные callbacks с текущим значением.
        """
        for callback in self._callbacks:
            callback(self._value)


class Binding(Generic[T]):
    """Односторонняя привязка к ObservableValue.

    Предоставляет интерфейс для чтения и записи значения
    с автоматическим уведомлением всех подписчиков.

    Attributes:
        _observable: Связанное наблюдаемое значение.

    Example:
        >>> observable = ObservableValue(10)
        >>> binding = Binding(observable)
        >>> binding.get()
        10
        >>> binding.set(20)
        >>> binding.get()
        20
    """

    def __init__(self, observable: ObservableValue[T]) -> None:
        """Инициализация привязки.

        Args:
            observable: Наблюдаемое значение для привязки.
        """
        self._observable: ObservableValue[T] = observable

    def get(self) -> T:
        """Возвращает текущее значение.

        Returns:
            Текущее значение из ObservableValue.

        Example:
            >>> observable = ObservableValue("text")
            >>> binding = Binding(observable)
            >>> binding.get()
            'text'
        """
        return self._observable.get()

    def set(self, value: T) -> None:
        """Устанавливает новое значение.

        Args:
            value: Новое значение для установки.

        Example:
            >>> observable = ObservableValue(0)
            >>> binding = Binding(observable)
            >>> binding.set(42)
        """
        self._observable.set(value)


class TwoWayBinding(Generic[T]):
    """Двусторонняя привязка между моделью и виджетом.

    Обеспечивает синхронизацию значения между ObservableValue (модель)
    и Tkinter виджетом. Поддерживает явную синхронизацию в обоих направлениях.

    Attributes:
        _model_value: Наблюдаемое значение модели.
        _widget_getter: Функция получения значения из виджета.
        _widget_setter: Функция установки значения в виджет.
        _model_callback: Callback для подписки на изменения модели.

    Example:
        >>> import tkinter as tk
        >>> root = tk.Tk()
        >>> entry = tk.Entry(root)
        >>> observable = ObservableValue("")
        >>> binding = TwoWayBinding(
        ...     observable,
        ...     entry.get,
        ...     entry.delete(0, tk.END) or entry.insert(0, ...)
        ... )
    """

    def __init__(
        self,
        model_value: ObservableValue[T],
        widget_getter: Callable[[], T],
        widget_setter: Callable[[T], None],
    ) -> None:
        """Инициализация двусторонней привязки.

        Args:
            model_value: Наблюдаемое значение модели.
            widget_getter: Функция для получения значения из виджета.
            widget_setter: Функция для установки значения в виджет.

        Example:
            >>> observable = ObservableValue("")
            >>> binding = TwoWayBinding(
            ...     observable,
            ...     lambda: entry.get(),
            ...     lambda v: entry.delete(0, tk.END) or entry.insert(0, v)
            ... )
        """
        self._model_value: ObservableValue[T] = model_value
        self._widget_getter: Callable[[], T] = widget_getter
        self._widget_setter: Callable[[T], None] = widget_setter

        # Подписываемся на изменения модели
        self._model_callback: Callable[[T], None] = self._on_model_changed
        self._model_value.bind(self._model_callback)

    def _on_model_changed(self, value: T) -> None:
        """Обработчик изменения значения модели.

        Автоматически обновляет виджет при изменении модели.

        Args:
            value: Новое значение модели.
        """
        # Обновляем виджет, только если значение отличается
        if self._widget_getter() != value:
            self._widget_setter(value)

    def sync_to_model(self) -> bool:
        """Синхронизирует виджет → модель.

        Получает текущее значение из виджета и обновляет модель.

        Returns:
            True если значение было изменено, False если осталось прежним.

        Example:
            >>> binding.sync_to_model()  # Обновляет модель из виджета
            True
        """
        widget_value = self._widget_getter()
        model_value = self._model_value.get()

        if widget_value != model_value:
            self._model_value.set(widget_value)
            return True
        return False

    def sync_from_model(self) -> bool:
        """Синхронизирует модель → виджет.

        Получает текущее значение из модели и обновляет виджет.

        Returns:
            True если значение было изменено, False если осталось прежним.

        Example:
            >>> binding.sync_from_model()  # Обновляет виджет из модели
            True
        """
        model_value = self._model_value.get()
        widget_value = self._widget_getter()

        if model_value != widget_value:
            self._widget_setter(model_value)
            return True
        return False

    def unbind(self) -> None:
        """Отвязывает привязку от модели.

        Удаляет callback из подписчиков ObservableValue.
        После вызова виджет больше не будет обновляться
        автоматически при изменении модели.

        Example:
            >>> binding.unbind()  # Полная отписка от модели
        """
        self._model_value.unbind(self._model_callback)


__all__: list[str] = [
    "ObservableValue",
    "Binding",
    "TwoWayBinding",
]
