"""Тесты для модуля bindings GUI.

Проверяет работу ObservableValue, Binding и TwoWayBinding классов.

Example:
    $ pytest tests/unit/gui/core/test_bindings.py -v

Note:
    Требуется запуск с виртуальным дисплеем для GUI тестов:
    $ xvfb-run -a python -m pytest tests/unit/gui/core/test_bindings.py -v
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.gui.core.bindings import Binding, ObservableValue, TwoWayBinding


# =============================================================================
# OBSERVABLE VALUE TESTS
# =============================================================================


class TestObservableValue:
    """Тесты для ObservableValue класса."""

    def test_init_stores_initial_value(self) -> None:
        """Тест: конструктор сохраняет начальное значение."""
        observable = ObservableValue("initial")
        assert observable.get() == "initial"

    def test_get_returns_current_value(self) -> None:
        """Тест: get() возвращает текущее значение."""
        observable = ObservableValue(42)
        assert observable.get() == 42

    def test_set_updates_value(self) -> None:
        """Тест: set() обновляет значение."""
        observable = ObservableValue(0)
        observable.set(100)
        assert observable.get() == 100

    def test_set_notifies_subscribers(self) -> None:
        """Тест: set() вызывает подписчиков при изменении."""
        observable = ObservableValue("old")
        callback = MagicMock()

        observable.bind(callback)
        observable.set("new")

        callback.assert_called_once_with("new")

    def test_set_does_not_notify_when_value_unchanged(self) -> None:
        """Тест: set() не вызывает подписчиков если значение не изменилось."""
        observable = ObservableValue("same")
        callback = MagicMock()

        observable.bind(callback)
        observable.set("same")

        callback.assert_not_called()

    def test_bind_adds_callback(self) -> None:
        """Тест: bind() добавляет callback."""
        observable = ObservableValue(0)
        callback = MagicMock()

        observable.bind(callback)
        observable.set(1)

        assert callback.call_count == 1

    def test_unbind_removes_callback(self) -> None:
        """Тест: unbind() удаляет callback."""
        observable = ObservableValue(0)
        callback = MagicMock()

        observable.bind(callback)
        observable.unbind(callback)
        observable.set(1)

        callback.assert_not_called()

    def test_multiple_subscribers_notified(self) -> None:
        """Тест: несколько подписчиков получают уведомления."""
        observable = ObservableValue(0)
        callback1 = MagicMock()
        callback2 = MagicMock()

        observable.bind(callback1)
        observable.bind(callback2)
        observable.set(42)

        callback1.assert_called_once_with(42)
        callback2.assert_called_once_with(42)

    def test_different_types(self) -> None:
        """Тест: ObservableValue работает с разными типами."""
        # int
        obs_int = ObservableValue(0)
        obs_int.set(100)
        assert obs_int.get() == 100

        # float
        obs_float = ObservableValue(0.0)
        obs_float.set(3.14)
        assert obs_float.get() == 3.14

        # list
        obs_list = ObservableValue([1, 2])
        obs_list.set([1, 2, 3])
        assert obs_list.get() == [1, 2, 3]


# =============================================================================
# BINDING TESTS
# =============================================================================


class TestBinding:
    """Тесты для Binding класса."""

    def test_init_binds_to_observable(self) -> None:
        """Тест: Binding привязывается к ObservableValue."""
        observable = ObservableValue("test")
        binding = Binding(observable)

        assert binding.get() == "test"

    def test_get_returns_observable_value(self) -> None:
        """Тест: get() возвращает значение из Observable."""
        observable = ObservableValue(42)
        binding = Binding(observable)

        assert binding.get() == 42

    def test_set_updates_observable(self) -> None:
        """Тест: set() обновляет значение Observable."""
        observable = ObservableValue(0)
        binding = Binding(observable)

        binding.set(100)

        assert observable.get() == 100
        assert binding.get() == 100

    def test_set_triggers_notifications(self) -> None:
        """Тест: set() через Binding вызывает подписчиков Observable."""
        observable = ObservableValue("old")
        callback = MagicMock()

        observable.bind(callback)
        binding = Binding(observable)
        binding.set("new")

        callback.assert_called_once_with("new")

    def test_multiple_bindings_share_observable(self) -> None:
        """Тест: несколько Binding могут использовать один Observable."""
        observable = ObservableValue(0)
        binding1 = Binding(observable)
        binding2 = Binding(observable)

        binding1.set(42)

        assert binding2.get() == 42
        assert observable.get() == 42


# =============================================================================
# TWO-WAY BINDING TESTS
# =============================================================================


class TestTwoWayBinding:
    """Тесты для TwoWayBinding класса."""

    @pytest.fixture
    def tk_app(self) -> tk.Tk:
        """Fixture: создаёт корневое окно Tk."""
        root = tk.Tk()
        root.withdraw()  # Скрываем окно
        yield root
        root.destroy()

    def test_init_subscribes_to_model(self) -> None:
        """Тест: конструктор подписывается на изменения модели."""
        observable = ObservableValue("initial")
        widget_getter = MagicMock(return_value="initial")
        widget_setter = MagicMock()

        TwoWayBinding(observable, widget_getter, widget_setter)

        # Изменяем модель и проверяем что виджет обновился
        widget_setter.reset_mock()
        observable.set("new")

        widget_setter.assert_called_once_with("new")

    def test_sync_to_model_updates_from_widget(self) -> None:
        """Тест: sync_to_model() обновляет модель из виджета."""
        observable = ObservableValue("old")
        widget_getter = MagicMock(return_value="new")
        widget_setter = MagicMock()

        binding = TwoWayBinding(observable, widget_getter, widget_setter)
        result = binding.sync_to_model()

        assert result is True
        assert observable.get() == "new"

    def test_sync_to_model_returns_false_when_unchanged(self) -> None:
        """Тест: sync_to_model() возвращает False если значение не изменилось."""
        observable = ObservableValue("same")
        widget_getter = MagicMock(return_value="same")
        widget_setter = MagicMock()

        binding = TwoWayBinding(observable, widget_getter, widget_setter)
        result = binding.sync_to_model()

        assert result is False

    def test_sync_from_model_updates_widget(self) -> None:
        """Тест: sync_from_model() обновляет виджет из модели."""
        observable = ObservableValue("model_value")
        widget_getter = MagicMock(return_value="old_widget")
        widget_setter = MagicMock()

        binding = TwoWayBinding(observable, widget_getter, widget_setter)
        result = binding.sync_from_model()

        assert result is True
        widget_setter.assert_called_once_with("model_value")

    def test_sync_from_model_returns_false_when_unchanged(self) -> None:
        """Тест: sync_from_model() возвращает False если значение не изменилось."""
        observable = ObservableValue("same")
        widget_getter = MagicMock(return_value="same")
        widget_setter = MagicMock()

        binding = TwoWayBinding(observable, widget_getter, widget_setter)
        result = binding.sync_from_model()

        assert result is False
        widget_setter.assert_not_called()

    def test_model_change_updates_widget(self) -> None:
        """Тест: изменение модели автоматически обновляет виджет."""
        observable = ObservableValue("initial")
        widget_getter = MagicMock(return_value="initial")
        widget_setter = MagicMock()

        TwoWayBinding(observable, widget_getter, widget_setter)

        # Меняем значение модели
        observable.set("updated")

        # Виджет должен быть обновлен
        widget_setter.assert_called_with("updated")

    def test_widget_not_updated_when_values_equal(self) -> None:
        """Тест: виджет не обновляется если значение совпадает."""
        observable = ObservableValue("same")
        widget_getter = MagicMock(return_value="same")
        widget_setter = MagicMock()

        TwoWayBinding(observable, widget_getter, widget_setter)

        # Сбрасываем вызовы от инициализации
        widget_setter.reset_mock()

        # Устанавливаем то же значение
        observable.set("same")

        # Виджет не должен быть обновлен
        widget_setter.assert_not_called()

    def test_unbind_stops_model_updates(self) -> None:
        """Тест: unbind() останавливает обновления виджета при изменении модели."""
        observable = ObservableValue("initial")
        widget_getter = MagicMock(return_value="initial")
        widget_setter = MagicMock()

        binding = TwoWayBinding(observable, widget_getter, widget_setter)

        # Отвязываемся от модели
        binding.unbind()

        # Сбрасываем мок
        widget_setter.reset_mock()

        # Меняем модель
        observable.set("new")

        # Виджет не должен обновиться
        widget_setter.assert_not_called()

    def test_with_real_tk_entry(self, tk_app: tk.Tk) -> None:
        """Тест: интеграция с реальным Tkinter Entry."""
        entry = tk.Entry(tk_app)
        entry.insert(0, "initial")

        observable = ObservableValue("initial")

        def widget_getter() -> str:
            return entry.get()

        def widget_setter(value: str) -> None:
            entry.delete(0, tk.END)
            entry.insert(0, value)

        binding = TwoWayBinding(observable, widget_getter, widget_setter)

        # Синхронизация виджет -> модель
        entry.delete(0, tk.END)
        entry.insert(0, "from_widget")
        result = binding.sync_to_model()

        assert result is True
        assert observable.get() == "from_widget"

        # Синхронизация модель -> виджет
        observable.set("from_model")
        assert entry.get() == "from_model"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestObservableValue",
    "TestBinding",
    "TestTwoWayBinding",
]
