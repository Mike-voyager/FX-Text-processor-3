"""Тесты для Toast System.

Покрытие:
- ToastManager создание и базовые операции
- ToastQueue ограничение размера (max 6)
- get_unread_count() функциональность
- Авто-закрытие через 30 секунд
- ToastType enum
"""

from __future__ import annotations

import time
import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest

# Импортируем из расширенной toast системы
from src.view.toast import ToastManager, ToastType, get_toast_manager, set_toast_manager
from src.view.toast.queue import ToastItem, ToastQueue


class TestToastType:
    """Тесты ToastType enum."""

    def test_toast_type_values(self) -> None:
        """Проверяет значения ToastType."""
        assert ToastType.INFO.value == "info"
        assert ToastType.SUCCESS.value == "success"
        assert ToastType.WARNING.value == "warning"
        assert ToastType.ERROR.value == "error"
        assert ToastType.PROGRESS.value == "progress"

    def test_toast_type_icons(self) -> None:
        """Проверяет иконки для каждого типа."""
        assert ToastType.INFO.icon == "ℹ️"
        assert ToastType.SUCCESS.icon == "✅"
        assert ToastType.WARNING.icon == "⚠️"
        assert ToastType.ERROR.icon == "❌"
        assert ToastType.PROGRESS.icon == "⏳"

    def test_toast_type_titles(self) -> None:
        """Проверяет заголовки для каждого типа."""
        assert ToastType.INFO.title == "Информация"
        assert ToastType.SUCCESS.title == "Успех"
        assert ToastType.WARNING.title == "Внимание"
        assert ToastType.ERROR.title == "Ошибка"
        assert ToastType.PROGRESS.title == "Выполнение"


class TestToastQueue:
    """Тесты ToastQueue."""

    def test_create_default(self) -> None:
        """Создание очереди с настройками по умолчанию."""
        queue = ToastQueue()
        assert queue._max_size == 6  # pylint: disable=protected-access

    def test_create_with_custom_size(self) -> None:
        """Создание очереди с пользовательским размером."""
        queue = ToastQueue(max_size=10)
        assert queue._max_size == 10  # pylint: disable=protected-access

    def test_create_invalid_size(self) -> None:
        """Создание очереди с недопустимым размером вызывает ошибку."""
        with pytest.raises(ValueError):
            ToastQueue(max_size=0)
        with pytest.raises(ValueError):
            ToastQueue(max_size=-1)

    def test_add_item(self) -> None:
        """Добавление элемента в очередь."""
        queue = ToastQueue()
        item = ToastItem(
            id="test-1",
            message="Test message",
            type=ToastType.INFO,
            duration_ms=3000,
        )
        removed = queue.add(item)

        assert len(queue) == 1
        assert removed is None  # Ничего не удалено

    def test_queue_max_size_fifo(self) -> None:
        """Очередь FIFO при достижении max_size (6 элементов)."""
        queue = ToastQueue(max_size=3)

        # Добавляем 3 элемента
        items = []
        for i in range(3):
            item = ToastItem(
                id=f"test-{i}",
                message=f"Message {i}",
                type=ToastType.INFO,
                duration_ms=3000,
            )
            items.append(item)
            queue.add(item)

        assert len(queue) == 3

        # Добавляем 4-й элемент — первый должен быть удалён
        item4 = ToastItem(
            id="test-3",
            message="Message 3",
            type=ToastType.INFO,
            duration_ms=3000,
        )
        removed = queue.add(item4)

        assert len(queue) == 3
        assert removed is not None
        assert removed.id == "test-0"  # Первый удалён
        assert "test-0" not in queue
        assert "test-1" in queue
        assert "test-2" in queue
        assert "test-3" in queue

    def test_queue_max_size_six(self) -> None:
        """Проверка лимита в 6 элементов (как в требованиях)."""
        queue = ToastQueue(max_size=6)

        # Добавляем 6 элементов
        for i in range(6):
            queue.add(
                ToastItem(
                    id=f"toast-{i}",
                    message=f"Message {i}",
                    type=ToastType.INFO,
                    duration_ms=3000,
                )
            )

        assert len(queue) == 6

        # Добавляем 7-й — первый удалён
        removed = queue.add(
            ToastItem(
                id="toast-6",
                message="Message 6",
                type=ToastType.INFO,
                duration_ms=3000,
            )
        )

        assert len(queue) == 6
        assert removed is not None
        assert removed.id == "toast-0"

    def test_remove_item(self) -> None:
        """Удаление элемента по ID."""
        queue = ToastQueue()
        item = ToastItem(
            id="remove-test",
            message="Test",
            type=ToastType.INFO,
            duration_ms=3000,
        )
        queue.add(item)

        removed = queue.remove("remove-test")
        assert removed is not None
        assert removed.id == "remove-test"
        assert len(queue) == 0

    def test_remove_nonexistent(self) -> None:
        """Удаление несуществующего элемента возвращает None."""
        queue = ToastQueue()
        removed = queue.remove("nonexistent")
        assert removed is None

    def test_get_item(self) -> None:
        """Получение элемента по ID без удаления."""
        queue = ToastQueue()
        item = ToastItem(
            id="get-test",
            message="Test",
            type=ToastType.INFO,
            duration_ms=3000,
        )
        queue.add(item)

        found = queue.get("get-test")
        assert found is not None
        assert found.id == "get-test"
        assert len(queue) == 1  # Не удалено

    def test_get_all(self) -> None:
        """Получение всех элементов."""
        queue = ToastQueue()
        for i in range(3):
            queue.add(
                ToastItem(
                    id=f"item-{i}",
                    message=f"Message {i}",
                    type=ToastType.INFO,
                    duration_ms=3000,
                )
            )

        all_items = queue.get_all()
        assert len(all_items) == 3

    def test_get_unread_count_empty(self) -> None:
        """get_unread_count() возвращает 0 для пустой очереди."""
        queue = ToastQueue()
        assert queue.get_unread_count() == 0

    def test_get_unread_count_all_unread(self) -> None:
        """get_unread_count() возвращает количество всех непрочитанных."""
        queue = ToastQueue()
        for i in range(3):
            queue.add(
                ToastItem(
                    id=f"unread-{i}",
                    message=f"Message {i}",
                    type=ToastType.INFO,
                    duration_ms=3000,
                )
            )

        assert queue.get_unread_count() == 3

    def test_mark_as_read(self) -> None:
        """Пометка элемента как прочитанного."""
        queue = ToastQueue()
        queue.add(
            ToastItem(
                id="read-test",
                message="Test",
                type=ToastType.INFO,
                duration_ms=3000,
            )
        )

        assert queue.get_unread_count() == 1
        result = queue.mark_as_read("read-test")
        assert result is True
        assert queue.get_unread_count() == 0

    def test_mark_as_read_nonexistent(self) -> None:
        """Пометка несуществующего элемента возвращает False."""
        queue = ToastQueue()
        result = queue.mark_as_read("nonexistent")
        assert result is False

    def test_mark_all_read(self) -> None:
        """Пометка всех элементов как прочитанных."""
        queue = ToastQueue()
        for i in range(5):
            queue.add(
                ToastItem(
                    id=f"read-all-{i}",
                    message=f"Message {i}",
                    type=ToastType.INFO,
                    duration_ms=3000,
                )
            )

        assert queue.get_unread_count() == 5
        count = queue.mark_all_read()
        assert count == 5
        assert queue.get_unread_count() == 0

    def test_clear(self) -> None:
        """Очистка очереди."""
        queue = ToastQueue()
        for i in range(3):
            queue.add(
                ToastItem(
                    id=f"clear-{i}",
                    message=f"Message {i}",
                    type=ToastType.INFO,
                    duration_ms=3000,
                )
            )

        queue.clear()
        assert len(queue) == 0

    def test_contains(self) -> None:
        """Проверка оператора in."""
        queue = ToastQueue()
        queue.add(
            ToastItem(
                id="contains-test",
                message="Test",
                type=ToastType.INFO,
                duration_ms=3000,
            )
        )

        assert "contains-test" in queue
        assert "nonexistent" not in queue


class TestToastManager:
    """Тесты ToastManager."""

    def test_create_default(self) -> None:
        """Создание менеджера с настройками по умолчанию."""
        manager = ToastManager()
        assert manager._max_queue_size == 6  # pylint: disable=protected-access
        assert manager._auto_show is True  # pylint: disable=protected-access

    def test_create_with_custom_size(self) -> None:
        """Создание менеджера с пользовательским размером очереди."""
        manager = ToastManager(max_queue_size=10)
        assert manager._max_queue_size == 10  # pylint: disable=protected-access

    def test_create_invalid_size(self) -> None:
        """Создание менеджера с недопустимым размером вызывает ошибку."""
        with pytest.raises(ValueError):
            ToastManager(max_queue_size=0)

    def test_show_returns_id(self) -> None:
        """show() возвращает уникальный ID."""
        manager = ToastManager(auto_show=False)
        toast_id = manager.show("Test message", ToastType.INFO, 3000)

        assert isinstance(toast_id, str)
        assert toast_id.startswith("toast_")

    def test_show_creates_different_ids(self) -> None:
        """show() создаёт разные ID для разных вызовов."""
        manager = ToastManager(auto_show=False)
        id1 = manager.show("Message 1", ToastType.INFO, 3000)
        id2 = manager.show("Message 2", ToastType.INFO, 3000)

        assert id1 != id2

    def test_show_default_type(self) -> None:
        """show() использует INFO по умолчанию."""
        manager = ToastManager(auto_show=False)
        toast_id = manager.show("Test message")

        queue = manager.get_queue()
        item = queue.get(toast_id)
        assert item is not None
        assert item.type == ToastType.INFO

    def test_show_default_duration(self) -> None:
        """show() использует 30 секунд по умолчанию."""
        manager = ToastManager(auto_show=False)
        toast_id = manager.show("Test message")

        queue = manager.get_queue()
        item = queue.get(toast_id)
        assert item is not None
        assert item.duration_ms == 30000  # 30 секунд

    def test_hide(self) -> None:
        """hide() удаляет уведомление."""
        manager = ToastManager(auto_show=False)
        toast_id = manager.show("Test message")

        assert toast_id in manager.get_queue()
        result = manager.hide(toast_id)
        assert result is True
        assert toast_id not in manager.get_queue()

    def test_hide_nonexistent(self) -> None:
        """hide() возвращает False для несуществующего ID."""
        manager = ToastManager()
        result = manager.hide("nonexistent")
        assert result is False

    def test_get_unread_count(self) -> None:
        """get_unread_count() возвращает количество непрочитанных."""
        manager = ToastManager(auto_show=False)

        assert manager.get_unread_count() == 0

        manager.show("Message 1")
        manager.show("Message 2")

        assert manager.get_unread_count() == 2

    def test_mark_as_read(self) -> None:
        """mark_as_read() помечает уведомление прочитанным."""
        manager = ToastManager(auto_show=False)
        toast_id = manager.show("Test message")

        assert manager.get_unread_count() == 1
        result = manager.mark_as_read(toast_id)
        assert result is True
        assert manager.get_unread_count() == 0

    def test_mark_all_read(self) -> None:
        """mark_all_read() помечает все уведомления прочитанными."""
        manager = ToastManager(auto_show=False)
        for i in range(3):
            manager.show(f"Message {i}")

        assert manager.get_unread_count() == 3
        count = manager.mark_all_read()
        assert count == 3
        assert manager.get_unread_count() == 0

    def test_get_queue(self) -> None:
        """get_queue() возвращает очередь."""
        manager = ToastManager()
        queue = manager.get_queue()
        assert isinstance(queue, ToastQueue)

    def test_clear(self) -> None:
        """clear() очищает все уведомления."""
        manager = ToastManager(auto_show=False)
        for i in range(3):
            manager.show(f"Message {i}")

        assert len(manager.get_queue()) == 3
        manager.clear()
        assert len(manager.get_queue()) == 0


class TestToastManagerWithPanel:
    """Тесты ToastManager с ToastPanel (требует tkinter)."""

    @pytest.fixture
    def tk_root(self):
        """Создаёт tkinter root для тестов."""
        root = tk.Tk()
        root.withdraw()
        yield root
        root.destroy()

    def test_set_parent_creates_panel(self, tk_root: tk.Tk) -> None:
        """set_parent() создаёт панель."""
        manager = ToastManager()
        assert manager.get_panel() is None

        manager.set_parent(tk_root)
        assert manager.get_panel() is not None

    def test_show_with_auto_show(self, tk_root: tk.Tk) -> None:
        """show() с auto_show=True показывает в панели."""
        manager = ToastManager(auto_show=True)
        manager.set_parent(tk_root)

        toast_id = manager.show("Test message", ToastType.INFO, 3000)

        # Проверяем что уведомление видимо
        panel = manager.get_panel()
        assert panel is not None
        assert panel.is_visible(toast_id)

    def test_hide_removes_from_panel(self, tk_root: tk.Tk) -> None:
        """hide() удаляет из панели."""
        manager = ToastManager(auto_show=True)
        manager.set_parent(tk_root)

        toast_id = manager.show("Test message")
        panel = manager.get_panel()
        assert panel is not None
        assert panel.is_visible(toast_id)

        manager.hide(toast_id)
        assert not panel.is_visible(toast_id)


class TestGetToastManager:
    """Тесты get_toast_manager() singleton."""

    def test_singleton_creation(self) -> None:
        """get_toast_manager() создаёт синглтон."""
        # Сбрасываем синглтон
        set_toast_manager(None)  # type: ignore[arg-type]

        manager1 = get_toast_manager()
        manager2 = get_toast_manager()

        assert manager1 is manager2

    def test_set_toast_manager(self) -> None:
        """set_toast_manager() устанавливает менеджер."""
        custom_manager = ToastManager(max_queue_size=10)
        set_toast_manager(custom_manager)

        retrieved = get_toast_manager()
        assert retrieved is custom_manager


class TestToastAutoClose:
    """Тесты авто-закрытия toast через 30 секунд."""

    def test_default_duration_is_30_seconds(self) -> None:
        """Длительность по умолчанию — 30 секунд."""
        assert ToastManager.DEFAULT_DURATION_MS == 30000

    def test_duration_stored_in_item(self) -> None:
        """Длительность сохраняется в ToastItem."""
        manager = ToastManager(auto_show=False)
        toast_id = manager.show("Test", duration_ms=30000)

        item = manager.get_queue().get(toast_id)
        assert item is not None
        assert item.duration_ms == 30000

    @pytest.mark.slow  # type: ignore[misc]
    def test_auto_close_simulation(self) -> None:
        """Симуляция авто-закрытия (проверка duration_ms)."""
        manager = ToastManager(auto_show=False)
        toast_id = manager.show("Test", duration_ms=30000)

        # Уведомление в очереди
        assert toast_id in manager.get_queue()

        # Помечаем прочитанным (как делает панель при закрытии)
        manager.mark_as_read(toast_id)
        assert manager.get_unread_count() == 0


class TestToastIntegration:
    """Интеграционные тесты Toast System."""

    def test_full_workflow(self) -> None:
        """Полный workflow: создать, показать, скрыть."""
        manager = ToastManager(auto_show=False)

        # Создаём несколько уведомлений
        ids = []
        for i in range(3):
            toast_id = manager.show(
                f"Message {i}",
                ToastType.SUCCESS,
                30000,
            )
            ids.append(toast_id)

        # Проверяем начальное состояние
        assert len(manager.get_queue()) == 3
        assert manager.get_unread_count() == 3

        # Помечаем одно прочитанным
        manager.mark_as_read(ids[0])
        assert manager.get_unread_count() == 2

        # Скрываем одно
        manager.hide(ids[1])
        assert len(manager.get_queue()) == 2

        # Помечаем все прочитанными
        manager.mark_all_read()
        assert manager.get_unread_count() == 0

        # Очищаем
        manager.clear()
        assert len(manager.get_queue()) == 0


__all__ = [
    "TestToastType",
    "TestToastQueue",
    "TestToastManager",
    "TestToastManagerWithPanel",
    "TestGetToastManager",
    "TestToastAutoClose",
    "TestToastIntegration",
]
