"""Тесты для модуля tab_stop_manager.py.

Покрытие тестами:
- Создание менеджера
- Добавление, удаление, перемещение табуляторов
- Граничные случаи и ошибки
- Потокобезопасность
- Итерация и проверка наличия

Coverage target: >=90%
"""

from __future__ import annotations

import threading
from typing import List

import pytest

from src.model.tab_stop import TabStop, TabStopType
from src.model.tab_stop_manager import TabStopManager


# ========== Manager Creation Tests ==========


class TestTabStopManagerCreation:
    """Тесты создания менеджера табуляторов."""

    def test_create_empty_manager(self) -> None:
        """Создание пустого менеджера."""
        manager = TabStopManager()
        assert manager.count() == 0
        assert manager.get_tabs() == []

    def test_manager_isolation(self) -> None:
        """Независимость разных менеджеров."""
        manager1 = TabStopManager()
        manager2 = TabStopManager()
        manager1.add_tab(10, TabStopType.LEFT)
        assert manager1.count() == 1
        assert manager2.count() == 0


# ========== Add Tab Tests ==========


class TestAddTab:
    """Тесты добавления табуляторов."""

    def test_add_single_tab(self) -> None:
        """Добавление одного табулятора."""
        manager = TabStopManager()
        tab = manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None
        assert tab.position == 10
        assert tab.tab_type == TabStopType.LEFT
        assert manager.count() == 1

    def test_add_multiple_tabs(self) -> None:
        """Добавление нескольких табуляторов."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)
        manager.add_tab(30, TabStopType.CENTER)
        assert manager.count() == 3

    def test_add_all_types(self) -> None:
        """Добавление табуляторов всех типов."""
        manager = TabStopManager()
        for i, tab_type in enumerate(TabStopType):
            tab = manager.add_tab((i + 1) * 10, tab_type)
            assert tab is not None
            assert tab.tab_type == tab_type

    def test_add_tab_at_position_one(self) -> None:
        """Добавление в позицию 1."""
        manager = TabStopManager()
        tab = manager.add_tab(1, TabStopType.LEFT)
        assert tab is not None
        assert tab.position == 1

    def test_add_tab_duplicate_position(self) -> None:
        """Невозможность добавить дубликат позиции."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        duplicate = manager.add_tab(10, TabStopType.RIGHT)
        assert duplicate is None
        assert manager.count() == 1

    def test_add_tab_invalid_type(self) -> None:
        """Ошибка при невалидном типе табулятора."""
        manager = TabStopManager()
        with pytest.raises(TypeError, match="tab_type must be TabStopType"):
            manager.add_tab(10, "LEFT")  # type: ignore

    def test_add_tab_returns_frozen_instance(self) -> None:
        """Возвращаемый TabStop является неизменяемым."""
        manager = TabStopManager()
        tab = manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None
        with pytest.raises(AttributeError):
            tab.position = 20  # type: ignore


# ========== Remove Tab Tests ==========


class TestRemoveTab:
    """Тесты удаления табуляторов."""

    def test_remove_existing_tab(self) -> None:
        """Удаление существующего табулятора."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        removed = manager.remove_tab(10)
        assert removed is True
        assert manager.count() == 0

    def test_remove_nonexistent_tab(self) -> None:
        """Удаление несуществующего табулятора."""
        manager = TabStopManager()
        removed = manager.remove_tab(10)
        assert removed is False

    def test_remove_from_empty_manager(self) -> None:
        """Удаление из пустого менеджера."""
        manager = TabStopManager()
        removed = manager.remove_tab(10)
        assert removed is False

    def test_remove_specific_position(self) -> None:
        """Удаление табулятора на конкретной позиции."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)
        manager.add_tab(30, TabStopType.CENTER)
        manager.remove_tab(20)
        assert manager.count() == 2
        assert manager.get_tab_at(20) is None
        assert manager.get_tab_at(10) is not None
        assert manager.get_tab_at(30) is not None


# ========== Move Tab Tests ==========


class TestMoveTab:
    """Тесты перемещения табуляторов."""

    def test_move_tab_success(self) -> None:
        """Успешное перемещение табулятора."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        moved = manager.move_tab(10, 20)
        assert moved is not None
        assert moved.position == 20
        assert moved.tab_type == TabStopType.LEFT
        assert manager.has_tab_at(10) is False
        assert manager.has_tab_at(20) is True

    def test_move_tab_same_position(self) -> None:
        """Перемещение на ту же позицию возвращает None."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        moved = manager.move_tab(10, 10)
        assert moved is None
        assert manager.has_tab_at(10) is True

    def test_move_tab_nonexistent(self) -> None:
        """Перемещение несуществующего табулятора."""
        manager = TabStopManager()
        moved = manager.move_tab(10, 20)
        assert moved is None

    def test_move_tab_to_occupied_position(self) -> None:
        """Перемещение на занятую позицию."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)
        moved = manager.move_tab(10, 20)
        assert moved is None
        # Оригинальный табулятор должен остаться на месте
        assert manager.has_tab_at(10) is True

    def test_move_tab_preserves_type(self) -> None:
        """Перемещение сохраняет тип табулятора."""
        manager = TabStopManager()
        for tab_type in TabStopType:
            manager.clear()
            manager.add_tab(10, tab_type)
            moved = manager.move_tab(10, 20)
            assert moved is not None
            assert moved.tab_type == tab_type

    def test_move_tab_to_position_one(self) -> None:
        """Перемещение в позицию 1."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        moved = manager.move_tab(10, 1)
        assert moved is not None
        assert moved.position == 1

    def test_move_tab_invalid_new_position(self) -> None:
        """Ошибка при невалидной новой позиции."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        with pytest.raises(ValueError, match="Position must be >= 1"):
            manager.move_tab(10, 0)


# ========== Get Tabs Tests ==========


class TestGetTabs:
    """Тесты получения списка табуляторов."""

    def test_get_tabs_empty(self) -> None:
        """Список пустого менеджера."""
        manager = TabStopManager()
        assert manager.get_tabs() == []

    def test_get_tabs_sorted(self) -> None:
        """Табуляторы возвращаются отсортированными."""
        manager = TabStopManager()
        manager.add_tab(30, TabStopType.LEFT)
        manager.add_tab(10, TabStopType.RIGHT)
        manager.add_tab(20, TabStopType.CENTER)
        tabs = manager.get_tabs()
        assert [t.position for t in tabs] == [10, 20, 30]

    def test_get_tabs_returns_copy(self) -> None:
        """Возвращается копия списка."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        tabs1 = manager.get_tabs()
        tabs2 = manager.get_tabs()
        assert tabs1 is not tabs2
        assert tabs1 == tabs2


# ========== Get Tab At Tests ==========


class TestGetTabAt:
    """Тесты получения табулятора по позиции."""

    def test_get_tab_at_existing(self) -> None:
        """Получение существующего табулятора."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        tab = manager.get_tab_at(10)
        assert tab is not None
        assert tab.position == 10

    def test_get_tab_at_nonexistent(self) -> None:
        """Получение несуществующего табулятора."""
        manager = TabStopManager()
        tab = manager.get_tab_at(10)
        assert tab is None

    def test_get_tab_at_returns_frozen(self) -> None:
        """Возвращаемый TabStop неизменяем."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        tab = manager.get_tab_at(10)
        with pytest.raises(AttributeError):
            tab.position = 20  # type: ignore


# ========== Has Tab At Tests ==========


class TestHasTabAt:
    """Тесты проверки наличия табулятора."""

    def test_has_tab_at_existing(self) -> None:
        """Проверка существующей позиции."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        assert manager.has_tab_at(10) is True

    def test_has_tab_at_nonexistent(self) -> None:
        """Проверка несуществующей позиции."""
        manager = TabStopManager()
        assert manager.has_tab_at(10) is False

    def test_has_tab_at_after_remove(self) -> None:
        """Проверка после удаления."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.remove_tab(10)
        assert manager.has_tab_at(10) is False


# ========== Clear Tests ==========


class TestClear:
    """Тесты очистки менеджера."""

    def test_clear_empty(self) -> None:
        """Очистка пустого менеджера."""
        manager = TabStopManager()
        manager.clear()
        assert manager.count() == 0

    def test_clear_with_tabs(self) -> None:
        """Очистка с табуляторами."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)
        manager.clear()
        assert manager.count() == 0
        assert manager.get_tabs() == []

    def test_clear_idempotent(self) -> None:
        """Повторная очистка без ошибок."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.clear()
        manager.clear()
        assert manager.count() == 0


# ========== Count and Len Tests ==========


class TestCount:
    """Тесты подсчета табуляторов."""

    def test_count_empty(self) -> None:
        """Подсчет в пустом менеджере."""
        manager = TabStopManager()
        assert manager.count() == 0
        assert len(manager) == 0

    def test_count_with_tabs(self) -> None:
        """Подсчет с табуляторами."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)
        assert manager.count() == 2
        assert len(manager) == 2

    def test_count_after_remove(self) -> None:
        """Подсчет после удаления."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)
        manager.remove_tab(10)
        assert manager.count() == 1


# ========== Contains Tests ==========


class TestContains:
    """Тесты оператора 'in'."""

    def test_contains_existing(self) -> None:
        """Проверка существующей позиции через 'in'."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        assert 10 in manager

    def test_contains_nonexistent(self) -> None:
        """Проверка несуществующей позиции."""
        manager = TabStopManager()
        assert 10 not in manager

    def test_contains_after_remove(self) -> None:
        """Проверка после удаления."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.remove_tab(10)
        assert 10 not in manager


# ========== Thread Safety Tests ==========


class TestThreadSafety:
    """Тесты потокобезопасности."""

    def test_concurrent_add(self) -> None:
        """Конкурентное добавление табуляторов."""
        manager = TabStopManager()
        num_threads = 10
        tabs_per_thread = 10
        errors: List[Exception] = []

        def add_tabs(thread_id: int) -> None:
            try:
                for i in range(tabs_per_thread):
                    pos = thread_id * tabs_per_thread + i + 1
                    manager.add_tab(pos, TabStopType.LEFT)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=add_tabs, args=(i,))
            for i in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert manager.count() == num_threads * tabs_per_thread

    def test_concurrent_remove(self) -> None:
        """Конкурентное удаление табуляторов."""
        manager = TabStopManager()
        # Добавляем табуляторы
        for i in range(100):
            manager.add_tab(i + 1, TabStopType.LEFT)

        errors: List[Exception] = []

        def remove_tabs(start: int) -> None:
            try:
                for i in range(start, start + 10):
                    manager.remove_tab(i + 1)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=remove_tabs, args=(i * 10,))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert manager.count() == 0

    def test_concurrent_mixed_operations(self) -> None:
        """Конкурентные смешанные операции."""
        manager = TabStopManager()
        errors: List[Exception] = []

        def worker(thread_id: int) -> None:
            try:
                for i in range(20):
                    pos = thread_id * 100 + i + 1
                    manager.add_tab(pos, TabStopType.LEFT)
                    manager.has_tab_at(pos)
                    manager.get_tab_at(pos)
                    if i % 2 == 0:
                        manager.remove_tab(pos)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# ========== Repr Tests ==========


class TestRepr:
    """Тесты строкового представления."""

    def test_repr_empty(self) -> None:
        """repr пустого менеджера."""
        manager = TabStopManager()
        repr_str = repr(manager)
        assert "TabStopManager" in repr_str
        assert "count=0" in repr_str

    def test_repr_with_tabs(self) -> None:
        """repr менеджера с табуляторами."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)
        repr_str = repr(manager)
        assert "TabStopManager" in repr_str
        assert "count=2" in repr_str
        assert "10" in repr_str
        assert "20" in repr_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
