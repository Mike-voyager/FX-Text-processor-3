"""Тесты для модуля tab_stop.py.

Покрытие тестами:
- TabStopType enum
- TabStop dataclass (создание, валидация, сравнение, сериализация)
- Граничные случаи и ошибки

Coverage target: >=90%
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from src.model.tab_stop import TabStop, TabStopType


# ========== TabStopType Tests ==========


class TestTabStopType:
    """Тесты для перечисления TabStopType."""

    def test_tab_stop_type_values(self) -> None:
        """Проверяет наличие всех типов табуляторов."""
        assert TabStopType.LEFT is not None
        assert TabStopType.RIGHT is not None
        assert TabStopType.CENTER is not None
        assert TabStopType.DECIMAL is not None

    def test_tab_stop_type_auto_values(self) -> None:
        """Проверяет авто-значения перечисления."""
        # auto() создает уникальные значения
        values = {t.value for t in TabStopType}
        assert len(values) == 4  # Все уникальны

    def test_tab_stop_type_iteration(self) -> None:
        """Проверяет итерацию по перечислению."""
        types = list(TabStopType)
        assert len(types) == 4
        assert TabStopType.LEFT in types
        assert TabStopType.RIGHT in types
        assert TabStopType.CENTER in types
        assert TabStopType.DECIMAL in types

    def test_tab_stop_type_name_access(self) -> None:
        """Проверяет доступ по имени."""
        assert TabStopType["LEFT"] == TabStopType.LEFT
        assert TabStopType["RIGHT"] == TabStopType.RIGHT
        assert TabStopType["CENTER"] == TabStopType.CENTER
        assert TabStopType["DECIMAL"] == TabStopType.DECIMAL


# ========== TabStop Creation Tests ==========


class TestTabStopCreation:
    """Тесты создания TabStop с валидацией."""

    def test_create_valid_tab_stop(self) -> None:
        """Создание валидного табулятора."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        assert tab.position == 10
        assert tab.tab_type == TabStopType.LEFT

    def test_create_tab_stop_at_minimum_position(self) -> None:
        """Создание табулятора в минимальной позиции (1)."""
        tab = TabStop(position=1, tab_type=TabStopType.LEFT)
        assert tab.position == 1

    def test_create_tab_stop_all_types(self) -> None:
        """Создание табуляторов всех типов."""
        for tab_type in TabStopType:
            tab = TabStop(position=10, tab_type=tab_type)
            assert tab.tab_type == tab_type

    def test_create_tab_stop_large_position(self) -> None:
        """Создание табулятора с большой позицией."""
        tab = TabStop(position=999999, tab_type=TabStopType.RIGHT)
        assert tab.position == 999999


# ========== TabStop Validation Tests ==========


class TestTabStopValidation:
    """Тесты валидации позиции табулятора."""

    def test_invalid_position_zero(self) -> None:
        """Ошибка при позиции 0."""
        with pytest.raises(ValueError, match="Position must be >= 1"):
            TabStop(position=0, tab_type=TabStopType.LEFT)

    def test_invalid_position_negative(self) -> None:
        """Ошибка при отрицательной позиции."""
        with pytest.raises(ValueError, match="Position must be >= 1"):
            TabStop(position=-5, tab_type=TabStopType.LEFT)

    def test_invalid_position_negative_large(self) -> None:
        """Ошибка при большой отрицательной позиции."""
        with pytest.raises(ValueError, match="Position must be >= 1"):
            TabStop(position=-1000, tab_type=TabStopType.LEFT)

    def test_invalid_position_float(self) -> None:
        """Ошибка при float позиции."""
        with pytest.raises(TypeError, match="Position must be int"):
            TabStop(position=10.5, tab_type=TabStopType.LEFT)  # type: ignore

    def test_invalid_position_string(self) -> None:
        """Ошибка при string позиции."""
        with pytest.raises(TypeError, match="Position must be int"):
            TabStop(position="10", tab_type=TabStopType.LEFT)  # type: ignore

    def test_invalid_position_none(self) -> None:
        """Ошибка при None позиции."""
        with pytest.raises(TypeError, match="Position must be int"):
            TabStop(position=None, tab_type=TabStopType.LEFT)  # type: ignore


# ========== TabStop Immutability Tests ==========


class TestTabStopImmutability:
    """Тесты неизменяемости frozen dataclass."""

    def test_frozen_position(self) -> None:
        """Невозможность изменить position."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        with pytest.raises(FrozenInstanceError):
            tab.position = 20  # type: ignore

    def test_frozen_tab_type(self) -> None:
        """Невозможность изменить tab_type."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        with pytest.raises(FrozenInstanceError):
            tab.tab_type = TabStopType.RIGHT  # type: ignore


# ========== TabStop Comparison Tests ==========


class TestTabStopComparison:
    """Тесты сравнения табуляторов."""

    def test_equality_same_values(self) -> None:
        """Равенство при одинаковых значениях."""
        tab1 = TabStop(position=10, tab_type=TabStopType.LEFT)
        tab2 = TabStop(position=10, tab_type=TabStopType.LEFT)
        assert tab1 == tab2
        assert hash(tab1) == hash(tab2)

    def test_inequality_different_position(self) -> None:
        """Неравенство при разных позициях."""
        tab1 = TabStop(position=10, tab_type=TabStopType.LEFT)
        tab2 = TabStop(position=20, tab_type=TabStopType.LEFT)
        assert tab1 != tab2

    def test_inequality_different_type(self) -> None:
        """Неравенство при разных типах."""
        tab1 = TabStop(position=10, tab_type=TabStopType.LEFT)
        tab2 = TabStop(position=10, tab_type=TabStopType.RIGHT)
        assert tab1 != tab2

    def test_less_than_by_position(self) -> None:
        """Сравнение по позиции (<)."""
        tab1 = TabStop(position=10, tab_type=TabStopType.LEFT)
        tab2 = TabStop(position=20, tab_type=TabStopType.LEFT)
        assert tab1 < tab2
        assert not (tab2 < tab1)

    def test_less_equal_by_position(self) -> None:
        """Сравнение по позиции (<=)."""
        tab1 = TabStop(position=10, tab_type=TabStopType.LEFT)
        tab2 = TabStop(position=20, tab_type=TabStopType.LEFT)
        tab3 = TabStop(position=10, tab_type=TabStopType.RIGHT)
        assert tab1 <= tab2
        assert tab1 <= tab3  # Равны по позиции

    def test_greater_than_by_position(self) -> None:
        """Сравнение по позиции (>)."""
        tab1 = TabStop(position=10, tab_type=TabStopType.LEFT)
        tab2 = TabStop(position=20, tab_type=TabStopType.LEFT)
        assert tab2 > tab1
        assert not (tab1 > tab2)

    def test_greater_equal_by_position(self) -> None:
        """Сравнение по позиции (>=)."""
        tab1 = TabStop(position=10, tab_type=TabStopType.LEFT)
        tab2 = TabStop(position=20, tab_type=TabStopType.LEFT)
        tab3 = TabStop(position=10, tab_type=TabStopType.RIGHT)
        assert tab2 >= tab1
        assert tab1 >= tab3  # Равны по позиции

    def test_comparison_with_non_tabstop(self) -> None:
        """Сравнение с не-TabStop возвращает NotImplemented."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        assert tab.__lt__(5) is NotImplemented
        assert tab.__le__(5) is NotImplemented
        assert tab.__gt__(5) is NotImplemented
        assert tab.__ge__(5) is NotImplemented


# ========== TabStop Sorting Tests ==========


class TestTabStopSorting:
    """Тесты сортировки табуляторов."""

    def test_sort_by_position(self) -> None:
        """Сортировка по позиции."""
        tabs = [
            TabStop(position=30, tab_type=TabStopType.LEFT),
            TabStop(position=10, tab_type=TabStopType.CENTER),
            TabStop(position=20, tab_type=TabStopType.RIGHT),
        ]
        sorted_tabs = sorted(tabs)
        assert [t.position for t in sorted_tabs] == [10, 20, 30]

    def test_sort_already_sorted(self) -> None:
        """Сортировка уже отсортированного списка."""
        tabs = [
            TabStop(position=10, tab_type=TabStopType.LEFT),
            TabStop(position=20, tab_type=TabStopType.RIGHT),
        ]
        sorted_tabs = sorted(tabs)
        assert [t.position for t in sorted_tabs] == [10, 20]


# ========== TabStop Serialization Tests ==========


class TestTabStopSerialization:
    """Тесты сериализации/десериализации."""

    def test_to_dict(self) -> None:
        """Сериализация в словарь."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        data = tab.to_dict()
        assert data == {"position": 10, "tab_type": "LEFT"}

    def test_to_dict_all_types(self) -> None:
        """Сериализация всех типов."""
        for tab_type in TabStopType:
            tab = TabStop(position=10, tab_type=tab_type)
            data = tab.to_dict()
            assert data["tab_type"] == tab_type.name
            assert data["position"] == 10

    def test_from_dict(self) -> None:
        """Десериализация из словаря."""
        data = {"position": 10, "tab_type": "LEFT"}
        tab = TabStop.from_dict(data)
        assert tab.position == 10
        assert tab.tab_type == TabStopType.LEFT

    def test_from_dict_all_types(self) -> None:
        """Десериализация всех типов."""
        for tab_type in TabStopType:
            data = {"position": 10, "tab_type": tab_type.name}
            tab = TabStop.from_dict(data)
            assert tab.tab_type == tab_type

    def test_round_trip(self) -> None:
        """Круговая сериализация."""
        original = TabStop(position=25, tab_type=TabStopType.DECIMAL)
        data = original.to_dict()
        restored = TabStop.from_dict(data)
        assert original == restored

    def test_from_dict_missing_position(self) -> None:
        """Ошибка при отсутствии position."""
        data: dict[str, str] = {"tab_type": "LEFT"}
        with pytest.raises((KeyError, TypeError)):
            TabStop.from_dict(data)  # type: ignore

    def test_from_dict_missing_tab_type(self) -> None:
        """Ошибка при отсутствии tab_type."""
        data: dict[str, int] = {"position": 10}
        with pytest.raises((KeyError, TypeError)):
            TabStop.from_dict(data)  # type: ignore

    def test_from_dict_invalid_tab_type(self) -> None:
        """Ошибка при невалидном tab_type."""
        data = {"position": 10, "tab_type": "INVALID"}
        with pytest.raises(ValueError, match="Invalid TabStopType"):
            TabStop.from_dict(data)

    def test_from_dict_invalid_position_type(self) -> None:
        """Ошибка при невалидном типе position."""
        data = {"position": "10", "tab_type": "LEFT"}
        with pytest.raises(TypeError, match="position must be int"):
            TabStop.from_dict(data)

    def test_from_dict_invalid_tab_type_type(self) -> None:
        """Ошибка при невалидном типе tab_type."""
        data = {"position": 10, "tab_type": 123}
        with pytest.raises(TypeError, match="tab_type must be str"):
            TabStop.from_dict(data)


# ========== TabStop Representation Tests ==========


class TestTabStopRepresentation:
    """Тесты строкового представления."""

    def test_repr(self) -> None:
        """Строковое представление для отладки."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        repr_str = repr(tab)
        assert "TabStop" in repr_str
        assert "position=10" in repr_str
        assert "tab_type=" in repr_str

    def test_repr_contains_values(self) -> None:
        """repr содержит значения полей."""
        tab = TabStop(position=25, tab_type=TabStopType.DECIMAL)
        repr_str = repr(tab)
        assert "25" in repr_str
        assert "DECIMAL" in repr_str


# ========== Slots Memory Tests ==========


class TestTabStopSlots:
    """Тесты для __slots__ оптимизации."""

    def test_no_dict(self) -> None:
        """Проверяет отсутствие __dict__ из-за slots."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        assert not hasattr(tab, "__dict__")

    def test_slots_attributes(self) -> None:
        """Проверяет что slots содержит ожидаемые атрибуты."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        assert hasattr(tab, "position")
        assert hasattr(tab, "tab_type")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
