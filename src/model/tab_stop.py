"""Модель табуляторов для FX Text Processor 3.

Предоставляет перечисление типов табуляторов и неизменяемую
дата-класс для представления позиции табуляции в документе.

See Also:
    - src/model/tab_stop_manager.py: управление табуляторами на уровне документа
    - src/model/enums.py: связанные перечисления (TabAlignment)

Attributes:
    TabStopType: Типы табуляторов (LEFT, RIGHT, CENTER, DECIMAL).
    TabStop: Дата-класс для позиции и типа табулятора.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Final


class TabStopType(Enum):
    """Тип табулятора для выравнивания текста.

    Табуляторы определяют позицию выравнивания текста в абзаце.
    Каждый тип имеет свое поведение при форматировании:

    - LEFT: Текст выравнивается по левому краю (⏵)
    - RIGHT: Текст выравнивается по правому краю (⏴)
    - CENTER: Текст центрируется относительно позиции (⏵⏴)
    - DECIMAL: Числа выравниваются по десятичной точке (⏵·)

    Examples:
        >>> tab_type = TabStopType.LEFT
        >>> print(tab_type)
        TabStopType.LEFT
        >>> tab_type.name
        'LEFT'
    """

    LEFT = auto()  # ⏵ Левый табулятор
    RIGHT = auto()  # ⏴ Правый табулятор
    CENTER = auto()  # ⏵⏴ Центрирующий табулятор
    DECIMAL = auto()  # ⏵· Десятичный табулятор


def _validate_position(position: int) -> None:
    """Валидирует позицию табулятора.

    Args:
        position: Проверяемая позиция.

    Raises:
        ValueError: Если позиция меньше 1.
        TypeError: Если позиция не является целым числом.
    """
    if not isinstance(position, int):
        raise TypeError(f"Position must be int, got {type(position).__name__}")
    if position < 1:
        raise ValueError(f"Position must be >= 1, got {position}")


@dataclass(frozen=True, slots=True)
class TabStop:
    """Позиция табулятора в документе.

    Неизменяемый дата-класс, представляющий табулятор с заданной
    позицией и типом выравнивания. Позиция задается в символах (1-based).

    Attributes:
        position: Позиция табулятора в символах (>= 1).
        tab_type: Тип табулятора (LEFT, RIGHT, CENTER, DECIMAL).

    Raises:
        ValueError: При создании с position < 1.
        TypeError: При создании с нецелочисленной позицией.

    Examples:
        >>> tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        >>> tab.position
        10
        >>> tab.tab_type
        <TabStopType.LEFT: ...>
        >>> tab == TabStop(10, TabStopType.LEFT)
        True
    """

    position: int  # Позиция в символах (1-based)
    tab_type: TabStopType

    def __post_init__(self) -> None:
        """Валидация после инициализации.

        Проверяет, что позиция табулятора является положительным
        целым числом (>= 1).
        """
        _validate_position(self.position)

    def __lt__(self, other: object) -> bool:
        """Сравнение по позиции для сортировки.

        Args:
            other: Другой TabStop для сравнения.

        Returns:
            True если позиция self меньше позиции other.

        Raises:
            TypeError: Если other не является TabStop.
        """
        if not isinstance(other, TabStop):
            return NotImplemented
        return self.position < other.position

    def __le__(self, other: object) -> bool:
        """Меньше или равно по позиции.

        Args:
            other: Другой TabStop для сравнения.

        Returns:
            True если позиция self <= позиции other.
        """
        if not isinstance(other, TabStop):
            return NotImplemented
        return self.position <= other.position

    def __gt__(self, other: object) -> bool:
        """Больше по позиции.

        Args:
            other: Другой TabStop для сравнения.

        Returns:
            True если позиция self > позиции other.
        """
        if not isinstance(other, TabStop):
            return NotImplemented
        return self.position > other.position

    def __ge__(self, other: object) -> bool:
        """Больше или равно по позиции.

        Args:
            other: Другой TabStop для сравнения.

        Returns:
            True если позиция self >= позиции other.
        """
        if not isinstance(other, TabStop):
            return NotImplemented
        return self.position >= other.position

    def __repr__(self) -> str:
        """Строковое представление для отладки.

        Returns:
            Строка вида 'TabStop(position=10, tab_type=TabStopType.LEFT)'.
        """
        return f"TabStop(position={self.position}, tab_type={self.tab_type})"

    def to_dict(self) -> dict[str, int | str]:
        """Сериализация в словарь.

        Returns:
            Словарь с ключами 'position' и 'tab_type'.

        Examples:
            >>> tab = TabStop(10, TabStopType.LEFT)
            >>> tab.to_dict()
            {'position': 10, 'tab_type': 'LEFT'}
        """
        return {
            "position": self.position,
            "tab_type": self.tab_type.name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, int | str]) -> "TabStop":
        """Десериализация из словаря.

        Args:
            data: Словарь с ключами 'position' и 'tab_type'.

        Returns:
            Новый экземпляр TabStop.

        Raises:
            KeyError: Если отсутствуют обязательные ключи.
            ValueError: Если тип табулятора не существует.
        """
        tab_type_name = data.get("tab_type")
        if not isinstance(tab_type_name, str):
            raise TypeError(f"tab_type must be str, got {type(tab_type_name).__name__}")
        try:
            tab_type = TabStopType[tab_type_name]
        except KeyError as e:
            raise ValueError(f"Invalid TabStopType: {tab_type_name}") from e

        position = data.get("position")
        if not isinstance(position, int):
            raise TypeError(f"position must be int, got {type(position).__name__}")

        return cls(position=position, tab_type=tab_type)


# Экспортируемые символы
__all__: Final[list[str]] = [
    "TabStopType",
    "TabStop",
]
