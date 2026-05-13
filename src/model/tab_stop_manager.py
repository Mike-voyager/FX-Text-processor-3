"""Менеджер табуляторов для FX Text Processor 3.

Предоставляет управление табуляторами на уровне документа.
Каждый документ имеет свой собственный экземпляр менеджера.

See Also:
    - src/model/tab_stop.py: модели табуляторов
    - src/model/paragraph.py: использование табуляторов в абзацах

Attributes:
    TabStopManager: Класс для управления коллекцией табуляторов.
"""

from __future__ import annotations

import threading
from typing import Final, Optional

from src.model.tab_stop import TabStop, TabStopType


class TabStopManager:
    """Менеджер табуляторов для документа.

    Управляет коллекцией табуляторов, обеспечивая:
    - Добавление табуляторов с проверкой на дубликаты
    - Удаление табуляторов по позиции
    - Перемещение табуляторов между позициями
    - Получение списка табуляторов (отсортированного)
    - Проверку наличия табулятора в позиции

    Потокобезопасность: все операции защищены блокировкой.

    Attributes:
        _tabs: Внутреннее хранилище табуляторов {position: TabStop}.
        _lock: Блокировка для потокобезопасности.

    Examples:
        >>> manager = TabStopManager()
        >>> tab = manager.add_tab(10, TabStopType.LEFT)
        >>> manager.has_tab_at(10)
        True
        >>> manager.get_tabs()
        [TabStop(position=10, tab_type=TabStopType.LEFT)]
    """

    def __init__(self) -> None:
        """Инициализирует пустой менеджер табуляторов."""
        self._tabs: dict[int, TabStop] = {}
        self._lock: threading.Lock = threading.Lock()

    def add_tab(self, position: int, tab_type: TabStopType) -> Optional[TabStop]:
        """Добавляет табулятор в указанной позиции.

        Args:
            position: Позиция табулятора в символах (>= 1).
            tab_type: Тип табулятора (LEFT, RIGHT, CENTER, DECIMAL).

        Returns:
            Созданный TabStop или None если позиция занята.

        Raises:
            ValueError: Если position < 1.
            TypeError: Если tab_type не является TabStopType.

        Examples:
            >>> manager = TabStopManager()
            >>> tab = manager.add_tab(10, TabStopType.LEFT)
            >>> tab is not None
            True
            >>> manager.add_tab(10, TabStopType.RIGHT)  # Дубликат
            None
        """
        if not isinstance(tab_type, TabStopType):
            raise TypeError(
                f"tab_type must be TabStopType, got {type(tab_type).__name__}"
            )

        with self._lock:
            if position in self._tabs:
                return None

            tab = TabStop(position=position, tab_type=tab_type)
            self._tabs[position] = tab
            return tab

    def remove_tab(self, position: int) -> bool:
        """Удаляет табулятор в указанной позиции.

        Args:
            position: Позиция табулятора для удаления.

        Returns:
            True если табулятор был удален, False если не найден.

        Examples:
            >>> manager = TabStopManager()
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> manager.remove_tab(10)
            True
            >>> manager.remove_tab(10)  # Уже удален
            False
        """
        with self._lock:
            if position in self._tabs:
                del self._tabs[position]
                return True
            return False

    def move_tab(self, old_pos: int, new_pos: int) -> Optional[TabStop]:
        """Перемещает табулятор с одной позиции на другую.

        Args:
            old_pos: Текущая позиция табулятора.
            new_pos: Новая позиция табулятора.

        Returns:
            Перемещенный TabStop с обновленной позицией или None если:
            - табулятор не найден в old_pos
            - new_pos занята другим табулятором
            - old_pos == new_pos (нет изменений)

        Raises:
            ValueError: Если new_pos < 1.

        Examples:
            >>> manager = TabStopManager()
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> moved = manager.move_tab(10, 20)
            >>> moved.position if moved else None
            20
            >>> manager.has_tab_at(10)
            False
            >>> manager.has_tab_at(20)
            True
        """
        if old_pos == new_pos:
            return None

        with self._lock:
            # Проверяем существование табулятора в old_pos
            if old_pos not in self._tabs:
                return None

            # Проверяем, что new_pos свободна
            if new_pos in self._tabs:
                return None

            # Получаем и удаляем старый табулятор
            tab = self._tabs.pop(old_pos)

            # Создаем новый табулятор с новой позицией
            new_tab = TabStop(position=new_pos, tab_type=tab.tab_type)
            self._tabs[new_pos] = new_tab
            return new_tab

    def get_tabs(self) -> list[TabStop]:
        """Возвращает список всех табуляторов, отсортированных по позиции.

        Returns:
            Список TabStop, отсортированный по возрастанию position.

        Examples:
            >>> manager = TabStopManager()
            >>> manager.add_tab(20, TabStopType.RIGHT)
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> tabs = manager.get_tabs()
            >>> [t.position for t in tabs]
            [10, 20]
        """
        with self._lock:
            return sorted(self._tabs.values(), key=lambda t: t.position)

    def get_tab_at(self, position: int) -> Optional[TabStop]:
        """Возвращает табулятор в указанной позиции.

        Args:
            position: Позиция для поиска.

        Returns:
            TabStop если найден, иначе None.

        Examples:
            >>> manager = TabStopManager()
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> manager.get_tab_at(10).tab_type
            <TabStopType.LEFT: ...>
            >>> manager.get_tab_at(20) is None
            True
        """
        with self._lock:
            return self._tabs.get(position)

    def clear(self) -> None:
        """Удаляет все табуляторы.

        Examples:
            >>> manager = TabStopManager()
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> manager.add_tab(20, TabStopType.RIGHT)
            >>> manager.clear()
            >>> manager.get_tabs()
            []
        """
        with self._lock:
            self._tabs.clear()

    def has_tab_at(self, position: int) -> bool:
        """Проверяет наличие табулятора в указанной позиции.

        Args:
            position: Позиция для проверки.

        Returns:
            True если табулятор существует в данной позиции.

        Examples:
            >>> manager = TabStopManager()
            >>> manager.has_tab_at(10)
            False
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> manager.has_tab_at(10)
            True
        """
        with self._lock:
            return position in self._tabs

    def count(self) -> int:
        """Возвращает количество табуляторов.

        Returns:
            Число табуляторов в менеджере.

        Examples:
            >>> manager = TabStopManager()
            >>> manager.count()
            0
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> manager.count()
            1
        """
        with self._lock:
            return len(self._tabs)

    def __len__(self) -> int:
        """Возвращает количество табуляторов.

        Returns:
            Число табуляторов в менеджере.
        """
        return self.count()

    def __contains__(self, position: int) -> bool:
        """Проверяет наличие табулятора через оператор 'in'.

        Args:
            position: Позиция для проверки.

        Returns:
            True если табулятор существует.

        Examples:
            >>> manager = TabStopManager()
            >>> 10 in manager
            False
            >>> manager.add_tab(10, TabStopType.LEFT)
            >>> 10 in manager
            True
        """
        return self.has_tab_at(position)

    def __repr__(self) -> str:
        """Строковое представление для отладки.

        Returns:
            Строка вида 'TabStopManager(count=N, tabs=[...])'.
        """
        with self._lock:
            tabs_str = ", ".join(repr(t) for t in sorted(
                self._tabs.values(), key=lambda t: t.position
            ))
            return f"TabStopManager(count={len(self._tabs)}, tabs=[{tabs_str}])"


# Экспортируемые символы
__all__: Final[list[str]] = [
    "TabStopManager",
]
