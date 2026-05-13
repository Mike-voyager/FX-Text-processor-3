"""Абстрактный базовый класс Command для паттерна Command.

Модуль определяет базовый интерфейс для всех команд в системе.
Каждая команда инкапсулирует действие и предоставляет механизм
для его выполнения, отмены и повтора.

Security:
    - Команды могут содержать sensitive данные (текст документа)
    - Подклассы должны реализовывать очистку в __del__ или cleanup()

Example:
    >>> class MyCommand(Command):
    ...     def __init__(self) -> None:
    ...         super().__init__("My Command")
    ...     def execute(self) -> None:
    ...         print("Executing")
    ...     def undo(self) -> None:
    ...         print("Undoing")
    >>> cmd = MyCommand()
    >>> cmd.execute()
    >>> cmd.is_executed
    True

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from time import time
from typing import Final

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_DESCRIPTION_LENGTH: Final[int] = 100
"""Максимальная длина описания команды (security: UI DoS protection)."""


# =============================================================================
# ABSTRACT COMMAND
# =============================================================================


class Command(ABC):
    """Абстрактный базовый класс для всех команд.

    Инкапсулирует действие и предоставляет методы для выполнения,
    отмены и повтора. Каждая команда имеет состояние выполнения,
    временную метку и описание для UI.

    Attributes:
        _description: Человекочитаемое описание команды.
        _is_executed: Флаг выполнения команды.
        _timestamp: Unix timestamp создания команды.

    State Machine:
        Initial → execute() → Executed
        Executed → undo() → Undone
        Undone → redo() → Executed
        Undone → execute() → Executed (новое выполнение)

    Example:
        >>> cmd = SomeCommand()
        >>> cmd.is_executed
        False
        >>> cmd.execute()
        >>> cmd.is_executed
        True
        >>> cmd.undo()
        >>> cmd.is_executed
        False

    Version: 1.0
    """

    def __init__(self, description: str = "") -> None:
        """Инициализация базовой команды.

        Args:
            description: Описание команды для UI (меню Edit).
                Обрезается до MAX_DESCRIPTION_LENGTH символов.

        Example:
            >>> cmd = MyCommand(description="Insert text 'Hello'")
            >>> cmd.get_description()
            'Insert text 'Hello''
        """
        # Security: truncate long descriptions
        self._description: str = description[:MAX_DESCRIPTION_LENGTH]
        self._is_executed: bool = False
        self._timestamp: float = time()

    @property
    def is_executed(self) -> bool:
        """Флаг выполнения команды.

        Returns:
            True если команда была выполнена (execute() или redo()),
            False если команда не выполнена или была отменена.

        Example:
            >>> cmd = SomeCommand()
            >>> cmd.is_executed
            False
            >>> cmd.execute()
            >>> cmd.is_executed
            True
            >>> cmd.undo()
            >>> cmd.is_executed
            False
        """
        return self._is_executed

    @property
    def timestamp(self) -> float:
        """Unix timestamp создания команды.

        Returns:
            Время создания команды в секундах с эпохи.

        Example:
            >>> cmd = SomeCommand()
            >>> cmd.timestamp > 0
            True
        """
        return self._timestamp

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Используется в меню Edit для отображения
        "Undo: <description>" и "Redo: <description>".

        Returns:
            Строка описания команды (max 100 символов).

        Example:
            >>> cmd = InsertTextCommand(text_widget, "Hello", "1.0")
            >>> cmd.get_description()
            'Insert "Hello" at 1.0'
        """
        return self._description

    def can_undo(self) -> bool:
        """Проверяет, может ли команда быть отменена.

        Базовая реализация возвращает True если команда выполнена.
        Подклассы могут переопределить для специфичной логики
        (например, необратимые команды).

        Returns:
            True если undo() доступен, иначе False.

        Example:
            >>> cmd = SomeCommand()
            >>> cmd.can_undo()
            False
            >>> cmd.execute()
            >>> cmd.can_undo()
            True
            >>> cmd.undo()
            >>> cmd.can_undo()
            False
        """
        return self._is_executed

    def can_redo(self) -> bool:
        """Проверяет, может ли команда быть повторена.

        Базовая реализация возвращает True если команда выполнена
        (redo() эквивалентно execute() для неотменённых команд).
        Для отменённых команд подклассы должны определить логику.

        Note:
            В текущей реализации redo() делегирует execute().
            Для команд с явным redo (без re-execution) переопределите.

        Returns:
            True если redo() доступен, иначе False.

        Example:
            >>> cmd = SomeCommand()
            >>> cmd.can_redo()
            True  # Можно выполнить первый раз
            >>> cmd.execute()
            >>> cmd.can_redo()
            True  # Можно повторить
        """
        return True

    @abstractmethod
    def execute(self) -> None:
        """Выполняет команду.

        Абстрактный метод, который должен быть реализован подклассами.
        Выполняет основное действие команды.

        Side Effects:
            - Устанавливает _is_executed = True
            - Обновляет _timestamp
            - Может изменять состояние внешних объектов

        Raises:
            RuntimeError: Если выполнение невозможно.
            Exception: Любые ошибки выполнения.

        Example:
            >>> cmd = InsertTextCommand(widget, "Hello", "1.0")
            >>> cmd.execute()  # Вставляет текст
        """
        self._timestamp = time()
        self._is_executed = True

    @abstractmethod
    def undo(self) -> None:
        """Отменяет команду.

        Абстрактный метод, который должен быть реализован подклассами.
        Выполняет обратное действие для отмены эффекта execute().

        Side Effects:
            - Устанавливает _is_executed = False
            - Может изменять состояние внешних объектов

        Raises:
            RuntimeError: Если отмена невозможна.
            Exception: Любые ошибки при отмене.

        Security:
            Убедитесь, что undo не приводит к inconsistent state.

        Example:
            >>> cmd.execute()
            >>> # Текст вставлен
            >>> cmd.undo()
            >>> # Текст удалён, состояние восстановлено
        """
        self._is_executed = False

    def redo(self) -> None:
        """Повторяет команду.

        По умолчанию делегирует execute(). Подклассы могут
        переопределить для оптимизации (например, повторное использование
        вычисленных значений вместо re-execution).

        Side Effects:
            - Вызывает execute() по умолчанию
            - Устанавливает _is_executed = True

        Example:
            >>> cmd.execute()
            >>> cmd.undo()
            >>> cmd.redo()  # Повторно выполняет команду
        """
        self.execute()

    def __repr__(self) -> str:
        """Строковое представление команды для отладки.

        Returns:
            Строка с классом, описанием и состоянием.

        Example:
            >>> cmd = SomeCommand(description="Test")
            >>> repr(cmd)
            "SomeCommand('Test', executed=False)"
        """
        return f"{self.__class__.__name__}({self._description!r}, executed={self._is_executed})"


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "Command",
    "MAX_DESCRIPTION_LENGTH",
]
