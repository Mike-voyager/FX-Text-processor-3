"""Менеджер истории команд (Undo/Redo) для GUI.

Реализует паттерн Command Stack с поддержкой отмены и повтора операций.
Обеспечивает thread-safe операции и ограничение глубины истории.

Classes:
    CommandStack: Стек команд с методами execute, undo, redo.

Constants:
    MAX_HISTORY: Максимальное количество команд в истории (1000).

Security:
    - clear() для очистки истории при lock session.
    - Thread-safe операции через threading.Lock.
    - Ограничение глубины истории для защиты от DoS.

Example:
    >>> stack = CommandStack()
    >>> stack.execute(InsertTextCommand(widget, "Hello", "1.0"))
    >>> stack.undo()
    >>> stack.redo()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import threading
from typing import Final

from src.gui.core.commands.command import Command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_HISTORY: Final[int] = 1000
"""Максимальное количество команд в истории (security: DoS protection)."""


# =============================================================================
# COMMAND STACK
# =============================================================================


class CommandStack:
    """Стек команд с поддержкой undo/redo.

    Управляет историей выполненных команд и предоставляет
    механизмы для их отмены и повтора.

    Attributes:
        _undo_stack: Стек выполненных команд (для undo).
        _redo_stack: Стек отменённых команд (для redo).
        _lock: Блокировка для thread-safe операций.
        _max_depth: Максимальная глубина истории.

    State Machine:
        Initial → execute(cmd) → undo_stack=[cmd]
        undo_stack=[cmd] → undo() → redo_stack=[cmd]
        redo_stack=[cmd] → redo() → undo_stack=[cmd]
        undo_stack=[cmd1, cmd2] → execute(cmd3) → redo_stack=[]

    Example:
        >>> stack = CommandStack()
        >>> stack.execute(SomeCommand())
        >>> stack.can_undo()
        True
        >>> stack.undo()
        >>> stack.can_redo()
        True

    Security:
        - clear() очищает оба стека для предотвращения утечки
          sensitive данных через undo/redo.
        - Thread-safe через threading.Lock.
    """

    def __init__(self, max_depth: int = MAX_HISTORY) -> None:
        """Инициализация CommandStack.

        Args:
            max_depth: Максимальная глубина истории команд.

        Example:
            >>> stack = CommandStack(max_depth=500)
            >>> len(stack)
            0
        """
        self._undo_stack: list[Command] = []
        self._redo_stack: list[Command] = []
        self._lock: threading.Lock = threading.Lock()
        self._max_depth: int = max_depth

    # -------------------------------------------------------------------------
    # PROPERTIES
    # -------------------------------------------------------------------------

    @property
    def max_depth(self) -> int:
        """Максимальная глубина истории.

        Returns:
            Максимальное количество команд в стеке.
        """
        return self._max_depth

    # -------------------------------------------------------------------------
    # PUBLIC METHODS
    # -------------------------------------------------------------------------

    def execute(self, cmd: Command) -> None:
        """Выполняет команду и добавляет её в историю.

        Вызывает cmd.execute(), добавляет команду в undo_stack
        и очищает redo_stack (новое действие делает redo невозможным).

        Args:
            cmd: Команда для выполнения (должна быть подклассом Command).

        Raises:
            TypeError: Если cmd не является Command.
            RuntimeError: Если выполнение команды завершилось ошибкой.

        Example:
            >>> stack = CommandStack()
            >>> stack.execute(InsertTextCommand(widget, "Hello", "1.0"))
            >>> stack.can_undo()
            True
        """
        if not isinstance(cmd, Command):
            raise TypeError("Аргумент должен быть Command")

        with self._lock:
            try:
                cmd.execute()
            except Exception as exc:
                raise RuntimeError(f"Command execution failed: {exc}") from exc

            self._undo_stack.append(cmd)
            self._redo_stack.clear()

            # Enforce history limit
            if len(self._undo_stack) > self._max_depth:
                self._undo_stack.pop(0)

    def undo(self) -> None:
        """Отменяет последнюю выполненную команду.

        Вызывает undo() последней команды из undo_stack и перемещает
        её в redo_stack. Если undo() выбрасывает исключение, команда
        остаётся в undo_stack.

        Raises:
            RuntimeError: Если undo_stack пуст (нет команд для отмены).
            RuntimeError: Если отмена команды завершилась ошибкой.

        Example:
            >>> stack.execute(cmd)
            >>> stack.undo()
            >>> stack.can_undo()
            False
        """
        with self._lock:
            if not self._undo_stack:
                raise RuntimeError("Нет команд для отмены")

            cmd = self._undo_stack.pop()
            try:
                cmd.undo()
            except Exception as exc:
                # Возвращаем команду обратно в стек при ошибке
                self._undo_stack.append(cmd)
                raise RuntimeError(f"Undo failed: {exc}") from exc

            self._redo_stack.append(cmd)

    def redo(self) -> None:
        """Повторяет последнюю отменённую команду.

        Вызывает redo() последней команды из redo_stack и перемещает
        её обратно в undo_stack. Если redo() выбрасывает исключение, команда
        остаётся в redo_stack.

        Raises:
            RuntimeError: Если redo_stack пуст (нет команд для повтора).
            RuntimeError: Если повтор команды завершился ошибкой.

        Example:
            >>> stack.execute(cmd)
            >>> stack.undo()
            >>> stack.redo()
            >>> stack.can_undo()
            True
        """
        with self._lock:
            if not self._redo_stack:
                raise RuntimeError("Нет команд для повтора")

            cmd = self._redo_stack.pop()
            try:
                cmd.redo()
            except Exception as exc:
                # Возвращаем команду обратно в стек при ошибке
                self._redo_stack.append(cmd)
                raise RuntimeError(f"Redo failed: {exc}") from exc

            self._undo_stack.append(cmd)

    def clear(self) -> None:
        """Очищает всю историю команд.

        Удаляет все команды из undo_stack и redo_stack.
        Используется при lock session или закрытии документа
        для предотвращения утечки sensitive данных.

        Security:
            После вызова undo/redo становятся недоступны.
            Команды становятся доступными для GC.

        Example:
            >>> stack.execute(cmd)
            >>> stack.clear()
            >>> stack.can_undo()
            False
        """
        with self._lock:
            self._undo_stack.clear()
            self._redo_stack.clear()

    def can_undo(self) -> bool:
        """Проверяет, доступна ли отмена.

        Returns:
            True если есть команды для отмены.
        """
        with self._lock:
            return len(self._undo_stack) > 0

    def can_redo(self) -> bool:
        """Проверяет, доступен ли повтор.

        Returns:
            True если есть команды для повтора.
        """
        with self._lock:
            return len(self._redo_stack) > 0

    def get_history(self) -> list[str]:
        """Возвращает список описаний команд в undo_stack.

        Returns:
            Список строк с описаниями команд (от старых к новым).
        """
        with self._lock:
            return [cmd.get_description() for cmd in self._undo_stack]

    def get_undo_description(self) -> str | None:
        """Возвращает описание команды для отмены.

        Returns:
            Описание последней команды или None если стек пуст.
        """
        with self._lock:
            if not self._undo_stack:
                return None
            return self._undo_stack[-1].get_description()

    def get_redo_description(self) -> str | None:
        """Возвращает описание команды для повтора.

        Returns:
            Описание последней отменённой команды или None если стек пуст.
        """
        with self._lock:
            if not self._redo_stack:
                return None
            return self._redo_stack[-1].get_description()

    # -------------------------------------------------------------------------
    # MAGIC METHODS
    # -------------------------------------------------------------------------

    def __len__(self) -> int:
        """Общее количество команд в стеках.

        Returns:
            Сумма команд в undo_stack и redo_stack.
        """
        with self._lock:
            return len(self._undo_stack) + len(self._redo_stack)

    def __repr__(self) -> str:
        """Строковое представление для отладки.

        Returns:
            Строка с информацией о размере стеков.
        """
        with self._lock:
            return (
                f"CommandStack(undo={len(self._undo_stack)}, "
                f"redo={len(self._redo_stack)}, max_depth={self._max_depth})"
            )


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "CommandStack",
    "MAX_HISTORY",
]
