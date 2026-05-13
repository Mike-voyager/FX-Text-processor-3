"""CommandStack — менеджер истории команд для undo/redo.

Реализует паттерн Command History с ограничением размера стека.
Обеспечивает thread-safe операции для многопоточных сценариев.

Security:
    - clear() для принудительной очистки истории (session lock)
    - MAX_HISTORY ограничивает потребление памяти
    - Thread-safe операции через RLock

Example:
    >>> stack = CommandStack()
    >>> stack.execute(InsertTextCommand(widget, "Hello", "1.0"))
    >>> stack.can_undo()
    True
    >>> stack.undo()
    >>> stack.can_redo()
    True
    >>> stack.clear()  # Security: wipe history

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from threading import RLock
from typing import Final, Optional

from src.gui.core.commands.command import Command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_HISTORY: Final[int] = 1000
"""Максимальное количество команд в истории.

Security: ограничение предотвращает DoS через memory exhaustion.
При превышении limit старые команды удаляются.
"""


# =============================================================================
# COMMAND STACK
# =============================================================================


class CommandStack:
    """Менеджер истории команд с поддержкой undo/redo.

    Управляет стеком выполненных команд и обеспечивает:
    - Выполнение команд с автоматическим добавлением в историю
    - Отмену (undo) и повтор (redo) команд
    - Ограничение размера истории (MAX_HISTORY)
    - Thread-safe операции

    State Machine:
        - undo_stack: команды, которые можно отменить
        - redo_stack: команды, которые можно повторить
        - execute() → push to undo_stack, clear redo_stack
        - undo() → pop from undo_stack, push to redo_stack
        - redo() → pop from redo_stack, push to undo_stack

    Attributes:
        _undo_stack: Список выполненных команд (новые в конце).
        _redo_stack: Список отменённых команд для redo.
        _lock: RLock для thread-safe операций.

    Thread Safety:
        Все публичные методы защищены RLock.
        Может использоваться из разных потоков (например,
        UI thread и background save).

    Example:
        >>> stack = CommandStack()
        >>> stack.execute(cmd1)  # undo_stack: [cmd1]
        >>> stack.execute(cmd2)  # undo_stack: [cmd1, cmd2]
        >>> stack.undo()          # undo_stack: [cmd1], redo_stack: [cmd2]
        >>> stack.redo()          # undo_stack: [cmd1, cmd2], redo_stack: []

    Version: 1.0
    """

    def __init__(self) -> None:
        """Инициализация пустого стека команд.

        Example:
            >>> stack = CommandStack()
            >>> stack.can_undo()
            False
            >>> stack.can_redo()
            False
        """
        self._undo_stack: list[Command] = []
        self._redo_stack: list[Command] = []
        self._lock: RLock = RLock()

    def execute(self, cmd: Command) -> None:
        """Выполняет команду и добавляет её в историю.

        Выполняет команду немедленно и добавляет в undo_stack.
        Очищает redo_stack (новое действие делает redo недоступным).
        При превышении MAX_HISTORY удаляет старые команды.

        Args:
            cmd: Команда для выполнения. Должна быть экземпляром Command.

        Raises:
            TypeError: Если cmd не является Command.
            RuntimeError: Если выполнение команды завершилось ошибкой.

        Side Effects:
            - Выполняет cmd.execute()
            - Добавляет cmd в undo_stack
            - Очищает redo_stack
            - Может удалить старые команды при превышении limit

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack = CommandStack()
            >>> cmd = InsertTextCommand(widget, "Hello", "1.0")
            >>> stack.execute(cmd)
            >>> stack.can_undo()
            True
        """
        if not isinstance(cmd, Command):
            raise TypeError(f"cmd должен быть Command, получен {type(cmd).__name__}")

        with self._lock:
            # Выполняем команду
            try:
                cmd.execute()
            except Exception as e:
                raise RuntimeError(f"Command execution failed: {e}") from e

            # Добавляем в undo_stack
            self._undo_stack.append(cmd)

            # Очищаем redo_stack (новое действие)
            self._redo_stack.clear()

            # Проверяем limit
            self._enforce_history_limit()

    def undo(self) -> None:
        """Отменяет последнюю выполненную команду.

        Берёт последнюю команду из undo_stack, вызывает undo()
        и перемещает в redo_stack.

        Raises:
            RuntimeError: Если нет команд для отмены (undo_stack пуст).

        Side Effects:
            - Вызывает cmd.undo() для последней команды
            - Перемещает команду из undo_stack в redo_stack

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack.execute(cmd)
            >>> stack.undo()  # Отменяет cmd
            >>> stack.can_redo()
            True
        """
        with self._lock:
            if not self._undo_stack:
                raise RuntimeError("Нет команд для отмены")

            cmd = self._undo_stack.pop()

            try:
                cmd.undo()
            except Exception as e:
                # Возвращаем команду обратно в случае ошибки
                self._undo_stack.append(cmd)
                raise RuntimeError(f"Undo failed: {e}") from e

            self._redo_stack.append(cmd)

    def redo(self) -> None:
        """Повторяет последнюю отменённую команду.

        Берёт последнюю команду из redo_stack, вызывает redo()
        и перемещает обратно в undo_stack.

        Raises:
            RuntimeError: Если нет команд для повтора (redo_stack пуст).

        Side Effects:
            - Вызывает cmd.redo() для последней отменённой команды
            - Перемещает команду из redo_stack в undo_stack

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack.execute(cmd)
            >>> stack.undo()
            >>> stack.redo()  # Повторно выполняет cmd
        """
        with self._lock:
            if not self._redo_stack:
                raise RuntimeError("Нет команд для повтора")

            cmd = self._redo_stack.pop()

            try:
                cmd.redo()
            except Exception as e:
                # Возвращаем команду обратно в случае ошибки
                self._redo_stack.append(cmd)
                raise RuntimeError(f"Redo failed: {e}") from e

            self._undo_stack.append(cmd)

    def can_undo(self) -> bool:
        """Проверяет, есть ли команды для отмены.

        Returns:
            True если undo_stack не пуст, иначе False.

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack.can_undo()
            False
            >>> stack.execute(cmd)
            >>> stack.can_undo()
            True
        """
        with self._lock:
            return len(self._undo_stack) > 0

    def can_redo(self) -> bool:
        """Проверяет, есть ли команды для повтора.

        Returns:
            True если redo_stack не пуст, иначе False.

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack.can_redo()
            False
            >>> stack.execute(cmd)
            >>> stack.undo()
            >>> stack.can_redo()
            True
        """
        with self._lock:
            return len(self._redo_stack) > 0

    def clear(self) -> None:
        """Очищает всю историю команд.

        Security-critical метод для принудительной очистки истории.
        Используется при блокировке сессии (session lock) для
        предотвращения утечки sensitive данных через undo/redo.

        Side Effects:
            - Очищает undo_stack
            - Очищает redo_stack
            - Команды становятся доступны для GC

        Security:
            Вызывать при session lock для wipe истории редактирования.

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack.execute(cmd_with_sensitive_data)
            >>> # User locks session
            >>> stack.clear()  # Wipe history
            >>> stack.can_undo()
            False
        """
        with self._lock:
            # Security: explicit clear of stacks
            self._undo_stack.clear()
            self._redo_stack.clear()

    def get_undo_description(self) -> Optional[str]:
        """Возвращает описание команды для отмены.

        Используется в UI для меню "Edit → Undo: <description>".

        Returns:
            Описание последней выполненной команды или None
            если undo_stack пуст.

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack.get_undo_description()
            None
            >>> stack.execute(InsertTextCommand(widget, "Hello", "1.0"))
            >>> stack.get_undo_description()
            'Insert "Hello" at 1.0'
        """
        with self._lock:
            if not self._undo_stack:
                return None
            return self._undo_stack[-1].get_description()

    def get_redo_description(self) -> Optional[str]:
        """Возвращает описание команды для повтора.

        Используется в UI для меню "Edit → Redo: <description>".

        Returns:
            Описание последней отменённой команды или None
            если redo_stack пуст.

        Thread Safety:
            Thread-safe через RLock.

        Example:
            >>> stack.get_redo_description()
            None
            >>> stack.execute(cmd)
            >>> stack.undo()
            >>> stack.get_redo_description()
            'Some command description'
        """
        with self._lock:
            if not self._redo_stack:
                return None
            return self._redo_stack[-1].get_description()

    def _enforce_history_limit(self) -> None:
        """Удаляет старые команды при превышении MAX_HISTORY.

        Private method, вызывается из execute().
        Удаляет самые старые команды из начала undo_stack.

        Side Effects:
            - Может удалить старые команды из undo_stack
            - Команды становятся доступны для GC

        Security:
            Предотвращает memory exhaustion через unlimited history.
        """
        excess = len(self._undo_stack) - MAX_HISTORY
        if excess > 0:
            # Удаляем старые команды с начала списка
            del self._undo_stack[:excess]

    def __len__(self) -> int:
        """Возвращает общее количество команд в истории.

        Returns:
            Сумма команд в undo_stack и redo_stack.

        Example:
            >>> len(stack)
            0
            >>> stack.execute(cmd1)
            >>> len(stack)
            1
            >>> stack.undo()
            >>> len(stack)
            1  # В redo_stack
        """
        with self._lock:
            return len(self._undo_stack) + len(self._redo_stack)

    def __repr__(self) -> str:
        """Строковое представление для отладки.

        Returns:
            Строка с размерами undo и redo стеков.

        Example:
            >>> repr(stack)
            'CommandStack(undo=2, redo=1)'
        """
        with self._lock:
            return (
                f"{self.__class__.__name__}"
                f"(undo={len(self._undo_stack)}, redo={len(self._redo_stack)})"
            )


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "CommandStack",
    "MAX_HISTORY",
]
