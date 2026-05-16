"""Макро-команды для групповых операций undo/redo.

Реализует паттерн Command для выполнения серий команд:
- MacroCommand: Именованная макрокоманда (выполняет серию команд).
- CompositeCommand: Анонимная группа команд (выполняет/отменяет группу).

Security:
    - Команды в макросе не очищаются при undo/redo отдельных шагов.
    - Ограничение на количество команд в макросе (DoS protection).

Example:
    >>> macro = MacroCommand("Format paragraph")
    >>> macro.add(InsertTextCommand(widget, "Hello", "1.0"))
    >>> macro.add(ApplyFormatCommand(widget, "1.0", "1.5", ("bold",)))
    >>> macro.execute()
    >>> macro.undo()  # Отменяет все команды в обратном порядке

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import Final

from src.gui.core.commands.command import Command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_MACRO_COMMANDS: Final[int] = 1000
"""Максимальное количество команд в макросе (security: DoS protection)."""


# =============================================================================
# COMPOSITE COMMAND
# =============================================================================


class CompositeCommand(Command):
    """Анонимная группа команд, выполняемых как единое целое.

    Все команды выполняются последовательно при execute().
    При undo() команды отменяются в обратном порядке.

    Attributes:
        _commands: Список команд в группе.

    Example:
        >>> group = CompositeCommand()
        >>> group.add(InsertTextCommand(widget, "A", "1.0"))
        >>> group.add(InsertTextCommand(widget, "B", "1.1"))
        >>> group.execute()
        >>> group.undo()  # Отменяет B, затем A
    """

    def __init__(self, description: str = "Composite command") -> None:
        """Инициализация составной команды.

        Args:
            description: Описание группы для UI.
        """
        super().__init__(description)
        self._commands: list[Command] = []

    def add(self, cmd: Command) -> None:
        """Добавляет команду в группу.

        Args:
            cmd: Команда для добавления.

        Raises:
            TypeError: Если cmd не является Command.
            RuntimeError: Если превышен лимит команд в группе.
        """
        if not isinstance(cmd, Command):
            raise TypeError("Аргумент должен быть Command")
        if len(self._commands) >= MAX_MACRO_COMMANDS:
            raise RuntimeError(f"Превышен лимит команд в группе ({MAX_MACRO_COMMANDS})")
        self._commands.append(cmd)

    def execute(self) -> None:
        """Выполняет все команды группы последовательно.

        Side Effects:
            - Устанавливает _is_executed = True.
            - Если одна из команд падает, выполнение прерывается.
        """
        for cmd in self._commands:
            cmd.execute()
        self._is_executed = True

    def undo(self) -> None:
        """Отменяет все команды группы в обратном порядке.

        Side Effects:
            - Устанавливает _is_executed = False.
            - Если одна из команд падает, отмена прерывается.
        """
        for cmd in reversed(self._commands):
            cmd.undo()
        self._is_executed = False

    def get_description(self) -> str:
        """Возвращает описание группы.

        Returns:
            Описание с количеством команд.
        """
        return f"{self._description} ({len(self._commands)} commands)"


# =============================================================================
# MACRO COMMAND
# =============================================================================


class MacroCommand(CompositeCommand):
    """Именованная макрокоманда для выполнения серии команд.

    Расширяет CompositeCommand, добавляя имя макроса
    для отображения в UI (меню Edit → Macros).

    Attributes:
        _name: Имя макроса.

    Example:
        >>> macro = MacroCommand("Bold and Italic")
        >>> macro.add(ApplyFormatCommand(widget, "1.0", "1.5", ("bold",)))
        >>> macro.add(ApplyFormatCommand(widget, "1.0", "1.5", ("italic",)))
        >>> macro.execute()
    """

    def __init__(self, name: str) -> None:
        """Инициализация макрокоманды.

        Args:
            name: Имя макроса для отображения в UI.
        """
        super().__init__(description=name)
        self._name: str = name

    @property
    def name(self) -> str:
        """Имя макроса.

        Returns:
            Строка с именем макроса.
        """
        return self._name

    def get_description(self) -> str:
        """Возвращает описание макроса.

        Returns:
            Имя макроса с количеством команд.
        """
        return f"Macro: {self._name} ({len(self._commands)} commands)"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "CompositeCommand",
    "MacroCommand",
    "MAX_MACRO_COMMANDS",
]
