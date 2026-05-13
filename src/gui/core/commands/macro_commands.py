"""Макрокоманды для группировки и именования команд.

Реализует составные команды для undo/redo нескольких действий как одно:
- CompositeCommand: выполняет несколько команд последовательно
- MacroCommand: именованная макрокоманда с метаданными

Security:
    - Атомичность: все команды выполняются или ни одна
    - Ограничение размера для предотвращения DoS

Example:
    >>> from src.gui.core.commands import CompositeCommand, InsertTextCommand
    >>> composite = CompositeCommand("Insert header")
    >>> composite.add(InsertTextCommand(widget, "Title\\n", "1.0"))
    >>> composite.add(ApplyFormatCommand(widget, "1.0", "1.6", ("bold",)))
    >>> stack.execute(composite)  # Выполняет обе команды
    >>> stack.undo()                # Отменяет обе команды

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

from src.gui.core.commands.command import Command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_MACRO_SIZE: Final[int] = 100
"""Максимальное количество команд в макросе (security: DoS protection)."""


# =============================================================================
# COMPOSITE COMMAND
# =============================================================================


class CompositeCommand(Command):
    """Составная команда для группировки нескольких команд.

    Выполняет все вложенные команды последовательно как одну операцию.
    При undo отменяет все команды в обратном порядке.
    Гарантирует атомичность: все команды выполняются или ни одна.

    Attributes:
        _commands: Список вложенных команд.
        _executed_count: Количество успешно выполненных команд.

    State Machine:
        Initial → execute() → All commands executed
        Executed → undo() → All commands undone (reverse order)

    Error Handling:
        Если одна из команд падает, предыдущие успешные команды
        автоматически отменяются (rollback).

    Example:
        >>> composite = CompositeCommand("Insert formatted title")
        >>> composite.add(InsertTextCommand(w, "Title", "1.0"))
        >>> composite.add(ApplyFormatCommand(w, "1.0", "1.5", ("bold",)))
        >>> stack.execute(composite)  # Атомарная операция
        >>> stack.undo()                # Отменяет обе команды

    Version: 1.0
    """

    def __init__(self, description: str = "Composite command") -> None:
        """Инициализация составной команды.

        Args:
            description: Описание для UI.

        Example:
            >>> composite = CompositeCommand("Insert header")
            >>> composite.get_description()
            'Insert header'
        """
        super().__init__(description=description)
        self._commands: list[Command] = []
        self._executed_count: int = 0

    def add(self, cmd: Command) -> "CompositeCommand":
        """Добавляет команду в составную команду.

        Поддерживает fluent interface (chainable).

        Args:
            cmd: Команда для добавления.

        Returns:
            Self для chaining.

        Raises:
            ValueError: Если cmd не является Command.
            RuntimeError: Если превышен MAX_MACRO_SIZE.

        Example:
            >>> composite.add(cmd1).add(cmd2).add(cmd3)
        """
        if not isinstance(cmd, Command):
            raise ValueError(f"cmd должен быть Command, получен {type(cmd).__name__}")

        if len(self._commands) >= MAX_MACRO_SIZE:
            raise RuntimeError(f"Превышен лимит команд в макросе: {MAX_MACRO_SIZE}")

        self._commands.append(cmd)
        return self

    def execute(self) -> None:
        """Выполняет все вложенные команды последовательно.

        Выполняет команды в порядке добавления. Если какая-либо
        команда падает, отменяет все предыдущие успешные команды.

        Side Effects:
            - Выполняет все вложенные команды
            - Устанавливает _executed_count
            - При ошибке: отменяет успешные команды (rollback)

        Raises:
            RuntimeError: Если выполнение любой команды завершилось ошибкой.

        Example:
            >>> composite.execute()  # Выполняет cmd1, cmd2, cmd3...
        """
        super().execute()

        executed: list[Command] = []

        try:
            for cmd in self._commands:
                cmd.execute()
                executed.append(cmd)
        except Exception as exc:
            # Rollback: отменяем успешно выполненные команды
            for cmd in reversed(executed):
                try:
                    cmd.undo()
                except (RuntimeError, AttributeError, TypeError):
                    # Логгируем, но игнорируем ошибки при rollback - лучше продолжить
                    # чем оставить частично отменённые команды
                    import logging

                    logging.getLogger(__name__).exception("Rollback error ignored")
            raise RuntimeError(f"Composite command failed: {exc}") from exc

        self._executed_count = len(executed)

    def undo(self) -> None:
        """Отменяет все вложенные команды в обратном порядке.

        Отменяет команды в обратном порядке (LIFO) для корректного
        восстановления состояния.

        Side Effects:
            - Отменяет все вложенные команды (reverse order)
            - Сбрасывает _executed_count

        Raises:
            RuntimeError: Если отмена любой команды завершилась ошибкой.

        Example:
            >>> composite.undo()  # Отменяет cmd3, cmd2, cmd1...
        """
        if self._executed_count == 0:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()

        errors: list[str] = []

        # Отменяем в обратном порядке (только выполненные)
        for cmd in reversed(self._commands[: self._executed_count]):
            try:
                cmd.undo()
            except Exception as e:
                errors.append(str(e))

        if errors:
            raise RuntimeError(f"Undo failed for some commands: {errors}")

        self._executed_count = 0

    def redo(self) -> None:
        """Повторяет составную команду.

        Делегирует execute() для повторного выполнения всех команд.

        Example:
            >>> composite.redo()  # Повторно выполняет все команды
        """
        # Сбрасываем состояние для чистого повторного выполнения
        self._executed_count = 0
        self.execute()

    def can_undo(self) -> bool:
        """Проверяет, может ли команда быть отменена.

        Returns:
            True если есть хотя бы одна выполненная команда.
        """
        return self._is_executed and self._executed_count > 0

    def can_redo(self) -> bool:
        """Проверяет, может ли команда быть повторена.

        Returns:
            True всегда (можно повторить даже неотменённые).
        """
        return True

    def __len__(self) -> int:
        """Возвращает количество вложенных команд.

        Returns:
            Количество команд в составной команде.

        Example:
            >>> len(composite)
            3
        """
        return len(self._commands)

    def __iter__(self) -> "Iterator[Command]":
        """Итератор по вложенным командам.

        Returns:
            Итератор по командам.

        Example:
            >>> for cmd in composite:
            ...     print(cmd.get_description())
        """
        return iter(self._commands)


# =============================================================================
# MACRO COMMAND
# =============================================================================


class MacroCommand(CompositeCommand):
    """Именованная макрокоманда с метаданными.

    Расширяет CompositeCommand метаданными:
    - name: Уникальное имя макроса
    - category: Категория (например, "headers", "forms")
    - shortcut: Клавиатурное сокращение
    - description: Подробное описание

    Макрокоманды могут быть сохранены и загружены из файлов,
    используются для пользовательских шаблонов.

    Attributes:
        _name: Уникальное имя макроса.
        _category: Категория для организации.
        _shortcut: Клавиатурное сокращение (опционально).
        _detailed_description: Подробное описание.

    Example:
        >>> macro = MacroCommand(
        ...     name="insert_invoice_header",
        ...     description="Вставляет заголовок накладной",
        ...     category="forms",
        ...     shortcut="Ctrl+Shift+I"
        ... )
        >>> macro.add(InsertTextCommand(w, "INVOICE", "1.0"))
        >>> macro.add(ApplyFormatCommand(w, "1.0", "1.7", ("bold",)))
        >>> stack.execute(macro)

    Version: 1.0
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        category: str = "general",
        shortcut: str = "",
        detailed_description: str = "",
    ) -> None:
        """Инициализация макрокоманды.

        Args:
            name: Уникальное имя макроса (идентификатор).
            description: Краткое описание для UI.
            category: Категория макроса (default: "general").
            shortcut: Клавиатурное сокращение (default: "").
            detailed_description: Подробное описание (default: "")

        Raises:
            ValueError: Если name пустой.

        Example:
            >>> macro = MacroCommand("header_invoice", "Invoice Header")
            >>> macro.name
            'header_invoice'
        """
        if not name or not name.strip():
            raise ValueError("name не может быть пустым")

        # Используем description как базовое, или name если не указано
        display_desc = description if description else name

        super().__init__(description=display_desc)

        self._name: str = name.strip()
        self._category: str = category
        self._shortcut: str = shortcut
        self._detailed_description: str = detailed_description

    @property
    def name(self) -> str:
        """Уникальное имя макроса.

        Returns:
            Строковый идентификатор макроса.

        Example:
            >>> macro.name
            'insert_invoice_header'
        """
        return self._name

    @property
    def category(self) -> str:
        """Категория макроса.

        Returns:
            Строковая категория (например, "forms", "headers").

        Example:
            >>> macro.category
            'forms'
        """
        return self._category

    @property
    def shortcut(self) -> str:
        """Клавиатурное сокращение.

        Returns:
            Строка сокращения (например, "Ctrl+Shift+I").

        Example:
            >>> macro.shortcut
            'Ctrl+Shift+I'
        """
        return self._shortcut

    @property
    def detailed_description(self) -> str:
        """Подробное описание макроса.

        Returns:
            Полное описание для tooltip или документации.

        Example:
            >>> macro.detailed_description
            'Вставляет форматированный заголовок накладной'
        """
        return self._detailed_description

    def set_shortcut(self, shortcut: str) -> "MacroCommand":
        """Устанавливает клавиатурное сокращение.

        Поддерживает fluent interface.

        Args:
            shortcut: Новое сокращение (например, "Ctrl+Shift+I").

        Returns:
            Self для chaining.

        Example:
            >>> macro.set_shortcut("Ctrl+H")
        """
        self._shortcut = shortcut
        return self

    def set_category(self, category: str) -> "MacroCommand":
        """Устанавливает категорию.

        Поддерживает fluent interface.

        Args:
            category: Новая категория.

        Returns:
            Self для chaining.

        Example:
            >>> macro.set_category("invoices")
        """
        self._category = category
        return self

    def set_detailed_description(self, description: str) -> "MacroCommand":
        """Устанавливает подробное описание.

        Поддерживает fluent interface.

        Args:
            description: Новое подробное описание.

        Returns:
            Self для chaining.

        Example:
            >>> macro.set_detailed_description("Вставляет заголовок...")
        """
        self._detailed_description = description
        return self

    def __repr__(self) -> str:
        """Строковое представление для отладки.

        Returns:
            Строка с именем, категорией и размером.

        Example:
            >>> repr(macro)
            "MacroCommand('header_invoice', category='forms', commands=3)"
        """
        return (
            f"{self.__class__.__name__}"
            f"({self._name!r}, category={self._category!r}, commands={len(self)})"
        )


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "CompositeCommand",
    "MacroCommand",
    "MAX_MACRO_SIZE",
]
