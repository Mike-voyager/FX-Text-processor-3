"""Модуль Command Pattern для FX Text Processor 3.

Реализует паттерн Command для undo/redo функциональности GUI.
Состоит из следующих компонентов:
- Command: абстрактный базовый класс для всех команд
- CommandStack: менеджер истории команд (undo/redo)
- Text commands: команды для работы с текстом
- Macro commands: составные и именованные макрокоманды

Security:
    - CommandStack.clear() для очистки истории при lock session
    - Лимит истории MAX_HISTORY = 1000 команд
    - Thread-safe операции

Architecture:
    Каждая команда инкапсулирует действие и его обратное действие.
    CommandStack управляет историей и координаторами undo/redo.

Example:
    >>> from src.gui.core.commands import CommandStack, InsertTextCommand
    >>> stack = CommandStack()
    >>> cmd = InsertTextCommand(text_widget, "Hello", index="1.0")
    >>> stack.execute(cmd)  # Выполняет и добавляет в историю
    >>> stack.undo()        # Отменяет последнюю команду
    >>> stack.redo()        # Повторяет отменённую команду

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

# Barcode commands
from src.gui.core.commands.barcode_commands import (
    InsertBarcodeCommand,
    InsertPlaceholderCommand,
    InsertQRCommand,
)

# Base command
from src.gui.core.commands.command import Command

# Command stack
from src.gui.core.commands.command_stack import CommandStack

# Macro commands
from src.gui.core.commands.macro_commands import (
    CompositeCommand,
    MacroCommand,
)

# Text commands
from src.gui.core.commands.text_commands import (
    ApplyFormatCommand,
    DeleteTextCommand,
    InsertTextCommand,
    SetCPICommand,
)

# Module exports
__all__: list[str] = [
    # Base
    "Command",
    # Stack
    "CommandStack",
    # Text commands
    "InsertTextCommand",
    "DeleteTextCommand",
    "ApplyFormatCommand",
    "SetCPICommand",
    # Barcode commands
    "InsertBarcodeCommand",
    "InsertQRCommand",
    "InsertPlaceholderCommand",
    # Macro commands
    "CompositeCommand",
    "MacroCommand",
]
