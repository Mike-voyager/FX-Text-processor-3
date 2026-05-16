"""Текстовые команды для редактора GUI.

Реализует паттерн Command для операций с текстом:
- Вставка текста (InsertTextCommand)
- Удаление текста (DeleteTextCommand)
- Применение форматирования (ApplyFormatCommand)
- Установка CPI (SetCPICommand)

Security:
    - MAX_TEXT_LENGTH ограничивает длину текста (DoS protection).
    - VALID_CPI_VALUES ограничивает допустимые значения CPI.

Example:
    >>> cmd = InsertTextCommand(text_widget, "Hello", "1.0")
    >>> cmd.execute()
    >>> cmd.undo()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Final, Iterable

from src.gui.core.commands.command import Command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_TEXT_LENGTH: Final[int] = 100_000
"""Максимальная длина текста (security: DoS protection)."""

VALID_CPI_VALUES: Final[frozenset[float]] = frozenset({10.0, 12.0, 15.0, 17.0, 20.0})
"""Допустимые значения символов на дюйм (CPI)."""

DEFAULT_CPI: Final[float] = 10.0
"""Значение CPI по умолчанию."""

VALID_FORMATS: Final[frozenset[str]] = frozenset(
    {"bold", "italic", "underline", "double_width", "double_height", "subscript", "superscript"}
)
"""Допустимые форматы текста."""


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def _validate_text_widget(widget: tk.Text) -> None:
    """Проверяет, что виджет является tk.Text.

    Args:
        widget: Виджет для проверки.

    Raises:
        ValueError: Если виджет не является экземпляром tk.Text.
    """
    if not isinstance(widget, tk.Text):
        raise ValueError("Виджет должен быть tk.Text")


# =============================================================================
# INSERT TEXT COMMAND
# =============================================================================


class InsertTextCommand(Command):
    """Команда вставки текста в tk.Text виджет.

    Attributes:
        _text_widget: Виджет tk.Text.
        _text: Текст для вставки (обрезан до MAX_TEXT_LENGTH).
        _index: Позиция вставки (Tkinter index).
        _tags: Теги форматирования.
        _end_index: Конечная позиция после вставки (для undo).

    Example:
        >>> cmd = InsertTextCommand(text_widget, "Hello", "1.0")
        >>> cmd.execute()
        >>> cmd.undo()  # Удаляет вставленный текст
    """

    def __init__(
        self,
        text_widget: tk.Text,
        text: str,
        index: str,
        tags: Iterable[str] = (),
    ) -> None:
        """Инициализация команды вставки текста.

        Args:
            text_widget: Виджет tk.Text.
            text: Текст для вставки.
            index: Позиция вставки (например, "1.0").
            tags: Теги форматирования (опционально).

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        super().__init__(f'Insert "{text[:50]}" at {index}')
        _validate_text_widget(text_widget)
        self._text_widget: tk.Text = text_widget
        self._text: str = text[:MAX_TEXT_LENGTH]
        self._index: str = index
        self._tags: tuple[str, ...] = tuple(tags)
        self._end_index: str | None = None

    def execute(self) -> None:
        """Вставляет текст в виджет.

        Side Effects:
            - Устанавливает _end_index.
            - Устанавливает _is_executed = True.
        """
        self._text_widget.insert(self._index, self._text, self._tags)
        self._end_index = self._text_widget.index(f"{self._index} + {len(self._text)} chars")
        self._is_executed = True

    def undo(self) -> None:
        """Удаляет вставленный текст.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        if self._end_index is not None:
            self._text_widget.delete(self._index, self._end_index)
        self._is_executed = False


# =============================================================================
# DELETE TEXT COMMAND
# =============================================================================


class DeleteTextCommand(Command):
    """Команда удаления текста из tk.Text виджета.

    Attributes:
        _text_widget: Виджет tk.Text.
        _start: Начальная позиция удаления.
        _end: Конечная позиция удаления.
        _deleted_text: Сохранённый удалённый текст (для undo).

    Example:
        >>> cmd = DeleteTextCommand(text_widget, "1.0", "1.5")
        >>> cmd.execute()
        >>> cmd.undo()  # Восстанавливает удалённый текст
    """

    def __init__(
        self,
        text_widget: tk.Text,
        start: str,
        end: str,
    ) -> None:
        """Инициализация команды удаления текста.

        Args:
            text_widget: Виджет tk.Text.
            start: Начальная позиция удаления.
            end: Конечная позиция удаления.

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        super().__init__(f"Delete text from {start} to {end}")
        _validate_text_widget(text_widget)
        self._text_widget: tk.Text = text_widget
        self._start: str = start
        self._end: str = end
        self._deleted_text: str = ""

    def execute(self) -> None:
        """Удаляет текст из виджета.

        Side Effects:
            - Сохраняет удалённый текст в _deleted_text.
            - Устанавливает _is_executed = True.
        """
        self._deleted_text = self._text_widget.get(self._start, self._end)
        self._text_widget.delete(self._start, self._end)
        self._is_executed = True

    def undo(self) -> None:
        """Восстанавливает удалённый текст.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        self._text_widget.insert(self._start, self._deleted_text)
        self._is_executed = False


# =============================================================================
# APPLY FORMAT COMMAND
# =============================================================================


class ApplyFormatCommand(Command):
    """Команда применения форматирования к тексту.

    Attributes:
        _text_widget: Виджет tk.Text.
        _start: Начальная позиция.
        _end: Конечная позиция.
        _formats: Кортеж применяемых форматов.

    Example:
        >>> cmd = ApplyFormatCommand(text_widget, "1.0", "1.5", ("bold",))
        >>> cmd.execute()
        >>> cmd.undo()  # Удаляет форматирование
    """

    def __init__(
        self,
        text_widget: tk.Text,
        start: str,
        end: str,
        formats: Iterable[str],
    ) -> None:
        """Инициализация команды форматирования.

        Args:
            text_widget: Виджет tk.Text.
            start: Начальная позиция.
            end: Конечная позиция.
            formats: Список форматов (например, ["bold", "italic"]).

        Raises:
            ValueError: Если text_widget не является tk.Text.
            ValueError: Если формат не поддерживается.
        """
        super().__init__(f"Apply {', '.join(formats)} to {start}-{end}")
        _validate_text_widget(text_widget)
        self._text_widget: tk.Text = text_widget
        self._start: str = start
        self._end: str = end
        self._formats: tuple[str, ...] = tuple(formats)

        # Validate formats
        invalid = set(self._formats) - VALID_FORMATS
        if invalid:
            raise ValueError(f"Неподдерживаемые форматы: {', '.join(invalid)}")

    def execute(self) -> None:
        """Применяет форматирование к диапазону текста.

        Side Effects:
            - Устанавливает _is_executed = True.
        """
        for fmt in self._formats:
            self._text_widget.tag_add(fmt, self._start, self._end)
        self._is_executed = True

    def undo(self) -> None:
        """Удаляет форматирование из диапазона.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        for fmt in self._formats:
            self._text_widget.tag_remove(fmt, self._start, self._end)
        self._is_executed = False


# =============================================================================
# SET CPI COMMAND
# =============================================================================


class SetCPICommand(Command):
    """Команда установки CPI (Characters Per Inch) для текста.

    Attributes:
        _text_widget: Виджет tk.Text.
        _new_cpi: Новое значение CPI.
        _start: Начальная позиция.
        _end: Конечная позиция.
        _old_cpi: Предыдущее значение CPI (для undo).

    Example:
        >>> cmd = SetCPICommand(text_widget, 12.0)
        >>> cmd.execute()
        >>> cmd.undo()  # Восстанавливает предыдущий CPI
    """

    def __init__(
        self,
        text_widget: tk.Text,
        cpi: float,
        start: str = "1.0",
        end: str | None = None,
    ) -> None:
        """Инициализация команды установки CPI.

        Args:
            text_widget: Виджет tk.Text.
            cpi: Значение CPI (должно быть в VALID_CPI_VALUES).
            start: Начальная позиция (по умолчанию "1.0").
            end: Конечная позиция (по умолчанию end-1c).

        Raises:
            ValueError: Если text_widget не является tk.Text.
            ValueError: Если CPI недопустимое.
        """
        super().__init__(f"Set CPI to {cpi}")
        _validate_text_widget(text_widget)
        if cpi not in VALID_CPI_VALUES:
            raise ValueError(f"Недопустимое значение CPI: {cpi}")
        self._text_widget: tk.Text = text_widget
        self._new_cpi: float = cpi
        self._start: str = start
        self._end: str = end if end is not None else "end-1c"

    def execute(self) -> None:
        """Применяет CPI тег к диапазону текста.

        Side Effects:
            - Устанавливает _is_executed = True.
        """
        tag_name = f"cpi_{int(self._new_cpi)}"
        self._text_widget.tag_add(tag_name, self._start, self._end)
        self._is_executed = True

    def undo(self) -> None:
        """Удаляет CPI тег из диапазона.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        tag_name = f"cpi_{int(self._new_cpi)}"
        self._text_widget.tag_remove(tag_name, self._start, self._end)
        self._is_executed = False


# =============================================================================
# SET TEXT COMMAND
# =============================================================================


class SetTextCommand(Command):
    """Команда полной замены текста в tk.Text виджете.

    Attributes:
        _text_widget: Виджет tk.Text.
        _old_text: Предыдущий текст (для undo).
        _new_text: Новый текст.

    Example:
        >>> cmd = SetTextCommand(text_widget, "old", "new")
        >>> cmd.execute()
        >>> cmd.undo()  # Восстанавливает старый текст
    """

    def __init__(
        self,
        text_widget: tk.Text,
        old_text: str,
        new_text: str,
    ) -> None:
        """Инициализация команды замены текста.

        Args:
            text_widget: Виджет tk.Text.
            old_text: Предыдущий текст.
            new_text: Новый текст.

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        super().__init__("Set text")
        _validate_text_widget(text_widget)
        self._text_widget: tk.Text = text_widget
        self._old_text: str = old_text
        self._new_text: str = new_text

    def execute(self) -> None:
        """Заменяет текст на новый.

        Side Effects:
            - Устанавливает _is_executed = True.
        """
        self._text_widget.delete("1.0", "end")
        self._text_widget.insert("1.0", self._new_text)
        self._is_executed = True

    def undo(self) -> None:
        """Восстанавливает старый текст.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        self._text_widget.delete("1.0", "end")
        self._text_widget.insert("1.0", self._old_text)
        self._is_executed = False


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "InsertTextCommand",
    "DeleteTextCommand",
    "ApplyFormatCommand",
    "SetCPICommand",
    "SetTextCommand",
    "MAX_TEXT_LENGTH",
    "VALID_CPI_VALUES",
    "DEFAULT_CPI",
]
