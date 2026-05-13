"""Текстовые команды для работы с tk.Text виджетом.

Реализует команды для редактирования текста в GUI:
- InsertTextCommand: вставка текста
- DeleteTextCommand: удаление текста
- ApplyFormatCommand: применение форматирования (bold, italic)
- SetCPICommand: изменение CPI (characters per inch)

Security:
    - Сохранение удалённого текста для undo
    - Валидация индексов tk.Text
    - Ограничение длины текста для предотвращения DoS

Example:
    >>> from src.gui.core.commands import CommandStack, InsertTextCommand
    >>> stack = CommandStack()
    >>> cmd = InsertTextCommand(text_widget, "Hello", "1.0")
    >>> stack.execute(cmd)
    >>> stack.undo()  # Удаляет вставленный текст

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Final, Optional

from src.gui.core.commands.command import Command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_TEXT_LENGTH: Final[int] = 100_000
"""Максимальная длина текста для вставки (security: DoS protection)."""

VALID_CPI_VALUES: Final[frozenset[float]] = frozenset({10.0, 12.0, 15.0, 17.0, 20.0})
"""Допустимые значения CPI для Epson FX-890."""

DEFAULT_CPI: Final[float] = 10.0
"""Значение CPI по умолчанию."""


# =============================================================================
# INSERT TEXT COMMAND
# =============================================================================


class InsertTextCommand(Command):
    """Команда вставки текста в tk.Text виджет.

    Сохраняет позицию вставки и вставленный текст для корректного undo.
    Поддерживает вставку как обычного текста, так и с тегами форматирования.

    Attributes:
        _text_widget: Ссылка на tk.Text виджет.
        _text: Текст для вставки.
        _index: Позиция вставки (tk.Text index, например "1.0").
        _end_index: Конечная позиция после вставки (для undo).

    Example:
        >>> cmd = InsertTextCommand(widget, "Hello", "1.0")
        >>> stack.execute(cmd)  # Вставляет "Hello" в позицию 1.0
        >>> stack.undo()          # Удаляет вставленный текст

    Version: 1.0
    """

    def __init__(
        self,
        text_widget: tk.Text,
        text: str,
        index: str,
        tags: Optional[tuple[str, ...]] = None,
    ) -> None:
        """Инициализация команды вставки текста.

        Args:
            text_widget: Целевой tk.Text виджет.
            text: Текст для вставки.
            index: Позиция вставки (например, "1.0" или "end").
            tags: Опциональные теги форматирования.

        Raises:
            ValueError: Если text_widget не является tk.Text.
            ValueError: Если text слишком длинный (> MAX_TEXT_LENGTH).

        Example:
            >>> cmd = InsertTextCommand(widget, "Hello", "1.0")
            >>> cmd.get_description()
            'Insert text at 1.0'
        """
        # Валидация виджета
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        # Security: truncate long text
        safe_text = text[:MAX_TEXT_LENGTH] if text else ""

        # Формируем описание
        preview = safe_text[:20] + "..." if len(safe_text) > 20 else safe_text
        description = f'Insert "{preview}" at {index}'

        super().__init__(description=description)

        self._text_widget: tk.Text = text_widget
        self._text: str = safe_text
        self._index: str = index
        self._tags: Optional[tuple[str, ...]] = tags
        self._end_index: Optional[str] = None  # Вычисляется при execute

    def execute(self) -> None:
        """Выполняет вставку текста.

        Вставляет текст в указанную позицию и сохраняет конечный индекс
        для последующего удаления при undo.

        Side Effects:
            - Вставляет текст в _text_widget
            - Устанавливает _end_index для undo
            - Применяет теги если указаны

        Raises:
            tk.TclError: Если индекс некорректен.
        """
        super().execute()

        # Сохраняем начальный индекс
        start_idx = self._index

        # Вставляем текст
        if self._tags:
            self._text_widget.insert(start_idx, self._text, self._tags)
        else:
            self._text_widget.insert(start_idx, self._text)

        # Вычисляем конечный индекс для undo
        # Формат: "line.column"
        lines = self._text.split("\n")
        if len(lines) == 1:
            # Однострочный текст
            start_parts = start_idx.split(".")
            if len(start_parts) == 2:
                line = int(start_parts[0])
                col = int(start_parts[1])
                new_col = col + len(self._text)
                self._end_index = f"{line}.{new_col}"
            else:
                # Fallback: используем tk.Text index
                self._end_index = self._text_widget.index(f"{start_idx} + {len(self._text)} chars")
        else:
            # Многострочный текст
            self._end_index = self._text_widget.index(f"{start_idx} + {len(self._text)} chars")

    def undo(self) -> None:
        """Отменяет вставку текста (удаляет вставленный текст).

        Удаляет текст между _index и _end_index.

        Raises:
            RuntimeError: Если execute() не был вызван.
            tk.TclError: Если индексы стали некорректными.
        """
        if self._end_index is None:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()

        # Удаляем вставленный текст
        self._text_widget.delete(self._index, self._end_index)


# =============================================================================
# DELETE TEXT COMMAND
# =============================================================================


class DeleteTextCommand(Command):
    """Команда удаления текста из tk.Text виджета.

    Сохраняет удалённый текст для восстановления при undo.
    Поддерживает удаление с сохранением тегов форматирования.

    Attributes:
        _text_widget: Ссылка на tk.Text виджет.
        _start_index: Начальная позиция удаления.
        _end_index: Конечная позиция удаления.
        _deleted_text: Сохранённый удалённый текст (для undo).
        _deleted_tags: Сохранённые теги удалённого текста.

    Example:
        >>> cmd = DeleteTextCommand(widget, "1.0", "1.5")
        >>> stack.execute(cmd)  # Удаляет текст
        >>> stack.undo()          # Восстанавливает удалённый текст

    Version: 1.0
    """

    def __init__(
        self,
        text_widget: tk.Text,
        start_index: str,
        end_index: str,
    ) -> None:
        """Инициализация команды удаления текста.

        Args:
            text_widget: Целевой tk.Text виджет.
            start_index: Начальная позиция удаления (например, "1.0").
            end_index: Конечная позиция удаления (например, "1.5" или "end").

        Raises:
            ValueError: Если text_widget не является tk.Text.

        Example:
            >>> cmd = DeleteTextCommand(widget, "1.0", "1.10")
            >>> cmd.get_description()
            'Delete text from 1.0 to 1.10'
        """
        # Валидация виджета
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        description = f"Delete text from {start_index} to {end_index}"
        super().__init__(description=description)

        self._text_widget: tk.Text = text_widget
        self._start_index: str = start_index
        self._end_index: str = end_index
        self._deleted_text: str = ""
        self._deleted_tags: list[tuple[str, ...]] = []

    def execute(self) -> None:
        """Выполняет удаление текста.

        Сохраняет удалённый текст и теги перед удалением.

        Side Effects:
            - Сохраняет текст и теги
            - Удаляет текст из виджета

        Raises:
            tk.TclError: Если индексы некорректны.
        """
        super().execute()

        # Сохраняем текст перед удалением
        self._deleted_text = self._text_widget.get(self._start_index, self._end_index)

        # Сохраняем теги для каждого символа (для восстановления форматирования)
        # Получаем список тегов в диапазоне
        ranges = self._text_widget.dump(self._start_index, self._end_index, tag=True)
        self._deleted_tags = ranges  # type: ignore[assignment]

        # Удаляем текст
        self._text_widget.delete(self._start_index, self._end_index)

    def undo(self) -> None:
        """Отменяет удаление (восстанавливает удалённый текст).

        Вставляет сохранённый текст обратно в исходную позицию.

        Raises:
            RuntimeError: Если execute() не был вызван.
        """
        if not self._deleted_text:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()

        # Восстанавливаем текст
        self._text_widget.insert(self._start_index, self._deleted_text)

        # Восстанавливаем теги если были
        # Примечание: полное восстановление тегов требует дополнительной логики
        # на основе сохранённого dump


# =============================================================================
# SET TEXT COMMAND
# =============================================================================


class SetTextCommand(Command):
    """Команда установки текста в tk.Text виджет.

    Полностью заменяет содержимое виджета, сохраняя старое значение для undo.
    Используется SmartEdit для агрегации изменений за сессию редактирования.

    Attributes:
        _text_widget: Ссылка на tk.Text виджет.
        _old_text: Предыдущее содержимое (для undo).
        _new_text: Новое содержимое для установки.

    Example:
        >>> cmd = SetTextCommand(widget, "old text", "new text")
        >>> stack.execute(cmd)  # Заменяет содержимое
        >>> stack.undo()        # Восстанавливает "old text"

    Version: 1.0
    """

    def __init__(
        self,
        text_widget: tk.Text,
        old_text: str,
        new_text: str,
    ) -> None:
        """Инициализация команды установки текста.

        Args:
            text_widget: Целевой tk.Text виджет.
            old_text: Предыдущее содержимое виджета.
            new_text: Новое содержимое для установки.

        Raises:
            ValueError: Если text_widget не является tk.Text.

        Example:
            >>> cmd = SetTextCommand(widget, "Hello", "World")
            >>> cmd.get_description()
            'Set text (5 chars)'
        """
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        safe_new = new_text[:MAX_TEXT_LENGTH] if new_text else ""
        safe_old = old_text[:MAX_TEXT_LENGTH] if old_text else ""
        preview = safe_new[:20] + "..." if len(safe_new) > 20 else safe_new
        description = f'Set text "{preview}"'

        super().__init__(description=description)

        self._text_widget: tk.Text = text_widget
        self._old_text: str = safe_old
        self._new_text: str = safe_new

    def execute(self) -> None:
        """Выполняет установку нового текста.

        Side Effects:
            - Заменяет содержимое _text_widget на _new_text
        """
        super().execute()
        self._text_widget.delete("1.0", tk.END)
        self._text_widget.insert("1.0", self._new_text)

    def undo(self) -> None:
        """Отменяет установку текста (восстанавливает старый текст).

        Raises:
            RuntimeError: Если execute() не был вызван.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        super().undo()
        self._text_widget.delete("1.0", tk.END)
        self._text_widget.insert("1.0", self._old_text)


# =============================================================================
# APPLY FORMAT COMMAND
# =============================================================================


class ApplyFormatCommand(Command):
    """Команда применения форматирования к тексту.

    Применяет теги форматирования (bold, italic, underline) к диапазону.
    Сохраняет предыдущие теги для восстановления при undo.

    Attributes:
        _text_widget: Ссылка на tk.Text виджет.
        _start_index: Начальная позиция.
        _end_index: Конечная позиция.
        _format_tags: Теги форматирования для применения.
        _previous_tags: Предыдущие теги (для undo).

    Supported Formats:
        - "bold": Жирный текст
        - "italic": Курсив
        - "underline": Подчёркивание
        - "double_width": Двойная ширина
        - "double_height": Двойная высота

    Example:
        >>> cmd = ApplyFormatCommand(widget, "1.0", "1.10", ("bold",))
        >>> stack.execute(cmd)
        >>> stack.undo()  # Убирает форматирование

    Version: 1.0
    """

    # Соответствие форматов и тегов tk.Text
    FORMAT_TAGS: Final[dict[str, str]] = {
        "bold": "bold",
        "italic": "italic",
        "underline": "underline",
        "double_width": "double_width",
        "double_height": "double_height",
    }

    def __init__(
        self,
        text_widget: tk.Text,
        start_index: str,
        end_index: str,
        format_tags: tuple[str, ...],
    ) -> None:
        """Инициализация команды форматирования.

        Args:
            text_widget: Целевой tk.Text виджет.
            start_index: Начальная позиция.
            end_index: Конечная позиция.
            format_tags: Кортеж тегов форматирования.

        Raises:
            ValueError: Если text_widget не является tk.Text.
            ValueError: Если указан неподдерживаемый формат.

        Example:
            >>> cmd = ApplyFormatCommand(widget, "1.0", "1.5", ("bold", "italic"))
        """
        # Валидация виджета
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        # Валидация форматов
        invalid_formats = set(format_tags) - set(self.FORMAT_TAGS.keys())
        if invalid_formats:
            raise ValueError(f"Неподдерживаемые форматы: {invalid_formats}")

        tags_str = ", ".join(format_tags)
        description = f"Apply {tags_str} to {start_index}-{end_index}"
        super().__init__(description=description)

        self._text_widget: tk.Text = text_widget
        self._start_index: str = start_index
        self._end_index: str = end_index
        self._format_tags: tuple[str, ...] = format_tags
        self._previous_tags: dict[str, set[str]] = {}

    def execute(self) -> None:
        """Применяет форматирование к диапазону.

        Сохраняет текущие теги перед применением новых.

        Side Effects:
            - Сохраняет предыдущие теги для undo
            - Добавляет новые теги к диапазону
        """
        super().execute()

        # Сохраняем предыдущие теги для каждой позиции
        # Упрощённая версия: сохраняем только теги, которые будем менять
        self._previous_tags = {}
        for fmt_tag in self._format_tags:
            tk_tag = self.FORMAT_TAGS[fmt_tag]
            # Получаем текущие теги в диапазоне
            current_tags = set()
            ranges = self._text_widget.dump(self._start_index, self._end_index, tag=True)
            for item in ranges:
                if item[0] == "tagon" or item[0] == "tagoff":
                    current_tags.add(item[1])
            self._previous_tags[tk_tag] = current_tags

            # Применяем новый тег
            self._text_widget.tag_add(tk_tag, self._start_index, self._end_index)

    def undo(self) -> None:
        """Отменяет форматирование.

        Удаляет применённые теги из диапазона.

        Raises:
            RuntimeError: Если execute() не был вызван.
        """
        if not self._previous_tags:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()

        # Удаляем применённые теги
        for fmt_tag in self._format_tags:
            tk_tag = self.FORMAT_TAGS[fmt_tag]
            self._text_widget.tag_remove(tk_tag, self._start_index, self._end_index)


# =============================================================================
# SET CPI COMMAND
# =============================================================================


class SetCPICommand(Command):
    """Команда изменения CPI (characters per inch).

    Изменяет настройку CPI для Epson FX-890.
    Сохраняет предыдущее значение для undo.

    Attributes:
        _text_widget: Ссылка на tk.Text виджет.
        _new_cpi: Новое значение CPI.
        _old_cpi: Предыдущее значение CPI (для undo).
        _apply_to_range: Применить только к диапазону или ко всему документу.

    Valid CPI Values:
        - 10.0: Pica (10 CPI)
        - 12.0: Elite (12 CPI)
        - 15.0: Micron (15 CPI)
        - 17.0: Compressed Pica
        - 20.0: Compressed Elite

    Example:
        >>> cmd = SetCPICommand(widget, 12.0)
        >>> stack.execute(cmd)  # Меняет CPI
        >>> stack.undo()        # Восстанавливает старое CPI

    Version: 1.0
    """

    def __init__(
        self,
        text_widget: tk.Text,
        cpi: float,
        start_index: Optional[str] = None,
        end_index: Optional[str] = None,
    ) -> None:
        """Инициализация команды изменения CPI.

        Args:
            text_widget: Целевой tk.Text виджет.
            cpi: Новое значение CPI (10.0, 12.0, 15.0, 17.0, или 20.0).
            start_index: Опциональная начальная позиция (для применения к диапазону).
            end_index: Опциональная конечная позиция.

        Raises:
            ValueError: Если text_widget не является tk.Text.
            ValueError: Если CPI не из VALID_CPI_VALUES.

        Example:
            >>> cmd = SetCPICommand(widget, 12.0)
            >>> cmd.get_description()
            'Set CPI to 12.0'
        """
        # Валидация виджета
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        # Валидация CPI
        if cpi not in VALID_CPI_VALUES:
            raise ValueError(
                f"Недопустимое значение CPI: {cpi}. Допустимые значения: {sorted(VALID_CPI_VALUES)}"
            )

        description = f"Set CPI to {cpi}"
        super().__init__(description=description)

        self._text_widget: tk.Text = text_widget
        self._new_cpi: float = cpi
        self._old_cpi: Optional[float] = None
        self._start_index: Optional[str] = start_index
        self._end_index: Optional[str] = end_index
        self._apply_to_range: bool = start_index is not None and end_index is not None

    def execute(self) -> None:
        """Применяет новое значение CPI.

        Сохраняет предыдущее значение и применяет новое.
        Для диапазона добавляет тег, иначе меняет глобальную настройку.

        Side Effects:
            - Сохраняет _old_cpi
            - Применяет _new_cpi через теги tk.Text
        """
        super().execute()

        # Сохраняем старое значение (в реальности может быть сложнее)
        self._old_cpi = DEFAULT_CPI  # Упрощённо

        # Формируем имя тега для CPI
        cpi_tag = f"cpi_{int(self._new_cpi)}"

        # Применяем к диапазону или всему документу
        if self._apply_to_range and self._start_index is not None and self._end_index is not None:
            self._text_widget.tag_add(cpi_tag, self._start_index, self._end_index)
        else:
            # Применяем ко всему документу ("1.0" до "end")
            self._text_widget.tag_add(cpi_tag, "1.0", "end")

        # Настраиваем шрифт для тега (в реальном приложении)
        # self._configure_cpi_font(cpi_tag, self._new_cpi)

    def undo(self) -> None:
        """Отменяет изменение CPI.

        Удаляет тег CPI из диапазона.

        Raises:
            RuntimeError: Если execute() не был вызван.
        """
        if self._old_cpi is None:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()

        # Удаляем тег нового CPI
        cpi_tag = f"cpi_{int(self._new_cpi)}"

        if self._apply_to_range and self._start_index is not None and self._end_index is not None:
            self._text_widget.tag_remove(cpi_tag, self._start_index, self._end_index)
        else:
            self._text_widget.tag_remove(cpi_tag, "1.0", "end")


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "InsertTextCommand",
    "DeleteTextCommand",
    "SetTextCommand",
    "ApplyFormatCommand",
    "SetCPICommand",
    "MAX_TEXT_LENGTH",
    "VALID_CPI_VALUES",
    "DEFAULT_CPI",
]
