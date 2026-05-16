"""Команды для вставки штрих-кодов и QR-кодов в редактор.

Реализует паттерн Command для операций со штрих-кодами:
- InsertBarcodeCommand: Вставка штрих-кода как изображения.
- InsertQRCommand: Вставка QR-кода как изображения.
- InsertPlaceholderCommand: Вставка текстового placeholder для штрих-кода.

Security:
    - marker_type и data обрезаются для защиты от DoS.
    - Проверка типа виджета (должен быть tk.Text).

Example:
    >>> cmd = InsertPlaceholderCommand(text_widget, "QR", "https://example.com", "1.0")
    >>> cmd.execute()
    >>> cmd.undo()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Final

from src.gui.core.commands.command import Command

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_MARKER_TYPE_LENGTH: Final[int] = 20
"""Максимальная длина типа маркера (security: DoS protection)."""

MAX_DATA_LENGTH: Final[int] = 50
"""Максимальная длина данных placeholder (security: DoS protection)."""


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
# INSERT BARCODE COMMAND
# =============================================================================


class InsertBarcodeCommand(Command):
    """Команда вставки штрих-кода как изображения.

    Attributes:
        _text_widget: Виджет tk.Text.
        _image: Изображение штрих-кода (tk.PhotoImage).
        _index: Позиция вставки.
        _start_index: Начальная позиция после вставки.
        _end_index: Конечная позиция после вставки.

    Example:
        >>> cmd = InsertBarcodeCommand(text_widget, photo_image, "1.0")
        >>> cmd.execute()
        >>> cmd.undo()  # Удаляет изображение
    """

    def __init__(
        self,
        text_widget: tk.Text,
        image: tk.PhotoImage,
        index: str,
    ) -> None:
        """Инициализация команды вставки штрих-кода.

        Args:
            text_widget: Виджет tk.Text.
            image: Изображение штрих-кода (tk.PhotoImage).
            index: Позиция вставки.

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        super().__init__("Insert barcode image")
        _validate_text_widget(text_widget)
        self._text_widget: tk.Text = text_widget
        self._image: tk.PhotoImage | None = image
        self._index: str = index
        self._start_index: str | None = None
        self._end_index: str | None = None

    def execute(self) -> None:
        """Вставляет изображение штрих-кода в текстовый виджет.

        Side Effects:
            - Устанавливает _start_index и _end_index.
            - Устанавливает _is_executed = True.
        """
        self._start_index = self._index
        assert self._image is not None
        self._text_widget.image_create(self._index, image=self._image)
        self._end_index = self._text_widget.index(f"{self._index} + 1 chars")
        self._is_executed = True

    def undo(self) -> None:
        """Удаляет вставленное изображение.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        if self._start_index is not None and self._end_index is not None:
            self._text_widget.delete(self._start_index, self._end_index)
        self._image = None
        self._is_executed = False


# =============================================================================
# INSERT QR COMMAND
# =============================================================================


class InsertQRCommand(Command):
    """Команда вставки QR-кода как изображения.

    Attributes:
        _text_widget: Виджет tk.Text.
        _image: Изображение QR-кода (tk.PhotoImage).
        _index: Позиция вставки.
        _start_index: Начальная позиция после вставки.
        _end_index: Конечная позиция после вставки.

    Example:
        >>> cmd = InsertQRCommand(text_widget, photo_image, "1.0")
        >>> cmd.execute()
        >>> cmd.undo()  # Удаляет QR изображение
    """

    def __init__(
        self,
        text_widget: tk.Text,
        image: tk.PhotoImage,
        index: str,
    ) -> None:
        """Инициализация команды вставки QR-кода.

        Args:
            text_widget: Виджет tk.Text.
            image: Изображение QR-кода (tk.PhotoImage).
            index: Позиция вставки.

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        super().__init__("Insert QR image")
        _validate_text_widget(text_widget)
        self._text_widget: tk.Text = text_widget
        self._image: tk.PhotoImage | None = image
        self._index: str = index
        self._start_index: str | None = None
        self._end_index: str | None = None

    def execute(self) -> None:
        """Вставляет изображение QR-кода в текстовый виджет.

        Side Effects:
            - Устанавливает _start_index и _end_index.
            - Устанавливает _is_executed = True.
        """
        self._start_index = self._index
        assert self._image is not None
        self._text_widget.image_create(self._index, image=self._image)
        self._end_index = self._text_widget.index(f"{self._index} + 1 chars")
        self._is_executed = True

    def undo(self) -> None:
        """Удаляет вставленное QR изображение.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        if self._start_index is not None and self._end_index is not None:
            self._text_widget.delete(self._start_index, self._end_index)
        self._image = None
        self._is_executed = False


# =============================================================================
# INSERT PLACEHOLDER COMMAND
# =============================================================================


class InsertPlaceholderCommand(Command):
    """Команда вставки текстового placeholder для штрих-кода.

    Attributes:
        _text_widget: Виджет tk.Text.
        _marker_type: Тип маркера (например, "BARCODE:CODE128").
        _data: Данные для штрих-кода.
        _index: Позиция вставки.
        _end_index: Конечная позиция после вставки.

    Example:
        >>> cmd = InsertPlaceholderCommand(text_widget, "QR", "https://example.com", "1.0")
        >>> cmd.execute()
        >>> cmd.undo()  # Удаляет placeholder
    """

    def __init__(
        self,
        text_widget: tk.Text,
        marker_type: str,
        data: str,
        index: str,
    ) -> None:
        """Инициализация команды вставки placeholder.

        Args:
            text_widget: Виджет tk.Text.
            marker_type: Тип маркера (например, "BARCODE:CODE128").
            data: Данные для штрих-кода.
            index: Позиция вставки.

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        super().__init__(f"Insert placeholder {marker_type}")
        _validate_text_widget(text_widget)
        self._text_widget: tk.Text = text_widget
        self._marker_type: str = marker_type[:MAX_MARKER_TYPE_LENGTH]
        self._data: str = data[:MAX_DATA_LENGTH]
        self._index: str = index
        self._end_index: str | None = None

    def execute(self) -> None:
        """Вставляет placeholder текст в виджет.

        Формат: ┇{marker_type}:{data}┇

        Side Effects:
            - Устанавливает _end_index.
            - Устанавливает _is_executed = True.
        """
        placeholder = f"┇{self._marker_type}:{self._data}┇"
        self._text_widget.insert(self._index, placeholder)
        self._end_index = self._text_widget.index(f"{self._index} + {len(placeholder)} chars")
        self._is_executed = True

    def undo(self) -> None:
        """Удаляет вставленный placeholder.

        Raises:
            RuntimeError: Если команда не была выполнена.
        """
        if not self._is_executed:
            raise RuntimeError("execute() должен быть вызван перед undo()")
        if self._end_index is not None:
            self._text_widget.delete(self._index, self._end_index)
        self._is_executed = False


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "InsertBarcodeCommand",
    "InsertQRCommand",
    "InsertPlaceholderCommand",
    "MAX_MARKER_TYPE_LENGTH",
    "MAX_DATA_LENGTH",
]
