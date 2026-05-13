"""Команды для вставки штрих-кодов и QR-кодов в tk.Text виджет.

Реализует undo/redo поддержку для вставки:
- InsertBarcodeCommand: вставка PhotoImage штрих-кода через image_create
- InsertQRCommand: вставка PhotoImage QR-кода через image_create
- InsertPlaceholderCommand: вставка текстового placeholder (wrapper над InsertTextCommand)

Security:
    - Очистка ссылок на PhotoImage при undo для предотвращения утечек памяти
    - Ограничение длины описания команды через MAX_DESCRIPTION_LENGTH

Example:
    >>> from src.gui.core.commands.barcode_commands import InsertBarcodeCommand
    >>> cmd = InsertBarcodeCommand(text_widget, photo_image, "1.0")
    >>> stack.execute(cmd)
    >>> stack.undo()  # Удаляет изображение и очищает ссылку

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
import uuid
from typing import Optional

from src.gui.core.commands.command import Command
from src.gui.core.commands.text_commands import InsertTextCommand

# =============================================================================
# INSERT BARCODE COMMAND
# =============================================================================


class InsertBarcodeCommand(Command):
    """Команда вставки изображения штрих-кода в tk.Text виджет.

    Создаёт встроенное изображение через image_create и поддерживает
    undo/redo через удаление по сохранённым индексам.

    Attributes:
        _text_widget: Целевой tk.Text виджет.
        _image: PhotoImage для вставки.
        _position: Начальная позиция вставки (expression).
        _name: Уникальное имя anchor изображения.
        _start_index: Реальный индекс после выполнения.
        _end_index: Конечный индекс для удаления (start + 1 char).

    Example:
        >>> cmd = InsertBarcodeCommand(widget, photo, "1.0")
        >>> stack.execute(cmd)
        >>> stack.undo()  # Удаляет изображение
    """

    def __init__(
        self,
        text_widget: tk.Text,
        image: tk.PhotoImage,
        position: str,
    ) -> None:
        """Инициализация команды вставки штрих-кода.

        Args:
            text_widget: Целевой tk.Text виджет.
            image: Сгенерированное PhotoImage.
            position: Позиция вставки (например, "1.0" или tk.INSERT).

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        super().__init__(description=f"Insert barcode image at {position}")

        self._text_widget: tk.Text = text_widget
        self._image: Optional[tk.PhotoImage] = image
        self._position: str = position
        self._name: str = f"barcode_{uuid.uuid4().hex}"
        self._start_index: Optional[str] = None
        self._end_index: Optional[str] = None

    def execute(self) -> None:
        """Выполняет вставку изображения штрих-кода.

        Сохраняет реальный индекс вставки и конечный индекс для
        последующего удаления при undo.

        Side Effects:
            - Вставляет image в _text_widget
            - Устанавливает _start_index и _end_index
        """
        super().execute()

        assert self._image is not None, "PhotoImage не должен быть None при execute()"

        # Разрешаем позицию в реальный индекс
        self._start_index = self._text_widget.index(self._position)

        self._text_widget.image_create(
            self._start_index,
            image=self._image,
            name=self._name,
        )

        # Изображение занимает 1 символ
        self._end_index = f"{self._start_index} + 1 chars"

    def undo(self) -> None:
        """Отменяет вставку изображения штрих-кода.

        Удаляет встроенное изображение по сохранённому диапазону
        и очищает ссылку на PhotoImage для GC.

        Raises:
            RuntimeError: Если execute() не был вызван.
        """
        if self._start_index is None or self._end_index is None:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()

        self._text_widget.delete(self._start_index, self._end_index)
        self._image = None


# =============================================================================
# INSERT QR COMMAND
# =============================================================================


class InsertQRCommand(Command):
    """Команда вставки изображения QR-кода в tk.Text виджет.

    Аналогична InsertBarcodeCommand, но для QR-кодов.

    Attributes:
        _text_widget: Целевой tk.Text виджет.
        _image: PhotoImage для вставки.
        _position: Начальная позиция вставки.
        _name: Уникальное имя anchor изображения.
        _start_index: Реальный индекс после выполнения.
        _end_index: Конечный индекс для удаления.

    Example:
        >>> cmd = InsertQRCommand(widget, photo, "1.0")
        >>> stack.execute(cmd)
        >>> stack.undo()
    """

    def __init__(
        self,
        text_widget: tk.Text,
        image: tk.PhotoImage,
        position: str,
    ) -> None:
        """Инициализация команды вставки QR-кода.

        Args:
            text_widget: Целевой tk.Text виджет.
            image: Сгенерированное PhotoImage.
            position: Позиция вставки.

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        super().__init__(description=f"Insert QR image at {position}")

        self._text_widget: tk.Text = text_widget
        self._image: Optional[tk.PhotoImage] = image
        self._position: str = position
        self._name: str = f"qr_{uuid.uuid4().hex}"
        self._start_index: Optional[str] = None
        self._end_index: Optional[str] = None

    def execute(self) -> None:
        """Выполняет вставку изображения QR-кода.

        Side Effects:
            - Вставляет image в _text_widget
            - Устанавливает _start_index и _end_index
        """
        super().execute()

        assert self._image is not None, "PhotoImage не должен быть None при execute()"

        self._start_index = self._text_widget.index(self._position)

        self._text_widget.image_create(
            self._start_index,
            image=self._image,
            name=self._name,
        )

        self._end_index = f"{self._start_index} + 1 chars"

    def undo(self) -> None:
        """Отменяет вставку изображения QR-кода.

        Raises:
            RuntimeError: Если execute() не был вызван.
        """
        if self._start_index is None or self._end_index is None:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()

        self._text_widget.delete(self._start_index, self._end_index)
        self._image = None


# =============================================================================
# INSERT PLACEHOLDER COMMAND
# =============================================================================


class InsertPlaceholderCommand(Command):
    """Команда вставки placeholder текста штрих-кода или QR-кода.

    Обёртка над InsertTextCommand для вставки маркера вида
    ┇BARCODE:TYPE:DATA┇ или ┇QR:DATA┇.

    Attributes:
        _text_widget: Целевой tk.Text виджет.
        _placeholder_text: Текст placeholder для вставки.
        _position: Позиция вставки.
        _inner: Внутренняя команда InsertTextCommand.

    Example:
        >>> cmd = InsertPlaceholderCommand(widget, "BARCODE", "CODE128", "123", "1.0")
        >>> stack.execute(cmd)
        >>> stack.undo()
    """

    def __init__(
        self,
        text_widget: tk.Text,
        marker_type: str,
        data: str,
        position: str,
    ) -> None:
        """Инициализация команды вставки placeholder.

        Args:
            text_widget: Целевой tk.Text виджет.
            marker_type: Тип маркера ("BARCODE" или "QR").
            data: Данные для кодирования.
            position: Позиция вставки.

        Raises:
            ValueError: Если text_widget не является tk.Text.
        """
        if not isinstance(text_widget, tk.Text):
            widget_type = type(text_widget).__name__
            raise ValueError(f"text_widget должен быть tk.Text, получен {widget_type}")

        safe_marker = marker_type[:20]
        safe_data = data[:50]
        preview = f"┇{safe_marker}:{safe_data}┇"
        super().__init__(description=f'Insert placeholder "{preview}" at {position}')

        self._text_widget: tk.Text = text_widget
        self._marker_type: str = safe_marker
        self._data: str = safe_data
        self._position: str = position
        self._inner: Optional[InsertTextCommand] = None

    def execute(self) -> None:
        """Выполняет вставку placeholder текста.

        Создаёт InsertTextCommand и выполняет её для вставки
        маркера в текстовый виджет.

        Side Effects:
            - Создаёт и выполняет внутреннюю InsertTextCommand
        """
        super().execute()

        placeholder_text = f"┇{self._marker_type}:{self._data}┇"
        self._inner = InsertTextCommand(
            self._text_widget,
            placeholder_text,
            self._position,
        )
        self._inner.execute()

    def undo(self) -> None:
        """Отменяет вставку placeholder текста.

        Делегирует undo внутренней InsertTextCommand.

        Raises:
            RuntimeError: Если execute() не был вызван.
        """
        if self._inner is None:
            raise RuntimeError("execute() должен быть вызван перед undo()")

        super().undo()
        self._inner.undo()


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "InsertBarcodeCommand",
    "InsertQRCommand",
    "InsertPlaceholderCommand",
]
