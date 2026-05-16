"""Навигатор документа для FX Text Processor 3.

Предоставляет виджет навигации по документу с:
- Отображением текущей позиции (строка, колонка)
- Полем ввода для перехода к строке
- Кнопками "В начало" и "В конец"
- Callback для внешней навигации

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_LINE_NUMBER: int = 999999
"""Максимальный допустимый номер строки."""

NAVIGATOR_HEIGHT: int = 28
"""Высота панели навигатора в пикселях."""

NAVIGATOR_BG_COLOR: str = "#d9d9d9"
"""Цвет фона панели навигатора."""

DOUBLE_HEIGHT_INDICATOR_BG: str = "#ff9800"
"""Цвет фона индикатора double-height."""

DOUBLE_HEIGHT_INDICATOR_FG: str = "#ffffff"
"""Цвет текста индикатора double-height."""


class Navigator(BaseWidget):
    """Навигатор по документу.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
    """

    def __init__(
        self,
        widget_id: str = "navigator",
        controller: Optional[ControllerProtocol] = None,
        *,
        initial_line: int = 1,
        initial_column: int = 1,
        initial_total_lines: int = 1,
        on_goto_line: Optional[Callable[[int], None]] = None,
        on_goto_start: Optional[Callable[[], None]] = None,
        on_goto_end: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация навигатора.

        Args:
            widget_id: Идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            initial_line: Начальная строка (>= 1).
            initial_column: Начальная колонка (>= 1).
            initial_total_lines: Общее количество строк (>= 0).
            on_goto_line: Callback при переходе к строке.
            on_goto_start: Callback при переходе в начало.
            on_goto_end: Callback при переходе в конец.

        Raises:
            ValueError: Если line или column < 1, или total_lines < 0.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        if initial_line < 1:
            raise ValueError("Номер строки должен быть >= 1")
        if initial_column < 1:
            raise ValueError("Номер колонки должен быть >= 1")
        if initial_total_lines < 0:
            raise ValueError("Количество строк не может быть отрицательным")

        self._line: int = initial_line
        self._column: int = initial_column
        self._total_lines: int = initial_total_lines

        self._on_goto_line: Optional[Callable[[int], None]] = on_goto_line
        self._on_goto_start: Optional[Callable[[], None]] = on_goto_start
        self._on_goto_end: Optional[Callable[[], None]] = on_goto_end

        # Double-height indicator state
        self._is_current_line_double_height: bool = False
        self._double_height_indicator: Optional[tk.Label] = None

        # Widget references (initialized in _create_tk_widget)
        self._position_label: Optional[tk.Label] = None
        self._goto_entry: Optional[tk.Entry] = None
        self._go_button: Optional[tk.Button] = None
        self._start_button: Optional[tk.Button] = None
        self._end_button: Optional[tk.Button] = None

    def _create_tk_widget(self, parent: Any) -> Any:
        """Создаёт панель навигатора.

        Args:
            parent: Родительский виджет.

        Returns:
            Frame с элементами навигации.
        """
        frame = tk.Frame(parent, height=NAVIGATOR_HEIGHT)
        frame.pack_propagate(False)

        # Position label
        self._position_label = tk.Label(
            frame,
            text=self._format_position(),
            font=("Courier", 10),
            padx=8,
        )
        self._position_label.pack(side=tk.LEFT, padx=(4, 8))

        # Separator
        separator = tk.Frame(frame, width=1, bg="gray60")
        separator.pack(side=tk.LEFT, fill=tk.Y, padx=4, pady=4)

        # Goto entry
        self._goto_entry = tk.Entry(frame, width=8, font=("Courier", 10))
        self._goto_entry.pack(side=tk.LEFT, padx=(4, 2))
        self._goto_entry.bind("<Return>", lambda _event: self._on_go_clicked())

        # Go button
        self._go_button = tk.Button(
            frame,
            text="Go",
            command=self._on_go_clicked,
            font=("Courier", 9),
            padx=6,
        )
        self._go_button.pack(side=tk.LEFT, padx=(0, 4))

        # Separator
        separator2 = tk.Frame(frame, width=1, bg="gray60")
        separator2.pack(side=tk.LEFT, fill=tk.Y, padx=4, pady=4)

        # Start button
        self._start_button = tk.Button(
            frame,
            text="|←",
            command=self._on_start_clicked,
            font=("Courier", 9),
            padx=6,
        )
        self._start_button.pack(side=tk.LEFT, padx=(0, 2))

        # End button
        self._end_button = tk.Button(
            frame,
            text="→|",
            command=self._on_end_clicked,
            font=("Courier", 9),
            padx=6,
        )
        self._end_button.pack(side=tk.LEFT, padx=(0, 4))

        # Double-height indicator (initially hidden)
        self._double_height_indicator = tk.Label(
            frame,
            text="",
            bg=NAVIGATOR_BG_COLOR,
            fg=NAVIGATOR_BG_COLOR,
            font=("Courier", 9),
            padx=4,
        )
        self._double_height_indicator.pack(side=tk.LEFT, padx=(0, 4))

        return frame

    def _setup_bindings(self) -> None:
        """Настраивает event bindings."""
        pass

    def _cleanup(self) -> None:
        """Очищает ресурсы."""
        self._position_label = None
        self._goto_entry = None
        self._go_button = None
        self._start_button = None
        self._end_button = None

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def get_position(self) -> tuple[int, int]:
        """Возвращает текущую позицию.

        Returns:
            Кортеж (строка, колонка).
        """
        return (self._line, self._column)

    def set_position(self, line: int, column: int) -> None:
        """Устанавливает позицию.

        Args:
            line: Номер строки (>= 1).
            column: Номер колонки (>= 1).

        Raises:
            ValueError: Если line или column < 1.
        """
        if line < 1:
            raise ValueError("Номер строки должен быть >= 1")
        if column < 1:
            raise ValueError("Номер колонки должен быть >= 1")

        self._line = line
        self._column = column

        if self._position_label is not None and self._position_label.winfo_exists():
            self._position_label.config(text=self._format_position())

    def get_total_lines(self) -> int:
        """Возвращает общее количество строк.

        Returns:
            Общее количество строк.
        """
        return self._total_lines

    def set_total_lines(self, total_lines: int) -> None:
        """Устанавливает общее количество строк.

        Args:
            total_lines: Новое количество строк (>= 0).

        Raises:
            ValueError: Если total_lines < 0.
        """
        if total_lines < 0:
            raise ValueError("Количество строк не может быть отрицательным")
        self._total_lines = total_lines

    def is_double_height_indicator_active(self) -> bool:
        """Проверяет, активен ли индикатор double-height.

        Returns:
            True если индикатор double-height активен.
        """
        return self._is_current_line_double_height

    def set_double_height_indicator(self, active: bool) -> None:
        """Устанавливает состояние индикатора double-height.

        Args:
            active: True для активации, False для скрытия.
        """
        self._is_current_line_double_height = active
        if self._double_height_indicator is not None:
            if active:
                self._double_height_indicator.config(
                    text="DH",
                    bg=DOUBLE_HEIGHT_INDICATOR_BG,
                    fg=DOUBLE_HEIGHT_INDICATOR_FG,
                )
            else:
                self._double_height_indicator.config(
                    text="",
                    bg=NAVIGATOR_BG_COLOR,
                    fg=NAVIGATOR_BG_COLOR,
                )

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _sanitize_line_input(self, text: str) -> Optional[int]:
        """Санитизирует ввод номера строки.

        Args:
            text: Текстовый ввод.

        Returns:
            Число или None если ввод невалиден.
        """
        if not text.isdigit():
            return None
        value = int(text)
        if value < 1 or value > MAX_LINE_NUMBER:
            return None
        return value

    def _format_position(self) -> str:
        """Форматирует текущую позицию для отображения.

        Returns:
            Строка вида "Ln 10, Col 25".
        """
        return f"Ln {self._line}, Col {self._column}"

    def _on_go_clicked(self) -> None:
        """Обработчик кнопки перехода к строке."""
        if self._goto_entry is None:
            return
        text = self._goto_entry.get()
        line = self._sanitize_line_input(text)
        if line is not None:
            self.set_position(line, self._column)
            if self._on_goto_line is not None:
                self._on_goto_line(line)

    def _on_start_clicked(self) -> None:
        """Обработчик кнопки перехода в начало."""
        self.set_position(1, 1)
        if self._on_goto_start is not None:
            self._on_goto_start()

    def _on_end_clicked(self) -> None:
        """Обработчик кнопки перехода в конец."""
        if self._total_lines > 0:
            self.set_position(self._total_lines, self._column)
        if self._on_goto_end is not None:
            self._on_goto_end()


__all__ = [
    "MAX_LINE_NUMBER",
    "NAVIGATOR_HEIGHT",
    "Navigator",
]
