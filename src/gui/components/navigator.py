"""Панель навигации по документу.

Модуль предоставляет панель для отображения текущей позиции курсора
и быстрой навигации по строкам документа.

Features:
    - Отображение текущей строки и колонки (Ln X, Col Y)
    - Отображение общего количества строк
    - Переход к конкретной строке (Go to line)
    - Быстрые кнопки: в начало / в конец
    - Валидация ввода

Example:
    >>> navigator = Navigator(
    ...     widget_id="doc_navigator",
    ...     controller=ctrl,
    ...     on_goto_line=lambda line: editor.goto_line(line),
    ...     on_goto_start=lambda: editor.goto_start(),
    ...     on_goto_end=lambda: editor.goto_end(),
    ... )
    >>> navigator.mount(parent_frame)
    >>> navigator.set_position(line=10, column=25)
    >>> navigator.set_total_lines(150)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from typing import Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.gui.layout.layout_constants import PADDING_NORMAL, PADDING_SMALL

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

# Размеры
NAVIGATOR_HEIGHT: Final[int] = 28
NAVIGATOR_BG_COLOR: Final[str] = "#f5f5f5"
NAVIGATOR_FG_COLOR: Final[str] = "#333333"
NAVIGATOR_ACCENT_COLOR: Final[str] = "#0078d4"

# Цвета индикатора double-height
DOUBLE_HEIGHT_INDICATOR_BG: Final[str] = "#d4edda"  # Светло-зелёный
DOUBLE_HEIGHT_INDICATOR_FG: Final[str] = "#155724"  # Тёмно-зелёный

# Шрифты
FONT_LABEL: Final[tuple[str, int]] = ("Segoe UI", 9)
FONT_VALUE: Final[tuple[str, int, str]] = ("Segoe UI", 9, "bold")

# Regex для валидации ввода номера строки
LINE_NUMBER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\d+$")

# Максимальное значение строки
MAX_LINE_NUMBER: Final[int] = 999999

# =============================================================================
# NAVIGATOR
# =============================================================================


class Navigator(BaseWidget):
    """Панель навигации по документу.

    Отображает текущую позицию курсора, общее количество строк
    и предоставляет элементы управления для быстрой навигации.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        on_goto_line: Callback при переходе к строке.
        on_goto_start: Callback при переходе в начало.
        on_goto_end: Callback при переходе в конец.

    Example:
        >>> navigator = Navigator(
        ...     widget_id="nav_main",
        ...     controller=ctrl,
        ...     on_goto_line=lambda line: print(f"Go to line {line}"),
        ... )
        >>> navigator.mount(parent)
        >>> navigator.set_position(line=1, column=1)
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        on_goto_line: Optional[Callable[[int], None]] = None,
        on_goto_start: Optional[Callable[[], None]] = None,
        on_goto_end: Optional[Callable[[], None]] = None,
        initial_line: int = 1,
        initial_column: int = 1,
        initial_total_lines: int = 1,
    ) -> None:
        """Инициализация панели навигации.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            on_goto_line: Callback при переходе к строке.
                Принимает номер строки (int).
            on_goto_start: Callback при переходе в начало документа.
            on_goto_end: Callback при переходе в конец документа.
            initial_line: Начальная строка (по умолчанию 1).
            initial_column: Начальная колонка (по умолчанию 1).
            initial_total_lines: Начальное общее количество строк.

        Raises:
            ValueError: Если line, column или total_lines < 1.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        if initial_line < 1:
            raise ValueError(f"Номер строки должен быть >= 1: {initial_line}")
        if initial_column < 1:
            raise ValueError(f"Номер колонки должен быть >= 1: {initial_column}")
        if initial_total_lines < 0:
            raise ValueError(f"Количество строк не может быть отрицательным: {initial_total_lines}")

        self._on_goto_line = on_goto_line
        self._on_goto_start = on_goto_start
        self._on_goto_end = on_goto_end
        self._on_highlight_line: Optional[Callable[[int, bool], None]] = None

        self._current_line: int = initial_line
        self._current_column: int = initial_column
        self._total_lines: int = max(initial_total_lines, 1)

        # Tkinter widgets
        self._frame: Optional[tk.Frame] = None
        self._position_label: Optional[tk.Label] = None
        self._lines_label: Optional[tk.Label] = None
        self._goto_entry: Optional[tk.Entry] = None
        self._double_height_indicator: Optional[tk.Label] = None

        # Double-height tracking
        self._is_current_line_double_height: bool = False

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт панель навигации.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный фрейм панели навигации.
        """
        # Основной фрейм
        self._frame = tk.Frame(
            parent,
            height=NAVIGATOR_HEIGHT,
            bg=NAVIGATOR_BG_COLOR,
        )
        self._frame.pack_propagate(False)

        # === Левая часть: позиция курсора ===
        pos_frame = tk.Frame(self._frame, bg=NAVIGATOR_BG_COLOR)
        pos_frame.pack(side=tk.LEFT, padx=(PADDING_NORMAL, PADDING_NORMAL * 2))

        # Ln X, Col Y
        self._position_label = tk.Label(
            pos_frame,
            text=self._format_position(),
            bg=NAVIGATOR_BG_COLOR,
            fg=NAVIGATOR_FG_COLOR,
            font=FONT_VALUE,
        )
        self._position_label.pack(side=tk.LEFT)

        # === Центральная часть: общее количество строк ===
        lines_frame = tk.Frame(self._frame, bg=NAVIGATOR_BG_COLOR)
        lines_frame.pack(side=tk.LEFT, padx=PADDING_NORMAL)

        tk.Label(
            lines_frame,
            text="Lines:",
            bg=NAVIGATOR_BG_COLOR,
            fg=NAVIGATOR_FG_COLOR,
            font=FONT_LABEL,
        ).pack(side=tk.LEFT, padx=(0, PADDING_SMALL))

        self._lines_label = tk.Label(
            lines_frame,
            text=str(self._total_lines),
            bg=NAVIGATOR_BG_COLOR,
            fg=NAVIGATOR_FG_COLOR,
            font=FONT_VALUE,
        )
        self._lines_label.pack(side=tk.LEFT)

        # === Индикатор double-height ===
        dh_frame = tk.Frame(self._frame, bg=NAVIGATOR_BG_COLOR)
        dh_frame.pack(side=tk.LEFT, padx=PADDING_NORMAL)

        self._double_height_indicator = tk.Label(
            dh_frame,
            text="2H",
            bg=NAVIGATOR_BG_COLOR,
            fg=NAVIGATOR_BG_COLOR,  # Невидим по умолчанию
            font=("Segoe UI", 8, "bold"),
            padx=4,
        )
        self._double_height_indicator.pack(side=tk.LEFT)

        # === Правая часть: Go to line ===
        goto_frame = tk.Frame(self._frame, bg=NAVIGATOR_BG_COLOR)
        goto_frame.pack(side=tk.RIGHT, padx=PADDING_NORMAL)

        # Label
        tk.Label(
            goto_frame,
            text="Go to line:",
            bg=NAVIGATOR_BG_COLOR,
            fg=NAVIGATOR_FG_COLOR,
            font=FONT_LABEL,
        ).pack(side=tk.LEFT, padx=(0, PADDING_SMALL))

        # Entry
        self._goto_entry = tk.Entry(
            goto_frame,
            width=6,
            justify=tk.RIGHT,
            font=FONT_LABEL,
        )
        self._goto_entry.pack(side=tk.LEFT, padx=(0, PADDING_SMALL))
        self._goto_entry.bind("<Return>", self._on_goto_entry_return)
        self._goto_entry.bind("<KP_Enter>", self._on_goto_entry_return)

        # Go button
        go_btn = tk.Button(
            goto_frame,
            text="Go",
            command=self._on_go_clicked,
            font=FONT_LABEL,
            padx=8,
        )
        go_btn.pack(side=tk.LEFT, padx=(0, PADDING_NORMAL))

        # Separator
        tk.Frame(
            goto_frame,
            width=1,
            height=NAVIGATOR_HEIGHT - 8,
            bg="#cccccc",
        ).pack(side=tk.LEFT, fill=tk.Y, padx=PADDING_NORMAL)

        # Navigation buttons
        btn_frame = tk.Frame(goto_frame, bg=NAVIGATOR_BG_COLOR)
        btn_frame.pack(side=tk.LEFT)

        # Start button (⏮)
        start_btn = tk.Button(
            btn_frame,
            text="⏮",
            command=self._on_start_clicked,
            font=FONT_LABEL,
            padx=6,
        )
        start_btn.pack(side=tk.LEFT, padx=(0, PADDING_SMALL))

        # End button (⏭)
        end_btn = tk.Button(
            btn_frame,
            text="⏭",
            command=self._on_end_clicked,
            font=FONT_LABEL,
            padx=6,
        )
        end_btn.pack(side=tk.LEFT)

        return self._frame

    def _setup_bindings(self) -> None:
        """Настраивает дополнительные bindings."""
        # Уже настроены в _create_tk_widget
        pass

    def _format_position(self) -> str:
        """Форматирует строку позиции.

        Returns:
            Строка в формате "Ln X, Col Y".
        """
        return f"Ln {self._current_line}, Col {self._current_column}"

    def _sanitize_line_input(self, value: str) -> Optional[int]:
        """Санитизирует и валидирует ввод номера строки.

        Args:
            value: Входная строка.

        Returns:
            Валидный номер строки или None если невалиден.
        """
        # Проверяем что это только цифры
        if not LINE_NUMBER_PATTERN.match(value):
            return None

        try:
            line_num = int(value)
        except ValueError:
            return None

        # Проверяем диапазон
        if line_num < 1 or line_num > MAX_LINE_NUMBER:
            return None

        return line_num

    def _on_goto_entry_return(self, event: tk.Event) -> None:
        """Обрабатывает нажатие Enter в поле ввода.

        Args:
            event: Событие клавиатуры.
        """
        self._on_go_clicked()

    def _on_go_clicked(self) -> None:
        """Обрабатывает нажатие кнопки Go."""
        if self._goto_entry is None:
            return

        value = self._goto_entry.get().strip()
        line_num = self._sanitize_line_input(value)

        if line_num is None:
            # Невалидный ввод — показываем ошибку и очищаем
            logger.warning("Невалидный ввод номера строки: %s", value)
            self._goto_entry.delete(0, tk.END)
            self._goto_entry.config(fg="red")
            if self._frame is not None:
                entry = self._goto_entry
                self._frame.after(500, lambda: entry.config(fg=NAVIGATOR_FG_COLOR))
            return

        # Ограничиваем существующими строками
        if line_num > self._total_lines:
            line_num = self._total_lines

        logger.debug("Переход к строке: %d", line_num)

        # Очищаем поле ввода
        self._goto_entry.delete(0, tk.END)

        # Вызываем callback
        if self._on_goto_line is not None:
            try:
                self._on_goto_line(line_num)
            except (AttributeError, TypeError, ValueError, KeyError, IndexError) as exc:
                logger.error("Ошибка в callback on_goto_line: %s", exc)

        # Отправляем через контроллер
        if self._controller is not None:
            self._controller.dispatch(
                "navigator_goto_line",
                line=line_num,
            )

    def _on_start_clicked(self) -> None:
        """Обрабатывает нажатие кнопки Start (⏮)."""
        logger.debug("Переход в начало документа")

        # Вызываем callback
        if self._on_goto_start is not None:
            try:
                self._on_goto_start()
            except Exception as exc:
                logger.error("Ошибка в callback on_goto_start: %s", exc)

        # Отправляем через контроллер
        if self._controller is not None:
            self._controller.dispatch("navigator_goto_start")

    def _on_end_clicked(self) -> None:
        """Обрабатывает нажатие кнопки End (⏭)."""
        logger.debug("Переход в конец документа")

        # Вызываем callback
        if self._on_goto_end is not None:
            try:
                self._on_goto_end()
            except Exception as exc:
                logger.error("Ошибка в callback on_goto_end: %s", exc)

        # Отправляем через контроллер
        if self._controller is not None:
            self._controller.dispatch("navigator_goto_end")

    def set_position(self, line: int, column: int) -> None:
        """Устанавливает текущую позицию курсора.

        Args:
            line: Номер строки (>= 1).
            column: Номер колонки (>= 1).

        Raises:
            ValueError: Если line или column < 1.

        Example:
            >>> navigator.set_position(line=10, column=25)
            >>> navigator.set_position(line=1, column=1)  # Start
        """
        if line < 1:
            raise ValueError(f"Номер строки должен быть >= 1: {line}")
        if column < 1:
            raise ValueError(f"Номер колонки должен быть >= 1: {column}")

        self._current_line = line
        self._current_column = column

        # Обновляем UI если смонтирован
        if self._is_mounted and self._position_label is not None:
            self._position_label.config(text=self._format_position())

        logger.debug("Обновлена позиция: Ln %d, Col %d", line, column)

    def set_total_lines(self, total: int) -> None:
        """Устанавливает общее количество строк.

        Args:
            total: Общее количество строк (>= 0).

        Raises:
            ValueError: Если total < 0.

        Example:
            >>> navigator.set_total_lines(150)
            >>> navigator.set_total_lines(1)  # Empty document
        """
        if total < 0:
            raise ValueError(f"Количество строк не может быть отрицательным: {total}")

        self._total_lines = max(total, 1)

        # Обновляем UI если смонтирован
        if self._is_mounted and self._lines_label is not None:
            self._lines_label.config(text=str(self._total_lines))

        logger.debug("Обновлено общее количество строк: %d", self._total_lines)

    def get_position(self) -> tuple[int, int]:
        """Возвращает текущую позицию курсора.

        Returns:
            Кортеж (line, column).
        """
        return (self._current_line, self._current_column)

    def get_total_lines(self) -> int:
        """Возвращает общее количество строк.

        Returns:
            Общее количество строк.
        """
        return self._total_lines

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._on_goto_line = None
        self._on_goto_start = None
        self._on_goto_end = None
        self._frame = None
        self._position_label = None
        self._lines_label = None
        self._goto_entry = None
        self._double_height_indicator = None
        self._on_highlight_line = None

    def set_on_highlight_line_callback(
        self,
        callback: Optional[Callable[[int, bool], None]],
    ) -> None:
        """Устанавливает callback для подсветки строки в Text widget.

        Вызывается при активации/деактивации double-height индикатора
        для подсветки следующей строки (shadow row).

        Args:
            callback: Функция, принимающая (line: int, highlight: bool).

        Example:
            >>> navigator.set_on_highlight_line_callback(
            ...     lambda line, hl: print(f"Highlight line {line}: {hl}")
            ... )
        """
        self._on_highlight_line = callback

    def set_double_height_indicator(self, is_double_height: bool) -> None:
        """Устанавливает индикатор double-height для текущей строки.

        Показывает или скрывает индикатор "2H" в зависимости от того,
        содержит ли текущая строка символы с двойной высотой.
        При активации вызывает обратную связь для подсветки
        следующей строки в Text widget (shadow row).

        Args:
            is_double_height: True если текущая строка содержит double-height.

        Example:
            >>> navigator.set_double_height_indicator(True)   # Показать "2H"
            >>> navigator.set_double_height_indicator(False)  # Скрыть индикатор
        """
        self._is_current_line_double_height = is_double_height

        if self._is_mounted and self._double_height_indicator is not None:
            if is_double_height:
                self._double_height_indicator.config(
                    bg=DOUBLE_HEIGHT_INDICATOR_BG,
                    fg=DOUBLE_HEIGHT_INDICATOR_FG,
                )
            else:
                self._double_height_indicator.config(
                    bg=NAVIGATOR_BG_COLOR,
                    fg=NAVIGATOR_BG_COLOR,
                )

        # Обратная связь: подсвечиваем следующую строку в Text widget
        if self._on_highlight_line is not None:
            try:
                next_line = self._current_line + 1
                self._on_highlight_line(next_line, is_double_height)
            except Exception as exc:
                logger.debug("Ошибка в callback подсветки строки: %s", exc, exc_info=True)

        logger.debug("Индикатор double-height: %s", is_double_height)

    def is_double_height_indicator_active(self) -> bool:
        """Проверяет, активен ли индикатор double-height.

        Returns:
            True если индикатор "2H" активен.

        Example:
            >>> navigator.is_double_height_indicator_active()
            True
        """
        return self._is_current_line_double_height


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "Navigator",
    "NAVIGATOR_HEIGHT",
    "MAX_LINE_NUMBER",
]
