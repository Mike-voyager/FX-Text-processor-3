"""Индикатор прогресса с текстом.

Модуль предоставляет ProgressIndicator — compound-виджет
прогресс-бара с текстовым статусом.

Example:
    >>> pi = ProgressIndicator(
    ...     widget_id="upload_progress",
    ...     show_text=True,
    ...     determinate=True
    ... )
    >>> pi.mount(parent)
    >>> pi.set_progress(0.5, "Загрузка...")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol


class ProgressIndicator(BaseWidget):
    """Прогресс-бар с текстовым статусом.

    Реализует compound-виджет:
    - Визуальный прогресс-бар (Canvas)
    - Текстовый статус
    - Детерминированный и индетерминированный режимы

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _show_text: Показывать ли текстовый статус.
        _determinate: Детерминированный режим.
        _progress: Текущий прогресс (0.0–1.0).
        _status_text: Текущий текст статуса.
    """

    def __init__(
        self,
        widget_id: str,
        show_text: bool = True,
        determinate: bool = True,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализирует индикатор прогресса.

        Args:
            widget_id: Уникальный идентификатор виджета.
            show_text: Показывать ли текстовый статус.
            determinate: Детерминированный режим по умолчанию.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._show_text: bool = show_text
        self._determinate: bool = determinate
        self._progress: float = 0.0
        self._status_text: str = ""
        self._indeterminate_running: bool = False
        self._after_id: Optional[str] = None

        self._canvas: Optional[tk.Canvas] = None
        self._label: Optional[tk.Label] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame с прогресс-баром и текстом.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame.
        """
        frame = tk.Frame(parent)

        bar_height = 16
        bar_width = 200

        self._canvas = tk.Canvas(
            frame,
            width=bar_width,
            height=bar_height,
            bg="#E0E0E0",
            highlightthickness=0,
        )
        self._canvas.pack(fill=tk.X, expand=True)

        if self._show_text:
            self._label = tk.Label(
                frame,
                text=self._status_text,
                font=("Courier", 9),
                anchor=tk.W,
            )
            self._label.pack(fill=tk.X, pady=(2, 0))

        self._draw_bar()
        return frame

    def _setup_bindings(self) -> None:
        """Нет специфичных bindings."""
        pass

    def set_progress(self, value: float, text: str = "") -> None:
        """Устанавливает прогресс и текст.

        Args:
            value: Значение прогресса (0.0–1.0).
            text: Текст статуса.
        """
        self._progress = max(0.0, min(1.0, value))
        if text:
            self._status_text = text
        self._determinate = True
        self._stop_indeterminate()
        self._draw_bar()
        if self._label is not None:
            self._label.config(text=self._status_text)

    def set_indeterminate(self, running: bool) -> None:
        """Устанавливает индетерминированный режим.

        Args:
            running: True для запуска анимации.
        """
        self._determinate = not running
        if running:
            self._start_indeterminate()
        else:
            self._stop_indeterminate()
            self._draw_bar()

    def set_text(self, text: str) -> None:
        """Устанавливает текст статуса.

        Args:
            text: Новый текст.
        """
        self._status_text = text
        if self._label is not None:
            self._label.config(text=text)

    def _draw_bar(self) -> None:
        """Перерисовывает прогресс-бар."""
        if self._canvas is None:
            return
        self._canvas.delete("all")
        width = int(self._canvas.winfo_width() or 200)
        height = int(self._canvas.winfo_height() or 16)
        if width <= 1:
            width = 200
        if height <= 1:
            height = 16

        if self._determinate:
            fill_width = int(width * self._progress)
            self._canvas.create_rectangle(0, 0, width, height, fill="#E0E0E0", outline="")
            self._canvas.create_rectangle(0, 0, fill_width, height, fill="#4CAF50", outline="")
        else:
            self._canvas.create_rectangle(0, 0, width, height, fill="#E0E0E0", outline="")

    def _start_indeterminate(self) -> None:
        """Запускает индетерминированную анимацию."""
        self._indeterminate_running = True
        self._animate_step()

    def _animate_step(self) -> None:
        """Один шаг индетерминированной анимации."""
        if not self._indeterminate_running or self._canvas is None:
            return
        self._canvas.delete("all")
        width = int(self._canvas.winfo_width() or 200)
        height = int(self._canvas.winfo_height() or 16)
        if width <= 1:
            width = 200
        if height <= 1:
            height = 16
        segment = width // 4
        offset = (self._canvas.winfo_x() // 2) % (width + segment) - segment
        self._canvas.create_rectangle(0, 0, width, height, fill="#E0E0E0", outline="")
        self._canvas.create_rectangle(
            offset,
            0,
            offset + segment,
            height,
            fill="#2196F3",
            outline="",
        )
        self._after_id = self._canvas.after(100, self._animate_step)

    def _stop_indeterminate(self) -> None:
        """Останавливает анимацию."""
        self._indeterminate_running = False
        if self._after_id is not None and self._canvas is not None:
            try:
                self._canvas.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании."""
        self._stop_indeterminate()
        self._canvas = None
        self._label = None


__all__: list[str] = ["ProgressIndicator"]
