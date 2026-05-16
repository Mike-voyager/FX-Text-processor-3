"""Бейдж статуса (цветная pill с текстом).

Модуль предоставляет StatusBadge — compound-виджет
для отображения цветного статуса.

Example:
    >>> badge = StatusBadge(widget_id="status", text="Активен", variant="success")
    >>> badge.mount(parent)
    >>> badge.set_variant("error")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol

_STATUS_COLORS: dict[str, tuple[str, str]] = {
    "default": ("#9E9E9E", "#FFFFFF"),
    "success": ("#4CAF50", "#FFFFFF"),
    "warning": ("#FF9800", "#FFFFFF"),
    "error": ("#F44336", "#FFFFFF"),
    "info": ("#2196F3", "#FFFFFF"),
}


class StatusBadge(BaseWidget):
    """Colorной статус-бейдж.

    Отображает текст внутри pill-области с configurable цветом.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _text: Текущий текст бейджа.
        _variant: Текущий вариант стиля.
    """

    def __init__(
        self,
        widget_id: str,
        text: str = "",
        variant: str = "default",
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализирует статус-бейдж.

        Args:
            widget_id: Уникальный идентификатор виджета.
            text: Начальный текст.
            variant: Вариант стиля (default/success/warning/error/info).
            controller: Опциональная ссылка на контроллер.

        Raises:
            ValueError: Если variant неизвестен.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        if variant not in _STATUS_COLORS:
            raise ValueError(f"Unknown variant: {variant}")
        self._text: str = text
        self._variant: str = variant
        self._label: Optional[tk.Label] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт pill-фрейм с текстом.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame.
        """
        bg, fg = _STATUS_COLORS[self._variant]
        frame = tk.Frame(parent, bg=bg, bd=0)
        frame.config(highlightbackground=bg, highlightthickness=4, highlightcolor=bg)

        self._label = tk.Label(
            frame,
            text=self._text,
            bg=bg,
            fg=fg,
            font=("Courier", 9, "bold"),
            padx=8,
            pady=2,
        )
        self._label.pack()
        return frame

    def _setup_bindings(self) -> None:
        """Нет специфичных bindings."""
        pass

    def set_text(self, text: str) -> None:
        """Устанавливает текст бейджа.

        Args:
            text: Новый текст.
        """
        self._text = text
        if self._label is not None:
            self._label.config(text=text)

    def set_variant(self, variant: str) -> None:
        """Устанавливает вариант стиля.

        Args:
            variant: Новый вариант (default/success/warning/error/info).

        Raises:
            ValueError: Если variant неизвестен.
        """
        if variant not in _STATUS_COLORS:
            raise ValueError(f"Unknown variant: {variant}")
        self._variant = variant
        if self._tk_widget is not None and self._label is not None:
            bg, fg = _STATUS_COLORS[variant]
            self._tk_widget.config(  # type: ignore[attr-defined]
                bg=bg, highlightbackground=bg, highlightcolor=bg
            )
            self._label.config(bg=bg, fg=fg)

    def _cleanup(self) -> None:
        """Очищает ссылку на label."""
        self._label = None


__all__: list[str] = ["StatusBadge"]
