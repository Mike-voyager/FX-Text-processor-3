"""Плитка списка с иконкой, заголовком и подзаголовком.

Модуль предоставляет ListTile — compound-виджет в стиле Material Design.

Example:
    >>> tile = ListTile(
    ...     widget_id="user_tile",
    ...     title="Иванов И.И.",
    ...     subtitle="Администратор",
    ...     icon="👤",
    ...     on_click=lambda: print("Clicked")
    ... )
    >>> tile.mount(parent)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol

ClickCallback = Optional[Callable[[], None]]


class ListTile(BaseWidget):
    """Плитка списка в стиле Material Design.

    Реализует compound-виджет:
    - Иконка (слева)
    - Заголовок и подзаголовок (центр)
    - Опциональный on_click callback
    - Подсветка при выборе

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _title: Текст заголовка.
        _subtitle: Текст подзаголовка.
        _icon: Текст иконки (emoji).
        _on_click: Callback при клике.
        _selected: Флаг выделения.
    """

    def __init__(
        self,
        widget_id: str,
        title: str,
        subtitle: str = "",
        icon: str = "",
        on_click: ClickCallback = None,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализирует плитку списка.

        Args:
            widget_id: Уникальный идентификатор виджета.
            title: Заголовок плитки.
            subtitle: Подзаголовок плитки.
            icon: Иконка (emoji или текст).
            on_click: Callback при клике по плитке.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._title: str = title
        self._subtitle: str = subtitle
        self._icon: str = icon
        self._on_click: ClickCallback = on_click
        self._selected: bool = False

        self._icon_label: Optional[tk.Label] = None
        self._title_label: Optional[tk.Label] = None
        self._subtitle_label: Optional[tk.Label] = None
        self._frame: Optional[tk.Frame] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame с иконкой, заголовком и подзаголовком.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame.
        """
        self._frame = tk.Frame(
            parent,
            relief=tk.FLAT,
            bd=0,
            padx=8,
            pady=6,
            bg="#FFFFFF",
            cursor="hand2" if self._on_click else "arrow",
        )

        # Icon
        self._icon_label = tk.Label(
            self._frame,
            text=self._icon,
            font=("Courier", 14),
            bg="#FFFFFF",
            width=2,
        )
        self._icon_label.pack(side=tk.LEFT, padx=(0, 8))

        # Text column
        text_frame = tk.Frame(self._frame, bg="#FFFFFF")
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._title_label = tk.Label(
            text_frame,
            text=self._title,
            font=("Courier", 10, "bold"),
            bg="#FFFFFF",
            fg="#000000",
            anchor=tk.W,
        )
        self._title_label.pack(fill=tk.X)

        if self._subtitle:
            self._subtitle_label = tk.Label(
                text_frame,
                text=self._subtitle,
                font=("Courier", 9),
                bg="#FFFFFF",
                fg="#666666",
                anchor=tk.W,
            )
            self._subtitle_label.pack(fill=tk.X)

        self._frame.bind("<Enter>", self._on_enter)
        self._frame.bind("<Leave>", self._on_leave)
        self._frame.bind("<Button-1>", self._on_click_event)

        return self._frame

    def _setup_bindings(self) -> None:
        """Bindings настроены в _create_tk_widget."""
        pass

    def set_title(self, text: str) -> None:
        """Устанавливает заголовок плитки.

        Args:
            text: Новый заголовок.
        """
        self._title = text
        if self._title_label is not None:
            self._title_label.config(text=text)

    def set_subtitle(self, text: str) -> None:
        """Устанавливает подзаголовок плитки.

        Args:
            text: Новый подзаголовок.
        """
        self._subtitle = text
        if self._subtitle_label is not None:
            self._subtitle_label.config(text=text)
        elif self._frame is not None and text and self._title_label is not None:
            # recreate subtitle if it didn't exist
            master = self._title_label.master
            self._subtitle_label = tk.Label(
                master,
                text=text,
                font=("Courier", 9),
                bg="#FFFFFF",
                fg="#666666",
                anchor=tk.W,
            )
            self._subtitle_label.pack(fill=tk.X)

    def set_icon(self, icon: str) -> None:
        """Устанавливает иконку плитки.

        Args:
            icon: Новая иконка.
        """
        self._icon = icon
        if self._icon_label is not None:
            self._icon_label.config(text=icon)

    def set_selected(self, selected: bool) -> None:
        """Устанавливает выделение плитки.

        Args:
            selected: True для выделения.
        """
        self._selected = selected
        if self._frame is not None:
            if selected:
                self._frame.config(bg="#E3F2FD")
                if self._icon_label:
                    self._icon_label.config(bg="#E3F2FD")
                if self._title_label:
                    self._title_label.config(bg="#E3F2FD")
                if self._subtitle_label:
                    self._subtitle_label.config(bg="#E3F2FD")
            else:
                self._frame.config(bg="#FFFFFF")
                if self._icon_label:
                    self._icon_label.config(bg="#FFFFFF")
                if self._title_label:
                    self._title_label.config(bg="#FFFFFF")
                if self._subtitle_label:
                    self._subtitle_label.config(bg="#FFFFFF")

    def _on_enter(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик наведения мыши.

        Args:
            event: Событие Tkinter.
        """
        if self._frame is not None and not self._selected:
            self._frame.config(bg="#F5F5F5")
            if self._icon_label:
                self._icon_label.config(bg="#F5F5F5")
            if self._title_label:
                self._title_label.config(bg="#F5F5F5")
            if self._subtitle_label:
                self._subtitle_label.config(bg="#F5F5F5")

    def _on_leave(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик ухода мыши.

        Args:
            event: Событие Tkinter.
        """
        if self._frame is not None and not self._selected:
            self._frame.config(bg="#FFFFFF")
            if self._icon_label:
                self._icon_label.config(bg="#FFFFFF")
            if self._title_label:
                self._title_label.config(bg="#FFFFFF")
            if self._subtitle_label:
                self._subtitle_label.config(bg="#FFFFFF")

    def _on_click_event(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик клика по плитке.

        Args:
            event: Событие Tkinter.
        """
        if self._on_click is not None:
            self._on_click()

    def _cleanup(self) -> None:
        """Очищает ссылки на внутренние виджеты."""
        self._icon_label = None
        self._title_label = None
        self._subtitle_label = None
        self._frame = None


__all__: list[str] = ["ListTile"]
