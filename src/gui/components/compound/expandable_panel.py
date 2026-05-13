"""Сворачиваемая панель с заголовком и контентом.

Модуль предоставляет ExpandablePanel — compound-виджет,
панель которую можно свернуть/развернуть.

Example:
    >>> panel = ExpandablePanel(
    ...     widget_id="settings_panel",
    ...     title="Настройки",
    ...     expanded=True
    ... )
    >>> panel.mount(parent)
    >>> panel.toggle()

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol


class ExpandablePanel(BaseWidget):
    """Сворачиваемая панель с заголовком и контентом.

    Реализует compound-виджет:
    - Заголовок с кнопкой переключения
    - Контейнер для произвольного контента
    - Состояние развернуто/свернуто

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _title: Заголовок панели.
        _expanded: Текущее состояние.
    """

    _COLLAPSE_ICON: str = "▼"
    _EXPAND_ICON: str = "▶"

    def __init__(
        self,
        widget_id: str,
        title: str,
        expanded: bool = True,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализирует сворачиваемую панель.

        Args:
            widget_id: Уникальный идентификатор виджета.
            title: Заголовок панели.
            expanded: Начальное состояние (True = развернута).
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._title: str = title
        self._expanded: bool = expanded
        self._content: Optional[tk.Widget] = None
        self._toggle_btn: Optional[tk.Label] = None
        self._content_frame: Optional[tk.Widget] = None
        self._main_frame: Optional[tk.Widget] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame с заголовком и областью контента.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame.
        """
        self._main_frame = tk.Frame(parent, bd=1, relief=tk.GROOVE)

        # Header frame
        header = tk.Frame(self._main_frame, bg="#F5F5F5", padx=4, pady=4)
        header.pack(fill=tk.X)

        self._toggle_btn = tk.Label(
            header,
            text=self._COLLAPSE_ICON if self._expanded else self._EXPAND_ICON,
            font=("Courier", 10, "bold"),
            bg="#F5F5F5",
            cursor="hand2",
            width=2,
        )
        self._toggle_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._toggle_btn.bind("<Button-1>", lambda e: self.toggle())

        title_label = tk.Label(
            header,
            text=self._title,
            font=("Courier", 10, "bold"),
            bg="#F5F5F5",
            anchor=tk.W,
        )
        title_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        title_label.bind("<Button-1>", lambda e: self.toggle())

        # Content frame
        self._content_frame = tk.Frame(self._main_frame, padx=4, pady=4)
        if self._expanded:
            self._content_frame.pack(fill=tk.BOTH, expand=True)
        else:
            self._content_frame.pack_forget()

        return self._main_frame

    def _setup_bindings(self) -> None:
        """Нет специфичных bindings."""
        pass

    def set_content(self, widget: tk.Widget) -> None:
        """Устанавливает содержимое панели.

        Args:
            widget: Tkinter виджет для размещения внутри панели.
        """
        self._content = widget
        if self._content_frame is not None:
            widget.pack(in_=self._content_frame, fill=tk.BOTH, expand=True)

    def toggle(self) -> None:
        """Переключает состояние свернуто/развернуто."""
        self.set_expanded(not self._expanded)

    def expand(self) -> None:
        """Разворачивает панель."""
        self.set_expanded(True)

    def collapse(self) -> None:
        """Сворачивает панель."""
        self.set_expanded(False)

    def set_expanded(self, expanded: bool) -> None:
        """Устанавливает состояние развернутости.

        Args:
            expanded: True для развёрнутого состояния.
        """
        self._expanded = expanded
        if self._content_frame is not None and self._toggle_btn is not None:
            if expanded:
                self._content_frame.pack(fill=tk.BOTH, expand=True)
                self._toggle_btn.config(text=self._COLLAPSE_ICON)
            else:
                self._content_frame.pack_forget()
                self._toggle_btn.config(text=self._EXPAND_ICON)

    @property
    def is_expanded(self) -> bool:
        """Возвращает текущее состояние развернутости.

        Returns:
            True если панель развернута.
        """
        return self._expanded

    def _cleanup(self) -> None:
        """Очищает ссылки на внутренние виджеты."""
        self._content = None
        self._toggle_btn = None
        self._content_frame = None
        self._main_frame = None


__all__: list[str] = ["ExpandablePanel"]
