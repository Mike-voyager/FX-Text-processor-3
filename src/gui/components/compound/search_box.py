"""Поле поиска с иконкой и очисткой.

Модуль предоставляет SearchBox — compound-виджет с полем ввода,
кнопкой очистки и debounce-колбэком.

Example:
    >>> search = SearchBox(
    ...     widget_id="doc_search",
    ...     placeholder="Поиск документов...",
    ...     on_search=lambda text: print(f"Ищем: {text}")
    ... )
    >>> search.mount(parent)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol

SearchCallback = Optional[Callable[[str], None]]


class SearchBox(BaseWidget):
    """Поле поиска с кнопкой очистки и debounce.

    Реализует compound-виджет поиска:
    - Entry для ввода текста
    - Кнопка очистки (×)
    - Debounce таймер для on_search колбэка
    - Placeholder текст

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _placeholder: Текст placeholder.
        _on_search: Колбэк поиска.
        _debounce_ms: Задержка debounce в миллисекундах.
    """

    def __init__(
        self,
        widget_id: str,
        placeholder: str = "Search...",
        on_search: SearchCallback = None,
        debounce_ms: int = 300,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализирует поле поиска.

        Args:
            widget_id: Уникальный идентификатор виджета.
            placeholder: Текст placeholder.
            on_search: Колбэк при изменении текста (с debounce).
            debounce_ms: Задержка debounce в миллисекундах.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._placeholder: str = placeholder
        self._on_search: SearchCallback = on_search
        self._debounce_ms: int = debounce_ms

        self._entry: Optional[tk.Entry] = None
        self._after_id: Optional[str] = None
        self._placeholder_active: bool = True

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame с Entry и кнопкой очистки.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame.
        """
        frame = tk.Frame(parent)

        self._entry = tk.Entry(
            frame,
            font=("Courier", 10),
            fg="#9E9E9E",
            highlightthickness=1,
        )
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._entry.insert(0, self._placeholder)
        self._placeholder_active = True

        self._entry.bind("<FocusIn>", self._on_focus_in)
        self._entry.bind("<FocusOut>", self._on_focus_out)
        self._entry.bind("<KeyRelease>", self._on_key_release)
        self._entry.bind("<Destroy>", lambda _e: self._cancel_debounce(), add=True)
        self._entry.bind("<Return>", self._on_return)

        clear_btn = tk.Button(
            frame,
            text="×",
            command=self.clear,
            font=("Courier", 12, "bold"),
            fg="#F44336",
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            width=2,
        )
        clear_btn.pack(side=tk.LEFT, padx=(2, 0))

        return frame

    def _setup_bindings(self) -> None:
        """Bindings настроены в _create_tk_widget."""
        pass

    def get_text(self) -> str:
        """Возвращает текущий текст поиска.

        Returns:
            Текст из поля ввода (пустая строка если placeholder).
        """
        if self._entry is not None:
            text = self._entry.get()
            if self._placeholder_active and text == self._placeholder:
                return ""
            return text
        return ""

    def set_text(self, text: str) -> None:
        """Устанавливает текст поиска.

        Args:
            text: Новый текст.
        """
        if self._entry is not None:
            self._entry.delete(0, tk.END)
            if text:
                self._entry.insert(0, text)
                self._entry.config(fg="#000000")
                self._placeholder_active = False
            else:
                self._entry.insert(0, self._placeholder)
                self._entry.config(fg="#9E9E9E")
                self._placeholder_active = True

    def clear(self) -> None:
        """Очищает поле поиска и сбрасывает placeholder."""
        if self._entry is not None:
            self._entry.delete(0, tk.END)
            self._entry.insert(0, self._placeholder)
            self._entry.config(fg="#9E9E9E")
            self._placeholder_active = True
        self._cancel_debounce()
        if self._on_search is not None:
            self._on_search("")

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода."""
        if self._entry is not None:
            self._entry.focus_set()

    def _on_focus_in(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик получения фокуса.

        Args:
            event: Событие Tkinter.
        """
        if self._entry is not None and self._placeholder_active:
            self._entry.delete(0, tk.END)
            self._entry.config(fg="#000000")
            self._placeholder_active = False

    def _on_focus_out(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие Tkinter.
        """
        if self._entry is not None:
            text = self._entry.get()
            if not text:
                self._entry.insert(0, self._placeholder)
                self._entry.config(fg="#9E9E9E")
                self._placeholder_active = True

    def _on_key_release(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик ввода текста с debounce.

        Args:
            event: Событие Tkinter.
        """
        if self._placeholder_active:
            return
        self._schedule_search()

    def _on_return(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик нажатия Enter — запускает поиск немедленно.

        Args:
            event: Событие Tkinter.
        """
        self._cancel_debounce()
        self._trigger_search()

    def _schedule_search(self) -> None:
        """Планирует вызов on_search с debounce."""
        self._cancel_debounce()
        if self._entry is not None and self._on_search is not None:
            self._after_id = self._entry.after(self._debounce_ms, self._trigger_search)

    def _cancel_debounce(self) -> None:
        """Отменяет запланированный debounce вызов."""
        if self._after_id is not None and self._entry is not None:
            try:
                self._entry.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

    def _trigger_search(self) -> None:
        """Вызывает on_search колбэк."""
        self._after_id = None
        if self._on_search is not None:
            self._on_search(self.get_text())

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании."""
        self._cancel_debounce()
        self._entry = None


__all__: list[str] = ["SearchBox"]
