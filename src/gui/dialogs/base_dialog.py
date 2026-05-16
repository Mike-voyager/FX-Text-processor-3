"""Базовый класс для модальных диалогов FX Text Processor 3.

Предоставляет единую логику центрирования, управления результатом,
отмены таймеров и обработки закрытия для всех диалогов приложения.

Example:
    >>> dialog = BaseDialog(parent, title="Пример", modal=True)
    >>> dialog.close(result="ok")
    >>> assert dialog.get_result() == "ok"

Version: 1.0
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional, cast


class BaseDialog(tk.Toplevel):
    """Базовый модальный диалог с центрированием и управлением результатом.

    Attributes:
        _result: Результат диалога, возвращаемый из show().
        _after_ids: Список идентификаторов after() для отмены при закрытии.
        _on_close_callback: Опциональный callback при закрытии.

    Example:
        >>> class MyDialog(BaseDialog):
        ...     def __init__(self, parent: tk.Widget) -> None:
        ...         super().__init__(parent, title="My", modal=True)
    """

    def __init__(
        self,
        parent: tk.Misc,
        title: str = "",
        modal: bool = True,
        center_on_parent: bool = True,
        on_close: Optional[Callable[[], None]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Инициализация базового диалога.

        Args:
            parent: Родительский виджет.
            title: Заголовок окна.
            modal: Блокировать родительское окно.
            center_on_parent: Центрировать окно относительно родителя.
            on_close: Callback при закрытии диалога.
            *args: Дополнительные позиционные аргументы для Toplevel.
            **kwargs: Дополнительные именованные аргументы для Toplevel.
        """
        super().__init__(parent, *args, **kwargs)
        self._parent: tk.Misc = parent
        self._on_close_callback: Optional[Callable[[], None]] = on_close
        self._result: Any = None
        self._after_ids: list[str] = []

        if title:
            self.title(title)

        if modal:
            self.transient(cast(tk.Wm, parent))
            self.bind("<Escape>", self._on_escape)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Отменяем pending after() при уничтожении окна (избежать TclError)
        self.bind("<Destroy>", lambda _e: self._cancel_afters(), add=True)

        if center_on_parent:
            self.after_idle(self._center_window)

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского.

        Использует winfo_rootx / winfo_rooty для корректного позиционирования
        при multi-monitor конфигурациях.
        """
        self.update_idletasks()

        parent = self._parent
        parent_x = parent.winfo_rootx() if hasattr(parent, "winfo_rootx") else 0
        parent_y = parent.winfo_rooty() if hasattr(parent, "winfo_rooty") else 0
        parent_width = parent.winfo_width() if hasattr(parent, "winfo_width") else 800
        parent_height = parent.winfo_height() if hasattr(parent, "winfo_height") else 600

        width = self.winfo_width() if self.winfo_width() > 1 else 400
        height = self.winfo_height() if self.winfo_height() > 1 else 300

        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2

        self.geometry(f"+{x}+{y}")

    def _on_escape(self, event: Optional[Any] = None) -> None:
        """Обработчик нажатия Escape (если modal=True)."""
        self._on_close()

    def _on_close(self) -> None:
        """Обработчик закрытия окна (WM_DELETE_WINDOW, Escape)."""
        self.close()

    def _cancel_afters(self) -> None:
        """Отменяет все зарегистрированные after() таймеры."""
        for after_id in self._after_ids:
            try:
                self.after_cancel(after_id)
            except tk.TclError:
                pass
        self._after_ids.clear()

    def destroy(self) -> None:
        """Уничтожает окно с cleanup (отмена таймеров + callback)."""
        self._cancel_afters()
        if self._on_close_callback is not None:
            self._on_close_callback()
        try:
            super().destroy()
        except tk.TclError:
            pass

    def close(self, result: Any = None) -> None:
        """Закрывает диалог с установкой результата.

        Args:
            result: Значение для _result.
        """
        self._result = result
        self.destroy()

    def get_result(self) -> Any:
        """Возвращает результат диалога.

        Returns:
            Значение, переданное в close(), или None.
        """
        return self._result

    def show(self) -> Any:
        """Показывает диалог модально и возвращает результат.

        Returns:
            Результат диалога (из get_result()).
        """
        self.deiconify()
        self.wait_visibility()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self.wait_window()
        return self.get_result()
