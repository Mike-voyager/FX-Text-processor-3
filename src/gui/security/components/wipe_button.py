"""Wipe Button - кнопка для безопасной очистки SecureEntry.

Модуль предоставляет WipeButton - кнопку, связанную с SecureEntry,
которая выполняет secure wipe при нажатии.

Example:
    >>> import tkinter as tk
    >>> from src.gui.security.components.secure_entry import SecureEntry
    >>> root = tk.Tk()
    >>> entry = SecureEntry(root)
    >>> entry.pack()
    >>> wipe_btn = WipeButton(root, target=entry)
    >>> wipe_btn.pack()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Optional

from src.gui.security.components.secure_entry import SecureEntry


class WipeButton(tk.Button):
    """Кнопка для очистки (wipe) связанного SecureEntry.

    Расширяет стандартный tk.Button функцией автоматического
    вызова wipe() у связанного SecureEntry виджета при нажатии.

    Attributes:
        _target: Связанный SecureEntry для очистки.
        _default_text: Текст кнопки по умолчанию.

    Example:
        >>> entry = SecureEntry(root, secure=True)
        >>> entry.insert(0, "secret")
        >>> wipe_btn = WipeButton(root, target=entry, text="🗑️ Очистить")
        >>> # При нажатии entry.wipe() будет вызван автоматически
    """

    def __init__(
        self,
        parent: tk.Widget,
        target: SecureEntry,
        text: str = "🗑️ Очистить",
        **kwargs: Any,
    ) -> None:
        """Инициализация WipeButton.

        Args:
            parent: Родительский виджет.
            target: SecureEntry для очистки (обязательно).
            text: Текст кнопки (default: "🗑️ Очистить").
            **kwargs: Дополнительные параметры для tk.Button.

        Raises:
            TypeError: Если target не является SecureEntry.

        Example:
            >>> wipe_btn = WipeButton(root, target=my_entry, text="Clear")
        """
        if not isinstance(target, SecureEntry):
            raise TypeError(f"target must be SecureEntry, got {type(target).__name__}")

        self._target: SecureEntry = target
        self._default_text: str = text

        # Настраиваем команду
        kwargs["command"] = self._on_click

        super().__init__(parent, text=text, **kwargs)

    def _on_click(self) -> None:
        """Обработчик нажатия кнопки.

        Вызывает wipe() у связанного SecureEntry.

        Example:
            >>> wipe_btn._on_click()  # Вызывает target.wipe()
        """
        if self._target is not None and self._target.winfo_exists():
            self._target.wipe()

    def set_target(self, target: SecureEntry) -> None:
        """Изменяет связанный SecureEntry.

        Args:
            target: Новый SecureEntry для очистки.

        Raises:
            TypeError: Если target не является SecureEntry.

        Example:
            >>> wipe_btn.set_target(new_entry)
        """
        if not isinstance(target, SecureEntry):
            raise TypeError(f"target must be SecureEntry, got {type(target).__name__}")
        self._target = target

    def get_target(self) -> Optional[SecureEntry]:
        """Возвращает текущий связанный SecureEntry.

        Returns:
            Связанный SecureEntry или None.

        Example:
            >>> target = wipe_btn.get_target()
            >>> if target:
            ...     print(target.widget_id)
        """
        return self._target

    def trigger_wipe(self) -> None:
        """Программно вызывает wipe без нажатия кнопки.

        Полезно для программной очистки из внешнего кода.

        Example:
            >>> wipe_btn.trigger_wipe()  # То же что и _on_click()
        """
        self._on_click()
