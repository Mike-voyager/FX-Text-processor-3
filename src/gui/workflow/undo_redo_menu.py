"""Undo/Redo menu items для workflow.

Предоставляет готовые компоненты меню для интеграции
undo/redo функциональности в UI.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Callable, Optional, Tuple

if TYPE_CHECKING:
    pass


class UndoRedoMenuItems:
    """Генератор пунктов меню undo/redo.

    Создаёт пункты меню с динамическими описаниями
    и hotkey bindings для undo/redo операций.

    Attributes:
        _undo_callback: Callback для undo.
        _redo_callback: Callback для redo.
        _get_undo_text: Функция получения текста undo.
        _get_redo_text: Функция получения текста redo.

    Example:
        >>> menu_items = UndoRedoMenuItems(
        ...     undo_callback=lambda: manager.undo(doc_id),
        ...     redo_callback=lambda: manager.redo(doc_id),
        ...     get_undo_text=lambda: "Отменить переход",
        ...     get_redo_text=lambda: "Повторить переход",
        ... )
        >>> menu_items.add_to_menu(tk_menu)
    """

    def __init__(
        self,
        undo_callback: Callable[[], None],
        redo_callback: Callable[[], None],
        get_undo_text: Callable[[], Optional[str]],
        get_redo_text: Callable[[], Optional[str]],
    ) -> None:
        """Инициализация генератора меню.

        Args:
            undo_callback: Функция вызываемая при выборе undo.
            redo_callback: Функция вызываемая при выборе redo.
            get_undo_text: Функция возвращающая описание undo или None.
            get_redo_text: Функция возвращающая описание redo или None.
        """
        self._undo_callback = undo_callback
        self._redo_callback = redo_callback
        self._get_undo_text = get_undo_text
        self._get_redo_text = get_redo_text

        self._undo_menu_item: Optional[int] = None
        self._redo_menu_item: Optional[int] = None

    def add_to_menu(
        self,
        menu: tk.Menu,
        index: Optional[int] = None,
        accelerator: bool = True,
    ) -> Tuple[int, int]:
        """Добавляет пункты undo/redo в меню.

        Args:
            menu: Tkinter меню для добавления.
            index: Позиция для вставки (None = в конец).
            accelerator: Показывать ли shortcuts.

        Returns:
            Кортеж (undo_index, redo_index).
        """
        from src.gui.workflow.constants import UNDO_REDO_SHORTCUTS

        undo_text = self._get_undo_text() or "Отменить"
        redo_text = self._get_redo_text() or "Повторить"

        undo_label = f"↶ {undo_text}"
        redo_label = f"↷ {redo_text}"

        undo_accel = UNDO_REDO_SHORTCUTS["undo"] if accelerator else ""
        redo_accel = UNDO_REDO_SHORTCUTS["redo"] if accelerator else ""

        if index is not None:
            self._undo_menu_item = index
            self._redo_menu_item = index + 1
        else:
            end_idx = menu.index(tk.END)
            self._undo_menu_item = int(end_idx) + 1 if end_idx is not None else 0
            menu.add_command(
                label=undo_label,
                command=self._undo_callback,
                accelerator=undo_accel,
            )

            self._redo_menu_item = self._undo_menu_item + 1
            menu.add_command(
                label=redo_label,
                command=self._redo_callback,
                accelerator=redo_accel,
            )

        return (self._undo_menu_item, self._redo_menu_item)

    def update_labels(self, menu: tk.Menu) -> None:
        """Обновляет подписи пунктов меню.

        Args:
            menu: Меню для обновления.
        """
        if self._undo_menu_item is None or self._redo_menu_item is None:
            return

        undo_text = self._get_undo_text()
        redo_text = self._get_redo_text()

        undo_label = f"↶ {undo_text}" if undo_text else "↶ Отменить"
        redo_label = f"↷ {redo_text}" if redo_text else "↷ Повторить"

        # Update entryconfig if items exist
        if self._undo_menu_item is not None:
            try:
                menu.entryconfig(self._undo_menu_item, label=undo_label)
            except tk.TclError:
                pass

        if self._redo_menu_item is not None:
            try:
                menu.entryconfig(self._redo_menu_item, label=redo_label)
            except tk.TclError:
                pass

    def enable_undo(self, menu: tk.Menu, enabled: bool = True) -> None:
        """Включает/выключает пункт undo.

        Args:
            menu: Меню для обновления.
            enabled: True для включения.
        """
        if self._undo_menu_item is not None:
            state = tk.NORMAL if enabled else tk.DISABLED
            try:
                menu.entryconfig(self._undo_menu_item, state=state)
            except tk.TclError:
                pass

    def enable_redo(self, menu: tk.Menu, enabled: bool = True) -> None:
        """Включает/выключает пункт redo.

        Args:
            menu: Меню для обновления.
            enabled: True для включения.
        """
        if self._redo_menu_item is not None:
            state = tk.NORMAL if enabled else tk.DISABLED
            try:
                menu.entryconfig(self._redo_menu_item, state=state)
            except tk.TclError:
                pass


class UndoRedoToolbarButtons:
    """Кнопки undo/redo для тулбара.

    Создаёт кнопки тулбара с иконками и состояниями.

    Example:
        >>> buttons = UndoRedoToolbarButtons(parent_frame)
        >>> undo_btn, redo_btn = buttons.create(
        ...     undo_callback=lambda: print("undo"),
        ...     redo_callback=lambda: print("redo"),
        ... )
    """

    def __init__(self, parent: tk.Widget) -> None:
        """Инициализация.

        Args:
            parent: Родительский виджет.
        """
        self._parent = parent
        self._undo_button: Optional[tk.Button] = None
        self._redo_button: Optional[tk.Button] = None

    def create(
        self,
        undo_callback: Callable[[], None],
        redo_callback: Callable[[], None],
        undo_tooltip: str = "Отменить (Ctrl+Z)",
        redo_tooltip: str = "Повторить (Ctrl+Y)",
    ) -> Tuple[tk.Button, tk.Button]:
        """Создаёт кнопки undo/redo.

        Args:
            undo_callback: Callback для undo.
            redo_callback: Callback для redo.
            undo_tooltip: Tooltip для undo кнопки.
            redo_tooltip: Tooltip для redo кнопки.

        Returns:
            Кортеж (undo_button, redo_button).
        """
        from src.gui.workflow.constants import UNDO_REDO_ICONS

        button_frame = tk.Frame(self._parent)
        button_frame.pack(side=tk.LEFT)

        self._undo_button = tk.Button(
            button_frame,
            text=UNDO_REDO_ICONS["undo"],
            command=undo_callback,
            state=tk.DISABLED,
            width=3,
        )
        self._undo_button.pack(side=tk.LEFT, padx=(0, 2))

        self._redo_button = tk.Button(
            button_frame,
            text=UNDO_REDO_ICONS["redo"],
            command=redo_callback,
            state=tk.DISABLED,
            width=3,
        )
        self._redo_button.pack(side=tk.LEFT)

        return (self._undo_button, self._redo_button)

    def set_undo_enabled(self, enabled: bool) -> None:
        """Включает/выключает кнопку undo.

        Args:
            enabled: True для включения.
        """
        if self._undo_button is not None:
            state = tk.NORMAL if enabled else tk.DISABLED
            self._undo_button.config(state=state)  # type: ignore[call-overload]

    def set_redo_enabled(self, enabled: bool) -> None:
        """Включает/выключает кнопку redo.

        Args:
            enabled: True для включения.
        """
        if self._redo_button is not None:
            state = tk.NORMAL if enabled else tk.DISABLED
            self._redo_button.config(state=state)  # type: ignore[call-overload]

    def set_undo_tooltip(self, text: Optional[str]) -> None:
        """Устанавливает tooltip для undo.

        Args:
            text: Текст tooltip или None.
        """
        # Tooltip implementation would use TooltipManager
        pass

    def set_redo_tooltip(self, text: Optional[str]) -> None:
        """Устанавливает tooltip для redo.

        Args:
            text: Текст tooltip или None.
        """
        pass


__all__ = [
    "UndoRedoMenuItems",
    "UndoRedoToolbarButtons",
]
