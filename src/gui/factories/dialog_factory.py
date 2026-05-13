"""Фабрика диалогов GUI.

Предоставляет stateless функции для создания стандартных модальных диалогов:
подтверждение, ввод, выбор из списка, ошибка и ожидание.

Example:
    >>> from src.gui.factories import create_confirm_dialog
    >>> if create_confirm_dialog(root, "Выход", "Выйти из приложения?"):
    ...     sys.exit(0)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog
from typing import Callable

__all__ = [
    "create_confirm_dialog",
    "create_input_dialog",
    "create_choice_dialog",
    "create_error_dialog",
    "create_wait_dialog",
]


def create_confirm_dialog(
    parent: tk.Tk,
    title: str,
    message: str,
) -> bool:
    """Показывает диалог подтверждения.

    Args:
        parent: Родительское окно.
        title: Заголовок диалога.
        message: Текст сообщения.

    Returns:
        True если пользователь выбрал "Да", иначе False.
    """
    result: bool = messagebox.askyesno(title=title, message=message, parent=parent)
    return result


def create_input_dialog(
    parent: tk.Tk,
    title: str,
    prompt: str,
    default: str = "",
) -> str | None:
    """Показывает диалог ввода строки.

    Args:
        parent: Родительское окно.
        title: Заголовок диалога.
        prompt: Текст подсказки.
        default: Значение по умолчанию.

    Returns:
        Введённая строка или None при отмене.
    """
    result = simpledialog.askstring(title=title, prompt=prompt, initialvalue=default, parent=parent)
    return result


def create_choice_dialog(
    parent: tk.Tk,
    title: str,
    message: str,
    choices: list[str],
) -> str | None:
    """Показывает диалог выбора из списка.

    Args:
        parent: Родительское окно.
        title: Заголовок диалога.
        message: Текст сообщения.
        choices: Список доступных вариантов.

    Returns:
        Выбранный вариант или None при отмене.
    """
    if not choices:
        return None

    result: str | None = None
    # При наличии малого числа пунктов можно сделать через custom Toplevel
    # Для простоты используем simpledialog с валидацией
    prompt_text = f"{message}\n\nДоступные варианты: {', '.join(choices)}"
    input_result = simpledialog.askstring(
        title=title,
        prompt=prompt_text,
        parent=parent,
    )
    if input_result is not None and input_result in choices:
        result = input_result
    return result


def create_error_dialog(
    parent: tk.Tk,
    title: str,
    message: str,
    detail: str = "",
) -> None:
    """Показывает диалог ошибки.

    Args:
        parent: Родительское окно.
        title: Заголовок диалога.
        message: Текст ошибки.
        detail: Дополнительные детали (опционально).
    """
    full_message = f"{message}\n\n{detail}" if detail else message
    messagebox.showerror(title=title, message=full_message, parent=parent)


def create_wait_dialog(
    parent: tk.Tk,
    title: str,
    message: str,
) -> tuple[tk.Toplevel, Callable[[], None]]:
    """Создаёт немодальное окно ожидания.

    Args:
        parent: Родительское окно.
        title: Заголовок окна.
        message: Текст сообщения.

    Returns:
        Кортеж (Toplevel окно, функция закрытия).
    """
    window = tk.Toplevel(parent)
    window.title(title)
    window.transient(parent)

    label = tk.Label(window, text=message)
    label.pack(padx=20, pady=20)

    def close() -> None:
        """Закрывает окно ожидания."""
        window.destroy()

    return window, close
