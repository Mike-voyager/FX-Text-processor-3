"""Фабрика виджетов GUI.

Предоставляет stateless функции для создания Tkinter/ttk виджетов
с применением стандартных theme-aware настроек.

Example:
    >>> from src.gui.factories import create_button, create_label
    >>> btn = create_button(parent, text="OK", command=on_ok)
    >>> lbl = create_label(parent, text="Status:")

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Literal

from src.gui.themes import ThemeManager

__all__ = [
    "create_button",
    "create_label",
    "create_entry",
    "create_frame",
    "create_scrollbar",
    "create_treeview",
    "create_combobox",
    "create_separator",
    "create_progressbar",
    "create_spacer",
]


def _get_theme_defaults() -> dict[str, Any]:
    """Возвращает theme-aware настройки из текущей темы.

    Returns:
        Словарь с bg, fg, font.

    Note:
        Если ThemeManager не инициализирован, возвращает {}.
    """
    try:
        theme = ThemeManager().get_current_theme()
        return {
            "bg": theme.bg_color,
            "fg": theme.fg_color,
            "font": (theme.font_family, theme.font_size),
        }
    except (AttributeError, KeyError):  # noqa: S110
        return {}


def create_button(
    parent: tk.Widget,
    text: str,
    command: Callable[[], None],
    **kwargs: Any,
) -> tk.Button:
    """Создаёт кнопку с theme-aware настройками.

    Args:
        parent: Родительский виджет.
        text: Текст кнопки.
        command: Callback при нажатии.
        **kwargs: Дополнительные параметры (переопределяют тему).

    Returns:
        Созданный tk.Button.
    """
    defaults = _get_theme_defaults()
    defaults.update({"text": text, "command": command})
    defaults.update(kwargs)
    return tk.Button(parent, **defaults)


def create_label(
    parent: tk.Widget,
    text: str,
    **kwargs: Any,
) -> tk.Label:
    """Создаёт метку с theme-aware настройками.

    Args:
        parent: Родительский виджет.
        text: Текст метки.
        **kwargs: Дополнительные параметры (переопределяют тему).

    Returns:
        Созданный tk.Label.
    """
    defaults = _get_theme_defaults()
    defaults.update({"text": text})
    defaults.update(kwargs)
    return tk.Label(parent, **defaults)


def create_entry(
    parent: tk.Widget,
    **kwargs: Any,
) -> tk.Entry:
    """Создаёт поле ввода с theme-aware настройками.

    Args:
        parent: Родительский виджет.
        **kwargs: Дополнительные параметры (переопределяют тему).

    Returns:
        Созданный tk.Entry.
    """
    defaults = _get_theme_defaults()
    # Дополнительные настройки для entry
    try:
        theme = ThemeManager().get_current_theme()
        defaults.update(
            {
                "insertbackground": theme.fg_color,
                "selectbackground": theme.accent_color,
                "selectforeground": theme.bg_color,
            }
        )
    except (AttributeError, KeyError):  # noqa: S110
        pass
    defaults.update(kwargs)
    return tk.Entry(parent, **defaults)


def create_frame(
    parent: tk.Widget,
    **kwargs: Any,
) -> tk.Frame:
    """Создаёт фрейм с theme-aware настройками.

    Args:
        parent: Родительский виджет.
        **kwargs: Дополнительные параметры (переопределяют тему).

    Returns:
        Созданный tk.Frame.
    """
    defaults = _get_theme_defaults()
    # Frame не поддерживает fg и font
    defaults.pop("fg", None)
    defaults.pop("font", None)
    defaults.update(kwargs)
    return tk.Frame(parent, **defaults)


def create_scrollbar(
    parent: tk.Widget,
    **kwargs: Any,
) -> ttk.Scrollbar:
    """Создаёт scrollbar.

    Args:
        parent: Родительский виджет.
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный ttk.Scrollbar.
    """
    return ttk.Scrollbar(parent, **kwargs)


def create_treeview(
    parent: tk.Widget,
    **kwargs: Any,
) -> ttk.Treeview:
    """Создаёт дерево с theme-aware настройками.

    Args:
        parent: Родительский виджет.
        **kwargs: Дополнительные параметры (переопределяют тему).

    Returns:
        Созданный ttk.Treeview.
    """
    defaults: dict[str, Any] = {}
    try:
        _ = ThemeManager().get_current_theme()
        defaults.update(
            {
                "style": kwargs.pop("style", ""),
            }
        )
        # ttk.Treeview стилизуется через ttk.Style, здесь только базовое
    except (AttributeError, KeyError):  # noqa: S110
        pass
    defaults.update(kwargs)
    return ttk.Treeview(parent, **defaults)


def create_combobox(
    parent: tk.Widget,
    values: tuple[str, ...],
    **kwargs: Any,
) -> ttk.Combobox:
    """Создаёт выпадающий список.

    Args:
        parent: Родительский виджет.
        values: Доступные значения.
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный ttk.Combobox.
    """
    defaults: dict[str, Any] = {"values": values}
    defaults.update(kwargs)
    return ttk.Combobox(parent, **defaults)


def create_separator(
    parent: tk.Widget,
    orient: Literal["horizontal", "vertical"] = "horizontal",
    **kwargs: Any,
) -> ttk.Separator:
    """Создаёт разделитель.

    Args:
        parent: Родительский виджет.
        orient: Ориентация (horizontal | vertical).
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный ttk.Separator.
    """
    return ttk.Separator(parent, orient=orient, **kwargs)


def create_progressbar(
    parent: tk.Widget,
    **kwargs: Any,
) -> ttk.Progressbar:
    """Создаёт индикатор прогресса.

    Args:
        parent: Родительский виджет.
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный ttk.Progressbar.
    """
    return ttk.Progressbar(parent, **kwargs)


def create_spacer(
    parent: tk.Widget,
    width: int = 10,
    **kwargs: Any,
) -> tk.Frame:
    """Создаёт пустой фрейм-отступ.

    Args:
        parent: Родительский виджет.
        width: Ширина отступа (в пикселях).
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный tk.Frame-отступ.
    """
    defaults: dict[str, Any] = {"width": width}
    defaults.update(kwargs)
    return tk.Frame(parent, **defaults)
