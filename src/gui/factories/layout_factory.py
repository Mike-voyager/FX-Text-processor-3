"""Фабрика layout patterns GUI.

Предоставляет stateless функции для создания типовых layout-компонентов:
паддинг-фреймы, разделители, скроллируемые фреймы, labeled фреймы,
тулбары и строки формы.

Example:
    >>> from src.gui.factories import create_padded_frame, pack_form_row
    >>> frame = create_padded_frame(parent, padding=20)
    >>> pack_form_row(frame, label, entry)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from src.gui.themes import ThemeManager

__all__ = [
    "create_padded_frame",
    "create_horizontal_divider",
    "create_scrollable_frame",
    "create_labeled_frame",
    "pack_toolbar",
    "pack_form_row",
]


def create_padded_frame(
    parent: tk.Widget,
    padding: int = 10,
    **kwargs: Any,
) -> tk.Frame:
    """Создаёт фрейм с внутренним отступом.

    Args:
        parent: Родительский виджет.
        padding: Отступ в пикселях.
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный tk.Frame.
    """
    try:
        theme = ThemeManager().get_current_theme()
        bg = theme.bg_color
    except (AttributeError, KeyError):
        bg = ""
    defaults: dict[str, Any] = {"padx": padding, "pady": padding}
    if bg:
        defaults["bg"] = bg
    defaults.update(kwargs)
    return tk.Frame(parent, **defaults)


def create_horizontal_divider(
    parent: tk.Widget,
    **kwargs: Any,
) -> ttk.Separator:
    """Создаёт горизонтальный разделитель.

    Args:
        parent: Родительский виджет.
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный ttk.Separator.
    """
    return ttk.Separator(parent, orient=tk.HORIZONTAL, **kwargs)


def create_scrollable_frame(
    parent: tk.Widget,
    **kwargs: Any,
) -> tuple[tk.Frame, tk.Canvas, tk.Frame]:
    """Создаёт скроллируемый фрейм через Canvas.

    Структура:
        outer_frame (pack/grid)
        -> canvas + scrollbar (pack/grid)
        -> inner_frame (внутри canvas)

    Args:
        parent: Родительский виджет.
        **kwargs: Дополнительные параметры для canvas.

    Returns:
        Кортеж (outer_frame, canvas, inner_frame).
    """
    outer_frame = tk.Frame(parent)

    canvas = tk.Canvas(outer_frame, **kwargs)
    scrollbar = ttk.Scrollbar(outer_frame, orient=tk.VERTICAL, command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)

    inner_frame = tk.Frame(canvas)
    inner_frame_id = canvas.create_window((0, 0), window=inner_frame, anchor=tk.NW)

    def _configure_inner(event: Any) -> None:
        """Адаптирует canvas под ширину inner_frame."""
        canvas_width = event.width
        canvas.itemconfig(inner_frame_id, width=canvas_width)

    inner_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox(tk.ALL)))
    canvas.bind("<Configure>", _configure_inner)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    return outer_frame, canvas, inner_frame


def create_labeled_frame(
    parent: tk.Widget,
    label_text: str,
    **kwargs: Any,
) -> tk.LabelFrame:
    """Создаёт фрейм с меткой.

    Args:
        parent: Родительский виджет.
        label_text: Текст метки.
        **kwargs: Дополнительные параметры.

    Returns:
        Созданный tk.LabelFrame.
    """
    try:
        theme = ThemeManager().get_current_theme()
        defaults: dict[str, Any] = {
            "text": label_text,
            "bg": theme.bg_color,
            "fg": theme.fg_color,
            "font": (theme.font_family, theme.font_size),
        }
    except (AttributeError, KeyError):
        defaults = {"text": label_text}
    defaults.update(kwargs)
    return tk.LabelFrame(parent, **defaults)


def pack_toolbar(
    parent: tk.Widget,
    *widgets: tk.Widget,
) -> None:
    """Упаковывает виджеты в тулбар (горизонтально, прижав к левому краю).

    Args:
        parent: Родительский контейнер.
        *widgets: Виджеты для упаковки.
    """
    for widget in widgets:
        widget.pack(side=tk.LEFT, padx=2, pady=2)


def pack_form_row(
    parent: tk.Widget,
    label: tk.Widget,
    control: tk.Widget,
    **kwargs: Any,
) -> None:
    """Упаковывает строку формы (label + control) в parent.

    Args:
        parent: Родительский контейнер.
        label: Виджет метки.
        control: Виджет управления.
        **kwargs: Дополнительные параметры для pack (side, fill и т.д.).
    """
    defaults: dict[str, Any] = {"side": tk.LEFT, "padx": 5, "pady": 2}
    defaults.update(kwargs)
    label.pack(**defaults)
    control.pack(**defaults)
