"""Фабричные функции GUI-компонентов FX Text Processor 3.

Модуль предоставляет stateless factory functions для создания виджетов,
диалогов, theme-aware настроек и layout patterns.

Example:
 >>> from src.gui.factories import create_button, create_label
    >>> from src.gui.factories import create_confirm_dialog, create_input_dialog
    >>> from src.gui.factories import get_theme_colors, create_themed_button
    >>> from src.gui.factories import create_padded_frame, pack_form_row

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from src.gui.factories.dialog_factory import (
    create_choice_dialog,
    create_confirm_dialog,
    create_error_dialog,
    create_input_dialog,
    create_wait_dialog,
)
from src.gui.factories.layout_factory import (
    create_horizontal_divider,
    create_labeled_frame,
    create_padded_frame,
    create_scrollable_frame,
    pack_form_row,
    pack_toolbar,
)
from src.gui.factories.theme_factory import (
    ThemeColors,
    apply_theme_to_widget,
    create_themed_button,
    get_theme_colors,
)
from src.gui.factories.widget_factory import (
    create_button,
    create_combobox,
    create_entry,
    create_frame,
    create_label,
    create_progressbar,
    create_scrollbar,
    create_separator,
    create_spacer,
    create_treeview,
)

__all__ = [
    # widget_factory
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
    # dialog_factory
    "create_confirm_dialog",
    "create_input_dialog",
    "create_choice_dialog",
    "create_error_dialog",
    "create_wait_dialog",
    # theme_factory
    "ThemeColors",
    "get_theme_colors",
    "apply_theme_to_widget",
    "create_themed_button",
    # layout_factory
    "create_padded_frame",
    "create_horizontal_divider",
    "create_scrollable_frame",
    "create_labeled_frame",
    "pack_toolbar",
    "pack_form_row",
]
