"""Dialogs for Form Designer.

Provides:
    - ConditionsEditorDialog: редактирование условий полей
    - OptionsEditorDialog: редактирование опций DROPDOWN/RADIO_GROUP

Example:
    >>> from src.gui.form_designer.dialogs import ConditionsEditorDialog, OptionsEditorDialog
    >>> dialog = ConditionsEditorDialog(parent, field_def)

Version: 1.0
"""

from __future__ import annotations

from src.gui.form_designer.dialogs.conditions_editor_dialog import (
    ConditionsEditorDialog,
)
from src.gui.form_designer.dialogs.options_editor_dialog import (
    FieldOption,
    OptionsEditorDialog,
)

__all__ = [
    "ConditionsEditorDialog",
    "OptionsEditorDialog",
    "FieldOption",
]
