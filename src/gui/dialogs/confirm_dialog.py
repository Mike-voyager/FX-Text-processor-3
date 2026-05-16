"""Confirm dialogs for FX Text Processor 3."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox
from typing import Optional


class SaveChangesDialog:
    """Dialog to confirm saving changes before closing."""

    @staticmethod
    def show(parent: Optional[tk.Widget] = None) -> str:
        """Show dialog and return user choice.

        Returns:
            'yes', 'no', or 'cancel'
        """
        result = messagebox.askyesnocancel(
            "Save changes?",
            "The document has been modified. Save before closing?",
            icon="warning",
        )
        if result is None:
            return "cancel"
        return "yes" if result else "no"
