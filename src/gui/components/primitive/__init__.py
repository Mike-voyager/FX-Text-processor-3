"""Примитивные GUI компоненты.

Базовые виджеты для построения UI.
"""

from __future__ import annotations

from src.gui.components.primitive.button import ThemedButton
from src.gui.components.primitive.checkbox import ThemedCheckbox
from src.gui.components.primitive.entry import ThemedEntry
from src.gui.components.primitive.label import ThemedLabel

__all__: list[str] = [
    "ThemedLabel",
    "ThemedButton",
    "ThemedEntry",
    "ThemedCheckbox",
]
