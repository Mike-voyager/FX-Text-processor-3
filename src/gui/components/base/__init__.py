"""Base widget classes.

Provides:
- BaseWidget: "dumb" widget with explicit lifecycle
- SmartBaseWidget: widget with local edit state

Example:
    >>> from src.gui.components.base.widget import BaseWidget
    >>> class MyButton(BaseWidget):
    ...     def _create_tk_widget(self, parent):
    ...         return tk.Button(parent, text="Click")

Version: 1.0
"""

from src.gui.components.base.widget import BaseWidget, SmartBaseWidget

__all__ = [
    "BaseWidget",
    "SmartBaseWidget",
]
