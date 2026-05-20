"""Базовые классы виджетов GUI.

Предоставляет:
- BaseWidget: «глупый» виджет с явным жизненным циклом mount/unmount.
- SmartBaseWidget: виджет с локальным состоянием редактирования.

Example:
    >>> from src.gui.components.base.widget import BaseWidget
    >>> class MyButton(BaseWidget):
    ...     def _create_tk_widget(self, parent):
    ...         return tk.Button(parent, text="Click")

Version: 1.0
"""

from src.gui.components.base.widget import BaseWidget, SmartBaseWidget

__all__: list[str] = [
    "BaseWidget",
    "SmartBaseWidget",
]
