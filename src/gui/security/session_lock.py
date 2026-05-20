"""Модуль session_lock — реэкспорт SessionLockScreen.

Каноническая реализация SessionLockScreen находится в
:mod:`src.gui.security.session_lock_screen`. Данный модуль
сохраняет обратную совместимость для импортов вида::

    from src.gui.security.session_lock import SessionLockScreen

Version: 2.0
Date: May 2026
"""

from src.gui.security.session_lock_screen import SessionLockScreen, UnlockCallback

__all__ = [
    "SessionLockScreen",
    "UnlockCallback",
]
