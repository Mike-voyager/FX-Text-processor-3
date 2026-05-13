"""Shared security components for FX Text Processor 3.

Модуль предоставляет общие виджеты безопасности для повторного
использования в Security UI:
- SecureEntry: Entry с secure wipe памяти
- MFAPanel: Панель для ввода MFA кода
- WipeButton: Кнопка для очистки связанного SecureEntry

Example:
    >>> from src.gui.security.components import SecureEntry, MFAPanel, WipeButton
    >>> entry = SecureEntry(root, secure=True)
    >>> panel = MFAPanel(root, methods=["totp", "backup_code"])
    >>> wipe_btn = WipeButton(root, target=entry)

Version: 1.0
Date: April 2026
"""

from src.gui.security.components.mfa_panel import MFAPanel
from src.gui.security.components.secure_entry import SecureEntry
from src.gui.security.components.wipe_button import WipeButton

__all__ = [
    "SecureEntry",
    "MFAPanel",
    "WipeButton",
]
