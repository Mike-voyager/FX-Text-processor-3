"""GUI Security модуль FX Text Processor 3.

Предоставляет компоненты безопасности для GUI:
- ModeManager: управление Normal/Special режимами
- ModeToggle: UI тумблер для переключения режимов
- MFAGate: единая точка входа для MFA операций
- SessionLockScreen: экран блокировки сессии

Example:
    >>> from src.gui.security import ModeManager, MFAGate, ModeToggle, Mode
    >>> manager = ModeManager()
    >>> manager.get_current_mode()
    'normal'
    >>> toggle = ModeToggle(parent, mode_manager=manager)
    >>> mfa_gate = MFAGate(auth_service)
    >>> result = mfa_gate.challenge(parent, user_id, ["totp"], "approve")

Version: 1.1
"""

from src.gui.security.mfa_gate import MFAGate, MFAMethod, MFAResult
from src.gui.security.mode_manager import ModeManager
from src.gui.security.mode_toggle import Mode, ModeToggle
from src.gui.security.session_lock import SessionLockScreen

__all__ = [
    # MFA
    "MFAGate",
    "MFAMethod",
    "MFAResult",
    # Mode management
    "ModeManager",
    "ModeToggle",
    "Mode",
    # Session lock
    "SessionLockScreen",
]
