"""Утилиты отладочного режима.

FX_DEBUG_MODE=1 — обходит MFA верификацию для удобства отладки.
⚠ ДОЛЖЕН БЫТЬ УДАЛЁН ИЛИ ДИЗАКТИВИРОВАН ПЕРЕ РЕЛИЗОМ!

Архитектура:
- Единая точка проверки: is_debug_mode()
- Все bypass-проверки MFA идут через эту функцию
- Каждая bypass-операция логируется в audit trail
- Визуальный индикатор в UI (StatusBar)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_ENV_VAR = "FX_DEBUG_MODE"


def is_debug_mode() -> bool:
    """Проверяет, включён ли отладочный режим.

    Returns:
        True если FX_DEBUG_MODE=1.
    """
    return os.getenv(_ENV_VAR, "0") == "1"


def should_bypass_mfa() -> bool:
    """Проверяет, следует ли обойти MFA-верификацию.

    В debug режиме MFA-проверки всегда проходят успешно.
    Каждая bypass-операция логируется.

    Returns:
        True если MFA следует обойти.
    """
    if is_debug_mode():
        logger.warning(
            "⚠ MFA BYPASSED — FX_DEBUG_MODE=1 is active. "
            "This MUST be disabled in production!"
        )
        return True
    return False


def get_debug_user_id() -> str:
    """Возвращает user_id для отладочного режима.

    Returns:
        Строку 'debug-operator'.
    """
    return "debug-operator"


__all__ = [
    "is_debug_mode",
    "should_bypass_mfa",
    "get_debug_user_id",
]
