"""
Исключения модуля блокировки сессии.

Иерархия:
    LockError (базовое)
    ├── LockTimeoutError
    └── UnlockError
        └── UnlockMFARequiredError

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class LockError(Exception):
    """
    Базовое исключение для ошибок блокировки сессии.

    Attributes:
        message: Человекочитаемое описание ошибки
        reason: Причина блокировки (опционально)
        context: Дополнительный контекст
    """

    def __init__(
        self,
        message: str,
        *,
        reason: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.context = context or {}

    def __str__(self) -> str:
        parts = [self.__class__.__name__, ": ", self.message]
        if self.reason:
            parts.append(f" [reason={self.reason}]")
        if self.context:
            ctx_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f" ({ctx_str})")
        return "".join(parts)


class LockTimeoutError(LockError):
    """
    Ошибка таймаута блокировки.

    Raises когда:
    - Время блокировки превысило максимум
    - Истёк timeout ожидания разблокировки
    """

    def __init__(
        self,
        message: str = "Lock timeout expired",
        *,
        timeout_seconds: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        ctx = context or {}
        if timeout_seconds:
            ctx["timeout_seconds"] = timeout_seconds
        super().__init__(message, reason="timeout", context=ctx)
        self.timeout_seconds = timeout_seconds


class UnlockError(LockError):
    """
    Ошибка разблокировки.

    Raises когда:
    - Неверный пароль
    - Сессия не заблокирована
    - Ошибка MFA
    """

    def __init__(
        self,
        message: str,
        *,
        reason: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, reason=reason, context=context)


class UnlockMFARequiredError(UnlockError):
    """
    Ошибка: требуется MFA для разблокировки.

    Raises когда:
    - Разблокировка требует второй фактор
    - MFA не пройден
    """

    def __init__(
        self,
        message: str = "MFA required for unlock",
        *,
        mfa_methods: Optional[list[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        ctx = context or {}
        if mfa_methods:
            ctx["available_mfa_methods"] = mfa_methods
        super().__init__(message, reason="mfa_required", context=ctx)
        self.mfa_methods = mfa_methods or []


__all__: list[str] = [
    "LockError",
    "LockTimeoutError",
    "UnlockError",
    "UnlockMFARequiredError",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"