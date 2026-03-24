"""
Модуль блокировки сессии.

Обеспечивает мгновенную блокировку и автоматическую блокировку
по таймауту неактивности с MFA для разблокировки.

Components:
    - SessionLockManager: Управление блокировкой сессии
    - AutoLockService: Фоновый мониторинг неактивности

Security:
    - Мгновенная блокировка по горячей клавише или таймауту
    - Очистка памяти чувствительных данных при блокировке
    - MFA для разблокировки
    - Audit-логирование всех событий

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from src.security.lock.exceptions import (
    LockError,
    LockTimeoutError,
    UnlockError,
    UnlockMFARequiredError,
)
from src.security.lock.models import LockEvent, LockReason, LockState
from src.security.lock.session_lock import SessionLockManager

__all__: list[str] = [
    # Exceptions
    "LockError",
    "LockTimeoutError",
    "UnlockError",
    "UnlockMFARequiredError",
    # Models
    "LockState",
    "LockReason",
    "LockEvent",
    # Managers
    "SessionLockManager",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"