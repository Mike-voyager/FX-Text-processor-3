"""Модуль блокировки сессии для FX Text Processor 3.

Предоставляет сервисы для автоматической и ручной блокировки сессии
при бездействии пользователя, при засыпании системы или по требованию.

Components:
    - LockConfig: Конфигурация блокировки сессии
    - SessionLockManager: Менеджер блокировки сессии
    - AutoLockService: Сервис автоматической блокировки по таймауту

Example:
    >>> from src.security.lock import SessionLockManager, AutoLockService, LockConfig
    >>> config = LockConfig(auto_lock_minutes=DEFAULT_AUTO_LOCK_MINUTES, require_mfa_to_unlock=True)
    >>> lock_manager = SessionLockManager(auth_controller, config)
    >>> auto_lock = AutoLockService(lock_manager)
    >>> auto_lock.start()
"""

from __future__ import annotations

from src.security.lock.auto_lock_service import (
    AutoLockError,
    AutoLockService,
)
from src.security.lock.session_lock_manager import (
    DEFAULT_AUTO_LOCK_MINUTES,
    LockConfig,
    SessionLockError,
    SessionLockManager,
    UnlockResult,
)

__version__ = "1.0.0"
__author__ = "Mike Voyager"

__all__ = [
    # Constants
    "DEFAULT_AUTO_LOCK_MINUTES",
    # Configuration
    "LockConfig",
    # Managers
    "SessionLockManager",
    "AutoLockService",
    # Results
    "UnlockResult",
    # Exceptions
    "SessionLockError",
    "AutoLockError",
]
