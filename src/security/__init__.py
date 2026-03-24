"""
Модуль безопасности: криптография, аутентификация, аудит, бланки.

Components:
    - crypto: Криптографическая подсистема (46 алгоритмов)
    - auth: Аутентификация и авторизация (MFA, sessions)
    - audit: Неизменяемый журнал событий (hash-chain)
    - blanks: Защищённые бланки (signing, verification)
    - integrity: Проверка целостности приложения и конфигурации
    - erasure: Безопасное удаление данных (memory, files, clipboard)
    - lock: Блокировка сессии (SessionLockManager, AutoLockService)
    - monitoring: Health checks системы (entropy, keystore, devices, etc.)
    - compliance: GDPR compliance (retention, anonymization, export, erasure)

Version: 1.4
Date: March 2026
"""

from __future__ import annotations

# Lazy imports for submodules
from src.security import audit, auth, blanks, compliance, crypto
from src.security import erasure
from src.security import integrity
from src.security import lock
from src.security import monitoring

__all__: list[str] = [
    "audit",
    "auth",
    "blanks",
    "crypto",
    "integrity",
    "erasure",
    "lock",
    "monitoring",
    "compliance",
]

__version__ = "1.4.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-25"
