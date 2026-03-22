"""
Модуль безопасности: криптография, аутентификация, аудит, бланки.

Components:
    - crypto: Криптографическая подсистема (46 алгоритмов)
    - auth: Аутентификация и авторизация (MFA, sessions)
    - audit: Неизменяемый журнал событий (hash-chain)
    - blanks: Защищённые бланки (signing, verification)

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

# Lazy imports for submodules
from src.security import audit, auth, blanks, crypto

__all__: list[str] = [
    "audit",
    "auth",
    "blanks",
    "crypto",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
