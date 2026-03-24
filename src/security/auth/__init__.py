"""
Модуль аутентификации и авторизации.

Components:
    - AuthService: Сервис аутентификации
    - PasswordService: Сервис паролей
    - PasswordHasher: Хеширование паролей (Argon2id)
    - SessionManager: Управление сессиями
    - Permissions: Права доступа
    - SecondFactorManager: Второй фактор (MFA)
    - TOTPService: Time-based OTP

MFA Support:
    - TOTP (Time-Based One-Time Password)
    - FIDO2/WebAuthn (hardware keys)
    - Backup Codes (single-use)

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from src.security.auth.auth_service import AuthService
from src.security.auth.password import PasswordHasher
from src.security.auth.password_service import PasswordService
from src.security.auth.permissions import Permission, PermissionChecker, Scope
from src.security.auth.permissions_service import PermissionsService
from src.security.auth.second_factor import SecondFactorManager
from src.security.auth.session import SessionManager
from src.security.auth.totp_service import TOTPService

__all__: list[str] = [
    # Auth
    "AuthService",
    # Password
    "PasswordHasher",
    "PasswordService",
    # Session
    "SessionManager",
    # Permissions
    "Permission",
    "Scope",
    "PermissionChecker",
    "PermissionsService",
    # Second Factor
    "SecondFactorManager",
    # MFA Services
    "TOTPService",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
