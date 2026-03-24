"""
Модуль второго фактора аутентификации: FIDO2, TOTP, Backup Codes.

Components:
    - TOTPFactor: Time-Based One-Time Password фактор
    - FIDO2Factor: FIDO2/WebAuthn фактор (hardware keys)
    - BackupCodeFactor: Резервные коды (single-use)

MFA Support:
    - TOTP: RFC 6238, HMAC-SHA1/SHA256/SHA512
    - FIDO2: WebAuthn Level 2, hardware authenticators
    - Backup Codes: 8-character alphanumeric codes

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

# Экспорты зависят от реализации в модулях
# См. src.security.auth.second_method.*

__all__: list[str] = [
    # Классы определены в соответствующих модулях
    # Импортируйте напрямую:
    # from src.security.auth.second_method.totp_factor import ...
    # from src.security.auth.second_method.fido2_factor import ...
    # from src.security.auth.second_method.backup_code_factor import ...
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
