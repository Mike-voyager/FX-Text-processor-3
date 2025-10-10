# -*- coding: utf-8 -*-
"""
FX Text Processor 3 – second_method package initialization.

Экспортирует базовые MFA-факторы для:
- Кодовых (backup) методов,
- TOTP (Google Authenticator, Authy и др.),
- FIDO2/WebAuthn (YubiKey, Windows Hello, TouchID).

Смотри: code.py, totp.py, fido2.py для реализации отдельных факторов.
"""

from .code import BackupCodeFactor
from .totp import TotpFactor
from .fido2 import Fido2Factor

__all__ = ["BackupCodeFactor", "TotpFactor", "Fido2Factor"]
