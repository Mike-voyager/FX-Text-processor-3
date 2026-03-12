# -*- coding: utf-8 -*-
"""Re-export модуля fido2 под именем fido2_factor (совместимость с документацией)."""

from src.security.auth.second_method.fido2 import (
    CredentialMismatch,
    DeviceNotFound,
    Fido2Factor,
    SignatureVerificationFailed,
)

__all__ = [
    "Fido2Factor",
    "DeviceNotFound",
    "CredentialMismatch",
    "SignatureVerificationFailed",
]
