# -*- coding: utf-8 -*-
"""Re-export модуля totp под именем totp_factor (совместимость с документацией)."""

from src.security.auth.second_method.totp import (
    TotpFactor,
    TotpSecretMissing,
    TotpVerificationFailed,
)

__all__ = ["TotpFactor", "TotpSecretMissing", "TotpVerificationFailed"]
