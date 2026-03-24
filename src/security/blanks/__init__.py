"""
Модуль защищённых бланков: жизненный цикл, подпись, верификация.

Реализует security-аспекты бланков:
- Lifecycle state machine (ISSUED → READY → PRINTED → ARCHIVED)
- Криптографическая подпись
- QR verification для offline проверки

Components:
    - BlankStatus: Статусы бланка
    - SigningMode: Режим подписи (SOFTWARE / HARDWARE_PIV / HARDWARE_OPENPGP)
    - ProtectedBlank: Защищённый бланк с криптографической идентичностью
    - BlankManager: Управление жизненным циклом бланков
    - verify_blank(): Верификация бланка по QR коду

Security:
    - Ed25519 / ML-DSA-65 / RSA-PSS подписи
    - Monotonic serial counter
    - Offline verification via QR

Version: 1.0
Date: March 2026
Priority: 🔴 CRITICAL (Phase 1)
"""

from __future__ import annotations

from src.security.blanks.manager import BlankManager
from src.security.blanks.models import (
    BlankStatus,
    ProtectedBlank,
    SigningMode,
    VerificationResult,
)
from src.security.blanks.signer import BlankSigner
from src.security.blanks.verification import verify_blank

__all__: list[str] = [
    # Models
    "BlankStatus",
    "SigningMode",
    "ProtectedBlank",
    "VerificationResult",
    # Manager
    "BlankManager",
    # Signer
    "BlankSigner",
    # Verification
    "verify_blank",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
