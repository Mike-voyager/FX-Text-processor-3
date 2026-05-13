"""
Модуль аппаратных криптографических backend-ов.

Обеспечивает единый интерфейс для работы с аппаратными
криптографическими устройствами:
    - PIV смарткарты (NIST SP 800-73)
    - OpenPGP Card (ISO/IEC 7816-4)
    - TPM 2.0 (Trusted Platform Module)

Все backend-и следуют общим принципам:
    - Приватные ключи НИКОГДА не покидают устройство.
    - PIN-коды передаются как параметры, не хранятся в объектах.
    - Thread-unsafe: один экземпляр на поток.
    - Поддержка контекстных менеджеров (with).

Зависимости:
    - pyscard>=2.0.0 — для PIV и OpenPGP backend-ов.
    - tpm2-pytss>=1.0.0 — опционально для TPM backend-а.
    - tpm2-tools — CLI fallback для TPM.

Example:
    >>> from src.security.hardware import PIVBackend, OpenPGPBackend, TPMBackend
    >>>
    >>> # PIV
    >>> with PIVBackend("yubikey_123", pin="123456") as piv:
    ...     sig = piv.sign(0x9C, b"data_hash")
    ...     pub = piv.get_public_key(0x9C)
    >>>
    >>> # OpenPGP
    >>> with OpenPGPBackend("sc_0_YubiKey", pin="123456") as pgp:
    ...     sig = pgp.sign(b"data_hash")
    ...     keys = pgp.get_public_keys()
    >>>
    >>> # TPM
    >>> with TPMBackend("/dev/tpm0") as tpm:
    ...     pub = tpm.create_key("my_key")
    ...     sig = tpm.sign("my_key", b"data_hash")
    ...     sealed = tpm.seal(b"secret", policy={"pcr": [0, 1, 2]})

Version: 1.0.0
Date: 2026-04-05
Author: Mike Voyager
"""

from __future__ import annotations

# OpenPGP Backend
from src.security.hardware.openpgp_backend import (
    OPENPGP_AID,
    OpenPGPAlgorithm,
    OpenPGPBackend,
    OpenPGPCardInfo,
    OpenPGPPublicKeys,
    OpenPGPSlot,
)

# PIV Backend
from src.security.hardware.piv_backend import (
    PIV_AID,
    PIV_SLOT_AUTHENTICATION,
    PIV_SLOT_CARD_AUTHENTICATION,
    PIV_SLOT_DIGITAL_SIGNATURE,
    PIV_SLOT_KEY_MANAGEMENT,
    PIVAlgorithm,
    PIVBackend,
    PIVCardInfo,
    PIVPublicKey,
    PIVSlotType,
)

# TPM Backend
from src.security.hardware.tpm_backend import (
    DEFAULT_TPM_PATH,
    TPMBackend,
    TPMCapabilities,
    TPMKeyInfo,
    TPMKeyType,
    TPMPolicy,
    TPMSealType,
)

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-05"

__all__ = [
    # PIV
    "PIVBackend",
    "PIVPublicKey",
    "PIVCardInfo",
    "PIVAlgorithm",
    "PIVSlotType",
    "PIV_AID",
    "PIV_SLOT_AUTHENTICATION",
    "PIV_SLOT_DIGITAL_SIGNATURE",
    "PIV_SLOT_KEY_MANAGEMENT",
    "PIV_SLOT_CARD_AUTHENTICATION",
    # OpenPGP
    "OpenPGPBackend",
    "OpenPGPSlot",
    "OpenPGPAlgorithm",
    "OpenPGPPublicKeys",
    "OpenPGPCardInfo",
    "OPENPGP_AID",
    # TPM
    "TPMBackend",
    "TPMKeyInfo",
    "TPMPolicy",
    "TPMCapabilities",
    "TPMKeyType",
    "TPMSealType",
    "DEFAULT_TPM_PATH",
]
