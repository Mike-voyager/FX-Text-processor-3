"""
Подпакет аппаратных криптографических устройств.

Предоставляет интерфейс для работы со смарткартами (PIV, OpenPGP) и YubiKey.
Все криптографические операции (подпись, расшифровка, генерация ключей)
выполняются НА УСТРОЙСТВЕ — приватный ключ никогда не покидает аппаратный модуль.

Опциональные зависимости:
    - pyscard>=2.0.0: работа со смарткартами (PIV, OpenPGP)
    - yubikey-manager>=5.0.0: работа с YubiKey

Example:
    >>> from src.security.crypto.hardware import HardwareCryptoManager
    >>> manager = HardwareCryptoManager()
    >>> devices = manager.list_devices()

Version: 1.0
Date: February 22, 2026
Priority: Phase 9 (CRYPTO_MASTER_PLAN v2.3)
"""

from __future__ import annotations

from src.security.crypto.hardware.hardware_crypto import (
    HardwareCryptoManager,
    SmartcardInfo,
    SmartcardType,
    KeyGenerationCapability,
)

__all__: list[str] = [
    "HardwareCryptoManager",
    "SmartcardInfo",
    "SmartcardType",
    "KeyGenerationCapability",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-22"
