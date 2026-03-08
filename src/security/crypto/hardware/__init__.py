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

    >>> from src.security.crypto.hardware import create_backend, DeviceBackend
    >>> backend = create_backend("yubikey_123", "yubikey_piv", serial_number=123)
    >>> isinstance(backend, DeviceBackend)
    True

Version: 1.1.0
Date: 2026-03-02
Priority: Phase 9 (CRYPTO_MASTER_PLAN v2.3)
"""

from __future__ import annotations

from src.security.crypto.hardware.backends import (
    DeviceBackend,
    JavaCardRawBackend,
    OpenPGPDeviceBackend,
    SlotInfo,
    SlotStatus,
    YubiKeyPivBackend,
    create_backend,
)
from src.security.crypto.hardware.hardware_crypto import (
    HardwareCryptoManager,
    KeyGenerationCapability,
    SmartcardInfo,
    SmartcardType,
)

__all__: list[str] = [
    # Manager (legacy — Phase 9)
    "HardwareCryptoManager",
    "SmartcardInfo",
    "SmartcardType",
    "KeyGenerationCapability",
    # Backends (Phase 3 — Hardware Crypto Roadmap)
    "DeviceBackend",
    "SlotInfo",
    "SlotStatus",
    "YubiKeyPivBackend",
    "OpenPGPDeviceBackend",
    "JavaCardRawBackend",
    "create_backend",
]

__version__ = "1.1.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"
