"""
Продвинутые криптографические модули для FX Text Processor 3.

Этот пакет содержит высокоуровневые криптографические конструкции,
построенные поверх базовых алгоритмов из CRYPTO_MASTER_PLAN v2.3.

Модули:
=======

- **hybrid_encryption**: Гибридное шифрование (KEX + Symmetric)
    - HybridEncryption: X25519/Kyber + AES-GCM/ChaCha20
    - create_hybrid_cipher(): Factory с предустановками

- **group_encryption**: Групповое шифрование
    - GroupKeyManager: Шифрование для множества получателей
    - Обёртка group key для каждого участника

- **key_escrow**: Депонирование ключей
    - DualKeyEscrow: Двойной доступ (user + escrow agent)
    - Восстановление данных при утере ключа

- **session_keys**: PFS сессии с рачетингом
    - PFSSession: Perfect Forward Secrecy
    - Key ratcheting (Signal-like)

Version: 2.3.2
Date: February 18, 2026
"""

from src.security.crypto.advanced.hybrid_encryption import (
    HybridConfig,
    HybridEncryption,
    PRESETS,
    create_hybrid_cipher,
)
from src.security.crypto.advanced.group_encryption import (
    Group,
    GroupEncryptedMessage,
    GroupKeyManager,
    GroupMember,
)
from src.security.crypto.advanced.key_escrow import (
    DualKeyEscrow,
    EscrowEncryptedData,
)
from src.security.crypto.advanced.session_keys import (
    EncryptedSessionMessage,
    PFSSession,
    SessionHandshake,
    SessionState,
)

__all__ = [
    # hybrid_encryption
    "HybridEncryption",
    "HybridConfig",
    "PRESETS",
    "create_hybrid_cipher",
    # group_encryption
    "GroupKeyManager",
    "Group",
    "GroupMember",
    "GroupEncryptedMessage",
    # key_escrow
    "DualKeyEscrow",
    "EscrowEncryptedData",
    # session_keys
    "PFSSession",
    "SessionState",
    "SessionHandshake",
    "EncryptedSessionMessage",
]

__version__ = "2.3.2"
__author__ = "Mike Voyager"
__date__ = "2026-02-18"
