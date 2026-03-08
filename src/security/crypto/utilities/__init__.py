"""
Утилиты криптографического модуля FX Text Processor 3.

Пакет утилит для CRYPTO_MASTER_PLAN v2.3 (Phase 8):
конфигурация, пароли, хранилище, ротация, сериализация,
управление ключами и миграция алгоритмов.

Модули:
=======

- **config**: Конфигурация крипто-модуля (CryptoConfig)
- **utils**: Генерация ключей, NonceManager, SecureMemory, FloppyOptimizer
- **passwords**: Хеширование паролей (Argon2id / scrypt)
- **serialization**: Сериализация ключей (PEM, DER, JWK, COMPACT)
- **secure_storage**: Зашифрованное хранилище (AES-256-GCM)
- **key_management**: Импорт/экспорт/обёртывание ключей
- **key_rotation**: Ротация ключей с расписанием
- **migration**: Миграция между алгоритмами (crypto agility)

Version: 1.0.0
Date: March 2, 2026
"""

from src.security.crypto.utilities.config import (
    CryptoConfig,
    FloppyMode,
)
from src.security.crypto.utilities.key_management import (
    KeyManager,
)
from src.security.crypto.utilities.key_rotation import (
    KeyRotationManager,
    KeyRotationStatus,
)
from src.security.crypto.utilities.migration import (
    CryptoMigrator,
    MigrationResult,
)
from src.security.crypto.utilities.passwords import (
    PasswordHasher,
    PasswordStrength,
    PasswordStrengthResult,
)
from src.security.crypto.utilities.secure_storage import (
    SecureStorage,
)
from src.security.crypto.utilities.serialization import (
    KeyFormat,
    deserialize_key,
    detect_format,
    from_compact,
    from_pem,
    serialize_key,
    to_compact,
    to_pem,
)
from src.security.crypto.utilities.utils import (
    FloppyOptimizer,
    NonceManager,
    SecureMemory,
    constant_time_compare,
    generate_key,
    generate_salt,
)

__all__ = [
    # config
    "CryptoConfig",
    "FloppyMode",
    # utils
    "generate_key",
    "generate_salt",
    "constant_time_compare",
    "NonceManager",
    "SecureMemory",
    "FloppyOptimizer",
    # passwords
    "PasswordHasher",
    "PasswordStrength",
    "PasswordStrengthResult",
    # serialization
    "KeyFormat",
    "serialize_key",
    "deserialize_key",
    "to_pem",
    "from_pem",
    "to_compact",
    "from_compact",
    "detect_format",
    # secure_storage
    "SecureStorage",
    # key_management
    "KeyManager",
    # key_rotation
    "KeyRotationManager",
    "KeyRotationStatus",
    # migration
    "CryptoMigrator",
    "MigrationResult",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"
