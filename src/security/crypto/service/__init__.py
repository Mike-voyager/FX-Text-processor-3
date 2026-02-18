"""
Сервисный слой криптографической подсистемы.

Экспортирует унифицированный высокоуровневый API:
    CryptoService    — основной сервис для всех операций
    EncryptedDocument — результат encrypt_document()
    SignedDocument    — результат sign_document()
    CryptoProfile     — enum профилей конфигурации
    ProfileConfig     — конфигурация алгоритмов для профиля
    get_profile_config() — получить конфигурацию профиля

Пример быстрого старта:
    >>> from src.security.crypto.service import CryptoService, CryptoProfile
    >>> service = CryptoService(profile=CryptoProfile.STANDARD)
    >>> key = service.generate_symmetric_key()
    >>> encrypted = service.encrypt_document(b"Hello", key)
    >>> plaintext = service.decrypt_document(encrypted, key)

Phase 7 — Service Layer (CRITICAL)
Date: February 17, 2026
"""

from src.security.crypto.service.crypto_service import (
    CryptoService,
    EncryptedDocument,
    SignedDocument,
)
from src.security.crypto.service.profiles import (
    CryptoProfile,
    ProfileConfig,
    get_profile_config,
    list_profiles,
)
from src.security.crypto.service.ui_helpers import (
    format_algorithm_info,
    format_algorithm_short,
    get_algorithm_warning,
    get_floppy_badge,
    get_profile_summary,
    get_security_badge,
    list_recommended_algorithms,
)

__all__ = [
    # Main service
    "CryptoService",
    # Result dataclasses
    "EncryptedDocument",
    "SignedDocument",
    # Profiles
    "CryptoProfile",
    "ProfileConfig",
    "get_profile_config",
    "list_profiles",
    # UI helpers
    "get_security_badge",
    "get_floppy_badge",
    "format_algorithm_info",
    "format_algorithm_short",
    "list_recommended_algorithms",
    "get_algorithm_warning",
    "get_profile_summary",
]
