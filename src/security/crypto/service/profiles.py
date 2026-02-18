"""
Профили конфигурации криптографической подсистемы.

Определяет CryptoProfile enum и ProfileConfig dataclass — наборы рекомендуемых
алгоритмов для каждого типа операций. Профиль выбирается один раз при создании
CryptoService и задаёт алгоритмы по умолчанию для всех операций.

Доступные профили:
    STANDARD          — Современный баланс скорости и безопасности
    PARANOID          — Максимальная безопасность (медленнее)
    LEGACY            — Совместимость со старыми системами (не для новых)
    FLOPPY_BASIC      — Оптимизация для дискет 3.5" (базовая)
    FLOPPY_AGGRESSIVE — Максимальная оптимизация для дискет 3.5"
    PQC_STANDARD      — Post-quantum стандарт (NIST Level 3)
    PQC_PARANOID      — Post-quantum максимум (NIST Level 5)

Example:
    >>> from src.security.crypto.service.profiles import CryptoProfile, get_profile_config
    >>> config = get_profile_config(CryptoProfile.STANDARD)
    >>> config.symmetric_algorithm
    'aes-256-gcm'
    >>> config.signing_algorithm
    'Ed25519'
    >>> config.post_quantum
    False

Version: 1.0
Date: February 17, 2026
Priority: Phase 7 — Service Layer
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

__all__ = [
    "CryptoProfile",
    "ProfileConfig",
    "PROFILES",
    "get_profile_config",
    "list_profiles",
]


# ==============================================================================
# ENUM: CRYPTO PROFILE
# ==============================================================================


class CryptoProfile(str, Enum):
    """
    Профиль конфигурации криптографической подсистемы.

    Каждый профиль задаёт набор рекомендуемых алгоритмов для всех типов
    криптографических операций. ID алгоритмов соответствуют ключам в
    AlgorithmRegistry.

    Значения (str): используются как ключи конфигурации.

    Example:
        >>> profile = CryptoProfile.STANDARD
        >>> profile.value
        'standard'
        >>> profile.label()
        'Стандартный'
        >>> profile.is_safe_for_new_systems()
        True
    """

    STANDARD = "standard"
    PARANOID = "paranoid"
    LEGACY = "legacy"
    FLOPPY_BASIC = "floppy_basic"
    FLOPPY_AGGRESSIVE = "floppy_aggressive"
    PQC_STANDARD = "pqc_standard"
    PQC_PARANOID = "pqc_paranoid"

    def label(self) -> str:
        """
        Читаемое название профиля на русском.

        Returns:
            Локализованное название

        Example:
            >>> CryptoProfile.LEGACY.label()
            'Legacy (совместимость)'
        """
        _labels: Dict[CryptoProfile, str] = {
            CryptoProfile.STANDARD: "Стандартный",
            CryptoProfile.PARANOID: "Параноидальный",
            CryptoProfile.LEGACY: "Legacy (совместимость)",
            CryptoProfile.FLOPPY_BASIC: "Дискета (базовый)",
            CryptoProfile.FLOPPY_AGGRESSIVE: "Дискета (агрессивный)",
            CryptoProfile.PQC_STANDARD: "Post-Quantum стандарт",
            CryptoProfile.PQC_PARANOID: "Post-Quantum параноидальный",
        }
        return _labels[self]

    def description(self) -> str:
        """
        Краткое описание профиля на русском.

        Returns:
            Описание с рекомендациями по применению
        """
        _descriptions: Dict[CryptoProfile, str] = {
            CryptoProfile.STANDARD: (
                "Баланс безопасности и производительности. "
                "AES-256-GCM + Ed25519 + X25519. Рекомендуется для большинства случаев."
            ),
            CryptoProfile.PARANOID: (
                "Максимальная безопасность. AES-256-GCM-SIV + Ed448 + X448. "
                "Медленнее, но устойчивее к будущим угрозам. Nonce-misuse resistant."
            ),
            CryptoProfile.LEGACY: (
                "Совместимость со старыми системами. 3DES + RSA-2048-PSS + PBKDF2. "
                "Только для обратной совместимости — НЕ рекомендуется для новых систем."
            ),
            CryptoProfile.FLOPPY_BASIC: (
                "Оптимизирован для дискет 3.5\" (1.44 MB). "
                "ChaCha20-Poly1305 + Ed25519 + BLAKE2s (малый overhead ключей)."
            ),
            CryptoProfile.FLOPPY_AGGRESSIVE: (
                "Максимальная оптимизация для дискет 3.5\". "
                "AES-128-GCM + Ed25519 + BLAKE2s (минимальный размер данных)."
            ),
            CryptoProfile.PQC_STANDARD: (
                "Post-quantum стандарт (NIST Level 3). "
                "AES-256-GCM + ML-DSA-65 + ML-KEM-768. Защита от квантовых атак."
            ),
            CryptoProfile.PQC_PARANOID: (
                "Post-quantum максимум (NIST Level 5). "
                "AES-256-GCM-SIV + ML-DSA-87 + ML-KEM-1024. "
                "Максимальная квантовая устойчивость."
            ),
        }
        return _descriptions[self]

    def is_safe_for_new_systems(self) -> bool:
        """
        Безопасен ли профиль для новых систем.

        Returns:
            False только для LEGACY (использует устаревшие алгоритмы)

        Example:
            >>> CryptoProfile.LEGACY.is_safe_for_new_systems()
            False
            >>> CryptoProfile.STANDARD.is_safe_for_new_systems()
            True
        """
        return self != CryptoProfile.LEGACY

    def is_floppy_optimized(self) -> bool:
        """
        Оптимизирован ли профиль для дискет.

        Returns:
            True для FLOPPY_BASIC и FLOPPY_AGGRESSIVE

        Example:
            >>> CryptoProfile.FLOPPY_BASIC.is_floppy_optimized()
            True
        """
        return self in (CryptoProfile.FLOPPY_BASIC, CryptoProfile.FLOPPY_AGGRESSIVE)

    def is_post_quantum(self) -> bool:
        """
        Использует ли профиль post-quantum алгоритмы.

        Returns:
            True для PQC_STANDARD и PQC_PARANOID

        Example:
            >>> CryptoProfile.PQC_STANDARD.is_post_quantum()
            True
        """
        return self in (CryptoProfile.PQC_STANDARD, CryptoProfile.PQC_PARANOID)


# ==============================================================================
# DATACLASS: PROFILE CONFIG
# ==============================================================================


@dataclass(frozen=True)
class ProfileConfig:
    """
    Конфигурация алгоритмов для профиля.

    Immutable dataclass, хранящий registry ID алгоритмов для каждого типа
    криптографической операции. Используется CryptoService как конфигурация
    по умолчанию.

    Attributes:
        profile: Профиль конфигурации
        symmetric_algorithm: ID симметричного шифра (registry key, lowercase)
        signing_algorithm: ID алгоритма подписи (registry key, PascalCase/uppercase)
        kex_algorithm: ID алгоритма обмена ключами (для гибридного шифрования)
        hash_algorithm: ID хеш-функции (для integrity checking)
        kdf_algorithm: ID KDF (для вывода ключей из паролей)
        asymmetric_algorithm: ID асимметричного алгоритма (для RSA шифрования)
        description: Описание профиля
        floppy_optimized: Оптимизирован ли для дискет
        post_quantum: Использует ли PQC алгоритмы
        safe_for_new_systems: Безопасен ли для новых систем
        additional_signing: Дополнительные алгоритмы подписи (для hybrid classical+PQC)

    Example:
        >>> config = get_profile_config(CryptoProfile.STANDARD)
        >>> config.symmetric_algorithm
        'aes-256-gcm'
        >>> config.algorithm_ids()
        {'symmetric': 'aes-256-gcm', 'signing': 'Ed25519', ...}
    """

    profile: CryptoProfile
    symmetric_algorithm: str
    signing_algorithm: str
    kex_algorithm: str
    hash_algorithm: str
    kdf_algorithm: str
    asymmetric_algorithm: str
    description: str
    floppy_optimized: bool = False
    post_quantum: bool = False
    safe_for_new_systems: bool = True
    additional_signing: List[str] = field(default_factory=list)

    def algorithm_ids(self) -> Dict[str, str]:
        """
        Все основные алгоритмы в виде словаря {категория: registry_id}.

        Returns:
            Словарь с ID алгоритмов для каждой категории

        Example:
            >>> config = get_profile_config(CryptoProfile.STANDARD)
            >>> ids = config.algorithm_ids()
            >>> ids["symmetric"]
            'aes-256-gcm'
            >>> ids["signing"]
            'Ed25519'
        """
        return {
            "symmetric": self.symmetric_algorithm,
            "signing": self.signing_algorithm,
            "kex": self.kex_algorithm,
            "hash": self.hash_algorithm,
            "kdf": self.kdf_algorithm,
            "asymmetric": self.asymmetric_algorithm,
        }


# ==============================================================================
# PROFILE DEFINITIONS
# ==============================================================================

#: Все предустановленные профили. Ключ — CryptoProfile, значение — ProfileConfig.
PROFILES: Dict[CryptoProfile, ProfileConfig] = {
    # ------------------------------------------------------------------
    # STANDARD: современный баланс безопасности и производительности
    # ------------------------------------------------------------------
    CryptoProfile.STANDARD: ProfileConfig(
        profile=CryptoProfile.STANDARD,
        symmetric_algorithm="aes-256-gcm",
        signing_algorithm="Ed25519",
        kex_algorithm="x25519",
        hash_algorithm="sha256",
        kdf_algorithm="argon2id",
        asymmetric_algorithm="RSA-OAEP-2048",
        description=CryptoProfile.STANDARD.description(),
        floppy_optimized=False,
        post_quantum=False,
        safe_for_new_systems=True,
    ),
    # ------------------------------------------------------------------
    # PARANOID: максимальная безопасность
    # ------------------------------------------------------------------
    CryptoProfile.PARANOID: ProfileConfig(
        profile=CryptoProfile.PARANOID,
        symmetric_algorithm="aes-256-gcm-siv",
        signing_algorithm="Ed448",
        kex_algorithm="x448",
        hash_algorithm="sha3-512",
        kdf_algorithm="argon2id",
        asymmetric_algorithm="RSA-OAEP-4096",
        description=CryptoProfile.PARANOID.description(),
        floppy_optimized=False,
        post_quantum=False,
        safe_for_new_systems=True,
    ),
    # ------------------------------------------------------------------
    # LEGACY: только для обратной совместимости
    # ------------------------------------------------------------------
    CryptoProfile.LEGACY: ProfileConfig(
        profile=CryptoProfile.LEGACY,
        symmetric_algorithm="3des-ede3",
        signing_algorithm="RSA-PSS-2048",
        kex_algorithm="x25519",  # KEX оставляем современным
        hash_algorithm="sha256",
        kdf_algorithm="pbkdf2-sha256",
        asymmetric_algorithm="RSA-OAEP-2048",
        description=CryptoProfile.LEGACY.description(),
        floppy_optimized=False,
        post_quantum=False,
        safe_for_new_systems=False,
    ),
    # ------------------------------------------------------------------
    # FLOPPY_BASIC: дискеты 3.5" — базовая оптимизация
    # ------------------------------------------------------------------
    CryptoProfile.FLOPPY_BASIC: ProfileConfig(
        profile=CryptoProfile.FLOPPY_BASIC,
        symmetric_algorithm="chacha20-poly1305",
        signing_algorithm="Ed25519",
        kex_algorithm="x25519",
        hash_algorithm="blake2s",
        kdf_algorithm="argon2id",
        asymmetric_algorithm="RSA-OAEP-2048",
        description=CryptoProfile.FLOPPY_BASIC.description(),
        floppy_optimized=True,
        post_quantum=False,
        safe_for_new_systems=True,
    ),
    # ------------------------------------------------------------------
    # FLOPPY_AGGRESSIVE: дискеты 3.5" — максимальная оптимизация
    # ------------------------------------------------------------------
    CryptoProfile.FLOPPY_AGGRESSIVE: ProfileConfig(
        profile=CryptoProfile.FLOPPY_AGGRESSIVE,
        symmetric_algorithm="aes-128-gcm",
        signing_algorithm="Ed25519",
        kex_algorithm="x25519",
        hash_algorithm="blake2s",
        kdf_algorithm="argon2id",
        asymmetric_algorithm="RSA-OAEP-2048",
        description=CryptoProfile.FLOPPY_AGGRESSIVE.description(),
        floppy_optimized=True,
        post_quantum=False,
        safe_for_new_systems=True,
    ),
    # ------------------------------------------------------------------
    # PQC_STANDARD: post-quantum стандарт (NIST Level 3)
    # ------------------------------------------------------------------
    CryptoProfile.PQC_STANDARD: ProfileConfig(
        profile=CryptoProfile.PQC_STANDARD,
        symmetric_algorithm="aes-256-gcm",
        signing_algorithm="ML-DSA-65",
        kex_algorithm="ml-kem-768",
        hash_algorithm="sha3-256",
        kdf_algorithm="argon2id",
        asymmetric_algorithm="RSA-OAEP-3072",
        description=CryptoProfile.PQC_STANDARD.description(),
        floppy_optimized=False,
        post_quantum=True,
        safe_for_new_systems=True,
        additional_signing=["Ed25519"],  # гибридная подпись classical+PQC
    ),
    # ------------------------------------------------------------------
    # PQC_PARANOID: post-quantum максимум (NIST Level 5)
    # ------------------------------------------------------------------
    CryptoProfile.PQC_PARANOID: ProfileConfig(
        profile=CryptoProfile.PQC_PARANOID,
        symmetric_algorithm="aes-256-gcm-siv",
        signing_algorithm="ML-DSA-87",
        kex_algorithm="ml-kem-1024",
        hash_algorithm="sha3-512",
        kdf_algorithm="argon2id",
        asymmetric_algorithm="RSA-OAEP-4096",
        description=CryptoProfile.PQC_PARANOID.description(),
        floppy_optimized=False,
        post_quantum=True,
        safe_for_new_systems=True,
        additional_signing=["Ed448"],  # гибридная подпись classical+PQC
    ),
}


# ==============================================================================
# PUBLIC API
# ==============================================================================


def get_profile_config(profile: CryptoProfile) -> ProfileConfig:
    """
    Получить конфигурацию для указанного профиля.

    Args:
        profile: Профиль криптографии

    Returns:
        ProfileConfig с набором алгоритмов для профиля

    Example:
        >>> config = get_profile_config(CryptoProfile.STANDARD)
        >>> config.symmetric_algorithm
        'aes-256-gcm'
        >>> config.post_quantum
        False

        >>> pqc = get_profile_config(CryptoProfile.PQC_STANDARD)
        >>> pqc.signing_algorithm
        'ML-DSA-65'
    """
    return PROFILES[profile]


def list_profiles(
    *,
    safe_only: bool = False,
    floppy_only: bool = False,
    pqc_only: bool = False,
) -> List[CryptoProfile]:
    """
    Список доступных профилей с опциональной фильтрацией.

    Args:
        safe_only: Только безопасные для новых систем (исключает LEGACY)
        floppy_only: Только оптимизированные для дискет
        pqc_only: Только post-quantum профили

    Returns:
        Отфильтрованный список профилей

    Example:
        >>> list_profiles()
        [<CryptoProfile.STANDARD: 'standard'>, ...]

        >>> list_profiles(floppy_only=True)
        [<CryptoProfile.FLOPPY_BASIC: 'floppy_basic'>,
         <CryptoProfile.FLOPPY_AGGRESSIVE: 'floppy_aggressive'>]

        >>> list_profiles(pqc_only=True)
        [<CryptoProfile.PQC_STANDARD: 'pqc_standard'>,
         <CryptoProfile.PQC_PARANOID: 'pqc_paranoid'>]
    """
    result = list(CryptoProfile)
    if safe_only:
        result = [p for p in result if PROFILES[p].safe_for_new_systems]
    if floppy_only:
        result = [p for p in result if PROFILES[p].floppy_optimized]
    if pqc_only:
        result = [p for p in result if PROFILES[p].post_quantum]
    return result


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-17"
