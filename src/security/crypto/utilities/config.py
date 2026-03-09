"""
Конфигурация криптографического модуля.

Централизованные настройки для всех 46 алгоритмов из CRYPTO_MASTER_PLAN v2.3.
Включает профили безопасности, floppy-оптимизацию и сериализацию конфигурации.

Example:
    >>> from src.security.crypto.utilities.config import CryptoConfig
    >>> config = CryptoConfig.default()
    >>> config.default_symmetric
    'aes-256-gcm'
    >>> floppy = CryptoConfig.floppy_aggressive()
    >>> floppy.compress_keystore
    True

Version: 1.1
Date: March 9, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from dataclasses import fields as dataclass_fields
from typing import Any, Dict, Literal

logger = logging.getLogger(__name__)

__all__: list[str] = [
    "FloppyMode",
    "SymmetricAlgorithm",
    "SigningAlgorithm",
    "HashAlgorithm",
    "KDFAlgorithm",
    "CryptoConfig",
]

__version__ = "1.1.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-09"

# ==============================================================================
# TYPES
# ==============================================================================

FloppyMode = Literal["disabled", "basic", "aggressive"]
"""Режим оптимизации для дискет."""

SymmetricAlgorithm = Literal["aes-256-gcm", "chacha20-poly1305"]
"""Поддерживаемые симметричные алгоритмы."""

SigningAlgorithm = Literal["ed25519", "rsa-pss-4096"]
"""Поддерживаемые алгоритмы подписи."""

HashAlgorithm = Literal["sha-256", "sha-512", "sha3-256", "blake2b"]
"""Поддерживаемые хеш-функции."""

KDFAlgorithm = Literal["argon2id", "scrypt", "pbkdf2-sha512"]
"""Поддерживаемые функции деривации ключей."""

# ==============================================================================
# CONFIGURATION
# ==============================================================================


# NOTE: dataclass намеренно мутабелен из-за apply_floppy_mode().
# Альтернатива — frozen=True + with_floppy_mode() → рассмотреть в v2.0
# при изменении публичного API.
@dataclass
class CryptoConfig:
    """
    Конфигурация криптографического модуля.

    Хранит все параметры: алгоритмы по умолчанию, ротация ключей,
    ограничения размеров и floppy-оптимизация.

    Note:
        Класс намеренно мутабелен для поддержки apply_floppy_mode().
        Используйте factory-методы (default, paranoid, floppy_basic,
        floppy_aggressive) вместо прямой инициализации.

    Example:
        >>> config = CryptoConfig.default()
        >>> config.auto_rotation_enabled
        True
        >>> config.rotation_interval_days
        90
        >>> paranoid = CryptoConfig.paranoid()
        >>> paranoid.min_key_size
        32
    """

    # --- Алгоритмы по умолчанию ---

    default_symmetric: str = "aes-256-gcm"
    """Симметричный шифр по умолчанию."""

    default_signing: str = "ed25519"
    """Алгоритм подписи по умолчанию."""

    default_hash: str = "sha-256"
    """Хеш-функция по умолчанию."""

    default_kdf: str = "argon2id"
    """Функция деривации ключей по умолчанию."""

    # --- Ротация ключей ---

    auto_rotation_enabled: bool = True
    """Включена ли автоматическая ротация ключей."""

    rotation_interval_days: int = 90
    """Интервал ротации ключей в днях (> 0)."""

    # --- Безопасность ---

    min_key_size: int = 16
    """Минимальный размер ключа в байтах (≥ 16, т.е. 128 бит)."""

    allow_legacy: bool = False
    """Разрешить использование устаревших алгоритмов (DES, 3DES)."""

    require_hardware_rng: bool = False
    """Требовать аппаратный ГСЧ."""

    # --- Floppy-оптимизация ---

    floppy_mode: FloppyMode = "disabled"
    """Режим оптимизации для дискет."""

    max_storage_size: int = 1_457_664
    """Максимальный размер хранилища в байтах (> 0). По умолчанию 1.44 MB."""

    compress_keystore: bool = False
    """Сжимать хранилище ключей (zlib)."""

    compact_key_format: bool = False
    """Использовать компактный формат ключей."""

    auto_cleanup_backups: bool = False
    """Автоматически удалять старые бэкапы."""

    max_backup_count: int = 5
    """Максимальное количество бэкапов (≥ 0)."""

    # --- Validation ---

    def __post_init__(self) -> None:
        """
        Валидация параметров после инициализации.

        Raises:
            ValueError: Если параметр нарушает инварианты безопасности.
        """
        if self.min_key_size < 16:
            raise ValueError(
                f"Параметр 'min_key_size' должен быть ≥ 16 байт (128 бит), "
                f"получено: {self.min_key_size}."
            )
        if self.rotation_interval_days <= 0:
            raise ValueError(
                f"Параметр 'rotation_interval_days' должен быть > 0, "
                f"получено: {self.rotation_interval_days}."
            )
        if self.max_backup_count < 0:
            raise ValueError(
                f"Параметр 'max_backup_count' должен быть ≥ 0, получено: {self.max_backup_count}."
            )
        if self.max_storage_size <= 0:
            raise ValueError(
                f"Параметр 'max_storage_size' должен быть > 0, получено: {self.max_storage_size}."
            )
        logger.debug(
            "CryptoConfig создан: symmetric=%s, signing=%s, floppy=%s",
            self.default_symmetric,
            self.default_signing,
            self.floppy_mode,
        )

    # --- Factory methods ---

    @classmethod
    def default(cls) -> CryptoConfig:
        """
        Конфигурация по умолчанию.

        Стандартные настройки для большинства случаев использования.
        AES-256-GCM, Ed25519, SHA-256, Argon2id.

        Returns:
            Стандартная конфигурация.

        Example:
            >>> config = CryptoConfig.default()
            >>> config.default_symmetric
            'aes-256-gcm'
        """
        return cls()

    @classmethod
    def paranoid(cls) -> CryptoConfig:
        """
        Параноидальная конфигурация.

        Максимальная безопасность: большие ключи (32 байта / 256 бит),
        частая ротация (30 дней), запрет legacy алгоритмов, требование
        аппаратного ГСЧ.

        Returns:
            Конфигурация с максимальной безопасностью.

        Example:
            >>> config = CryptoConfig.paranoid()
            >>> config.require_hardware_rng
            True
            >>> config.rotation_interval_days
            30
        """
        return cls(
            default_symmetric="aes-256-gcm",
            default_signing="ed25519",
            default_hash="sha-512",
            default_kdf="argon2id",
            auto_rotation_enabled=True,
            rotation_interval_days=30,
            min_key_size=32,
            allow_legacy=False,
            require_hardware_rng=True,
        )

    @classmethod
    def floppy_basic(cls) -> CryptoConfig:
        """
        Базовая floppy-конфигурация.

        Оптимизация для ограниченного хранилища (1.44 MB) с сохранением
        совместимости форматов. Включает сжатие keystore и автоочистку
        бэкапов (не более 3).

        Returns:
            Конфигурация с базовой floppy-оптимизацией.

        Example:
            >>> config = CryptoConfig.floppy_basic()
            >>> config.compress_keystore
            True
            >>> config.max_backup_count
            3
        """
        return cls(
            floppy_mode="basic",
            compress_keystore=True,
            compact_key_format=False,
            auto_cleanup_backups=True,
            max_backup_count=3,
        )

    @classmethod
    def floppy_aggressive(cls) -> CryptoConfig:
        """
        Агрессивная floppy-конфигурация.

        Максимальная экономия места: сжатие, компактные форматы,
        минимум бэкапов (1). Подходит для реально ограниченных носителей
        3.5" (1.44 MB).

        Returns:
            Конфигурация с агрессивной floppy-оптимизацией.

        Example:
            >>> config = CryptoConfig.floppy_aggressive()
            >>> config.compact_key_format
            True
            >>> config.max_backup_count
            1
        """
        return cls(
            floppy_mode="aggressive",
            compress_keystore=True,
            compact_key_format=True,
            auto_cleanup_backups=True,
            max_backup_count=1,
            max_storage_size=1_457_664,
        )

    # --- Methods ---

    def apply_floppy_mode(self, mode: FloppyMode) -> None:
        """
        Применить floppy-режим к текущей конфигурации (in-place).

        Обновляет все связанные поля в соответствии с выбранным режимом.
        При переходе в 'aggressive' также сбрасывает max_storage_size
        до значения 1.44 MB.

        Args:
            mode: Режим оптимизации ('disabled', 'basic', 'aggressive').

        Example:
            >>> config = CryptoConfig.default()
            >>> config.apply_floppy_mode("aggressive")
            >>> config.compress_keystore
            True
            >>> config.max_storage_size
            1457664
        """
        logger.debug("Применяется floppy-режим: %r", mode)
        self.floppy_mode = mode
        if mode == "disabled":
            self.compress_keystore = False
            self.compact_key_format = False
            self.auto_cleanup_backups = False
        elif mode == "basic":
            self.compress_keystore = True
            self.compact_key_format = False
            self.auto_cleanup_backups = True
            self.max_backup_count = 3
        elif mode == "aggressive":
            self.compress_keystore = True
            self.compact_key_format = True
            self.auto_cleanup_backups = True
            self.max_backup_count = 1
            self.max_storage_size = 1_457_664

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация конфигурации в словарь.

        Returns:
            Словарь со всеми параметрами конфигурации.

        Example:
            >>> config = CryptoConfig.default()
            >>> d = config.to_dict()
            >>> d["default_symmetric"]
            'aes-256-gcm'
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CryptoConfig:
        """
        Десериализация конфигурации из словаря.

        Неизвестные ключи молча игнорируются (логируются на WARNING)
        для совместимости при изменении схемы конфигурации между версиями.

        Args:
            data: Словарь с параметрами конфигурации.

        Returns:
            Экземпляр CryptoConfig.

        Example:
            >>> config = CryptoConfig.from_dict({"rotation_interval_days": 60})
            >>> config.rotation_interval_days
            60
            >>> config.default_symmetric  # остальное — дефолт
            'aes-256-gcm'
        """
        known_fields = {f.name for f in dataclass_fields(cls)}
        unknown = set(data.keys()) - known_fields
        if unknown:
            logger.warning(
                "CryptoConfig.from_dict: неизвестные поля проигнорированы: %s",
                sorted(unknown),
            )
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)
