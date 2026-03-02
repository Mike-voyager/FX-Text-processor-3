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

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Literal

__all__: list[str] = [
    "FloppyMode",
    "CryptoConfig",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"


# ==============================================================================
# TYPES
# ==============================================================================

FloppyMode = Literal["disabled", "basic", "aggressive"]
"""Режим оптимизации для дискет."""


# ==============================================================================
# CONFIGURATION
# ==============================================================================


@dataclass
class CryptoConfig:
    """
    Конфигурация криптографического модуля.

    Хранит все параметры: алгоритмы по умолчанию, ротация ключей,
    ограничения размеров и floppy-оптимизация.

    Example:
        >>> config = CryptoConfig.default()
        >>> config.auto_rotation_enabled
        True
        >>> config.rotation_interval_days
        90
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
    """Интервал ротации ключей в днях."""

    # --- Безопасность ---
    min_key_size: int = 16
    """Минимальный размер ключа в байтах (128 бит)."""

    allow_legacy: bool = False
    """Разрешить использование устаревших алгоритмов (DES, 3DES)."""

    require_hardware_rng: bool = False
    """Требовать аппаратный ГСЧ."""

    # --- Floppy-оптимизация ---
    floppy_mode: FloppyMode = "disabled"
    """Режим оптимизации для дискет."""

    max_storage_size: int = 1_457_664
    """Максимальный размер хранилища в байтах (1.44 MB)."""

    compress_keystore: bool = False
    """Сжимать хранилище ключей (zlib)."""

    compact_key_format: bool = False
    """Использовать компактный формат ключей."""

    auto_cleanup_backups: bool = False
    """Автоматически удалять старые бэкапы."""

    max_backup_count: int = 5
    """Максимальное количество бэкапов."""

    # --- Factory methods ---

    @classmethod
    def default(cls) -> CryptoConfig:
        """
        Конфигурация по умолчанию.

        Стандартные настройки для большинства случаев использования.
        AES-256-GCM, Ed25519, SHA-256, Argon2id.

        Returns:
            Стандартная конфигурация.
        """
        return cls()

    @classmethod
    def paranoid(cls) -> CryptoConfig:
        """
        Параноидальная конфигурация.

        Максимальная безопасность: большие ключи, частая ротация,
        запрет legacy алгоритмов.

        Returns:
            Конфигурация с максимальной безопасностью.
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

        Оптимизация для ограниченного хранилища с сохранением
        совместимости форматов.

        Returns:
            Конфигурация с базовой floppy-оптимизацией.
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
        минимум бэкапов. Подходит для реально ограниченных носителей.

        Returns:
            Конфигурация с агрессивной floppy-оптимизацией.
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
        Применить floppy-режим к текущей конфигурации.

        Args:
            mode: Режим оптимизации ('disabled', 'basic', 'aggressive').
        """
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

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация конфигурации в словарь.

        Returns:
            Словарь со всеми параметрами конфигурации.
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CryptoConfig:
        """
        Десериализация конфигурации из словаря.

        Args:
            data: Словарь с параметрами конфигурации.

        Returns:
            Экземпляр CryptoConfig.
        """
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)
