# -*- coding: utf-8 -*-
"""
RU: Конфигурация криптографических параметров с профилями для разных устройств.
EN: Cryptographic parameters configuration with device-specific profiles.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


class Argon2Profile(str, Enum):
    """Predefined Argon2id parameter profiles for different device capabilities."""

    # Desktop/laptop systems (default)
    DESKTOP = "desktop"

    # High-performance servers
    SERVER = "server"

    # Custom tuning (use with explicit parameters)
    CUSTOM = "custom"


@dataclass(frozen=True)
class Argon2Config:
    """
    Argon2id configuration parameters.

    Attributes:
        time_cost: Number of iterations (higher = slower, more secure).
        memory_cost: Memory usage in KiB (higher = more GPU-resistant).
        parallelism: Number of parallel threads.
        salt_length: Salt length in bytes (default 16).

    Examples:
        >>> config = Argon2Config.from_profile(Argon2Profile.DESKTOP)
        >>> config.memory_cost
        65536

        >>> config = Argon2Config(time_cost=5, memory_cost=131072, parallelism=8)
        >>> config.time_cost
        5
    """

    time_cost: int
    memory_cost: int  # in KiB
    parallelism: int
    salt_length: int = 16

    def __post_init__(self) -> None:
        """Validate parameters."""
        if self.time_cost < 2:
            raise ValueError("time_cost must be >= 2")
        if self.memory_cost < 65536:
            raise ValueError("memory_cost must be >= 65536 KiB (64 MiB)")
        if self.parallelism < 1:
            raise ValueError("parallelism must be >= 1")
        if self.salt_length < 8 or self.salt_length > 64:
            raise ValueError("salt_length must be between 8 and 64 bytes")

    @staticmethod
    def from_profile(profile: Argon2Profile) -> "Argon2Config":
        """
        Create configuration from predefined profile.

        Args:
            profile: Device capability profile.

        Returns:
            Argon2Config instance.

        Examples:
            >>> cfg = Argon2Config.from_profile(Argon2Profile.MOBILE)
            >>> cfg.memory_cost  # Lighter for mobile
            32768
        """
        return _PROFILE_PARAMS[profile]


# Predefined profiles
_PROFILE_PARAMS: Final[dict[Argon2Profile, Argon2Config]] = {
    # Desktop: balanced security/performance (OWASP recommended minimum)
    Argon2Profile.DESKTOP: Argon2Config(
        time_cost=3,
        memory_cost=65536,  # 64 MiB
        parallelism=4,
    ),
    # Server: maximum security for high-value targets
    Argon2Profile.SERVER: Argon2Config(
        time_cost=5,
        memory_cost=131072,  # 128 MiB
        parallelism=8,
    ),
    # Custom: same as desktop (override with explicit params)
    Argon2Profile.CUSTOM: Argon2Config(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
    ),
}


__all__ = [
    "Argon2Profile",
    "Argon2Config",
]
