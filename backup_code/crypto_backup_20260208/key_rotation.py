# -*- coding: utf-8 -*-
"""
RU: Политика ротации ключей с автоматическим мониторингом.
EN: Key rotation policy with automatic monitoring.

Features:
- Age-based rotation (default: 90 days)
- Operation-based rotation (default: 2^31 encryptions)
- Automatic health monitoring
- Rotation event logging
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Final, Optional

from .exceptions import KeyNotFoundError, KeyRotationError

_LOGGER: Final = logging.getLogger(__name__)


@dataclass
class KeyMetadata:
    """
    Metadata for cryptographic key lifecycle management.

    Attributes:
        key_id: Unique key identifier.
        created_at: Key creation timestamp.
        encryptions_count: Number of encryption operations performed.
        max_age: Maximum key age before rotation (default 90 days).
        max_operations: Maximum operations before rotation (default 2^31).
        rotated_from: Previous key ID (if this key was rotated).
    """

    key_id: str
    created_at: datetime
    encryptions_count: int = 0
    max_age: timedelta = field(default_factory=lambda: timedelta(days=90))
    max_operations: int = 2**31  # 50% of AES-GCM birthday bound
    rotated_from: Optional[str] = None

    def needs_rotation(self) -> bool:
        """
        Determine if key rotation is required.

        Returns:
            True if rotation recommended.

        Policy:
            - Age exceeded: key older than max_age
            - Operations exceeded: more than max_operations encryptions
        """
        age_exceeded = (datetime.now() - self.created_at) > self.max_age
        ops_exceeded = self.encryptions_count >= self.max_operations

        if age_exceeded:
            _LOGGER.warning(
                "Key %s exceeds age limit (%d days)", self.key_id[:8], self.max_age.days
            )
        if ops_exceeded:
            _LOGGER.warning(
                "Key %s exceeds operation limit (%d ops)",
                self.key_id[:8],
                self.max_operations,
            )

        return age_exceeded or ops_exceeded

    def increment_operations(self, count: int = 1) -> None:
        """Increment encryption counter."""
        self.encryptions_count += count

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "key_id": self.key_id,
            "created_at": self.created_at.isoformat(),
            "encryptions_count": self.encryptions_count,
            "max_age_days": self.max_age.days,
            "max_operations": self.max_operations,
            "rotated_from": self.rotated_from,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyMetadata:
        """Deserialize from dictionary."""
        return cls(
            key_id=data["key_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            encryptions_count=data["encryptions_count"],
            max_age=timedelta(days=data["max_age_days"]),
            max_operations=data["max_operations"],
            rotated_from=data.get("rotated_from"),
        )


class KeyRotationManager:
    """
    Manages key rotation lifecycle for multiple keys.

    Features:
        - Persistent metadata storage (JSON)
        - Automatic rotation checks
        - Rotation history tracking

    Example:
        >>> manager = KeyRotationManager("keys_metadata.json")
        >>> meta = manager.create_key("aes-master-2024")
        >>> meta.increment_operations(1000)
        >>> if meta.needs_rotation():
        ...     new_meta = manager.rotate_key("aes-master-2024", "aes-master-2025")
    """

    def __init__(self, metadata_path: str):
        """
        Initialize key rotation manager.

        Args:
            metadata_path: Path to JSON file for persistent metadata.
        """
        self._metadata_path = Path(metadata_path)
        self._keys: Dict[str, KeyMetadata] = {}
        self._load_metadata()

    def _load_metadata(self) -> None:
        """Load key metadata from disk."""
        if not self._metadata_path.exists():
            _LOGGER.info("No existing metadata file, starting fresh")
            return

        try:
            with open(self._metadata_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for key_id, meta_dict in data.items():
                self._keys[key_id] = KeyMetadata.from_dict(meta_dict)

            _LOGGER.info("Loaded metadata for %d keys", len(self._keys))
        except Exception as e:
            _LOGGER.error("Failed to load metadata: %s", e)

    def _save_metadata(self) -> None:
        """Persist key metadata to disk."""
        try:
            data = {k: v.to_dict() for k, v in self._keys.items()}

            self._metadata_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self._metadata_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            _LOGGER.debug("Saved metadata for %d keys", len(self._keys))
        except Exception as e:
            _LOGGER.error("Failed to save metadata: %s", e)

    def create_key(
        self, key_id: str, max_age_days: int = 90, max_operations: int = 2**31
    ) -> KeyMetadata:
        """
        Register new key with metadata.

        Args:
            key_id: Unique key identifier.
            max_age_days: Maximum key age in days.
            max_operations: Maximum encryption operations.

        Returns:
            KeyMetadata instance.
        """
        if key_id in self._keys:
            raise KeyRotationError(f"Key {key_id} already exists")

        meta = KeyMetadata(
            key_id=key_id,
            created_at=datetime.now(),
            max_age=timedelta(days=max_age_days),
            max_operations=max_operations,
        )

        self._keys[key_id] = meta
        self._save_metadata()

        _LOGGER.info("Created key metadata: %s", key_id)
        return meta

    def get_key(self, key_id: str) -> Optional[KeyMetadata]:
        """Retrieve key metadata."""
        return self._keys.get(key_id)

    def rotate_key(self, old_key_id: str, new_key_id: str) -> KeyMetadata:
        """
        Rotate key and create new metadata.

        Args:
            old_key_id: Key being rotated out.
            new_key_id: New key replacing old one.

        Returns:
            New key metadata.
        """
        old_meta = self._keys.get(old_key_id)
        if old_meta is None:
            raise KeyNotFoundError(f"Key {old_key_id} not found")

        new_meta = KeyMetadata(
            key_id=new_key_id,
            created_at=datetime.now(),
            max_age=old_meta.max_age,
            max_operations=old_meta.max_operations,
            rotated_from=old_key_id,
        )

        self._keys[new_key_id] = new_meta
        self._save_metadata()

        _LOGGER.info("Rotated key: %s -> %s", old_key_id, new_key_id)
        return new_meta

    def check_all_keys(self) -> Dict[str, bool]:
        """
        Check rotation status for all keys.

        Returns:
            Dictionary mapping key_id -> needs_rotation.
        """
        results = {}
        for key_id, meta in self._keys.items():
            results[key_id] = meta.needs_rotation()

        needs_rotation = [k for k, v in results.items() if v]
        if needs_rotation:
            _LOGGER.warning("Keys requiring rotation: %s", needs_rotation)

        return results

    def increment_operations(self, key_id: str, count: int = 1) -> None:
        """
        Increment operation counter for key.

        Args:
            key_id: Key identifier.
            count: Number of operations to add.
        """
        meta = self._keys.get(key_id)
        if meta is None:
            raise KeyNotFoundError(f"Key {key_id} not found")

        meta.increment_operations(count)
        self._save_metadata()


__all__ = [
    "KeyMetadata",
    "KeyRotationManager",
]
