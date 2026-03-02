"""
Управление ротацией ключей.

Автоматическое и ручное обновление ключей с отслеживанием метаданных
ротации. Хранит историю в SecureStorage.

Example:
    >>> from src.security.crypto.utilities.key_rotation import KeyRotationManager
    >>> manager = KeyRotationManager(storage, config)
    >>> status = manager.rotate_key("main_key")
    >>> status.rotation_count
    1

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.security.crypto.core.exceptions import (
    CryptoError,
    CryptoKeyError,
)
from src.security.crypto.utilities.config import CryptoConfig
from src.security.crypto.utilities.secure_storage import SecureStorage

__all__: list[str] = [
    "KeyRotationStatus",
    "KeyRotationManager",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"

logger = logging.getLogger(__name__)

# Prefix для метаданных ротации в хранилище
_ROTATION_META_PREFIX = "_rotation_meta_"


# ==============================================================================
# DATA CLASSES
# ==============================================================================


@dataclass(frozen=True)
class KeyRotationStatus:
    """
    Статус ротации ключа.

    Attributes:
        key_id: Идентификатор ключа.
        created_at: Время создания (ISO 8601).
        rotated_at: Время последней ротации (ISO 8601 или None).
        rotation_count: Количество ротаций.
        next_rotation: Время следующей ротации (ISO 8601 или None).
    """

    key_id: str
    created_at: str
    rotated_at: Optional[str] = None
    rotation_count: int = 0
    next_rotation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "key_id": self.key_id,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "rotation_count": self.rotation_count,
            "next_rotation": self.next_rotation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KeyRotationStatus:
        """Десериализация из словаря."""
        return cls(
            key_id=data["key_id"],
            created_at=data["created_at"],
            rotated_at=data.get("rotated_at"),
            rotation_count=data.get("rotation_count", 0),
            next_rotation=data.get("next_rotation"),
        )


# ==============================================================================
# KEY ROTATION MANAGER
# ==============================================================================


class KeyRotationManager:
    """
    Управление ротацией ключей.

    Хранит метаданные ротации в SecureStorage с prefix '_rotation_meta_'.
    Поддерживает ручную и автоматическую (по расписанию) ротацию.

    Example:
        >>> manager = KeyRotationManager(storage, config)
        >>> status = manager.rotate_key("my_key", new_key=os.urandom(32))
        >>> manager.get_key_age_days("my_key")
        0
    """

    def __init__(
        self,
        storage: SecureStorage,
        config: Optional[CryptoConfig] = None,
    ) -> None:
        """
        Инициализация менеджера ротации.

        Args:
            storage: Хранилище ключей.
            config: Конфигурация (по умолчанию CryptoConfig.default()).
        """
        self._storage = storage
        self._config = config or CryptoConfig.default()

    def rotate_key(
        self,
        key_name: str,
        new_key: Optional[bytes] = None,
    ) -> KeyRotationStatus:
        """
        Ротация ключа.

        Заменяет текущий ключ новым и обновляет метаданные ротации.

        Args:
            key_name: Имя ключа в хранилище.
            new_key: Новый ключ. Если None, генерируется автоматически.

        Returns:
            Обновлённый статус ротации.

        Raises:
            CryptoKeyError: Если ключ не найден.
        """
        # Проверяем, что ключ существует
        if not self._storage.has_key(key_name):
            raise CryptoKeyError(f"Key not found for rotation: '{key_name}'")

        # Получаем текущий ключ для определения размера
        old_key = self._storage.retrieve_key(key_name)

        # Генерируем новый ключ если не указан
        if new_key is None:
            new_key = os.urandom(len(old_key))

        # Получаем текущие метаданные ротации
        meta = self._load_rotation_meta(key_name)
        now = datetime.now(timezone.utc).isoformat()

        rotation_count = meta.get("rotation_count", 0) + 1
        created_at = meta.get("created_at", now)

        # Вычисляем следующую ротацию
        next_rotation: Optional[str] = None
        if self._config.auto_rotation_enabled:
            from datetime import timedelta
            next_dt = datetime.now(timezone.utc) + timedelta(
                days=self._config.rotation_interval_days
            )
            next_rotation = next_dt.isoformat()

        # Сохраняем новый ключ
        self._storage.store_key(key_name, new_key)

        # Обновляем метаданные
        status = KeyRotationStatus(
            key_id=key_name,
            created_at=created_at,
            rotated_at=now,
            rotation_count=rotation_count,
            next_rotation=next_rotation,
        )
        self._save_rotation_meta(key_name, status.to_dict())

        logger.info(
            "Key rotated: '%s' (rotation #%d)", key_name, rotation_count
        )
        return status

    def schedule_rotation(
        self,
        key_name: str,
        interval_days: int,
    ) -> None:
        """
        Установить расписание ротации для ключа.

        Args:
            key_name: Имя ключа.
            interval_days: Интервал ротации в днях.
        """
        from datetime import timedelta

        meta = self._load_rotation_meta(key_name)
        next_dt = datetime.now(timezone.utc) + timedelta(days=interval_days)
        meta["next_rotation"] = next_dt.isoformat()
        meta.setdefault("key_id", key_name)
        meta.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        self._save_rotation_meta(key_name, meta)

        logger.info(
            "Rotation scheduled for '%s' in %d days", key_name, interval_days
        )

    def get_rotation_status(self, key_name: str) -> KeyRotationStatus:
        """
        Получение статуса ротации ключа.

        Args:
            key_name: Имя ключа.

        Returns:
            Текущий статус ротации.
        """
        meta = self._load_rotation_meta(key_name)
        if not meta:
            return KeyRotationStatus(
                key_id=key_name,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        return KeyRotationStatus.from_dict(meta)

    def list_due_for_rotation(self) -> List[str]:
        """
        Список ключей, требующих ротации.

        Returns:
            Имена ключей с истёкшим сроком ротации.
        """
        now = datetime.now(timezone.utc)
        due: List[str] = []

        for key_name in self._storage.list_keys():
            if key_name.startswith(_ROTATION_META_PREFIX):
                continue

            meta = self._load_rotation_meta(key_name)
            next_rotation = meta.get("next_rotation")
            if next_rotation:
                try:
                    next_dt = datetime.fromisoformat(next_rotation)
                    if next_dt <= now:
                        due.append(key_name)
                except (ValueError, TypeError):
                    continue

        return due

    def get_key_age_days(self, key_name: str) -> int:
        """
        Возраст ключа в днях.

        Args:
            key_name: Имя ключа.

        Returns:
            Количество дней с момента создания (или последней ротации).
        """
        meta = self._load_rotation_meta(key_name)
        reference = meta.get("rotated_at") or meta.get("created_at")
        if not reference:
            return 0

        try:
            ref_dt = datetime.fromisoformat(reference)
            delta = datetime.now(timezone.utc) - ref_dt
            return max(0, delta.days)
        except (ValueError, TypeError):
            return 0

    # --- Private ---

    def _meta_key(self, key_name: str) -> str:
        """Имя записи метаданных ротации в хранилище."""
        return f"{_ROTATION_META_PREFIX}{key_name}"

    def _load_rotation_meta(self, key_name: str) -> Dict[str, Any]:
        """Загрузка метаданных ротации."""
        meta_name = self._meta_key(key_name)
        if not self._storage.has_key(meta_name):
            return {}
        try:
            data = self._storage.retrieve_key(meta_name)
            parsed: Dict[str, Any] = json.loads(data.decode("utf-8"))
            return parsed
        except Exception:
            return {}

    def _save_rotation_meta(
        self, key_name: str, meta: Dict[str, Any]
    ) -> None:
        """Сохранение метаданных ротации."""
        meta_name = self._meta_key(key_name)
        data = json.dumps(meta, ensure_ascii=True).encode("utf-8")
        self._storage.store_key(meta_name, data)
