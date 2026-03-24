"""
Модели данных для модуля блокировки сессии.

Определяет:
- LockState: Состояние блокировки
- LockReason: Причина блокировки
- LockEvent: Событие блокировки

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4


class LockState(Enum):
    """
    Состояния блокировки сессии.

    States:
        UNLOCKED: Сессия активна, пользователь работает
        LOCKED: Сессия заблокирована, требуется разблокировка
        LOCKING: Переходное состояние, выполняется блокировка
        UNLOCKING: Переходное состояние, выполняется разблокировка
    """

    UNLOCKED = "unlocked"
    """Сессия активна."""

    LOCKED = "locked"
    """Сессия заблокирована."""

    LOCKING = "locking"
    """Выполняется блокировка."""

    UNLOCKING = "unlocking"
    """Выполняется разблокировка."""

    @property
    def is_transition(self) -> bool:
        """Переходное состояние."""
        return self in (LockState.LOCKING, LockState.UNLOCKING)

    @property
    def is_locked(self) -> bool:
        """Сессия заблокирована или блокируется."""
        return self in (LockState.LOCKED, LockState.LOCKING)


class LockReason(Enum):
    """
    Причины блокировки.

    Reasons:
        MANUAL: Ручная блокировка пользователем (Ctrl+L)
        IDLE_TIMEOUT: Таймаут неактивности
        SYSTEM: Системное событие (sleep, hibernate)
        SECURITY: Событие безопасности (подозрительная активность)
        MFA_REQUIRED: Требуется MFA подтверждение
    """

    MANUAL = "manual"
    """Ручная блокировка (Ctrl+L или меню)."""

    IDLE_TIMEOUT = "idle_timeout"
    """Автоматическая блокировка по таймауту."""

    SYSTEM = "system"
    """Системное событие (sleep/hibernate)."""

    SECURITY = "security"
    """Событие безопасности."""

    MFA_REQUIRED = "mfa_required"
    """Требуется MFA для критической операции."""

    @property
    def is_automatic(self) -> bool:
        """Автоматическая блокировка."""
        return self in (LockReason.IDLE_TIMEOUT, LockReason.SYSTEM, LockReason.SECURITY)

    @property
    def requires_mfa_to_unlock(self) -> bool:
        """Требует MFA для разблокировки."""
        return self in (LockReason.SECURITY, LockReason.MFA_REQUIRED)


@dataclass(frozen=True)
class LockEvent:
    """
    Событие блокировки/разблокировки.

    Immutable событие для audit log.

    Attributes:
        event_id: Уникальный идентификатор (UUID v4)
        event_type: Тип события (locked/unlocked)
        timestamp: Время события (UTC)
        reason: Причина блокировки
        session_id: ID сессии
        user_id: ID пользователя
        mfa_method: Использованный MFA метод (опционально)
        metadata: Дополнительные метаданные
    """

    event_id: str
    event_type: str  # "locked" or "unlocked"
    timestamp: datetime
    reason: LockReason
    session_id: str
    user_id: str
    mfa_method: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create_lock_event(
        cls,
        reason: LockReason,
        session_id: str,
        user_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "LockEvent":
        """
        Создать событие блокировки.

        Args:
            reason: Причина блокировки
            session_id: ID сессии
            user_id: ID пользователя
            metadata: Дополнительные метаданные

        Returns:
            LockEvent с типом "locked"
        """
        return cls(
            event_id=str(uuid4()),
            event_type="locked",
            timestamp=datetime.now(timezone.utc),
            reason=reason,
            session_id=session_id,
            user_id=user_id,
            metadata=metadata or {},
        )

    @classmethod
    def create_unlock_event(
        cls,
        session_id: str,
        user_id: str,
        mfa_method: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "LockEvent":
        """
        Создать событие разблокировки.

        Args:
            session_id: ID сессии
            user_id: ID пользователя
            mfa_method: Использованный MFA метод
            metadata: Дополнительные метаданные

        Returns:
            LockEvent с типом "unlocked"
        """
        return cls(
            event_id=str(uuid4()),
            event_type="unlocked",
            timestamp=datetime.now(timezone.utc),
            reason=LockReason.MANUAL,  # Разблокировка всегда manual
            session_id=session_id,
            user_id=user_id,
            mfa_method=mfa_method,
            metadata=metadata or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason.value,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "mfa_method": self.mfa_method,
            "metadata": {k: str(v)[:100] for k, v in self.metadata.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LockEvent":
        """Десериализация из словаря."""
        return cls(
            event_id=data["event_id"],
            event_type=data["event_type"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            reason=LockReason(data["reason"]),
            session_id=data["session_id"],
            user_id=data["user_id"],
            mfa_method=data.get("mfa_method"),
            metadata=data.get("metadata", {}),
        )


@dataclass(frozen=True)
class LockConfig:
    """
    Конфигурация блокировки.

    Attributes:
        idle_timeout_seconds: Таймаут неактивности (0 = отключено)
        mfa_required_for_unlock: Требовать MFA для разблокировки
        max_unlock_attempts: Максимум попыток разблокировки
        lock_on_system_events: Блокировать при sleep/hibernate
        clear_clipboard_on_lock: Очищать буфер обмена при блокировке
        wipe_memory_on_lock: Обнулять чувствительную память
    """

    idle_timeout_seconds: int = 300  # 5 минут
    mfa_required_for_unlock: bool = True
    max_unlock_attempts: int = 3
    lock_on_system_events: bool = True
    clear_clipboard_on_lock: bool = True
    wipe_memory_on_lock: bool = True

    def __post_init__(self) -> None:
        """Валидация конфигурации."""
        if self.idle_timeout_seconds < 0:
            raise ValueError("idle_timeout_seconds должен быть >= 0")
        if self.max_unlock_attempts < 1:
            raise ValueError("max_unlock_attempts должен быть >= 1")

    @property
    def is_idle_timeout_enabled(self) -> bool:
        """Таймаут неактивности включён."""
        return self.idle_timeout_seconds > 0


__all__: list[str] = [
    "LockState",
    "LockReason",
    "LockEvent",
    "LockConfig",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"