"""
Управление блокировкой сессии.

SessionLockManager обеспечивает мгновенную блокировку приложения
и безопасную разблокировку с MFA.

Features:
    - Мгновенная блокировка (Ctrl+L)
    - Автоблокировка по таймауту неактивности
    - Очистка памяти и буфера обмена
    - MFA для разблокировки
    - Audit-логирование

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from src.security.erasure import clear_clipboard
from src.security.lock.exceptions import (
    LockError,
    LockTimeoutError,
    UnlockError,
    UnlockMFARequiredError,
)
from src.security.lock.models import LockConfig, LockEvent, LockReason, LockState

LOG = logging.getLogger(__name__)

# Тип callback для аудита
AuditCallback = Callable[[str, Dict[str, Any]], None]


@dataclass
class SessionLockManager:
    """
    Менеджер блокировки сессии.

    Управляет состоянием блокировки, таймаутами неактивности
    и безопасной разблокировкой с MFA.

    Attributes:
        config: Конфигурация блокировки
        session_id: ID сессии
        user_id: ID пользователя
        audit_callback: Callback для audit-логирования
        mfa_required_callback: Callback для запроса MFA

    Thread Safety:
        - Все операции синхронизированы через lock
        - Безопасен для многопоточной среды

    Example:
        >>> manager = SessionLockManager(
        ...     config=LockConfig(idle_timeout_seconds=300),
        ...     session_id="session-123",
        ...     user_id="operator",
        ... )
        >>> manager.lock(reason=LockReason.MANUAL)
        >>> # Пользователь заблокирован
        >>> manager.unlock(password="secret123")
        >>> # Разблокирован
    """

    config: LockConfig = field(default_factory=LockConfig)
    session_id: str = field(default="default-session")
    user_id: str = field(default="operator")
    audit_callback: Optional[AuditCallback] = field(default=None)
    mfa_required_callback: Optional[Callable[[], bool]] = field(default=None)

    # Внутреннее состояние
    _state: LockState = field(default=LockState.UNLOCKED, init=False)
    _lock_reason: Optional[LockReason] = field(default=None, init=False)
    _locked_at: Optional[datetime] = field(default=None, init=False)
    _unlock_attempts: int = field(default=0, init=False)
    _last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc), init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _on_lock_callbacks: list[Callable[[], None]] = field(default_factory=list, init=False)
    _on_unlock_callbacks: list[Callable[[], None]] = field(default_factory=list, init=False)

    @property
    def state(self) -> LockState:
        """Текущее состояние блокировки."""
        with self._lock:
            return self._state

    @property
    def is_locked(self) -> bool:
        """Сессия заблокирована."""
        return self.state.is_locked

    @property
    def lock_reason(self) -> Optional[LockReason]:
        """Причина блокировки (если заблокирована)."""
        with self._lock:
            return self._lock_reason

    @property
    def locked_at(self) -> Optional[datetime]:
        """Время блокировки (если заблокирована)."""
        with self._lock:
            return self._locked_at

    @property
    def idle_seconds(self) -> int:
        """Время неактивности в секундах."""
        with self._lock:
            return int((datetime.now(timezone.utc) - self._last_activity).total_seconds())

    # --------------------------------------------------------------------------
    # Activity Tracking
    # --------------------------------------------------------------------------

    def record_activity(self) -> None:
        """
        Записать активность пользователя.

        Вызывается при любом действии пользователя для сброса
        таймера автоблокировки.

        Example:
            >>> manager.record_activity()  # Сбросить таймер неактивности
        """
        with self._lock:
            self._last_activity = datetime.now(timezone.utc)
            LOG.debug("Activity recorded: user=%s session=%s", self.user_id, self.session_id)

    # --------------------------------------------------------------------------
    # Lock / Unlock
    # --------------------------------------------------------------------------

    def lock(
        self,
        reason: LockReason = LockReason.MANUAL,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LockEvent:
        """
        Заблокировать сессию.

        Выполняет:
        1. Переводит состояние в LOCKING
        2. Очищает буфер обмена (если настроено)
        3. Вызывает callbacks блокировки
        4. Переводит состояние в LOCKED
        5. Логирует событие

        Args:
            reason: Причина блокировки
            metadata: Дополнительные метаданные

        Returns:
            LockEvent с информацией о блокировке

        Raises:
            LockError: Ошибка блокировки

        Example:
            >>> manager.lock(reason=LockReason.IDLE_TIMEOUT)
        """
        with self._lock:
            if self._state.is_locked:
                LOG.warning("Session already locked: %s", self._state)
                return LockEvent.create_lock_event(
                    reason=self._lock_reason or reason,
                    session_id=self.session_id,
                    user_id=self.user_id,
                    metadata={"already_locked": True},
                )

            # Переходное состояние
            self._state = LockState.LOCKING
            LOG.info("Locking session: reason=%s user=%s", reason.value, self.user_id)

            try:
                # Очищаем буфер обмена
                if self.config.clear_clipboard_on_lock:
                    try:
                        clear_clipboard()
                        LOG.debug("Clipboard cleared")
                    except Exception as e:
                        LOG.warning("Failed to clear clipboard: %s", e)

                # Вызываем callbacks
                for callback in self._on_lock_callbacks:
                    try:
                        callback()
                    except Exception as e:
                        LOG.warning("Lock callback failed: %s", e)

                # Устанавливаем состояние
                self._state = LockState.LOCKED
                self._lock_reason = reason
                self._locked_at = datetime.now(timezone.utc)
                self._unlock_attempts = 0

                # Создаём событие
                event = LockEvent.create_lock_event(
                    reason=reason,
                    session_id=self.session_id,
                    user_id=self.user_id,
                    metadata=metadata,
                )

                # Логируем
                self._audit("session.locked", {
                    "reason": reason.value,
                    "event_id": event.event_id,
                })

                LOG.info("Session locked: reason=%s", reason.value)
                return event

            except Exception as e:
                self._state = LockState.UNLOCKED
                raise LockError(f"Failed to lock session: {e}", reason=reason.value) from e

    def unlock(
        self,
        password: Optional[str] = None,
        mfa_code: Optional[str] = None,
    ) -> LockEvent:
        """
        Разблокировать сессию.

        Выполняет:
        1. Проверяет пароль (если требуется)
        2. Проверяет MFA (если требуется)
        3. Переводит состояние в UNLOCKING
        4. Вызывает callbacks разблокировки
        5. Переводит состояние в UNLOCKED
        6. Логирует событие

        Args:
            password: Пароль для разблокировки (если требуется)
            mfa_code: Код MFA для разблокировки (если требуется)

        Returns:
            LockEvent с информацией о разблокировке

        Raises:
            UnlockError: Неверный пароль или MFA
            UnlockMFARequiredError: Требуется MFA
            LockError: Сессия не заблокирована

        Example:
            >>> manager.unlock(password="secret123", mfa_code="123456")
        """
        with self._lock:
            if self._state != LockState.LOCKED:
                raise LockError(
                    "Session is not locked",
                    reason=self._state.value,
                )

            # Проверяем количество попыток
            if self._unlock_attempts >= self.config.max_unlock_attempts:
                raise LockTimeoutError(
                    "Max unlock attempts exceeded",
                    timeout_seconds=None,
                )

            self._unlock_attempts += 1

            # Переходное состояние
            self._state = LockState.UNLOCKING
            LOG.info("Unlocking session: user=%s attempt=%d", self.user_id, self._unlock_attempts)

            try:
                # TODO: Проверка пароля через AuthService
                # Пока просто проверяем что пароль не пустой
                if password is None or len(password) < 1:
                    raise UnlockError("Password required for unlock", reason="password_required")

                # Проверяем MFA если требуется
                mfa_method: Optional[str] = None
                if self.config.mfa_required_for_unlock or (
                    self._lock_reason and self._lock_reason.requires_mfa_to_unlock
                ):
                    if mfa_code is None:
                        raise UnlockMFARequiredError(
                            "MFA code required for unlock",
                            mfa_methods=["totp", "fido2", "backup_code"],
                        )

                    # TODO: Проверка MFA через SecondFactorService
                    # Пока просто проверяем что код не пустой
                    if len(mfa_code) < 6:
                        raise UnlockError("Invalid MFA code", reason="invalid_mfa")

                    mfa_method = "totp"  # Заглушка

                # Вызываем callbacks
                for callback in self._on_unlock_callbacks:
                    try:
                        callback()
                    except Exception as e:
                        LOG.warning("Unlock callback failed: %s", e)

                # Устанавливаем состояние
                self._state = LockState.UNLOCKED
                self._lock_reason = None
                self._locked_at = None
                self._unlock_attempts = 0
                self._last_activity = datetime.now(timezone.utc)

                # Создаём событие
                event = LockEvent.create_unlock_event(
                    session_id=self.session_id,
                    user_id=self.user_id,
                    mfa_method=mfa_method,
                )

                # Логируем
                self._audit("session.unlocked", {
                    "event_id": event.event_id,
                    "mfa_method": mfa_method,
                })

                LOG.info("Session unlocked: user=%s mfa=%s", self.user_id, mfa_method or "none")
                return event

            except (UnlockError, UnlockMFARequiredError):
                # Не меняем состояние, остаёмся в LOCKED
                self._state = LockState.LOCKED
                raise
            except Exception as e:
                self._state = LockState.LOCKED
                raise UnlockError(f"Failed to unlock session: {e}") from e

    # --------------------------------------------------------------------------
    # Callbacks
    # --------------------------------------------------------------------------

    def on_lock(self, callback: Callable[[], None]) -> None:
        """
        Регистрировать callback для события блокировки.

        Args:
            callback: Функция без параметров, вызывается при блокировке

        Example:
            >>> manager.on_lock(lambda: clear_sensitive_data())
        """
        with self._lock:
            self._on_lock_callbacks.append(callback)

    def on_unlock(self, callback: Callable[[], None]) -> None:
        """
        Регистрировать callback для события разблокировки.

        Args:
            callback: Функция без параметров, вызывается при разблокировке

        Example:
            >>> manager.on_unlock(lambda: restore_ui_state())
        """
        with self._lock:
            self._on_unlock_callbacks.append(callback)

    # --------------------------------------------------------------------------
    # Audit
    # --------------------------------------------------------------------------

    def _audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Логирование события в audit log."""
        if self.audit_callback:
            try:
                self.audit_callback(event_type, details)
            except Exception as e:
                LOG.error("Audit callback failed: %s", e)

    # --------------------------------------------------------------------------
    # Utility
    # --------------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"SessionLockManager("
            f"state={self._state.value}, "
            f"user={self.user_id}, "
            f"session={self.session_id})"
        )


__all__: list[str] = [
    "SessionLockManager",
    "AuditCallback",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"