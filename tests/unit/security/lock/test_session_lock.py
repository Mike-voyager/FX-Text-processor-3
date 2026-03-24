"""
Тесты для SessionLockManager.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest import mock

import pytest

from src.security.lock.exceptions import (
    LockError,
    LockTimeoutError,
    UnlockError,
    UnlockMFARequiredError,
)
from src.security.lock.models import LockConfig, LockEvent, LockReason, LockState
from src.security.lock.session_lock import SessionLockManager


class TestLockModels:
    """Тесты моделей LockState, LockReason, LockEvent."""

    def test_lock_state_properties(self) -> None:
        """Тест свойств LockState."""
        assert LockState.UNLOCKED.is_transition is False
        assert LockState.LOCKED.is_transition is False
        assert LockState.LOCKING.is_transition is True
        assert LockState.UNLOCKING.is_transition is True

        assert LockState.UNLOCKED.is_locked is False
        assert LockState.LOCKED.is_locked is True
        assert LockState.LOCKING.is_locked is True

    def test_lock_reason_properties(self) -> None:
        """Тест свойств LockReason."""
        assert LockReason.MANUAL.is_automatic is False
        assert LockReason.IDLE_TIMEOUT.is_automatic is True
        assert LockReason.SYSTEM.is_automatic is True

        assert LockReason.MANUAL.requires_mfa_to_unlock is False
        assert LockReason.SECURITY.requires_mfa_to_unlock is True
        assert LockReason.MFA_REQUIRED.requires_mfa_to_unlock is True

    def test_lock_event_create_lock(self) -> None:
        """Тест создания события блокировки."""
        event = LockEvent.create_lock_event(
            reason=LockReason.MANUAL,
            session_id="session-123",
            user_id="user-456",
        )

        assert event.event_type == "locked"
        assert event.reason == LockReason.MANUAL
        assert event.session_id == "session-123"
        assert event.user_id == "user-456"
        assert event.mfa_method is None

    def test_lock_event_create_unlock(self) -> None:
        """Тест создания события разблокировки."""
        event = LockEvent.create_unlock_event(
            session_id="session-123",
            user_id="user-456",
            mfa_method="totp",
        )

        assert event.event_type == "unlocked"
        assert event.reason == LockReason.MANUAL
        assert event.session_id == "session-123"
        assert event.user_id == "user-456"
        assert event.mfa_method == "totp"

    def test_lock_event_serialization(self) -> None:
        """Тест сериализации/десериализации LockEvent."""
        event = LockEvent.create_lock_event(
            reason=LockReason.IDLE_TIMEOUT,
            session_id="session-123",
            user_id="user-456",
            metadata={"idle_seconds": 300},
        )

        data = event.to_dict()
        assert data["event_type"] == "locked"
        assert data["reason"] == "idle_timeout"
        assert data["session_id"] == "session-123"

        restored = LockEvent.from_dict(data)
        assert restored.event_type == event.event_type
        assert restored.reason == event.reason
        assert restored.session_id == event.session_id

    def test_lock_config_validation(self) -> None:
        """Тест валидации LockConfig."""
        # Валидная конфигурация
        config = LockConfig(
            idle_timeout_seconds=300,
            mfa_required_for_unlock=True,
        )
        assert config.idle_timeout_seconds == 300
        assert config.is_idle_timeout_enabled is True

        # Отключённый таймаут
        config_disabled = LockConfig(idle_timeout_seconds=0)
        assert config_disabled.is_idle_timeout_enabled is False

        # Невалидный таймаут
        with pytest.raises(ValueError):
            LockConfig(idle_timeout_seconds=-1)

        # Невалидное количество попыток
        with pytest.raises(ValueError):
            LockConfig(max_unlock_attempts=0)


class TestSessionLockManager:
    """Тесты SessionLockManager."""

    @pytest.fixture
    def manager(self) -> SessionLockManager:
        """Создать менеджер для тестов."""
        return SessionLockManager(
            config=LockConfig(idle_timeout_seconds=300, mfa_required_for_unlock=False),
            session_id="test-session",
            user_id="test-user",
        )

    def test_initial_state(self, manager: SessionLockManager) -> None:
        """Тест начального состояния."""
        assert manager.state == LockState.UNLOCKED
        assert manager.is_locked is False
        assert manager.lock_reason is None
        assert manager.locked_at is None

    def test_lock_manual(self, manager: SessionLockManager) -> None:
        """Тест ручной блокировки."""
        event = manager.lock(reason=LockReason.MANUAL)

        assert manager.state == LockState.LOCKED
        assert manager.is_locked is True
        assert manager.lock_reason == LockReason.MANUAL
        assert manager.locked_at is not None
        assert event.event_type == "locked"
        assert event.reason == LockReason.MANUAL

    def test_lock_already_locked(self, manager: SessionLockManager) -> None:
        """Тест повторной блокировки."""
        manager.lock(reason=LockReason.MANUAL)
        event = manager.lock(reason=LockReason.IDLE_TIMEOUT)

        # Должен вернуть событие с предыдущей причиной
        assert manager.lock_reason == LockReason.MANUAL
        assert event.metadata.get("already_locked") is True

    def test_unlock_success(self, manager: SessionLockManager) -> None:
        """Тест успешной разблокировки."""
        manager.lock(reason=LockReason.MANUAL)

        event = manager.unlock(password="password123")

        assert manager.state == LockState.UNLOCKED
        assert manager.is_locked is False
        assert manager.lock_reason is None
        assert event.event_type == "unlocked"

    def test_unlock_not_locked(self, manager: SessionLockManager) -> None:
        """Тест разблокировки незаблокированной сессии."""
        with pytest.raises(LockError) as exc_info:
            manager.unlock(password="password123")

        assert "not locked" in str(exc_info.value).lower()

    def test_unlock_wrong_password(self, manager: SessionLockManager) -> None:
        """Тест разблокировки с неверным паролем."""
        manager.lock(reason=LockReason.MANUAL)

        with pytest.raises(UnlockError) as exc_info:
            manager.unlock(password="")  # Пустой пароль

        assert manager.state == LockState.LOCKED
        assert manager._unlock_attempts == 1

    def test_unlock_max_attempts(self, manager: SessionLockManager) -> None:
        """Тест превышения попыток разблокировки."""
        manager.lock(reason=LockReason.MANUAL)
        manager.config = LockConfig(max_unlock_attempts=2)

        # Первая попытка
        with pytest.raises(UnlockError):
            manager.unlock(password="")

        # Вторая попытка
        with pytest.raises(UnlockError):
            manager.unlock(password="")

        # Третья попытка - превышен лимит
        with pytest.raises(LockTimeoutError):
            manager.unlock(password="")

    def test_unlock_mfa_required(self, manager: SessionLockManager) -> None:
        """Тест требования MFA для разблокировки."""
        manager.config = LockConfig(mfa_required_for_unlock=True)
        manager.lock(reason=LockReason.MANUAL)

        with pytest.raises(UnlockMFARequiredError) as exc_info:
            manager.unlock(password="password123")

        assert "MFA" in str(exc_info.value)
        assert "totp" in exc_info.value.mfa_methods

    def test_unlock_with_mfa(self, manager: SessionLockManager) -> None:
        """Тест разблокировки с MFA."""
        manager.config = LockConfig(mfa_required_for_unlock=True)
        manager.lock(reason=LockReason.MANUAL)

        event = manager.unlock(password="password123", mfa_code="123456")

        assert manager.state == LockState.UNLOCKED
        assert event.mfa_method == "totp"

    def test_lock_security_requires_mfa(self, manager: SessionLockManager) -> None:
        """Тест что SECURITY блокировка требует MFA для разблокировки."""
        manager.config = LockConfig(mfa_required_for_unlock=False)
        manager.lock(reason=LockReason.SECURITY)

        # Даже если mfa_required_for_unlock=False, SECURITY требует MFA
        with pytest.raises(UnlockMFARequiredError):
            manager.unlock(password="password123")

    def test_record_activity(self, manager: SessionLockManager) -> None:
        """Тест записи активности."""
        initial_idle = manager.idle_seconds

        time.sleep(0.1)  # Небольшая задержка
        manager.record_activity()

        # После record_activity idle_seconds должен быть близок к 0
        assert manager.idle_seconds < 1

    def test_callbacks(self, manager: SessionLockManager) -> None:
        """Тест callbacks при блокировке/разблокировке."""
        lock_called = []
        unlock_called = []

        manager.on_lock(lambda: lock_called.append(1))
        manager.on_unlock(lambda: unlock_called.append(1))

        manager.lock(reason=LockReason.MANUAL)
        assert len(lock_called) == 1

        manager.unlock(password="password123")
        assert len(unlock_called) == 1

    def test_audit_callback(self, manager: SessionLockManager) -> None:
        """Тест audit callback."""
        events = []

        def audit_callback(event_type: str, details: dict) -> None:
            events.append((event_type, details))

        manager.audit_callback = audit_callback

        manager.lock(reason=LockReason.MANUAL)
        manager.unlock(password="password123")

        assert len(events) == 2
        assert events[0][0] == "session.locked"
        assert events[1][0] == "session.unlocked"

    def test_clear_clipboard_on_lock(self, manager: SessionLockManager) -> None:
        """Тест очистки буфера обмена при блокировке."""
        manager.config = LockConfig(clear_clipboard_on_lock=True)

        with mock.patch("src.security.lock.session_lock.clear_clipboard") as mock_clear:
            manager.lock(reason=LockReason.MANUAL)
            mock_clear.assert_called_once()

    def test_repr(self, manager: SessionLockManager) -> None:
        """Тест строкового представления."""
        repr_str = repr(manager)
        assert "SessionLockManager" in repr_str
        assert "unlocked" in repr_str
        assert "test-user" in repr_str


class TestLockExceptions:
    """Тесты исключений модуля lock."""

    def test_lock_error(self) -> None:
        """Тест базового исключения LockError."""
        error = LockError("Test error", reason="manual", context={"key": "value"})

        assert error.message == "Test error"
        assert error.reason == "manual"
        assert error.context == {"key": "value"}
        assert "LockError" in str(error)
        assert "manual" in str(error)

    def test_lock_timeout_error(self) -> None:
        """Тест LockTimeoutError."""
        error = LockTimeoutError(timeout_seconds=300)

        assert error.timeout_seconds == 300
        assert "timeout" in str(error).lower()

    def test_unlock_error(self) -> None:
        """Тест UnlockError."""
        error = UnlockError("Invalid password", reason="invalid_password")

        assert error.message == "Invalid password"
        assert error.reason == "invalid_password"

    def test_unlock_mfa_required_error(self) -> None:
        """Тест UnlockMFARequiredError."""
        error = UnlockMFARequiredError(
            mfa_methods=["totp", "fido2", "backup_code"]
        )

        assert len(error.mfa_methods) == 3
        assert "totp" in error.mfa_methods
        assert "MFA" in str(error)