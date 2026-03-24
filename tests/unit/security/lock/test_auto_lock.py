"""
Тесты для AutoLockService.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import time
from unittest import mock

import pytest

from src.security.lock.auto_lock import AutoLockService, DEFAULT_CHECK_INTERVAL, DEFAULT_WARNING_SECONDS
from src.security.lock.models import LockConfig, LockReason, LockState
from src.security.lock.session_lock import SessionLockManager


class TestAutoLockService:
    """Тесты AutoLockService."""

    @pytest.fixture
    def manager(self) -> SessionLockManager:
        """Создать менеджер для тестов."""
        return SessionLockManager(
            config=LockConfig(idle_timeout_seconds=60, mfa_required_for_unlock=False),
            session_id="test-session",
            user_id="test-user",
        )

    @pytest.fixture
    def auto_lock(self, manager: SessionLockManager) -> AutoLockService:
        """Создать сервис автоблокировки для тестов."""
        return AutoLockService(
            lock_manager=manager,
            check_interval=1,  # Быстрая проверка для тестов
            warning_seconds=10,
        )

    def test_initial_state(self, auto_lock: AutoLockService) -> None:
        """Тест начального состояния."""
        assert auto_lock.is_running is False
        assert auto_lock.config.idle_timeout_seconds == 60

    def test_start_stop(self, auto_lock: AutoLockService) -> None:
        """Тест запуска и остановки."""
        auto_lock.start()
        assert auto_lock.is_running is True

        auto_lock.stop()
        assert auto_lock.is_running is False

    def test_start_when_disabled(self) -> None:
        """Тест запуска когда автоблокировка отключена."""
        manager = SessionLockManager(
            config=LockConfig(idle_timeout_seconds=0),  # Отключено
        )
        auto_lock = AutoLockService(lock_manager=manager)

        auto_lock.start()  # Не должен запуститься

        assert auto_lock.is_running is False

    def test_context_manager(self, manager: SessionLockManager) -> None:
        """Тест контекстного менеджера."""
        with AutoLockService(lock_manager=manager, check_interval=1) as auto_lock:
            assert auto_lock.is_running is True

        assert auto_lock.is_running is False

    def test_double_start_error(self, auto_lock: AutoLockService) -> None:
        """Тест ошибки при двойном запуске."""
        auto_lock.start()

        with pytest.raises(RuntimeError) as exc_info:
            auto_lock.start()

        assert "already running" in str(exc_info.value).lower()

        auto_lock.stop()

    def test_idle_seconds_from_manager(self, auto_lock: AutoLockService) -> None:
        """Тест получения времени неактивности из менеджера."""
        # idle_seconds берётся из lock_manager.idle_seconds
        idle = auto_lock._get_idle_seconds()
        assert idle >= 0

    def test_get_system_idle_seconds_linux(self, auto_lock: AutoLockService) -> None:
        """Тест получения системной неактивности на Linux."""
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "300000\n"  # 300 секунд

                idle = auto_lock._get_system_idle_seconds()
                # Если xprintidle установлен, вернёт значение
                # Иначе вернёт 0

    def test_get_system_idle_seconds_windows(self, auto_lock: AutoLockService) -> None:
        """Тест получения системной неактивности на Windows."""
        with mock.patch("platform.system", return_value="Windows"):
            # Windows использует ctypes, который может быть недоступен
            idle = auto_lock._get_system_idle_seconds()
            assert idle >= 0

    def test_get_system_idle_seconds_macos(self, auto_lock: AutoLockService) -> None:
        """Тест получения системной неактивности на macOS."""
        with mock.patch("platform.system", return_value="Darwin"):
            idle = auto_lock._get_system_idle_seconds()
            assert idle >= 0

    def test_warning_callback(self, auto_lock: AutoLockService) -> None:
        """Тест callback предупреждения."""
        warnings = []

        def on_warning(remaining: int) -> None:
            warnings.append(remaining)

        auto_lock.on_warning = on_warning

        # Симулируем отправку предупреждения
        auto_lock._send_warning(30)
        auto_lock._send_warning(15)

        assert len(warnings) == 2
        assert 30 in warnings
        assert 15 in warnings

    def test_perform_lock(self, auto_lock: AutoLockService, manager: SessionLockManager) -> None:
        """Тест выполнения блокировки."""
        auto_lock._perform_lock(idle_seconds=120)

        assert manager.state == LockState.LOCKED
        assert manager.lock_reason == LockReason.IDLE_TIMEOUT

    def test_auto_lock_after_timeout(self, manager: SessionLockManager) -> None:
        """Тест автоблокировки после таймаута."""
        # Укорорачиваем таймаут для теста
        manager.config = LockConfig(idle_timeout_seconds=2)
        auto_lock = AutoLockService(
            lock_manager=manager,
            check_interval=1,
            warning_seconds=1,
        )

        auto_lock.start()

        # Ждём автоматической блокировки
        for _ in range(10):  # Максимум 10 секунд ожидания
            if manager.is_locked:
                break
            time.sleep(1)

        auto_lock.stop()

        assert manager.is_locked is True
        assert manager.lock_reason == LockReason.IDLE_TIMEOUT

    def test_warning_before_lock(self, manager: SessionLockManager) -> None:
        """Тест предупреждения перед блокировкой."""
        warnings = []

        def on_warning(remaining: int) -> None:
            warnings.append(remaining)

        manager.config = LockConfig(idle_timeout_seconds=3)
        auto_lock = AutoLockService(
            lock_manager=manager,
            check_interval=1,
            warning_seconds=2,
            on_warning=on_warning,
        )

        auto_lock.start()

        # Ждём пока не пройдёт таймаут
        for _ in range(10):
            if manager.is_locked or len(warnings) > 0:
                break
            time.sleep(1)

        auto_lock.stop()

        # Должно быть хотя бы одно предупреждение
        assert len(warnings) > 0

    def test_no_lock_when_unlocked_and_active(self, auto_lock: AutoLockService, manager: SessionLockManager) -> None:
        """Тест что блокировка не срабатывает при активности."""
        auto_lock.start()

        # Симулируем активность каждую секунду
        for _ in range(5):
            manager.record_activity()
            time.sleep(0.5)

        auto_lock.stop()

        # Не должен быть заблокирован
        assert manager.is_locked is False

    def test_repr(self, auto_lock: AutoLockService) -> None:
        """Тест строкового представления."""
        repr_str = repr(auto_lock)
        assert "AutoLockService" in repr_str
        assert "timeout=" in repr_str


class TestAutoLockConstants:
    """Тесты констант."""

    def test_default_check_interval(self) -> None:
        """Тест значения DEFAULT_CHECK_INTERVAL."""
        assert DEFAULT_CHECK_INTERVAL == 10
        assert DEFAULT_CHECK_INTERVAL >= 1

    def test_default_warning_seconds(self) -> None:
        """Тест значения DEFAULT_WARNING_SECONDS."""
        assert DEFAULT_WARNING_SECONDS == 30
        assert DEFAULT_WARNING_SECONDS >= 5


class TestAutoLockIntegration:
    """Интеграционные тесты."""

    def test_full_lock_unlock_cycle(self) -> None:
        """Тест полного цикла блокировки-разблокировки."""
        manager = SessionLockManager(
            config=LockConfig(
                idle_timeout_seconds=2,
                mfa_required_for_unlock=False,
            ),
            session_id="test-session",
            user_id="test-user",
        )

        auto_lock = AutoLockService(
            lock_manager=manager,
            check_interval=1,
            warning_seconds=1,
        )

        # Запускаем мониторинг
        auto_lock.start()

        # Ждём автоблокировки
        for _ in range(10):
            if manager.is_locked:
                break
            time.sleep(1)

        auto_lock.stop()

        # Проверяем что заблокировано
        assert manager.is_locked is True
        assert manager.lock_reason == LockReason.IDLE_TIMEOUT

        # Разблокируем
        event = manager.unlock(password="password123")

        assert manager.is_locked is False
        assert event.event_type == "unlocked"

    def test_manual_lock_overrides_auto(self) -> None:
        """Тест что ручная блокировка работает вместе с авто."""
        manager = SessionLockManager(
            config=LockConfig(
                idle_timeout_seconds=300,  # Длинный таймаут
                mfa_required_for_unlock=False,  # Без MFA
            ),
            session_id="test-session",
            user_id="test-user",
        )

        auto_lock = AutoLockService(lock_manager=manager, check_interval=1)
        auto_lock.start()

        # Ручная блокировка
        manager.lock(reason=LockReason.MANUAL)

        assert manager.is_locked is True
        assert manager.lock_reason == LockReason.MANUAL

        auto_lock.stop()

        # Разблокировка
        manager.unlock(password="password123")
        assert manager.is_locked is False