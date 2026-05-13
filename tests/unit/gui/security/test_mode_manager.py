# -*- coding: utf-8 -*-
"""Тесты для ModeManager.

Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest
from src.gui.security.mode_manager import ModeManager
from src.security.monitoring.models import (
    HealthCheckReport,
    HealthCheckResult,
    HealthCheckStatus,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    """Сброс singleton перед каждым тестом."""
    ModeManager.reset_instance()
    yield
    ModeManager.reset_instance()


@pytest.fixture
def mock_health_checker() -> MagicMock:
    """Создание мока HealthChecker."""
    mock = MagicMock()
    # По умолчанию healthy
    mock.run_critical.return_value = HealthCheckReport(
        checks=[
            HealthCheckResult.healthy("entropy"),
        ],
        overall_status=HealthCheckStatus.HEALTHY,
    )
    return mock


@pytest.fixture
def mock_auth_service() -> MagicMock:
    """Создание мока AuthService."""
    mock = MagicMock()
    mock_result = MagicMock()
    mock_result.success = True
    mock_result.session_id = "test-session-123"
    mock_result.failure_reason = None
    mock.authenticate.return_value = mock_result
    return mock


class TestModeManager:
    """Тесты для класса ModeManager."""

    def test_singleton_pattern(self) -> None:
        """Проверка singleton паттерна."""
        manager1 = ModeManager()
        manager2 = ModeManager()
        assert manager1 is manager2

    def test_initial_mode_is_normal(self) -> None:
        """Проверка начального режима."""
        manager = ModeManager()
        assert manager.get_current_mode() == ModeManager.MODE_NORMAL
        assert manager.is_normal()
        assert not manager.is_special()

    def test_is_normal_in_normal_mode(self) -> None:
        """Проверка is_normal() в Normal Mode."""
        manager = ModeManager()
        assert manager.is_normal()

    def test_is_special_in_normal_mode(self) -> None:
        """Проверка is_special() в Normal Mode."""
        manager = ModeManager()
        assert not manager.is_special()


class TestCanEnterSpecial:
    """Тесты для can_enter_special()."""

    def test_can_enter_from_normal(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка входа из Normal Mode."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        can_enter, reason = manager.can_enter_special()
        assert can_enter is True
        assert reason == "ok"

    def test_cannot_enter_when_already_special(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка блокировки при уже Special Mode."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        # Входим в Special
        manager.enter_special({"password": "test", "totp": "123456"})
        # Проверяем повторный вход
        can_enter, reason = manager.can_enter_special()
        assert can_enter is False
        assert reason == "already_special"

    def test_cannot_enter_when_disabled(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка блокировки когда Special Mode отключён."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.disable_special_mode("test reason")
        can_enter, reason = manager.can_enter_special()
        assert can_enter is False
        assert reason == "disabled"

    def test_cannot_enter_when_health_check_failed(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка блокировки при failed health check."""
        mock_health_checker.run_critical.return_value = HealthCheckReport(
            checks=[
                HealthCheckResult.unhealthy("entropy", "Low entropy"),
            ],
            overall_status=HealthCheckStatus.UNHEALTHY,
        )
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        can_enter, reason = manager.can_enter_special()
        assert can_enter is False
        assert reason == "health_check_failed"


class TestCanExitSpecial:
    """Тесты для can_exit_special()."""

    def test_cannot_exit_from_normal(self) -> None:
        """Проверка выхода из Normal Mode."""
        manager = ModeManager()
        can_exit, reason = manager.can_exit_special()
        assert can_exit is False
        assert reason == "already_normal"

    def test_can_exit_from_special(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка выхода из Special Mode."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.enter_special({"password": "test", "totp": "123456"})
        can_exit, reason = manager.can_exit_special()
        assert can_exit is True
        assert reason == "ok"


class TestEnterSpecial:
    """Тесты для enter_special()."""

    def test_enter_success(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Успешный вход в Special Mode."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        result = manager.enter_special({"password": "test", "totp": "123456"})
        assert result is True
        assert manager.is_special()

    def test_enter_without_auth_service(self, mock_health_checker: MagicMock) -> None:
        """Вход без auth_service должен вернуть False."""
        manager = ModeManager(health_checker=mock_health_checker)
        result = manager.enter_special({"password": "test", "totp": "123456"})
        assert result is False
        assert manager.is_normal()

    def test_enter_with_failed_mfa(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Вход с неправильным MFA."""
        mock_auth_service.authenticate.return_value.success = False
        mock_auth_service.authenticate.return_value.failure_reason = "invalid_mfa"
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        result = manager.enter_special({"password": "wrong", "totp": "000000"})
        assert result is False
        assert manager.is_normal()

    def test_enter_when_already_special(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Повторный вход в Special Mode."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.enter_special({"password": "test", "totp": "123456"})
        result = manager.enter_special({"password": "test", "totp": "123456"})
        assert result is False
        assert manager.is_special()


class TestExitSpecial:
    """Тесты для exit_special()."""

    def test_exit_success(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Успешный выход из Special Mode."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.enter_special({"password": "test", "totp": "123456"})
        result = manager.exit_special()
        assert result is True
        assert manager.is_normal()

    def test_exit_from_normal(self) -> None:
        """Выход из Normal Mode должен вернуть False."""
        manager = ModeManager()
        result = manager.exit_special()
        assert result is False
        assert manager.is_normal()

    def test_exit_with_confirm_false(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Выход с confirm=False."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.enter_special({"password": "test", "totp": "123456"})
        result = manager.exit_special(confirm=False)
        assert result is True
        assert manager.is_normal()


class TestCallbacks:
    """Тесты для callback системы."""

    def test_callback_on_mode_change(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Callback вызывается при смене режима."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        callback_calls: list[tuple[str, str]] = []

        def callback(old_mode: str, new_mode: str) -> None:
            callback_calls.append((old_mode, new_mode))

        manager.on_mode_change(callback)
        manager.enter_special({"password": "test", "totp": "123456"})

        assert len(callback_calls) == 1
        assert callback_calls[0] == ("normal", "special")

    def test_callback_on_exit_special(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Callback вызывается при выходе из Special."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        callback_calls: list[tuple[str, str]] = []

        def callback(old_mode: str, new_mode: str) -> None:
            callback_calls.append((old_mode, new_mode))

        manager.enter_special({"password": "test", "totp": "123456"})
        manager.on_mode_change(callback)
        manager.exit_special()

        assert len(callback_calls) == 1
        assert callback_calls[0] == ("special", "normal")

    def test_multiple_callbacks(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Несколько callbacks вызываются."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        calls1: list[tuple[str, str]] = []
        calls2: list[tuple[str, str]] = []

        manager.on_mode_change(lambda old, new: calls1.append((old, new)))
        manager.on_mode_change(lambda old, new: calls2.append((old, new)))
        manager.enter_special({"password": "test", "totp": "123456"})

        assert len(calls1) == 1
        assert len(calls2) == 1


class TestHealthCheckIntegration:
    """Тесты интеграции с HealthChecker."""

    def test_check_health_status_without_checker(self) -> None:
        """Проверка без HealthChecker."""
        manager = ModeManager()
        result = manager.check_health_status()
        assert result is None

    def test_check_health_status_with_checker(self, mock_health_checker: MagicMock) -> None:
        """Проверка с HealthChecker."""
        manager = ModeManager(health_checker=mock_health_checker)
        result = manager.check_health_status()
        assert result is not None
        assert isinstance(result, HealthCheckReport)


class TestSpecialModeDisable:
    """Тесты отключения Special Mode."""

    def test_disable_from_normal(self) -> None:
        """Отключение в Normal Mode."""
        manager = ModeManager()
        manager.disable_special_mode("test reason")
        assert manager.is_special_mode_disabled()
        assert manager.is_normal()

    def test_disable_from_special(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Отключение в Special Mode вызывает exit."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.enter_special({"password": "test", "totp": "123456"})

        callback_calls: list[tuple[str, str]] = []
        manager.on_mode_change(lambda old, new: callback_calls.append((old, new)))

        manager.disable_special_mode("critical error")

        assert manager.is_special_mode_disabled()
        assert manager.is_normal()
        assert len(callback_calls) == 1
        assert callback_calls[0] == ("special", "normal")

    def test_enable_after_disable(self) -> None:
        """Включение после отключения."""
        manager = ModeManager()
        manager.disable_special_mode("test")
        assert manager.is_special_mode_disabled()

        manager.enable_special_mode()
        assert not manager.is_special_mode_disabled()


class TestReset:
    """Тесты сброса состояния."""

    def test_reset_to_normal(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Сброс возвращает в Normal."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.enter_special({"password": "test", "totp": "123456"})
        manager.reset()

        assert manager.is_normal()
        assert not manager.is_special_mode_disabled()

    def test_reset_clears_callbacks(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Сброс очищает callbacks."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        calls: list[tuple[str, str]] = []
        manager.on_mode_change(lambda old, new: calls.append((old, new)))
        manager.reset()

        # Callback не должен вызваться после reset
        manager.enter_special({"password": "test", "totp": "123456"})
        assert len(calls) == 0


class TestModeManagerPhase3:
    """Дополнительные тесты Phase 3 для ModeManager."""

    def test_mode_initial_state_is_normal(self) -> None:
        """Проверка начального состояния — Normal Mode."""
        manager = ModeManager()
        assert manager.get_current_mode() == ModeManager.MODE_NORMAL
        assert manager.is_normal()
        assert not manager.is_special()

    def test_can_enter_special_requires_health_check(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка что can_enter_special требует health check."""
        mock_health_checker.run_critical.return_value = HealthCheckReport(
            checks=[HealthCheckResult.healthy("entropy")],
            overall_status=HealthCheckStatus.HEALTHY,
        )
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        can_enter, reason = manager.can_enter_special()
        assert can_enter is True
        assert reason == "ok"
        mock_health_checker.run_critical.assert_called_once()

    def test_enter_special_with_mfa(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Вход в Special Mode с MFA верификацией."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        result = manager.enter_special({
            "password": "test_password",
            "totp": "123456",
            "user_id": "test_user",
        })
        assert result is True
        assert manager.is_special()
        mock_auth_service.authenticate.assert_called_once_with(
            user_id="test_user",
            password="test_password",
            factor_type="totp",
            factor_credential="123456",
        )

    def test_exit_special_requires_confirm(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Выход из Special Mode с confirm параметром."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        manager.enter_special({"password": "test", "totp": "123456"})
        assert manager.is_special()

        # Выход с confirm=False (без подтверждения)
        result = manager.exit_special(confirm=False)
        assert result is True
        assert manager.is_normal()

        # Входим снова
        manager.enter_special({"password": "test", "totp": "123456"})
        # Выход с confirm=True (по умолчанию, с подтверждением)
        result = manager.exit_special(confirm=True)
        assert result is True
        assert manager.is_normal()

    def test_mode_change_callbacks(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка callback при смене режима."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )
        callbacks: list[tuple[str, str]] = []

        def on_mode_change(old_mode: str, new_mode: str) -> None:
            callbacks.append((old_mode, new_mode))

        manager.on_mode_change(on_mode_change)

        # Переход в Special
        manager.enter_special({"password": "test", "totp": "123456"})
        assert len(callbacks) == 1
        assert callbacks[0] == ("normal", "special")

        # Переход в Normal
        manager.exit_special()
        assert len(callbacks) == 2
        assert callbacks[1] == ("special", "normal")

    def test_disable_enable_special_mode(
        self,
        mock_health_checker: MagicMock,
        mock_auth_service: MagicMock,
    ) -> None:
        """Тестирование disable/enable Special Mode."""
        manager = ModeManager(
            health_checker=mock_health_checker,
            auth_service=mock_auth_service,
        )

        # Изначально Special Mode включён
        assert not manager.is_special_mode_disabled()

        # Отключаем Special Mode
        manager.disable_special_mode("maintenance")
        assert manager.is_special_mode_disabled()

        # Нельзя войти в Special Mode
        can_enter, reason = manager.can_enter_special()
        assert can_enter is False
        assert reason == "disabled"

        # Включаем Special Mode
        manager.enable_special_mode()
        assert not manager.is_special_mode_disabled()

        # Теперь можно войти
        can_enter, _ = manager.can_enter_special()
        assert can_enter is True


__all__ = [
    "TestModeManager",
    "TestCanEnterSpecial",
    "TestCanExitSpecial",
    "TestEnterSpecial",
    "TestExitSpecial",
    "TestCallbacks",
    "TestHealthCheckIntegration",
    "TestSpecialModeDisable",
    "TestReset",
    "TestModeManagerPhase3",
]
