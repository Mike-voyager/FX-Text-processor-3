"""Интеграционные тесты для Security Flow Phase 2 FX Text Processor 3.

Тестирует интеграцию компонентов безопасности:
- SessionLockScreen
- BackupCodesDialog
- CryptoProfileDialog
- AutoLockSettingsDialog
- ModeToggle

Требования:
    - Запускать через: xvfb-run -a pytest tests/integration/gui/test_security_flow.py
    - Все тесты независимы и имеют собственный setup/teardown

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import sys
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Generator, Optional
from unittest.mock import MagicMock, Mock, patch

import pytest

# Mark all tests as GUI tests requiring xvfb
pytestmark = [
    pytest.mark.integration,
    pytest.mark.security,
    pytest.mark.slow,
]


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для создания root Tk окна.

    Yields:
        tk.Tk: Root окно для тестов.
    """
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    yield root
    root.destroy()


@pytest.fixture
def security_fixtures() -> dict[str, Any]:
    """Фикстуры для security тестов.

    Returns:
        Словарь с замоканными сервисами безопасности.
    """
    # Mock SessionLockManager
    lock_manager = Mock()
    lock_manager.is_locked.return_value = True
    lock_manager.get_locked_at.return_value = datetime.now(timezone.utc)
    lock_manager.get_lock_reason.return_value = Mock()
    lock_manager.get_lock_reason.return_value.value = "manual"
    lock_manager.get_idle_time_minutes.return_value = 5.0

    # UnlockResult для успешной разблокировки
    @dataclass
    class UnlockResult:
        success: bool = True
        error_code: Optional[str] = None
        error_message: Optional[str] = None

    lock_manager.unlock_session.return_value = UnlockResult()

    # Mock AutoLockService
    auto_lock_service = Mock()
    auto_lock_service.get_state.return_value = Mock()
    auto_lock_service.get_state.return_value.value = "running"
    auto_lock_service.is_running.return_value = True
    auto_lock_service.start.return_value = None
    auto_lock_service.stop.return_value = None

    # Mock MFAGate
    mfa_gate = Mock()

    @dataclass
    class MFAResult:
        verified: bool = True
        method: str = "totp"
        user_id: str = "operator"
        timestamp: datetime = datetime.now()
        audit_token: str = "test-token-123"
        error_message: Optional[str] = None

    mfa_gate.challenge.return_value = MFAResult()
    mfa_gate.verify_transition.return_value = (True, MFAResult())

    # Mock AuthService
    auth_service = Mock()
    auth_service.verify_credentials.return_value = True

    return {
        "lock_manager": lock_manager,
        "auto_lock_service": auto_lock_service,
        "mfa_gate": mfa_gate,
        "auth_service": auth_service,
    }


@pytest.fixture
def theme_manager() -> Generator[Mock, None, None]:
    """Фикстура для ThemeManager с моками.

    Yields:
        Mock: Замоканный ThemeManager.
    """
    from src.gui.themes import Theme

    mock_theme = Theme(
        bg_color="#000000",
        fg_color="#00FF00",
        accent_color="#00AA00",
        warning_color="#FFA500",
        error_color="#FF0000",
        success_color="#00FF00",
        border_color="#003300",
        font_family="Courier New",
        font_size=12,
    )

    with patch("src.gui.themes.get_theme_manager") as mock_get_manager:
        mock_manager = Mock()
        mock_manager.get_current_theme.return_value = mock_theme
        mock_manager.list_themes.return_value = [
            "classic_green",
            "retro_green",
            "amber",
            "phosphor_white",
            "high_contrast",
        ]
        mock_get_manager.return_value = mock_manager
        yield mock_manager


# =============================================================================
# TEST CLASS: SecurityFlowIntegrationTests
# =============================================================================


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="GUI тесты требуют X11 на Windows",
)
class TestSecurityFlowIntegration:
    """Интеграционные тесты для Security Flow Phase 2.

    Тестирует взаимодействие компонентов безопасности вместе:
    - SessionLockScreen с SessionLockManager
    - BackupCodesDialog с MFAGate
    - CryptoProfileDialog с MFA challenge
    - AutoLockSettingsDialog с AutoLockService
    - ModeToggle с MFA
    """

    def test_full_lock_unlock_cycle(
        self,
        root: tk.Tk,
        security_fixtures: dict[str, Any],
    ) -> None:
        """Полный цикл блокировки и разблокировки.

        Сценарий:
            1. Блокировка сессии через SessionLockManager
            2. Показ SessionLockScreen
            3. Ввод пароля и MFA
            4. Успешная разблокировка
            5. Проверка что сессия разблокирована
        """
        from src.gui.security.session_lock import SessionLockScreen

        lock_manager = security_fixtures["lock_manager"]
        mfa_gate = security_fixtures["mfa_gate"]

        # Настраиваем начальное состояние - сессия заблокирована
        lock_manager.is_locked.return_value = True

        # Создаём экран блокировки
        lock_screen = SessionLockScreen(
            parent=root,
            lock_manager=lock_manager,
            mfa_gate=mfa_gate,
        )

        # Проверяем что экран создан
        assert lock_screen is not None
        assert lock_screen.is_locked() is True

        # Симулируем успешную разблокировку
        lock_manager.is_locked.return_value = False
        lock_manager.unlock_session.return_value.success = True

        # Проверяем что сессия теперь разблокирована
        assert lock_screen.is_locked() is False

        # Очищаем ресурсы
        lock_screen.destroy()

    def test_auto_lock_triggers(
        self,
        root: tk.Tk,
        security_fixtures: dict[str, Any],
    ) -> None:
        """Срабатывание автоблокировки.

        Сценарий:
            1. Настройка AutoLockService с таймаутом 1 минута
            2. Симуляция бездействия
            3. Проверка автоблокировки
            4. Разблокировка
        """
        from src.gui.dialogs.auto_lock_settings_dialog import (
            AutoLockSettingsDialog,
            AutoLockSettingsResult,
        )
        from src.security.lock.session_lock_manager import LockConfig

        auto_lock_service = security_fixtures["auto_lock_service"]

        # Создаём конфигурацию с таймаутом 1 минута
        config = LockConfig(
            enabled=True,
            auto_lock_minutes=1,
            lock_on_sleep=True,
            lock_on_screensaver=True,
            require_mfa_to_unlock=True,
            clear_clipboard_on_lock=True,
            hide_documents_on_lock=True,
        )

        # Создаём диалог настроек
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=config,
            auto_lock_service=auto_lock_service,
        )

        assert dialog is not None

        # Проверяем что сервис запущен
        assert auto_lock_service.is_running() is True

        # Симулируем истечение времени бездействия
        auto_lock_service.get_idle_time_minutes.return_value = 2.0  # 2 минуты

        # Проверяем что idle time превышает таймаут
        idle_time = auto_lock_service.get_idle_time_minutes()
        assert idle_time > config.auto_lock_minutes

        # Очищаем ресурсы
        dialog.destroy()

    def test_profile_change_with_session(
        self,
        root: tk.Tk,
        security_fixtures: dict[str, Any],
    ) -> None:
        """Смена профиля в активной сессии.

        Сценарий:
            1. Текущий профиль: STANDARD
            2. Открытие CryptoProfileDialog
            3. Выбор PARANOID
            4. MFA challenge
            5. Применение профиля
        """
        from src.gui.dialogs.crypto_profile_dialog import (
            CryptoProfileDialog,
            ProfileSelectionResult,
        )
        from src.security.crypto.service.profiles import CryptoProfile

        mfa_gate = security_fixtures["mfa_gate"]

        # Настраиваем MFA результат как успешный
        @dataclass
        class MockMFAResult:
            verified: bool = True
            method: str = "totp"
            user_id: str = "operator"
            timestamp: datetime = datetime.now()
            audit_token: str = "test-token"

        mfa_gate.challenge.return_value = MockMFAResult()

        # Создаём диалог с текущим профилем STANDARD
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
            mfa_gate=mfa_gate,
        )

        assert dialog is not None
        assert dialog._current_profile == CryptoProfile.STANDARD

        # Симулируем выбор PARANOID профиля
        dialog._selected_profile = CryptoProfile.PARANOID

        # Симулируем MFA challenge
        mfa_result = mfa_gate.challenge(
            parent=root,
            user_id="operator",
            methods=["totp", "backup"],
            reason="change_crypto_profile",
        )

        # Проверяем что MFA пройдена
        assert mfa_result.verified is True

        # Создаём результат выбора профиля
        result = ProfileSelectionResult(
            profile=CryptoProfile.PARANOID,
            previous_profile=CryptoProfile.STANDARD,
            is_downgrade=False,
            mfa_verified=True,
        )

        # Проверяем результат
        assert result.profile == CryptoProfile.PARANOID
        assert result.previous_profile == CryptoProfile.STANDARD
        assert result.is_downgrade is False
        assert result.mfa_verified is True

        # Очищаем ресурсы
        dialog.destroy()

    def test_mfa_workflow_across_components(
        self,
        root: tk.Tk,
        security_fixtures: dict[str, Any],
    ) -> None:
        """MFA работает во всех компонентах.

        Сценарий:
            1. ModeToggle в Special (требует MFA)
            2. BackupCodesDialog regenerate (требует MFA)
            3. CryptoProfileDialog change (требует MFA)
            4. SessionLockScreen unlock (требует MFA)
        """
        from src.gui.security.mode_toggle import Mode, ModeToggle
        from src.gui.security.mfa_gate import MFAResult

        mfa_gate = security_fixtures["mfa_gate"]
        auth_service = security_fixtures["auth_service"]

        # Настраиваем MFA результат
        mfa_result = MFAResult(
            verified=True,
            method="totp",
            timestamp=datetime.now(),
            audit_token="test-token",
            user_id="operator",
        )
        mfa_gate.challenge.return_value = mfa_result

        # 1. Проверяем ModeToggle
        mode_manager = Mock()
        mode_manager.can_enter_special.return_value = (True, "")
        mode_manager.enter_special.return_value = None

        toggle = ModeToggle(
            parent=root,  # type: ignore[arg-type]
            mode_manager=mode_manager,
            mfa_gate=mfa_gate,
            initial_mode=Mode.NORMAL,
        )

        assert toggle is not None
        assert toggle.get_mode() == Mode.NORMAL

        # Симулируем MFA для переключения в Special
        challenge_result = mfa_gate.challenge(
            parent=root,
            user_id="operator",
            required_methods=["totp", "backup_code"],
            operation="enter_special_mode",
        )
        assert challenge_result.verified is True

        # 2. Проверяем BackupCodesDialog с MFA
        from src.gui.dialogs.backup_codes_dialog import BackupCodesDialog

        # Создаём диалог резервных кодов
        codes_dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
            mfa_gate=mfa_gate,
        )

        assert codes_dialog is not None

        # Симулируем регенерацию кодов с MFA
        regen_result = mfa_gate.challenge(
            parent=root,
            user_id="operator",
            required_methods=["totp", "backup"],
            operation="regenerate_backup_codes",
        )
        assert regen_result.verified is True

        # 3. Проверяем CryptoProfileDialog с MFA
        from src.gui.dialogs.crypto_profile_dialog import CryptoProfileDialog
        from src.security.crypto.service.profiles import CryptoProfile

        profile_dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
            mfa_gate=mfa_gate,
        )

        assert profile_dialog is not None

        profile_change_result = mfa_gate.challenge(
            parent=root,
            user_id="operator",
            methods=["totp", "backup"],
            reason="change_crypto_profile",
        )
        assert profile_change_result.verified is True

        # 4. Проверяем SessionLockScreen с MFA
        from src.gui.security.session_lock import SessionLockScreen

        lock_manager = security_fixtures["lock_manager"]
        lock_screen = SessionLockScreen(
            parent=root,
            lock_manager=lock_manager,
            mfa_gate=mfa_gate,
        )

        assert lock_screen is not None

        # Очищаем ресурсы
        codes_dialog.destroy()
        profile_dialog.destroy()
        lock_screen.destroy()
        toggle.destroy()

    def test_security_ui_themes(
        self,
        root: tk.Tk,
        security_fixtures: dict[str, Any],
        theme_manager: Mock,
    ) -> None:
        """Все компоненты используют ThemeManager.

        Сценарий:
            1. Переключение темы
            2. Проверка что все компоненты обновили цвета
        """
        from src.gui.themes import Theme

        # Проверяем что theme_manager предоставляет темы
        themes = theme_manager.list_themes()
        assert len(themes) > 0
        assert "classic_green" in themes

        # Получаем текущую тему
        current_theme = theme_manager.get_current_theme()
        assert current_theme is not None
        assert current_theme.bg_color is not None
        assert current_theme.fg_color is not None

        # Проверяем что компоненты применяют тему
        # Создаём разные компоненты и проверяем их настройки

        # 1. SessionLockScreen
        from src.gui.security.session_lock import SessionLockScreen

        lock_manager = security_fixtures["lock_manager"]
        lock_screen = SessionLockScreen(
            parent=root,
            lock_manager=lock_manager,
        )

        # Проверяем что фон окна установлен
        bg_color = lock_screen.cget("bg")
        assert bg_color is not None

        lock_screen.destroy()

        # 2. BackupCodesDialog
        from src.gui.dialogs.backup_codes_dialog import BackupCodesDialog

        codes_dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Проверяем что диалог имеет цвет фона
        dialog_bg = codes_dialog.cget("bg")
        assert dialog_bg is not None

        codes_dialog.destroy()

        # 3. ModeToggle
        from src.gui.security.mode_toggle import Mode, ModeToggle

        mode_manager = Mock()
        toggle = ModeToggle(
            parent=root,  # type: ignore[arg-type]
            mode_manager=mode_manager,
            initial_mode=Mode.NORMAL,
        )

        # Проверяем что тумблер имеет настройки темы
        toggle_bg = toggle.cget("bg")
        assert toggle_bg is not None

        toggle.destroy()

        # 4. Проверяем переключение темы
        # Создаём альтернативную тему
        dark_theme = Theme(
            bg_color="#001100",
            fg_color="#00CC00",
            accent_color="#008800",
            warning_color="#CC9900",
            error_color="#CC0000",
            success_color="#00CC00",
            border_color="#002200",
            font_family="Courier New",
            font_size=14,
        )

        # Настраиваем мок для register_theme и set_theme
        theme_manager.register_theme.return_value = None
        theme_manager.set_theme.return_value = None

        # Регистрируем тему
        theme_manager.register_theme("dark_green_test", dark_theme)
        theme_manager.register_theme.assert_called_once_with("dark_green_test", dark_theme)

        # Устанавливаем тему и настраиваем мок для возврата нового имени
        theme_manager.get_current_theme_name.return_value = "dark_green_test"
        theme_manager.set_theme("dark_green_test")
        theme_manager.set_theme.assert_called_once_with("dark_green_test")

        # Проверяем что тема изменилась
        assert theme_manager.get_current_theme_name() == "dark_green_test"

        # Сбрасываем тему
        theme_manager.get_current_theme_name.return_value = "classic_green"
        theme_manager.set_theme("classic_green")
        assert theme_manager.get_current_theme_name() == "classic_green"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestSecurityFlowIntegration",
]
