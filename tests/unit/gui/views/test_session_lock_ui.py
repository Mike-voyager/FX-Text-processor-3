# -*- coding: utf-8 -*-
"""Тесты для Session Lock UI (UI_SPEC 9.2).

Покрывает: отображение экрана блокировки, выбор метода MFA,
адаптивное поле ввода, таймер продолжительности, разблокировка.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

try:
    import tkinter as tk
    from src.gui.views.main_window import MainWindow
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_root() -> "Generator[tk.Tk, None, None]":
    """Создание корневого окна Tkinter для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_auth_controller() -> MagicMock:
    """Создание мока auth controller."""
    mock = MagicMock()
    mock.verify_password.return_value = True
    mock.verify_totp.return_value = True
    mock.verify_fido2.return_value = True
    mock.verify_backup_code.return_value = True
    return mock


# =============================================================================
# TestSessionLockUI - тесты отображения UI
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.security
class TestSessionLockUI:
    """Тесты UI экрана блокировки сессии."""

    def test_lock_screen_widgets_created(self, mock_root: tk.Tk) -> None:
        """Проверка создания всех виджетов экрана блокировки."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True

        # Mock services
        window._toast_service = MagicMock()

        # Show lock overlay
        window._show_lock_overlay()

        # Check that all widgets are created
        assert window._lock_overlay is not None
        assert window._lock_frame is not None
        assert hasattr(window, '_mfa_method_var')
        assert hasattr(window, '_mfa_input_var')
        assert hasattr(window, '_mfa_input_entry')
        assert hasattr(window, '_mfa_input_label')
        assert hasattr(window, '_lock_time_label')
        assert hasattr(window, '_lock_duration_label')
        assert hasattr(window, '_lock_error_label')
        assert hasattr(window, '_unlock_btn')
        assert hasattr(window, '_auto_lock_countdown_label')

        window._hide_lock_overlay()

    def test_lock_time_displayed(self, mock_root: tk.Tk) -> None:
        """Проверка отображения времени блокировки."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()

        # Check that lock time label contains time
        assert window._lock_time_label is not None
        time_text = window._lock_time_label.cget("text")
        assert "Время блокировки:" in time_text

        window._hide_lock_overlay()

    def test_mfa_method_selection_created(self, mock_root: tk.Tk) -> None:
        """Проверка создания выбора метода MFA."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()

        # Check that MFA method frame exists
        assert hasattr(window, '_mfa_method_frame')
        assert window._mfa_method_var is not None
        # Default method should be password
        assert window._mfa_method_var.get() == "password"

        window._hide_lock_overlay()

    def test_mfa_method_options(self, mock_root: tk.Tk) -> None:
        """Проверка доступных методов MFA."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()

        # Check all methods can be set
        methods = ["password", "fido2", "totp", "backup_code"]
        for method in methods:
            window._mfa_method_var.set(method)
            assert window._mfa_method_var.get() == method

        window._hide_lock_overlay()


@pytest.mark.security
class TestSessionLockInputAdaptive:
    """Тесты адаптивного поля ввода."""

    def test_password_input_hidden(self, mock_root: tk.Tk) -> None:
        """Пароль скрыт звёздочками."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()
        window._mfa_method_var.set("password")

        # Password should be hidden
        show_char = window._mfa_input_entry.cget("show")
        assert show_char == "*"

        window._hide_lock_overlay()

    def test_totp_input_visible(self, mock_root: tk.Tk) -> None:
        """TOTP код видим."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()
        window._mfa_method_var.set("totp")

        # Trigger method change
        window._on_mfa_method_changed()

        # TOTP should be visible (no show character)
        show_char = window._mfa_input_entry.cget("show")
        assert show_char == ""

        window._hide_lock_overlay()

    def test_input_label_changes(self, mock_root: tk.Tk) -> None:
        """Метка поля ввода меняется в зависимости от метода."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()

        # Test password label
        window._mfa_method_var.set("password")
        window._on_mfa_method_changed()
        assert "Пароль" in window._mfa_input_label.cget("text")

        # Test TOTP label
        window._mfa_method_var.set("totp")
        window._on_mfa_method_changed()
        assert "TOTP" in window._mfa_input_label.cget("text")

        # Test FIDO2 label
        window._mfa_method_var.set("fido2")
        window._on_mfa_method_changed()
        assert "PIN" in window._mfa_input_label.cget("text")

        # Test backup code label
        window._mfa_method_var.set("backup_code")
        window._on_mfa_method_changed()
        assert "Резервный" in window._mfa_input_label.cget("text")

        window._hide_lock_overlay()


@pytest.mark.security
class TestSessionLockUnlock:
    """Тесты разблокировки с разными методами."""

    def test_unlock_with_password(self, mock_root: tk.Tk, mock_auth_controller: MagicMock) -> None:
        """Разблокировка паролем."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        with patch.object(window, '_get_auth_controller', return_value=mock_auth_controller):
            with patch.object(window, '_get_current_user_id', return_value="test-user"):
                with patch.object(window, 'unlock_session') as mock_unlock:
                    window._show_lock_overlay()

                    # Set password method and enter password
                    window._mfa_method_var.set("password")
                    window._mfa_input_var.set("correct_password")

                    # Attempt unlock
                    window._on_unlock_clicked()

                    # Verify password check was called
                    mock_auth_controller.verify_password.assert_called_once()

                    window._hide_lock_overlay()

    def test_unlock_with_totp(self, mock_root: tk.Tk, mock_auth_controller: MagicMock) -> None:
        """Разблокировка TOTP кодом."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        with patch.object(window, '_get_auth_controller', return_value=mock_auth_controller):
            with patch.object(window, '_get_current_user_id', return_value="test-user"):
                with patch.object(window, 'unlock_session') as mock_unlock:
                    window._show_lock_overlay()

                    # Set TOTP method and enter code
                    window._mfa_method_var.set("totp")
                    window._mfa_input_var.set("123456")

                    # Attempt unlock
                    window._on_unlock_clicked()

                    # Verify TOTP check was called
                    mock_auth_controller.verify_totp.assert_called_once()

                    window._hide_lock_overlay()

    def test_unlock_with_backup_code(self, mock_root: tk.Tk, mock_auth_controller: MagicMock) -> None:
        """Разблокировка резервным кодом."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        with patch.object(window, '_get_auth_controller', return_value=mock_auth_controller):
            with patch.object(window, '_get_current_user_id', return_value="test-user"):
                with patch.object(window, 'unlock_session') as mock_unlock:
                    window._show_lock_overlay()

                    # Set backup code method and enter code
                    window._mfa_method_var.set("backup_code")
                    window._mfa_input_var.set("backup123")

                    # Attempt unlock
                    window._on_unlock_clicked()

                    # Verify backup code check was called
                    mock_auth_controller.verify_backup_code.assert_called_once()

                    window._hide_lock_overlay()

    def test_unlock_with_empty_input_shows_error(self, mock_root: tk.Tk) -> None:
        """Пустой ввод показывает ошибку."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()

        # Set password method but no password
        window._mfa_method_var.set("password")
        window._mfa_input_var.set("")

        # Attempt unlock
        window._on_unlock_clicked()

        # Verify error is shown
        error_text = window._lock_error_label.cget("text")
        assert "Введите" in error_text

        window._hide_lock_overlay()


@pytest.mark.security
class TestSessionLockVerificationMethods:
    """Тесты методов верификации."""

    def test_verify_password_calls_controller(self, mock_root: tk.Tk) -> None:
        """Проверка пароля вызывает контроллер."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        auth_controller = MagicMock()
        auth_controller.verify_password.return_value = True

        result = window._verify_password(auth_controller, "user", "pass")

        assert result is True
        auth_controller.verify_password.assert_called_once_with("user", "pass")

    def test_verify_totp_calls_controller(self, mock_root: tk.Tk) -> None:
        """Проверка TOTP вызывает контроллер."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        auth_controller = MagicMock()
        auth_controller.verify_totp.return_value = True

        result = window._verify_totp(auth_controller, "user", "123456")

        assert result is True
        auth_controller.verify_totp.assert_called_once_with("user", "123456")

    def test_verify_fido2_calls_controller(self, mock_root: tk.Tk) -> None:
        """Проверка FIDO2 вызывает контроллер."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        auth_controller = MagicMock()
        auth_controller.verify_fido2.return_value = True

        result = window._verify_fido2(auth_controller, "user", "1234")

        assert result is True
        auth_controller.verify_fido2.assert_called_once_with("user", "1234")

    def test_verify_backup_code_calls_controller(self, mock_root: tk.Tk) -> None:
        """Проверка резервного кода вызывает контроллер."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        auth_controller = MagicMock()
        auth_controller.verify_backup_code.return_value = True

        result = window._verify_backup_code(auth_controller, "user", "code")

        assert result is True
        auth_controller.verify_backup_code.assert_called_once_with("user", "code")

    def test_verify_methods_handle_exceptions(self, mock_root: tk.Tk) -> None:
        """Методы верификации обрабатывают исключения."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        auth_controller = MagicMock()
        auth_controller.verify_password.side_effect = Exception("DB error")

        result = window._verify_password(auth_controller, "user", "pass")

        assert result is False


@pytest.mark.security
class TestSessionLockDurationTimer:
    """Тесты таймера продолжительности блокировки."""

    def test_lock_duration_label_format(self, mock_root: tk.Tk) -> None:
        """Формат метки продолжительности."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = True
        window._toast_service = MagicMock()

        window._show_lock_overlay()

        # Check initial format
        duration_text = window._lock_duration_label.cget("text")
        assert "Продолжительность:" in duration_text

        window._hide_lock_overlay()

    def test_update_lock_duration_when_unlocked(self, mock_root: tk.Tk) -> None:
        """Обновление продолжительности не выполняется при разблокировке."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = mock_root
        window._is_locked = False  # Not locked
        window._toast_service = MagicMock()

        # Should return early
        window._update_lock_duration()

        # No error should occur
        assert True


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestSessionLockUI",
    "TestSessionLockInputAdaptive",
    "TestSessionLockUnlock",
    "TestSessionLockVerificationMethods",
    "TestSessionLockDurationTimer",
]
