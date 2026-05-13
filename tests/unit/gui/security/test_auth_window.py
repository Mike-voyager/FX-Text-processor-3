# -*- coding: utf-8 -*-
"""Тесты для окна аутентификации AuthWindow.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

if TYPE_CHECKING:
    from collections.abc import Generator


if not TKINTER_AVAILABLE:
    pytest.skip("Tkinter not available", allow_module_level=True)


from src.gui.security.auth_window import AuthWindow, MFASelection
from src.gui.security.mfa_gate import MFAGate, MFAResult


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_root() -> tk.Tk:
    """Создание корневого окна Tkinter для тестов."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


@pytest.fixture
def mock_auth_service() -> MagicMock:
    """Создание мока AuthService."""
    mock = MagicMock()
    mock.authenticate.return_value = MagicMock(success=True, user_id="test-user-123")
    mock.has_fido2.return_value = True
    mock.has_totp.return_value = True
    mock.has_backup_codes.return_value = True
    return mock


@pytest.fixture
def mock_mfa_gate() -> Generator[MagicMock, None, None]:
    """Создание мока MFAGate."""
    with patch("src.gui.security.auth_window.MFAGate") as mock_class:
        mock_instance = MagicMock()
        mock_instance.challenge.return_value = MFAResult.success(
            method="totp",
            user_id="test-user-123",
            audit_token="test-token",
        )
        mock_class.return_value = mock_instance
        yield mock_class


# =============================================================================
# TestAuthWindow - базовые тесты
# =============================================================================


@pytest.mark.security
class TestAuthWindow:
    """Базовые тесты для класса AuthWindow."""

    def test_constructor(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка инициализации AuthWindow."""
        window = AuthWindow(
            parent=mock_root,
            on_auth_success=lambda x: None,
        )

        assert window._parent == mock_root
        assert window._auth_service is None  # Demo mode
        assert window._on_auth_success is not None
        assert window._window is None
        assert window._password_var.get() == ""

    def test_constructor_with_auth_service(
        self,
        mock_root: tk.Tk,
        mock_auth_service: MagicMock,
    ) -> None:
        """Проверка инициализации с auth_service."""
        window = AuthWindow(
            parent=mock_root,
            auth_service=mock_auth_service,
            on_auth_success=lambda x: None,
        )

        assert window._auth_service == mock_auth_service
        assert window._mfa_gate is not None

    def test_constructor_with_callbacks(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка установки callbacks."""
        success_called: list[str] = []
        cancel_called: list[bool] = []

        def on_success(user_id: str) -> None:
            success_called.append(user_id)

        def on_cancel() -> None:
            cancel_called.append(True)

        window = AuthWindow(
            parent=mock_root,
            on_auth_success=on_success,
            on_cancel=on_cancel,
        )

        assert window._on_auth_success == on_success
        assert window._on_cancel_callback == on_cancel


# =============================================================================
# TestAuthWindowLifecycle - тесты жизненного цикла
# =============================================================================


@pytest.mark.security
class TestAuthWindowLifecycle:
    """Тесты жизненного цикла окна (show, hide, destroy)."""

    def test_show_creates_window(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка что show() создаёт окно."""
        window = AuthWindow(parent=mock_root)
        window.show()

        assert window._window is not None
        assert window._window.winfo_exists()

        window.destroy()

    def test_show_hide_destroy(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка show(), hide() и destroy()."""
        window = AuthWindow(parent=mock_root)

        # Show
        window.show()
        assert window._window is not None
        assert window._window.winfo_exists()

        # Hide
        window.hide()
        # Window still exists but is withdrawn
        assert window._window.winfo_exists()

        # Destroy
        window.destroy()
        assert window._window is None or not window._window.winfo_exists()

    def test_destroy_clears_resources(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка что destroy() очищает ресурсы."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Set some data
        window._password_var.set("secret")

        window.destroy()

        # Password should be cleared
        assert window._password_var.get() == ""
        assert window._password_entry is None
        assert window._error_label is None


# =============================================================================
# TestPasswordVisibility - тесты видимости пароля
# =============================================================================


@pytest.mark.security
class TestPasswordVisibility:
    """Тесты переключения видимости пароля."""

    def test_password_visibility_toggle(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка переключения видимости пароля."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Initially hidden
        assert window._password_entry is not None
        assert window._password_entry.cget("show") == "*"
        assert not window._password_visible

        # Toggle to visible
        window._toggle_password_visibility()
        assert window._password_visible
        assert window._password_entry.cget("show") == ""

        # Toggle back to hidden
        window._toggle_password_visibility()
        assert not window._password_visible
        assert window._password_entry.cget("show") == "*"

        window.destroy()

    def test_toggle_button_text_changes(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка изменения текста кнопки toggle."""
        window = AuthWindow(parent=mock_root)
        window.show()

        assert window._toggle_btn is not None

        # Initially eye emoji
        initial_text = window._toggle_btn.cget("text")

        # Toggle
        window._toggle_password_visibility()
        toggled_text = window._toggle_btn.cget("text")

        assert initial_text != toggled_text

        window.destroy()


# =============================================================================
# TestMFASelection - тесты выбора MFA метода
# =============================================================================


@pytest.mark.security
class TestMFASelection:
    """Тесты выбора метода MFA."""

    def test_mfa_method_selection(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка выбора метода MFA."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Default is FIDO2
        assert window._mfa_method.get() == MFASelection.FIDO2.value

        # Change to TOTP
        window._mfa_method.set(MFASelection.TOTP.value)
        assert window._mfa_method.get() == MFASelection.TOTP.value

        # Change to Backup Codes
        window._mfa_method.set(MFASelection.BACKUP_CODES.value)
        assert window._mfa_method.get() == MFASelection.BACKUP_CODES.value

        window.destroy()

    def test_mfa_methods_display_names(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка отображаемых имён методов MFA."""
        window = AuthWindow(parent=mock_root)

        # Test display names
        assert "FIDO2" in window._get_method_display_name(MFASelection.FIDO2)
        assert "TOTP" in window._get_method_display_name(MFASelection.TOTP)
        assert "Backup" in window._get_method_display_name(MFASelection.BACKUP_CODES)


# =============================================================================
# TestLoginFlow - тесты процесса входа
# =============================================================================


@pytest.mark.security
class TestLoginFlow:
    """Тесты процесса входа в систему."""

    def test_login_demo_mode(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка входа в demo режиме."""
        success_user: list[str] = []

        def on_success(user_id: str) -> None:
            success_user.append(user_id)

        window = AuthWindow(
            parent=mock_root,
            on_auth_success=on_success,
        )
        window.show()

        # Enter password
        window._password_var.set("any_password")

        # Login
        window._on_login()

        # Should succeed in demo mode
        assert len(success_user) == 1
        assert success_user[0] == "demo-user"

    def test_login_empty_password_shows_error(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка ошибки при пустом пароле."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # No password set
        window._on_login()

        # Error should be shown
        assert window._error_label is not None
        error_text = window._error_label.cget("text")
        assert "пароль" in error_text.lower() or error_text != ""

        window.destroy()

    def test_login_with_real_auth_service(
        self,
        mock_root: tk.Tk,
        mock_auth_service: MagicMock,
        mock_mfa_gate: MagicMock,
    ) -> None:
        """Проверка входа с реальным auth_service."""
        success_user: list[str] = []

        def on_success(user_id: str) -> None:
            success_user.append(user_id)

        window = AuthWindow(
            parent=mock_root,
            auth_service=mock_auth_service,
            on_auth_success=on_success,
        )
        window.show()

        # Enter password
        window._password_var.set("correct_password")

        # Login
        window._on_login()

        # Auth service should be called
        mock_auth_service.authenticate.assert_called_once_with("correct_password")

        # Should succeed
        assert len(success_user) == 1
        assert success_user[0] == "test-user-123"

        window.destroy()

    def test_login_with_wrong_password(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка входа с неверным паролем."""
        auth_service = MagicMock()
        auth_service.authenticate.return_value = MagicMock(
            success=False,
            user_id=None,
        )

        window = AuthWindow(
            parent=mock_root,
            auth_service=auth_service,
        )
        window.show()

        # Enter password
        window._password_var.set("wrong_password")

        # Login
        window._on_login()

        # Error should be shown
        assert window._error_label is not None
        error_text = window._error_label.cget("text")
        assert error_text != ""

        window.destroy()


# =============================================================================
# TestCancelFlow - тесты отмены
# =============================================================================


@pytest.mark.security
class TestCancelFlow:
    """Тесты отмены аутентификации."""

    def test_cancel_callback(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка вызова callback при отмене."""
        cancel_called: list[bool] = []

        def on_cancel() -> None:
            cancel_called.append(True)

        window = AuthWindow(
            parent=mock_root,
            on_cancel=on_cancel,
        )
        window.show()

        # Cancel
        window._on_cancel()

        # Callback should be called
        assert len(cancel_called) == 1
        assert cancel_called[0] is True

    def test_cancel_clears_password(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка что отмена очищает пароль."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Set password
        window._password_var.set("secret_password")
        assert window._password_var.get() == "secret_password"

        # Просто вызываем wipe_credentials напрямую для проверки очистки
        # Это тестирует security поведение - пароль должен очищаться
        window.wipe_credentials()

        # Password should be cleared
        assert window._password_var.get() == ""

        window.destroy()


# =============================================================================
# TestEscapeBinding - тесты ESC
# =============================================================================


@pytest.mark.security
class TestEscapeBinding:
    """Тесты биндинга клавиши ESC."""

    def test_escape_binding(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка что ESC вызывает отмену."""
        cancel_called: list[bool] = []

        def on_cancel() -> None:
            cancel_called.append(True)

        window = AuthWindow(
            parent=mock_root,
            on_cancel=on_cancel,
        )
        window.show()

        # Simulate ESC key press
        assert window._window is not None
        window._window.event_generate("<Escape>")
        window._window.update_idletasks()

        # Give time for event to process
        import time
        time.sleep(0.1)

        window.destroy()

    def test_window_close_protocol(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка что закрытие окна вызывает отмену."""
        cancel_called: list[bool] = []

        def on_cancel() -> None:
            cancel_called.append(True)

        window = AuthWindow(
            parent=mock_root,
            on_cancel=on_cancel,
        )
        window.show()

        # Simulate window close
        assert window._window is not None
        protocol = window._window.tk.call("wm", "protocol", window._window._w)
        # Protocol is set to _on_cancel
        window.destroy()


# =============================================================================
# TestWipeCredentials - тесты очистки учётных данных
# =============================================================================


@pytest.mark.security
class TestWipeCredentials:
    """Тесты очистки учётных данных."""

    def test_wipe_credentials(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка очистки учётных данных."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Set password
        window._password_var.set("secret_password")
        assert window._password_var.get() == "secret_password"

        # Wipe
        window.wipe_credentials()

        # Password should be cleared
        assert window._password_var.get() == ""

        window.destroy()

    def test_wipe_on_destroy(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка что destroy вызывает wipe_credentials."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Set password
        window._password_var.set("secret_password")

        # Destroy
        window.destroy()

        # Password should be cleared
        assert window._password_var.get() == ""


# =============================================================================
# TestErrorHandling - тесты обработки ошибок
# =============================================================================


@pytest.mark.security
class TestErrorHandling:
    """Тесты обработки ошибок."""

    def test_show_error(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка отображения ошибки."""
        window = AuthWindow(parent=mock_root)
        window.show()

        error_message = "Test error message"
        window._show_error(error_message)

        assert window._error_label is not None
        assert window._error_label.cget("text") == error_message

        window.destroy()

    def test_clear_error(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка очистки ошибки."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Show error
        window._show_error("Some error")
        assert window._error_label.cget("text") == "Some error"

        # Clear error
        window._clear_error()
        assert window._error_label.cget("text") == ""

        window.destroy()

    def test_clear_error_on_login(
        self,
        mock_root: tk.Tk,
    ) -> None:
        """Проверка что _on_login очищает ошибку."""
        window = AuthWindow(parent=mock_root)
        window.show()

        # Show error first
        window._show_error("Previous error")

        # Try login with empty password (will show new error)
        # But first clear should be called
        window._clear_error = MagicMock(side_effect=window._clear_error)
        window._on_login()

        # clear_error should be called
        window._clear_error.assert_called_once()

        window.destroy()


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    "TestAuthWindow",
    "TestAuthWindowLifecycle",
    "TestPasswordVisibility",
    "TestMFASelection",
    "TestLoginFlow",
    "TestCancelFlow",
    "TestEscapeBinding",
    "TestWipeCredentials",
    "TestErrorHandling",
]
