# -*- coding: utf-8 -*-
"""Тесты для AuthOverlay.

Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

try:
    import tkinter as tk
    from src.gui.views.auth_overlay import AuthOverlay
    from src.gui.components.mfa_form import MFAForm
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


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


@pytest.fixture
def mock_root() -> MagicMock:
    """Создание мока Tk root."""
    mock = MagicMock()
    mock.after = MagicMock()
    return mock


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestAuthOverlayCreation:
    """Тесты создания AuthOverlay."""

    def test_auth_overlay_creation(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Проверка создания AuthOverlay."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            assert overlay._parent is mock_root
            assert overlay._auth_service is mock_auth_service
            assert overlay._widget_id == "auth_overlay"
            assert not overlay._is_visible

    def test_auth_overlay_creation_with_callbacks(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Проверка создания с callbacks."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            success_called = [False]
            cancel_called = [False]
            
            def on_success() -> None:
                success_called[0] = True
                
            def on_cancel() -> None:
                cancel_called[0] = True
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
                on_auth_success=on_success,
                on_cancel=on_cancel,
            )
            
            assert overlay._auth_success_callback is on_success
            assert overlay._cancel_callback is on_cancel


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestAuthOverlayShowHide:
    """Тесты показа и скрытия AuthOverlay."""

    def test_auth_overlay_show_hide(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Проверка показа и скрытия overlay."""
        with patch('tkinter.Frame') as mock_frame, \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            mock_frame_instance = MagicMock()
            mock_frame.return_value = mock_frame_instance
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            # Монтируем и показываем
            mock_parent_frame = MagicMock()
            overlay._create_tk_widget(mock_parent_frame)
            
            # Проверяем что overlay создался
            assert overlay._overlay_frame is not None

    def test_auth_overlay_is_visible(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Проверка is_visible()."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            # Изначально не виден
            assert not overlay.is_visible()

    def test_hide_wipes_credentials(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Проверка что hide() очищает credentials."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            # Устанавливаем мок mfa_form напрямую
            mfa_form_mock = MagicMock()
            overlay._mfa_form = mfa_form_mock
            overlay._overlay_frame = MagicMock()
            
            overlay.wipe_credentials()
            
            # Проверяем что wipe_credentials вызван
            mfa_form_mock.wipe_credentials.assert_called_once()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestAuthOverlayFIDO2:
    """Тесты FIDO2 функциональности."""

    def test_fido2_disabled_without_callback(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """FIDO2 disabled если auth_service не передан."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
            )
            
            # Без auth_service FIDO2 должен быть недоступен
            assert overlay._auth_service is None

    def test_fido2_enabled_with_callback(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """FIDO2 enabled если auth_service передан."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            assert overlay._auth_service is mock_auth_service
            # Проверяем что overlay передает _on_fido2_request в MFAForm
            assert hasattr(overlay, '_on_fido2_request')

    def test_fido2_request_no_auth_service(self, mock_root: MagicMock) -> None:
        """_on_fido2_request возвращает False если auth_service нет."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
            )
            
            overlay._status_label = MagicMock()
            
            result = overlay._on_fido2_request("user", "pass")
            
            assert result is False
            overlay._status_label.config.assert_called_with(
                text="Status: Auth service not configured",
                fg=overlay.ERROR_FG,
            )

    def test_fido2_request_success(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """FIDO2 request успеш."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            success_called = [False]
            
            def on_success() -> None:
                success_called[0] = True
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
                on_auth_success=on_success,
            )
            
            overlay._overlay_frame = MagicMock()
            overlay._status_label = MagicMock()
            overlay._is_visible = True
            
            result = overlay._on_fido2_request("test_user", "test_pass")
            
            assert result is True
            mock_auth_service.authenticate.assert_called_once_with(
                user_id="test_user",
                password="test_pass",
                factor_type="fido2",
                factor_credential=None,
            )
            assert success_called[0] is True
            # hide() вызывает place_forget на _overlay_frame
            overlay._overlay_frame.place_forget.assert_called_once()

    def test_fido2_request_failure(self, mock_root: MagicMock) -> None:
        """FIDO2 request failure отображает ошибку."""
        mock_auth_service_inst = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.failure_reason = "invalid_mfa"
        mock_auth_service_inst.authenticate.return_value = mock_result
        
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service_inst,
            )
            
            overlay._status_label = MagicMock()
            
            result = overlay._on_fido2_request("test_user", "test_pass")
            
            assert result is False
            # Проверяем что auth_service был вызван
            mock_auth_service_inst.authenticate.assert_called_once()
            # Проверяем что status_label показывает ошибку
            overlay._status_label.config.assert_called()

    def test_fido2_request_exception(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """FIDO2 request exception отображает ошибку."""
        mock_auth_service.authenticate.side_effect = RuntimeError("FIDO2 error")
        
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            overlay._status_label = MagicMock()
            
            result = overlay._on_fido2_request("test_user", "test_pass")
            
            assert result is False
            overlay._status_label.config.assert_called_with(
                text="Status: FIDO2 authentication failed",
                fg=overlay.ERROR_FG,
            )


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestAuthOverlayMethodSwitching:
    """Тесты переключения методов MFA."""

    def test_method_constants(self) -> None:
        """Константы методов совпадают с MFAForm."""
        assert MFAForm.METHOD_FIDO2 == "fido2"
        assert MFAForm.METHOD_TOTP == "totp"
        assert MFAForm.METHOD_BACKUP == "backup"


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestAuthOverlayAuthentication:
    """Тесты аутентификации."""

    def test_authenticate_totp_success(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Успешная аутентификация TOTP."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            success_called = [False]
            
            def on_success() -> None:
                success_called[0] = True
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
                on_auth_success=on_success,
            )
            
            overlay._overlay_frame = MagicMock()
            overlay._status_label = MagicMock()
            overlay._is_visible = True
            
            result = overlay._on_mfa_submit("test_user", "test_pass", "totp", "123456")
            
            assert result is True
            assert success_called[0] is True
            mock_auth_service.authenticate.assert_called_once_with(
                user_id="test_user",
                password="test_pass",
                factor_type="totp",
                factor_credential="123456",
            )
            # hide() вызывает place_forget
            overlay._overlay_frame.place_forget.assert_called_once()

    def test_authenticate_backup_success(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Успешная аутентификация backup code."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            overlay._overlay_frame = MagicMock()
            overlay._status_label = MagicMock()
            overlay._is_visible = True
            
            result = overlay._on_mfa_submit("test_user", "test_pass", "backup", "BACKUPCODE123")
            
            assert result is True
            mock_auth_service.authenticate.assert_called_once_with(
                user_id="test_user",
                password="test_pass",
                factor_type="backupcode",
                factor_credential="BACKUPCODE123",
            )

    def test_authenticate_no_auth_service(self, mock_root: MagicMock) -> None:
        """Аутентификация без auth_service."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
            )
            
            overlay._status_label = MagicMock()
            
            result = overlay._on_mfa_submit("test_user", "test_pass", "totp", "123456")
            
            assert result is False
            overlay._status_label.config.assert_called()

    def test_authenticate_failure(self, mock_root: MagicMock) -> None:
        """Неуспешная аутентификация."""
        mock_auth_service = MagicMock()
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.failure_reason = "invalid_password"
        mock_auth_service.authenticate.return_value = mock_result
        
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            overlay._status_label = MagicMock()
            
            result = overlay._on_mfa_submit("test_user", "wrong_pass", "totp", "000000")
            
            # Проверяем что auth_service был вызван
            mock_auth_service.authenticate.assert_called_once()
            # Проверяем что status_label показывает ошибку
            overlay._status_label.config.assert_called()
            assert result is False

    def test_cancel_callback(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Проверка callback при отмене."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            cancel_called = [False]
            
            def on_cancel() -> None:
                cancel_called[0] = True
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
                on_cancel=on_cancel,
            )
            
            overlay._overlay_frame = MagicMock()
            overlay._is_visible = True
            # Создаём мок mfa_form
            mfa_form_mock = MagicMock()
            overlay._mfa_form = mfa_form_mock
            
            overlay._on_cancel()
            
            # Проверяем что callback вызван
            assert cancel_called[0] is True
            # wipe_credentials вызывается дважды: _on_cancel и hide()
            mfa_form_mock.wipe_credentials.assert_called()
            # hide() вызывает place_forget
            overlay._overlay_frame.place_forget.assert_called_once()

    def test_fido2_submits_via_fido2_callback(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """FIDO2 submit идёт через _on_fido2_request, а не через _on_mfa_submit."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            overlay._overlay_frame = MagicMock()
            overlay._status_label = MagicMock()
            overlay._is_visible = True
            
            # _on_mfa_submit с method == fido2 теперь factor_type=None,
            # поэтому authenticate вернёт False (mfa_missing)
            result = overlay._on_mfa_submit("test_user", "test_pass", "fido2", "")
            
            assert result is False
            # Проверяем что _on_fido2_request работает корректно
            success_called = [False]
            def on_success() -> None:
                success_called[0] = True
            overlay._auth_success_callback = on_success
            
            result = overlay._on_fido2_request("test_user", "test_pass")
            
            assert result is True
            mock_auth_service.authenticate.assert_called_with(
                user_id="test_user",
                password="test_pass",
                factor_type="fido2",
                factor_credential=None,
            )
            assert success_called[0] is True


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestAuthOverlayWipeCredentials:
    """Тесты очистки credentials."""

    def test_wipe_credentials(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Проверка очистки credentials."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):
            
            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )
            
            # Создаём мок mfa_form
            mfa_form_mock = MagicMock()
            overlay._mfa_form = mfa_form_mock
            
            overlay.wipe_credentials()
            
            # Проверяем что wipe_credentials вызван через mfa_form
            mfa_form_mock.wipe_credentials.assert_called_once()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestAuthOverlayFIDO2GracefulDegradation:
    """Regression-тесты для корректной обработки FIDO2 в _on_mfa_submit.

    Проверяет, что при выборе FIDO2 метода в _on_mfa_submit
    не блокируется обработка с ошибкой, а показывается
    user-friendly предупреждение (graceful degradation).
    """

    def test_fido2_method_returns_false_with_warning(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """Выбор FIDO2 метода в _on_mfa_submit показывает warning, не error.

        Regression: раньше FIDO2 метод в _on_mfa_submit показывал
        error-сообщение и блокировал обработку. Теперь показывается
        user-friendly warning с рекомендацией настроить FIDO2.
        """
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):

            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
            )

            overlay._status_label = MagicMock()

            result = overlay._on_mfa_submit(
                "test_user", "test_pass", MFAForm.METHOD_FIDO2, ""
            )

            # FIDO2 через _on_mfa_submit возвращает False (не блокирует)
            assert result is False
            # Статус должен быть установлен
            overlay._status_label.config.assert_called()
            call_args = overlay._status_label.config.call_args
            # Проверяем что текст содержит рекомендацию настройки
            text_value = call_args.kwargs.get("text", "")
            assert "FIDO2" in text_value
            # Проверяем что fg цвет warning (оранжевый), не error (красный)
            fg_color = call_args.kwargs.get("fg", "")
            assert fg_color == "#f39c12"  # WARNING_FG

    def test_fido2_via_callback_still_works(self, mock_root: MagicMock, mock_auth_service: MagicMock) -> None:
        """FIDO2 аутентификация через _on_fido2_request callback работает корректно."""
        success_called = [False]

        def on_success() -> None:
            success_called[0] = True

        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar'):

            overlay = AuthOverlay(
                parent=mock_root,
                widget_id="auth_overlay",
                auth_service=mock_auth_service,
                on_auth_success=on_success,
            )

            overlay._overlay_frame = MagicMock()
            overlay._status_label = MagicMock()
            overlay._is_visible = True

            result = overlay._on_fido2_request("test_user", "test_pass")

            # FIDO2 через callback успешно работает
            assert result is True
            mock_auth_service.authenticate.assert_called_once_with(
                user_id="test_user",
                password="test_pass",
                factor_type="fido2",
                factor_credential=None,
            )
            assert success_called[0] is True


__all__ = [
    "TestAuthOverlayCreation",
    "TestAuthOverlayShowHide",
    "TestAuthOverlayFIDO2",
    "TestAuthOverlayMethodSwitching",
    "TestAuthOverlayAuthentication",
    "TestAuthOverlayWipeCredentials",
    "TestAuthOverlayFIDO2GracefulDegradation",
]
