# -*- coding: utf-8 -*-
"""Тесты для MFAForm.

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
    from src.gui.components.mfa_form import MFAForm
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


@pytest.fixture
def mock_root() -> MagicMock:
    """Создание мока Tk root."""
    mock = MagicMock()
    mock.after = MagicMock()
    return mock


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMFAFormCreation:
    """Тесты создания MFAForm."""

    def test_mfa_form_creation_default(self, mock_root: MagicMock) -> None:
        """Проверка создания MFAForm с настройками по умолчанию."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "totp"
            mock_var.return_value = mock_var_instance

            form = MFAForm(parent=mock_root)

            assert form._on_submit is None
            assert form._on_fido2_request is None
            assert not form._fido2_available

    def test_mfa_form_creation_with_callbacks(self, mock_root: MagicMock) -> None:
        """Проверка создания MFAForm с callbacks."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "totp"
            mock_var.return_value = mock_var_instance

            submit_called: list[tuple[str, str, str, str]] = []
            fido2_called: list[tuple[str, str]] = []

            def on_submit(username: str, password: str, method: str, token: str) -> bool:
                submit_called.append((username, password, method, token))
                return True

            def on_fido2(username: str, password: str) -> bool:
                fido2_called.append((username, password))
                return True

            form = MFAForm(
                parent=mock_root,
                on_submit=on_submit,
                on_fido2_request=on_fido2,
            )

            assert form._on_submit is on_submit
            assert form._on_fido2_request is on_fido2
            assert form._fido2_available


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMFAFormFIDO2Degradation:
    """Тесты graceful degradation для FIDO2."""

    def test_fido2_disabled_without_callback(self, mock_root: MagicMock) -> None:
        """FIDO2 radio disabled если on_fido2_request не передан."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label') as mock_label, \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton') as mock_radio, \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "totp"
            mock_var.return_value = mock_var_instance

            radio_instance = MagicMock()
            mock_radio.return_value = radio_instance

            form = MFAForm(parent=mock_root)

            assert form._fido2_available is False
            assert form._fido2_radio is not None
            # Проверяем что radio создался хотя бы один раз
            assert mock_radio.call_count >= 1
            # Проверяем что Label для FIDO2 был создан с серым цветом
            label_calls = [call for call in mock_label.call_args_list
                           if call.kwargs.get("fg") == "#7f8c8d"]
            assert len(label_calls) > 0

    def test_fido2_enabled_with_callback(self, mock_root: MagicMock) -> None:
        """FIDO2 radio active если on_fido2_request передан."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton') as mock_radio, \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "totp"
            mock_var.return_value = mock_var_instance

            radio_instance = MagicMock()
            mock_radio.return_value = radio_instance

            def on_fido2(username: str, password: str) -> bool:
                return True

            form = MFAForm(
                parent=mock_root,
                on_fido2_request=on_fido2,
            )

            assert form._fido2_available is True
            radio_instance.config.assert_not_called()

    def test_fido2_submit_shows_touch_key_message(self, mock_root: MagicMock) -> None:
        """При FIDO2 submit показывается сообщение 'Коснитесь FIDO2 ключа...'."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label') as mock_label, \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.side_effect = lambda: "fido2"
            mock_var.return_value = mock_var_instance

            fido2_called: list[tuple[str, str]] = []

            def on_fido2(username: str, password: str) -> bool:
                fido2_called.append((username, password))
                return True

            form = MFAForm(
                parent=mock_root,
                on_fido2_request=on_fido2,
            )

            # Устанавливаем значения через StringVar mock
            password_var = MagicMock()
            password_var.get.return_value = "test_pass"
            username_var = MagicMock()
            username_var.get.return_value = "test_user"
            method_var = MagicMock()
            method_var.get.return_value = "fido2"

            form._password_var = password_var
            form._username_var = username_var
            form._method_var = method_var
            form._submit_btn = MagicMock()
            form._error_label = MagicMock()
            form._token_frame = MagicMock()

            form._on_submit_clicked()

            assert len(fido2_called) == 1
            assert fido2_called[0] == ("test_user", "test_pass")
            # Проверяем что показано сообщение о касании ключа
            error_calls = [
                call for call in form._error_label.config.call_args_list
                if call.kwargs.get("text") == "Коснитесь FIDO2 ключа..."
            ]
            assert len(error_calls) == 1

    def test_fido2_submit_failure_message(self, mock_root: MagicMock) -> None:
        """При неудачном FIDO2 возвращает корректное сообщение."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "fido2"
            mock_var.return_value = mock_var_instance

            def on_fido2(username: str, password: str) -> bool:
                return False

            form = MFAForm(
                parent=mock_root,
                on_fido2_request=on_fido2,
            )

            password_var = MagicMock()
            password_var.get.return_value = "test_pass"
            username_var = MagicMock()
            username_var.get.return_value = "test_user"
            method_var = MagicMock()
            method_var.get.return_value = "fido2"

            form._password_var = password_var
            form._username_var = username_var
            form._method_var = method_var
            form._submit_btn = MagicMock()
            form._error_label = MagicMock()

            form._on_submit_clicked()

            # Проверяем сообщение об ошибке
            error_calls = [
                call for call in form._error_label.config.call_args_list
                if call.kwargs.get("text") == "FIDO2 аутентификация не удалась"
            ]
            assert len(error_calls) == 1

    def test_fido2_unavailable_shows_error(self, mock_root: MagicMock) -> None:
        """При выборе FIDO2 без callback показывается ошибка."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "fido2"
            mock_var.return_value = mock_var_instance

            form = MFAForm(parent=mock_root)

            password_var = MagicMock()
            password_var.get.return_value = "test_pass"
            method_var = MagicMock()
            method_var.get.return_value = "fido2"

            form._password_var = password_var
            form._method_var = method_var
            form._error_label = MagicMock()
            form._submit_btn = MagicMock()

            form._on_submit_clicked()

            assert form._fido2_available is False
            form._error_label.config.assert_called_with(text="FIDO2 not implemented yet")


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMFAFormTOTPBackupFlow:
    """Тесты TOTP и Backup flow."""

    def test_totp_requires_token(self, mock_root: MagicMock) -> None:
        """TOTP требует token."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.side_effect = lambda: "totp"
            mock_var.return_value = mock_var_instance

            form = MFAForm(parent=mock_root)

            password_var = MagicMock()
            password_var.get.return_value = "test_pass"
            token_var = MagicMock()
            token_var.get.return_value = ""
            method_var = MagicMock()
            method_var.get.return_value = "totp"

            form._password_var = password_var
            form._token_var = token_var
            form._method_var = method_var
            form._error_label = MagicMock()
            form._token_entry = MagicMock()

            form._on_submit_clicked()

            form._error_label.config.assert_called_with(text="Token is required")
            form._token_entry.focus_set.assert_called_once()

    def test_totp_six_digits(self, mock_root: MagicMock) -> None:
        """TOTP должен быть 6 цифрами."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.side_effect = lambda: "totp"
            mock_var.return_value = mock_var_instance

            form = MFAForm(parent=mock_root)

            password_var = MagicMock()
            password_var.get.return_value = "test_pass"
            token_var = MagicMock()
            token_var.get.return_value = "123"
            method_var = MagicMock()
            method_var.get.return_value = "totp"

            form._password_var = password_var
            form._token_var = token_var
            form._method_var = method_var
            form._error_label = MagicMock()
            form._token_entry = MagicMock()

            form._on_submit_clicked()

            form._error_label.config.assert_called_with(text="TOTP must be 6 digits")

    def test_backup_requires_token(self, mock_root: MagicMock) -> None:
        """Backup Code требует token."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "backup"
            mock_var.return_value = mock_var_instance

            form = MFAForm(parent=mock_root)

            password_var = MagicMock()
            password_var.get.return_value = "test_pass"
            token_var = MagicMock()
            token_var.get.return_value = ""
            method_var = MagicMock()
            method_var.get.return_value = "backup"

            form._password_var = password_var
            form._token_var = token_var
            form._method_var = method_var
            form._error_label = MagicMock()
            form._token_entry = MagicMock()

            form._on_submit_clicked()

            form._error_label.config.assert_called_with(text="Token is required")
            form._token_entry.focus_set.assert_called_once()

    def test_totp_success(self, mock_root: MagicMock) -> None:
        """Успешная аутентификация TOTP."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "totp"
            mock_var.return_value = mock_var_instance

            submit_called: list[tuple[str, str, str, str]] = []

            def on_submit(username: str, password: str, method: str, token: str) -> bool:
                submit_called.append((username, password, method, token))
                return True

            form = MFAForm(
                parent=mock_root,
                on_submit=on_submit,
            )

            password_var = MagicMock()
            password_var.get.return_value = "test_pass"
            token_var = MagicMock()
            token_var.get.return_value = "123456"
            username_var = MagicMock()
            username_var.get.return_value = "test_user"
            method_var = MagicMock()
            method_var.get.return_value = "totp"

            form._password_var = password_var
            form._token_var = token_var
            form._username_var = username_var
            form._method_var = method_var
            form._submit_btn = MagicMock()

            form._on_submit_clicked()

            assert len(submit_called) == 1
            assert submit_called[0] == ("test_user", "test_pass", "totp", "123456")

    def test_password_required(self, mock_root: MagicMock) -> None:
        """Пароль обязателен."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "totp"
            mock_var.return_value = mock_var_instance

            form = MFAForm(parent=mock_root)

            password_var = MagicMock()
            password_var.get.return_value = ""
            method_var = MagicMock()
            method_var.get.return_value = "totp"

            form._password_var = password_var
            form._method_var = method_var
            form._error_label = MagicMock()
            form._password_entry = MagicMock()

            form._on_submit_clicked()

            form._error_label.config.assert_called_with(text="Password is required")
            form._password_entry.focus_set.assert_called_once()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMFAFormWipeCredentials:
    """Тесты очистки credentials."""

    def test_wipe_clears_fields(self, mock_root: MagicMock) -> None:
        """wipe_credentials очищает все поля."""
        with patch('tkinter.Frame'), \
             patch('tkinter.Label'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Radiobutton'), \
             patch('tkinter.StringVar') as mock_var:

            mock_var_instance = MagicMock()
            mock_var_instance.get.return_value = "totp"
            mock_var.return_value = mock_var_instance

            form = MFAForm(parent=mock_root)

            form.wipe_credentials()

            # Проверяем что все vars очищены через set("")
            calls = mock_var_instance.set.call_args_list
            assert len(calls) == 3


__all__ = [
    "TestMFAFormCreation",
    "TestMFAFormFIDO2Degradation",
    "TestMFAFormTOTPBackupFlow",
    "TestMFAFormWipeCredentials",
]
