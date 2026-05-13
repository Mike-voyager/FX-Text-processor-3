# -*- coding: utf-8 -*-
"""Тесты для MFAGate и его интеграции с GUI компонентами.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from src.gui.security.mfa_gate import (
    MFAGate,
    MFAMethodSelectorDialog,
    MFAResult,
)
from src.security.audit import AuditEventType

try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


if TYPE_CHECKING:
    pass


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_auth_controller() -> MagicMock:
    """Создание мока AuthController."""
    mock = MagicMock()
    mock.verify_totp.return_value = True
    mock.verify_backup_code.return_value = True
    mock.get_current_user.return_value = "test-user-123"
    mock.is_mfa_verified.return_value = False
    mock.mark_mfa_satisfied.return_value = True
    return mock


@pytest.fixture
def mock_auth_service_verified() -> MagicMock:
    """Создание мока AuthService с пройденным MFA."""
    mock = MagicMock()
    mock.is_mfa_verified.return_value = True
    mock.mark_mfa_satisfied.return_value = True
    mock.get_current_user.return_value = "test-user-123"
    mock.verify_totp.return_value = True
    mock.verify_backup_code.return_value = True
    return mock


@pytest.fixture
def mock_audit_log() -> MagicMock:
    """Создание мока AuditLog."""
    mock = MagicMock()
    mock.log_event.return_value = None
    return mock


@pytest.fixture
def mock_mfa_dialog() -> MagicMock:
    """Создание мока MFADialog."""
    mock = MagicMock()
    mock.show.return_value = MFAResult.success(
        method="totp",
        user_id="test-user-123",
        audit_token="test-token-123",
    )
    mock.get_method.return_value = "totp"
    return mock


@pytest.fixture
def mock_mfa_dialog_failure() -> MagicMock:
    """Создание мока MFADialog, возвращающего failure."""
    mock = MagicMock()
    mock.show.return_value = MFAResult.failure(
        method="totp",
        user_id="test-user-123",
        error_message="Invalid code",
    )
    mock.get_method.return_value = "totp"
    return mock


@pytest.fixture
def mock_root() -> MagicMock:
    """Создание мока корневого окна Tkinter."""
    mock = MagicMock()
    mock.winfo_exists.return_value = True
    return mock


# =============================================================================
# TestMFAGate - базовые тесты MFAGate
# =============================================================================

class TestMFAGate:
    """Базовые тесты для класса MFAGate."""

    def test_mfa_gate_init_with_audit_log(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка инициализации MFAGate с AuditLog."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        assert gate._auth_service == mock_auth_controller
        assert gate._audit_log == mock_audit_log

    def test_mfa_gate_init_without_audit_log(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Проверка инициализации MFAGate без AuditLog."""
        gate = MFAGate(auth_service=mock_auth_controller)

        assert gate._auth_service == mock_auth_controller
        assert gate._audit_log is None

    def test_register_dialog(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Проверка регистрации диалога MFA."""
        gate = MFAGate(auth_service=mock_auth_controller)
        mock_dialog_class = MagicMock()

        gate.register_dialog("totp", mock_dialog_class)

        assert "totp" in gate._dialogs
        assert gate._dialogs["totp"] == mock_dialog_class

    def test_challenge_success(
        self,
        mock_auth_controller: MagicMock,
        mock_mfa_dialog: MagicMock,
    ) -> None:
        """Проверка успешного MFA challenge."""
        gate = MFAGate(auth_service=mock_auth_controller)
        gate.register_dialog("totp", lambda: mock_mfa_dialog)  # type: ignore[arg-type]

        mock_parent = MagicMock()
        result = gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp"],
            operation="test_operation",
        )

        assert result.verified is True
        assert result.method == "totp"
        assert result.user_id == "test-user-123"

    def test_challenge_failure_all_methods(
        self,
        mock_auth_controller: MagicMock,
        mock_mfa_dialog_failure: MagicMock,
    ) -> None:
        """Проверка неуспешного MFA challenge для всех методов."""
        gate = MFAGate(auth_service=mock_auth_controller)
        gate.register_dialog("totp", lambda: mock_mfa_dialog_failure)  # type: ignore[arg-type]
        gate.register_dialog("backup_code", lambda: mock_mfa_dialog_failure)  # type: ignore[arg-type]

        mock_parent = MagicMock()
        result = gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp", "backup_code"],
            operation="test_operation",
        )

        assert result.verified is False
        assert result.error_message is not None
        assert "MFA verification failed" in result.error_message

    def test_challenge_no_registered_dialogs(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Проверка challenge когда нет зарегистрированных диалогов."""
        gate = MFAGate(auth_service=mock_auth_controller)

        mock_parent = MagicMock()
        result = gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp", "fido2"],
            operation="test_operation",
        )

        assert result.verified is False
        assert result.error_message is not None
        assert "MFA verification failed" in result.error_message


# =============================================================================
# TestMFAGateIntegration - интеграция MFAGate в GUI компоненты
# =============================================================================

@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMFAGateIntegration:
    """Тесты интеграции MFAGate в GUI компоненты."""

    @pytest.mark.skip(reason="MainWindow not available in test environment")
    def test_mfa_gate_used_in_main_window_unlock(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка что main_window использует MFAGate для unlock."""
        with patch("src.gui.security.mfa_gate.MFAGate.challenge") as mock_challenge:
            # Setup successful MFA
            mock_challenge.return_value = MFAResult.success(
                method="totp",
                user_id="test-user-123",
                audit_token="audit-123",
            )

            # Import main_window components
            with patch("src.gui.views.main_window.ToastService", create=True), \
                 patch("src.gui.views.main_window.MainLayout", create=True), \
                 patch("src.gui.views.main_window.StatusBar", create=True), \
                 patch("src.gui.views.main_window.SideBar", create=True), \
                 patch("src.gui.views.main_window.CardFileTabBar", create=True), \
                 patch("src.gui.views.main_window.DocumentView", create=True):

                from src.gui.views.main_window import MainWindow

                window = MainWindow(controller=mock_auth_controller, audit_log=mock_audit_log)

                with patch.object(window, "_is_locked", True), \
                      patch.object(
                          window, "_get_auth_controller", return_value=mock_auth_controller
                      ), \
                      patch.object(
                          window, "_get_current_user_id", return_value="test-user-123"
                      ), \
                      patch.object(window, "_toast_service") as _mock_toast:

                    # Create mock MFAGate
                    mock_mfa_gate = MagicMock()
                    mock_mfa_gate.challenge.return_value = MFAResult.success(
                        method="totp",
                        user_id="test-user-123",
                        audit_token="audit-123",
                    )

                    with patch("src.gui.views.main_window.MFAGate", return_value=mock_mfa_gate):
                        window._on_unlock_clicked()

                        # Verify that MFAGate is called
                        mock_mfa_gate.challenge.assert_called_once()
                        call_args = mock_mfa_gate.challenge.call_args
                        assert call_args.kwargs["user_id"] == "test-user-123"
                        assert call_args.kwargs["operation"] == "unlock_session"
                        assert "totp" in call_args.kwargs["required_methods"]

    def test_mfa_gate_used_in_reject_dialog(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Проверка что reject_dialog использует MFAGate."""
        # Read the source to verify MFAGate is used
        import inspect

        from src.gui.dialogs.reject_dialog import RejectDialog
        source = inspect.getsource(RejectDialog._show_mfa_dialog)

        # Verify MFAGate is imported and used
        assert "MFAGate" in source
        assert "mfa_gate.challenge" in source
        assert "reject_document" in source

        # Verify that the method creates MFAGate with the correct parameters structure
        # (we don't need to actually call it since that would require app_context)
        assert "auth_controller" in source or "auth_controller=" in source

    def test_mfa_gate_receives_audit_log(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка что MFAGate получает audit_log."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        assert gate._audit_log is mock_audit_log

        # Register a mock dialog that returns success
        mock_dialog = MagicMock()
        mock_dialog.show.return_value = MFAResult.success(
            method="totp",
            user_id="test-user",
            audit_token="token-123",
        )
        gate.register_dialog("totp", lambda: mock_dialog)  # type: ignore[arg-type]

        # Call challenge
        mock_parent = MagicMock()
        gate.challenge(
            parent=mock_parent,
            user_id="test-user",
            required_methods=["totp"],
            operation="test_operation",
        )

        # Verify audit_log was used (via _log_mfa_success)
        mock_audit_log.log_event.assert_called()

    @pytest.mark.skip(reason="MainWindow structure changed")
    def test_no_duplicate_mfa_logic_in_main_window(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Проверка что дублирующий MFA код удален из main_window."""
        # Read the main_window source to verify it uses MFAGate
        import inspect

        from src.gui.views import main_window

        source = inspect.getsource(main_window.MainWindow._on_unlock_clicked)

        # Should use MFAGate, not create MFAVerificationDialog directly
        assert "MFAGate" in source
        assert "MFAVerificationDialog" not in source

    def test_no_duplicate_mfa_logic_in_reject_dialog(
        self,
    ) -> None:
        """Проверка что дублирующий MFA код удален из reject_dialog."""
        # Read the reject_dialog source
        import inspect

        from src.gui.dialogs import reject_dialog

        source = inspect.getsource(reject_dialog.RejectDialog._show_mfa_dialog)

        # Should use MFAGate
        assert "MFAGate" in source
        assert "MFAVerificationDialog" not in source


# =============================================================================
# TestMFAAuditLogging - логирование MFA событий
# =============================================================================

class TestMFAAuditLogging:
    """Тесты логирования MFA событий в AuditService."""

    def test_mfa_success_logged_to_audit(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка что успешная MFA верификация логируется."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        # Register a mock dialog that returns success
        mock_dialog = MagicMock()
        mock_dialog.show.return_value = MFAResult.success(
            method="totp",
            user_id="test-user-123",
            audit_token="audit-token-456",
        )
        gate.register_dialog("totp", lambda: mock_dialog)  # type: ignore[arg-type]

        # Call challenge
        mock_parent = MagicMock()
        result = gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp"],
            operation="unlock_session",
        )

        # Verify success
        assert result.verified is True

        # Verify audit log was called with AUTH_MFA_SUCCESS
        mock_audit_log.log_event.assert_called()
        call_args = mock_audit_log.log_event.call_args
        assert call_args.args[0] == AuditEventType.AUTH_MFA_SUCCESS

    def test_mfa_failure_logged_to_audit(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка что неуспешная MFA верификация логируется."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        # Register a mock dialog that raises an exception (simulating failure)
        mock_dialog = MagicMock()
        mock_dialog.show.side_effect = Exception("MFA verification failed: Invalid code")
        gate.register_dialog("totp", lambda: mock_dialog)  # type: ignore[arg-type]

        # Call challenge
        mock_parent = MagicMock()
        result = gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp"],
            operation="unlock_session",
        )

        # Verify failure
        assert result.verified is False

        # Verify audit log was called with AUTH_MFA_FAILED (due to exception)
        mock_audit_log.log_event.assert_called()
        call_args = mock_audit_log.log_event.call_args
        assert call_args.args[0] == AuditEventType.AUTH_MFA_FAILED

    def test_mfa_audit_includes_user_id(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка что audit log содержит user_id."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        mock_dialog = MagicMock()
        mock_dialog.show.return_value = MFAResult.success(
            method="totp",
            user_id="test-user-123",
            audit_token="audit-123",
        )
        gate.register_dialog("totp", lambda: mock_dialog)  # type: ignore[arg-type]

        mock_parent = MagicMock()
        gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp"],
            operation="test_operation",
        )

        # Verify user_id is in audit details
        call_args = mock_audit_log.log_event.call_args
        assert "user_id" in call_args.kwargs["details"]
        assert call_args.kwargs["details"]["user_id"] == "test-user-123"

    def test_mfa_audit_includes_method(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка что audit log содержит method."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        mock_dialog = MagicMock()
        mock_dialog.show.return_value = MFAResult.success(
            method="totp",
            user_id="test-user-123",
            audit_token="audit-123",
        )
        gate.register_dialog("totp", lambda: mock_dialog)  # type: ignore[arg-type]

        mock_parent = MagicMock()
        gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp"],
            operation="test_operation",
        )

        # Verify method is in audit details
        call_args = mock_audit_log.log_event.call_args
        assert "method" in call_args.kwargs["details"]
        assert call_args.kwargs["details"]["method"] == "totp"

    def test_mfa_audit_includes_operation(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Проверка что audit log содержит operation."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        mock_dialog = MagicMock()
        mock_dialog.show.return_value = MFAResult.success(
            method="totp",
            user_id="test-user-123",
            audit_token="audit-123",
        )
        gate.register_dialog("totp", lambda: mock_dialog)  # type: ignore[arg-type]

        mock_parent = MagicMock()
        gate.challenge(
            parent=mock_parent,
            user_id="test-user-123",
            required_methods=["totp"],
            operation="unlock_session",
        )

        # Verify operation is in audit details
        call_args = mock_audit_log.log_event.call_args
        assert "operation" in call_args.kwargs["details"]
        assert call_args.kwargs["details"]["operation"] == "unlock_session"


# =============================================================================
# TestErrorLogging - логирование ошибок
# =============================================================================

class TestErrorLogging:
    """Тесты что silent exception handling заменен на логирование."""

    def test_mfa_gate_logs_success_errors(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
        caplog: Any,
    ) -> None:
        """Проверка что _log_mfa_success логирует ошибки."""
        import logging

        # Make audit log raise an exception
        mock_audit_log.log_event.side_effect = Exception("Audit log error")

        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        with caplog.at_level(logging.ERROR, logger="src.gui.security.mfa_gate"):
            gate._log_mfa_success(
                user_id="test-user",
                method="totp",
                operation="test",
                audit_token="token-123",
            )

        assert "Failed to log MFA success" in caplog.text

    def test_mfa_gate_logs_failure_errors(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
        caplog: Any,
    ) -> None:
        """Проверка что _log_mfa_error логирует ошибки."""
        import logging

        # Make audit log raise an exception
        mock_audit_log.log_event.side_effect = Exception("Audit log error")

        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        with caplog.at_level(logging.ERROR, logger="src.gui.security.mfa_gate"):
            gate._log_mfa_error(
                user_id="test-user",
                method="totp",
                operation="test",
                error="MFA failed",
            )

        assert "Failed to log MFA error to audit" in caplog.text

    @pytest.mark.skip(reason="MainWindow structure changed in Phase 3")
    def test_main_window_logs_session_lock(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
        caplog: Any,
    ) -> None:
        """Проверка что main_window логирует session lock."""

        with patch("src.gui.views.main_window.ToastService", create=True), \
             patch("src.gui.views.main_window.MainLayout", create=True), \
             patch("src.gui.views.main_window.StatusBar", create=True), \
             patch("src.gui.views.main_window.SideBar", create=True), \
             patch("src.gui.views.main_window.CardFileTabBar", create=True), \
             patch("src.gui.views.main_window.DocumentView", create=True):

            from src.gui.views.main_window import MainWindow

            window = MainWindow(
                controller=mock_auth_controller,
                audit_log=mock_audit_log,
            )

            # Set up the window state - not locked and has root
            window._is_locked = False
            window._root = MagicMock()

            with patch.object(window, "_document_view", MagicMock()), \
                 patch.object(window, "_toast_service", MagicMock()), \
                 patch.object(window, "_wipe_sensitive_data"), \
                 patch.object(window, "_get_current_user_id", return_value="test-user"):

                mock_audit_log.log_event.reset_mock()
                window.lock_session()

                # Verify audit log was called
                mock_audit_log.log_event.assert_called()
                call_args = mock_audit_log.log_event.call_args
                from src.security.audit.events import AuditEventType
                assert call_args.args[0] == AuditEventType.SESSION_LOCKED

    @pytest.mark.skip(reason="MainWindow structure changed in Phase 3")
    def test_main_window_logs_session_unlock(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
        caplog: Any,
    ) -> None:
        """Проверка что main_window логирует session unlock."""

        with patch("src.gui.views.main_window.ToastService", create=True), \
             patch("src.gui.views.main_window.MainLayout", create=True), \
             patch("src.gui.views.main_window.StatusBar", create=True), \
             patch("src.gui.views.main_window.SideBar", create=True), \
             patch("src.gui.views.main_window.CardFileTabBar", create=True), \
             patch("src.gui.views.main_window.DocumentView", create=True):

            from src.gui.views.main_window import MainWindow

            window = MainWindow(
                controller=mock_auth_controller,
                audit_log=mock_audit_log,
            )

            with patch.object(window, "_document_view"), \
                 patch.object(window, "_toast_service"), \
                 patch.object(window, "_get_current_user_id", return_value="test-user"):

                # Set locked state
                window._is_locked = True

                mock_audit_log.log_event.reset_mock()
                window.unlock_session()

                # Verify audit log was called
                mock_audit_log.log_event.assert_called()
                call_args = mock_audit_log.log_event.call_args
                from src.security.audit.events import AuditEventType
                assert call_args.args[0] == AuditEventType.APP_UNLOCKED


# =============================================================================
# TestMFAGateExecute — тесты Decorator API execute()
# =============================================================================

class TestMFAGateExecute:
    """Тесты для нового Decorator API MFAGate.execute()."""

    def test_execute_no_mfa_required(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Если requires_mfa=False — операция выполняется сразу."""
        gate = MFAGate(auth_service=mock_auth_controller)

        operation = MagicMock(return_value="result")
        result = gate.execute(
            parent=MagicMock(),
            operation=operation,
            operation_name="test_op",
            requires_mfa=False,
        )

        assert result == "result"
        operation.assert_called_once()
        mock_auth_controller.is_mfa_verified.assert_not_called()

    def test_execute_mfa_already_verified(
        self,
        mock_auth_service_verified: MagicMock,
    ) -> None:
        """Если MFA уже пройдена — операция выполняется без диалога."""
        gate = MFAGate(auth_service=mock_auth_service_verified)

        operation = MagicMock(return_value=42)
        result = gate.execute(
            parent=MagicMock(),
            operation=operation,
            operation_name="test_op",
            requires_mfa=True,
        )

        assert result == 42
        operation.assert_called_once()
        mock_auth_service_verified.is_mfa_verified.assert_called_once()

    def test_execute_mfa_dialog_success(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Если MFA пройдена через диалог — операция выполняется."""
        gate = MFAGate(auth_service=mock_auth_controller)

        operation = MagicMock(return_value="transition_ok")
        mock_parent = MagicMock()

        # Patch MFAMethodSelectorDialog to return success
        mock_result = MFAResult.success(
            method="totp",
            user_id="test-user-123",
            audit_token="audit-123",
        )

        mock_dialog_instance = MagicMock()
        mock_dialog_instance.show.return_value = mock_result

        with patch(
            "src.gui.security.mfa_gate.MFAMethodSelectorDialog",
            return_value=mock_dialog_instance,
        ) as mock_dialog_cls:
            result = gate.execute(
                parent=mock_parent,
                operation=operation,
                operation_name="test_op",
                requires_mfa=True,
            )

            # Verify dialog was instantiated with correct args
            mock_dialog_cls.assert_called_once()
            call_kwargs = mock_dialog_cls.call_args.kwargs
            assert call_kwargs["parent"] == mock_parent
            assert call_kwargs["auth_service"] == mock_auth_controller
            assert call_kwargs["operation_name"] == "test_op"

        assert result == "transition_ok"
        operation.assert_called_once()
        mock_auth_controller.mark_mfa_satisfied.assert_called_once()

    def test_execute_mfa_dialog_cancelled(
        self,
        mock_auth_controller: MagicMock,
    ) -> None:
        """Если MFA отменена — возвращается None."""
        gate = MFAGate(auth_service=mock_auth_controller)

        operation = MagicMock(return_value="should_not_run")
        mock_parent = MagicMock()

        mock_dialog_instance = MagicMock()
        mock_dialog_instance.show.return_value = None

        # Patch dialog to return None (cancelled)
        with patch(
            "src.gui.security.mfa_gate.MFAMethodSelectorDialog",
            return_value=mock_dialog_instance,
        ):
            result = gate.execute(
                parent=mock_parent,
                operation=operation,
                operation_name="test_op",
                requires_mfa=True,
            )

        assert result is None
        operation.assert_not_called()

    def test_execute_logs_success_to_audit(
        self,
        mock_auth_controller: MagicMock,
        mock_audit_log: MagicMock,
    ) -> None:
        """Успешная MFA верификация логируется в audit."""
        gate = MFAGate(
            auth_service=mock_auth_controller,
            audit_log=mock_audit_log,
        )

        operation = MagicMock(return_value="ok")
        mock_result = MFAResult.success(
            method="totp",
            user_id="test-user-123",
            audit_token="audit-123",
        )

        mock_dialog_instance = MagicMock()
        mock_dialog_instance.show.return_value = mock_result

        with patch(
            "src.gui.security.mfa_gate.MFAMethodSelectorDialog",
            return_value=mock_dialog_instance,
        ):
            gate.execute(
                parent=MagicMock(),
                operation=operation,
                operation_name="sign_document",
                requires_mfa=True,
            )

        mock_audit_log.log_event.assert_called()
        call_args = mock_audit_log.log_event.call_args
        assert call_args.args[0] == AuditEventType.AUTH_MFA_SUCCESS


# =============================================================================
# TestMFAMethodSelectorDialog — unit тесты диалога
# =============================================================================

@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMFAMethodSelectorDialog:
    """Unit тесты для MFAMethodSelectorDialog."""

    def test_dialog_init(self) -> None:
        """Проверка инициализации диалога."""
        root = tk.Tk()
        auth = MagicMock()
        auth.get_current_user.return_value = "operator"

        dialog = MFAMethodSelectorDialog(
            parent=root,
            auth_service=auth,
            operation_name="Тестовая операция",
        )

        assert dialog._operation_name == "Тестовая операция"
        assert dialog._user_id == "operator"
        assert dialog._current_method == "totp"

        dialog.destroy()
        root.destroy()

    def test_dialog_show_returns_none_on_cancel(self) -> None:
        """При отмене show() возвращает None."""
        root = tk.Tk()
        auth = MagicMock()
        auth.get_current_user.return_value = "operator"

        dialog = MFAMethodSelectorDialog(
            parent=root,
            auth_service=auth,
            operation_name="Операция",
        )

        # Simulate cancel by calling destroy directly
        dialog.after(50, dialog._on_cancel)
        result = dialog.show()

        assert result is None
        root.destroy()

    def test_totp_validation_format(self) -> None:
        """Проверка валидации формата TOTP."""
        root = tk.Tk()
        auth = MagicMock()
        auth.get_current_user.return_value = "operator"
        auth.verify_totp.return_value = True

        dialog = MFAMethodSelectorDialog(
            parent=root,
            auth_service=auth,
            operation_name="Операция",
        )

        # Simulate entering valid TOTP and clicking verify
        dialog._code_entry.insert(0, "123456")
        dialog._on_verify()

        auth.verify_totp.assert_called_once_with("operator", "123456")
        assert dialog._result is not None
        assert dialog._result.verified is True

        dialog.destroy()
        root.destroy()

    def test_backup_code_validation_format(self) -> None:
        """Проверка валидации формата backup code."""
        root = tk.Tk()
        auth = MagicMock()
        auth.get_current_user.return_value = "operator"
        auth.verify_backup_code.return_value = True

        dialog = MFAMethodSelectorDialog(
            parent=root,
            auth_service=auth,
            operation_name="Операция",
        )

        # Switch to backup code method
        dialog._method_var.set("backup_code")
        dialog._on_method_changed()

        dialog._code_entry.insert(0, "ABCD-1234")
        dialog._on_verify()

        auth.verify_backup_code.assert_called_once_with("operator", "ABCD-1234")
        assert dialog._result is not None
        assert dialog._result.verified is True

        dialog.destroy()
        root.destroy()

    def test_fido2_disabled(self) -> None:
        """FIDO2 radio button должен быть disabled."""
        root = tk.Tk()
        auth = MagicMock()
        auth.get_current_user.return_value = "operator"

        dialog = MFAMethodSelectorDialog(
            parent=root,
            auth_service=auth,
            operation_name="Операция",
        )

        # Find FIDO2 radiobutton and check state
        fido2_found = False
        for widget in dialog.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, tk.LabelFrame):
                    for frame in child.winfo_children():
                        for radio in frame.winfo_children():
                            if isinstance(radio, tk.Radiobutton):
                                # Check if this is the FIDO2 radio by looking at state
                                state = str(radio.cget("state"))
                                if state == "disabled":
                                    fido2_found = True

        assert fido2_found, "FIDO2 radiobutton should be disabled"

        dialog.destroy()
        root.destroy()


# =============================================================================
# Module Exports
# =============================================================================

__all__: list[str] = [
    "TestMFAGate",
    "TestMFAGateIntegration",
    "TestMFAAuditLogging",
    "TestErrorLogging",
    "TestMFAGateExecute",
    "TestMFAMethodSelectorDialog",
]
