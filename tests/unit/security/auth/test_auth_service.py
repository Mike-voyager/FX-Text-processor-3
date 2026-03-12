# -*- coding: utf-8 -*-
"""
Тесты для модуля src.security.auth.auth_service.

Покрывает: AuthService.authenticate(), validate_access(), logout(),
logout_all(), change_password(), AuthResult, AuthError, PasswordError,
SecondFactorError, обработку audit_callback.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import pytest

from src.security.auth.auth_service import (
    AuthError,
    AuthResult,
    AuthService,
    PasswordError,
    SecondFactorError,
)
from src.security.auth.permissions import (
    OPERATOR_SCOPES,
    MFARequiredError,
    Permission,
    ScopeError,
)
from src.security.auth.session import TokenBundle, ValidationResult

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Вспомогательные стабы
# ---------------------------------------------------------------------------


def _make_bundle(session_id: str = "sid-1", user_id: str = "operator") -> TokenBundle:
    """Создаёт тестовый TokenBundle."""
    return TokenBundle(
        session_id=session_id,
        user_id=user_id,
        access_token="access-" + session_id,
        refresh_token="refresh-" + session_id,
        access_expires_at=9_999_999_999,
        refresh_expires_at=9_999_999_999,
    )


def _make_validation(
    session_id: str = "sid-1",
    mfa_ok: bool = True,
    scopes: Optional[FrozenSet[str]] = None,
) -> ValidationResult:
    """Создаёт тестовый ValidationResult."""
    return ValidationResult(
        valid=True,
        user_id="operator",
        session_id=session_id,
        scopes=scopes if scopes is not None else OPERATOR_SCOPES,
        mfa_ok=mfa_ok,
        mfa_required=True,
        expires_at=9_999_999_999,
        reason=None,
    )


class DummyPasswordService:
    """Заглушка PasswordService."""

    def __init__(
        self,
        verify_result: bool = True,
        verify_raises: Optional[Exception] = None,
        change_result: bool = True,
        change_raises: Optional[Exception] = None,
    ) -> None:
        self._verify_result = verify_result
        self._verify_raises = verify_raises
        self._change_result = change_result
        self._change_raises = change_raises
        self.verify_calls: List[Tuple[str, str]] = []
        self.change_calls: List[Dict[str, Any]] = []

    def verify_password(self, user_id: str, password: str) -> bool:
        self.verify_calls.append((user_id, password))
        if self._verify_raises is not None:
            raise self._verify_raises
        return self._verify_result

    def change_password(
        self, user_id: str, *, current_password: str, new_password: str
    ) -> bool:
        self.change_calls.append(
            {
                "user_id": user_id,
                "current": current_password,
                "new": new_password,
            }
        )
        if self._change_raises is not None:
            raise self._change_raises
        return self._change_result


class DummyMFAManager:
    """Заглушка SecondFactorManager."""

    def __init__(
        self,
        verify_result: bool = True,
        verify_raises: Optional[Exception] = None,
    ) -> None:
        self._verify_result = verify_result
        self._verify_raises = verify_raises
        self.verify_calls: List[Dict[str, Any]] = []

    def verify_factor(
        self,
        user_id: str,
        factor_type: str,
        credential: Any,
        state: Optional[Dict[str, Any]] = None,
    ) -> bool:
        self.verify_calls.append(
            {
                "user_id": user_id,
                "factor_type": factor_type,
                "credential": credential,
                "state": state,
            }
        )
        if self._verify_raises is not None:
            raise self._verify_raises
        return self._verify_result


class DummySessionService:
    """Заглушка SessionService."""

    def __init__(self) -> None:
        self.created: List[Dict[str, Any]] = []
        self.mfa_satisfied: List[str] = []
        self.mfa_required_checks: List[str] = []
        self.locked: List[str] = []
        self.revoked_all: List[str] = []
        self.validated: List[str] = []

        self._bundle: Optional[TokenBundle] = None
        self._validation: Optional[ValidationResult] = None
        self._revoke_count: int = 2
        self._require_mfa_raises: Optional[Exception] = None

    def create_session(
        self,
        user_id: str,
        *,
        mfa_required: bool = True,
        scopes: Optional[FrozenSet[str]] = None,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
        remember: bool = False,
    ) -> TokenBundle:
        self.created.append(
            {
                "user_id": user_id,
                "mfa_required": mfa_required,
                "scopes": scopes,
            }
        )
        if self._bundle is not None:
            return self._bundle
        return _make_bundle(user_id=user_id)

    def mark_mfa_satisfied(self, session_id: str) -> None:
        self.mfa_satisfied.append(session_id)

    def require_mfa(
        self, session_id: str, freshness_seconds: Optional[int] = None
    ) -> None:
        self.mfa_required_checks.append(session_id)
        if self._require_mfa_raises is not None:
            raise self._require_mfa_raises

    def validate(
        self,
        access_token: str,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> ValidationResult:
        self.validated.append(access_token)
        if self._validation is not None:
            return self._validation
        return _make_validation()

    def lock(self, session_id: str, *, user_id: str = "") -> None:
        self.locked.append(session_id)

    def revoke_all(self, user_id: str) -> int:
        self.revoked_all.append(user_id)
        return self._revoke_count


class DummyPermissionsService:
    """Заглушка PermissionsService."""

    def __init__(
        self, assert_raises: Optional[Exception] = None
    ) -> None:
        self._assert_raises = assert_raises
        self.assert_calls: List[Dict[str, Any]] = []

    def assert_access(
        self,
        scopes: FrozenSet[str],
        permission: Permission,
        *,
        mfa_satisfied: bool = False,
    ) -> None:
        self.assert_calls.append(
            {
                "scopes": scopes,
                "permission": permission,
                "mfa_satisfied": mfa_satisfied,
            }
        )
        if self._assert_raises is not None:
            raise self._assert_raises


class DummyAuditLog:
    """Заглушка audit_callback."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        self.calls.append((event, details))


class BrokenAuditLog:
    """Заглушка audit_callback, выбрасывающая исключение."""

    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        raise RuntimeError("audit сломан")


def _make_auth_service(
    pw_verify: bool = True,
    pw_raises: Optional[Exception] = None,
    mfa_verify: bool = True,
    mfa_raises: Optional[Exception] = None,
    require_second_factor: bool = True,
    audit: Optional[DummyAuditLog] = None,
    perm_service: Optional[DummyPermissionsService] = None,
) -> Tuple[AuthService, DummyPasswordService, DummyMFAManager, DummySessionService]:
    """Фабрика AuthService с заглушками зависимостей."""
    pw_svc = DummyPasswordService(
        verify_result=pw_verify, verify_raises=pw_raises
    )
    mfa_mgr = DummyMFAManager(
        verify_result=mfa_verify, verify_raises=mfa_raises
    )
    sess_svc = DummySessionService()
    perms_svc = perm_service or DummyPermissionsService()
    svc = AuthService(
        password_service=pw_svc,
        mfa_manager=mfa_mgr,
        session_service=sess_svc,  # type: ignore[arg-type]
        permissions_service=perms_svc,  # type: ignore[arg-type]
        audit_callback=audit,
        require_second_factor=require_second_factor,
    )
    return svc, pw_svc, mfa_mgr, sess_svc


# ---------------------------------------------------------------------------
# Тесты AuthResult
# ---------------------------------------------------------------------------


class TestAuthResult:
    """Тесты для frozen dataclass AuthResult."""

    def test_is_frozen(self) -> None:
        """AuthResult является frozen dataclass."""
        # Arrange
        result = AuthResult(success=True, user_id="op")
        # Act / Assert
        with pytest.raises(Exception):
            result.success = False  # type: ignore[misc]

    def test_default_fields(self) -> None:
        """AuthResult имеет корректные значения по умолчанию."""
        # Arrange / Act
        result = AuthResult(success=True, user_id="op")
        # Assert
        assert result.session_id is None
        assert result.token_bundle is None
        assert result.failure_reason is None
        assert result.mfa_required is True

    def test_success_fields(self) -> None:
        """AuthResult сохраняет все поля при успешной аутентификации."""
        # Arrange
        bundle = _make_bundle()
        # Act
        result = AuthResult(
            success=True,
            user_id="op",
            session_id="sid-1",
            token_bundle=bundle,
        )
        # Assert
        assert result.success is True
        assert result.session_id == "sid-1"
        assert result.token_bundle is bundle


# ---------------------------------------------------------------------------
# Тесты иерархии исключений
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Тесты для иерархии исключений AuthError."""

    def test_auth_error_is_exception(self) -> None:
        """AuthError является подклассом Exception."""
        assert issubclass(AuthError, Exception)

    def test_password_error_is_auth_error(self) -> None:
        """PasswordError является подклассом AuthError."""
        assert issubclass(PasswordError, AuthError)

    def test_second_factor_error_is_auth_error(self) -> None:
        """SecondFactorError является подклассом AuthError."""
        assert issubclass(SecondFactorError, AuthError)

    def test_can_raise_password_error(self) -> None:
        """PasswordError можно создать и поймать."""
        with pytest.raises(PasswordError):
            raise PasswordError("неверный пароль")

    def test_can_raise_second_factor_error(self) -> None:
        """SecondFactorError можно создать и поймать."""
        with pytest.raises(SecondFactorError):
            raise SecondFactorError("неверный код")


# ---------------------------------------------------------------------------
# Тесты AuthService.authenticate() — успешный путь
# ---------------------------------------------------------------------------


class TestAuthenticateSuccess:
    """Тесты успешного пути аутентификации."""

    def test_success_full_mfa_flow(self) -> None:
        """authenticate() возвращает AuthResult(success=True) при корректных данных."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        result = svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="123456",
        )
        # Assert
        assert result.success is True
        assert result.user_id == "operator"
        assert result.session_id is not None
        assert result.token_bundle is not None
        assert result.failure_reason is None

    def test_session_is_created(self) -> None:
        """authenticate() создаёт сессию через session_service."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="123456",
        )
        # Assert
        assert len(sess.created) == 1

    def test_mfa_satisfied_is_marked(self) -> None:
        """authenticate() помечает MFA как пройденный после успешной проверки."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="123456",
        )
        # Assert
        assert len(sess.mfa_satisfied) == 1

    def test_audit_auth_success_called(self) -> None:
        """authenticate() вызывает audit_callback 'auth.success' при успехе."""
        # Arrange
        audit = DummyAuditLog()
        svc, pw, mfa, sess = _make_auth_service(audit=audit)
        # Act
        svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="123456",
        )
        # Assert
        events = [c[0] for c in audit.calls]
        assert "auth.success" in events

    def test_custom_scopes_passed_to_session(self) -> None:
        """authenticate() передаёт кастомные scopes в session_service."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        custom: FrozenSet[str] = frozenset({"documents"})
        # Act
        svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="123456",
            scopes=custom,
        )
        # Assert
        assert sess.created[0]["scopes"] == custom

    def test_no_mfa_if_require_second_factor_false(self) -> None:
        """authenticate() пропускает MFA при require_second_factor=False."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(require_second_factor=False)
        # Act
        result = svc.authenticate("operator", password="secret")
        # Assert
        assert result.success is True
        assert len(mfa.verify_calls) == 0
        # MFA не помечается при пропуске второго фактора
        assert len(sess.mfa_satisfied) == 0


# ---------------------------------------------------------------------------
# Тесты AuthService.authenticate() — ошибки пароля
# ---------------------------------------------------------------------------


class TestAuthenticatePasswordFailures:
    """Тесты ветвей ошибок проверки пароля."""

    def test_password_exception_returns_password_error_reason(self) -> None:
        """authenticate() возвращает failure_reason='password_error' при исключении."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(
            pw_raises=RuntimeError("db error")
        )
        # Act
        result = svc.authenticate("operator", password="secret")
        # Assert
        assert result.success is False
        assert result.failure_reason == "password_error"

    def test_password_false_returns_invalid_password_reason(self) -> None:
        """authenticate() возвращает failure_reason='invalid_password' при verify_password=False."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(pw_verify=False)
        # Act
        result = svc.authenticate("operator", password="wrong")
        # Assert
        assert result.success is False
        assert result.failure_reason == "invalid_password"

    def test_audit_auth_failed_called_on_password_exception(self) -> None:
        """authenticate() вызывает audit 'auth.failed' при исключении пароля."""
        # Arrange
        audit = DummyAuditLog()
        svc, pw, mfa, sess = _make_auth_service(
            pw_raises=RuntimeError("err"), audit=audit
        )
        # Act
        svc.authenticate("operator", password="secret")
        # Assert
        events = [c[0] for c in audit.calls]
        assert "auth.failed" in events

    def test_audit_auth_failed_called_on_invalid_password(self) -> None:
        """authenticate() вызывает audit 'auth.failed' при неверном пароле."""
        # Arrange
        audit = DummyAuditLog()
        svc, pw, mfa, sess = _make_auth_service(pw_verify=False, audit=audit)
        # Act
        svc.authenticate("operator", password="wrong")
        # Assert
        events = [c[0] for c in audit.calls]
        assert "auth.failed" in events


# ---------------------------------------------------------------------------
# Тесты AuthService.authenticate() — ошибки MFA
# ---------------------------------------------------------------------------


class TestAuthenticateMFAFailures:
    """Тесты ветвей ошибок второго фактора."""

    def test_missing_factor_type_returns_mfa_missing(self) -> None:
        """authenticate() возвращает 'mfa_missing' при отсутствии factor_type."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        result = svc.authenticate(
            "operator",
            password="secret",
            factor_type=None,
            factor_credential="123456",
        )
        # Assert
        assert result.success is False
        assert result.failure_reason == "mfa_missing"

    def test_missing_factor_credential_returns_mfa_missing(self) -> None:
        """authenticate() возвращает 'mfa_missing' при отсутствии factor_credential."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        result = svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential=None,
        )
        # Assert
        assert result.success is False
        assert result.failure_reason == "mfa_missing"

    def test_mfa_exception_returns_mfa_error(self) -> None:
        """authenticate() возвращает 'mfa_error' при исключении в verify_factor."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(
            mfa_raises=RuntimeError("fido2 error")
        )
        # Act
        result = svc.authenticate(
            "operator",
            password="secret",
            factor_type="fido2",
            factor_credential=b"assertion",
        )
        # Assert
        assert result.success is False
        assert result.failure_reason == "mfa_error"

    def test_mfa_false_returns_invalid_mfa(self) -> None:
        """authenticate() возвращает 'invalid_mfa' при verify_factor=False."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(mfa_verify=False)
        # Act
        result = svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="000000",
        )
        # Assert
        assert result.success is False
        assert result.failure_reason == "invalid_mfa"

    def test_audit_failed_called_on_mfa_missing(self) -> None:
        """authenticate() вызывает audit 'auth.failed' при отсутствии MFA."""
        # Arrange
        audit = DummyAuditLog()
        svc, pw, mfa, sess = _make_auth_service(audit=audit)
        # Act
        svc.authenticate("operator", password="secret", factor_type=None)
        # Assert
        events = [c[0] for c in audit.calls]
        assert "auth.failed" in events

    def test_audit_failed_called_on_mfa_error(self) -> None:
        """authenticate() вызывает audit 'auth.failed' при исключении MFA."""
        # Arrange
        audit = DummyAuditLog()
        svc, pw, mfa, sess = _make_auth_service(
            mfa_raises=RuntimeError("err"), audit=audit
        )
        # Act
        svc.authenticate(
            "operator", password="secret", factor_type="totp", factor_credential="x"
        )
        # Assert
        events = [c[0] for c in audit.calls]
        assert "auth.failed" in events

    def test_audit_failed_called_on_invalid_mfa(self) -> None:
        """authenticate() вызывает audit 'auth.failed' при неверном MFA."""
        # Arrange
        audit = DummyAuditLog()
        svc, pw, mfa, sess = _make_auth_service(mfa_verify=False, audit=audit)
        # Act
        svc.authenticate(
            "operator", password="secret", factor_type="totp", factor_credential="bad"
        )
        # Assert
        events = [c[0] for c in audit.calls]
        assert "auth.failed" in events


# ---------------------------------------------------------------------------
# Тесты AuthService.validate_access()
# ---------------------------------------------------------------------------


class TestValidateAccess:
    """Тесты для метода validate_access()."""

    def test_delegates_to_session_service_without_permission(self) -> None:
        """validate_access() делегирует session_service.validate() без required_permission."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        result = svc.validate_access("my-token")
        # Assert
        assert "my-token" in sess.validated
        assert isinstance(result, ValidationResult)

    def test_calls_permissions_service_with_required_permission(self) -> None:
        """validate_access() вызывает permissions_service.assert_access() при required_permission."""
        # Arrange
        perm_svc = DummyPermissionsService()
        svc, pw, mfa, sess = _make_auth_service(perm_service=perm_svc)
        # Act
        svc.validate_access("tok", required_permission=Permission.DOCUMENT_READ)
        # Assert
        assert len(perm_svc.assert_calls) == 1
        call = perm_svc.assert_calls[0]
        assert call["permission"] is Permission.DOCUMENT_READ

    def test_passes_mfa_ok_to_permissions_service(self) -> None:
        """validate_access() передаёт mfa_ok из ValidationResult в permissions_service."""
        # Arrange
        perm_svc = DummyPermissionsService()
        svc, pw, mfa, sess = _make_auth_service(perm_service=perm_svc)
        sess._validation = _make_validation(mfa_ok=True)
        # Act
        svc.validate_access("tok", required_permission=Permission.DOCUMENT_READ)
        # Assert
        assert perm_svc.assert_calls[0]["mfa_satisfied"] is True

    def test_scope_error_propagates(self) -> None:
        """validate_access() пробрасывает ScopeError от permissions_service."""
        # Arrange
        perm_svc = DummyPermissionsService(
            assert_raises=ScopeError(Permission.DOCUMENT_READ, frozenset())
        )
        svc, pw, mfa, sess = _make_auth_service(perm_service=perm_svc)
        # Act / Assert
        with pytest.raises(ScopeError):
            svc.validate_access("tok", required_permission=Permission.DOCUMENT_READ)

    def test_no_permissions_check_when_permission_is_none(self) -> None:
        """validate_access() не вызывает permissions_service при required_permission=None."""
        # Arrange
        perm_svc = DummyPermissionsService()
        svc, pw, mfa, sess = _make_auth_service(perm_service=perm_svc)
        # Act
        svc.validate_access("tok")
        # Assert
        assert len(perm_svc.assert_calls) == 0


# ---------------------------------------------------------------------------
# Тесты AuthService.logout()
# ---------------------------------------------------------------------------


class TestLogout:
    """Тесты для метода logout()."""

    def test_calls_session_service_lock(self) -> None:
        """logout() вызывает session_service.lock()."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        svc.logout("sid-1", user_id="operator")
        # Assert
        assert "sid-1" in sess.locked


# ---------------------------------------------------------------------------
# Тесты AuthService.logout_all()
# ---------------------------------------------------------------------------


class TestLogoutAll:
    """Тесты для метода logout_all()."""

    def test_calls_session_service_revoke_all(self) -> None:
        """logout_all() вызывает session_service.revoke_all()."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        svc.logout_all("operator")
        # Assert
        assert "operator" in sess.revoked_all

    def test_returns_count(self) -> None:
        """logout_all() возвращает количество отозванных сессий."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        sess._revoke_count = 5
        # Act
        count = svc.logout_all("operator")
        # Assert
        assert count == 5

    def test_audit_called(self) -> None:
        """logout_all() вызывает audit_callback."""
        # Arrange
        audit = DummyAuditLog()
        svc, pw, mfa, sess = _make_auth_service(audit=audit)
        # Act
        svc.logout_all("operator")
        # Assert
        assert len(audit.calls) >= 1


# ---------------------------------------------------------------------------
# Тесты AuthService.change_password()
# ---------------------------------------------------------------------------


class TestChangePassword:
    """Тесты для метода change_password()."""

    def test_calls_require_mfa(self) -> None:
        """change_password() вызывает session_service.require_mfa()."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        svc.change_password(
            "operator",
            current_password="old",
            new_password="new",
            session_id="sid-1",
        )
        # Assert
        assert "sid-1" in sess.mfa_required_checks

    def test_calls_password_service_change(self) -> None:
        """change_password() вызывает password_service.change_password()."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        svc.change_password(
            "operator",
            current_password="old",
            new_password="new",
            session_id="sid-1",
        )
        # Assert
        assert len(pw.change_calls) == 1
        assert pw.change_calls[0]["user_id"] == "operator"

    def test_revokes_all_sessions_on_success(self) -> None:
        """change_password() отзывает все сессии пользователя при успехе."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service()
        # Act
        svc.change_password(
            "operator",
            current_password="old",
            new_password="new",
            session_id="sid-1",
        )
        # Assert
        assert "operator" in sess.revoked_all

    def test_raises_password_error_when_service_raises(self) -> None:
        """change_password() выбрасывает PasswordError при ошибке password_service."""
        # Arrange
        pw_svc = DummyPasswordService(change_raises=ValueError("слабый пароль"))
        mfa_mgr = DummyMFAManager()
        sess_svc = DummySessionService()
        svc = AuthService(
            password_service=pw_svc,
            mfa_manager=mfa_mgr,
            session_service=sess_svc,  # type: ignore[arg-type]
        )
        # Act / Assert
        with pytest.raises(PasswordError):
            svc.change_password(
                "operator",
                current_password="old",
                new_password="bad",
                session_id="sid-1",
            )

    def test_require_mfa_permission_error_propagates(self) -> None:
        """change_password() пробрасывает PermissionError от require_mfa."""
        # Arrange
        pw_svc = DummyPasswordService()
        mfa_mgr = DummyMFAManager()
        sess_svc = DummySessionService()
        sess_svc._require_mfa_raises = PermissionError("MFA не пройден")
        svc = AuthService(
            password_service=pw_svc,
            mfa_manager=mfa_mgr,
            session_service=sess_svc,  # type: ignore[arg-type]
        )
        # Act / Assert
        with pytest.raises(PermissionError):
            svc.change_password(
                "operator",
                current_password="old",
                new_password="new",
                session_id="sid-1",
            )



    def test_change_password_returns_false_does_not_revoke(self) -> None:
        """change_password() не отзывает сессии, если password_service вернул False."""
        # Arrange
        pw_svc = DummyPasswordService(change_result=False)
        mfa_mgr = DummyMFAManager()
        sess_svc = DummySessionService()
        svc = AuthService(
            password_service=pw_svc,
            mfa_manager=mfa_mgr,
            session_service=sess_svc,  # type: ignore[arg-type]
        )
        # Act
        result = svc.change_password(
            "operator",
            current_password="old",
            new_password="new",
            session_id="sid-1",
        )
        # Assert
        assert result is False
        assert "operator" not in sess_svc.revoked_all


# ---------------------------------------------------------------------------
# Тесты обработки audit_callback в AuthService
# ---------------------------------------------------------------------------


class TestAuditCallbackHandling:
    """Тесты для обработки исключений в _audit()."""

    def test_broken_audit_does_not_propagate_on_success(self) -> None:
        """Исключение в audit_callback не выходит при успешной аутентификации."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(audit=BrokenAuditLog())  # type: ignore[arg-type]
        # Act / Assert — не должно бросать
        result = svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="123456",
        )
        assert result.success is True

    def test_broken_audit_does_not_propagate_on_failure(self) -> None:
        """Исключение в audit_callback не выходит при неудаче аутентификации."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(
            pw_verify=False, audit=BrokenAuditLog()  # type: ignore[arg-type]
        )
        # Act / Assert — не должно бросать
        result = svc.authenticate("operator", password="wrong")
        assert result.success is False

    def test_none_audit_callback_no_error(self) -> None:
        """audit_callback=None не вызывает ошибок."""
        # Arrange
        svc, pw, mfa, sess = _make_auth_service(audit=None)
        # Act / Assert — не должно бросать
        svc.authenticate(
            "operator",
            password="secret",
            factor_type="totp",
            factor_credential="123456",
        )
