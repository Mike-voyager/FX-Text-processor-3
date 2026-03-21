# -*- coding: utf-8 -*-
"""
Тесты для модуля src.security.auth.session_service.

Покрывает: SessionService.create_session(), validate(), mark_mfa_satisfied(),
require_mfa(), refresh(), lock(), revoke(), revoke_all(), list_active(),
get_snapshot(), purge_expired(), SessionInfo, обработку audit_callback.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

import pytest
from src.security.auth.permissions import OPERATOR_SCOPES
from src.security.auth.session import TokenBundle, ValidationResult
from src.security.auth.session_service import SessionInfo, SessionService

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Вспомогательные стабы
# ---------------------------------------------------------------------------


def _make_bundle(session_id: str = "sid-1", user_id: str = "operator") -> TokenBundle:
    """Создаёт тестовый TokenBundle с заданными параметрами."""
    return TokenBundle(
        session_id=session_id,
        user_id=user_id,
        access_token="access-token-" + session_id,
        refresh_token="refresh-token-" + session_id,
        access_expires_at=9_999_999_999,
        refresh_expires_at=9_999_999_999,
    )


def _make_validation_result(
    session_id: str = "sid-1",
    user_id: str = "operator",
    mfa_ok: bool = False,
    scopes: Optional[FrozenSet[str]] = None,
) -> ValidationResult:
    """Создаёт тестовый ValidationResult."""
    return ValidationResult(
        valid=True,
        user_id=user_id,
        session_id=session_id,
        scopes=scopes if scopes is not None else OPERATOR_SCOPES,
        mfa_ok=mfa_ok,
        mfa_required=True,
        expires_at=9_999_999_999,
        reason=None,
    )


class DummySessionManager:
    """Заглушка SessionManager, записывающая вызовы методов."""

    def __init__(self) -> None:
        self.issued: List[Dict[str, Any]] = []
        self.validated: List[str] = []
        self.mfa_satisfied: List[str] = []
        self.mfa_required_checks: List[str] = []
        self.refreshed: List[str] = []
        self.revoked_by_session: List[str] = []
        self.revoked_all: List[str] = []
        self.listed: List[str] = []
        self.snapshots: List[str] = []
        self.purge_calls: int = 0

        # Конфигурируемые ответы
        self._issue_bundle: Optional[TokenBundle] = None
        self._validation_result: Optional[ValidationResult] = None
        self._refresh_bundle: Optional[TokenBundle] = None
        self._revoke_result: bool = True
        self._revoke_all_count: int = 3
        self._list_result: Tuple[int, Tuple[str, ...]] = (2, ("sid-1", "sid-2"))
        self._snapshot: Dict[str, object] = {"session_id": "sid-1", "user_id": "op"}
        self._purge_count: int = 5

    def issue(
        self,
        user_id: str,
        scopes: FrozenSet[str],
        mfa_required: bool = True,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
        remember: bool = False,
    ) -> TokenBundle:
        self.issued.append(
            {
                "user_id": user_id,
                "scopes": scopes,
                "mfa_required": mfa_required,
                "device_fingerprint": device_fingerprint,
                "ip": ip,
                "remember": remember,
            }
        )
        if self._issue_bundle is not None:
            return self._issue_bundle
        return _make_bundle(user_id=user_id)

    def validate_access(
        self,
        token: str,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> ValidationResult:
        self.validated.append(token)
        if self._validation_result is not None:
            return self._validation_result
        return _make_validation_result()

    def mark_mfa_satisfied(self, session_id: str) -> None:
        self.mfa_satisfied.append(session_id)

    def require_mfa(self, session_id: str, freshness_seconds: Optional[int] = None) -> None:
        self.mfa_required_checks.append(session_id)

    def refresh(
        self,
        refresh_token: str,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> TokenBundle:
        self.refreshed.append(refresh_token)
        if self._refresh_bundle is not None:
            return self._refresh_bundle
        return _make_bundle(session_id="sid-refreshed")

    def revoke_by_session_id(self, session_id: str) -> bool:
        self.revoked_by_session.append(session_id)
        return self._revoke_result

    def revoke_all_user_sessions(self, user_id: str) -> int:
        self.revoked_all.append(user_id)
        return self._revoke_all_count

    def list_active_sessions(self, user_id: str) -> Tuple[int, Tuple[str, ...]]:
        self.listed.append(user_id)
        return self._list_result

    def get_snapshot(self, session_id: str) -> Mapping[str, object]:
        self.snapshots.append(session_id)
        return self._snapshot

    def purge_expired(self) -> int:
        self.purge_calls += 1
        return self._purge_count


class DummyAuditLog:
    """Заглушка audit_callback."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        self.calls.append((event, details))


class BrokenAuditLog:
    """Заглушка audit_callback, всегда выбрасывающая исключение."""

    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        raise RuntimeError("audit сломан")


# ---------------------------------------------------------------------------
# Тесты SessionInfo
# ---------------------------------------------------------------------------


class TestSessionInfo:
    """Тесты для frozen dataclass SessionInfo."""

    def test_is_frozen(self) -> None:
        """SessionInfo является frozen dataclass."""
        # Arrange
        info = SessionInfo(
            session_id="s1",
            user_id="op",
            active=True,
            mfa_satisfied=False,
            scopes=("full",),
        )
        # Act / Assert
        with pytest.raises(Exception):
            info.active = False  # type: ignore[misc]

    def test_fields(self) -> None:
        """SessionInfo сохраняет все поля корректно."""
        # Arrange / Act
        info = SessionInfo(
            session_id="s1",
            user_id="op",
            active=True,
            mfa_satisfied=True,
            scopes=("full", "documents"),
        )
        # Assert
        assert info.session_id == "s1"
        assert info.user_id == "op"
        assert info.active is True
        assert info.mfa_satisfied is True
        assert "full" in info.scopes


# ---------------------------------------------------------------------------
# Тесты SessionService.create_session()
# ---------------------------------------------------------------------------


class TestCreateSession:
    """Тесты для метода create_session()."""

    def test_calls_session_manager_issue(self) -> None:
        """create_session() вызывает session_manager.issue() с корректными аргументами."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        svc.create_session("operator", mfa_required=True)
        # Assert
        assert len(mgr.issued) == 1
        call = mgr.issued[0]
        assert call["user_id"] == "operator"
        assert call["mfa_required"] is True

    def test_returns_token_bundle(self) -> None:
        """create_session() возвращает TokenBundle."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        bundle = svc.create_session("operator")
        # Assert
        assert isinstance(bundle, TokenBundle)

    def test_uses_operator_scopes_by_default(self) -> None:
        """create_session() использует OPERATOR_SCOPES по умолчанию."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        svc.create_session("operator")
        # Assert
        assert mgr.issued[0]["scopes"] == OPERATOR_SCOPES

    def test_uses_custom_scopes(self) -> None:
        """create_session() передаёт кастомные scopes в session_manager."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        custom_scopes: FrozenSet[str] = frozenset({"documents"})
        # Act
        svc.create_session("operator", scopes=custom_scopes)
        # Assert
        assert mgr.issued[0]["scopes"] == custom_scopes

    def test_audit_auth_success_called(self) -> None:
        """create_session() вызывает audit_callback с событием 'auth.success'."""
        # Arrange
        audit = DummyAuditLog()
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr, audit_callback=audit)  # type: ignore[arg-type]
        # Act
        svc.create_session("operator")
        # Assert
        assert len(audit.calls) == 1
        event, details = audit.calls[0]
        assert event == "auth.success"
        assert details["user_id"] == "operator"


# ---------------------------------------------------------------------------
# Тесты SessionService.validate()
# ---------------------------------------------------------------------------


class TestValidate:
    """Тесты для метода validate()."""

    def test_delegates_to_session_manager(self) -> None:
        """validate() делегирует вызов session_manager.validate_access()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        result = svc.validate("my-token")
        # Assert
        assert "my-token" in mgr.validated
        assert isinstance(result, ValidationResult)

    def test_passes_fingerprint_and_ip(self) -> None:
        """validate() передаёт device_fingerprint и ip в session_manager."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]

        # Подменяем метод чтобы проверить аргументы
        captured: Dict[str, Any] = {}

        def _mock_validate(
            token: str,
            device_fingerprint: Optional[str] = None,
            ip: Optional[str] = None,
        ) -> ValidationResult:
            captured["token"] = token
            captured["fp"] = device_fingerprint
            captured["ip"] = ip
            return _make_validation_result()

        mgr.validate_access = _mock_validate  # type: ignore[method-assign]
        # Act
        svc.validate("tok", device_fingerprint="fp1", ip="127.0.0.1")
        # Assert
        assert captured["fp"] == "fp1"
        assert captured["ip"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# Тесты SessionService.mark_mfa_satisfied()
# ---------------------------------------------------------------------------


class TestMarkMfaSatisfied:
    """Тесты для метода mark_mfa_satisfied()."""

    def test_delegates_to_session_manager(self) -> None:
        """mark_mfa_satisfied() делегирует вызов session_manager."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        svc.mark_mfa_satisfied("sid-1")
        # Assert
        assert "sid-1" in mgr.mfa_satisfied

    def test_audit_mfa_challenged_called(self) -> None:
        """mark_mfa_satisfied() вызывает audit_callback с 'auth.mfa_challenged'."""
        # Arrange
        audit = DummyAuditLog()
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr, audit_callback=audit)  # type: ignore[arg-type]
        # Act
        svc.mark_mfa_satisfied("sid-1")
        # Assert
        assert len(audit.calls) == 1
        event, details = audit.calls[0]
        assert event == "auth.mfa_challenged"
        assert details["session_id"] == "sid-1"


# ---------------------------------------------------------------------------
# Тесты SessionService.require_mfa()
# ---------------------------------------------------------------------------


class TestRequireMfa:
    """Тесты для метода require_mfa()."""

    def test_delegates_to_session_manager(self) -> None:
        """require_mfa() делегирует вызов session_manager.require_mfa()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        svc.require_mfa("sid-1")
        # Assert
        assert "sid-1" in mgr.mfa_required_checks

    def test_passes_freshness_seconds(self) -> None:
        """require_mfa() передаёт freshness_seconds в session_manager."""
        # Arrange
        mgr = DummySessionManager()
        captured: Dict[str, Any] = {}

        def _mock_require(session_id: str, freshness_seconds: Optional[int] = None) -> None:
            captured["sid"] = session_id
            captured["freshness"] = freshness_seconds

        mgr.require_mfa = _mock_require  # type: ignore[method-assign]
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        svc.require_mfa("sid-1", freshness_seconds=300)
        # Assert
        assert captured["freshness"] == 300


# ---------------------------------------------------------------------------
# Тесты SessionService.refresh()
# ---------------------------------------------------------------------------


class TestRefresh:
    """Тесты для метода refresh()."""

    def test_delegates_to_session_manager(self) -> None:
        """refresh() делегирует вызов session_manager.refresh()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        bundle = svc.refresh("refresh-tok")
        # Assert
        assert "refresh-tok" in mgr.refreshed
        assert isinstance(bundle, TokenBundle)


# ---------------------------------------------------------------------------
# Тесты SessionService.lock()
# ---------------------------------------------------------------------------


class TestLock:
    """Тесты для метода lock()."""

    def test_calls_revoke_by_session_id(self) -> None:
        """lock() вызывает session_manager.revoke_by_session_id()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        svc.lock("sid-1")
        # Assert
        assert "sid-1" in mgr.revoked_by_session

    def test_audit_app_locked_called(self) -> None:
        """lock() вызывает audit_callback с событием 'app.locked'."""
        # Arrange
        audit = DummyAuditLog()
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr, audit_callback=audit)  # type: ignore[arg-type]
        # Act
        svc.lock("sid-1", user_id="operator")
        # Assert
        assert len(audit.calls) == 1
        event, details = audit.calls[0]
        assert event == "app.locked"
        assert details["session_id"] == "sid-1"
        assert details["user_id"] == "operator"


# ---------------------------------------------------------------------------
# Тесты SessionService.revoke()
# ---------------------------------------------------------------------------


class TestRevoke:
    """Тесты для метода revoke()."""

    def test_returns_true_when_session_found(self) -> None:
        """revoke() возвращает True, если сессия найдена и отозвана."""
        # Arrange
        mgr = DummySessionManager()
        mgr._revoke_result = True
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        result = svc.revoke("sid-1")
        # Assert
        assert result is True

    def test_returns_false_when_session_not_found(self) -> None:
        """revoke() возвращает False, если сессия не найдена."""
        # Arrange
        mgr = DummySessionManager()
        mgr._revoke_result = False
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        result = svc.revoke("nonexistent")
        # Assert
        assert result is False

    def test_audit_called_on_true(self) -> None:
        """revoke() вызывает audit_callback при успешном отзыве."""
        # Arrange
        audit = DummyAuditLog()
        mgr = DummySessionManager()
        mgr._revoke_result = True
        svc = SessionService(session_manager=mgr, audit_callback=audit)  # type: ignore[arg-type]
        # Act
        svc.revoke("sid-1")
        # Assert
        assert len(audit.calls) == 1
        event, details = audit.calls[0]
        assert event == "session.revoke"
        assert details["session_id"] == "sid-1"

    def test_audit_not_called_on_false(self) -> None:
        """revoke() не вызывает audit_callback при неудаче."""
        # Arrange
        audit = DummyAuditLog()
        mgr = DummySessionManager()
        mgr._revoke_result = False
        svc = SessionService(session_manager=mgr, audit_callback=audit)  # type: ignore[arg-type]
        # Act
        svc.revoke("nonexistent")
        # Assert
        assert len(audit.calls) == 0


# ---------------------------------------------------------------------------
# Тесты SessionService.revoke_all()
# ---------------------------------------------------------------------------


class TestRevokeAll:
    """Тесты для метода revoke_all()."""

    def test_calls_revoke_all_user_sessions(self) -> None:
        """revoke_all() вызывает session_manager.revoke_all_user_sessions()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        svc.revoke_all("operator")
        # Assert
        assert "operator" in mgr.revoked_all

    def test_audit_session_revoke_all_called(self) -> None:
        """revoke_all() вызывает audit_callback с 'session.revoke_all'."""
        # Arrange
        audit = DummyAuditLog()
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr, audit_callback=audit)  # type: ignore[arg-type]
        # Act
        count = svc.revoke_all("operator")
        # Assert
        assert len(audit.calls) == 1
        event, details = audit.calls[0]
        assert event == "session.revoke_all"
        assert details["user_id"] == "operator"
        assert details["count"] == count


# ---------------------------------------------------------------------------
# Тесты SessionService.list_active()
# ---------------------------------------------------------------------------


class TestListActive:
    """Тесты для метода list_active()."""

    def test_delegates_to_session_manager(self) -> None:
        """list_active() делегирует вызов session_manager.list_active_sessions()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        result = svc.list_active("operator")
        # Assert
        assert "operator" in mgr.listed
        count, ids = result
        assert count == 2


# ---------------------------------------------------------------------------
# Тесты SessionService.get_snapshot()
# ---------------------------------------------------------------------------


class TestGetSnapshot:
    """Тесты для метода get_snapshot()."""

    def test_delegates_to_session_manager(self) -> None:
        """get_snapshot() делегирует вызов session_manager.get_snapshot()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        snapshot = svc.get_snapshot("sid-1")
        # Assert
        assert "sid-1" in mgr.snapshots
        assert isinstance(snapshot, dict)


# ---------------------------------------------------------------------------
# Тесты SessionService.purge_expired()
# ---------------------------------------------------------------------------


class TestPurgeExpired:
    """Тесты для метода purge_expired()."""

    def test_delegates_to_session_manager(self) -> None:
        """purge_expired() делегирует вызов session_manager.purge_expired()."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr)  # type: ignore[arg-type]
        # Act
        count = svc.purge_expired()
        # Assert
        assert mgr.purge_calls == 1
        assert count == mgr._purge_count


# ---------------------------------------------------------------------------
# Тесты обработки audit_callback
# ---------------------------------------------------------------------------


class TestAuditCallbackHandling:
    """Тесты для обработки исключений в audit_callback."""

    def test_none_audit_callback_no_error(self) -> None:
        """audit_callback=None не вызывает ошибок."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr, audit_callback=None)  # type: ignore[arg-type]
        # Act / Assert — не должно бросать
        svc.create_session("operator")

    def test_broken_audit_callback_does_not_propagate(self) -> None:
        """Исключение в audit_callback не выходит за пределы SessionService."""
        # Arrange
        mgr = DummySessionManager()
        svc = SessionService(session_manager=mgr, audit_callback=BrokenAuditLog())  # type: ignore[arg-type]
        # Act / Assert — не должно бросать
        svc.create_session("operator")
        svc.lock("sid-1")
        svc.revoke("sid-1")
