# -*- coding: utf-8 -*-
"""
Тесты для модуля src.security.auth.permissions_service.

Покрывает: PermissionsService.decide(), check(), assert_access(),
mfa_required_for(), effective_permissions(), mfa_gated_permissions(),
denial_count, audit_callback, AccessDecision, DenialReason.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import pytest
from src.security.auth.permissions import (
    MFA_REQUIRED_PERMISSIONS,
    OPERATOR_SCOPES,
    MFARequiredError,
    Permission,
    ScopeError,
)
from src.security.auth.permissions_service import (
    AccessDecision,
    DenialReason,
    PermissionsService,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Вспомогательные стабы
# ---------------------------------------------------------------------------


class DummyAuditLog:
    """Заглушка для audit_callback: записывает вызовы."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        self.calls.append((event, details))


class BrokenAuditLog:
    """Заглушка audit_callback, которая всегда выбрасывает исключение."""

    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        raise RuntimeError("audit сломан")


# ---------------------------------------------------------------------------
# Тесты AccessDecision
# ---------------------------------------------------------------------------


class TestAccessDecision:
    """Тесты для frozen dataclass AccessDecision."""

    def test_is_frozen(self) -> None:
        """AccessDecision является frozen dataclass."""
        # Arrange
        decision = AccessDecision(granted=True, permission=Permission.DOCUMENT_READ)
        # Act / Assert
        with pytest.raises(Exception):
            decision.granted = False  # type: ignore[misc]

    def test_fields_default_values(self) -> None:
        """Поля reason и mfa_required имеют корректные значения по умолчанию."""
        # Arrange / Act
        decision = AccessDecision(granted=True, permission=Permission.BLANK_SIGN)
        # Assert
        assert decision.reason is None
        assert decision.mfa_required is False

    def test_fields_with_denial(self) -> None:
        """AccessDecision сохраняет reason и mfa_required при отказе."""
        # Arrange / Act
        decision = AccessDecision(
            granted=False,
            permission=Permission.DEVICE_PROVISION,
            reason=DenialReason.MFA_REQUIRED,
            mfa_required=True,
        )
        # Assert
        assert decision.granted is False
        assert decision.reason == DenialReason.MFA_REQUIRED
        assert decision.mfa_required is True


# ---------------------------------------------------------------------------
# Тесты DenialReason
# ---------------------------------------------------------------------------


class TestDenialReason:
    """Тесты для строковых констант DenialReason."""

    def test_scope_missing_constant(self) -> None:
        """DenialReason.SCOPE_MISSING == 'scope_missing'."""
        assert DenialReason.SCOPE_MISSING == "scope_missing"

    def test_mfa_required_constant(self) -> None:
        """DenialReason.MFA_REQUIRED == 'mfa_required'."""
        assert DenialReason.MFA_REQUIRED == "mfa_required"


# ---------------------------------------------------------------------------
# Тесты PermissionsService.decide()
# ---------------------------------------------------------------------------


class TestPermissionsServiceDecide:
    """Тесты для метода decide()."""

    def test_granted_valid_scope_non_mfa(self) -> None:
        """decide() возвращает granted=True для допустимого scope и не-MFA операции."""
        # Arrange
        svc = PermissionsService()
        # Act
        decision = svc.decide(OPERATOR_SCOPES, Permission.DOCUMENT_READ, mfa_satisfied=False)
        # Assert
        assert decision.granted is True
        assert decision.reason is None

    def test_granted_valid_scope_mfa_satisfied(self) -> None:
        """decide() возвращает granted=True при mfa_satisfied=True для MFA-операции."""
        # Arrange
        svc = PermissionsService()
        # Act
        decision = svc.decide(OPERATOR_SCOPES, Permission.DEVICE_PROVISION, mfa_satisfied=True)
        # Assert
        assert decision.granted is True

    def test_denied_scope_missing(self) -> None:
        """decide() возвращает granted=False с reason=scope_missing при отсутствии scope."""
        # Arrange
        svc = PermissionsService()
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act
        decision = svc.decide(scopes, Permission.DOCUMENT_READ)
        # Assert
        assert decision.granted is False
        assert decision.reason == DenialReason.SCOPE_MISSING

    def test_denied_mfa_required(self) -> None:
        """decide() возвращает granted=False с reason=mfa_required для MFA-операции."""
        # Arrange
        svc = PermissionsService()
        # Act
        decision = svc.decide(OPERATOR_SCOPES, Permission.DEVICE_PROVISION, mfa_satisfied=False)
        # Assert
        assert decision.granted is False
        assert decision.reason == DenialReason.MFA_REQUIRED

    def test_mfa_required_flag_set_on_mfa_permission(self) -> None:
        """decide() устанавливает mfa_required=True для MFA-gated разрешения."""
        # Arrange
        svc = PermissionsService()
        # Act
        decision = svc.decide(OPERATOR_SCOPES, Permission.KEY_EXPORT, mfa_satisfied=False)
        # Assert
        assert decision.mfa_required is True

    def test_audit_callback_called_on_scope_denial(self) -> None:
        """audit_callback вызывается при отказе по scope."""
        # Arrange
        audit = DummyAuditLog()
        svc = PermissionsService(audit_callback=audit)
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act
        svc.decide(scopes, Permission.DOCUMENT_READ)
        # Assert
        assert len(audit.calls) == 1
        event, details = audit.calls[0]
        assert event == "access.denied"
        assert details["permission"] == Permission.DOCUMENT_READ.value
        assert details["reason"] == DenialReason.SCOPE_MISSING

    def test_audit_callback_called_on_mfa_denial(self) -> None:
        """audit_callback вызывается при отказе по MFA."""
        # Arrange
        audit = DummyAuditLog()
        svc = PermissionsService(audit_callback=audit)
        # Act
        svc.decide(OPERATOR_SCOPES, Permission.DEVICE_PROVISION, mfa_satisfied=False)
        # Assert
        assert len(audit.calls) == 1
        event, details = audit.calls[0]
        assert event == "access.denied"
        assert details["reason"] == DenialReason.MFA_REQUIRED

    def test_audit_callback_exception_does_not_propagate(self) -> None:
        """Исключение в audit_callback не выходит за пределы decide()."""
        # Arrange
        svc = PermissionsService(audit_callback=BrokenAuditLog())
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act — не должно бросать
        decision = svc.decide(scopes, Permission.DOCUMENT_READ)
        # Assert
        assert decision.granted is False

    def test_denial_count_increments_on_denial(self) -> None:
        """denial_count увеличивается при каждом отказе."""
        # Arrange
        svc = PermissionsService()
        scopes: FrozenSet[str] = frozenset({"audit"})
        assert svc.denial_count == 0
        # Act
        svc.decide(scopes, Permission.DOCUMENT_READ)
        svc.decide(scopes, Permission.BLANK_SIGN)
        # Assert
        assert svc.denial_count == 2

    def test_denial_count_not_incremented_on_grant(self) -> None:
        """denial_count не меняется при успешном доступе."""
        # Arrange
        svc = PermissionsService()
        # Act
        svc.decide(OPERATOR_SCOPES, Permission.DOCUMENT_READ, mfa_satisfied=False)
        # Assert
        assert svc.denial_count == 0


# ---------------------------------------------------------------------------
# Тесты PermissionsService.check()
# ---------------------------------------------------------------------------


class TestPermissionsServiceCheck:
    """Тесты для метода check()."""

    def test_check_returns_true_when_granted(self) -> None:
        """check() возвращает True при успешном доступе."""
        # Arrange
        svc = PermissionsService()
        # Act
        result = svc.check(OPERATOR_SCOPES, Permission.DOCUMENT_READ)
        # Assert
        assert result is True

    def test_check_returns_false_when_denied(self) -> None:
        """check() возвращает False при отказе в доступе."""
        # Arrange
        svc = PermissionsService()
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act
        result = svc.check(scopes, Permission.DOCUMENT_READ)
        # Assert
        assert result is False

    def test_check_returns_false_for_mfa_without_mfa(self) -> None:
        """check() возвращает False для MFA-операции без MFA."""
        # Arrange
        svc = PermissionsService()
        # Act
        result = svc.check(OPERATOR_SCOPES, Permission.DEVICE_PROVISION, mfa_satisfied=False)
        # Assert
        assert result is False


# ---------------------------------------------------------------------------
# Тесты PermissionsService.assert_access()
# ---------------------------------------------------------------------------


class TestPermissionsServiceAssertAccess:
    """Тесты для метода assert_access()."""

    def test_assert_access_passes_on_valid(self) -> None:
        """assert_access() не выбрасывает исключение при допустимом доступе."""
        # Arrange
        svc = PermissionsService()
        # Act / Assert — не должно бросать
        svc.assert_access(OPERATOR_SCOPES, Permission.DOCUMENT_READ)

    def test_assert_access_raises_scope_error(self) -> None:
        """assert_access() выбрасывает ScopeError при отсутствии scope."""
        # Arrange
        svc = PermissionsService()
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act / Assert
        with pytest.raises(ScopeError):
            svc.assert_access(scopes, Permission.DOCUMENT_READ)

    def test_assert_access_raises_mfa_required_error(self) -> None:
        """assert_access() выбрасывает MFARequiredError без MFA для MFA-операции."""
        # Arrange
        svc = PermissionsService()
        # Act / Assert
        with pytest.raises(MFARequiredError):
            svc.assert_access(OPERATOR_SCOPES, Permission.DEVICE_PROVISION, mfa_satisfied=False)

    def test_assert_access_passes_mfa_satisfied(self) -> None:
        """assert_access() проходит для MFA-операции с mfa_satisfied=True."""
        # Arrange
        svc = PermissionsService()
        # Act / Assert — не должно бросать
        svc.assert_access(OPERATOR_SCOPES, Permission.DEVICE_PROVISION, mfa_satisfied=True)


# ---------------------------------------------------------------------------
# Тесты PermissionsService.mfa_required_for()
# ---------------------------------------------------------------------------


class TestPermissionsServiceMfaRequiredFor:
    """Тесты для метода mfa_required_for()."""

    def test_true_for_mfa_permission(self) -> None:
        """mfa_required_for() возвращает True для MFA-gated операции."""
        # Arrange
        svc = PermissionsService()
        # Act / Assert
        assert svc.mfa_required_for(Permission.KEY_EXPORT) is True

    def test_false_for_non_mfa_permission(self) -> None:
        """mfa_required_for() возвращает False для обычной операции."""
        # Arrange
        svc = PermissionsService()
        # Act / Assert
        assert svc.mfa_required_for(Permission.DOCUMENT_READ) is False


# ---------------------------------------------------------------------------
# Тесты PermissionsService.effective_permissions()
# ---------------------------------------------------------------------------


class TestPermissionsServiceEffectivePermissions:
    """Тесты для метода effective_permissions()."""

    def test_non_empty_for_operator_scopes(self) -> None:
        """effective_permissions() непуст для OPERATOR_SCOPES."""
        # Arrange
        svc = PermissionsService()
        # Act
        result = svc.effective_permissions(OPERATOR_SCOPES)
        # Assert
        assert len(result) > 0

    def test_full_scope_returns_all(self) -> None:
        """effective_permissions() возвращает все разрешения для scope='full'."""
        # Arrange
        svc = PermissionsService()
        # Act
        result = svc.effective_permissions(OPERATOR_SCOPES)
        # Assert
        assert result == frozenset(Permission)

    def test_empty_scopes_returns_empty(self) -> None:
        """effective_permissions() возвращает пустое множество для пустых scope."""
        # Arrange
        svc = PermissionsService()
        # Act
        result = svc.effective_permissions(frozenset())
        # Assert
        assert result == frozenset()


# ---------------------------------------------------------------------------
# Тесты PermissionsService.mfa_gated_permissions()
# ---------------------------------------------------------------------------


class TestPermissionsServiceMfaGatedPermissions:
    """Тесты для метода mfa_gated_permissions()."""

    def test_subset_of_effective(self) -> None:
        """mfa_gated_permissions() является подмножеством effective_permissions()."""
        # Arrange
        svc = PermissionsService()
        # Act
        effective = svc.effective_permissions(OPERATOR_SCOPES)
        mfa_gated = svc.mfa_gated_permissions(OPERATOR_SCOPES)
        # Assert
        assert mfa_gated <= effective

    def test_all_require_mfa(self) -> None:
        """Все разрешения из mfa_gated_permissions() требуют MFA."""
        # Arrange
        svc = PermissionsService()
        # Act
        mfa_gated = svc.mfa_gated_permissions(OPERATOR_SCOPES)
        # Assert
        for perm in mfa_gated:
            assert perm in MFA_REQUIRED_PERMISSIONS

    def test_equals_mfa_required_for_full_scope(self) -> None:
        """mfa_gated_permissions() для 'full' scope равен MFA_REQUIRED_PERMISSIONS."""
        # Arrange
        svc = PermissionsService()
        # Act
        result = svc.mfa_gated_permissions(OPERATOR_SCOPES)
        # Assert
        assert result == MFA_REQUIRED_PERMISSIONS
