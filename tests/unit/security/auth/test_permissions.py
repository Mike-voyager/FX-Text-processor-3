# -*- coding: utf-8 -*-
"""
Тесты для модуля src.security.auth.permissions.

Покрывает: Permission, Scope, MFA_REQUIRED_PERMISSIONS, OPERATOR_PERMISSIONS,
OPERATOR_SCOPES, SCOPE_PERMISSIONS, OperatorRole, OPERATOR_ROLE,
PermissionPolicy, PERMISSION_POLICIES, requires_mfa, scopes_to_permissions,
PermissionChecker, исключения MFARequiredError и ScopeError.
"""

from __future__ import annotations

from typing import FrozenSet

import pytest

from src.security.auth.permissions import (
    MFA_REQUIRED_PERMISSIONS,
    OPERATOR_PERMISSIONS,
    OPERATOR_ROLE,
    OPERATOR_SCOPES,
    PERMISSION_POLICIES,
    SCOPE_PERMISSIONS,
    MFARequiredError,
    OperatorRole,
    Permission,
    PermissionChecker,
    PermissionPolicy,
    Scope,
    ScopeError,
    requires_mfa,
    scopes_to_permissions,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Permission enum
# ---------------------------------------------------------------------------


class TestPermissionEnum:
    """Тесты для перечисления Permission."""

    def test_permission_count(self) -> None:
        """Перечисление Permission содержит ровно 27 значений."""
        # Arrange / Act
        members = list(Permission)
        # Assert
        assert len(members) == 27

    def test_permission_values_format(self) -> None:
        """Каждое значение Permission имеет формат 'resource:action'."""
        # Arrange / Act / Assert
        for perm in Permission:
            assert ":" in perm.value, f"Неверный формат у {perm.name}: '{perm.value}'"

    def test_all_expected_document_permissions(self) -> None:
        """Все 6 разрешений группы document:* существуют."""
        # Arrange
        expected = {
            "document:read",
            "document:write",
            "document:delete",
            "document:sign",
            "document:encrypt",
            "document:export",
        }
        # Act
        values = {p.value for p in Permission if p.value.startswith("document:")}
        # Assert
        assert values == expected

    def test_all_expected_blank_permissions(self) -> None:
        """Все 5 разрешений группы blank:* существуют."""
        # Arrange
        expected = {
            "blank:read",
            "blank:issue",
            "blank:sign",
            "blank:void",
            "blank:verify",
        }
        # Act
        values = {p.value for p in Permission if p.value.startswith("blank:")}
        # Assert
        assert values == expected

    def test_all_expected_key_permissions(self) -> None:
        """Все 3 разрешения группы key:* существуют."""
        # Arrange
        expected = {"key:export", "key:import_device", "key:rotate"}
        # Act
        values = {p.value for p in Permission if p.value.startswith("key:")}
        # Assert
        assert values == expected

    def test_all_expected_device_permissions(self) -> None:
        """Все 3 разрешения группы device:* существуют."""
        # Arrange
        expected = {"device:list", "device:provision", "device:revoke"}
        # Act
        values = {p.value for p in Permission if p.value.startswith("device:")}
        # Assert
        assert values == expected

    def test_permission_is_str_enum(self) -> None:
        """Permission является одновременно str и Enum."""
        # Arrange / Act / Assert
        assert isinstance(Permission.DOCUMENT_READ, str)
        assert Permission.DOCUMENT_READ == "document:read"


# ---------------------------------------------------------------------------
# Scope enum
# ---------------------------------------------------------------------------


class TestScopeEnum:
    """Тесты для перечисления Scope."""

    def test_scope_count(self) -> None:
        """Перечисление Scope содержит ровно 10 значений (включая FULL)."""
        # Arrange / Act
        members = list(Scope)
        # Assert
        assert len(members) == 10

    def test_scope_values(self) -> None:
        """Все ожидаемые scope присутствуют."""
        # Arrange
        expected_values = {
            "documents",
            "blanks",
            "keys",
            "devices",
            "security",
            "audit",
            "backup",
            "config",
            "sessions",
            "full",
        }
        # Act
        actual = {s.value for s in Scope}
        # Assert
        assert actual == expected_values

    def test_full_scope_exists(self) -> None:
        """Scope.FULL с значением 'full' существует."""
        # Arrange / Act / Assert
        assert Scope.FULL.value == "full"


# ---------------------------------------------------------------------------
# MFA_REQUIRED_PERMISSIONS
# ---------------------------------------------------------------------------


class TestMfaRequiredPermissions:
    """Тесты для константы MFA_REQUIRED_PERMISSIONS."""

    def test_exactly_six_entries(self) -> None:
        """MFA_REQUIRED_PERMISSIONS содержит ровно 6 разрешений."""
        # Arrange / Act / Assert
        assert len(MFA_REQUIRED_PERMISSIONS) == 6

    def test_contains_key_export(self) -> None:
        """KEY_EXPORT требует MFA."""
        assert Permission.KEY_EXPORT in MFA_REQUIRED_PERMISSIONS

    def test_contains_key_import_device(self) -> None:
        """KEY_IMPORT_DEVICE требует MFA."""
        assert Permission.KEY_IMPORT_DEVICE in MFA_REQUIRED_PERMISSIONS

    def test_contains_device_provision(self) -> None:
        """DEVICE_PROVISION требует MFA."""
        assert Permission.DEVICE_PROVISION in MFA_REQUIRED_PERMISSIONS

    def test_contains_device_revoke(self) -> None:
        """DEVICE_REVOKE требует MFA."""
        assert Permission.DEVICE_REVOKE in MFA_REQUIRED_PERMISSIONS

    def test_contains_security_downgrade(self) -> None:
        """SECURITY_DOWNGRADE требует MFA."""
        assert Permission.SECURITY_DOWNGRADE in MFA_REQUIRED_PERMISSIONS

    def test_contains_backup_restore(self) -> None:
        """BACKUP_RESTORE требует MFA."""
        assert Permission.BACKUP_RESTORE in MFA_REQUIRED_PERMISSIONS

    def test_is_frozenset(self) -> None:
        """MFA_REQUIRED_PERMISSIONS является frozenset."""
        assert isinstance(MFA_REQUIRED_PERMISSIONS, frozenset)


# ---------------------------------------------------------------------------
# OPERATOR_PERMISSIONS и OPERATOR_SCOPES
# ---------------------------------------------------------------------------


class TestOperatorConstants:
    """Тесты для констант оператора."""

    def test_operator_permissions_is_frozenset(self) -> None:
        """OPERATOR_PERMISSIONS является frozenset."""
        assert isinstance(OPERATOR_PERMISSIONS, frozenset)

    def test_operator_permissions_non_empty(self) -> None:
        """OPERATOR_PERMISSIONS не пуст."""
        assert len(OPERATOR_PERMISSIONS) > 0

    def test_operator_scopes_equals_full(self) -> None:
        """OPERATOR_SCOPES равен frozenset({'full'})."""
        # Arrange
        expected: FrozenSet[str] = frozenset({"full"})
        # Assert
        assert OPERATOR_SCOPES == expected

    def test_operator_scopes_is_frozenset(self) -> None:
        """OPERATOR_SCOPES является frozenset."""
        assert isinstance(OPERATOR_SCOPES, frozenset)


# ---------------------------------------------------------------------------
# SCOPE_PERMISSIONS
# ---------------------------------------------------------------------------


class TestScopePermissions:
    """Тесты для словаря SCOPE_PERMISSIONS."""

    def test_full_scope_contains_all_permissions(self) -> None:
        """Scope.FULL содержит все разрешения."""
        # Arrange
        all_perms = frozenset(Permission)
        # Act
        full_perms = SCOPE_PERMISSIONS[Scope.FULL]
        # Assert
        assert all_perms == full_perms

    def test_documents_scope_permissions(self) -> None:
        """Scope.DOCUMENTS содержит все document:* разрешения."""
        # Arrange
        expected = frozenset(p for p in Permission if p.value.startswith("document:"))
        # Act
        actual = SCOPE_PERMISSIONS[Scope.DOCUMENTS]
        # Assert
        assert actual == expected

    def test_blanks_scope_permissions(self) -> None:
        """Scope.BLANKS содержит все blank:* разрешения."""
        # Arrange
        expected = frozenset(p for p in Permission if p.value.startswith("blank:"))
        # Act
        actual = SCOPE_PERMISSIONS[Scope.BLANKS]
        # Assert
        assert actual == expected

    def test_keys_scope_permissions(self) -> None:
        """Scope.KEYS содержит все key:* разрешения."""
        # Arrange
        expected = frozenset(p for p in Permission if p.value.startswith("key:"))
        # Act
        actual = SCOPE_PERMISSIONS[Scope.KEYS]
        # Assert
        assert actual == expected

    def test_devices_scope_permissions(self) -> None:
        """Scope.DEVICES содержит все device:* разрешения."""
        # Arrange
        expected = frozenset(p for p in Permission if p.value.startswith("device:"))
        # Act
        actual = SCOPE_PERMISSIONS[Scope.DEVICES]
        # Assert
        assert actual == expected

    def test_non_full_scopes_are_subset_of_full(self) -> None:
        """Каждый не-FULL scope является подмножеством Scope.FULL."""
        # Arrange
        full = SCOPE_PERMISSIONS[Scope.FULL]
        # Act / Assert
        for scope, perms in SCOPE_PERMISSIONS.items():
            if scope != Scope.FULL:
                assert perms <= full, f"Scope {scope} не является подмножеством FULL"

    def test_all_scopes_covered_in_mapping(self) -> None:
        """Все значения Scope присутствуют в SCOPE_PERMISSIONS."""
        # Arrange / Act / Assert
        for scope in Scope:
            assert scope in SCOPE_PERMISSIONS, f"Scope {scope} отсутствует в SCOPE_PERMISSIONS"


# ---------------------------------------------------------------------------
# OperatorRole
# ---------------------------------------------------------------------------


class TestOperatorRole:
    """Тесты для frozen dataclass OperatorRole."""

    def test_is_frozen(self) -> None:
        """OperatorRole является frozen dataclass."""
        # Arrange
        role = OperatorRole(
            name="test",
            display_name="Test",
            permissions=frozenset({Permission.DOCUMENT_READ}),
            scopes=frozenset({"documents"}),
        )
        # Act / Assert
        with pytest.raises(Exception):
            role.name = "other"  # type: ignore[misc]

    def test_has_permission_true(self) -> None:
        """has_permission() возвращает True, если разрешение в наборе."""
        # Arrange
        role = OperatorRole(
            name="r",
            display_name="R",
            permissions=frozenset({Permission.DOCUMENT_READ, Permission.BLANK_SIGN}),
            scopes=frozenset({"documents", "blanks"}),
        )
        # Act / Assert
        assert role.has_permission(Permission.DOCUMENT_READ) is True

    def test_has_permission_false(self) -> None:
        """has_permission() возвращает False, если разрешение отсутствует."""
        # Arrange
        role = OperatorRole(
            name="r",
            display_name="R",
            permissions=frozenset({Permission.DOCUMENT_READ}),
            scopes=frozenset({"documents"}),
        )
        # Act / Assert
        assert role.has_permission(Permission.KEY_EXPORT) is False

    def test_can_access_scope_true(self) -> None:
        """can_access_scope() возвращает True для присутствующего scope."""
        # Arrange
        role = OperatorRole(
            name="r",
            display_name="R",
            permissions=frozenset(),
            scopes=frozenset({"documents", "blanks"}),
        )
        # Act / Assert
        assert role.can_access_scope("documents") is True

    def test_can_access_scope_false(self) -> None:
        """can_access_scope() возвращает False для отсутствующего scope."""
        # Arrange
        role = OperatorRole(
            name="r",
            display_name="R",
            permissions=frozenset(),
            scopes=frozenset({"documents"}),
        )
        # Act / Assert
        assert role.can_access_scope("keys") is False


# ---------------------------------------------------------------------------
# OPERATOR_ROLE
# ---------------------------------------------------------------------------


class TestOperatorRoleConstant:
    """Тесты для предопределённой константы OPERATOR_ROLE."""

    def test_name_is_operator(self) -> None:
        """OPERATOR_ROLE.name == 'operator'."""
        assert OPERATOR_ROLE.name == "operator"

    def test_has_all_permissions(self) -> None:
        """OPERATOR_ROLE содержит все разрешения."""
        # Arrange
        all_perms = frozenset(Permission)
        # Assert
        assert OPERATOR_ROLE.permissions == all_perms

    def test_scopes_equals_full(self) -> None:
        """OPERATOR_ROLE.scopes == frozenset({'full'})."""
        assert OPERATOR_ROLE.scopes == frozenset({"full"})

    def test_has_every_permission(self) -> None:
        """OPERATOR_ROLE.has_permission() True для каждого Permission."""
        # Arrange / Act / Assert
        for perm in Permission:
            assert OPERATOR_ROLE.has_permission(perm) is True


# ---------------------------------------------------------------------------
# PermissionPolicy
# ---------------------------------------------------------------------------


class TestPermissionPolicy:
    """Тесты для frozen dataclass PermissionPolicy."""

    def test_is_frozen(self) -> None:
        """PermissionPolicy является frozen dataclass."""
        # Arrange
        policy = PermissionPolicy(
            permission=Permission.DOCUMENT_READ,
            mfa_required=False,
        )
        # Act / Assert
        with pytest.raises(Exception):
            policy.mfa_required = True  # type: ignore[misc]

    def test_for_permission_mfa_gated(self) -> None:
        """for_permission() устанавливает mfa_required=True для MFA-gated операций."""
        # Arrange / Act
        policy = PermissionPolicy.for_permission(Permission.KEY_EXPORT)
        # Assert
        assert policy.mfa_required is True
        assert policy.permission is Permission.KEY_EXPORT

    def test_for_permission_non_mfa(self) -> None:
        """for_permission() устанавливает mfa_required=False для обычных операций."""
        # Arrange / Act
        policy = PermissionPolicy.for_permission(Permission.DOCUMENT_READ)
        # Assert
        assert policy.mfa_required is False

    def test_for_permission_all_mfa_gated(self) -> None:
        """for_permission() правильно определяет MFA для всех MFA-gated разрешений."""
        # Arrange / Act / Assert
        for perm in MFA_REQUIRED_PERMISSIONS:
            policy = PermissionPolicy.for_permission(perm)
            assert policy.mfa_required is True, f"Ожидается mfa_required=True для {perm}"

    def test_description_equals_value(self) -> None:
        """for_permission() устанавливает description равным permission.value."""
        # Arrange / Act
        policy = PermissionPolicy.for_permission(Permission.BLANK_SIGN)
        # Assert
        assert policy.description == Permission.BLANK_SIGN.value


# ---------------------------------------------------------------------------
# PERMISSION_POLICIES
# ---------------------------------------------------------------------------


class TestPermissionPolicies:
    """Тесты для словаря PERMISSION_POLICIES."""

    def test_covers_all_permissions(self) -> None:
        """PERMISSION_POLICIES содержит запись для каждого Permission."""
        # Arrange / Act / Assert
        for perm in Permission:
            assert perm in PERMISSION_POLICIES, f"{perm} отсутствует в PERMISSION_POLICIES"

    def test_policies_are_permission_policy_instances(self) -> None:
        """Каждое значение в PERMISSION_POLICIES является PermissionPolicy."""
        for policy in PERMISSION_POLICIES.values():
            assert isinstance(policy, PermissionPolicy)

    def test_mfa_gated_policies_have_mfa_required(self) -> None:
        """MFA-gated разрешения имеют mfa_required=True в политике."""
        for perm in MFA_REQUIRED_PERMISSIONS:
            assert PERMISSION_POLICIES[perm].mfa_required is True


# ---------------------------------------------------------------------------
# requires_mfa()
# ---------------------------------------------------------------------------


class TestRequiresMfa:
    """Тесты для функции requires_mfa."""

    @pytest.mark.parametrize(
        "permission",
        [
            Permission.KEY_EXPORT,
            Permission.KEY_IMPORT_DEVICE,
            Permission.DEVICE_PROVISION,
            Permission.DEVICE_REVOKE,
            Permission.SECURITY_DOWNGRADE,
            Permission.BACKUP_RESTORE,
        ],
    )
    def test_returns_true_for_mfa_gated(self, permission: Permission) -> None:
        """requires_mfa() возвращает True для всех MFA-gated операций."""
        assert requires_mfa(permission) is True

    @pytest.mark.parametrize(
        "permission",
        [
            Permission.DOCUMENT_READ,
            Permission.DOCUMENT_WRITE,
            Permission.BLANK_SIGN,
            Permission.DEVICE_LIST,
            Permission.AUDIT_READ,
            Permission.CONFIG_READ,
            Permission.SESSION_LIST,
        ],
    )
    def test_returns_false_for_non_mfa(self, permission: Permission) -> None:
        """requires_mfa() возвращает False для обычных операций."""
        assert requires_mfa(permission) is False


# ---------------------------------------------------------------------------
# scopes_to_permissions()
# ---------------------------------------------------------------------------


class TestScopesToPermissions:
    """Тесты для функции scopes_to_permissions."""

    def test_full_scope_returns_all(self) -> None:
        """Scope 'full' возвращает все разрешения."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"full"})
        # Act
        result = scopes_to_permissions(scopes)
        # Assert
        assert result == frozenset(Permission)

    def test_empty_scopes_returns_empty(self) -> None:
        """Пустой набор scope возвращает пустой набор разрешений."""
        # Arrange
        scopes: FrozenSet[str] = frozenset()
        # Act
        result = scopes_to_permissions(scopes)
        # Assert
        assert result == frozenset()

    def test_documents_scope_returns_correct_permissions(self) -> None:
        """Scope 'documents' возвращает только document:* разрешения."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"documents"})
        # Act
        result = scopes_to_permissions(scopes)
        # Assert
        assert result == SCOPE_PERMISSIONS[Scope.DOCUMENTS]

    def test_combined_scopes(self) -> None:
        """Комбинация scope возвращает объединение разрешений."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"documents", "blanks"})
        expected = SCOPE_PERMISSIONS[Scope.DOCUMENTS] | SCOPE_PERMISSIONS[Scope.BLANKS]
        # Act
        result = scopes_to_permissions(scopes)
        # Assert
        assert result == expected

    def test_unknown_scope_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Неизвестный scope логируется как warning и игнорируется."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"unknown_scope_xyz"})
        # Act
        with caplog.at_level("WARNING", logger="security.auth.permissions"):
            result = scopes_to_permissions(scopes)
        # Assert
        assert result == frozenset()
        assert "unknown_scope_xyz" in caplog.text

    def test_unknown_scope_combined_with_known(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Неизвестный scope игнорируется, известный обрабатывается корректно."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"documents", "nonexistent"})
        # Act
        with caplog.at_level("WARNING", logger="security.auth.permissions"):
            result = scopes_to_permissions(scopes)
        # Assert
        assert result == SCOPE_PERMISSIONS[Scope.DOCUMENTS]

    def test_keys_scope(self) -> None:
        """Scope 'keys' возвращает key:* разрешения."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"keys"})
        # Act
        result = scopes_to_permissions(scopes)
        # Assert
        assert Permission.KEY_EXPORT in result
        assert Permission.KEY_ROTATE in result


# ---------------------------------------------------------------------------
# PermissionChecker
# ---------------------------------------------------------------------------


class TestPermissionChecker:
    """Тесты для класса PermissionChecker."""

    def test_has_permission_true_non_strict(self) -> None:
        """has_permission() возвращает True для допустимого scope (strict=False)."""
        # Arrange
        checker = PermissionChecker(strict=False)
        scopes: FrozenSet[str] = frozenset({"full"})
        # Act
        result = checker.has_permission(scopes, Permission.DOCUMENT_READ)
        # Assert
        assert result is True

    def test_has_permission_false_non_strict(self) -> None:
        """has_permission() возвращает False без исключения (strict=False)."""
        # Arrange
        checker = PermissionChecker(strict=False)
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act
        result = checker.has_permission(scopes, Permission.DOCUMENT_READ)
        # Assert
        assert result is False

    def test_has_permission_raises_on_strict(self) -> None:
        """has_permission() выбрасывает ScopeError при strict=True."""
        # Arrange
        checker = PermissionChecker(strict=True)
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act / Assert
        with pytest.raises(ScopeError):
            checker.has_permission(scopes, Permission.DOCUMENT_READ)

    def test_is_mfa_required_delegates_to_requires_mfa(self) -> None:
        """is_mfa_required() делегирует к requires_mfa()."""
        # Arrange
        checker = PermissionChecker()
        # Act / Assert
        assert checker.is_mfa_required(Permission.DEVICE_PROVISION) is True
        assert checker.is_mfa_required(Permission.DOCUMENT_READ) is False

    def test_assert_permission_raises_scope_error_on_missing_scope(self) -> None:
        """assert_permission() выбрасывает ScopeError при отсутствии разрешения в scope."""
        # Arrange
        checker = PermissionChecker()
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act / Assert
        with pytest.raises(ScopeError):
            checker.assert_permission(scopes, Permission.DOCUMENT_READ)

    def test_assert_permission_raises_mfa_required_error(self) -> None:
        """assert_permission() выбрасывает MFARequiredError для MFA-gated операции без MFA."""
        # Arrange
        checker = PermissionChecker()
        scopes: FrozenSet[str] = frozenset({"full"})
        # Act / Assert
        with pytest.raises(MFARequiredError):
            checker.assert_permission(
                scopes, Permission.DEVICE_PROVISION, mfa_satisfied=False
            )

    def test_assert_permission_passes_with_mfa_satisfied(self) -> None:
        """assert_permission() не выбрасывает исключение при mfa_satisfied=True."""
        # Arrange
        checker = PermissionChecker()
        scopes: FrozenSet[str] = frozenset({"full"})
        # Act / Assert — не должно бросать
        checker.assert_permission(
            scopes, Permission.DEVICE_PROVISION, mfa_satisfied=True
        )

    def test_assert_permission_passes_non_mfa_without_mfa(self) -> None:
        """assert_permission() не требует MFA для обычной операции."""
        # Arrange
        checker = PermissionChecker()
        scopes: FrozenSet[str] = frozenset({"full"})
        # Act / Assert — не должно бросать
        checker.assert_permission(
            scopes, Permission.DOCUMENT_READ, mfa_satisfied=False
        )

    def test_effective_permissions_equals_scopes_to_permissions(self) -> None:
        """effective_permissions() идентично scopes_to_permissions()."""
        # Arrange
        checker = PermissionChecker()
        scopes: FrozenSet[str] = frozenset({"documents", "blanks"})
        # Act
        expected = scopes_to_permissions(scopes)
        actual = checker.effective_permissions(scopes)
        # Assert
        assert actual == expected

    def test_mfa_required_permissions_returns_intersection(self) -> None:
        """mfa_required_permissions() возвращает пересечение с MFA_REQUIRED_PERMISSIONS."""
        # Arrange
        checker = PermissionChecker()
        scopes: FrozenSet[str] = frozenset({"full"})
        # Act
        result = checker.mfa_required_permissions(scopes)
        # Assert
        assert result == MFA_REQUIRED_PERMISSIONS

    def test_mfa_required_permissions_non_full_scope(self) -> None:
        """mfa_required_permissions() возвращает только MFA-разрешения из scope 'keys'."""
        # Arrange
        checker = PermissionChecker()
        scopes: FrozenSet[str] = frozenset({"keys"})
        # Act
        result = checker.mfa_required_permissions(scopes)
        # Assert — KEY_ROTATE не требует MFA, KEY_EXPORT и KEY_IMPORT_DEVICE — требуют
        assert Permission.KEY_EXPORT in result
        assert Permission.KEY_IMPORT_DEVICE in result
        assert Permission.KEY_ROTATE not in result


# ---------------------------------------------------------------------------
# Исключения
# ---------------------------------------------------------------------------


class TestExceptions:
    """Тесты для исключений MFARequiredError и ScopeError."""

    def test_mfa_required_error_permission_attribute(self) -> None:
        """MFARequiredError сохраняет атрибут permission."""
        # Arrange / Act
        exc = MFARequiredError(Permission.KEY_EXPORT)
        # Assert
        assert exc.permission is Permission.KEY_EXPORT

    def test_mfa_required_error_message(self) -> None:
        """MFARequiredError содержит описание операции в сообщении."""
        # Arrange / Act
        exc = MFARequiredError(Permission.DEVICE_PROVISION)
        # Assert
        assert "device:provision" in str(exc)

    def test_scope_error_required_attribute(self) -> None:
        """ScopeError сохраняет атрибут required."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act
        exc = ScopeError(Permission.DOCUMENT_READ, scopes)
        # Assert
        assert exc.required is Permission.DOCUMENT_READ

    def test_scope_error_active_scopes_attribute(self) -> None:
        """ScopeError сохраняет атрибут active_scopes."""
        # Arrange
        scopes: FrozenSet[str] = frozenset({"audit"})
        # Act
        exc = ScopeError(Permission.DOCUMENT_READ, scopes)
        # Assert
        assert exc.active_scopes == scopes

    def test_mfa_required_error_is_permission_error(self) -> None:
        """MFARequiredError является подклассом PermissionError."""
        # Arrange / Act
        exc = MFARequiredError(Permission.KEY_EXPORT)
        # Assert
        from src.security.auth.permissions import PermissionError as PermError

        assert isinstance(exc, PermError)

    def test_scope_error_is_permission_error(self) -> None:
        """ScopeError является подклассом PermissionError."""
        # Arrange
        scopes: FrozenSet[str] = frozenset()
        # Act
        exc = ScopeError(Permission.DOCUMENT_READ, scopes)
        # Assert
        from src.security.auth.permissions import PermissionError as PermError

        assert isinstance(exc, PermError)
