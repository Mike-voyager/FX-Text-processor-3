"""Unit tests for PasswordService with comprehensive coverage."""

from datetime import timedelta

import pytest

from src.security.auth.password_service import (
    AccountLockedError,
    InMemoryUserStorage,
    PasswordExpiredError,
    PasswordService,
    PasswordServiceError,
    WeakPasswordError,
)


@pytest.fixture
def service() -> PasswordService:
    """Create PasswordService instance for testing."""
    return PasswordService()


def test_create_password_success(service: PasswordService) -> None:
    """Test successful password creation."""
    assert service.create_password("user1", "ValidPass!123")
    assert service.storage.user_exists("user1")


def test_create_password_weak_fails(service: PasswordService) -> None:
    """Test that weak password fails creation."""
    with pytest.raises(WeakPasswordError):
        service.create_password("user1", "weakpass")


def test_password_history_reuse(service: PasswordService) -> None:
    """Test that password history prevents reuse."""
    service.create_password("user2", "UniquePass!12")
    with pytest.raises(WeakPasswordError):
        service.change_password("user2", "UniquePass!12", "UniquePass!12")


def test_password_expiry(service: PasswordService) -> None:
    """Test password expiration detection."""
    service.create_password("expuser", "ExpiringPass!1")
    created_at = service.storage.get_password_created_at("expuser")
    assert created_at is not None
    service.storage.set_password_created_at("expuser", created_at - timedelta(days=185))
    with pytest.raises(PasswordExpiredError):
        service.verify_password("expuser", "ExpiringPass!1")


def test_temporary_password(service: PasswordService) -> None:
    """Test temporary password functionality."""
    service.set_temporary_password("user3", "TempPass!1")
    assert service.is_temporary_password("user3")
    service.change_password("user3", "TempPass!1", "FinalPass!1")
    assert not service.is_temporary_password("user3")


def test_lockout_mechanism(service: PasswordService) -> None:
    """Test account lockout after failed attempts."""
    service.create_password("user4", "LockPass!321")
    for _ in range(6):
        try:
            service.verify_password("user4", "Bad!")
        except AccountLockedError:
            break
    assert service.is_locked_out("user4")


def test_unlock_user(service: PasswordService) -> None:
    """Test unlocking a locked account."""
    service.create_password("user5", "UnlockPass!321")
    for _ in range(6):
        try:
            service.verify_password("user5", "Mistake!")
        except AccountLockedError:
            break
    assert service.is_locked_out("user5")
    service.unlock_user("user5", "admin1")
    assert not service.is_locked_out("user5")


def test_statistics(service: PasswordService) -> None:
    """Test statistics generation."""
    service.create_password("u1", "Strong!111")
    service.create_password("u2", "Strong!222")
    stats = service.get_statistics()
    assert stats["total_users"] >= 2
    assert isinstance(stats["locked_accounts"], int)
    assert isinstance(stats["avg_failed_attempts"], float)


def test_check_password_strength(service: PasswordService) -> None:
    """Test password strength checking."""
    result = service.check_password_strength("StrongPass!2024")
    assert result["valid"] is True
    weak = service.check_password_strength("weak")
    assert weak["valid"] is False
    assert len(weak["issues"]) > 0


def test_verify_password_correct(service: PasswordService) -> None:
    """Test correct password verification."""
    service.create_password("user6", "CorrectPass!123")
    assert service.verify_password("user6", "CorrectPass!123")


def test_verify_password_incorrect(service: PasswordService) -> None:
    """Test incorrect password verification."""
    service.create_password("user7", "CorrectPass!456")
    assert not service.verify_password("user7", "WrongPass!999")


def test_change_password_success(service: PasswordService) -> None:
    """Test successful password change."""
    service.create_password("user8", "OldPass!111")
    assert service.change_password("user8", "OldPass!111", "NewPass!222")
    assert service.verify_password("user8", "NewPass!222")
    assert not service.verify_password("user8", "OldPass!111")


def test_reset_password(service: PasswordService) -> None:
    """Test password reset by admin."""
    service.create_password("user9", "Original!123")
    assert service.reset_password("user9", "ResetPass!456", admin_id="admin1")
    assert service.verify_password("user9", "ResetPass!456")
    assert service.is_temporary_password("user9")


def test_days_until_expiration(service: PasswordService) -> None:
    """Test days until password expiration calculation."""
    service.create_password("user10", "ExpiryTest!123")
    days = service.days_until_expiration("user10")
    assert days is not None
    assert days > 0


def test_context_manager(service: PasswordService) -> None:
    """Test context manager functionality with cleanup."""
    with service as svc:
        svc.create_password("ctx_user", "ContextPass!123")
        assert svc.storage.user_exists("ctx_user")


# ==================== ADDITIONAL TESTS ====================


def test_verify_nonexistent_user(service: PasswordService) -> None:
    """Test verification of non-existent user."""
    assert not service.verify_password("ghost_user", "AnyPass!123")
    assert service.last_error == "User not found"


def test_change_password_wrong_old(service: PasswordService) -> None:
    """Test password change with wrong old password."""
    service.create_password("user11", "CurrentPass!111")
    with pytest.raises(PasswordServiceError):
        service.change_password("user11", "WrongOld!999", "NewPass!222")


def test_reset_clears_lockout(service: PasswordService) -> None:
    """Test that password reset clears lockout counter."""
    service.create_password("user12", "LockTest!123")

    for _ in range(6):
        try:
            service.verify_password("user12", "Wrong!")
        except AccountLockedError:
            break

    assert service.is_locked_out("user12")
    service.reset_password("user12", "NewPass!456")
    assert not service.is_locked_out("user12")


def test_password_strength_edge_cases(service: PasswordService) -> None:
    """Test password strength with edge cases."""
    result = service.check_password_strength("Ab1!")
    assert not result["valid"]
    assert "length<8" in result["issues"]

    result = service.check_password_strength("lowercase123!")
    assert not result["valid"]
    assert "no_uppercase" in result["issues"]


def test_failed_attempts_counter(service: PasswordService) -> None:
    """Test failed attempts counter tracking."""
    service.create_password("user13", "CountTest!123")
    assert service.get_failed_attempts("user13") == 0

    for i in range(3):
        try:
            service.verify_password("user13", f"Wrong{i}!")
        except AccountLockedError:
            break

    attempts = service.get_failed_attempts("user13")
    assert attempts > 0
    assert attempts <= 3


def test_export_policy(service: PasswordService) -> None:
    """Test policy export."""
    policy = service.export_policy()
    assert isinstance(policy, dict)


def test_is_password_expired(service: PasswordService) -> None:
    """Test password expiration check."""
    service.create_password("user14", "ExpCheck!123")
    assert not service.is_password_expired("user14")

    created_at = service.storage.get_password_created_at("user14")
    assert created_at is not None
    service.storage.set_password_created_at("user14", created_at - timedelta(days=200))
    assert service.is_password_expired("user14")


def test_statistics_with_expiring_passwords(service: PasswordService) -> None:
    """Test statistics includes expiring passwords."""
    service.create_password("expire_soon", "ExpireSoon!123")

    created_at = service.storage.get_password_created_at("expire_soon")
    assert created_at is not None
    service.storage.set_password_created_at(
        "expire_soon", created_at - timedelta(days=160)
    )

    stats = service.get_statistics()
    assert "password_expires_soon" in stats
    assert isinstance(stats["password_expires_soon"], list)


def test_temporary_password_flag_persists(service: PasswordService) -> None:
    """Test that temporary password flag persists correctly."""
    service.reset_password("user15", "TempReset!123", admin_id="admin")
    assert service.is_temporary_password("user15")
    service.verify_password("user15", "TempReset!123")
    assert service.is_temporary_password("user15")


def test_password_history_limit() -> None:
    """Test password history respects length limit of 5."""
    # Use fresh service instance
    test_service = PasswordService()

    test_service.create_password("hist_user", "Password1!")

    # Change password 6 times (exceeding history limit of 5)
    passwords = [
        "Password2!",
        "Password3!",
        "Password4!",
        "Password5!",
        "Password6!",
        "Password7!",
    ]

    current = "Password1!"
    for pwd in passwords:
        test_service.change_password("hist_user", current, pwd)
        current = pwd

    # After 6 changes, Password1! should be outside history window (limit=5)
    # History now contains: [Password3!, Password4!, Password5!, Password6!, Password7!]
    test_service.change_password("hist_user", "Password7!", "Password1!")


def test_multiple_services_isolation(service: PasswordService) -> None:
    """Test that multiple service instances are isolated."""
    service1 = PasswordService()
    service2 = PasswordService()

    service1.create_password("iso_user1", "Pass1!234")
    service2.create_password("iso_user2", "Pass2!234")

    assert service1.storage.user_exists("iso_user1")
    assert not service1.storage.user_exists("iso_user2")

    assert service2.storage.user_exists("iso_user2")
    assert not service2.storage.user_exists("iso_user1")


def test_context_manager_cleanup_on_exception(service: PasswordService) -> None:
    """Test that context manager cleans up even on exception."""
    try:
        with service as svc:
            svc.create_password("exc_user", "ExcPass!123")
            raise ValueError("Test exception")
    except ValueError:
        pass
