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
    service.storage.set_password_created_at("expire_soon", created_at - timedelta(days=160))

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


# ==================== NEW TESTS FOR MISSING COVERAGE ====================


@pytest.mark.security
def test_create_password_history_reuse_when_user_exists() -> None:
    """create_password бросает WeakPasswordError при повторном использовании пароля.

    Проверяет ветки 175-180: user_exists and not _check_password_history.
    """
    # Arrange
    svc = PasswordService()
    svc.create_password("dupuser", "FirstPass!1")

    # Act / Assert: попытка создать тот же пароль повторно
    with pytest.raises(WeakPasswordError, match="recently"):
        svc.create_password("dupuser", "FirstPass!1")
    assert svc.last_error == "Password used recently"


@pytest.mark.security
def test_create_password_hasher_policy_violation_branch() -> None:
    """create_password перехватывает PolicyViolation от hasher и бросает WeakPasswordError.

    Проверяет ветки 185-188: except PolicyViolation → WeakPasswordError.
    """
    from src.security.auth.password import PolicyViolation

    # Arrange: hasher, чья hash_password всегда бросает PolicyViolation
    class StrictHasher:
        def generate_salt(self) -> bytes:
            import secrets

            return secrets.token_bytes(16)

        def hash_password(self, password: str, salt: bytes, user_id: str) -> str:
            raise PolicyViolation("Hasher rejected it")

        def verify_password(self, *a: object, **kw: object) -> bool:
            return False

        def needs_rehash(self, *a: object, **kw: object) -> bool:
            return False

        def update_password(self, *a: object, **kw: object) -> str:
            return ""

        def reset_attempts(self, user_id: str) -> None:
            pass

        def export_audit(self, user_id: str) -> dict:  # type: ignore[type-arg]
            return {"attempts": 0}

        def export_policy(self) -> dict:  # type: ignore[type-arg]
            return {}

        def zeroize_all_secrets(self) -> None:
            pass

    from src.security.auth.password_service import InMemoryUserStorage

    svc = PasswordService(
        hasher=StrictHasher(),  # type: ignore[arg-type]
        user_storage=InMemoryUserStorage(),
    )

    # Act / Assert
    with pytest.raises(WeakPasswordError):
        svc.create_password("hashfail", "ValidPass!99")
    assert svc.last_error is not None


@pytest.mark.security
def test_verify_password_no_stored_hash() -> None:
    """verify_password возвращает False если для пользователя нет хеша.

    Проверяет ветку 226-229: stored_hash is None → last_error = 'No password set'.
    """
    # Arrange: зарегистрировать пользователя без пароля
    from src.security.auth.password_service import InMemoryUserStorage

    storage = InMemoryUserStorage()
    # user_exists True, но hash не задан
    storage._storage["nopassuser"] = ""  # type: ignore[attr-defined]

    svc = PasswordService(user_storage=storage)

    # Act
    result = svc.verify_password("nopassuser", "AnyPass!1")

    # Assert
    assert result is False
    assert svc.last_error == "No password set"


@pytest.mark.security
def test_verify_password_raises_lockout_active_from_hasher() -> None:
    """verify_password поднимает AccountLockedError при LockoutActive от hasher.

    Проверяет ветку 233-235: except LockoutActive → AccountLockedError.
    """
    from src.security.auth.password import LockoutActive
    from src.security.auth.password_service import InMemoryUserStorage

    class LockingHasher:
        def generate_salt(self) -> bytes:
            import secrets

            return secrets.token_bytes(16)

        def hash_password(self, password: str, salt: bytes, user_id: str) -> str:
            return "v1:argon2id$" + "aa" * 8 + "$somehash"

        def verify_password(
            self,
            password: str,
            hashed: str,
            user_id: str = "unknown",
            track_attempts: bool = True,
        ) -> bool:
            raise LockoutActive("Locked")

        def needs_rehash(self, *a: object, **kw: object) -> bool:
            return False

        def update_password(self, *a: object, **kw: object) -> str:
            return ""

        def reset_attempts(self, user_id: str) -> None:
            pass

        def export_audit(self, user_id: str) -> dict:  # type: ignore[type-arg]
            return {"attempts": 0}

        def export_policy(self) -> dict:  # type: ignore[type-arg]
            return {}

        def zeroize_all_secrets(self) -> None:
            pass

    storage = InMemoryUserStorage()
    storage._storage["lkuser"] = "v1:argon2id$" + "aa" * 8 + "$somehash"  # type: ignore[attr-defined]

    svc = PasswordService(hasher=LockingHasher(), user_storage=storage)  # type: ignore[arg-type]

    # Act / Assert
    with pytest.raises(AccountLockedError):
        svc.verify_password("lkuser", "AnyPass!1")
    assert svc.last_error == "Account locked"


@pytest.mark.security
def test_verify_password_internal_error_returns_false() -> None:
    """verify_password возвращает False при InternalError/InvalidHashFormat.

    Проверяет ветку 236-238: except (InvalidHashFormat, InternalError) → return False.
    """
    from src.security.auth.password import InternalError
    from src.security.auth.password_service import InMemoryUserStorage

    class ErrorHasher:
        def generate_salt(self) -> bytes:
            import secrets

            return secrets.token_bytes(16)

        def hash_password(self, password: str, salt: bytes, user_id: str) -> str:
            return "v1:argon2id$" + "bb" * 8 + "$hash"

        def verify_password(
            self,
            password: str,
            hashed: str,
            user_id: str = "unknown",
            track_attempts: bool = True,
        ) -> bool:
            raise InternalError("KDF crashed")

        def needs_rehash(self, *a: object, **kw: object) -> bool:
            return False

        def update_password(self, *a: object, **kw: object) -> str:
            return ""

        def reset_attempts(self, user_id: str) -> None:
            pass

        def export_audit(self, user_id: str) -> dict:  # type: ignore[type-arg]
            return {"attempts": 0}

        def export_policy(self) -> dict:  # type: ignore[type-arg]
            return {}

        def zeroize_all_secrets(self) -> None:
            pass

    storage = InMemoryUserStorage()
    storage._storage["erruser"] = "v1:argon2id$" + "bb" * 8 + "$hash"  # type: ignore[attr-defined]

    svc = PasswordService(hasher=ErrorHasher(), user_storage=storage)  # type: ignore[arg-type]

    # Act
    result = svc.verify_password("erruser", "ValidPass!1")

    # Assert
    assert result is False
    assert svc.last_error is not None


@pytest.mark.security
def test_verify_password_triggers_rehash_and_updates_storage() -> None:
    """verify_password автоматически перехеширует и обновляет хранилище при needs_rehash.

    Проверяет ветки 240-242: result and needs_rehash → update_password → set_password_hash.
    """
    from src.security.auth.password import PasswordHasher

    # Arrange: создать хеш с "старыми" параметрами
    old_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    pw = "RehashMe!1"
    old_hash = old_hasher.hash_password(pw, old_hasher.generate_salt(), "rehashuser")

    storage = InMemoryUserStorage()
    storage.set_password_hash("rehashuser", old_hash)

    # Новый hasher с другими параметрами — needs_rehash вернёт True
    new_hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
    svc = PasswordService(hasher=new_hasher, user_storage=storage)

    # Act
    result = svc.verify_password("rehashuser", pw)

    # Assert: пароль верен
    assert result is True
    # Хеш в хранилище изменился (был перехеширован)
    new_stored = storage.get_password_hash("rehashuser")
    assert new_stored != old_hash


@pytest.mark.security
def test_change_password_weak_new_raises() -> None:
    """change_password бросает WeakPasswordError при слабом новом пароле.

    Проверяет ветки 258-260: not is_valid_password(new_password) → WeakPasswordError.
    """
    # Arrange
    svc = PasswordService()
    svc.create_password("chgweak", "OldStrong!1")

    # Act / Assert
    with pytest.raises(WeakPasswordError):
        svc.change_password("chgweak", "OldStrong!1", "weak")
    assert svc.last_error == "Password policy violation"


@pytest.mark.security
def test_change_password_history_reuse_raises() -> None:
    """change_password бросает WeakPasswordError при повторе старого пароля из истории.

    Проверяет ветки 262-264: not _check_password_history → WeakPasswordError.
    """
    # Arrange
    svc = PasswordService()
    svc.create_password("chghist", "HistPass!1")

    # Act / Assert
    with pytest.raises(WeakPasswordError, match="recently"):
        svc.change_password("chghist", "HistPass!1", "HistPass!1")
    assert svc.last_error == "Password used recently"


@pytest.mark.security
def test_change_password_hasher_policy_violation_branch() -> None:
    """change_password перехватывает PolicyViolation от hasher и бросает WeakPasswordError.

    Проверяет ветки 269-271: except PolicyViolation → WeakPasswordError.
    """
    from src.security.auth.password import PolicyViolation
    from src.security.auth.password_service import InMemoryUserStorage

    class FailOnNewHasher:
        _calls: int = 0

        def generate_salt(self) -> bytes:
            import secrets

            return secrets.token_bytes(16)

        def hash_password(self, password: str, salt: bytes, user_id: str) -> str:
            self._calls += 1
            if self._calls == 1:
                # Первый вызов — create_password
                from src.security.auth.password import PasswordHasher as _PH

                return _PH(time_cost=1, memory_cost=8192, parallelism=1).hash_password(
                    password, salt, user_id
                )
            raise PolicyViolation("Cannot rehash")

        def verify_password(
            self,
            password: str,
            hashed: str,
            user_id: str = "unknown",
            track_attempts: bool = True,
        ) -> bool:
            # verify через реальный hasher
            from src.security.auth.password import PasswordHasher as _PH

            return _PH(time_cost=1, memory_cost=8192, parallelism=1).verify_password(
                password, hashed, user_id, track_attempts
            )

        def needs_rehash(self, *a: object, **kw: object) -> bool:
            return False

        def update_password(self, *a: object, **kw: object) -> str:
            return ""

        def reset_attempts(self, user_id: str) -> None:
            pass

        def export_audit(self, user_id: str) -> dict:  # type: ignore[type-arg]
            return {"attempts": 0}

        def export_policy(self) -> dict:  # type: ignore[type-arg]
            return {}

        def zeroize_all_secrets(self) -> None:
            pass

    storage = InMemoryUserStorage()
    fail_hasher = FailOnNewHasher()
    svc = PasswordService(hasher=fail_hasher, user_storage=storage)  # type: ignore[arg-type]
    svc.create_password("failchg", "OldPass!99")

    # Act / Assert
    with pytest.raises(WeakPasswordError):
        svc.change_password("failchg", "OldPass!99", "NewPass!99")


@pytest.mark.security
def test_reset_password_weak_raises() -> None:
    """reset_password бросает WeakPasswordError для слабого пароля.

    Проверяет ветки 283-285: not is_valid_password → WeakPasswordError.
    """
    # Arrange
    svc = PasswordService()

    # Act / Assert
    with pytest.raises(WeakPasswordError):
        svc.reset_password("anyuser", "weak")
    assert svc.last_error == "Reset password policy violation"


@pytest.mark.security
def test_reset_password_hasher_policy_violation_branch() -> None:
    """reset_password перехватывает PolicyViolation от hasher и бросает WeakPasswordError.

    Проверяет ветки 290-292: except PolicyViolation → WeakPasswordError.
    """
    from src.security.auth.password import PolicyViolation
    from src.security.auth.password_service import InMemoryUserStorage

    class AlwaysFailHasher:
        def generate_salt(self) -> bytes:
            import secrets

            return secrets.token_bytes(16)

        def hash_password(self, password: str, salt: bytes, user_id: str) -> str:
            raise PolicyViolation("Reset rejected")

        def verify_password(self, *a: object, **kw: object) -> bool:
            return False

        def needs_rehash(self, *a: object, **kw: object) -> bool:
            return False

        def update_password(self, *a: object, **kw: object) -> str:
            return ""

        def reset_attempts(self, user_id: str) -> None:
            pass

        def export_audit(self, user_id: str) -> dict:  # type: ignore[type-arg]
            return {"attempts": 0}

        def export_policy(self) -> dict:  # type: ignore[type-arg]
            return {}

        def zeroize_all_secrets(self) -> None:
            pass

    svc = PasswordService(
        hasher=AlwaysFailHasher(),  # type: ignore[arg-type]
        user_storage=InMemoryUserStorage(),
    )

    with pytest.raises(WeakPasswordError):
        svc.reset_password("anyuser", "ValidPass!99")
    assert svc.last_error is not None


@pytest.mark.security
def test_set_temporary_password_weak_raises() -> None:
    """set_temporary_password бросает WeakPasswordError для слабого пароля.

    Проверяет ветки 305-307: not is_valid_password → WeakPasswordError.
    """
    # Arrange
    svc = PasswordService()

    # Act / Assert
    with pytest.raises(WeakPasswordError):
        svc.set_temporary_password("tmpuser", "bad")
    assert svc.last_error == "Temporary password policy violation"


@pytest.mark.security
def test_set_temporary_password_hasher_policy_violation_branch() -> None:
    """set_temporary_password перехватывает PolicyViolation от hasher.

    Проверяет ветки 311-314: except PolicyViolation → WeakPasswordError.
    """
    from src.security.auth.password import PolicyViolation
    from src.security.auth.password_service import InMemoryUserStorage

    class AlwaysFailHasher:
        def generate_salt(self) -> bytes:
            import secrets

            return secrets.token_bytes(16)

        def hash_password(self, password: str, salt: bytes, user_id: str) -> str:
            raise PolicyViolation("Temp rejected")

        def verify_password(self, *a: object, **kw: object) -> bool:
            return False

        def needs_rehash(self, *a: object, **kw: object) -> bool:
            return False

        def update_password(self, *a: object, **kw: object) -> str:
            return ""

        def reset_attempts(self, user_id: str) -> None:
            pass

        def export_audit(self, user_id: str) -> dict:  # type: ignore[type-arg]
            return {"attempts": 0}

        def export_policy(self) -> dict:  # type: ignore[type-arg]
            return {}

        def zeroize_all_secrets(self) -> None:
            pass

    svc = PasswordService(
        hasher=AlwaysFailHasher(),  # type: ignore[arg-type]
        user_storage=InMemoryUserStorage(),
    )

    with pytest.raises(WeakPasswordError):
        svc.set_temporary_password("tmpuser", "ValidPass!99")
    assert svc.last_error is not None


@pytest.mark.security
def test_days_until_expiration_no_created_at_returns_none() -> None:
    """days_until_expiration возвращает None если дата создания не задана.

    Проверяет ветку created_at is None → return None (строка 383-384).
    """
    # Arrange: пользователь без даты создания пароля
    storage = InMemoryUserStorage()
    # Регистрировать хеш без вызова set_password_created_at
    storage._storage["nodateuser"] = "v1:argon2id$" + "cc" * 8 + "$hash"  # type: ignore[attr-defined]
    svc = PasswordService(user_storage=storage)

    # Act
    days = svc.days_until_expiration("nodateuser")

    # Assert
    assert days is None


@pytest.mark.security
def test_days_until_expiration_zero_when_already_expired() -> None:
    """days_until_expiration возвращает 0 когда пароль уже истёк.

    Проверяет ветку max(0, delta.days) для отрицательных delta (строка 386).
    """
    from datetime import datetime, timedelta, timezone

    # Arrange
    svc = PasswordService()
    svc.create_password("expireduser", "ExpiredPass!1")
    created_at = svc.storage.get_password_created_at("expireduser")
    assert created_at is not None
    svc.storage.set_password_created_at("expireduser", created_at - timedelta(days=200))

    # Act
    days = svc.days_until_expiration("expireduser")

    # Assert
    assert days == 0


@pytest.mark.security
def test_check_expiration_no_created_at_returns_false() -> None:
    """_check_expiration возвращает False когда дата создания не задана.

    Проверяет ветку not created_at → return False (строки 152-154).
    """
    # Arrange
    storage = InMemoryUserStorage()
    storage._storage["nodate2"] = "v1:argon2id$" + "dd" * 8 + "$hash"  # type: ignore[attr-defined]
    svc = PasswordService(user_storage=storage)

    # Act
    result = svc._check_expiration("nodate2")

    # Assert
    assert result is False


@pytest.mark.security
def test_statistics_with_zero_users() -> None:
    """get_statistics корректно работает на пустом хранилище.

    Проверяет деление на max(1, total_users) при total_users=0 (строка 395).
    """
    # Arrange
    svc = PasswordService()  # пустое хранилище

    # Act
    stats = svc.get_statistics()

    # Assert
    assert stats["total_users"] == 0
    assert stats["avg_failed_attempts"] == 0.0
    assert stats["locked_accounts"] == 0
    assert stats["password_expires_soon"] == []


@pytest.mark.security
def test_verify_password_internal_user_not_found() -> None:
    """_verify_password_internal возвращает False для несуществующего пользователя.

    Проверяет ветку not user_exists → False (строки 198-199).
    """
    # Arrange
    svc = PasswordService()

    # Act
    result = svc._verify_password_internal("ghost", "AnyPass!1")

    # Assert
    assert result is False


@pytest.mark.security
def test_verify_password_internal_no_stored_hash() -> None:
    """_verify_password_internal возвращает False если хеш пуст.

    Проверяет ветку not stored_hash → False (строки 201-203).
    """
    # Arrange
    storage = InMemoryUserStorage()
    storage._storage["emptyuser"] = ""  # type: ignore[attr-defined]
    svc = PasswordService(user_storage=storage)

    # Act
    result = svc._verify_password_internal("emptyuser", "SomePass!1")

    # Assert
    assert result is False


@pytest.mark.security
def test_verify_password_internal_exception_returns_false() -> None:
    """_verify_password_internal возвращает False при InvalidHashFormat/InternalError.

    Проверяет ветку except (InvalidHashFormat, InternalError) → False (строки 211-212).
    """
    from src.security.auth.password import InvalidHashFormat
    from src.security.auth.password_service import InMemoryUserStorage

    class ErrorVerifyHasher:
        def generate_salt(self) -> bytes:
            import secrets

            return secrets.token_bytes(16)

        def hash_password(self, password: str, salt: bytes, user_id: str) -> str:
            return "v1:argon2id$" + "ee" * 8 + "$hash"

        def verify_password(
            self,
            password: str,
            hashed: str,
            user_id: str = "unknown",
            track_attempts: bool = True,
        ) -> bool:
            raise InvalidHashFormat("Bad format")

        def needs_rehash(self, *a: object, **kw: object) -> bool:
            return False

        def update_password(self, *a: object, **kw: object) -> str:
            return ""

        def reset_attempts(self, user_id: str) -> None:
            pass

        def export_audit(self, user_id: str) -> dict:  # type: ignore[type-arg]
            return {"attempts": 0}

        def export_policy(self) -> dict:  # type: ignore[type-arg]
            return {}

        def zeroize_all_secrets(self) -> None:
            pass

    storage = InMemoryUserStorage()
    storage._storage["baduser"] = "v1:argon2id$" + "ee" * 8 + "$hash"  # type: ignore[attr-defined]

    svc = PasswordService(
        hasher=ErrorVerifyHasher(),  # type: ignore[arg-type]
        user_storage=storage,
    )

    # Act
    result = svc._verify_password_internal("baduser", "SomePass!1")

    # Assert
    assert result is False


@pytest.mark.security
def test_password_service_verify_lockout_via_is_locked_out() -> None:
    """verify_password поднимает AccountLockedError если is_locked_out вернул True.

    Проверяет ветки 222-224: is_locked_out → AccountLockedError.
    """
    # Arrange: создать пользователя и вручную выставить максимум попыток
    from src.security.auth.password import MAX_FAILED_ATTEMPTS

    svc = PasswordService()
    svc.create_password("lockeduser", "LockedPass!1")
    # Вручную заблокировать через hasher
    svc.hasher._attempts["lockeduser"] = MAX_FAILED_ATTEMPTS

    # Act / Assert
    with pytest.raises(AccountLockedError):
        svc.verify_password("lockeduser", "LockedPass!1")
    assert svc.last_error == "Account locked"


@pytest.mark.security
def test_password_strength_all_issues_reported() -> None:
    """check_password_strength сообщает обо всех проблемах одновременно.

    Проверяет полноту списка issues для совершенно слабого пароля.
    """
    # Arrange
    svc = PasswordService()

    # Act: пароль без верхнего регистра, строчных букв, цифр, спецсимволов и короткий
    result = svc.check_password_strength("a")

    # Assert
    assert result["valid"] is False
    issues = result["issues"]
    assert "length<8" in issues
    assert "no_uppercase" in issues
    assert "no_digit" in issues
    assert "no_special" in issues


@pytest.mark.security
def test_password_strength_no_lowercase_issue() -> None:
    """check_password_strength включает 'no_lowercase' для строк без строчных букв.

    Проверяет отдельную ветку no_lowercase в check_password_strength (строка 370).
    """
    # Arrange
    svc = PasswordService()

    # Act: только заглавные + цифры + спецсимвол
    result = svc.check_password_strength("UPPERCASE1!")

    # Assert
    assert "no_lowercase" in result["issues"]


@pytest.mark.security
def test_reset_password_without_admin_id() -> None:
    """reset_password без admin_id использует строку 'system' в аудите.

    Проверяет ветку admin_id or 'system' (строка 298).
    """
    # Arrange
    svc = PasswordService()
    svc.create_password("sys_reset_user", "OldPass!1")

    # Act: без явного admin_id
    result = svc.reset_password("sys_reset_user", "NewPass!1")

    # Assert
    assert result is True
    assert svc.verify_password("sys_reset_user", "NewPass!1")
