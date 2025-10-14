# Модуль: src/security/auth/password_service.py
# Назначение (RU): Сервисный фасад управления паролями: создание, проверка, смена, reset, политики, истории, блокировки, аудит.
"""
Enterprise PasswordService — полный жизненный цикл управления паролями:
- Создание, валидация, смена, сброс
- История паролей
- Истечение срока действия (expiration)
- Временные пароли
- Сильное rate limiting
- Аудит и статистика

Синхронная реализация (готовность для масштабирования).
"""

from __future__ import annotations
from typing import Optional, Dict, Any, List, Protocol
from datetime import datetime, timedelta, timezone
import logging

from security.auth.password import (
    PasswordHasher,
    is_valid_password,
    MAX_FAILED_ATTEMPTS,
)

logger = logging.getLogger(__name__)

PASSWORD_EXPIRY_DAYS: int = 180
PASSWORD_HISTORY_LENGTH: int = 5
TEMP_PASSWORD_FLAG: str = "__TEMP__"


class UserStorage(Protocol):
    """Protocol for user storage backend with extended password management."""

    def get_password_hash(self, user_id: str) -> Optional[str]:
        """Retrieve stored password hash for user."""
        ...

    def set_password_hash(self, user_id: str, password_hash: str) -> None:
        """Store password hash for user."""
        ...

    def user_exists(self, user_id: str) -> bool:
        """Check if user exists."""
        ...

    def get_password_history(
        self, user_id: str, limit: int = PASSWORD_HISTORY_LENGTH
    ) -> List[str]:
        """Get password history for user."""
        ...

    def add_password_to_history(self, user_id: str, password_hash: str) -> None:
        """Add password hash to history."""
        ...

    def get_password_created_at(self, user_id: str) -> Optional[datetime]:
        """Get password creation timestamp."""
        ...

    def set_password_created_at(self, user_id: str, timestamp: datetime) -> None:
        """Set password creation timestamp."""
        ...

    def is_temporary_password(self, user_id: str) -> bool:
        """Check if password is temporary."""
        ...

    def set_temporary_flag(self, user_id: str, is_temp: bool) -> None:
        """Set temporary password flag."""
        ...

    def user_ids(self) -> List[str]:
        """Get list of all user IDs."""
        ...


class InMemoryUserStorage:
    """Simple in-memory user storage for development/testing."""

    def __init__(self) -> None:
        self._storage: Dict[str, str] = {}
        self._history: Dict[str, List[str]] = {}
        self._created_at: Dict[str, datetime] = {}
        self._temp_flag: Dict[str, bool] = {}

    def get_password_hash(self, user_id: str) -> Optional[str]:
        return self._storage.get(user_id)

    def set_password_hash(self, user_id: str, password_hash: str) -> None:
        self._storage[user_id] = password_hash
        self.add_password_to_history(user_id, password_hash)
        self.set_password_created_at(user_id, datetime.now(timezone.utc))

    def user_exists(self, user_id: str) -> bool:
        return user_id in self._storage

    def get_password_history(
        self, user_id: str, limit: int = PASSWORD_HISTORY_LENGTH
    ) -> List[str]:
        return self._history.get(user_id, [])[-limit:]

    def add_password_to_history(self, user_id: str, password_hash: str) -> None:
        hist = self._history.setdefault(user_id, [])
        hist.append(password_hash)
        if len(hist) > PASSWORD_HISTORY_LENGTH:
            hist.pop(0)

    def get_password_created_at(self, user_id: str) -> Optional[datetime]:
        return self._created_at.get(user_id)

    def set_password_created_at(self, user_id: str, timestamp: datetime) -> None:
        self._created_at[user_id] = timestamp

    def is_temporary_password(self, user_id: str) -> bool:
        return self._temp_flag.get(user_id, False)

    def set_temporary_flag(self, user_id: str, is_temp: bool) -> None:
        self._temp_flag[user_id] = is_temp

    def user_ids(self) -> List[str]:
        return list(self._storage.keys())


class PasswordServiceError(Exception):
    """Base exception for password service errors."""

    pass


class WeakPasswordError(PasswordServiceError):
    """Raised when password does not meet policy requirements."""

    pass


class AccountLockedError(PasswordServiceError):
    """Raised when account is locked due to failed attempts."""

    pass


class PasswordExpiredError(PasswordServiceError):
    """Raised when password has expired."""

    pass


class PasswordService:
    """
    High-level password management service.

    Orchestrates PasswordHasher and UserStorage for complete
    password lifecycle management with security policies and auditing.

    Args:
        hasher: PasswordHasher instance (creates default if None)
        user_storage: UserStorage implementation (creates in-memory if None)

    Example:
        >>> service = PasswordService()
        >>> service.create_password("alice", "Secure!123")
        True
        >>> service.verify_password("alice", "Secure!123")
        True
    """

    def __init__(
        self,
        hasher: Optional[PasswordHasher] = None,
        user_storage: Optional[UserStorage] = None,
    ) -> None:
        self.hasher: PasswordHasher = hasher if hasher is not None else PasswordHasher()
        self.storage: UserStorage = (
            user_storage if user_storage is not None else InMemoryUserStorage()
        )
        self.last_error: Optional[str] = None

    def _check_password_history(self, user_id: str, new_password: str) -> bool:
        """Check if password was used recently."""
        history = self.storage.get_password_history(user_id)
        for old_hash in history:
            if self.hasher.verify_password(new_password, old_hash, user_id):
                return False
        return True

    def _check_expiration(self, user_id: str) -> bool:
        """Check if password has expired."""
        created_at = self.storage.get_password_created_at(user_id)
        if not created_at:
            return False
        return datetime.now(timezone.utc) > (
            created_at + timedelta(days=PASSWORD_EXPIRY_DAYS)
        )

    def _audit_log(self, event: str, user_id: str, details: Dict[str, Any]) -> None:
        """Log structured audit event."""
        record: Dict[str, Any] = {
            "event": event,
            "user_id": user_id,
            "details": details,
            "time": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"AUDIT {record}")

    def create_password(self, user_id: str, password: str) -> bool:
        """Create password for new user."""
        self.last_error = None

        if not is_valid_password(password):
            self.last_error = "Password does not meet policy"
            self._audit_log(
                "password_policy_violation", user_id, {"reason": "weak_password"}
            )
            raise WeakPasswordError(self.last_error)

        if self.storage.user_exists(user_id) and not self._check_password_history(
            user_id, password
        ):
            self.last_error = "Password used recently"
            self._audit_log("password_history_reuse", user_id, {})
            raise WeakPasswordError(self.last_error)

        salt = self.hasher.generate_salt()
        password_hash = self.hasher.hash_password(password, salt, user_id)
        self.storage.set_password_hash(user_id, password_hash)
        self.storage.set_temporary_flag(user_id, False)
        self._audit_log("password_created", user_id, {})
        return True

    def _verify_password_internal(self, user_id: str, password: str) -> bool:
        """
        Internal password verification without side effects.

        Performs password verification without:
        - Tracking failed attempts
        - Enforcing account lockout
        - Modifying attempt counters

        Use this for internal operations like password changes where
        lockout enforcement is not appropriate.
        """
        if not self.storage.user_exists(user_id):
            return False

        stored_hash = self.storage.get_password_hash(user_id)
        if not stored_hash:
            return False

        # Use track_attempts=False to skip lockout logic
        return bool(
            self.hasher.verify_password(
                password, stored_hash, user_id=user_id, track_attempts=False
            )
        )

    def verify_password(self, user_id: str, password: str) -> bool:
        """Verify password during authentication."""
        self.last_error = None

        if not self.storage.user_exists(user_id):
            self.last_error = "User not found"
            return False

        if self.is_locked_out(user_id):
            self.last_error = "Account locked"
            raise AccountLockedError(self.last_error)

        stored_hash = self.storage.get_password_hash(user_id)
        if not stored_hash:
            self.last_error = "No password set"
            return False

        result = bool(self.hasher.verify_password(password, stored_hash, user_id))

        if result and self.hasher.needs_rehash(stored_hash, user_id):
            new_hash = self.hasher.update_password(password, stored_hash, user_id)
            self.storage.set_password_hash(user_id, new_hash)

        if result and self._check_expiration(user_id):
            self.last_error = "Password expired"
            raise PasswordExpiredError(self.last_error)

        return result

    def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """Change user password (requires old password verification)."""
        self.last_error = None

        # Use internal verification without side effects
        if not self._verify_password_internal(user_id, old_password):
            self.last_error = "Old password incorrect"
            raise PasswordServiceError(self.last_error)

        if not is_valid_password(new_password):
            self.last_error = "Password policy violation"
            raise WeakPasswordError(self.last_error)

        if not self._check_password_history(user_id, new_password):
            self.last_error = "Password used recently"
            raise WeakPasswordError(self.last_error)

        salt = self.hasher.generate_salt()
        new_hash = self.hasher.hash_password(new_password, salt, user_id)
        self.storage.set_password_hash(user_id, new_hash)
        self.storage.set_temporary_flag(user_id, False)
        self._audit_log("password_changed", user_id, {})
        return True

    def reset_password(
        self, user_id: str, new_password: str, admin_id: Optional[str] = None
    ) -> bool:
        """Reset user password (admin operation)."""
        self.last_error = None

        if not is_valid_password(new_password):
            self.last_error = "Reset password policy violation"
            raise WeakPasswordError(self.last_error)

        salt = self.hasher.generate_salt()
        new_hash = self.hasher.hash_password(new_password, salt, user_id)
        self.storage.set_password_hash(user_id, new_hash)
        self.storage.set_temporary_flag(user_id, True)
        self.hasher._attempts[user_id] = 0
        self._audit_log("password_reset", user_id, {"admin_id": admin_id or "system"})
        return True

    def set_temporary_password(self, user_id: str, temp_password: str) -> bool:
        """Set temporary password that must be changed on first login."""
        self.last_error = None

        if not is_valid_password(temp_password):
            self.last_error = "Temporary password policy violation"
            raise WeakPasswordError(self.last_error)

        salt = self.hasher.generate_salt()
        temp_hash = self.hasher.hash_password(temp_password, salt, user_id)
        self.storage.set_password_hash(user_id, temp_hash)
        self.storage.set_temporary_flag(user_id, True)
        self._audit_log("temporary_password_set", user_id, {})
        return True

    def is_temporary_password(self, user_id: str) -> bool:
        """Check if current password is temporary."""
        return bool(self.storage.is_temporary_password(user_id))

    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """Check password strength and provide feedback."""
        issues: List[str] = []

        if len(password) < 8:
            issues.append("length<8")
        if len(password) > 256:
            issues.append("length>256")
        if not any(c.isupper() for c in password):
            issues.append("no_uppercase")
        if not any(c.isdigit() for c in password):
            issues.append("no_digit")
        if not any(c in "!@#$%^&*()-_=+[]{}|;:'\"<>,.?/" for c in password):
            issues.append("no_special_char")
        if not any(c.isalpha() for c in password):
            issues.append("no_alpha")

        valid = len(issues) == 0
        score = max(0, 100 - len(issues) * 20)

        return {
            "valid": valid,
            "score": score,
            "issues": issues,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def is_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out due to failed attempts."""
        attempts = int(self.hasher._attempts.get(user_id, 0))
        return bool(attempts >= MAX_FAILED_ATTEMPTS)

    def unlock_user(self, user_id: str, admin_id: str) -> bool:
        """Unlock user account (admin operation)."""
        self.hasher._attempts[user_id] = 0
        self._audit_log("user_unlocked", user_id, {"admin_id": admin_id})
        return True

    def get_failed_attempts(self, user_id: str) -> int:
        """Get number of failed login attempts for user."""
        return int(self.hasher._attempts.get(user_id, 0))

    def export_policy(self) -> Dict[str, Any]:
        """Export current password policy configuration."""
        policy = self.hasher.export_policy()
        return dict(policy)

    def is_password_expired(self, user_id: str) -> bool:
        """Check if password has expired."""
        return self._check_expiration(user_id)

    def days_until_expiration(self, user_id: str) -> Optional[int]:
        """Get number of days until password expires."""
        created_at = self.storage.get_password_created_at(user_id)
        if not created_at:
            return None
        delta = (created_at + timedelta(days=PASSWORD_EXPIRY_DAYS)) - datetime.now(
            timezone.utc
        )
        return max(0, delta.days)

    def get_statistics(self) -> Dict[str, Any]:
        """Get password security statistics for monitoring."""
        all_users = self.storage.user_ids()
        total_users = len(all_users)

        locked_accounts = sum(1 for u in all_users if self.is_locked_out(u))

        total_failed = sum(self.get_failed_attempts(u) for u in all_users)
        avg_failed = total_failed / max(1, total_users)

        expires_soon: List[str] = []
        for u in all_users:
            days = self.days_until_expiration(u)
            if days is not None and days < 30:
                expires_soon.append(u)

        return {
            "total_users": total_users,
            "locked_accounts": locked_accounts,
            "avg_failed_attempts": avg_failed,
            "password_expires_soon": expires_soon,
        }

    def __enter__(self) -> "PasswordService":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit with cleanup."""
        # Теперь метод существует!
        self.hasher.zeroize_all_secrets()
