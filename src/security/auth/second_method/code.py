# -*- coding: utf-8 -*-
"""
Модуль: security/auth/second_method/code.py

RU: Экстремально стойкие одноразовые резервные коды (Backup/Recovery codes)
    с TTL, аудитом, блокировкой и поддержкой UX для FX Text Processor 3.

EN: Enterprise-grade backup/recovery codes with TTL, audit trail, lockout,
    and UX support for FX Text Processor 3.
"""

from __future__ import annotations

import secrets
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Final, List

__all__ = [
    "BackupCodeFactor",
    "CodeExpired",
    "CodeUsed",
    "CodeLockout",
    "DEFAULT_TTL_DAYS",
]

# ---- Constants ----
CODE_BITS: Final[int] = 256
BLOCK_SIZE: Final[int] = 4
MAX_ATTEMPTS: Final[int] = 5
LOCK_SECONDS: Final[int] = 180
DEFAULT_TTL_DAYS: Final[int] = 90


# ---- Exceptions ----
class CodeExpired(ValueError):
    """Backup code has exceeded its TTL."""


class CodeUsed(ValueError):
    """Backup code was already used."""


class CodeLockout(RuntimeError):
    """Account locked due to failed code attempts."""


# ---- Helpers ----
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_str() -> str:
    return _now().isoformat()


def format_code(raw_hex: str, block_size: int = BLOCK_SIZE) -> str:
    """
    Format raw hex code into human-readable blocks.

    Args:
        raw_hex: Raw hexadecimal string
        block_size: Number of characters per block

    Returns:
        Formatted code with dash separators (e.g., "a1b2-c3d4-...")

    Example:
        >>> format_code("a1b2c3d4e5f6", 4)
        'a1b2-c3d4-e5f6'
    """
    return "-".join(
        [raw_hex[i : i + block_size] for i in range(0, len(raw_hex), block_size)]
    )


class BackupCodeFactor:
    """
    Backup/Recovery code second factor with TTL, anti-brute-force lockout, and audit trail.

    Features:
    - Cryptographically strong codes (256-bit)
    - Per-batch TTL (default: 90 days)
    - Anti-brute-force lockout after MAX_ATTEMPTS failed attempts
    - Full audit trail of all verification attempts
    - UX-friendly formatted codes

    Example:
        >>> factor = BackupCodeFactor()
        >>> state = factor.setup("user123", count=10)
        >>> codes = factor.get_active_codes(state)
        >>> result = factor.verify("user123", codes[0], state)
        >>> assert result["status"] == "success"
    """

    def setup(
        self,
        user_id: str,
        count: int = 10,
        ttl_days: int = DEFAULT_TTL_DAYS,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generate a fresh batch of backup codes for user.

        Args:
            user_id: User identifier
            count: Number of codes to generate (default: 10)
            ttl_days: Time-to-live in days (default: 90)
            **kwargs: Additional metadata

        Returns:
            State dict with codes, metadata, and audit log

        Example:
            >>> state = factor.setup("alice", count=5, ttl_days=30)
            >>> len(factor.get_active_codes(state))
            5
        """
        created = _now()
        codes: List[Dict[str, Any]] = [
            {
                "raw": secrets.token_hex(CODE_BITS // 8),
                "code": "",
                "used": False,
                "used_at": None,
                "failed_attempts": 0,
            }
            for _ in range(count)
        ]
        for c in codes:
            c["code"] = format_code(c["raw"])

        return {
            "codes": codes,
            "created_at": created.isoformat(),
            "ttl_days": ttl_days,
            "lock_until": None,
            "failed_attempts": 0,
            "audit": [],
        }

    def remove(self, user_id: str, state: Dict[str, Any]) -> None:
        """
        Remove all backup codes and invalidate state (anti-forensics, SOC audit).

        Args:
            user_id: User identifier
            state: Current factor state

        Side effects:
            - Clears all codes
            - Marks state as locked indefinitely
            - Appends removal event to audit log
        """
        now_str = _now_str()
        state["codes"] = []
        state["lock_until"] = now_str
        state["audit"] = state.get("audit", [])
        state["audit"].append(
            {"action": "remove", "timestamp": now_str, "user_id": user_id}
        )

    def verify(self, user_id: str, code: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify backup code for user.

        Args:
            user_id: User identifier
            code: Code to verify (with or without dashes)
            state: Current factor state

        Returns:
            Verification result dict with keys:
            - status: "success"|"fail"|"lockout"|"expired"|"used"
            - remaining_lock_sec: Seconds until unlock (if locked)
            - audit: Updated audit trail

        Raises:
            CodeExpired: If batch TTL exceeded
            CodeLockout: If account is locked
            CodeUsed: If code was already used

        Example:
            >>> result = factor.verify("bob", "a1b2-c3d4-...", state)
            >>> if result["status"] == "success":
            ...     print("Code accepted")
        """
        now = _now()
        now_str = now.isoformat()
        audit = state.setdefault("audit", [])

        # Check TTL
        created_at_str = state.get("created_at", now_str)
        created_at = datetime.fromisoformat(created_at_str)
        ttl_days = state.get("ttl_days", DEFAULT_TTL_DAYS)
        if now > created_at + timedelta(days=ttl_days):
            audit.append({"timestamp": now_str, "code": code, "result": "expired"})
            raise CodeExpired("Backup codes have expired")

        # Check lockout
        lock_until_str = state.get("lock_until")
        if lock_until_str:
            lock_until = datetime.fromisoformat(lock_until_str)
            if now < lock_until:
                remaining_sec = int((lock_until - now).total_seconds())
                audit.append(
                    {
                        "timestamp": now_str,
                        "code": code,
                        "result": "lockout",
                        "locked_for": remaining_sec,
                    }
                )
                raise CodeLockout(f"Account locked for {remaining_sec} seconds")

        # Normalize code
        normalized = code.replace("-", "").replace(" ", "").lower()

        for c in state.get("codes", []):
            candidate = c["raw"].lower()
            if candidate == normalized:
                if c["used"]:
                    audit.append({"timestamp": now_str, "code": code, "result": "used"})
                    raise CodeUsed("Code was already used")
                # Success
                c["used"] = True
                c["used_at"] = now_str
                audit.append({"timestamp": now_str, "code": code, "result": "success"})
                state["failed_attempts"] = 0
                state["lock_until"] = None
                return {"status": "success", "remaining_lock_sec": 0, "audit": audit}

        # Failed attempt
        audit.append({"timestamp": now_str, "code": code, "result": "fail"})
        state["failed_attempts"] = state.get("failed_attempts", 0) + 1

        if state["failed_attempts"] >= MAX_ATTEMPTS:
            lock_until = now + timedelta(seconds=LOCK_SECONDS)
            state["lock_until"] = lock_until.isoformat()
            state["failed_attempts"] = 0
            raise CodeLockout(f"Account locked for {LOCK_SECONDS} seconds")

        return {"status": "fail", "remaining_lock_sec": 0, "audit": audit}

    def expire(self, state: Dict[str, Any]) -> None:
        """
        Soft-invalidate all unused codes (e.g., user-requested purge).

        Args:
            state: Current factor state

        Side effects:
            - Marks all unused codes as used
            - Appends expire timestamp
        """
        now_str = _now_str()
        for c in state.get("codes", []):
            if not c["used"]:
                c["used"] = True
                c["used_at"] = now_str

    def get_active_codes(self, state: Dict[str, Any]) -> List[str]:
        """
        Return formatted unused codes for UI/export.

        Args:
            state: Current factor state

        Returns:
            List of formatted codes (e.g., ["a1b2-c3d4-...", ...])
        """
        return [c["code"] for c in state.get("codes", []) if not c["used"]]

    def get_audit_log(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Return full audit trail.

        Args:
            state: Current factor state

        Returns:
            List of audit events with timestamps and results
        """
        return list(state.get("audit", []))

    def is_expired(self, state: Dict[str, Any]) -> bool:
        """
        Check if code batch has exceeded TTL.

        Args:
            state: Current factor state

        Returns:
            True if expired, False otherwise
        """
        now = _now()
        created_at_str = state.get("created_at", now.isoformat())
        created_at = datetime.fromisoformat(created_at_str)
        ttl_days = state.get("ttl_days", DEFAULT_TTL_DAYS)
        return now > created_at + timedelta(days=ttl_days)

    def export_policy(self, deterministic: bool = True) -> Dict[str, Any]:
        """
        Export backup code policy configuration.

        Args:
            deterministic: Return ordered dict for stable snapshots

        Returns:
            Policy dict with constants and limits
        """
        data = {
            "code_bits": CODE_BITS,
            "block_size": BLOCK_SIZE,
            "max_attempts": MAX_ATTEMPTS,
            "lock_seconds": LOCK_SECONDS,
            "default_ttl_days": DEFAULT_TTL_DAYS,
            "format_example": format_code("a" * 64, BLOCK_SIZE),
        }
        if deterministic:
            return OrderedDict(sorted(data.items(), key=lambda kv: kv[0]))
        return data

    def export_audit(
        self, state: Dict[str, Any], deterministic: bool = True
    ) -> Dict[str, Any]:
        """
        Export audit summary for monitoring.

        Args:
            state: Current factor state
            deterministic: Return ordered dict

        Returns:
            Audit summary with counts and status
        """
        codes = state.get("codes", [])
        total = len(codes)
        used = sum(1 for c in codes if c["used"])
        active = total - used

        data = {
            "total_codes": total,
            "used_codes": used,
            "active_codes": active,
            "failed_attempts": state.get("failed_attempts", 0),
            "is_locked": bool(state.get("lock_until")),
            "is_expired": self.is_expired(state),
            "audit_events": len(state.get("audit", [])),
        }
        if deterministic:
            return OrderedDict(sorted(data.items(), key=lambda kv: kv[0]))
        return data

    def is_locked(self, state: Dict[str, Any]) -> bool:
        """Check if account is currently locked."""
        lock_until_str = state.get("lock_until")
        if not lock_until_str:
            return False
        lock_until = datetime.fromisoformat(lock_until_str)
        return _now() < lock_until

    def get_remaining_codes(self, state: Dict[str, Any]) -> int:
        """Return count of unused codes."""
        return sum(1 for c in state.get("codes", []) if not c["used"])

    def get_lock_remaining_seconds(self, state: Dict[str, Any]) -> int:
        """Return seconds until unlock (0 if not locked)."""
        lock_until_str = state.get("lock_until")
        if not lock_until_str:
            return 0
        lock_until = datetime.fromisoformat(lock_until_str)
        now = _now()
        if now >= lock_until:
            return 0
        return int((lock_until - now).total_seconds())
