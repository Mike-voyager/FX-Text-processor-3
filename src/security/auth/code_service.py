# -*- coding: utf-8 -*-
"""
Thread-safe proxy API for backup/recovery codes via SecondFactorManager.
All operations are guarded by a module-level mutex.
Uses ONLY public manager APIs (no private fields).
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional, TypedDict, cast

from src.app_context import get_app_context
from src.security.crypto.kdf import (  # ensure exported in kdf.__all__
    derive_key_argon2id,
)

_logger = logging.getLogger("security.auth.code_service")
_lock = threading.Lock()


class BackupCodeStatus(TypedDict, total=False):
    codes: List[Dict[str, Any]]
    remaining: int
    consumed: int
    ttl_seconds: Optional[int]
    audit: List[Any]
    error: Optional[str]


def _export_state(user_id: str) -> Dict[str, Any]:
    """
    Export factor state snapshot for 'backupcode' via a public manager method (if available).
    Fallback to {} to avoid private access.
    """
    mgr = get_app_context().mfa_manager
    export = getattr(mgr, "export_factor_state", None)
    if callable(export):
        snap = export(user_id, "backupcode")
        return cast(Dict[str, Any], snap or {})
    return {}


def issue_backup_codes_for_user(
    user_id: str, count: int = 12, ttlsec: int = 7 * 24 * 3600
) -> BackupCodeStatus:
    """
    Issue a batch of backup codes for a user and return a typed status DTO.
    """
    # Basic input validation for robustness
    if not isinstance(user_id, str) or not user_id.strip():
        return BackupCodeStatus(error="user_id must be a non-empty string")
    if not isinstance(count, int) or count < 1 or count > 20:
        return BackupCodeStatus(error="count must be between 1 and 20")
    if not isinstance(ttlsec, int) or ttlsec < 60 or ttlsec > 90 * 24 * 3600:
        return BackupCodeStatus(error="ttlsec must be in [60, 7776000]")

    with _lock:
        try:
            mgr = get_app_context().mfa_manager
            mgr.setup_factor(user_id, "backupcode", count=count, ttlseconds=ttlsec)
            state = _export_state(user_id)
            raw_codes = state.get("codes", [])
            codes: List[Dict[str, Any]] = [
                c if isinstance(c, dict) else dict(c) for c in raw_codes
            ]
            remaining = int(state.get("remaining", len(codes)))
            consumed = int(state.get("consumed", 0))
            _logger.info("Backup codes issued: user=%s count=%d", user_id, count)
            return BackupCodeStatus(
                codes=codes,  # initial reveal only; do not re-expose in status endpoints
                remaining=remaining,
                consumed=consumed,
                ttl_seconds=(
                    int(state.get("ttl_seconds", ttlsec))
                    if "ttl_seconds" in state
                    else ttlsec
                ),
            )
        except Exception as exc:
            _logger.error(
                "Issue backup codes failed: user=%s err=%s",
                user_id,
                exc.__class__.__name__,
            )
            return BackupCodeStatus(error=str(exc))


def validate_backup_code_for_user(user_id: str, code: str) -> bool:
    """
    Validate (and burn) a single backup code for the user.
    Returns True if accepted and consumed; False otherwise.
    """
    if not isinstance(user_id, str) or not user_id.strip():
        return False
    if not isinstance(code, str) or not code.strip():
        return False

    with _lock:
        try:
            mgr = get_app_context().mfa_manager
            # Manager expects 'credential' argument
            ok: bool = bool(mgr.verify_factor(user_id, "backupcode", credential=code))
            _logger.debug("Backup code validate: user=%s ok=%s", user_id, ok)
            return ok
        except Exception as exc:
            _logger.warning(
                "Validate backup code failed: user=%s err=%s",
                user_id,
                exc.__class__.__name__,
            )
            return False


def remove_backup_codes_for_user(user_id: str) -> None:
    """
    Expire all backup codes for the user.
    """
    if not isinstance(user_id, str) or not user_id.strip():
        return

    with _lock:
        try:
            mgr = get_app_context().mfa_manager
            mgr.remove_factor(user_id, "backupcode")
            _logger.warning("Backup codes removed: user=%s", user_id)
        except Exception as exc:
            _logger.error(
                "Remove backup codes failed: user=%s err=%s",
                user_id,
                exc.__class__.__name__,
            )


def partial_revoke_backup_code(user_id: str, code: str) -> bool:
    """
    Mark a single backup code as used/burned (delegates to validate).
    """
    return validate_backup_code_for_user(user_id, code)


def get_backup_codes_status(user_id: str) -> BackupCodeStatus:
    """
    Return a typed status snapshot for backup codes.
    Note: does not re-expose actual code values.
    """
    if not isinstance(user_id, str) or not user_id.strip():
        return BackupCodeStatus(error="user_id must be a non-empty string")

    with _lock:
        try:
            state = _export_state(user_id)
            return BackupCodeStatus(
                remaining=int(state.get("remaining", 0)),
                consumed=int(state.get("consumed", 0)),
                ttl_seconds=cast(Optional[int], state.get("ttl_seconds")),
                audit=cast(List[Any], state.get("audit", [])),
            )
        except Exception as exc:
            _logger.error(
                "Get backup codes status failed: user=%s err=%s",
                user_id,
                exc.__class__.__name__,
            )
            return BackupCodeStatus(error=str(exc))


def get_backup_codes_audit(user_id: str) -> List[Any]:
    """
    Return audit trail entries for backup codes.
    """
    if not isinstance(user_id, str) or not user_id.strip():
        return []

    with _lock:
        try:
            state = _export_state(user_id)
            audit = cast(List[Any], state.get("audit", []))
            _logger.debug(
                "Backup code audit requested: user=%s size=%d", user_id, len(audit)
            )
            return audit
        except Exception as exc:
            _logger.error(
                "Get backup codes audit failed: user=%s err=%s",
                user_id,
                exc.__class__.__name__,
            )
            return []


def get_backup_code_secret_for_storage(user_id: str, code: str) -> bytes:
    """
    Return a deterministic 32-byte key derived from user_id|code with a per-user salt.
    Raises PermissionError if the code is invalid.
    """
    if not isinstance(user_id, str) or not user_id.strip():
        raise PermissionError("Invalid user_id")
    if not isinstance(code, str) or not code.strip():
        raise PermissionError("Invalid backup code")

    if not validate_backup_code_for_user(user_id, code):
        raise PermissionError("Invalid backup code")

    personal_salt = ("backup/user/" + user_id).encode("utf-8")
    return derive_key_argon2id(
        password=(user_id + "|" + code),
        salt=personal_salt,
        length=32,
    )
