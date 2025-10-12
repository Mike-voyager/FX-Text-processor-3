"""
Thread-safe proxy API for backup/recovery codes via SecondFactorManager.
Operations guarded by module-level mutex.
Extended for per-user salt, status methods, explicit documentation.
"""

import logging
import threading
from typing import Dict, Any, List

from src.app_context import get_app_context
from security.crypto.kdf import derive_key_argon2id

_manager_lock = threading.Lock()


def _get_latest_code_state(mgr: Any, user_id: str) -> Dict[str, Any]:
    factors: List[dict] = mgr._factors.get(user_id, {}).get("backupcode", [])
    if not factors:
        return {}
    return factors[-1]["state"]  # type: ignore


def issue_backup_codes_for_user(
    user_id: str, count: int = 12, ttlsec: int = 604800
) -> List[Dict[str, Any]]:
    """
    Issues a batch of backup codes for user.
    Returns a list of code dicts.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        mgr.setup_factor(user_id, "backupcode", count=count, ttlseconds=ttlsec)
        state: Dict[str, Any] = _get_latest_code_state(mgr, user_id)
        codes_raw = state.get("codes", [])
        codes: List[Dict[str, Any]] = [
            code if isinstance(code, dict) else dict(code) for code in codes_raw
        ]
        logging.info("Backup codes issued for user %s. Count: %d", user_id, count)
        return list(codes_raw)


def validate_backup_code_for_user(user_id: str, code: str) -> bool:
    """
    Validates or burns (single-use) a backup code for user.
    Returns True if valid and burned, False if not valid.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        return mgr.verify_factor(user_id, "backupcode", code)


def remove_backup_codes_for_user(user_id: str) -> None:
    """
    Deletes (expires) all backup codes for user.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        mgr.remove_factor(user_id, "backupcode")
        logging.warning("Backup codes removed for user %s.", user_id)


def partial_revoke_backup_code(user_id: str, code: str) -> bool:
    """
    Marks a single backup code as used/burned (partial revoke).
    Returns True if successful.
    """
    # Эта функция полагается на то, что validate_* реально делает expire/отметку used
    return validate_backup_code_for_user(user_id, code)


def get_backup_codes_status(user_id: str) -> Dict[str, Any]:
    """
    Returns current status/info for backup codes of user.
    Example: {"codes": [...], "ttl": ...}
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        return _get_latest_code_state(mgr, user_id)


def get_backup_codes_audit(user_id: str) -> List[Any]:
    """
    Returns audit trail for backup codes.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        state: Dict[str, Any] = _get_latest_code_state(mgr, user_id)
        audit: List[Any] = state.get("audit", [])
        logging.debug("Requested audit trail for %s.", user_id)
        return audit


def get_backup_code_secret_for_storage(user_id: str, code: str) -> bytes:
    """
    Returns cryptographic key for SecureStorage by user+backup code.
    Per-user unique salt to strengthen KDF.
    Throws PermissionError if code invalid.
    """
    if validate_backup_code_for_user(user_id, code):
        # уникальная соль для каждого user_id/backup code класса!
        personal_salt = ("backup/user/" + user_id).encode("utf-8")
        return derive_key_argon2id(
            (user_id + "|" + code).encode("utf-8"), salt=personal_salt, length=32
        )
    raise PermissionError("Invalid backup code")
