"""
Thread-safe proxy API for backup/recovery codes via SecondFactorManager.
Operations guarded by module-level mutex.
"""

import logging
from typing import Dict, Any, List
import threading

from src.security.auth.second_factor import SecondFactorManager

_manager_lock = threading.Lock()


def _get_latest_code_state(mgr: SecondFactorManager, user_id: str) -> Dict[str, Any]:
    factors: List[dict] = mgr._factors.get(user_id, {}).get("backupcode", [])
    if not factors:
        return {}
    return factors[-1]["state"]  # type: ignore


def issue_backup_codes_for_user(
    user_id: str, count: int = 12, ttlsec: int = 604800
) -> List[Dict[str, Any]]:
    """
    Issues a batch of backup codes for user.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
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
    Validates user backup code.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        return mgr.verify_factor(user_id, "backupcode", code)


def remove_backup_codes_for_user(user_id: str) -> None:
    """
    Deletes (expires) all backup codes for user.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        mgr.remove_factor(user_id, "backupcode")
        logging.warning("Backup codes removed for user %s.", user_id)


def get_backup_codes_status(user_id: str) -> Dict[str, Any]:
    """
    Returns current status/info for backup codes of user.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        return _get_latest_code_state(mgr, user_id)


def get_backup_codes_audit(user_id: str) -> List[Any]:
    """
    Returns audit trail for backup codes.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        state: Dict[str, Any] = _get_latest_code_state(mgr, user_id)
        audit: List[Any] = state.get("audit", [])
        logging.debug("Requested audit trail for %s.", user_id)
        return audit
