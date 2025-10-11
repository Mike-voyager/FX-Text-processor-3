"""
Thread-safe proxy API for controller/UI to interact with FIDO2/WebAuthn factor using SecondFactorManager.
All security logic is delegated to Fido2Factor. Operations guarded by module-level mutex.
"""

import logging
from typing import Dict, Any, List
import threading

from src.security.auth.second_factor import SecondFactorManager

_manager_lock = threading.Lock()


def _get_latest_fido2_state(mgr: SecondFactorManager, user_id: str) -> Dict[str, Any]:
    factors: List[dict] = mgr._factors.get(user_id, {}).get("fido2", [])
    if not factors:
        return {}
    return factors[-1]["state"]  # type: ignore


def setup_fido2_for_user(user_id: str, device_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Registers a new FIDO2 device for user. Returns device state dict.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        mgr.setup_factor(user_id, "fido2", deviceinfo=device_info)
        state: Dict[str, Any] = _get_latest_fido2_state(mgr, user_id)
        logging.info("FIDO2 factor setup for user %s", user_id)
        return state


def validate_fido2_response(user_id: str, response: Dict[str, Any]) -> bool:
    """
    Verifies user WebAuthn/FIDO2 response for user device.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        return mgr.verify_factor(user_id, "fido2", response)


def remove_fido2_for_user(user_id: str) -> None:
    """
    Deletes user's FIDO2/WebAuthn device.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        mgr.remove_factor(user_id, "fido2")
        logging.warning("FIDO2 factor removed for user %s.", user_id)


def get_fido2_status(user_id: str) -> Dict[str, Any]:
    """
    Returns current status/info for FIDO2 factor of user.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        return _get_latest_fido2_state(mgr, user_id)


def get_fido2_audit(user_id: str) -> List[Any]:
    """
    Returns audit trail for FIDO2 factor.
    """
    with _manager_lock:
        mgr = SecondFactorManager()
        state: Dict[str, Any] = _get_latest_fido2_state(mgr, user_id)
        audit: List[Any] = state.get("audit", [])
        logging.debug("Requested audit trail for %s.", user_id)
        return audit
