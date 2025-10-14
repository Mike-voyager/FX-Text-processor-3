"""
Thread-safe proxy API for controller/UI to interact with FIDO2/WebAuthn factor using SecondFactorManager.
All security logic is delegated to Fido2Factor. Operations guarded by module-level mutex.
"""

import logging
from typing import Dict, Any, List
import threading

from security.crypto.kdf import derive_key_argon2id
from security.auth.second_factor import SecondFactorManager
from app_context import get_app_context

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
        mgr = get_app_context().mfa_manager
        mgr.setup_factor(user_id, "fido2", deviceinfo=device_info)
        state: Dict[str, Any] = _get_latest_fido2_state(mgr, user_id)
        logging.info("FIDO2 factor setup for user %s", user_id)
        return state


def validate_fido2_response(user_id: str, response: Dict[str, Any]) -> bool:
    """
    Verifies user WebAuthn/FIDO2 response for user device.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        result = mgr.verify_factor(user_id, "fido2", response)
        return bool(result)  # Явное приведение к bool


def remove_fido2_for_user(user_id: str) -> None:
    """
    Deletes user's FIDO2/WebAuthn device.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        mgr.remove_factor(user_id, "fido2")
        logging.warning("FIDO2 factor removed for user %s.", user_id)


def get_fido2_status(user_id: str) -> Dict[str, Any]:
    """
    Returns current status/info for FIDO2 factor of user.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        return _get_latest_fido2_state(mgr, user_id)


def get_fido2_audit(user_id: str) -> List[Any]:
    """
    Returns audit trail for FIDO2 factor.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        state: Dict[str, Any] = _get_latest_fido2_state(mgr, user_id)
        audit: List[Any] = state.get("audit", [])
        logging.debug("Requested audit trail for %s.", user_id)
        return audit


def get_fido2_secret_for_storage(user_id: str, response: dict) -> bytes:
    """
    Derives encryption key from FIDO2 response for secure storage.

    Args:
        user_id: User identifier
        response: FIDO2 authentication response

    Returns:
        32-byte derived key for storage encryption

    Raises:
        PermissionError: If FIDO2 response is invalid
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        state = _get_latest_fido2_state(mgr, user_id)
        from .second_method.fido2 import Fido2Factor

        factor = Fido2Factor()
        result = factor.verify(user_id, response, state)
        if result.get("status") != "success":
            raise PermissionError("Invalid FIDO2 response")

        credential_id = response.get("credential_id", "")
        signature = response.get("signature", "")
        if not credential_id or not signature:
            raise PermissionError("Missing credential_id or signature")

        personal_salt = f"fido2/user/{user_id}/dev/{credential_id}".encode("utf-8")

        # Явно приводим к bytes
        derived_key: bytes = derive_key_argon2id(
            (user_id + credential_id + str(signature)).encode("utf-8"),
            salt=personal_salt,
            length=32,
        )

        return derived_key
