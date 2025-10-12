# src/security/auth/totp_service.py
"""
Thread-safe proxy API for controller/UI to interact with TOTP 2FA factor using production SecondFactorManager.
All security logic is delegated to TotpFactor. Operations guarded by module-level mutex.
"""

import logging
from typing import Dict, Any, List, Tuple
import threading
import pyotp
import qrcode
from io import BytesIO

from src.app_context import get_app_context
from src.security.auth.second_factor import SecondFactorManager
from security.crypto.kdf import derive_key_argon2id

_manager_lock = threading.Lock()


def get_totp_secret_for_storage(user_id: str, otp: str) -> bytes:
    """
    On-the-fly derive crypto key for SecureStorage based on valid TOTP OTP.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        state = _get_latest_totp_state(mgr, user_id)
        secret = state.get("secret", "")
        if not secret:
            raise PermissionError("No TOTP secret for user")
        import pyotp

        totp = pyotp.TOTP(secret)
        if not totp.verify(otp):
            raise PermissionError("Invalid TOTP code")
        # Персональная соль для каждого юзера/фактора
        personal_salt = (f"totp/user/{user_id}").encode("utf-8")
        return derive_key_argon2id(
            (user_id + secret).encode("utf-8"), salt=personal_salt, length=32
        )


def _get_latest_totp_state(mgr: SecondFactorManager, user_id: str) -> Dict[str, Any]:
    """Helper to get the latest state dict of the user's TOTP factor."""
    factors = mgr._factors.get(user_id, {}).get("totp", [])
    if not factors:
        return {}
    return factors[-1]["state"]  # type: ignore


def setup_totp_for_user(
    user_id: str, username: str, issuer: str = "FX Text Processor"
) -> Dict[str, str | bytes]:
    """
    Registers and activates a new TOTP factor for given user, returning secret and QR/URI.
    Returns: dict {"secret": str, "uri": str, "qr": bytes}
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        mgr.setup_factor(user_id, "totp", username=username, issuer=issuer)
        state = _get_latest_totp_state(mgr, user_id)
        secret = state.get("secret", "")
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf, "PNG")
        logging.info("TOTP factor setup for user %s.", user_id)
        return {"secret": secret, "uri": uri, "qr": buf.getvalue()}


def validate_totp_code(user_id: str, code: str) -> bool:
    """
    Verifies input TOTP code against current factor for given user.
    Returns: True if code valid, False otherwise
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        return mgr.verify_factor(user_id, "totp", code)


def remove_totp_for_user(user_id: str) -> None:
    """
    Securely removes TOTP factor for user. Cleans up secret and audit.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        mgr.remove_factor(user_id, "totp")
        logging.warning("TOTP factor removed for user %s.", user_id)


def get_totp_status(user_id: str) -> Dict[str, Any]:
    """
    Returns current status/info for TOTP factor of user.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        return _get_latest_totp_state(mgr, user_id)


def get_totp_audit(user_id: str) -> List[Any]:
    """
    Returns audit trail for TOTP factor, including all critical actions.
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        state = _get_latest_totp_state(mgr, user_id)
        audit = state.get("audit", [])
        logging.debug("Requested audit trail for %s.", user_id)
        return list(audit)


def generate_totp_qr_uri(user_id: str) -> Tuple[str, bytes]:
    """
    Returns URI and QR PNG for user, for use in Authenticator (recovery/restore).
    """
    with _manager_lock:
        mgr = get_app_context().mfa_manager
        state = _get_latest_totp_state(mgr, user_id)
        secret = state.get("secret", "")
        username = state.get("username", "")
        issuer = state.get("issuer", "FX Text Processor")
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf, "PNG")
        logging.info("Generated recovery QR/URI for user %s.", user_id)
        return uri, buf.getvalue()
