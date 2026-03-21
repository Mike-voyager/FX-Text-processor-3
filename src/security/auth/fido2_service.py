# -*- coding: utf-8 -*-
"""
Thread-safe proxy API for controller/UI to interact
with FIDO2/WebAuthn factor using SecondFactorManager.
All security logic is delegated to the manager via public APIs.
Operations guarded by a module-level mutex.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, cast

from src.app_context import get_app_context

# KDF import; callers/tests may monkeypatch derive_key_argon2id on this module
try:
    from src.security.crypto.service.crypto_service import CryptoService
    from src.security.crypto.service.profiles import CryptoProfile

    _default_crypto_service = CryptoService(profile=CryptoProfile.STANDARD)

    def _get_crypto_service_impl() -> CryptoService:
        """Implementation: Получить CryptoService из app_context или создать default."""
        try:
            ctx = get_app_context()
            if hasattr(ctx, "crypto_service"):
                return ctx.crypto_service
        except Exception:  # pragma: no cover
            _logger.debug("Failed to get crypto_service from app_context, using default")
        # Fallback for tests or pre-initialization
        return _default_crypto_service

    def derive_key_argon2id(password: bytes, salt: bytes, length: int) -> bytes:
        """Обёртка над CryptoService.derive_key для совместимости с monkeypatching в тестах."""
        crypto_service = _get_crypto_service_impl()
        return crypto_service.derive_key(password, salt, key_length=length)

except Exception:  # pragma: no cover

    def _get_crypto_service_impl_fallback() -> Any:
        raise RuntimeError("_get_crypto_service_impl is not available")

    def derive_key_argon2id_fallback(password: bytes, salt: bytes, length: int) -> bytes:  # noqa: ARG001
        raise RuntimeError("derive_key_argon2id is not available")

    # Assign fallback implementations
    _get_crypto_service_impl = _get_crypto_service_impl_fallback
    derive_key_argon2id = derive_key_argon2id_fallback


# Public alias for backward compatibility
_get_crypto_service = _get_crypto_service_impl

_logger = logging.getLogger("security.auth.fido2_service")
_lock = threading.Lock()


def _export_state(user_id: str) -> Dict[str, Any]:
    """
    Export factor state snapshot for 'fido2' via a public manager method if available.
    Falls back to empty dict to avoid private access.
    """
    mgr = get_app_context().mfa_manager
    export = getattr(mgr, "export_factor_state", None)
    if callable(export):
        snap = export(user_id, "fido2")
        return cast(Dict[str, Any], snap or {})
    return {}


def setup_fido2_for_user(user_id: str, device_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Register a new FIDO2 device for the user and return a state snapshot.
    """
    with _lock:
        mgr = get_app_context().mfa_manager
        mgr.setup_factor(user_id, "fido2", deviceinfo=device_info)
        state = _export_state(user_id)
        _logger.info("FIDO2 factor setup: user=%s", user_id)
        return state


def validate_fido2_response(user_id: str, response: Dict[str, Any]) -> bool:
    """
    Verify the user's WebAuthn/FIDO2 response for the registered device.
    """
    with _lock:
        mgr = get_app_context().mfa_manager
        ok: bool = bool(mgr.verify_factor(user_id, "fido2", credential=response))
        _logger.debug("FIDO2 validate: user=%s ok=%s", user_id, ok)
        return ok


def remove_fido2_for_user(user_id: str) -> None:
    """
    Remove user's FIDO2/WebAuthn device.
    """
    with _lock:
        mgr = get_app_context().mfa_manager
        mgr.remove_factor(user_id, "fido2")
        _logger.warning("FIDO2 factor removed: user=%s", user_id)


def get_fido2_status(user_id: str) -> Dict[str, Any]:
    """
    Return the current state snapshot for the user's FIDO2 factor.
    """
    with _lock:
        return _export_state(user_id)


def get_fido2_audit(user_id: str) -> List[Any]:
    """
    Return audit trail for the user's FIDO2 factor.
    """
    with _lock:
        state = _export_state(user_id)
        audit = cast(List[Any], state.get("audit", []))
        _logger.debug("FIDO2 audit requested: user=%s size=%d", user_id, len(audit))
        return audit


def get_fido2_secret_for_storage(user_id: str, response: Dict[str, Any]) -> bytes:
    """
    Derive a deterministic 32-byte key for SecureStorage from stable device/user attributes.
    Raises PermissionError if the response is invalid.
    """
    with _lock:
        if not validate_fido2_response(user_id, response):
            raise PermissionError("Invalid FIDO2 response")

        # Prefer stable attributes for repeatable key derivation
        credential_id = response.get("credential_id", "")
        if not credential_id:
            raise PermissionError("Missing credential_id")

        signature = response.get("signature", "")
        if not signature:
            raise PermissionError("Missing signature")

        # Read registered public_key from state snapshot if present
        state = _export_state(user_id)
        pubkey = state.get("public_key", "")
        if not pubkey:
            # Fallback: still deterministic with credential_id only, but weaker entropy
            pubkey = ""

        personal_salt = f"fido2/user/{user_id}/dev/{credential_id}".encode("utf-8")

        return derive_key_argon2id(
            (user_id + "|" + credential_id + "|" + str(pubkey)).encode("utf-8"),
            personal_salt,
            32,
        )
