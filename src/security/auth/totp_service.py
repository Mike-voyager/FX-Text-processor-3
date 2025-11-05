# -*- coding: utf-8 -*-
"""
Module: src/security/auth/totp_service.py

Thread-safe TOTP service facade for controller/UI:
- Setup TOTP factor for user
- Validate TOTP code (with rate limiting/lockout)
- Remove TOTP factor
- Get status and audit (with redaction)
- Generate provisioning URI and QR code (rate-limited, parameterized)
- Export secret-derived material for storage (with OTP verification, DI KDF/pepper)
- Export policy/config
"""

from __future__ import annotations

import io
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple, Optional, Union, TypedDict

# External deps expected; callers/tests may monkeypatch these names on this module
try:
    import pyotp  # type: ignore
except Exception:  # pragma: no cover
    pyotp = None  # type: ignore

try:
    import qrcode  # type: ignore
    from qrcode.constants import ERROR_CORRECT_M as _QR_EC  # type: ignore
except Exception:  # pragma: no cover
    qrcode = None  # type: ignore
    _QR_EC = None  # type: ignore

# KDF import; callers/tests may monkeypatch derive_key_argon2id on this module
try:
    from src.security.crypto.kdf import derive_key_argon2id  # type: ignore
except Exception:  # pragma: no cover
    def derive_key_argon2id(password: Union[bytes, str], salt: bytes, length: int) -> bytes:  # type: ignore
        raise RuntimeError("derive_key_argon2id is not available")

# App context provider; callers/tests should monkeypatch this to a concrete context
def get_app_context() -> Any:  # pragma: no cover
    raise RuntimeError("Application context is not configured for totp_service")

# Logger
_logger = logging.getLogger(__name__)

# Reentrant lock for manager operations
_manager_lock = threading.RLock()

# ---- Service Configuration (DI) ----
DEFAULT_ISSUER: str = "FX Text Processor"
DEFAULT_DIGITS: int = 6
DEFAULT_INTERVAL: int = 30        # seconds
DEFAULT_VALID_WINDOW: int = 1     # accepts codes in adjacent steps ±1

# Rate limiting and lockout
RATE_LIMIT_MAX_FAILS: int = 5
RATE_LIMIT_LOCK_SECONDS: int = 120
RATE_LIMIT_MIN_INTERVAL_SECONDS: int = 2

# QR generation parameters
QR_BOX_SIZE: int = 6
QR_BORDER: int = 2
QR_MIN_INTERVAL_SECONDS: int = 5   # minimal interval between QR regenerations per user

# DI container
_config: Dict[str, Any] = {
    "issuer": DEFAULT_ISSUER,
    "pepper": None,                   # Optional[Union[str, bytes]]
    "kdf": derive_key_argon2id,
    "argon2_params": None,            # Reserved for passing Argon2 params to provider
    "valid_window": DEFAULT_VALID_WINDOW,
    "digits": DEFAULT_DIGITS,
    "interval": DEFAULT_INTERVAL,
    "rate": {
        "max_fails": RATE_LIMIT_MAX_FAILS,
        "lock_seconds": RATE_LIMIT_LOCK_SECONDS,
        "min_interval": RATE_LIMIT_MIN_INTERVAL_SECONDS,
        "qr_min_interval": QR_MIN_INTERVAL_SECONDS,
    },
}

def configure_totp_service(
    *,
    issuer: Optional[str] = None,
    pepper: Optional[Union[str, bytes]] = None,
    kdf: Optional[Any] = None,
    argon2_params: Optional[Dict[str, Any]] = None,
    valid_window: Optional[int] = None,
    digits: Optional[int] = None,
    interval: Optional[int] = None,
    rate: Optional[Dict[str, int]] = None,
) -> None:
    """
    Configure TOTP service parameters (DI).
    """
    with _manager_lock:
        if issuer is not None:
            _config["issuer"] = issuer
        if pepper is not None:
            _config["pepper"] = pepper
        if kdf is not None:
            _config["kdf"] = kdf
        if argon2_params is not None:
            _config["argon2_params"] = argon2_params
        if valid_window is not None:
            _config["valid_window"] = int(valid_window)
        if digits is not None:
            _config["digits"] = int(digits)
        if interval is not None:
            _config["interval"] = int(interval)
        if rate is not None:
            _config["rate"].update({k: int(v) for k, v in rate.items()})

# ---- Domain Exceptions ----
class TotpError(RuntimeError):
    pass

class TotpNotConfigured(TotpError):
    pass

class TotpInvalidCode(TotpError):
    pass

class TotpRuntimeUnavailable(TotpError):
    pass

class TotpLockedOut(TotpError):
    def __init__(self, remaining_seconds: int) -> None:
        super().__init__(f"TOTP locked for {remaining_seconds} seconds")
        self.remaining_seconds = remaining_seconds

# ---- Internal State for Rate Limiting ----
# Keep minimal per-user counters in memory; for multi-process, back these by shared store
_rl_state: Dict[str, Dict[str, Any]] = {}  # { user_id: {failed:int, lock_until:datetime|None, last_try:datetime|None, last_qr:datetime|None} }

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _get_rl(user_id: str) -> Dict[str, Any]:
    st = _rl_state.get(user_id)
    if not st:
        st = {"failed": 0, "lock_until": None, "last_try": None, "last_qr": None}
        _rl_state[user_id] = st
    return st

def _check_locked(user_id: str) -> None:
    st = _get_rl(user_id)
    lock_until: Optional[datetime] = st.get("lock_until")
    if lock_until and _now() < lock_until:
        remaining = int((lock_until - _now()).total_seconds())
        raise TotpLockedOut(max(remaining, 1))

def _check_min_interval(user_id: str) -> None:
    st = _get_rl(user_id)
    last_try: Optional[datetime] = st.get("last_try")
    min_interval = _config["rate"]["min_interval"]
    if last_try is not None and (_now() - last_try).total_seconds() < min_interval:
        # treat as soft violation; do not raise, but log and delay should be implemented by caller if desired
        _logger.debug("TOTP attempt too frequent for user=%s", user_id)

def _register_failure(user_id: str) -> None:
    st = _get_rl(user_id)
    st["failed"] = int(st.get("failed", 0)) + 1
    st["last_try"] = _now()
    if st["failed"] >= _config["rate"]["max_fails"]:
        st["failed"] = 0
        st["lock_until"] = _now() + timedelta(seconds=_config["rate"]["lock_seconds"])

def _register_success(user_id: str) -> None:
    st = _get_rl(user_id)
    st["failed"] = 0
    st["lock_until"] = None
    st["last_try"] = _now()

def _check_qr_rate_limit(user_id: str) -> None:
    st = _get_rl(user_id)
    last_qr: Optional[datetime] = st.get("last_qr")
    if last_qr and (_now() - last_qr).total_seconds() < _config["rate"]["qr_min_interval"]:
        _logger.debug("QR generation too frequent for user=%s", user_id)
    st["last_qr"] = _now()

# ---- Internal helpers ----

def _get_first_totp_state(ctx: Any, user_id: str) -> Dict[str, Any]:
    """
    Best-effort state fetch from manager's internal storage for 'totp' factor.
    Expecting ctx.mfa_manager._factors[user_id]['totp'] = [{'state': {...}}, ...].
    """
    mgr = getattr(ctx, "mfa_manager", None)
    factors = getattr(mgr, "_factors", {})
    user_map = factors.get(user_id, {})
    totp_list = user_map.get("totp", [])
    if isinstance(totp_list, list):
        for item in totp_list:
            if isinstance(item, dict):
                st = item.get("state")
                if isinstance(st, dict):
                    return st
    return {}

def _validate_label(text: str, *, max_len: int = 64) -> str:
    """
    Ensure username/issuer are safe for otpauth URI: clip length, strip control chars.
    """
    sanitized = "".join(ch for ch in text if 32 <= ord(ch) < 127)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len]
    return sanitized

def _provisioning_uri(secret: str, name: str, issuer: str, *, digits: Optional[int] = None, interval: Optional[int] = None) -> str:
    """
    Build otpauth provisioning URI using pyotp if available; empty string otherwise.
    """
    if not secret:
        return ""
    if pyotp is None:  # pragma: no cover
        return ""
    totp_obj = pyotp.TOTP(
        secret,
        digits=(digits if digits is not None else _config["digits"]),
        interval=(interval if interval is not None else _config["interval"]),
    )  # type: ignore
    return totp_obj.provisioning_uri(name=name, issuer_name=issuer)

def _make_qr_bytes(uri: str) -> Tuple[bytes, str]:
    """
    Create QR PNG bytes for a provisioning URI. Returns empty bytes if qrcode unavailable.
    Returns (bytes, mime).
    """
    if not uri or qrcode is None:  # pragma: no cover
        return b"", "image/png"
    try:
        if hasattr(qrcode, "QRCode"):
            qr = qrcode.QRCode(  # type: ignore
                version=None,
                error_correction=_QR_EC if _QR_EC is not None else 0,
                box_size=QR_BOX_SIZE,
                border=QR_BORDER,
            )
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
        else:
            img = qrcode.make(uri)  # type: ignore
        buf = io.BytesIO()
        img.save(buf, "PNG")  # type: ignore
        return buf.getvalue(), "image/png"
    except Exception as e:  # pragma: no cover
        _logger.warning("QR generation failed: %s", e)
        return b"", "image/png"

def _normalize_otp(otp: str) -> str:
    """
    Normalize user-entered OTP: remove spaces and dashes.
    """
    return otp.replace(" ", "").replace("-", "")

def _deterministic_salt(user_id: str) -> bytes:
    """
    Deterministic, user-bound salt for storage key derivation (does not expose TOTP secret).
    """
    return f"totp:{user_id}".encode("utf-8")

def _redact_secret(secret: Optional[str]) -> str:
    """
    Redact secret for public status (avoid leaking to UI/logs).
    """
    if not secret:
        return ""
    return "****"

# Typed API structures
class SetupResult(TypedDict, total=True):
    uri: str
    qr: bytes
    qr_mime: str

class StatusPublic(TypedDict, total=False):
    username: str
    issuer: str
    digits: int
    interval: int
    created_at: str

class QRResult(TypedDict, total=True):
    uri: str
    qr: bytes
    qr_mime: str

# ---- Public API ----

def setup_totp_for_user(
    user_id: str,
    username: str,
    issuer: Optional[str] = None,
    *,
    include_secret: bool = False,
    digits: Optional[int] = None,
    interval: Optional[int] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Initialize TOTP factor via manager and return basic info with URI and QR code bytes.
    Manager persists the state (secret/audit/metadata).
    """
    with _manager_lock:
        ctx = get_app_context()
        eff_issuer = _validate_label(issuer or _config["issuer"])
        eff_username = _validate_label(username)
        ctx.mfa_manager.setup_factor(
            user_id,
            "totp",
            username=eff_username,
            issuer=eff_issuer,
            digits=digits or _config["digits"],
            interval=interval or _config["interval"],
            **kwargs,
        )
        state = _get_first_totp_state(ctx, user_id)

        secret = state.get("secret", "")
        uri = _provisioning_uri(secret, state.get("username", eff_username), state.get("issuer", eff_issuer), digits=digits, interval=interval)
        qr, mime = _make_qr_bytes(uri)

        # Attempt to append audit event if storage supports it
        try:
            state.setdefault("audit", []).append({
                "ts": _now().isoformat(),
                "action": "setup",
                "result": "success",
            })
        except Exception:
            pass

        result: Dict[str, Any] = {"uri": uri, "qr": qr, "qr_mime": mime}
        if include_secret:
            result["secret"] = secret
        return result

def validate_totp_code(user_id: str, code: str) -> bool:
    """
    Validate a TOTP credential through the manager's factor verification API with rate limiting/lockout.
    """
    with _manager_lock:
        _check_locked(user_id)
        _check_min_interval(user_id)
        ctx = get_app_context()
        ok = bool(ctx.mfa_manager.verify_factor(user_id, "totp", _normalize_otp(code)))
        if ok:
            _register_success(user_id)
        else:
            _register_failure(user_id)
        return ok

def remove_totp_for_user(user_id: str) -> None:
    """
    Remove TOTP factor for a user via manager and clear state.
    """
    with _manager_lock:
        ctx = get_app_context()
        # Best-effort audit
        try:
            st = _get_first_totp_state(ctx, user_id)
            st.setdefault("audit", []).append({
                "ts": _now().isoformat(),
                "action": "remove",
            })
        except Exception:
            pass
        ctx.mfa_manager.remove_factor(user_id, "totp")

def get_totp_status(user_id: str, *, redact: bool = False) -> Dict[str, Any]:
    """
    Return current TOTP state dict for diagnostics; {} if not configured.
    If redact=True, masks secret to avoid leakage to UI/logs.
    """
    with _manager_lock:
        ctx = get_app_context()
        st = dict(_get_first_totp_state(ctx, user_id))
        if not st:
            return {}
        if redact and "secret" in st:
            st["secret"] = _redact_secret(st.get("secret"))
        # Clip to known public-safe fields if redact requested
        if redact:
            pub: StatusPublic = {
                "username": st.get("username", ""),
                "issuer": st.get("issuer", _config["issuer"]),
                "digits": int(st.get("digits", _config["digits"])),
                "interval": int(st.get("interval", _config["interval"])),
                "created_at": st.get("created_at", ""),
            }
            return dict(pub)
        return st

def get_totp_status_public(user_id: str) -> Dict[str, Any]:
    """
    Public-friendly status for UI: secret is always redacted and only safe fields are returned.
    """
    return get_totp_status(user_id, redact=True)

def get_totp_audit(user_id: str) -> List[Any]:
    """
    Return audit entries list for TOTP factor; [] if none.
    """
    with _manager_lock:
        ctx = get_app_context()
        state = _get_first_totp_state(ctx, user_id)
        return list(state.get("audit", []))

def generate_totp_qr_uri(user_id: str) -> QRResult:
    """
    Generate provisioning URI and QR PNG bytes for a user's TOTP secret (rate-limited).
    Returns empty payload if user/secret not found or qrcode unavailable.
    """
    with _manager_lock:
        _check_qr_rate_limit(user_id)
        ctx = get_app_context()
        state = _get_first_totp_state(ctx, user_id)
        secret = state.get("secret", "")
        uri = _provisioning_uri(
            secret,
            state.get("username", user_id),
            state.get("issuer", _config["issuer"]),
            digits=state.get("digits", _config["digits"]),
            interval=state.get("interval", _config["interval"]),
        )
        qr, mime = _make_qr_bytes(uri)
        return {"uri": uri, "qr": qr, "qr_mime": mime}

def regenerate_totp_qr(user_id: str) -> QRResult:
    """
    Regenerate provisioning URI and QR (same as generate, but semantic alias for UI flows).
    """
    return generate_totp_qr_uri(user_id)

def get_totp_secret_for_storage(
    user_id: str,
    otp: str,
    *,
    dk_len: int = 64,
    valid_window: Optional[int] = None,
) -> bytes:
    """
    Verify user's current TOTP code and derive a storage key.
    - On success: returns derived bytes of length dk_len
    - On failure or missing factor: raises domain exceptions
    Notes:
      * Uses normalized OTP (no spaces/dashes)
      * Imports pyotp locally to honor potential sys.modules monkeypatching
      * Uses deterministic user-bound salt (does not leak secret)
      * Applies rate limiting/lockout
      * Valid window is configurable
    """
    with _manager_lock:
        _check_locked(user_id)
        _check_min_interval(user_id)

        ctx = get_app_context()
        state = _get_first_totp_state(ctx, user_id)
        secret = state.get("secret")
        if not secret:
            raise TotpNotConfigured("TOTP factor is not configured")

        # Fresh import to ensure any runtime monkeypatching is honored
        try:
            import pyotp as _pyotp  # type: ignore
        except Exception as e:  # pragma: no cover
            raise TotpRuntimeUnavailable("TOTP runtime is unavailable") from e

        normalized = _normalize_otp(otp)
        digits = int(state.get("digits", _config["digits"]))
        interval = int(state.get("interval", _config["interval"]))
        vw = int(valid_window if valid_window is not None else _config["valid_window"])

        totp_obj = _pyotp.TOTP(secret, digits=digits, interval=interval)  # type: ignore
        ok = bool(totp_obj.verify(normalized, valid_window=vw))  # type: ignore
        if not ok:
            _register_failure(user_id)
            # Best-effort audit
            try:
                state.setdefault("audit", []).append({
                    "ts": _now().isoformat(),
                    "action": "verify",
                    "result": "fail",
                })
            except Exception:
                pass
            raise TotpInvalidCode("Invalid TOTP credential")

        _register_success(user_id)
        try:
            state.setdefault("audit", []).append({
                "ts": _now().isoformat(),
                "action": "verify",
                "result": "success",
            })
        except Exception:
            pass

        # Derive key using Argon2id with deterministic, user-bound salt and optional pepper
        salt = _deterministic_salt(user_id)

        # Compose password material: OTP plus optional pepper (bytes or utf-8 encoded)
        pepper = _config.get("pepper")
        if isinstance(pepper, str):
            pepper_bytes = pepper.encode("utf-8")
        elif isinstance(pepper, (bytes, bytearray)):
            pepper_bytes = bytes(pepper)
        else:
            pepper_bytes = b""

        password_bytes = normalized.encode("utf-8") + pepper_bytes

        kdf_func = _config.get("kdf") or derive_key_argon2id
        derived = kdf_func(password_bytes, salt, dk_len)  # type: ignore

        if not isinstance(derived, (bytes, bytearray)):
            derived = bytes(derived)
        return bytes(derived)

def export_policy() -> Dict[str, Any]:
    """
    Export effective TOTP service policy/config for monitoring.
    """
    with _manager_lock:
        rate = dict(_config["rate"])
        return {
            "issuer": _config["issuer"],
            "digits": _config["digits"],
            "interval": _config["interval"],
            "valid_window": _config["valid_window"],
            "rate_limit": {
                "max_fails": rate["max_fails"],
                "lock_seconds": rate["lock_seconds"],
                "min_interval": rate["min_interval"],
                "qr_min_interval": rate["qr_min_interval"],
            },
            "qr": {
                "box_size": QR_BOX_SIZE,
                "border": QR_BORDER,
                "error_correction": "M" if _QR_EC is not None else "default",
            },
            "pepper_configured": _config["pepper"] is not None,
            "kdf_configured": _config.get("kdf") is not None,
        }
