# src/security/auth/second_factor_service.py
"""
Сервисный слой/Thin API над SecondFactorManager для всех операций MFA/2FA.
Интеграция через AppContext/DI.
Внедрены:
1. Exception/обработка ошибок
2. Логирование ошибок и инцидентов
3. Валидация входных данных
4. TypedDict для ответов
5. Docstrings с примерами
"""

from typing import Any, Dict, Optional, List, TypedDict, Union
import logging

from src.app_context import get_app_context
from src.security.auth.second_factor import SecondFactorManager

# --- Typed Response Contracts ---


class FactorStatus(TypedDict, total=False):
    secret: str
    uri: str
    qr: bytes
    state: Dict[str, Any]
    valid: bool
    expired: bool
    error: Optional[str]


class AuditRecord(TypedDict, total=False):
    action: str
    user: str
    type: str
    ts: int
    result: Union[bool, str, None]
    error: Optional[str]


# --- Service Implementation ---

_ctx = get_app_context()
_manager: SecondFactorManager = _ctx.mfa_manager


def _log_and_return_error(fn: str, exc: Exception) -> FactorStatus:
    logging.error("SecondFactorService [%s] error: %s", fn, exc)
    return FactorStatus(valid=False, error=str(exc), state={})


def _validate_input(user_id: str, factor_type: Optional[str] = None) -> None:
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id must be a non-empty string")
    if factor_type is not None and (not isinstance(factor_type, str) or not factor_type.strip()):
        raise ValueError("factor_type must be a non-empty string")


def setup_factor(
    user_id: str,
    factor_type: str,
    **kwargs: Any,
) -> FactorStatus:
    """
    Create a new factor for user.
    Args:
        user_id: User identifier (str)
        factor_type: Factor type ("totp", "fido2", "backupcode", ...)
        kwargs: Extra parameters
    Returns:
        FactorStatus TypedDict or error
    Example:
        >>> setup_factor("user", "totp", username="user", issuer="App")
    """
    try:
        _validate_input(user_id, factor_type)
        factor_id = _manager.setup_factor(user_id, factor_type, **kwargs)
        state = _manager.get_status(user_id, factor_type) or {}
        return FactorStatus(valid=True, state=state)
    except Exception as e:
        return _log_and_return_error("setup_factor", e)


def verify_factor(
    user_id: str,
    factor_type: str,
    credential: Any,
    factor_id: Optional[str] = None,
) -> FactorStatus:
    """
    Verify a credential for given factor type.
    Returns FactorStatus (valid/error).
    """
    try:
        _validate_input(user_id, factor_type)
        valid = _manager.verify_factor(user_id, factor_type, credential, factor_id)
        status = _manager.get_status(user_id, factor_type) or {}
        expired = False
        if status.get("ttlseconds") and status.get("created"):
            import time

            expired = (int(time.time()) - int(status["created"])) > int(status["ttlseconds"])
        return FactorStatus(valid=bool(valid and not expired), expired=expired, state=status)
    except Exception as e:
        return _log_and_return_error("verify_factor", e)


def remove_factor(
    user_id: str,
    factor_type: str,
    factor_id: Optional[str] = None,
) -> FactorStatus:
    """
    Remove (delete) a factor for user.
    Returns FactorStatus/err.
    """
    try:
        _validate_input(user_id, factor_type)
        _manager.remove_factor(user_id, factor_type, factor_id)
        return FactorStatus(valid=True, state={})
    except Exception as e:
        return _log_and_return_error("remove_factor", e)


def rotate_factor(
    user_id: str,
    factor_type: str,
    **kwargs: Any,
) -> FactorStatus:
    """
    Rotate (remove + create) a new factor for user.
    Returns new status or error.
    """
    try:
        _validate_input(user_id, factor_type)
        state = _manager.rotate_factor(user_id, factor_type, **kwargs) or {}
        return FactorStatus(valid=True, state=state)
    except Exception as e:
        return _log_and_return_error("rotate_factor", e)


def get_factor_status(
    user_id: str,
    factor_type: str,
) -> FactorStatus:
    """
    Get current factor status for user/type.
    """
    try:
        _validate_input(user_id, factor_type)
        state = _manager.get_status(user_id, factor_type) or {}
        if not state:
            return FactorStatus(valid=False, error="no status", state={})
        return FactorStatus(valid=True, state=state)
    except Exception as e:
        return _log_and_return_error("get_factor_status", e)


def get_factor_audit(
    user_id: Optional[str] = None,
    factor_type: Optional[str] = None,
) -> List[AuditRecord]:
    """
    Get audit records (optionally filtered by user/factor).
    Returns: List of AuditRecord
    """
    try:
        return _manager.get_audit(user_id, factor_type)  # type: ignore
    except Exception as e:
        logging.error("SecondFactorService [get_factor_audit] error: %s", e)
        return [
            AuditRecord(
                action="audit_exception",
                user=str(user_id),
                type=str(factor_type),
                result=None,
                error=str(e),
            )
        ]


def register_factor_type(
    name: str,
    cls: type,
) -> FactorStatus:
    """
    Register a new factor (dynamic extension).
    """
    try:
        _manager.register_factor_type(name, cls)
        return {"valid": True}
    except Exception as e:
        return _log_and_return_error("register_factor_type", e)


def unregister_factor_type(
    name: str,
) -> FactorStatus:
    """
    Unregister a previously dynamically registered factor.
    """
    try:
        _manager.unregister_factor_type(name)
        return {"valid": True}
    except Exception as e:
        return _log_and_return_error("unregister_factor_type", e)
