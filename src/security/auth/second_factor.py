# -*- coding: utf-8 -*-
"""
Менеджер второго фактора (MFA/2FA) FX Text Processor 3.
RU: Централизует хранение и управление всеми факторами (TOTP, FIDO2, Backup Codes), поддерживает расширяемый DI, TTL, аудит, потокобезопасность.
EN: Centralized MFA/2FA manager for factor lifecycle and audit, supporting extensible DI, TTL, thread safety.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import (
    Any,
    Dict,
    Final,
    List,
    Optional,
    Protocol,
    Type,
    cast,
    runtime_checkable,
)

from src.security.crypto.core.protocols import KeyStoreProtocol  # type: ignore

from .second_method.code import BackupCodeFactor
from .second_method.fido2 import Fido2Factor

# Факторы: импорт строго через Protocol для расширяемости и типизации
from .second_method.totp import TotpFactor


@runtime_checkable
class FactorProtocol(Protocol):
    """
    EN: Abstract protocol for second factor implementation (TOTP, FIDO2, BackupCode).
    Signature must match for DI registration.
    """

    def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]: ...
    def verify(
        self, user_id: str, credential: Any, state: Dict[str, Any], **kwargs: Any
    ) -> Any: ...
    def remove(self, user_id: str, state: Dict[str, Any]) -> None: ...


def _now_ts() -> int:
    return int(time.time())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_created_ts(state: Dict[str, Any]) -> int:
    created_at = state.get("created_at")
    if isinstance(created_at, str):
        try:
            return int(datetime.fromisoformat(created_at).timestamp())
        except Exception:
            pass
    created = state.get("created")
    try:
        return int(created) if created is not None else _now_ts()
    except Exception:
        return _now_ts()


def _state_is_expired(state: Dict[str, Any]) -> bool:
    ttl = state.get("ttlseconds") or state.get("ttl_seconds")
    if not ttl:
        return False
    try:
        ttl_i = int(ttl)
    except Exception:
        return False
    created_ts = _state_created_ts(state)
    return (_now_ts() - created_ts) > ttl_i


def _copy_for_public(state: Dict[str, Any]) -> Dict[str, Any]:
    # Redact secrets for public export
    redacted = dict(state)
    for k in ("secret", "seed", "credential", "backup_codes", "private_key", "sk"):
        if k in redacted:
            redacted[k] = "****"
    return redacted


_STORAGE_ITEM: Final[str] = "mfa_state"


class SecondFactorManager:
    """
    Production MFA/2FA manager for factor lifecycle, secure storage, DI registry, audit and TTL.
    All key operations are thread-safe and extensible via DI.
    Example usage:
        >>> mgr = SecondFactorManager(get_keystore())
        >>> mgr.setup_factor("uid1", "totp", interval=30)
        >>> ok = mgr.verify_factor("uid1", "totp", otp="123456")
    """

    def __init__(
        self, storage: KeyStoreProtocol, logger: Optional[logging.Logger] = None
    ) -> None:
        self._logger = logger or logging.getLogger("security.second_factor")
        self._lock = threading.RLock()
        self._storage: KeyStoreProtocol = storage

        # Extensible registry: enforce FactorProtocol compliance
        self._factor_registry: Dict[str, Type[FactorProtocol]] = {}
        self.register_factor_type("totp", cast(Type[FactorProtocol], TotpFactor))
        self.register_factor_type("fido2", cast(Type[FactorProtocol], Fido2Factor))
        self.register_factor_type(
            "backupcode", cast(Type[FactorProtocol], BackupCodeFactor)
        )

        self._factors: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        self._audit: List[Dict[str, Any]] = []
        self._load_storage()

    # ---------- Persistence ----------

    def _load_storage(self) -> None:
        try:
            raw_bytes = self._storage.load(_STORAGE_ITEM)
        except KeyError:
            raw_bytes = b""
        except Exception as e:
            self._logger.error("Failed to load encrypted MFA state: %s", e)
            raw_bytes = b""
        if not raw_bytes:
            self._factors = {}
            self._audit = []
            self._logger.debug("MFA state not found, starting fresh")
            return
        try:
            obj = json.loads(raw_bytes.decode("utf-8"))
            self._factors = cast(
                Dict[str, Dict[str, List[Dict[str, Any]]]], obj.get("factors", {})
            )
            self._audit = cast(List[Dict[str, Any]], obj.get("audit", []))
            self._logger.debug(
                "Loaded MFA state from keystore item '%s'", _STORAGE_ITEM
            )
        except Exception as e:
            self._logger.error("Failed to parse MFA state JSON: %s", e)
            self._factors = {}
            self._audit = []

    def _save_storage(self) -> None:
        try:
            payload = {
                "factors": self._factors,
                "audit": self._audit,
            }
            data = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            self._storage.save(_STORAGE_ITEM, data)
            self._logger.debug("Saved MFA state to keystore item '%s'", _STORAGE_ITEM)
        except Exception as e:
            self._logger.error("Failed to save MFA state: %s", e)

    # ---------- Registry ----------

    def register_factor_type(self, name: str, cls: Type[FactorProtocol]) -> None:
        if name in self._factor_registry:
            raise ValueError(f"Factor type {name} already registered")
        # Protocol compliance
        required = ["setup", "verify", "remove"]
        missing = [m for m in required if not hasattr(cls, m)]
        if missing:
            raise TypeError(f"Registered factor missing methods: {missing}")
        self._factor_registry[name] = cls

    def unregister_factor_type(self, name: str) -> None:
        if name in self._factor_registry:
            del self._factor_registry[name]

    # ---------- Validation ----------

    def _validate_user_id(self, user_id: str) -> None:
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in user_id):
            raise ValueError("user_id contains unsupported characters")

    def _validate_factor_type(self, factor_type: str) -> None:
        if not isinstance(factor_type, str) or not factor_type.strip():
            raise ValueError("factor_type must be a non-empty string")
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in factor_type):
            raise ValueError("factor_type contains unsupported characters")

    # ---------- Core operations ----------

    def setup_factor(
        self,
        user_id: str,
        factor_type: str,
        **kwargs: Any,
    ) -> str:
        """
        Issue MFA factor by type, persist securely, return factor ID.
        Args:
            user_id: User identifier (str).
            factor_type: Factor type name (str).
            **kwargs: Factor-specific options.
        Returns:
            str: Factor ID.
        Raises:
            ValueError: If user/factor invalid or missing registry.
        """
        with self._lock:
            self._validate_user_id(user_id)
            self._validate_factor_type(factor_type)
            factor_cls = self._factor_registry.get(factor_type)
            if factor_cls is None:
                raise ValueError(f"Unknown factor type: {factor_type}")

            instance = factor_cls()
            factor_state = instance.setup(user_id, **kwargs)
            if not factor_state.get("id"):
                factor_state["id"] = uuid.uuid4().hex
            if "ttlseconds" in kwargs and kwargs["ttlseconds"]:
                factor_state["ttlseconds"] = kwargs["ttlseconds"]
            if "created_at" not in factor_state:
                factor_state["created_at"] = _now_iso()
            if "created" not in factor_state:
                try:
                    factor_state["created"] = int(
                        datetime.fromisoformat(factor_state["created_at"]).timestamp()
                    )
                except Exception:
                    factor_state["created"] = _now_ts()

            entry = {
                "state": factor_state,
                "ts": _state_created_ts(factor_state),
            }
            self._factors.setdefault(user_id, {}).setdefault(factor_type, []).append(
                entry
            )
            self._audit.append(
                {
                    "action": "setup",
                    "user": user_id,
                    "type": factor_type,
                    "id": factor_state.get("id"),
                    "ts": _now_iso(),
                }
            )
            self._save_storage()
            return cast(str, factor_state.get("id")) or str(
                factor_state.get("created", "")
            )

    def verify_factor(
        self,
        user_id: str,
        factor_type: str,
        credential: Any,
        factor_id: Optional[str] = None,
        **kwargs: Any,
    ) -> bool:
        """
        Verify MFA factor (by id or latest), audit result.
        Args:
            user_id (str): User identifier.
            factor_type (str): Factor type name.
            credential (Any): MFA credential to verify.
            factor_id (str, optional): Factor ID, if not latest.
            **kwargs (Any): Extra parameters passed to factor's verify.
        Returns:
            bool: True if verification passed, else False.
        """
        with self._lock:
            self._validate_user_id(user_id)
            self._validate_factor_type(factor_type)
            factor_list = self._factors.get(user_id, {}).get(factor_type, [])
            if not factor_list:
                return False

            entry = None
            if factor_id:
                for f in reversed(factor_list):
                    if f["state"].get("id", "") == factor_id:
                        entry = f
                        break
            if entry is None:
                entry = factor_list[-1]
            state = entry["state"]

            if _state_is_expired(state):
                self._audit.append(
                    {
                        "action": "expired",
                        "user": user_id,
                        "type": factor_type,
                        "id": state.get("id"),
                        "ts": _now_iso(),
                    }
                )
                self._save_storage()
                return False

            factor_cls = self._factor_registry.get(factor_type)
            if factor_cls is None:
                return False

            instance = factor_cls()
            ok = False
            reason: Optional[str] = None

            try:
                result = instance.verify(user_id, credential, state, **kwargs)
                if isinstance(result, bool):
                    ok = result
                elif isinstance(result, dict):
                    status = result.get("status")
                    ok = bool(
                        status == "success" or result.get("ok") or result.get("valid")
                    )
                    reason = result.get("detail") or result.get("reason")
                else:
                    ok = bool(result)
            except Exception as e:
                ok = False
                reason = f"exception:{e}"

            self._audit.append(
                {
                    "action": "verify",
                    "user": user_id,
                    "type": factor_type,
                    "id": state.get("id"),
                    "result": ok,
                    "reason": reason,
                    "ts": _now_iso(),
                }
            )
            self._save_storage()
            return ok

    def remove_factor(
        self,
        user_id: str,
        factor_type: str,
        factor_id: Optional[str] = None,
    ) -> None:
        """
        Remove a specific factor instance (by id or latest) and persist changes.
        Args:
            user_id (str): User identifier.
            factor_type (str): Type of factor.
            factor_id (str, optional): Factor id.
        """
        with self._lock:
            self._validate_user_id(user_id)
            self._validate_factor_type(factor_type)
            factor_list = self._factors.get(user_id, {}).get(factor_type, [])
            if not factor_list:
                return

            idx: Optional[int] = None
            if factor_id:
                for i, entry in enumerate(factor_list):
                    if entry["state"].get("id", "") == factor_id:
                        idx = i
                        break
            if idx is None:
                idx = len(factor_list) - 1
            entry = factor_list[idx]
            state = entry["state"]

            factor_cls = self._factor_registry.get(factor_type)
            if factor_cls is not None:
                try:
                    instance = factor_cls()
                    instance.remove(user_id, state)
                except Exception as e:
                    self._logger.warning("Factor remove failed: %s", e)
            try:
                del factor_list[idx]
            except Exception:
                pass
            if (
                user_id in self._factors
                and factor_type in self._factors[user_id]
                and not self._factors[user_id][factor_type]
            ):
                try:
                    del self._factors[user_id][factor_type]
                except Exception:
                    pass
                if user_id in self._factors and not self._factors[user_id]:
                    try:
                        del self._factors[user_id]
                    except Exception:
                        pass
            self._audit.append(
                {
                    "action": "remove",
                    "user": user_id,
                    "type": factor_type,
                    "id": state.get("id"),
                    "ts": _now_iso(),
                }
            )
            self._save_storage()

    def remove_all_factors(
        self,
        user_id: str,
        factor_type: str,
    ) -> None:
        """
        Remove all factors of given type for user (irreversible).
        Args:
            user_id (str): User identifier.
            factor_type (str): Type of factor.
        """
        with self._lock:
            self._validate_user_id(user_id)
            self._validate_factor_type(factor_type)
            factors_by_user = self._factors.get(user_id)
            if not factors_by_user or factor_type not in factors_by_user:
                self._save_storage()
                return
            for entry in list(reversed(factors_by_user[factor_type])):
                fid = entry["state"].get("id", "")
                self.remove_factor(user_id, factor_type, factor_id=fid)

    # ---------- Read operations ----------

    def get_status(
        self, user_id: str, factor_type: str, *, redact: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Get latest factor status (optionally redacted).
        """
        with self._lock:
            self._validate_user_id(user_id)
            self._validate_factor_type(factor_type)
            factor_list = self._factors.get(user_id, {}).get(factor_type, [])
            if not factor_list:
                return None
            state = cast(Dict[str, Any], factor_list[-1]["state"])
            return _copy_for_public(state) if redact else dict(state)

    def get_status_public(
        self, user_id: str, factor_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Public factor status for UI: returns ID, timestamps, TTL etc.
        """
        st = self.get_status(user_id, factor_type, redact=True)
        if not st:
            return None
        pub = {
            "id": st.get("id"),
            "created_at": st.get("created_at"),
            "ttlseconds": st.get("ttlseconds") or st.get("ttl_seconds"),
            "name": st.get("name"),
            "type": st.get("type"),
        }
        return {k: v for k, v in pub.items() if v is not None}

    def get_history(
        self, user_id: str, factor_type: str, *, redact: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Return history of issued factors.
        """
        with self._lock:
            self._validate_user_id(user_id)
            self._validate_factor_type(factor_type)
            records = [
                entry["state"]
                for entry in self._factors.get(user_id, {}).get(factor_type, [])
            ]
            if not redact:
                return [dict(r) for r in records]
            return [_copy_for_public(r) for r in records]

    def get_audit(
        self, user_id: Optional[str] = None, factor_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Return operation audit log (optionally filtered).
        """
        with self._lock:
            history = self._audit
            if user_id:
                history = [rec for rec in history if rec.get("user") == user_id]
            if factor_type:
                history = [rec for rec in history if rec.get("type") == factor_type]
            return list(history)

    # ---------- Discovery ops ----------

    def list_factors(self, user_id: str) -> Dict[str, List[str]]:
        """
        List factor types and their IDs for given user.
        """
        with self._lock:
            self._validate_user_id(user_id)
            out: Dict[str, List[str]] = {}
            user_map = self._factors.get(user_id, {})
            for ftype, items in user_map.items():
                out[ftype] = [cast(str, e["state"].get("id", "")) for e in items]
            return out

    def list_factor_ids(self, user_id: str, factor_type: str) -> List[str]:
        """
        List factor IDs of given type for user.
        """
        with self._lock:
            self._validate_user_id(user_id)
            self._validate_factor_type(factor_type)
            items = self._factors.get(user_id, {}).get(factor_type, [])
            return [cast(str, e["state"].get("id", "")) for e in items]
