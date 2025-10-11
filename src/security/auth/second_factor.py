# src/security/auth/second_factor.py
"""
Менеджер второго фактора MFA/2FA для FX Text Processor 3.

Зашифрованное хранение, потокобезопасность, TTL, ротация, валидация, расширяемость через DI.
"""

import threading
import logging
import time
from typing import Dict, Any, List, Optional, Type

from src.security.crypto.secure_storage import SecureStorage
from .second_method.totp import TotpFactor
from .second_method.fido2 import Fido2Factor
from .second_method.code import BackupCodeFactor


class SecondFactorManager:
    """
    MFA/2FA production manager — хранит, выпускает, проверяет факторы.
    Все данные всегда зашифрованы; расшифровка только на момент операции.
    DI: SecureStorage и logger передаются параметрами конструктора.
    """

    def __init__(
        self,
        storage: SecureStorage,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._logger = logger or logging.getLogger("security.second_factor")
        self.storage = storage
        self._lock = threading.Lock()
        self._factor_registry: Dict[str, Type] = {
            "totp": TotpFactor,
            "fido2": Fido2Factor,
            "backupcode": BackupCodeFactor,
        }
        self._factors: Dict[str, Dict[str, List[dict]]] = {}
        self._audit: List[dict] = []
        self._load_storage()

    def _validate_user_id(self, user_id: str) -> None:
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in user_id):
            raise ValueError("user_id contains unsupported characters")

    def register_factor_type(self, name: str, cls: Type) -> None:
        if name in self._factor_registry:
            raise ValueError(f"Factor type {name} already registered")
        self._factor_registry[name] = cls

    def unregister_factor_type(self, name: str) -> None:
        if name in self._factor_registry:
            del self._factor_registry[name]

    def _load_storage(self) -> None:
        try:
            raw = self.storage.load()
            if raw:
                self._factors = raw.get("factors", {})
                self._audit = raw.get("audit", [])
                self._logger.info("Loaded MFA state from encrypted storage.")
            else:
                self._factors = {}
                self._audit = []
        except Exception as e:
            self._logger.error(f"Failed to load encrypted MFA state: {e}")
            self._factors = {}
            self._audit = []

    def _save_storage(self) -> None:
        try:
            payload = {
                "factors": self._factors,
                "audit": self._audit,
            }
            self.storage.save(payload)
            self._logger.info("Saved MFA state to encrypted storage.")
        except Exception as e:
            self._logger.error(f"Failed to save MFA state: {e}")

    def rotate_factor(
        self,
        user_id: str,
        factor_type: str,
        **kwargs: Any,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._validate_user_id(user_id)
            self.remove_factor(user_id, factor_type)
            self._logger.info(f"Rotating factor {factor_type} for {user_id}")
            self.setup_factor(user_id, factor_type, **kwargs)
            return self.get_status(user_id, factor_type)

    def _is_expired(self, state: Dict[str, Any]) -> bool:
        ttl = state.get("ttlseconds")
        created = state.get("created")
        if ttl and created:
            return (int(time.time()) - int(created)) > int(ttl)
        return False

    def _secure_del(self, d: Dict[str, Any], keys: Optional[List[str]] = None) -> None:
        if not keys:
            keys = [k for k in d.keys()]
        for k in keys:
            if k in d:
                d[k] = None

    def setup_factor(
        self,
        user_id: str,
        factor_type: str,
        **kwargs: Any,
    ) -> str:
        with self._lock:
            self._validate_user_id(user_id)
            factor_cls = self._factor_registry.get(factor_type)
            if factor_cls is None:
                raise ValueError(f"Unknown factor type: {factor_type}")
            instance = factor_cls()
            factor_state = instance.setup(user_id, **kwargs)
            if "ttlseconds" in kwargs and kwargs["ttlseconds"]:
                factor_state["ttlseconds"] = kwargs["ttlseconds"]
            factor_entry = {"state": factor_state, "ts": factor_state.get("created", 0)}
            self._factors.setdefault(user_id, {}).setdefault(factor_type, []).append(factor_entry)
            self._audit.append(
                {
                    "action": "setup",
                    "user": user_id,
                    "type": factor_type,
                    "ts": factor_state.get("created", 0),
                }
            )
            self._save_storage()
            self._secure_del(factor_state, ["secret", "seed", "credential", "backup_codes"])
            return factor_state.get("id", "") or str(factor_state.get("created", ""))

    def verify_factor(
        self,
        user_id: str,
        factor_type: str,
        credential: Any,
        factor_id: Optional[str] = None,
    ) -> bool:
        with self._lock:
            self._validate_user_id(user_id)
            factor_list = self._factors.get(user_id, {}).get(factor_type, [])
            if not factor_list:
                return False
            entry = next(
                (f for f in reversed(factor_list) if f["state"].get("id", "") == factor_id), None
            )
            if entry is None:
                entry = factor_list[-1]
            state = entry["state"]
            if self._is_expired(state):
                self._audit.append({"action": "expired", "user": user_id, "type": factor_type})
                return False
            factor_cls = self._factor_registry.get(factor_type)
            if factor_cls is None:
                return False
            instance = factor_cls()
            result = instance.verify(user_id, credential, state)
            self._audit.append(
                {"action": "verify", "user": user_id, "type": factor_type, "result": result}
            )
            self._save_storage()
            self._secure_del(state, ["secret", "seed", "credential", "backup_codes"])
            return bool(result)

    def remove_factor(
        self,
        user_id: str,
        factor_type: str,
        factor_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._validate_user_id(user_id)
            factor_list = self._factors.get(user_id, {}).get(factor_type, [])
            if not factor_list:
                return
            idx = None
            if factor_id:
                for i, entry in enumerate(factor_list):
                    if entry["state"].get("id", "") == factor_id:
                        idx = i
                        break
            if idx is None:
                idx = len(factor_list) - 1
            entry = factor_list[idx]
            factor_cls = self._factor_registry.get(factor_type)
            if factor_cls is not None:
                instance = factor_cls()
                instance.remove(user_id, entry["state"])
            self._secure_del(entry["state"])
            factor_list.pop(idx)
            self._audit.append({"action": "remove", "user": user_id, "type": factor_type})
            self._save_storage()

    def get_status(
        self,
        user_id: str,
        factor_type: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._validate_user_id(user_id)
            factor_list = self._factors.get(user_id, {}).get(factor_type, [])
            if not factor_list:
                return None
            return factor_list[-1]["state"]

    def get_audit(
        self,
        user_id: Optional[str] = None,
        factor_type: Optional[str] = None,
    ) -> List[dict]:
        with self._lock:
            history = self._audit
            if user_id:
                history = [rec for rec in history if rec.get("user") == user_id]
            if factor_type:
                history = [rec for rec in history if rec.get("type") == factor_type]
            return list(history)
