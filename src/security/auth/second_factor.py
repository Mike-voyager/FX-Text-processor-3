# src/security/auth/second_factor.py
"""
Менеджер второго фактора MFA/2FA для FX Text Processor 3.

Зашифрованное хранение, потокобезопасность, TTL, ротация, валидация, расширяемость через DI.
"""

import threading
import logging
import time
from typing import Dict, Any, List, Optional, Type, cast

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
        self._lock = threading.RLock()
        self._factor_registry: Dict[str, Type] = {
            "totp": TotpFactor,
            "fido2": Fido2Factor,
            "backupcode": BackupCodeFactor,
        }
        self._factors: Dict[str, Dict[str, List[dict]]] = {}
        self._audit: List[dict] = []
        self._load_storage()

    def _validate_user_id(self, user_id: str) -> None:
        """Checks correctness of user_id (non-empty ASCII string)"""
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in user_id):
            raise ValueError("user_id contains unsupported characters")

    def register_factor_type(self, name: str, cls: Type) -> None:
        """Registers additional factor (extensible design)"""
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
        """Удаляет и выпускает новый фактор выбранного типа (safe rotate)."""
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
        """Best effort RAM wipe: удаляет ключи из dict и максимум затирает содержимое, если строка/bytearray."""
        if not keys:
            keys = [k for k in d.keys()]
        for k in keys:
            if k in d:
                v = d[k]
                try:
                    if isinstance(v, bytearray):
                        for i in range(len(v)):
                            v[i] = 0
                    elif isinstance(v, str):
                        d[k] = "\0" * len(v)
                except Exception:
                    pass
                del d[k]

    def setup_factor(
        self,
        user_id: str,
        factor_type: str,
        **kwargs: Any,
    ) -> str:
        """Выпускает фактор выбранного типа и возвращает его ID (или время создания в виде строки)."""
        with self._lock:
            self._validate_user_id(user_id)
            factor_cls = self._factor_registry.get(factor_type)
            if factor_cls is None:
                raise ValueError(f"Unknown factor type: {factor_type}")
            instance = factor_cls()
            factor_state = instance.setup(user_id, **kwargs)
            if "ttlseconds" in kwargs and kwargs["ttlseconds"]:
                factor_state["ttlseconds"] = kwargs["ttlseconds"]
            # лейбл для новых версий факторов (future: v2+, поддержка "истории")
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
            # Явно возвращаем либо ID, либо строку с created (всегда может восстановить по get_history)
            return factor_state.get("id", "") or str(factor_state.get("created", ""))

    def verify_factor(
        self,
        user_id: str,
        factor_type: str,
        credential: Any,
        factor_id: Optional[str] = None,
    ) -> bool:
        """Проверяет MFA фактор (по factor_id или последнему).
        Фиксирует действие в аудите, чистит RAM после завершения"""
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
        """Удаляет один фактор (по factor_id или последний).
        Для полного удаления всех факторов типа используйте remove_all_factors."""
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

    def remove_all_factors(
        self,
        user_id: str,
        factor_type: str,
    ) -> None:
        """Удаляет все факторы данного типа для пользователя (поведение CI теряет все generation-версии!)."""
        with self._lock:
            self._validate_user_id(user_id)
            factors_by_user = self._factors.get(user_id)
            if not factors_by_user or factor_type not in factors_by_user:
                self._save_storage()
                return
            factor_list = factors_by_user[factor_type]
            while factor_list:
                self.remove_factor(
                    user_id, factor_type, factor_id=factor_list[-1]["state"].get("id", "")
                )
            # После удаления всех факторов — чистим структуру, если нужно
            if user_id in self._factors and factor_type in self._factors[user_id]:
                del self._factors[user_id][factor_type]
                if not self._factors[user_id]:
                    del self._factors[user_id]
            self._save_storage()

    def get_status(
        self,
        user_id: str,
        factor_type: str,
    ) -> Optional[Dict[str, Any]]:
        """Краткая информация о последнем факторе user/factor_type"""
        with self._lock:
            self._validate_user_id(user_id)
            factor_list = self._factors.get(user_id, {}).get(factor_type, [])
            if not factor_list:
                return None
            return cast(Dict[str, Any], factor_list[-1]["state"])

    def get_history(
        self,
        user_id: str,
        factor_type: str,
    ) -> List[Dict[str, Any]]:
        """Возвращает историю всех выпусков данного фактора для пользователя (генерации/экспирации)"""
        with self._lock:
            self._validate_user_id(user_id)
            return [entry["state"] for entry in self._factors.get(user_id, {}).get(factor_type, [])]

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


# Конец production version.
