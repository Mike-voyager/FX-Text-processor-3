# -*- coding: utf-8 -*-
"""
Модуль: second_factor.py
Назначение: Менеджер второго фактора MFA/2FA для FX Text Processor 3.

- Хранит одну или более конфигураций второго фактора на пользователя: TOTP, FIDO2/WebAuthn, backup-коды.
- Выпуск резервных кодов разрешен только аутентифицированному пользователю (через контроллер/интерфейс).
- Все backup-коды batch-структуры — одноразовые, у каждого кода свой флаг used и used_ts.
- TTL для резервных кодов — настраивается, автоматическая инвалидация по времени.
- Хранение всех секретов — в локальном зашифрованном хранилище (AES-256-GCM через SymmetricCipher).
- UI/экспорт/печать backup-кодов — вне этого модуля.
"""

from __future__ import annotations
import os
import time
import json
import threading
import logging
from typing import Any, Dict, List, Optional, Type

from .second_method.totp import TotpFactor
from .second_method.fido2 import Fido2Factor
from .second_method.code import BackupCodeFactor

from src.security.crypto.symmetric import SymmetricCipher


class SecondFactorManager:
    """
    Ядро жизненного цикла MFA/2FA факторов: хранение, выпуск, проверка, инвалидация, аудит.
    """

    _DEFAULT_STORAGE = "second_factors_store.bin"

    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        storage_path: Optional[str] = None,
        encryption_key: Optional[bytes] = None,
    ):
        self._logger = logger or logging.getLogger("security.second_factor")
        self._storage_path = storage_path or self._DEFAULT_STORAGE
        self._enc_key = encryption_key or SymmetricCipher.generatekey()
        self._lock = threading.Lock()
        self._factor_registry: Dict[str, Type] = {
            "totp": TotpFactor,
            "fido2": Fido2Factor,
            "backup_code": BackupCodeFactor,
        }
        # user_id -> factor_type -> list of factor dicts {id, created, state, ttl, codes:[{code, used, used_ts}] ...}
        self._factors: Dict[str, Dict[str, List[dict]]] = {}
        self._audit_log: List[dict] = []
        self.load()

    def is_any_factor_configured(self, user_id: str) -> bool:
        return user_id in self._factors and any(self._factors[user_id].values())

    def available_factors(self, user_id: str) -> List[str]:
        return list(self._factors.get(user_id, {}).keys())

    def setup_factor(self, user_id: str, factor_type: str, **params) -> str:
        if factor_type not in self._factor_registry:
            raise ValueError(f"Unknown factor type: {factor_type}")
        with self._lock:
            self._factors.setdefault(user_id, {})
            factor_class = self._factor_registry[factor_type]
            factor_instance = factor_class()
            factor_state = factor_instance.setup(user_id, **params)
            factor_id = params.get("factor_id") or os.urandom(8).hex()
            created = int(time.time())
            ttl = int(params.get("ttl_sec", 604800)) if factor_type == "backup_code" else None
            # Для backup_code создаем batch codes со структурой [{code, used, used_ts}]
            if factor_type == "backup_code":
                codes = [
                    {"code": c, "used": False, "used_ts": None}
                    for c in factor_state.get("codes", [])
                ]
                factor_state["codes"] = codes
            self._factors[user_id].setdefault(factor_type, []).append(
                dict(id=factor_id, state=factor_state, created=created, ttl=ttl)
            )
            self._audit_log.append(
                {
                    "ts": created,
                    "user_id": user_id,
                    "op": "setup",
                    "type": factor_type,
                    "factor_id": factor_id,
                }
            )
            self.save()
            self._logger.info("Setup %s factor for user=%s id=%s", factor_type, user_id, factor_id)
        return factor_id

    def remove_factor(
        self, user_id: str, factor_type: str, factor_id: Optional[str] = None
    ) -> None:
        with self._lock:
            f_list = self._factors.get(user_id, {}).get(factor_type, [])
            if factor_id is None:
                self._factors[user_id][factor_type] = []
            else:
                self._factors[user_id][factor_type] = [f for f in f_list if f["id"] != factor_id]
            self._audit_log.append(
                {
                    "ts": time.time(),
                    "user_id": user_id,
                    "op": "remove",
                    "type": factor_type,
                    "factor_id": factor_id,
                }
            )
            self.save()
            self._logger.info("Removed %s for user=%s id=%s", factor_type, user_id, factor_id)

    def verify_factor(
        self,
        user_id: str,
        factor_type: str,
        credential: str | dict,
        factor_id: Optional[str] = None,
    ) -> bool:
        factors = self._factors.get(user_id, {}).get(factor_type, [])
        now = int(time.time())
        for factor in factors:
            if factor_id and factor["id"] != factor_id:
                continue
            if factor_type == "backup_code":
                ttl = factor.get("ttl", 604800)
                if now > factor["created"] + ttl:
                    continue
                for c in factor["state"].get("codes", []):
                    if c["code"] == credential and not c["used"]:
                        c["used"] = True
                        c["used_ts"] = now
                        self._audit_log.append(
                            {
                                "ts": now,
                                "user_id": user_id,
                                "op": "backup_code_used",
                                "factor_id": factor["id"],
                                "code": credential,
                            }
                        )
                        self.save()
                        self._logger.info(
                            "Backup code used for user=%s, code=%s", user_id, credential
                        )
                        return True
            else:
                ok = self._factor_registry[factor_type]().verify(
                    user_id, credential, factor["state"]
                )
                if ok:
                    self._audit_log.append(
                        {
                            "ts": now,
                            "user_id": user_id,
                            "op": "verify",
                            "type": factor_type,
                            "factor_id": factor["id"],
                        }
                    )
                    return True
        return False

    def issue_backup_codes(self, user_id: str, count: int = 10, ttl_sec: int = 604800) -> List[str]:
        """Create new batch backup codes; returns codes for UI printing/export."""
        factor_id = self.setup_factor(user_id, "backup_code", count=count, ttl_sec=ttl_sec)
        return self._get_backup_codes_for_factor(user_id, factor_id)

    def _get_backup_codes_for_factor(self, user_id: str, factor_id: str) -> List[str]:
        for factor in self._factors.get(user_id, {}).get("backup_code", []):
            if factor["id"] == factor_id:
                return [c["code"] for c in factor["state"]["codes"]]
        return []

    def save(self) -> None:
        """Сохраняет состояние в файл с AES-256-GCM."""
        raw = json.dumps(
            {"factors": self._factors, "audit": self._audit_log}, ensure_ascii=False
        ).encode("utf-8")
        nonce = SymmetricCipher.generatenonce()
        ciphertext = SymmetricCipher.encrypt(raw, self._enc_key, nonce)
        with open(self._storage_path, "wb") as f:
            f.write(nonce + ciphertext)

    def load(self) -> None:
        """Восстанавливает состояние из файла, расшифровка через AES-256-GCM."""
        if not os.path.exists(self._storage_path):
            return
        with open(self._storage_path, "rb") as f:
            buf = f.read()
        nonce = buf[: SymmetricCipher.NONCELENGTH]
        ct = buf[SymmetricCipher.NONCELENGTH :]
        raw = SymmetricCipher.decrypt(ct, self._enc_key, nonce)
        store = json.loads(raw.decode("utf-8"))
        self._factors = store.get("factors", {})
        self._audit_log = store.get("audit", [])


# SRP: вся визуализация, показ или печать backup-кодов — реализуется только во внешнем слое (контроллер/интерфейс).
