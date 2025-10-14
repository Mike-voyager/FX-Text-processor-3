# -*- coding: utf-8 -*-
"""
Модуль: second_method/code.py

Версия: Production+UX+Audit
Назначение: Экстремально стойкие одноразовые резервные коды (Backup/Recovery codes) с TTL, аудитом, блокировкой и поддержкой UX для FX Text Processor 3.
"""

import secrets
import time
from typing import Dict, Any, Tuple, Optional, List

CODE_BITS = 256
BLOCK_SIZE = 4
MAX_ATTEMPTS = 5
LOCK_SECONDS = 180
DEFAULT_TTL = 3600 * 24 * 90  # 90 дней


def format_code(raw_hex: str, block_size: int = BLOCK_SIZE) -> str:
    return "-".join(
        [raw_hex[i : i + block_size] for i in range(0, len(raw_hex), block_size)]
    )


class BackupCodeFactor:
    def setup(
        self,
        user_id: str,
        count: int = 10,
        ttl_seconds: int = DEFAULT_TTL,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        created: int = int(time.time())
        codes: list[Dict[str, Any]] = [
            {
                "raw": secrets.token_hex(CODE_BITS // 8),
                "code": "",  # будет отформатировано позже
                "used": False,
                "used_ts": None,
                "failed_attempts": 0,
            }
            for _ in range(count)
        ]
        # Формируем "красивый" код отдельно для каждого
        for c in codes:
            c["code"] = format_code(c["raw"])
        return {
            "codes": codes,
            "created": created,
            "ttl_seconds": ttl_seconds,
            "lock_until": 0,
            "audit": [],
        }

    def remove(self, user_id: str, state: Dict[str, Any]) -> None:
        """Удаляет все backup-коды и делает state невалидным (anti-forensics, SOC audit)."""
        now = int(time.time())
        state["codes"] = []
        state["lockuntil"] = now
        state["audit"] = state.get("audit", [])
        state["audit"].append({"action": "remove", "ts": now, "user_id": user_id})

    def verify(self, user_id: str, code: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Проверяет резервный код для пользователя.
        Возвращает dict:
          {"status": "success"|"fail"|"lockout"|"expired"|"used",
           "remaining_lock_sec": int,
           "audit": [...], ...}
        """
        now: int = int(time.time())
        audit = state.setdefault("audit", [])
        # Проверка TTL
        created = state.get("created", now)
        ttl_seconds = state.get("ttl_seconds", DEFAULT_TTL)
        if now > created + ttl_seconds:
            audit.append({"ts": now, "code": code, "result": "expired"})
            return {"status": "expired", "remaining_lock_sec": 0, "audit": audit}

        # Anti-brute-force lockout
        lock_until: int = state.get("lock_until", 0)
        remaining_lock_sec = max(0, lock_until - now)
        if now < lock_until:
            audit.append(
                {
                    "ts": now,
                    "code": code,
                    "result": "lockout",
                    "locked_for": remaining_lock_sec,
                }
            )
            return {
                "status": "lockout",
                "remaining_lock_sec": remaining_lock_sec,
                "audit": audit,
            }

        # Нормализуем формат кода (убираем дефисы и пробелы)
        normalized_code = code.replace("-", "").replace(" ", "").lower()
        for c in state.get("codes", []):
            candidate_code = c["raw"].lower()
            # Проверяем только неиспользованные
            if candidate_code == normalized_code and not c["used"]:
                c["used"] = True
                c["used_ts"] = now
                audit.append({"ts": now, "code": code, "result": "success"})
                # Сброс счетчика ошибок и блокировки
                c["failed_attempts"] = 0
                state["lock_until"] = 0
                return {"status": "success", "remaining_lock_sec": 0, "audit": audit}
            if candidate_code == normalized_code and c["used"]:
                audit.append({"ts": now, "code": code, "result": "used"})
                return {"status": "used", "remaining_lock_sec": 0, "audit": audit}
        # Неудачная попытка
        audit.append({"ts": now, "code": code, "result": "fail"})
        state["failed_attempts"] = state.get("failed_attempts", 0) + 1
        if state["failed_attempts"] >= MAX_ATTEMPTS:
            state["lock_until"] = now + LOCK_SECONDS
            state["failed_attempts"] = 0
            return {
                "status": "lockout",
                "remaining_lock_sec": LOCK_SECONDS,
                "audit": audit,
            }
        return {"status": "fail", "remaining_lock_sec": 0, "audit": audit}

    def expire(self, state: Dict[str, Any]) -> None:
        """Мягкая инвалидация всего batch кодов (например, по просьбе пользователя)."""
        now = int(time.time())
        for c in state.get("codes", []):
            if not c["used"]:
                c["used"] = True
                c["used_ts"] = now

    def get_active_codes(self, state: Dict[str, Any]) -> list[str]:
        """Вернуть только неиспользованные (форматированные) backup-коды для UI/экспорта."""
        return [c["code"] for c in state.get("codes", []) if not c["used"]]

    def get_audit_log(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Вернуть журнал всех успешных, ошибочных, использованных и заблокированных попыток."""
        return list(state.get("audit", []))

    def is_expired(self, state: Dict[str, Any]) -> bool:
        now = int(time.time())
        created = state.get("created", now)
        ttl_seconds = state.get("ttl_seconds", DEFAULT_TTL)
        return bool(now > created + ttl_seconds)
