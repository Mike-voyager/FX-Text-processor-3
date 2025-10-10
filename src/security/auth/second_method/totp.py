# -*- coding: utf-8 -*-
"""
Модуль: second_method/totp.py

Назначение: TOTP (Time-based One-Time Password) второй фактор для FX Text Processor 3.
- Поддержка Google Authenticator, Authy, FreeOTP и других стандартных OTP-приложений.
- Генерация, хранение, проверка кода, запись метаданных, интеграция с SecondFactorManager.
"""

import pyotp
import time
from typing import Optional, Dict, Any


class TotpFactor:
    """
    Реализация TOTP (RFC 6238) второго фактора.
    Методы:
      - setup(user_id, secret, username, issuer) -> dict: генерирует/сохраняет secret и метаданные.
      - remove(user_id) -> None: делегируется manager'у.
      - verify(user_id, otp, state) -> bool: проверяет OTP-код, может логировать результат.
    """

    def setup(
        self,
        user_id: str,
        secret: Optional[str] = None,
        username: str = "",
        issuer: str = "FX Text Processor",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if not secret:
            secret = pyotp.random_base32()
        created: int = int(time.time())
        return {
            "secret": secret,
            "created": created,
            "username": username,
            "issuer": issuer,
            "rotated": False,
        }

    def remove(self, user_id: str, state: Dict[str, Any]) -> None:
        """Безвозвратно удаляет секрет (anti-forensics), пишет audit."""
        now = int(time.time())
        state["audit"] = state.get("audit", [])
        state["audit"].append({"action": "remove", "ts": now, "user_id": user_id})
        if "secret" in state:
            del state["secret"]

    def verify(self, user_id: str, otp: str, state: dict) -> bool:
        secret = state.get("secret")
        if not secret:
            return False
        try:
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(otp, valid_window=1)
            if is_valid:
                state["last_success"] = int(time.time())
            return is_valid
        except Exception:
            return False
