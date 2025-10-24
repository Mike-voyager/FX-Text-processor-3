# -*- coding: utf-8 -*-
"""
Модуль: security/auth/second_method/totp.py

RU: TOTP (Time-based One-Time Password) второй фактор для FX Text Processor 3.
    Поддержка Google Authenticator, Authy, FreeOTP и других стандартных OTP-приложений.
    Генерация, хранение, проверка кода, запись метаданных, интеграция с SecondFactorManager.

EN: Enterprise-grade TOTP (RFC 6238) second factor with Google Authenticator, Authy,
    FreeOTP support, QR code generation, anti-replay protection, and audit trail.
"""

from __future__ import annotations

import pyotp
from typing import Optional, Dict, Any, List, Final
from datetime import datetime, timezone
from collections import OrderedDict

__all__ = [
    "TotpFactor",
    "TotpSecretMissing",
    "TotpVerificationFailed",
]

# ---- Constants ----
DEFAULT_ISSUER: Final[str] = "FX Text Processor"
DEFAULT_DIGITS: Final[int] = 6
DEFAULT_INTERVAL: Final[int] = 30  # seconds
VALID_WINDOW: Final[int] = 1  # accept codes ±1 time step


# ---- Exceptions ----
class TotpSecretMissing(ValueError):
    """TOTP secret not configured for user."""


class TotpVerificationFailed(RuntimeError):
    """TOTP code verification failed."""


# ---- Helpers ----
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_str() -> str:
    return _now().isoformat()


class TotpFactor:
    """
    TOTP (RFC 6238) second factor with QR code generation, anti-replay, and audit trail.

    Features:
    - Compatible with Google Authenticator, Authy, FreeOTP, etc.
    - QR code URI generation for easy setup
    - Anti-replay protection (prevents reuse of same code)
    - Configurable digits (6/8) and interval (30s)
    - Full audit trail of verification attempts
    - Secret rotation support

    Example:
        >>> factor = TotpFactor()
        >>> state = factor.setup("user123", username="alice@example.com")
        >>> qr_uri = factor.get_provisioning_uri(state)
        >>> # User scans QR code
        >>> factor.verify("user123", "123456", state)
        True
    """

    def setup(
        self,
        user_id: str,
        secret: Optional[str] = None,
        username: str = "",
        issuer: str = DEFAULT_ISSUER,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Initialize TOTP for user with secret and metadata.

        Args:
            user_id: User identifier
            secret: Base32-encoded secret (auto-generated if None)
            username: Display name for authenticator app (e.g., email)
            issuer: Service name displayed in authenticator app
            **kwargs: Additional metadata

        Returns:
            State dict with secret, metadata, and timestamps

        Example:
            >>> state = factor.setup("alice", username="alice@example.com")
            >>> state["secret"]
            'JBSWY3DPEHPK3PXP'
        """
        if not secret:
            secret = pyotp.random_base32()

        created_at = _now_str()

        return {
            "secret": secret,
            "created_at": created_at,
            "username": username or user_id,
            "issuer": issuer,
            "digits": DEFAULT_DIGITS,
            "interval": DEFAULT_INTERVAL,
            "rotated": False,
            "last_used_time_step": None,  # for anti-replay
            "audit": [],
        }

    def remove(self, user_id: str, state: Dict[str, Any]) -> None:
        """
        Remove TOTP secret and invalidate state (anti-forensics).

        Args:
            user_id: User identifier
            state: Current factor state

        Side effects:
            - Deletes secret from state
            - Appends removal event to audit log
        """
        now_str = _now_str()
        state["audit"] = state.get("audit", [])
        state["audit"].append({
            "action": "remove",
            "timestamp": now_str,
            "user_id": user_id,
        })
        if "secret" in state:
            del state["secret"]

    def verify(
        self,
        user_id: str,
        otp: str,
        state: Dict[str, Any],
        enable_anti_replay: bool = True,
    ) -> bool:
        """
        Verify TOTP code with optional anti-replay protection.

        Args:
            user_id: User identifier
            otp: 6-digit (or 8-digit) OTP code as string
            state: Current factor state
            enable_anti_replay: Enable replay detection (default: True)

        Returns:
            True if code is valid

        Raises:
            TotpSecretMissing: No secret configured
            TotpVerificationFailed: Invalid code or replay detected

        Example:
            >>> factor.verify("alice", "123456", state)
            True
        """
        secret = state.get("secret")
        if not secret:
            raise TotpSecretMissing("TOTP secret not configured")

        now_str = _now_str()
        audit = state.setdefault("audit", [])

        # Validate format first
        digits = state.get("digits", DEFAULT_DIGITS)
        if not self.validate_otp_format(otp, digits):
            audit.append({
                "timestamp": now_str,
                "result": "invalid_format",
                "otp": otp[:2] + "****" if len(otp) >= 2 else "****",
            })
            raise TotpVerificationFailed(f"Invalid OTP format (expected {digits} digits)")

        # Anti-replay check
        if enable_anti_replay:
            interval = state.get("interval", DEFAULT_INTERVAL)
            current_time_step = int(_now().timestamp() / interval)
            last_used_time_step = state.get("last_used_time_step")

            if last_used_time_step is not None and current_time_step <= last_used_time_step:
                audit.append({
                    "timestamp": now_str,
                    "result": "replay_detected",
                    "otp": otp[:2] + "****",
                    "time_step": current_time_step,
                })
                raise TotpVerificationFailed("Code already used (replay detected)")

        try:
            totp = pyotp.TOTP(
                secret,
                digits=digits,
                interval=state.get("interval", DEFAULT_INTERVAL),
            )
            is_valid = totp.verify(otp, valid_window=VALID_WINDOW)

            if is_valid:
                state["last_success_at"] = now_str
                if enable_anti_replay:
                    interval = state.get("interval", DEFAULT_INTERVAL)
                    state["last_used_time_step"] = int(_now().timestamp() / interval)

                audit.append({
                    "timestamp": now_str,
                    "result": "success",
                    "otp": otp[:2] + "****",  # partial masking
                })
                return True
            else:
                audit.append({
                    "timestamp": now_str,
                    "result": "fail",
                    "otp": otp[:2] + "****",
                })
                raise TotpVerificationFailed("Invalid TOTP code")

        except TotpVerificationFailed:
            raise
        except Exception as e:
            audit.append({
                "timestamp": now_str,
                "result": "error",
                "error": str(e),
            })
            raise TotpVerificationFailed(f"TOTP verification error: {e}") from e

    def is_secret_configured(self, state: Dict[str, Any]) -> bool:
        """
        Check if TOTP secret is configured.

        Args:
            state: Current factor state

        Returns:
            True if secret exists and is non-empty

        Example:
            >>> if factor.is_secret_configured(state):
            ...     factor.verify("alice", "123456", state)
        """
        return "secret" in state and state["secret"] is not None and state["secret"] != ""

    @staticmethod
    def validate_otp_format(otp: str, expected_digits: int = DEFAULT_DIGITS) -> bool:
        """
        Validate OTP format (digits only, correct length).

        Args:
            otp: OTP code to validate
            expected_digits: Expected number of digits (6 or 8)

        Returns:
            True if format is valid

        Example:
            >>> TotpFactor.validate_otp_format("123456", 6)
            True
            >>> TotpFactor.validate_otp_format("abc123", 6)
            False
        """
        return otp.isdigit() and len(otp) == expected_digits

    def get_provisioning_uri(self, state: Dict[str, Any]) -> str:
        """
        Generate provisioning URI for QR code.

        Args:
            state: Current factor state

        Returns:
            otpauth:// URI for QR code generation

        Raises:
            TotpSecretMissing: No secret configured

        Example:
            >>> uri = factor.get_provisioning_uri(state)
            >>> # Generate QR code from uri using qrcode library
            >>> # import qrcode
            >>> # img = qrcode.make(uri)
        """
        if not self.is_secret_configured(state):
            raise TotpSecretMissing("TOTP secret not configured")

        secret = state["secret"]
        username = state.get("username", "user")
        issuer = state.get("issuer", DEFAULT_ISSUER)
        digits = state.get("digits", DEFAULT_DIGITS)
        interval = state.get("interval", DEFAULT_INTERVAL)

        totp = pyotp.TOTP(secret, digits=digits, interval=interval)
        return totp.provisioning_uri(name=username, issuer_name=issuer)

    def rotate_secret(self, state: Dict[str, Any], new_secret: Optional[str] = None) -> str:
        """
        Rotate TOTP secret (for security refresh).

        Args:
            state: Current factor state
            new_secret: New secret (auto-generated if None)

        Returns:
            New secret (Base32-encoded)

        Side effects:
            - Updates secret in state
            - Marks as rotated
            - Resets anti-replay counter
            - Appends rotation event to audit

        Example:
            >>> new_secret = factor.rotate_secret(state)
            >>> new_uri = factor.get_provisioning_uri(state)
        """
        if not new_secret:
            new_secret = pyotp.random_base32()

        now_str = _now_str()
        state["secret"] = new_secret
        state["rotated"] = True
        state["rotated_at"] = now_str
        state["last_used_time_step"] = None  # reset anti-replay
        state.setdefault("audit", []).append({
            "action": "secret_rotated",
            "timestamp": now_str,
        })

        return new_secret

    def get_current_code(self, state: Dict[str, Any]) -> str:
        """
        Get current valid TOTP code (for testing/debugging only).

        Args:
            state: Current factor state

        Returns:
            Current 6-digit code

        Raises:
            TotpSecretMissing: No secret configured

        Warning:
            Use only in development/testing. Never expose in production UI.

        Example:
            >>> code = factor.get_current_code(state)  # for testing only
        """
        if not self.is_secret_configured(state):
            raise TotpSecretMissing("TOTP secret not configured")

        totp = pyotp.TOTP(
            state["secret"],
            digits=state.get("digits", DEFAULT_DIGITS),
            interval=state.get("interval", DEFAULT_INTERVAL),
        )
        return totp.now()

    def get_audit_log(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get full audit trail.

        Args:
            state: Current factor state

        Returns:
            List of audit events
        """
        return list(state.get("audit", []))

    def export_policy(self, deterministic: bool = True) -> Dict[str, Any]:
        """
        Export TOTP factor policy configuration.

        Args:
            deterministic: Return ordered dict for stable snapshots

        Returns:
            Policy dict with constants and configuration
        """
        data = {
            "default_issuer": DEFAULT_ISSUER,
            "default_digits": DEFAULT_DIGITS,
            "default_interval": DEFAULT_INTERVAL,
            "valid_window": VALID_WINDOW,
            "anti_replay_enabled": True,
            "rfc_standard": "RFC 6238",
        }
        if deterministic:
            return OrderedDict(sorted(data.items(), key=lambda kv: kv[0]))
        return data

    def export_audit(
        self,
        state: Dict[str, Any],
        deterministic: bool = True,
    ) -> Dict[str, Any]:
        """
        Export audit summary for monitoring.

        Args:
            state: Current factor state
            deterministic: Return ordered dict

        Returns:
            Audit summary with success count and timestamps
        """
        audit = state.get("audit", [])
        success_count = sum(1 for event in audit if event.get("result") == "success")
        fail_count = sum(1 for event in audit if event.get("result") == "fail")
        replay_count = sum(1 for event in audit if event.get("result") == "replay_detected")

        data = {
            "created_at": state.get("created_at"),
            "last_success_at": state.get("last_success_at"),
            "rotated": state.get("rotated", False),
            "rotated_at": state.get("rotated_at"),
            "audit_events": len(audit),
            "success_count": success_count,
            "fail_count": fail_count,
            "replay_count": replay_count,
        }
        if deterministic:
            return OrderedDict(sorted(data.items(), key=lambda kv: kv[0]))
        return data
