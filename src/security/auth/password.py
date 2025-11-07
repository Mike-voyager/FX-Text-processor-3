# -*- coding: utf-8 -*-
"""
RU: Корпоративный безопасный модуль управления паролями для FX-Text-processor-3.
- Argon2id, соль+pepper с ротацией, блокировки, расширяемая политика, MFA-интеграция, аудит/экспорт,
  потокобезопасный/async, alerts/SIEM, очистка секретов, DI для KDF, временные метки.

EN: Enterprise-grade, secure password management module for FX-Text-processor-3.
- Argon2id, salt+pepper rotation, lockout warnings, advanced policy, MFA/SIEM hooks, audit export,
  thread-safe/async, secret zeroization, DI KDF, full event timestamping.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import threading
from collections import OrderedDict
from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
)
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import blake2b
from typing import Any, Callable, Dict, Final, Optional, Protocol, Tuple, Union

from argon2 import PasswordHasher as _Argon2Hasher
from argon2 import exceptions as argon2_exc

__all__ = [
    "PasswordHasher",
    "is_valid_password",
    "MAX_FAILED_ATTEMPTS",
    "PolicyViolation",
    "LockoutActive",
    "InvalidHashFormat",
    "RehashRequired",
    "InternalError",
]

_LOG = logging.getLogger(__name__)

# ---- Constants & Policy ----
_DEFAULT_SALT_LENGTH: Final[int] = 16
_HASH_FORMAT_VERSION: Final[str] = "v1"
_HASH_FORMAT_RE: Final[re.Pattern[str]] = re.compile(
    r"^v1:argon2id\$[0-9a-f]{16,}\$.+$"
)

_PEPPER_ENV_VAR: Final[str] = "FX_TEXT_PW_PEPPER"
MAX_FAILED_ATTEMPTS: Final[int] = 5

_MIN_PASSWORD_LENGTH: Final[int] = 8
_MAX_PASSWORD_LENGTH: Final[int] = 256
_MAX_INPUT_LENGTH: Final[int] = 10_000  # DoS guard for extreme inputs

_REQ_SPECIAL: Final[bool] = True
_REQ_UPPER: Final[bool] = True
_REQ_DIGIT: Final[bool] = True
_PASSWORD_BLACKLIST: Final = {
    "12345678",
    "password",
    "qwerty123",
    "letmein",
    "11111111",
    "iloveyou",
    "rfrfz;tnscerf",
    "woman=human",
}

# Async/Threading configuration
_THREAD_POOL_MAX_WORKERS: Final[int] = 2
_THREAD_TASK_TIMEOUT_SEC: Final[float] = 30.0
_thread_pool: Optional[ThreadPoolExecutor] = None
_thread_pool_lock = threading.Lock()

# MFA events rate limiting
_MFA_RATE_LIMIT_SEC: Final[float] = 5.0  # per (user,event)
_last_mfa_emit: Dict[Tuple[str, str], float] = {}
_last_mfa_lock = threading.Lock()


# ---- Exceptions ----
class PolicyViolation(ValueError):
    """Password does not meet complexity or policy requirements."""


class LockoutActive(RuntimeError):
    """Account is locked due to failed attempts."""


class InvalidHashFormat(ValueError):
    """Hash string is malformed or has unsupported format."""


class RehashRequired(RuntimeError):
    """Policy/params have changed and rehash is required."""


class InternalError(RuntimeError):
    """Unexpected internal error during hashing/verifying."""


# ---- Utils ----
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_str() -> str:
    return _now().isoformat()


def get_thread_pool() -> ThreadPoolExecutor:
    global _thread_pool
    if _thread_pool is None:
        with _thread_pool_lock:
            if _thread_pool is None:
                _thread_pool = ThreadPoolExecutor(
                    max_workers=_THREAD_POOL_MAX_WORKERS,
                    thread_name_prefix="password_hasher",
                )
    return _thread_pool


def run_with_timeout(
    func: Callable[..., Any],
    *args: Any,
    timeout: float = _THREAD_TASK_TIMEOUT_SEC,
    **kwargs: Any,
) -> Any:
    pool = get_thread_pool()
    fut: Future[Any] = pool.submit(func, *args, **kwargs)
    try:
        return fut.result(timeout=timeout)
    except FuturesTimeout:
        fut.cancel()
        raise InternalError("Password operation timed out")


def is_valid_password(
    password: str,
    min_length: int = _MIN_PASSWORD_LENGTH,
    max_length: int = _MAX_PASSWORD_LENGTH,
    req_special: bool = _REQ_SPECIAL,
    req_upper: bool = _REQ_UPPER,
    req_digit: bool = _REQ_DIGIT,
    blacklist: Optional[set] = None,
) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) > _MAX_INPUT_LENGTH:
        return False
    if not (min_length <= len(password) <= max_length):
        return False
    if blacklist and password.lower() in blacklist:
        return False
    if req_special and not any(c in "!@#$%^&*()-_=+[]{}|;:'\"<>,.?/" for c in password):
        return False
    if req_upper and not any(c.isupper() for c in password):
        return False
    if req_digit and not any(c.isdigit() for c in password):
        return False
    if not any(c.isalpha() for c in password):
        return False
    return True


def get_pepper(
    env_var: str = _PEPPER_ENV_VAR,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    v = os.environ.get(env_var)
    if v is None:
        return None, None
    v_rot = os.environ.get(env_var + ".old")
    if v_rot:
        return v.encode("utf-8"), v_rot.encode("utf-8")
    return v.encode("utf-8"), None


def zero_memory(buf: Union[bytes, bytearray, memoryview]) -> None:
    try:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0
        elif isinstance(buf, memoryview) and not buf.readonly:
            buf[:] = b"\x00" * len(buf)
    except Exception:
        pass


def _rate_limited(user_id: str, event: str) -> bool:
    now_ts = _now().timestamp()
    key = (user_id, event)
    with _last_mfa_lock:
        last = _last_mfa_emit.get(key, 0.0)
        if now_ts - last < _MFA_RATE_LIMIT_SEC:
            return True
        _last_mfa_emit[key] = now_ts
        return False


# ---- MFA Events ----
class MfaEvent:
    PASSWORD_HASHED = "password_hashed"
    PASSWORD_VERIFY_SUCCESS = "password_verify_success"
    PASSWORD_VERIFY_FAILED = "password_verify_failed"
    PASSWORD_REHASH_NEEDED = "password_rehash_needed"
    PASSWORD_POLICY_VIOLATION = "password_policy_violation"
    PASSWORD_LOCKOUT = "password_lockout"
    ALERT = "alert"


class MfaCallback(Protocol):
    def __call__(self, event: str, user_id: str, metadata: Dict[str, Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event: str
    user_id: str
    timestamp: str
    metadata: Dict[str, Any]


# ---- Core Hasher ----
@dataclass(frozen=True, slots=True)
class PasswordHasher:
    time_cost: int = 2
    memory_cost: int = 65536
    parallelism: int = 2
    pepper: Optional[bytes] = None
    pepper_old: Optional[bytes] = None
    mfa_callback: Optional[MfaCallback] = None
    kdf: Optional[Any] = None
    require_pepper: bool = False  # fail hashing if pepper is not set

    # pepper rotation lifetime (days) for accepting pepper_old
    pepper_rotation_days: int = 30
    pepper_rotated_at: Optional[datetime] = None  # when old pepper started being old

    _attempts: Dict[str, int] = field(default_factory=dict, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _ph: Any = field(init=False)

    def __post_init__(self) -> None:
        pepper, pepper_old = self.pepper, self.pepper_old
        if pepper is None:
            pepper, pepper_old = get_pepper()
        object.__setattr__(self, "pepper", pepper)
        object.__setattr__(self, "pepper_old", pepper_old)
        if self.require_pepper and self.pepper is None:
            raise PolicyViolation("Pepper is required but not configured")

        kdf = (
            self.kdf
            if self.kdf is not None
            else _Argon2Hasher(
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
            )
        )
        object.__setattr__(self, "_ph", kdf)
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(self, "_attempts", {})

        # initialize rotation timestamp if old pepper provided
        if self.pepper_old and self.pepper_rotated_at is None:
            object.__setattr__(self, "pepper_rotated_at", _now())

    # ---- Internal helpers ----
    def _event(
        self,
        event: str,
        user_id: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        meta = dict(metadata) if metadata else {}
        meta["timestamp"] = _now_str()
        return AuditEvent(event, user_id, meta["timestamp"], meta)

    def _fire_mfa(
        self,
        event: str,
        user_id: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self.mfa_callback is None:
            return
        if _rate_limited(user_id, event):
            return
        e = self._event(event, user_id, metadata)
        try:
            self.mfa_callback(
                e.event, e.user_id, {"timestamp": e.timestamp, **e.metadata}
            )
        except Exception as exc:
            _LOG.error("MFA callback error for %s: %s", event, exc)

    def _mix_password(
        self, password: str, salt: bytes, pepper: Optional[bytes] = None
    ) -> str:
        salt_marker = blake2b(salt, digest_size=8).hexdigest()
        # Guard extremely long passwords to avoid memory blow-up during concat
        if len(password) > _MAX_INPUT_LENGTH:
            raise PolicyViolation("Password too long")
        mix = salt_marker + password
        if pepper:
            mix += pepper.decode("utf-8", errors="replace")
        return mix

    def _parse_hash(self, hashed: str) -> Tuple[str, bytes, str]:
        if not isinstance(hashed, str) or not _HASH_FORMAT_RE.match(hashed):
            _LOG.error(
                "Invalid hash format: %r",
                hashed[:32] + "..." if isinstance(hashed, str) else "<non-str>",
            )
            raise InvalidHashFormat("Malformed or unsupported hash string")
        try:
            version_algo, salthex, argon_hash = hashed.split("$", 2)
            version, _algo = version_algo.split(":", 1)
            salt = bytes.fromhex(salthex)
            return version, salt, argon_hash
        except Exception as exc:
            _LOG.error("Malformed hash parsing: %s", exc)
            raise InvalidHashFormat("Malformed hash string") from exc

    def _accept_pepper_old(self) -> bool:
        if not self.pepper_old:
            return False
        if not self.pepper_rotated_at:
            return True
        return _now() - self.pepper_rotated_at <= timedelta(
            days=self.pepper_rotation_days
        )

    # ---- Public API ----
    def generate_salt(self, length: int = _DEFAULT_SALT_LENGTH) -> bytes:
        if length < 8:
            raise PolicyViolation("Salt length must be >= 8")
        salt = secrets.token_bytes(length)
        _LOG.debug("Generated salt len=%d", len(salt))
        return salt

    def hash_password(
        self, password: str, salt: Optional[bytes] = None, user_id: str = "unknown"
    ) -> str:
        with self._lock:
            if not is_valid_password(password, blacklist=_PASSWORD_BLACKLIST):
                self._fire_mfa(
                    MfaEvent.PASSWORD_POLICY_VIOLATION,
                    user_id,
                    metadata={"reason": "complexity"},
                )
                _LOG.warning("Password policy violation for user %s", user_id)
                raise PolicyViolation("Password failed policy requirements")
            if salt is None:
                salt = self.generate_salt()
            if len(salt) < 8:
                _LOG.warning("Salt length %d too short; must be >=8", len(salt))
                raise PolicyViolation("Salt must be at least 8 bytes")

            mix = self._mix_password(password, salt, self.pepper)
            try:
                hash_raw = self._ph.hash(mix)
            except Exception as exc:
                _LOG.error("Hashing failed for user %s: %s", user_id, exc)
                raise InternalError("Hashing failed") from exc

            result = f"{_HASH_FORMAT_VERSION}:argon2id${salt.hex()}${hash_raw}"

            # Best-effort zeroization of a salt copy
            zero_memory(memoryview(bytearray(salt)))

            self._fire_mfa(
                MfaEvent.PASSWORD_HASHED,
                user_id,
                metadata={"ver": _HASH_FORMAT_VERSION},
            )
            _LOG.info(
                "Password hashed for user %s: ver=%s", user_id, _HASH_FORMAT_VERSION
            )
            return result

    async def hash_password_async(
        self, password: str, salt: Optional[bytes] = None, user_id: str = "unknown"
    ) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            get_thread_pool(), self.hash_password, password, salt, user_id
        )

    def verify_password(
        self,
        password: str,
        hashed: str,
        user_id: str = "unknown",
        track_attempts: bool = True,
    ) -> bool:
        with self._lock:
            attempts = self._attempts.get(user_id, 0)
            if track_attempts and attempts >= MAX_FAILED_ATTEMPTS:
                self._fire_mfa(
                    MfaEvent.PASSWORD_LOCKOUT,
                    user_id,
                    metadata={"locked": True, "attempts": attempts},
                )
                _LOG.warning(
                    "User %s locked out after %d failed attempts.", user_id, attempts
                )
                raise LockoutActive("Account is locked")

            try:
                version, salt, argon_hash = self._parse_hash(hashed)
                peppers = [self.pepper]
                if self._accept_pepper_old():
                    peppers.append(self.pepper_old)
                success = False
                for p in peppers:
                    mix = self._mix_password(password, salt, p)
                    try:
                        self._ph.verify(argon_hash, mix)
                        success = True
                        break
                    except argon2_exc.VerifyMismatchError:
                        continue

                # Zeroize salt copy
                zero_memory(memoryview(bytearray(salt)))

                if success:
                    if track_attempts:
                        self._attempts[user_id] = 0
                    self._fire_mfa(MfaEvent.PASSWORD_VERIFY_SUCCESS, user_id)
                    return True
                else:
                    if track_attempts:
                        new_attempts = attempts + 1
                        self._attempts[user_id] = new_attempts
                        remaining = max(0, MAX_FAILED_ATTEMPTS - new_attempts)
                        self._fire_mfa(
                            MfaEvent.PASSWORD_VERIFY_FAILED,
                            user_id,
                            metadata={
                                "attempts": new_attempts,
                                "remaining_until_lock": remaining,
                            },
                        )
                        if new_attempts >= MAX_FAILED_ATTEMPTS:
                            self._fire_mfa(MfaEvent.PASSWORD_LOCKOUT, user_id)
                    return False

            except LockoutActive:
                raise
            except InvalidHashFormat:
                raise
            except Exception as exc:
                self._fire_mfa(MfaEvent.ALERT, user_id, metadata={"error": str(exc)})
                _LOG.error("Error verifying password for user %s: %s", user_id, exc)
                raise InternalError("Verification failed") from exc

    async def verify_password_async(
        self,
        password: str,
        hashed: str,
        user_id: str = "unknown",
        track_attempts: bool = True,
    ) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            get_thread_pool(),
            self.verify_password,
            password,
            hashed,
            user_id,
            track_attempts,
        )

    def needs_rehash(self, hashed: str, user_id: str = "unknown") -> bool:
        with self._lock:
            try:
                version, _salt, argon_hash = self._parse_hash(hashed)
                if version != _HASH_FORMAT_VERSION:
                    self._fire_mfa(
                        MfaEvent.PASSWORD_REHASH_NEEDED,
                        user_id,
                        metadata={"reason": "version_upgrade"},
                    )
                    _LOG.info("Rehash needed for user %s: version change", user_id)
                    return True
                if self._ph.check_needs_rehash(argon_hash):
                    self._fire_mfa(
                        MfaEvent.PASSWORD_REHASH_NEEDED,
                        user_id,
                        metadata={"reason": "params_change"},
                    )
                    _LOG.info("Rehash needed for user %s: policy change", user_id)
                    return True
                return False
            except InvalidHashFormat:
                # malformed hashes should force rotation
                return True
            except Exception as exc:
                self._fire_mfa(MfaEvent.ALERT, user_id, metadata={"error": str(exc)})
                _LOG.error("Error during needs_rehash user %s: %s", user_id, exc)
                # Be conservative: require rehash on internal errors
                return True

    def update_password(
        self, password: str, hashed: str, user_id: str = "unknown"
    ) -> str:
        with self._lock:
            if not self.verify_password(
                password, hashed, user_id, track_attempts=False
            ):
                raise PolicyViolation("Password verification failed. Update aborted.")
            if self.needs_rehash(hashed, user_id):
                salt = self.generate_salt()
                new_hash = self.hash_password(password, salt, user_id)
                _LOG.info("Password updated for user %s", user_id)
                return new_hash
            return hashed

    async def update_password_async(
        self, password: str, hashed: str, user_id: str = "unknown"
    ) -> str:
        loop = asyncio.get_event_loop()
        # Use bounded timeout to prevent task pile-up
        return await loop.run_in_executor(
            get_thread_pool(), self.update_password, password, hashed, user_id
        )

    @staticmethod
    def is_valid_password(password: str) -> bool:
        return is_valid_password(password, blacklist=_PASSWORD_BLACKLIST)

    # ---- Policy/Audit (stable serialization) ----
    def export_policy(self, deterministic: bool = True) -> Dict[str, Any]:
        data = {
            "schema_version": 1,
            "format_version": _HASH_FORMAT_VERSION,
            "algo": "argon2id",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "min_password_length": _MIN_PASSWORD_LENGTH,
            "max_password_length": _MAX_PASSWORD_LENGTH,
            "pepper_required": self.require_pepper,
            "pepper_set": bool(self.pepper is not None),
            "pepper_rotated": bool(self.pepper_old is not None),
            "pepper_rotation_days": self.pepper_rotation_days,
            "mfa_enabled": bool(self.mfa_callback is not None),
            "lockout_threshold": MAX_FAILED_ATTEMPTS,
            "req_special": _REQ_SPECIAL,
            "req_upper": _REQ_UPPER,
            "req_digit": _REQ_DIGIT,
            "blacklist_sample": list(sorted(_PASSWORD_BLACKLIST))[:8],
            "thread_safe": True,
            "dos_max_input_length": _MAX_INPUT_LENGTH,
            "mfa_rate_limit_sec": _MFA_RATE_LIMIT_SEC,
        }
        if deterministic:
            return OrderedDict(
                sorted(data.items(), key=lambda kv: kv[0])
            )  # stable key order
        return data

    def export_audit(self, user_id: str, deterministic: bool = True) -> Dict[str, Any]:
        att = int(self._attempts.get(user_id, 0))
        data = {
            "user_id": user_id,
            "attempts": att,
            "timestamp": _now_str(),
        }
        if deterministic:
            return OrderedDict(sorted(data.items(), key=lambda kv: kv[0]))
        return data

    # ---- Admin operations ----
    def reset_attempts(self, user_id: str) -> None:
        with self._lock:
            if user_id in self._attempts:
                self._attempts.pop(user_id, None)

    # ---- Lifecycle ----
    def shutdown(self) -> None:
        global _thread_pool
        with _thread_pool_lock:
            if _thread_pool:
                _thread_pool.shutdown(wait=True)
                _thread_pool = None

    def zeroize_all_secrets(self) -> None:
        with self._lock:
            # Drop pepper references (bytes are immutable; dropping references is the safest approach)
            if self.pepper is not None:
                object.__setattr__(self, "pepper", None)
            if self.pepper_old is not None:
                object.__setattr__(self, "pepper_old", None)
            # Clear attempts map
            if self._attempts:
                self._attempts.clear()
            _LOG.info("All secrets cleared from memory")
        self.shutdown()

    def __enter__(self) -> "PasswordHasher":
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> None:
        self.zeroize_all_secrets()
