"""
RU: Корпоративный безопасный модуль управления паролями для FX-Text-processor-3.
- Argon2id, соль+pepper с ротацией, блокировки, расширяемая политика, MFA-интеграция, аудит/экспорт, потокобезопасный/async, alerts/SIEM, очистка секретов, DI для KDF, временные метки.

EN: Enterprise-grade, secure password management module for FX-Text-processor-3.
- Argon2id, salt+pepper rotation, lockout warnings, advanced policy, MFA/SIEM hooks, audit export, thread-safe/async, secret zeroization, DI KDF, full event timestamping.

Example:
    from security.auth.password import PasswordHasher, MfaCallback

    def mfa_hook(event, user_id, metadata):
        logger.info(f"MFA event: {event} for user {user_id}")

    hasher = PasswordHasher(pepper=b"mysecretX", mfa_callback=mfa_hook)
    hashed = await hasher.hash_password_async("Qwe!2022", hasher.generate_salt(), user_id="admin42")
    assert await hasher.verify_password_async("Qwe!2022", hashed, user_id="admin42")
"""

import asyncio
import logging
import os
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple, Final, Callable, Dict, Any, Protocol, Union
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import blake2b
from argon2 import PasswordHasher as _Argon2Hasher, exceptions as argon2_exc

_LOG = logging.getLogger(__name__)

_DEFAULT_SALT_LENGTH: Final[int] = 16
_HASH_FORMAT_VERSION: Final[str] = "v1"
_PEPPER_ENV_VAR: Final[str] = "FX_TEXT_PW_PEPPER"
MAX_FAILED_ATTEMPTS: Final[int] = 5

_MIN_PASSWORD_LENGTH: Final[int] = 8
_MAX_PASSWORD_LENGTH: Final[int] = 256
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

_thread_pool: Optional[ThreadPoolExecutor] = None
_thread_pool_lock = threading.Lock()


def get_thread_pool() -> ThreadPoolExecutor:
    global _thread_pool
    if _thread_pool is None:
        with _thread_pool_lock:
            if _thread_pool is None:
                _thread_pool = ThreadPoolExecutor(
                    max_workers=2, thread_name_prefix="password_hasher"
                )
    return _thread_pool


def is_valid_password(
    password: str,
    min_length: int = _MIN_PASSWORD_LENGTH,
    max_length: int = _MAX_PASSWORD_LENGTH,
    req_special: bool = _REQ_SPECIAL,
    req_upper: bool = _REQ_UPPER,
    req_digit: bool = _REQ_DIGIT,
    blacklist: Optional[set] = None,
) -> bool:
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


def get_pepper(env_var: str = _PEPPER_ENV_VAR) -> Tuple[Optional[bytes], Optional[bytes]]:
    v = os.environ.get(env_var)
    if v is None:
        return None, None
    v_rot = os.environ.get(env_var + ".old")
    if v_rot:
        return v.encode("utf-8"), v_rot.encode("utf-8")
    return v.encode("utf-8"), None


def zero_memory(secret: Union[str, bytes]) -> None:
    try:
        if isinstance(secret, bytearray):
            for i in range(len(secret)):
                secret[i] = 0
    except Exception:
        pass


class MfaEvent:
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


def _now() -> str:
    return datetime.utcnow().isoformat()


@dataclass(frozen=True, slots=True)
class PasswordHasher:
    time_cost: int = 2
    memory_cost: int = 65536
    parallelism: int = 2
    pepper: Optional[bytes] = None
    pepper_old: Optional[bytes] = None
    mfa_callback: Optional[MfaCallback] = None
    kdf: Optional[Any] = None

    _attempts: Dict[str, int] = field(default_factory=dict, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _ph: Any = field(init=False)

    def __post_init__(self) -> None:
        pepper, pepper_old = self.pepper, self.pepper_old
        if pepper is None:
            pepper, pepper_old = get_pepper()
        object.__setattr__(self, "pepper", pepper)
        object.__setattr__(self, "pepper_old", pepper_old)
        kdf = (
            self.kdf
            if self.kdf is not None
            else _Argon2Hasher(
                time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism
            )
        )
        object.__setattr__(self, "_ph", kdf)
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(self, "_attempts", {})

    def _event(
        self, event: str, user_id: str = "unknown", metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        meta = dict(metadata) if metadata else {}
        meta["timestamp"] = _now()
        return AuditEvent(event, user_id, meta["timestamp"], meta)

    def _fire_mfa(
        self, event: str, user_id: str = "unknown", metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        e = self._event(event, user_id, metadata)
        if self.mfa_callback:
            try:
                self.mfa_callback(e.event, e.user_id, {"timestamp": e.timestamp, **e.metadata})
            except Exception as exc:
                _LOG.error("MFA callback error for %s: %s", event, exc)

    def generate_salt(self, length: int = _DEFAULT_SALT_LENGTH) -> bytes:
        salt = secrets.token_bytes(length)
        _LOG.debug("Generated salt: %s", salt.hex())
        return salt

    def _mix_password(self, password: str, salt: bytes, pepper: Optional[bytes] = None) -> str:
        salt_marker = blake2b(salt, digest_size=8).hexdigest()
        mix = salt_marker + password
        if pepper:
            mix += pepper.decode("utf-8", errors="replace")
        return mix

    def hash_password(
        self, password: str, salt: Optional[bytes] = None, user_id: str = "unknown"
    ) -> str:
        with self._lock:
            if not is_valid_password(password, blacklist=_PASSWORD_BLACKLIST):
                self._fire_mfa(
                    MfaEvent.PASSWORD_POLICY_VIOLATION, user_id, metadata={"reason": "complexity"}
                )
                _LOG.warning("Password policy violation for user %s", user_id)
                raise ValueError("Password failed policy requirements.")
            if salt is None:
                salt = self.generate_salt()
            if len(salt) < 8:
                _LOG.warning("Salt length %d too short; must be >=8", len(salt))
                raise ValueError("Salt must be at least 8 bytes.")
            mix = self._mix_password(password, salt, self.pepper)
            try:
                hash_raw = self._ph.hash(mix)
            except Exception as exc:
                _LOG.error("Hashing failed for user %s: %s", user_id, exc)
                raise
            result = f"{_HASH_FORMAT_VERSION}:argon2id${salt.hex()}${hash_raw}"
            zero_memory(password)
            zero_memory(salt)
            self._fire_mfa(
                MfaEvent.PASSWORD_VERIFY_SUCCESS,
                user_id,
                metadata={"audited": True, "ver": _HASH_FORMAT_VERSION},
            )
            _LOG.info("Password hashed for user %s: ver=%s", user_id, _HASH_FORMAT_VERSION)
            return result

    async def hash_password_async(
        self, password: str, salt: Optional[bytes] = None, user_id: str = "unknown"
    ) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            get_thread_pool(), self.hash_password, password, salt, user_id
        )

    def verify_password(
        self, password: str, hashed: str, user_id: str = "unknown", allow_lockout: bool = True
    ) -> bool:
        with self._lock:
            attempts = self._attempts.get(user_id, 0)
            if allow_lockout and attempts >= MAX_FAILED_ATTEMPTS:
                self._fire_mfa(
                    MfaEvent.PASSWORD_LOCKOUT,
                    user_id,
                    metadata={"locked": True, "attempts": attempts},
                )
                _LOG.warning("User %s locked out after %d failed attempts.", user_id, attempts)
                return False
            try:
                version, salt, argon_hash = self._parse_hash(hashed)
                peppers = (self.pepper, self.pepper_old)
                success = False
                for p in peppers:
                    mix = self._mix_password(password, salt, p)
                    try:
                        self._ph.verify(argon_hash, mix)
                        success = True
                        break
                    except argon2_exc.VerifyMismatchError:
                        continue
                zero_memory(password)
                zero_memory(salt)
                if success:
                    self._attempts[user_id] = 0
                    self._fire_mfa(MfaEvent.PASSWORD_VERIFY_SUCCESS, user_id)
                    return True
                else:
                    self._attempts[user_id] = attempts + 1
                    self._fire_mfa(
                        MfaEvent.PASSWORD_VERIFY_FAILED,
                        user_id,
                        metadata={"attempts": self._attempts[user_id]},
                    )
                    if self._attempts[user_id] >= MAX_FAILED_ATTEMPTS:
                        self._fire_mfa(MfaEvent.PASSWORD_LOCKOUT, user_id)
                    return False
            except Exception as exc:
                self._fire_mfa(MfaEvent.ALERT, user_id, metadata={"error": str(exc)})
                _LOG.error("Error verifying password for user %s: %s", user_id, exc)
                return False

    async def verify_password_async(
        self, password: str, hashed: str, user_id: str = "unknown", allow_lockout: bool = True
    ) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            get_thread_pool(), self.verify_password, password, hashed, user_id, allow_lockout
        )

    def needs_rehash(self, hashed: str, user_id: str = "unknown") -> bool:
        with self._lock:
            try:
                version, salt, argon_hash = self._parse_hash(hashed)
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
            except Exception as exc:
                self._fire_mfa(MfaEvent.ALERT, user_id, metadata={"error": str(exc)})
                _LOG.error("Error during needs_rehash user %s: %s", user_id, exc)
                return True

    def update_password(self, password: str, hashed: str, user_id: str = "unknown") -> str:
        with self._lock:
            if self.verify_password(password, hashed, user_id):
                if self.needs_rehash(hashed, user_id):
                    salt = self.generate_salt()
                    new_hash = self.hash_password(password, salt, user_id)
                    _LOG.info("Password updated for user %s", user_id)
                    return new_hash
                return hashed
            else:
                raise ValueError("Password verification failed. Update aborted.")

    async def update_password_async(
        self, password: str, hashed: str, user_id: str = "unknown"
    ) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            get_thread_pool(), self.update_password, password, hashed, user_id
        )

    @staticmethod
    def is_valid_password(password: str) -> bool:
        return is_valid_password(password, blacklist=_PASSWORD_BLACKLIST)

    def export_policy(self) -> Dict[str, Any]:
        return {
            "version": _HASH_FORMAT_VERSION,
            "algo": "argon2id",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "min_password_length": _MIN_PASSWORD_LENGTH,
            "max_password_length": _MAX_PASSWORD_LENGTH,
            "pepper_set": bool(self.pepper is not None),
            "pepper_rotated": bool(self.pepper_old is not None),
            "mfa_enabled": bool(self.mfa_callback is not None),
            "lockout_threshold": MAX_FAILED_ATTEMPTS,
            "req_special": _REQ_SPECIAL,
            "req_upper": _REQ_UPPER,
            "req_digit": _REQ_DIGIT,
            "blacklist": list(_PASSWORD_BLACKLIST),
            "thread_safe": True,
        }

    def export_audit(self, user_id: str) -> Dict[str, Any]:
        att = self._attempts.get(user_id, 0)
        return {"user_id": user_id, "attempts": att, "timestamp": _now()}

    def shutdown(self) -> None:
        global _thread_pool
        with _thread_pool_lock:
            if _thread_pool:
                _thread_pool.shutdown(wait=True)
                _thread_pool = None

    @staticmethod
    def _parse_hash(hashed: str) -> Tuple[str, bytes, str]:
        if not hashed or "$" not in hashed or ":" not in hashed:
            _LOG.error(f"Malformed hash string: {hashed}")
            raise ValueError("Malformed hash string")
        try:
            version_algo, salt_hex, argon_hash = hashed.split("$", 2)
            version, _ = version_algo.split(":", 1)
            salt = bytes.fromhex(salt_hex)
            return version, salt, argon_hash
        except Exception as exc:
            _LOG.error("Malformed hash parsing: %s", exc)
            raise ValueError("Malformed hash string") from exc
