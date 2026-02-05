# security/crypto/hashing.py
# -*- coding: utf-8 -*-
"""
RU: Безопасное хэширование паролей с полной поддержкой PBKDF2-HMAC-SHA256 и Argon2id,
опциональным pepper, DI-параметрами, needs_rehash, constant-time верификацией и rate limiting.

EN: Secure password hashing with full PBKDF2-HMAC-SHA256 and Argon2id support,
optional pepper, DI parameters, needs_rehash, constant-time verification, and rate limiting.

Formats:
- PBKDF2 (legacy):        "pbkdf2:sha256:<iterations>:<b64salt>:<b64dk>"
- PBKDF2 (+pepper):       "pbkdf2:sha256:<iterations>:pv=<ver>:<b64salt>:<b64dk>"
- Argon2id (no pepper):   "argon2id:<t>:<m>:<p>[:v=19]:<b64salt>:<b64hash>"
- Argon2id (+pepper):     "argon2id:<t>:<m>:<p>[:pv=<ver>][:v=19]:<b64salt>:<b64hash>"

Notes:
- Pepper is applied via HMAC-SHA256(pepper, password_bytes) before hashing.
- Argon2id uses fixed low-level version 19 (Argon2 v1.3) for deterministic outputs (v=19 is recorded in the hash).
- No secrets (passwords, peppers, salts, hashes) are logged.
- Rate limiting prevents brute-force attacks (exponential backoff after max attempts).
- Argon2id priority protocol, PBKDF2-HMAC-SHA256 for variability and experimentation
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import threading
import time
from typing import Any, Callable, Dict, Final, List, Optional, Tuple

from .exceptions import HashSchemeError
from .utils import generate_salt, secure_compare

_LOGGER: Final = logging.getLogger(__name__)

# Security limits
_MAX_PASSWORD_LEN: Final[int] = 4096  # 4KB reasonable upper bound to prevent DoS

# PBKDF2 policy
_SCHEME_PBKDF2: Final[str] = "pbkdf2"
_HASH_NAME: Final[str] = "sha256"
_MIN_ITERS: Final[int] = 100_000
_MIN_SALT_LEN: Final[int] = 8
_MAX_SALT_LEN: Final[int] = 64

# Argon2id defaults (can be overridden via ctor)
_DEF_T: Final[int] = 3
_DEF_M: Final[int] = 65_536  # KiB (~64 MiB)
_DEF_P: Final[int] = 2
_ARGON2_VERSION: Final[int] = 19  # v1.3

# Rate limiting constants
_MAX_FAILED_ATTEMPTS: Final[int] = 5
_LOCKOUT_DURATION: Final[float] = 30.0  # seconds
_BACKOFF_BASE: Final[float] = 0.5  # seconds
_BACKOFF_MULTIPLIER: Final[float] = 2.0

# Thread-safe storage for failed attempts
_failed_attempts: Dict[str, List[float]] = {}
_attempts_lock = threading.Lock()


def _try_import_argon2() -> Tuple[Callable[..., bytes], Any, int]:
    """
    Lazy import for argon2.low_level; returns (hash_secret_raw, Type, version).
    Raises ImportError if argon2-cffi is unavailable.
    """
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw, Type, _ARGON2_VERSION


def _check_rate_limit(identifier: str) -> None:
    """
    Check rate limit for password verification attempts.

    Args:
        identifier: unique identifier (e.g., username or session ID).

    Raises:
        HashSchemeError: if rate limit exceeded.
    """
    now = time.time()

    with _attempts_lock:
        attempts = _failed_attempts.get(identifier, [])
        # Clean old attempts (> lockout duration)
        attempts = [t for t in attempts if now - t < _LOCKOUT_DURATION]

        if len(attempts) >= _MAX_FAILED_ATTEMPTS:
            # Calculate exponential backoff
            last_attempt = max(attempts)
            excess = len(attempts) - _MAX_FAILED_ATTEMPTS
            wait_time = _BACKOFF_BASE * (_BACKOFF_MULTIPLIER**excess)
            elapsed = now - last_attempt

            if elapsed < wait_time:
                remaining = int(wait_time - elapsed) + 1
                _LOGGER.warning(
                    "Rate limit exceeded for identifier: %s... (attempts: %d)",
                    identifier[:8],
                    len(attempts),
                )
                raise HashSchemeError(
                    f"Слишком много неудачных попыток. Повторите через {remaining} сек."
                )


def _record_failed_attempt(identifier: str) -> None:
    """Record failed password verification attempt."""
    now = time.time()
    with _attempts_lock:
        if identifier not in _failed_attempts:
            _failed_attempts[identifier] = []
        _failed_attempts[identifier].append(now)


def _clear_failed_attempts(identifier: str) -> None:
    """Clear failed attempts on successful verification."""
    with _attempts_lock:
        _failed_attempts.pop(identifier, None)


# После импортов, перед классом PasswordHasher добавьте:


def compute_hash(
    data: bytes,
    *,
    algorithm: str = "sha3-256",
) -> str:
    """
    Compute cryptographic hash of data.

    Args:
        data: bytes to hash.
        algorithm: hash algorithm name (sha256, sha3-256, blake2b).

    Returns:
        Hexadecimal hash string.

    Raises:
        HashSchemeError: on unsupported algorithm.

    Examples:
        >>> compute_hash(b"hello", algorithm="sha3-256")
        '3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392'
    """
    if algorithm == "sha256":
        return compute_hash_sha256(data)
    elif algorithm == "sha3-256":
        return compute_hash_sha3_256(data)
    elif algorithm == "blake2b":
        return compute_hash_blake2b(data)
    else:
        raise HashSchemeError(f"Unsupported hash algorithm: {algorithm}")


def compute_hash_sha256(data: bytes) -> str:
    """
    Compute SHA-256 hash (legacy/compatibility).

    Args:
        data: bytes to hash.

    Returns:
        64-character hex string.
    """
    return hashlib.sha256(data).hexdigest()


def compute_hash_sha3_256(data: bytes) -> str:
    """
    Compute SHA3-256 hash (NIST standard).

    Args:
        data: bytes to hash.

    Returns:
        64-character hex string.
    """
    return hashlib.sha3_256(data).hexdigest()


def compute_hash_blake2b(data: bytes, digest_size: int = 64) -> str:
    """
    Compute BLAKE2b hash (high-performance alternative).

    Args:
        data: bytes to hash.
        digest_size: output size in bytes (1-64, default 64).

    Returns:
        Hexadecimal hash string (length = digest_size * 2).
    """
    return hashlib.blake2b(data, digest_size=digest_size).hexdigest()


def hash_password(
    password: str,
    *,
    salt: Optional[bytes] = None,
) -> Tuple[str, bytes]:
    """
    Hash password using Argon2id.

    Args:
        password: plaintext password.
        salt: optional salt (generated if None).

    Returns:
        Tuple of (hash_string, salt).
    """
    if salt is None:
        salt = generate_salt(16)

    hasher = PasswordHasher()
    hash_str = hasher.hash_password(password)

    return hash_str, salt


def verify_password(password: str, hash_str: str, salt: bytes) -> bool:
    """
    Verify password against hash.

    Args:
        password: plaintext password to verify.
        hash_str: stored Argon2 hash string (includes salt).

    Returns:
        True if password matches, False otherwise.
    """
    hasher = PasswordHasher()
    return hasher.verify_password(password, hash_str)


class PasswordHasher:
    """
    Password hashing provider supporting PBKDF2-HMAC-SHA256 and Argon2id.

    Implements HashingProtocol interface (duck-typed Protocol):
      - hash_password(password: str) -> str
      - verify_password(password: str, hashed: str, identifier: Optional[str]) -> bool
      - needs_rehash(hashed: str) -> bool

    Args:
        scheme: "pbkdf2" or "argon2id".
        iterations: PBKDF2 iterations (>= 100_000).
        salt_len: salt length (8..64).
        rate_limit_enabled: enable rate limiting (default: True).
        pepper_provider: optional callable returning pepper bytes.
        pepper_version: optional version label embedded into hash when pepper is used.
        time_cost: Argon2id time cost (>= 2).
        memory_cost: Argon2id memory cost in KiB (>= 65536).
        parallelism: Argon2id parallelism (>= 1).
    """

    __slots__ = (
        "_scheme",
        "_rate_limit_enabled",
        "_iterations",
        "_salt_len",
        "_pepper_provider",
        "_pepper_version",
        "_t",
        "_m",
        "_p",
    )

    def __init__(
        self,
        scheme: str = "pbkdf2",
        *,
        iterations: int = 200_000,
        rate_limit_enabled: bool = True,
        salt_len: int = 16,
        pepper_provider: Optional[Callable[[], bytes]] = None,
        pepper_version: Optional[str] = None,
        time_cost: int = _DEF_T,
        memory_cost: int = _DEF_M,
        parallelism: int = _DEF_P,
    ) -> None:
        if scheme not in ("pbkdf2", "argon2id"):
            raise HashSchemeError("Unsupported hashing scheme")
        if not isinstance(salt_len, int) or not (
            _MIN_SALT_LEN <= salt_len <= _MAX_SALT_LEN
        ):
            raise HashSchemeError("Salt length must be between 8 and 64 bytes")

        self._scheme = scheme
        self._rate_limit_enabled = rate_limit_enabled
        self._salt_len = salt_len
        self._pepper_provider = pepper_provider
        self._pepper_version = pepper_version
        if pepper_provider is None and pepper_version is not None:
            raise HashSchemeError("pepper_version requires pepper_provider")

        if scheme == "pbkdf2":
            if not isinstance(iterations, int) or iterations < _MIN_ITERS:
                raise HashSchemeError(f"Iterations must be >= {_MIN_ITERS}")
            self._iterations = iterations
            self._t = _DEF_T
            self._m = _DEF_M
            self._p = _DEF_P
        else:
            # Argon2id parameter validation
            if not (isinstance(time_cost, int) and time_cost >= 2):
                raise HashSchemeError("Argon2id time_cost must be >= 2")
            if not (isinstance(memory_cost, int) and memory_cost >= 65_536):
                raise HashSchemeError("Argon2id memory_cost must be >= 65536 (KiB)")
            if not (isinstance(parallelism, int) and parallelism >= 1):
                raise HashSchemeError("Argon2id parallelism must be >= 1")
            self._iterations = (
                _MIN_ITERS  # unused for argon2id, keep for interface parity
            )
            self._t = time_cost
            self._m = memory_cost
            self._p = parallelism

    # Internal: pepper application
    def _peppered(self, password: str) -> bytes:
        if self._pepper_provider is None:
            return password.encode("utf-8")
        pepper = self._pepper_provider()
        return hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()

    # Public API

    def hash_password(self, password: str) -> str:
        if not isinstance(password, str) or password == "":
            raise HashSchemeError("Password must be a non-empty string")

        if len(password) > _MAX_PASSWORD_LEN:
            raise HashSchemeError(
                f"Password exceeds maximum length ({_MAX_PASSWORD_LEN} characters)"
            )

        try:
            pw_bytes = self._peppered(password)
            salt = generate_salt(self._salt_len)

            if self._scheme == "pbkdf2":
                dk = hashlib.pbkdf2_hmac(
                    _HASH_NAME, pw_bytes, salt, self._iterations, dklen=32
                )
                parts = [_SCHEME_PBKDF2, _HASH_NAME, str(self._iterations)]
                if (
                    self._pepper_provider is not None
                    and self._pepper_version is not None
                ):
                    parts.append(f"pv={self._pepper_version}")
                parts.append(base64.b64encode(salt).decode("ascii"))
                parts.append(base64.b64encode(dk).decode("ascii"))
                out = ":".join(parts)
                _LOGGER.info(
                    "Password hashed (scheme=PBKDF2, iters=%d)", self._iterations
                )
                return out

            # Argon2id
            hash_secret_raw, Type, ver = _try_import_argon2()
            dk = hash_secret_raw(
                secret=pw_bytes,
                salt=salt,
                time_cost=self._t,
                memory_cost=self._m,
                parallelism=self._p,
                hash_len=32,
                type=Type.ID,
                version=ver,
            )
            parts = ["argon2id", str(self._t), str(self._m), str(self._p)]
            if self._pepper_provider is not None and self._pepper_version is not None:
                parts.append(f"pv={self._pepper_version}")
            # always record Argon2 low-level version for transparency/backward-compat
            parts.append(f"v={ver}")
            parts.append(base64.b64encode(salt).decode("ascii"))
            parts.append(base64.b64encode(dk).decode("ascii"))
            out = ":".join(parts)
            _LOGGER.info(
                "Password hashed (scheme=Argon2id, t=%d, m=%d)", self._t, self._m
            )
            return out

        except ImportError as exc:
            _LOGGER.error("Argon2id not available: %s", exc.__class__.__name__)
            raise HashSchemeError("Argon2id not available") from exc
        except Exception as exc:
            _LOGGER.error("Password hashing failed: %s", exc.__class__.__name__)
            raise HashSchemeError("Hashing failed") from exc

    def verify_password(
        self,
        password: str,
        hashed: str,
        identifier: Optional[str] = None,
    ) -> bool:
        """
        Verify password with optional rate limiting.

        Args:
            password: plaintext password.
            hashed: stored hash.
            identifier: unique ID for rate limiting (e.g., username, session ID).

        Returns:
            True if password matches, False otherwise.

        Raises:
            HashSchemeError: if rate limit exceeded.
        """
        # Check rate limit before expensive hashing
        if self._rate_limit_enabled and identifier:
            _check_rate_limit(identifier)

        try:
            parts = hashed.split(":")
            if not parts:
                return False

            result = False

            if parts[0] == _SCHEME_PBKDF2:
                # pbkdf2:sha256:<iters>[:pv=...]:<salt>:<dk>
                if len(parts) not in (5, 6):
                    return False
                _, name, iters_s = parts[0], parts[1], parts[2]
                if name != _HASH_NAME:
                    return False
                iters = int(iters_s)
                if len(parts) == 6:
                    pv_field = parts[3]
                    if not pv_field.startswith("pv="):
                        return False

                    # Check for empty pepper version (malformed)
                    stored_pv = pv_field[3:]
                    if stored_pv == "":
                        _LOGGER.warning("Empty pepper version in PBKDF2 hash")
                        return False

                    if self._pepper_provider is None:
                        return False
                    pw_bytes = self._peppered(password)
                    salt_b64, dk_b64 = parts[4], parts[5]
                else:
                    # legacy without pepper
                    pw_bytes = password.encode("utf-8")
                    salt_b64, dk_b64 = parts[3], parts[4]

                salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
                stored = base64.b64decode(dk_b64.encode("ascii"), validate=True)
                candidate = hashlib.pbkdf2_hmac(
                    _HASH_NAME, pw_bytes, salt, iters, dklen=len(stored)
                )
                result = secure_compare(candidate, stored)

            elif parts[0] == "argon2id":
                # argon2id:<t>:<m>:<p>[:pv=...][:v=19]:<salt>:<hash>
                if len(parts) < 6:
                    return False
                t = int(parts[1])
                m = int(parts[2])
                p = int(parts[3])

                # parse optional pv and v (order-insensitive, up to two fields)
                idx = 4
                saw_pv = False
                saw_v = False
                if idx < len(parts) and parts[idx].startswith("pv="):
                    saw_pv = True
                    if self._pepper_provider is None:
                        return False
                    pw_bytes = self._peppered(password)
                    idx += 1
                else:
                    pw_bytes = password.encode("utf-8")

                # second optional field could be v=19 (or pv if first was v)
                if idx < len(parts) and parts[idx].startswith("v="):
                    saw_v = True
                    idx += 1
                elif not saw_pv and idx < len(parts) and parts[idx].startswith("pv="):
                    # order: v then pv (rare) — handle as well
                    saw_pv = True
                    if self._pepper_provider is None:
                        return False
                    pw_bytes = self._peppered(password)
                    idx += 1
                    if idx < len(parts) and parts[idx].startswith("v="):
                        saw_v = True
                        idx += 1

                # now expect salt and hash
                if idx + 1 >= len(parts):
                    return False
                salt_b64 = parts[idx]
                dk_b64 = parts[idx + 1]
                salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
                stored = base64.b64decode(dk_b64.encode("ascii"), validate=True)

                hash_secret_raw, Type, ver = _try_import_argon2()
                candidate = hash_secret_raw(
                    secret=pw_bytes,
                    salt=salt,
                    time_cost=t,
                    memory_cost=m,
                    parallelism=p,
                    hash_len=len(stored),
                    type=Type.ID,
                    version=ver,
                )
                result = secure_compare(candidate, stored)

            # Update rate limiting state
            if identifier:
                if result:
                    _clear_failed_attempts(identifier)
                elif self._rate_limit_enabled:
                    _record_failed_attempt(identifier)

            return result

        except HashSchemeError:
            raise  # re-raise rate limit errors
        except Exception:
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """
        Policy:
        - PBKDF2: iters < configured OR salt_len < configured OR pv mismatch (presence/version).
        - Argon2id: any of t/m/p < configured OR salt_len < configured OR pv mismatch OR (if present) v != 19.
        - Unknown/malformed formats => True.
        """
        try:
            parts = hashed.split(":")
            if not parts:
                return True

            if parts[0] == _SCHEME_PBKDF2:
                # pbkdf2:sha256:iters[:pv=..]:salt:dk
                if len(parts) not in (5, 6):
                    return True
                _, name, iters_s = parts[0], parts[1], parts[2]
                if name != _HASH_NAME:
                    return True
                iters = int(iters_s)
                if len(parts) == 6:
                    pv_field = parts[3]
                    if not pv_field.startswith("pv="):
                        return True
                    stored_pv = pv_field[3:]

                    # Validate pepper version (empty = malformed)
                    if stored_pv == "":
                        _LOGGER.warning(
                            "Empty pepper version in PBKDF2 hash (needs rehash)"
                        )
                        return True

                    salt_b64 = parts[4]
                else:
                    stored_pv = None
                    salt_b64 = parts[3]

                salt_len = len(
                    base64.b64decode(salt_b64.encode("ascii"), validate=True)
                )
                if iters < self._iterations:
                    return True
                if salt_len < self._salt_len:
                    return True
                if (
                    self._pepper_provider is not None
                    and self._pepper_version is not None
                ):
                    if stored_pv != self._pepper_version:
                        return True
                return False

            if parts[0] == "argon2id":
                if len(parts) < 6:
                    return True
                t = int(parts[1])
                m = int(parts[2])
                p = int(parts[3])

                idx = 4
                stored_pv = None
                stored_v: Optional[str] = None

                for _ in range(2):
                    if idx < len(parts) and parts[idx].startswith("pv="):
                        stored_pv = parts[idx][3:]
                        idx += 1
                        continue
                    if idx < len(parts) and parts[idx].startswith("v="):
                        stored_v = parts[idx][2:]
                        idx += 1
                        continue
                    break

                if idx >= len(parts):
                    return True
                salt_b64 = parts[idx]
                salt_len = len(
                    base64.b64decode(salt_b64.encode("ascii"), validate=True)
                )

                if t < self._t or m < self._m or p < self._p:
                    return True
                if salt_len < self._salt_len:
                    return True
                if (
                    self._pepper_provider is not None
                    and self._pepper_version is not None
                ):
                    if stored_pv != self._pepper_version:
                        return True
                if stored_v is not None and stored_v != str(_ARGON2_VERSION):
                    return True
                return False

            return True
        except Exception:
            return True


__all__ = [
    "compute_hash",
    "compute_hash_blake2b",
    "compute_hash_sha256",
    "compute_hash_sha3_256",
    "hash_password",
    "verify_password",
    "PasswordHasher",
]
