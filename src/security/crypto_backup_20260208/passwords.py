# -*- coding: utf-8 -*-
"""
Unified password hashing with Argon2id/PBKDF2 and attack protection.

Features:
- Argon2id (primary, GPU-resistant)
- PBKDF2-HMAC-SHA256 (fallback)
- BLAKE3-HMAC pepper support (10× faster than SHA256)
- Timing attack protection (constant-time operations)
- Rate limiting (per-identifier + global)
- Pepper version MAC (downgrade protection)

Best practices:
- Use Argon2id for all new hashes
- Enable rate limiting in production
- Use pepper for additional security layer
- Monitor needs_rehash() for parameter upgrades

Examples:
    >>> # Basic usage
    >>> hasher = PasswordHasher()
    >>> hashed = hasher.hash_password("user_password")
    >>> hasher.verify_password("user_password", hashed, identifier="user123")
    True

    >>> # With pepper (recommended)
    >>> hasher = PasswordHasher(
    ...     pepper_provider=lambda: b"secret_pepper_32_bytes_long!",
    ...     pepper_version="v1"
    ... )
    >>> hashed = hasher.hash_password("password")

    >>> # Check if rehash needed
    >>> if hasher.needs_rehash(old_hash):
    ...     new_hash = hasher.hash_password(password)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Final, List, Optional, Tuple

from .exceptions import HashSchemeError
from .utils import generate_salt, secure_compare

# Try BLAKE3 (optional, fallback to HMAC-SHA256)
try:
    from .blake3_hash import BLAKE3_AVAILABLE, hmac_blake3
except ImportError:
    BLAKE3_AVAILABLE = False
    hmac_blake3 = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from argon2.low_level import Type as Argon2Type

    # Callable with keyword-only args after positional
    from typing import Protocol

    class HashSecretRaw(Protocol):
        def __call__(
            self,
            secret: bytes,
            salt: bytes,
            *,
            time_cost: int,
            memory_cost: int,
            parallelism: int,
            hash_len: int,
            type: Argon2Type,
            version: int,
        ) -> bytes: ...

else:
    Argon2Type = Any
    HashSecretRaw = Any

_LOGGER: Final = logging.getLogger(__name__)

# ============================================
# SECURITY CONSTANTS
# ============================================

_MAX_PASSWORD_LEN: Final[int] = 4096
_MIN_ITERS: Final[int] = 100_000
_MIN_SALT_LEN: Final[int] = 8
_MAX_SALT_LEN: Final[int] = 64

# Argon2id defaults (OWASP recommended)
_DEF_T: Final[int] = 3  # time_cost
_DEF_M: Final[int] = 65_536  # memory_cost (64 MB)
_DEF_P: Final[int] = 2  # parallelism
_ARGON2_VERSION: Final[int] = 19

# Rate limiting
_MAX_FAILED_ATTEMPTS: Final[int] = 5
_LOCKOUT_DURATION: Final[float] = 30.0
_BACKOFF_BASE: Final[float] = 0.5
_BACKOFF_MULTIPLIER: Final[float] = 2.0
_GLOBAL_MAX_ATTEMPTS_PER_MINUTE: Final[int] = 100

# ============================================
# GLOBAL STATE (Thread-safe)
# ============================================

_global_verification_attempts: int = 0
_global_last_reset: float = time.time()
_global_lock = threading.Lock()

_failed_attempts: Dict[str, List[float]] = {}
_attempts_lock = threading.Lock()

# ============================================
# HELPER FUNCTIONS
# ============================================


def _try_import_argon2() -> Tuple[HashSecretRaw, Any, int]:
    """Import Argon2 dynamically to avoid hard dependency."""
    try:
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw, Type, _ARGON2_VERSION
    except ImportError as exc:
        raise HashSchemeError(
            "Argon2id not available. Install: pip install argon2-cffi"
        ) from exc


def _check_global_rate_limit() -> None:
    """Check global rate limit (all verifications across all users)."""
    global _global_verification_attempts, _global_last_reset

    now = time.time()
    with _global_lock:
        # Reset counter every minute
        if now - _global_last_reset > 60:
            _global_verification_attempts = 0
            _global_last_reset = now

        if _global_verification_attempts >= _GLOBAL_MAX_ATTEMPTS_PER_MINUTE:
            _LOGGER.error("Global rate limit exceeded")
            raise HashSchemeError("Too many verification attempts. Try again later.")

        _global_verification_attempts += 1


def _check_rate_limit(identifier: str) -> None:
    """Check per-identifier rate limit with exponential backoff."""
    now = time.time()

    with _attempts_lock:
        # Clean old attempts
        attempts = _failed_attempts.get(identifier, [])
        attempts = [t for t in attempts if now - t < _LOCKOUT_DURATION]

        if len(attempts) >= _MAX_FAILED_ATTEMPTS:
            last_attempt = max(attempts)
            excess = len(attempts) - _MAX_FAILED_ATTEMPTS
            wait_time = _BACKOFF_BASE * (_BACKOFF_MULTIPLIER**excess)
            elapsed = now - last_attempt

            if elapsed < wait_time:
                remaining = int(wait_time - elapsed) + 1
                raise HashSchemeError(
                    f"Too many failed attempts. Retry in {remaining}s."
                )


def _record_failed_attempt(identifier: str) -> None:
    """Record a failed verification attempt."""
    now = time.time()
    with _attempts_lock:
        if identifier not in _failed_attempts:
            _failed_attempts[identifier] = []
        _failed_attempts[identifier].append(now)


def _clear_failed_attempts(identifier: str) -> None:
    """Clear failed attempts after successful verification."""
    with _attempts_lock:
        _failed_attempts.pop(identifier, None)


def _compute_pepper_version_mac(pepper: bytes, version: str) -> bytes:
    """Compute MAC for pepper version (downgrade protection)."""
    mac = hmac.new(pepper, f"pv={version}".encode(), hashlib.sha256).digest()
    return mac[:8]  # 64 bits sufficient for MAC


# ============================================
# MAIN CLASS
# ============================================


class PasswordHasher:
    """
    Unified password hasher with Argon2id/PBKDF2.

    Security features:
    - BLAKE3 pepper (10× faster than HMAC-SHA256)
    - Constant-time dummy operations (timing attack protection)
    - Pepper version MAC (downgrade attack protection)
    - Global + per-identifier rate limiting

    Args:
        scheme: "argon2id" (recommended) or "pbkdf2"
        iterations: PBKDF2 iterations (min 100,000)
        rate_limit_enabled: Enable rate limiting
        salt_len: Salt length in bytes (8-64)
        pepper_provider: Function returning 32-byte pepper
        pepper_version: Version label for pepper rotation
        time_cost: Argon2id time cost (min 2)
        memory_cost: Argon2id memory in KiB (min 65,536 = 64 MB)
        parallelism: Argon2id parallelism (min 1)
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
        "_use_blake3_pepper",
    )

    def __init__(
        self,
        scheme: str = "argon2id",
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
        # Validate scheme
        if scheme not in ("pbkdf2", "argon2id"):
            raise HashSchemeError("Scheme must be 'pbkdf2' or 'argon2id'")

        # Validate salt length
        if not (_MIN_SALT_LEN <= salt_len <= _MAX_SALT_LEN):
            raise HashSchemeError(
                f"Salt length must be {_MIN_SALT_LEN}-{_MAX_SALT_LEN} bytes"
            )

        # Validate pepper configuration
        if pepper_version and not pepper_provider:
            raise HashSchemeError("pepper_version requires pepper_provider")

        self._scheme = scheme
        self._rate_limit_enabled = rate_limit_enabled
        self._salt_len = salt_len
        self._pepper_provider = pepper_provider
        self._pepper_version = pepper_version

        # Determine if BLAKE3 is available for pepper (ONE TIME, for BOTH schemes)
        self._use_blake3_pepper = False
        if pepper_provider and BLAKE3_AVAILABLE and hmac_blake3 is not None:
            # Validate pepper length for BLAKE3
            try:
                test_pepper = pepper_provider()
                if len(test_pepper) == 32:
                    self._use_blake3_pepper = True
                    _LOGGER.info(
                        "Using BLAKE3 for pepper (10× faster than HMAC-SHA256)"
                    )
                else:
                    _LOGGER.warning(
                        "Pepper length is %d bytes, but BLAKE3 requires 32 bytes. "
                        "Falling back to HMAC-SHA256",
                        len(test_pepper),
                    )
            except Exception as exc:
                _LOGGER.warning(
                    "Failed to validate pepper (%s), falling back to HMAC-SHA256", exc
                )

        # Scheme-specific configuration
        if scheme == "pbkdf2":
            if iterations < _MIN_ITERS:
                raise HashSchemeError(f"Iterations must be >= {_MIN_ITERS}")
            self._iterations = iterations
            self._t = _DEF_T
            self._m = _DEF_M
            self._p = _DEF_P
        else:  # argon2id
            if time_cost < 2:
                raise HashSchemeError("time_cost must be >= 2")
            if memory_cost < 65_536:
                raise HashSchemeError("memory_cost must be >= 65,536 (64 MB)")
            if parallelism < 1:
                raise HashSchemeError("parallelism must be >= 1")

            self._iterations = _MIN_ITERS
            self._t = time_cost
            self._m = memory_cost
            self._p = parallelism

    def _peppered(self, password: str) -> bytes:
        """Apply pepper to password (HMAC-based KDF)."""
        if self._pepper_provider is None:
            return password.encode("utf-8")

        pepper = self._pepper_provider()
        pw_bytes = password.encode("utf-8")

        # Use BLAKE3 if available (10× faster)
        if self._use_blake3_pepper:
            assert hmac_blake3 is not None  # Type guard
            return hmac_blake3(pepper, pw_bytes)
        else:
            return hmac.new(pepper, pw_bytes, hashlib.sha256).digest()

    def hash_password(self, password: str) -> str:
        """
        Hash password with configured scheme.

        Args:
            password: User password (max 4096 chars)

        Returns:
            Encoded hash string

        Raises:
            HashSchemeError: On invalid password or hashing failure
        """
        if not password or len(password) > _MAX_PASSWORD_LEN:
            raise HashSchemeError("Invalid password length")

        pw_bytes = self._peppered(password)
        salt = generate_salt(self._salt_len)

        try:
            if self._scheme == "pbkdf2":
                return self._hash_pbkdf2(pw_bytes, salt)
            else:  # argon2id
                return self._hash_argon2(pw_bytes, salt)
        except Exception as exc:
            _LOGGER.error("Password hashing failed: %s", exc)
            raise HashSchemeError("Password hashing failed") from exc

    def _hash_pbkdf2(self, pw_bytes: bytes, salt: bytes) -> str:
        """Hash with PBKDF2-HMAC-SHA256."""
        dk = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, self._iterations, dklen=32)

        parts = ["pbkdf2", "sha256", str(self._iterations)]

        # Add pepper metadata if configured
        if self._pepper_provider and self._pepper_version:
            pepper = self._pepper_provider()
            vmac = _compute_pepper_version_mac(pepper, self._pepper_version)
            parts.append(f"pv={self._pepper_version}")
            parts.append(f"vmac={base64.b64encode(vmac).decode()}")

        parts.append(base64.b64encode(salt).decode())
        parts.append(base64.b64encode(dk).decode())

        return ":".join(parts)

    def _hash_argon2(self, pw_bytes: bytes, salt: bytes) -> str:
        """Hash with Argon2id."""
        hash_secret_raw, Type, version = _try_import_argon2()

        raw_hash = hash_secret_raw(
            pw_bytes,
            salt,
            time_cost=self._t,
            memory_cost=self._m,
            parallelism=self._p,
            hash_len=32,
            type=Type.ID,
            version=version,
        )

        parts = ["argon2id", str(self._t), str(self._m), str(self._p)]

        # Add pepper metadata if configured
        if self._pepper_provider and self._pepper_version:
            pepper = self._pepper_provider()
            vmac = _compute_pepper_version_mac(pepper, self._pepper_version)
            parts.append(f"pv={self._pepper_version}")
            parts.append(f"vmac={base64.b64encode(vmac).decode()}")

        parts.append(f"v={version}")
        parts.append(base64.b64encode(salt).decode())
        parts.append(base64.b64encode(raw_hash).decode())

        return ":".join(parts)

    def verify_password(
        self,
        password: str,
        hashed: str,
        identifier: Optional[str] = None,
    ) -> bool:
        """
        Verify password with timing attack protection.

        Args:
            password: User-provided password
            hashed: Stored hash string
            identifier: Optional identifier for rate limiting (e.g., username)

        Returns:
            True if password matches, False otherwise

        Security features:
        - Constant-time dummy operations (prevents timing leaks)
        - Global rate limiting (prevents distributed attacks)
        - Per-identifier rate limiting (prevents brute force)
        - Pepper version MAC verification (prevents downgrade attacks)
        """
        if not isinstance(password, str) or not isinstance(hashed, str):
            return False
        if not password or not hashed:
            return False

        # Apply rate limiting
        if self._rate_limit_enabled:
            try:
                _check_global_rate_limit()
                if identifier:
                    _check_rate_limit(identifier)
            except HashSchemeError:
                return False

        # Constant-time dummy operation (if parsing fails)
        def _dummy_hash() -> None:
            hashlib.pbkdf2_hmac("sha256", b"dummy", b"salt" * 2, 10000, dklen=32)

        try:
            parts = hashed.split(":")
            if len(parts) < 4:
                _dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

            scheme = parts[0]

            if scheme == "pbkdf2":
                result = self._verify_pbkdf2(password, parts, identifier, _dummy_hash)
            elif scheme == "argon2id":
                result = self._verify_argon2(password, parts, identifier, _dummy_hash)
            else:
                _LOGGER.warning("Unknown scheme: %s", scheme)
                _dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

            # Handle result
            if result:
                if identifier:
                    _clear_failed_attempts(identifier)
                _LOGGER.debug("%s verification successful", scheme.upper())
            else:
                if identifier:
                    _record_failed_attempt(identifier)
                _LOGGER.debug("%s verification failed", scheme.upper())

            return result

        except Exception as exc:
            _LOGGER.debug("Verification exception: %s", exc)
            _dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

    def _verify_pbkdf2(
        self,
        password: str,
        parts: List[str],
        identifier: Optional[str],
        dummy_hash: Callable[[], None],
    ) -> bool:
        """Verify PBKDF2 hash."""
        # Format: pbkdf2:sha256:iterations[:pv=X:vmac=Y]:salt:hash

        if parts[1] != "sha256":
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        try:
            iterations = int(parts[2])
        except ValueError:
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        # Parse metadata
        offset = 3
        pepper_version = None
        version_mac_expected = None

        # Check for pv
        if offset < len(parts) and parts[offset].startswith("pv="):
            pv_value = parts[offset][3:]
            if not pv_value:  # Empty pv=
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False
            pepper_version = pv_value
            offset += 1

            # pv MUST have vmac
            if offset >= len(parts) or not parts[offset].startswith("vmac="):
                _LOGGER.warning("Pepper version without MAC - invalid format")
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

            try:
                version_mac_expected = base64.b64decode(parts[offset][5:])
            except Exception:
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False
            offset += 1

        # Must have salt and hash
        if offset + 1 >= len(parts):
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        # Decode salt and hash
        try:
            salt = base64.b64decode(parts[offset])
            dk_stored = base64.b64decode(parts[offset + 1])
        except Exception:
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        # Verify pepper version MAC (if present)
        if pepper_version is not None:
            if self._pepper_provider is None:
                _LOGGER.warning("Hash requires pepper but no provider configured")
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

            pepper = self._pepper_provider()
            version_mac_actual = _compute_pepper_version_mac(pepper, pepper_version)

            assert version_mac_expected is not None  # Already checked above
            if not secure_compare(version_mac_actual, version_mac_expected):
                _LOGGER.warning("Pepper MAC mismatch - downgrade attack detected")
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

        # Compute hash
        pw_bytes = self._peppered(password)
        dk_candidate = hashlib.pbkdf2_hmac(
            "sha256", pw_bytes, salt, iterations, dklen=len(dk_stored)
        )

        return secure_compare(dk_candidate, dk_stored)

    def _verify_argon2(
        self,
        password: str,
        parts: List[str],
        identifier: Optional[str],
        dummy_hash: Callable[[], None],
    ) -> bool:
        """Verify Argon2id hash."""
        # Format: argon2id:t:m:p[:pv=X:vmac=Y]:v=19:salt:hash

        if len(parts) < 7:
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        try:
            t = int(parts[1])
            m = int(parts[2])
            p = int(parts[3])
        except ValueError:
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        # Parse metadata (strict order: pv, vmac, v)
        offset = 4
        pepper_version = None
        version_mac_expected = None
        stored_version = None

        # Check for pv
        if offset < len(parts) and parts[offset].startswith("pv="):
            pv_value = parts[offset][3:]
            if not pv_value:  # Empty pv=
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False
            pepper_version = pv_value
            offset += 1

            # pv MUST have vmac
            if offset >= len(parts) or not parts[offset].startswith("vmac="):
                _LOGGER.warning("Pepper version without MAC - invalid format")
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

            try:
                version_mac_expected = base64.b64decode(parts[offset][5:])
            except Exception:
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False
            offset += 1

        # Check for v
        if offset < len(parts) and parts[offset].startswith("v="):
            try:
                stored_version = int(parts[offset][2:])
            except ValueError:
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False
            offset += 1

            # Reject old versions
            if stored_version < _ARGON2_VERSION:
                _LOGGER.warning(
                    "Argon2 version %d < %d - rejected", stored_version, _ARGON2_VERSION
                )
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

        # Must have salt and hash
        if offset + 1 >= len(parts):
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        # Decode salt and hash
        try:
            salt = base64.b64decode(parts[offset])
            hash_stored = base64.b64decode(parts[offset + 1])
        except Exception:
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        # Verify pepper version MAC (if present)
        if pepper_version is not None:
            if self._pepper_provider is None:
                _LOGGER.warning("Hash requires pepper but no provider configured")
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

            pepper = self._pepper_provider()
            version_mac_actual = _compute_pepper_version_mac(pepper, pepper_version)

            assert version_mac_expected is not None  # Already checked above
            if not secure_compare(version_mac_actual, version_mac_expected):
                _LOGGER.warning("Pepper MAC mismatch - downgrade attack detected")
                dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False

        # Compute hash with Argon2id
        try:
            hash_secret_raw, Type, _ = _try_import_argon2()
        except (ImportError, HashSchemeError):
            _LOGGER.error("Argon2 not available")
            dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False

        pw_bytes = self._peppered(password)
        hash_candidate = hash_secret_raw(
            pw_bytes,
            salt,
            time_cost=t,
            memory_cost=m,
            parallelism=p,
            hash_len=len(hash_stored),
            type=Type.ID,
            version=_ARGON2_VERSION,
        )

        return secure_compare(hash_candidate, hash_stored)

    def needs_rehash(self, hashed: str) -> bool:
        """
        Check if hash needs parameter upgrade.

        Returns True if:
        - Parameters are weaker than configured
        - Wrong pepper version
        - Malformed format
        - Old Argon2 version
        """
        try:
            parts = hashed.split(":")
            if len(parts) < 4:
                return True

            scheme = parts[0]

            if scheme == "pbkdf2":
                # Must be sha256
                if len(parts) < 3 or parts[1] != "sha256":
                    return True

                # Check iterations
                try:
                    iterations = int(parts[2])
                except ValueError:
                    return True

                # Parse metadata
                offset = 3
                stored_pv = None

                if offset < len(parts) and parts[offset].startswith("pv="):
                    pv_value = parts[offset][3:]
                    if not pv_value:  # Empty pv=
                        return True
                    stored_pv = pv_value
                    offset += 1

                    # Must have vmac
                    if offset >= len(parts) or not parts[offset].startswith("vmac="):
                        return True
                    offset += 1

                # Must have salt and hash
                if offset + 1 >= len(parts):
                    return True

                # Check pepper version mismatch
                if stored_pv and self._pepper_provider and self._pepper_version:
                    if stored_pv != self._pepper_version:
                        return True

                # Check weak iterations
                return iterations < self._iterations

            elif scheme == "argon2id":
                # Parse t, m, p
                try:
                    t = int(parts[1])
                    m = int(parts[2])
                    p = int(parts[3])
                except (ValueError, IndexError):
                    return True

                # Parse metadata
                offset = 4
                stored_pv = None
                stored_version = None

                # Check for pv
                if offset < len(parts) and parts[offset].startswith("pv="):
                    pv_value = parts[offset][3:]
                    if not pv_value:  # Empty pv=
                        return True
                    stored_pv = pv_value
                    offset += 1

                    # Must have vmac
                    if offset >= len(parts) or not parts[offset].startswith("vmac="):
                        return True
                    offset += 1

                # Check for v
                if offset < len(parts) and parts[offset].startswith("v="):
                    try:
                        stored_version = int(parts[offset][2:])
                    except ValueError:
                        return True
                    offset += 1

                # Must have salt and hash
                if offset + 1 >= len(parts):
                    return True

                # Check version mismatch
                if stored_version is not None and stored_version != _ARGON2_VERSION:
                    return True

                # Check pepper version mismatch
                if stored_pv and self._pepper_provider and self._pepper_version:
                    if stored_pv != self._pepper_version:
                        return True

                # Check weak parameters
                return t < self._t or m < self._m or p < self._p

            # Unknown scheme
            return True

        except Exception:
            return True


__all__ = ["PasswordHasher"]
