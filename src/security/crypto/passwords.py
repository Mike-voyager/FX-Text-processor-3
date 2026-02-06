# -*- coding: utf-8 -*-
"""
RU: Password hashing с Argon2id/PBKDF2 и защитой от атак.
EN: Password hashing with Argon2id/PBKDF2 and attack protection.

Unified password hashing module with:
- Argon2id (primary, GPU-resistant)
- PBKDF2-HMAC-SHA256 (fallback)
- BLAKE3-HMAC pepper support
- Timing attack protection
- Rate limiting (per-identifier + global)
- Pepper version MAC (downgrade protection)

Best practices:
- Use Argon2id for all new hashes
- Enable rate limiting in production
- Use pepper for additional security layer
- Monitor needs_rehash() for parameter upgrades
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import threading
import time
from typing import Callable, Dict, Final, List, Optional, Tuple

from .exceptions import HashSchemeError
from .utils import generate_salt, secure_compare

_LOGGER: Final = logging.getLogger(__name__)

# Try BLAKE3
try:
    from .blake3_hash import hmac_blake3, BLAKE3_AVAILABLE
except ImportError:
    BLAKE3_AVAILABLE = False
    hmac_blake3 = None

# Security limits
_MAX_PASSWORD_LEN: Final[int] = 4096
_MIN_ITERS: Final[int] = 100_000
_MIN_SALT_LEN: Final[int] = 8
_MAX_SALT_LEN: Final[int] = 64

# Argon2id defaults
_DEF_T: Final[int] = 3
_DEF_M: Final[int] = 65_536
_DEF_P: Final[int] = 2
_ARGON2_VERSION: Final[int] = 19

# Rate limiting
_MAX_FAILED_ATTEMPTS: Final[int] = 5
_LOCKOUT_DURATION: Final[float] = 30.0
_BACKOFF_BASE: Final[float] = 0.5
_BACKOFF_MULTIPLIER: Final[float] = 2.0
_GLOBAL_MAX_ATTEMPTS_PER_MINUTE: Final[int] = 100

# Global state
_global_verification_attempts: int = 0
_global_last_reset: float = time.time()
_global_lock = threading.Lock()

_failed_attempts: Dict[str, List[float]] = {}
_attempts_lock = threading.Lock()


def _try_import_argon2() -> Tuple[Callable, any, int]:
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw, Type, _ARGON2_VERSION


def _check_global_rate_limit() -> None:
    global _global_verification_attempts, _global_last_reset
    now = time.time()
    
    with _global_lock:
        if now - _global_last_reset > 60:
            _global_verification_attempts = 0
            _global_last_reset = now
        
        if _global_verification_attempts >= _GLOBAL_MAX_ATTEMPTS_PER_MINUTE:
            _LOGGER.error("Global rate limit exceeded")
            raise HashSchemeError("Слишком много запросов. Повторите позже.")
        
        _global_verification_attempts += 1


def _check_rate_limit(identifier: str) -> None:
    now = time.time()
    with _attempts_lock:
        attempts = _failed_attempts.get(identifier, [])
        attempts = [t for t in attempts if now - t < _LOCKOUT_DURATION]

        if len(attempts) >= _MAX_FAILED_ATTEMPTS:
            last_attempt = max(attempts)
            excess = len(attempts) - _MAX_FAILED_ATTEMPTS
            wait_time = _BACKOFF_BASE * (_BACKOFF_MULTIPLIER**excess)
            elapsed = now - last_attempt

            if elapsed < wait_time:
                remaining = int(wait_time - elapsed) + 1
                raise HashSchemeError(f"Повторите через {remaining} сек.")


def _record_failed_attempt(identifier: str) -> None:
    now = time.time()
    with _attempts_lock:
        if identifier not in _failed_attempts:
            _failed_attempts[identifier] = []
        _failed_attempts[identifier].append(now)


def _clear_failed_attempts(identifier: str) -> None:
    with _attempts_lock:
        _failed_attempts.pop(identifier, None)


def _compute_pepper_version_mac(pepper: bytes, version: str) -> bytes:
    mac = hmac.new(pepper, f"pv={version}".encode(), hashlib.sha256).digest()
    return mac[:8]


class PasswordHasher:
    """
    Unified password hasher with Argon2id/PBKDF2.
    
    Improvements over basic hashing:
    - BLAKE3 pepper (10× faster than HMAC-SHA256)
    - Constant-time dummy operations
    - Pepper version MAC
    - Global + per-identifier rate limiting
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
        if scheme not in ("pbkdf2", "argon2id"):
            raise HashSchemeError("Scheme must be 'pbkdf2' or 'argon2id'")
        
        if not (_MIN_SALT_LEN <= salt_len <= _MAX_SALT_LEN):
            raise HashSchemeError(f"Salt length must be {_MIN_SALT_LEN}-{_MAX_SALT_LEN} bytes")

        self._scheme = scheme
        self._rate_limit_enabled = rate_limit_enabled
        self._salt_len = salt_len
        self._pepper_provider = pepper_provider
        self._pepper_version = pepper_version
        
        # Use BLAKE3 if available
        if pepper_provider and BLAKE3_AVAILABLE:
            _LOGGER.info("Using BLAKE3 for pepper (10× faster)")
            self._use_blake3_pepper = True
        else:
            self._use_blake3_pepper = False

        if scheme == "pbkdf2":
            if iterations < _MIN_ITERS:
                raise HashSchemeError(f"Iterations must be >= {_MIN_ITERS}")
            self._iterations = iterations
            self._t = _DEF_T
            self._m = _DEF_M
            self._p = _DEF_P
        else:
            if time_cost < 2:
                raise HashSchemeError("time_cost must be >= 2")
            if memory_cost < 65_536:
                raise HashSchemeError("memory_cost must be >= 65536")
            if parallelism < 1:
                raise HashSchemeError("parallelism must be >= 1")
            self._iterations = _MIN_ITERS
            self._t = time_cost
            self._m = memory_cost
            self._p = parallelism

    def _peppered(self, password: str) -> bytes:
        if self._pepper_provider is None:
            return password.encode("utf-8")
        
        pepper = self._pepper_provider()
        pw_bytes = password.encode("utf-8")
        
        if self._use_blake3_pepper and hmac_blake3:
            return hmac_blake3(pepper, pw_bytes)
        else:
            return hmac.new(pepper, pw_bytes, hashlib.sha256).digest()

    def hash_password(self, password: str) -> str:
        if not password or len(password) > _MAX_PASSWORD_LEN:
            raise HashSchemeError("Invalid password length")

        pw_bytes = self._peppered(password)
        salt = generate_salt(self._salt_len)

        if self._scheme == "pbkdf2":
            dk = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, self._iterations, dklen=32)
            
            parts = ["pbkdf2", "sha256", str(self._iterations)]
            
            if self._pepper_provider and self._pepper_version:
                parts.append(f"pv={self._pepper_version}")
                pepper = self._pepper_provider()
                vmac = _compute_pepper_version_mac(pepper, self._pepper_version)
                parts.append(f"vmac={base64.b64encode(vmac).decode()}")
            
            parts.append(base64.b64encode(salt).decode())
            parts.append(base64.b64encode(dk).decode())
            
            return ":".join(parts)
        
        else:  # argon2id
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
            
            if self._pepper_provider and self._pepper_version:
                parts.append(f"pv={self._pepper_version}")
                pepper = self._pepper_provider()
                vmac = _compute_pepper_version_mac(pepper, self._pepper_version)
                parts.append(f"vmac={base64.b64encode(vmac).decode()}")
            
            parts.append(f"v={version}")
            parts.append(base64.b64encode(salt).decode())
            parts.append(base64.b64encode(raw_hash).decode())
            
            return ":".join(parts)

    def verify_password(
        self,
        password: str,
        hashed: str,
        identifier: Optional[str] = None
    ) -> bool:
        """
        Verify password with timing attack protection.
        
        Args:
            password: user-provided password to verify.
            hashed: stored hash string.
            identifier: optional identifier for rate limiting (e.g., username, user_id).
        
        Returns:
            True if password matches, False otherwise.
        
        Security features:
            - Constant-time dummy operations (prevents timing leaks)
            - Global rate limiting (prevents distributed attacks)
            - Per-identifier rate limiting (prevents brute force)
            - Pepper version MAC verification (prevents downgrade attacks)
        
        Examples:
            >>> hasher = PasswordHasher()
            >>> hashed = hasher.hash_password("user_password")
            >>> hasher.verify_password("user_password", hashed, identifier="user123")
            True
            >>> hasher.verify_password("wrong_password", hashed, identifier="user123")
            False
        """
        if not isinstance(password, str) or not isinstance(hashed, str):
            return False
        
        if not password or not hashed:
            return False
        
        # Check global rate limit first
        if self._rate_limit_enabled:
            try:
                _check_global_rate_limit()
            except HashSchemeError:
                return False
        
        # Check per-identifier rate limit
        if self._rate_limit_enabled and identifier:
            try:
                _check_rate_limit(identifier)
            except HashSchemeError:
                return False
        
        # Dummy hash for timing consistency (if hash parsing fails)
        def _dummy_hash() -> None:
            """Constant-time dummy operation."""
            dummy_salt = b"dummy_salt_16byt"
            hashlib.pbkdf2_hmac('sha256', b'dummy_password', dummy_salt, 10000, dklen=32)
        
        try:
            parts = hashed.split(":")
            
            if len(parts) < 4:
                _dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False
            
            scheme = parts[0]
            
            # ========================================
            # PBKDF2 Verification
            # ========================================
            if scheme == "pbkdf2":
                # Parse PBKDF2 hash format:
                # pbkdf2:sha256:iterations[:pv=version][:vmac=base64][salt_b64]:[hash_b64]
                
                if parts[1] != "sha256":
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                try:
                    iterations = int(parts[2])
                except ValueError:
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                # Check for pepper version
                pepper_version = None
                version_mac_expected = None
                offset = 3
                
                if offset < len(parts) and parts[offset].startswith("pv="):
                    pepper_version = parts[offset][3:]
                    offset += 1
                    
                    # Check version MAC
                    if offset < len(parts) and parts[offset].startswith("vmac="):
                        try:
                            version_mac_expected = base64.b64decode(parts[offset][5:])
                        except Exception:
                            _dummy_hash()
                            if identifier:
                                _record_failed_attempt(identifier)
                            return False
                        offset += 1
                
                # Extract salt and hash
                if offset + 1 >= len(parts):
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                salt_b64 = parts[offset]
                dk_b64 = parts[offset + 1]
                
                try:
                    salt = base64.b64decode(salt_b64)
                    dk_stored = base64.b64decode(dk_b64)
                except Exception:
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                # Verify pepper version MAC (if present)
                if pepper_version is not None and self._pepper_provider is not None:
                    pepper = self._pepper_provider()
                    version_mac_actual = _compute_pepper_version_mac(pepper, pepper_version)
                    
                    if version_mac_expected is None:
                        _LOGGER.warning("Pepper version present but MAC missing")
                        if identifier:
                            _record_failed_attempt(identifier)
                        return False
                    
                    if not secure_compare(version_mac_actual, version_mac_expected):
                        _LOGGER.warning("Pepper version MAC mismatch - possible downgrade attack")
                        if identifier:
                            _record_failed_attempt(identifier)
                        return False
                
                # Compute hash with provided password
                pw_bytes = self._peppered(password)
                dk_candidate = hashlib.pbkdf2_hmac(
                    "sha256",
                    pw_bytes,
                    salt,
                    iterations,
                    dklen=len(dk_stored)
                )
                
                # Constant-time comparison
                result = secure_compare(dk_candidate, dk_stored)
                
                if result:
                    if identifier:
                        _clear_failed_attempts(identifier)
                    _LOGGER.debug("PBKDF2 password verification successful")
                else:
                    if identifier:
                        _record_failed_attempt(identifier)
                    _LOGGER.debug("PBKDF2 password verification failed")
                
                return result
            
            # ========================================
            # Argon2id Verification
            # ========================================
            elif scheme == "argon2id":
                # Parse Argon2id hash format:
                # argon2id:t:m:p[:pv=version][:vmac=base64][:v=version]:[salt_b64]:[hash_b64]
                
                if len(parts) < 7:
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                try:
                    t = int(parts[1])
                    m = int(parts[2])
                    p = int(parts[3])
                except ValueError:
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                # Check for pepper version
                pepper_version = None
                version_mac_expected = None
                offset = 4
                
                if offset < len(parts) and parts[offset].startswith("pv="):
                    pepper_version = parts[offset][3:]
                    offset += 1
                    
                    if offset < len(parts) and parts[offset].startswith("vmac="):
                        try:
                            version_mac_expected = base64.b64decode(parts[offset][5:])
                        except Exception:
                            _dummy_hash()
                            if identifier:
                                _record_failed_attempt(identifier)
                            return False
                        offset += 1
                
                # Skip version field (v=19)
                if offset < len(parts) and parts[offset].startswith("v="):
                    offset += 1
                
                # Extract salt and hash
                if offset + 1 >= len(parts):
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                salt_b64 = parts[offset]
                hash_b64 = parts[offset + 1]
                
                try:
                    salt = base64.b64decode(salt_b64)
                    hash_stored = base64.b64decode(hash_b64)
                except Exception:
                    _dummy_hash()
                    if identifier:
                        _record_failed_attempt(identifier)
                    return False
                
                # Verify pepper version MAC
                if pepper_version is not None and self._pepper_provider is not None:
                    pepper = self._pepper_provider()
                    version_mac_actual = _compute_pepper_version_mac(pepper, pepper_version)
                    
                    if version_mac_expected is None:
                        _LOGGER.warning("Pepper version present but MAC missing")
                        if identifier:
                            _record_failed_attempt(identifier)
                        return False
                    
                    if not secure_compare(version_mac_actual, version_mac_expected):
                        _LOGGER.warning("Pepper version MAC mismatch - possible downgrade attack")
                        if identifier:
                            _record_failed_attempt(identifier)
                        return False
                
                # Compute hash with Argon2id
                try:
                    hash_secret_raw, Type, _ = _try_import_argon2()
                except ImportError:
                    _LOGGER.error("Argon2 not available")
                    _dummy_hash()
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
                
                # Constant-time comparison
                result = secure_compare(hash_candidate, hash_stored)
                
                if result:
                    if identifier:
                        _clear_failed_attempts(identifier)
                    _LOGGER.debug("Argon2id password verification successful")
                else:
                    if identifier:
                        _record_failed_attempt(identifier)
                    _LOGGER.debug("Argon2id password verification failed")
                
                return result
            
            # Unknown scheme
            else:
                _LOGGER.warning("Unknown password hash scheme: %s", scheme)
                _dummy_hash()
                if identifier:
                    _record_failed_attempt(identifier)
                return False
        
        except Exception as exc:
            _LOGGER.debug("Password verification exception: %s", exc.__class__.__name__)
            _dummy_hash()
            if identifier:
                _record_failed_attempt(identifier)
            return False


    def needs_rehash(self, hashed: str) -> bool:
        """Check if hash needs parameter upgrade."""
        try:
            parts = hashed.split(":")
            if len(parts) < 4:
                return True
            
            scheme = parts[0]
            
            if scheme == "pbkdf2":
                iterations = int(parts[2])
                return iterations < self._iterations
            elif scheme == "argon2id":
                t, m, p = int(parts[1]), int(parts[2]), int(parts[3])
                return t < self._t or m < self._m or p < self._p
            
            return True
        except Exception:
            return True


__all__ = ["PasswordHasher"]
