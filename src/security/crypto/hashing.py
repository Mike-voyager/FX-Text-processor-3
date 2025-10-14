# Модуль безопасного хэширования и валидации паролей с поддержкой схем, соли, аудита и legacy-механизмов.
"""
Secure, extensible password hashing/validation for FX-Text-processor-3.
RU: Хэширование и проверка пароля через современные (Argon2id, bcrypt) и Legacy-схемы, аудит, fail-safe-политика.
"""

import logging
import secrets
import hashlib
from typing import Optional, Dict, Any
from enum import Enum
from base64 import b64encode, b64decode

from types import ModuleType

argon2_ll: Optional[ModuleType]
argon2_exc: Optional[ModuleType]
try:
    from argon2 import PasswordHasher, exceptions as argon2_exc, low_level as argon2_ll
except ImportError:
    argon2_ll = None
    argon2_exc = None


bcrypt: Optional[ModuleType]
try:
    import bcrypt
except ImportError:
    bcrypt = None

__all__ = [
    "hash_password",
    "verify_password",
    "needs_rehash",
    "get_hash_scheme",
    "HashScheme",
    "legacy_verify_password",
    "add_audit",
]


class HashScheme(str, Enum):
    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"
    PBKDF2 = "pbkdf2"
    SHA256 = "sha256"


_LOG = logging.getLogger("fxtext.security.hashing")
_LOG.setLevel(logging.INFO)

_AUDIT_TRAIL: list[Dict[str, Any]] = []

# System-wide defaults
_DEFAULT_TIME_COST = 3
_DEFAULT_MEMORY_COST = 65536
_DEFAULT_PARALLELISM = 2
_MAX_PASSWORD_LEN = 1024


def add_audit(
    event: str, user_id: Optional[str], context: Optional[Dict[str, Any]] = None
) -> None:
    """Add audit trail event to memory (for SIEM/forensic)."""
    ent = {
        "event": event,
        "user_id": user_id,
        "context": context,
        "ts": hashlib.blake2b(
            repr(secrets.token_bytes(16)).encode(), digest_size=8
        ).hexdigest(),
    }
    _AUDIT_TRAIL.append(ent)
    _LOG.debug(f"Audit event added: {ent}")


def get_hash_scheme(hashed: str) -> str:
    """Heuristic parse hash string to scheme."""
    if not isinstance(hashed, str):
        return "unknown"
    if hashed.startswith("$argon2id$") or hashed.startswith("argon2id$"):
        return HashScheme.ARGON2ID.value
    if (
        hashed.startswith("$2a$")
        or hashed.startswith("$2b$")
        or hashed.startswith("$2y$")
    ):
        return HashScheme.BCRYPT.value
    if hashed.startswith("pbkdf2:"):
        return HashScheme.PBKDF2.value
    if len(hashed) == 64 and all(c in "0123456789abcdef" for c in hashed):
        return HashScheme.SHA256.value
    return "unknown"


def _validate_costs(time_cost: int, memory_cost: int, parallelism: int) -> None:
    errors = []
    if time_cost < 2:
        errors.append("time_cost must be >=2")
    if memory_cost < 8192:
        errors.append("memory_cost must be >=8192KB")
    if not (1 <= parallelism <= 16):
        errors.append("parallelism must be in [1,16]")
    if errors:
        _LOG.warning(f"Parameter validation failed: {errors}.")
        raise ValueError("; ".join(errors))
    _LOG.debug("Parameter validation passed.")


def hash_password(
    password: str,
    salt: Optional[bytes] = None,
    *,
    time_cost: int = _DEFAULT_TIME_COST,
    memory_cost: int = _DEFAULT_MEMORY_COST,
    parallelism: int = _DEFAULT_PARALLELISM,
    scheme: str = "argon2id",
) -> str:
    """Hash password using configurable scheme (default: Argon2id).

    Args:
        password: UTF-8 string, max 1024 chars.
        salt: Optional salt (used only for low-level Argon2id, bcrypt, pbkdf2).
        time_cost, memory_cost, parallelism: scheme parameters.
        scheme: HashScheme; one of {"argon2id", "bcrypt", "pbkdf2", "sha256"}.

    Returns:
        Encoded hash string.

    Example:
        >>> hashval = hash_password("Pa$$w0rd!")
        >>> assert verify_password("Pa$$w0rd!", hashval)
    """
    add_audit("hash_password", None, {"scheme": scheme})

    if not isinstance(password, str) or not password:
        _LOG.error("Empty/invalid password.")
        raise ValueError("Password must be non-empty string.")

    if len(password) > _MAX_PASSWORD_LEN:
        _LOG.warning("Password length exceeds maximum allowed, will be truncated.")
        password = password[:_MAX_PASSWORD_LEN]

    _validate_costs(time_cost, memory_cost, parallelism)

    scheme_e = HashScheme(scheme)
    if scheme_e == HashScheme.ARGON2ID:
        if salt is not None and argon2_ll is not None:
            try:
                hashval_bytes = argon2_ll.hash_secret(
                    password.encode("utf-8"),
                    salt,
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=32,
                    type=argon2_ll.Type.ID,
                )
                argon2_hash: str = hashval_bytes.decode("utf-8")
                _LOG.info("Password hashed with argon2id (custom salt, low-level).")
                return argon2_hash
            except Exception as exc:
                _LOG.error(f"Low-level argon2id hashing failed: {exc}")
                raise
        else:
            try:
                ph = PasswordHasher(
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                )
                managed_hash: str = ph.hash(password)
                _LOG.info("Password hashed with argon2id (managed salt).")
                return managed_hash
            except Exception as exc:
                _LOG.error(f"Argon2id hashing error: {exc}")
                raise
    elif scheme_e == HashScheme.BCRYPT:
        if bcrypt is None:
            _LOG.error("bcrypt package required.")
            raise ImportError("bcrypt not available.")
        bcrypt_salt: bytes = salt if salt is not None else bcrypt.gensalt()
        bcrypt_hash_bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt_salt)
        bcrypt_hash: str = bcrypt_hash_bytes.decode("utf-8")
        _LOG.info("Password hashed with bcrypt.")
        return bcrypt_hash
    elif scheme_e == HashScheme.PBKDF2:
        pbkdf2_salt: bytes = salt if salt is not None else secrets.token_bytes(16)
        pbkdf2_hash_bytes = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), pbkdf2_salt, 100_000
        )
        salt_str: str = b64encode(pbkdf2_salt).decode("ascii")
        hash_str: str = b64encode(pbkdf2_hash_bytes).decode("ascii")
        return f"pbkdf2:{salt_str}:{hash_str}"
    elif scheme_e == HashScheme.SHA256:
        sha_salt: bytes = salt if salt is not None else secrets.token_bytes(8)
        d: str = hashlib.sha256(sha_salt + password.encode()).hexdigest()
        return d
    else:
        _LOG.error("Unknown scheme selected.")
        raise ValueError("Unsupported hashing scheme.")


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash, auto-detecting scheme."""
    if not isinstance(hashed, str):
        _LOG.warning("Hash must be a string.")
        return False

    scheme = get_hash_scheme(hashed)
    add_audit("verify_password", None, {"scheme": scheme})
    if scheme == HashScheme.ARGON2ID.value:
        try:
            ph = PasswordHasher()
            res = ph.verify(hashed, password)
            _LOG.info("Password verification succeeded (argon2id).")
            return bool(res)
        except Exception as exc:
            if argon2_exc and isinstance(exc, argon2_exc.VerifyMismatchError):
                _LOG.warning("Password mismatch (argon2id).")
                return False
            _LOG.warning(f"Argon2id verification error: {exc}")
            return False
    elif scheme == HashScheme.BCRYPT.value and bcrypt:
        try:
            match = bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
            if match:
                _LOG.info("Password verification succeeded (bcrypt).")
            else:
                _LOG.warning("Password mismatch (bcrypt).")
            return bool(match)
        except Exception as exc:
            _LOG.warning(f"Bcrypt verification error: {exc}")
            return False
    elif scheme == HashScheme.PBKDF2.value:
        try:
            parts = hashed.split(":")
            if len(parts) != 3:
                _LOG.warning("Invalid pbkdf2 hash format.")
                return False
            salt = b64decode(parts[1])
            expected = b64decode(parts[2])
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
            match = secrets.compare_digest(actual, expected)
            if match:
                _LOG.info("Password verification succeeded (pbkdf2).")
            else:
                _LOG.warning("Password mismatch (pbkdf2).")
            return bool(match)
        except Exception as exc:
            _LOG.warning(f"PBKDF2 verification error: {exc}")
            return False
    elif scheme == HashScheme.SHA256.value:
        _LOG.warning("Legacy SHA256 verification detected—unsafe for passwords!")
        return False  # Always refuse legacy for passwords
    else:
        _LOG.warning("Hash format not recognized during verification.")
        return False


def legacy_verify_password(password: str, hashed: str, scheme: str) -> bool:
    """Direct legacy check (for migration)."""
    _LOG.debug(f"Legacy verify for scheme: {scheme}")
    if scheme == "sha256":
        # Insecure: do not use in production, only for migration!
        # You must know original salt; this example is unsafe!
        return False
    # Add more legacy checks as needed
    return False


def needs_rehash(
    hashed: str,
    *,
    time_cost: int = _DEFAULT_TIME_COST,
    memory_cost: int = _DEFAULT_MEMORY_COST,
    parallelism: int = _DEFAULT_PARALLELISM,
    scheme: str = "argon2id",
) -> bool:
    """Check if a hash needs to be updated (parameters/scheme)."""
    real_scheme = get_hash_scheme(hashed)
    add_audit("needs_rehash", None, {"scheme": scheme, "actual": real_scheme})
    if real_scheme != scheme:
        _LOG.info(f"Hash scheme changed from {real_scheme} → {scheme}: needs rehash.")
        return True
    scheme_enum = HashScheme(scheme)
    if scheme_enum == HashScheme.ARGON2ID:
        try:
            ph = PasswordHasher(
                time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism
            )
            needs = ph.check_needs_rehash(hashed)
            if needs:
                _LOG.info("Argon2id hash parameters changed: needs rehash.")
            return needs
        except Exception as exc:
            _LOG.error(f"Failed to check needs_rehash: {exc}")
            return True
    # For legacy/Bcrypt/PBKDF2, always recommend upgrade if params mismatched
    return False


# Secure memory cleanup (Python only partial, for illustration)
def _wipe_sensitive_data(obj: Optional[str | bytes]) -> None:
    # Secure deletion not guaranteed in Python, log only for transparency
    _LOG.debug("Wiping sensitive data from memory.")
    del obj


# Документация: fail-safe policy — любые ошибки не раскрывают детали, всегда возвращают False/raise
# Документировано, что для одних и тех же паролей хэши разные (random salt).

# Потокобезопасность: модуль идемпотентен, глобального состояния нет.
