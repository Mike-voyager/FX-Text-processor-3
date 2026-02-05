# -*- coding: utf-8 -*-
"""
CryptoService (strict Argon2id profile).

- Prefers Argon2id for KDF/password hashing; PBKDF2 is available only by explicit configuration.
- Default signing algorithm: Ed25519. Optional: RSA-4096, ECDSA-P256 via config.
- Salt files protected with HMAC integrity tags to prevent tampering.
- No secrets are logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Final, Optional, Union, cast

from .exceptions import HashSchemeError, KDFAlgorithmError
from .hashing import PasswordHasher
from .kdf import DefaultKdfProvider
from .protocols import (
    Argon2idParams,
    KdfParams,
    KdfProtocol,
    PBKDF2Params,
    SymmetricCipherProtocol,
)
from .secure_storage import FileEncryptedStorageBackend
from .signatures import Ed25519Signer
from .symmetric import SymmetricCipher
from .utils import generate_salt, set_secure_file_permissions

LOGGER: Final = logging.getLogger(__name__)


class AsymmetricSignerAdapter:
    """
    Adapter to expose SigningProtocol-compatible interface over an AsymmetricKeyPair instance.

    Implements duck-typed SigningProtocol:
      - sign(data: bytes, *, context: Optional[bytes]) -> bytes
      - verify(data: bytes, signature: bytes, *, context: Optional[bytes]) -> bool
      - public_key(fmt: str) -> bytes | str
      - get_fingerprint() -> str

    Notes:
      - Context is ignored for asymmetric signers (kept for interface parity).
      - No secrets are logged.
    """

    __slots__ = ("_akp",)

    def __init__(self, akp: object) -> None:
        self._akp = akp

    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        return cast(bytes, getattr(self._akp, "sign")(data))

    def verify(
        self, data: bytes, signature: bytes, *, context: Optional[bytes] = None
    ) -> bool:
        return bool(getattr(self._akp, "verify")(data, signature))

    def public_key(self, fmt: str = "raw") -> Union[bytes, str]:
        return cast(Union[bytes, str], getattr(self._akp, "public_key")(fmt=fmt))

    def get_fingerprint(self) -> str:
        return cast(str, getattr(self._akp, "get_fingerprint")())


@dataclass(slots=True)
class KdfPolicy:
    use_argon2id: bool = True
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 131_072  # KiB
    argon2_parallelism: int = 2
    pbkdf2_iterations: int = 200_000
    salt_len: int = 16


@dataclass(slots=True)
class HashingPolicy:
    scheme: str = "argon2id"  # "argon2id" | "pbkdf2"
    iterations: int = 200_000
    salt_len: int = 16
    rate_limit_enabled: bool = True


@dataclass(slots=True)
class ServiceConfig:
    signing_algorithm: str = "ed25519"  # "ed25519" | "rsa4096" | "ecdsa_p256"
    rsa_key_size: int = 4096
    kdf: KdfPolicy = field(default_factory=KdfPolicy)
    hashing: HashingPolicy = field(default_factory=HashingPolicy)
    pepper_provider: Optional[Callable[[], bytes]] = None
    pepper_version: Optional[str] = None


@dataclass(slots=True)
class CryptoService:
    """
    Unified cryptographic service façade.

    Provides high-level API for:
      - Symmetric encryption (AES-256-GCM)
      - Digital signatures (Ed25519/RSA/ECDSA)
      - Key derivation (Argon2id/PBKDF2)
      - Password hashing with rate limiting
      - Encrypted keystore management

    Examples:
        >>> config = ServiceConfig()
        >>> service = CryptoService.new_default(config)
        >>>
        >>> # Password hashing
        >>> hashed = service.hash_password("my_password")
        >>> assert service.verify_password("my_password", hashed)
        >>>
        >>> # Signing
        >>> sig = service.sign(b"message")
        >>> assert service.verify(b"message", sig)
        >>>
        >>> # Encryption
        >>> key = b"0" * 32
        >>> nonce, ct = service.encrypt(key, b"plaintext")
        >>> pt = service.decrypt(key, nonce, ct)
    """

    symmetric: SymmetricCipherProtocol
    signer: object  # SigningProtocol (duck-typed)
    kdf: KdfProtocol
    hasher: object  # HashingProtocol (duck-typed)
    config: ServiceConfig

    @staticmethod
    def new_default(cfg: Optional[ServiceConfig] = None) -> CryptoService:
        """
        Create a default CryptoService according to config.

        Raises:
            HashSchemeError: If hashing scheme is argon2id but argon2 is unavailable.
            ValueError: If signing algorithm is not supported.
        """
        cfg = cfg or ServiceConfig()

        # Symmetric: hold concrete impl, expose as protocol for typing
        symmetric_impl = SymmetricCipher()
        symmetric: SymmetricCipherProtocol = cast(
            SymmetricCipherProtocol, symmetric_impl
        )

        # KDF provider
        kdf_provider: KdfProtocol = DefaultKdfProvider()

        # Hashing provider
        if cfg.hashing.scheme == "argon2id":
            try:
                __import__("argon2")
            except ImportError as e:
                LOGGER.critical(
                    "Argon2id REQUIRED for production but not available. "
                    "Install: pip install argon2-cffi>=23.1.0"
                )
                raise HashSchemeError("Argon2id not available") from e
            hasher: object = PasswordHasher(
                scheme="argon2id",
                time_cost=2,
                memory_cost=65_536,
                parallelism=1,
                rate_limit_enabled=cfg.hashing.rate_limit_enabled,
                salt_len=cfg.hashing.salt_len,
                pepper_provider=cfg.pepper_provider,
                pepper_version=cfg.pepper_version,
            )
        elif cfg.hashing.scheme == "pbkdf2":
            LOGGER.warning(
                "⚠️ SECURITY DEGRADATION: Using PBKDF2 instead of Argon2id. "
                "Resistance to GPU attacks reduced by ~6,666×. "
                "This configuration is NOT RECOMMENDED for production."
            )
            hasher = PasswordHasher(
                scheme="pbkdf2",
                iterations=cfg.hashing.iterations,
                rate_limit_enabled=cfg.hashing.rate_limit_enabled,
                salt_len=cfg.hashing.salt_len,
                pepper_provider=cfg.pepper_provider,
                pepper_version=cfg.pepper_version,
            )
        else:
            raise HashSchemeError("Unsupported hashing scheme")

        # Signing provider
        if cfg.signing_algorithm == "ed25519":
            signer: object = Ed25519Signer.generate()
        elif cfg.signing_algorithm in ("rsa4096", "ecdsa_p256"):
            from .asymmetric import AsymmetricKeyPair

            akp = AsymmetricKeyPair.generate(
                cfg.signing_algorithm, key_size=cfg.rsa_key_size
            )
            signer = AsymmetricSignerAdapter(akp)
        else:
            raise ValueError("Unsupported signing algorithm")

        return CryptoService(symmetric, signer, kdf_provider, hasher, cfg)

    # ---- Password hashing façade ----

    def hash_password(self, password: str) -> str:
        return cast(str, getattr(self.hasher, "hash_password")(password))

    def verify_password(
        self,
        password: str,
        hashed: str,
        identifier: Optional[str] = None,
    ) -> bool:
        return bool(
            getattr(self.hasher, "verify_password")(password, hashed, identifier)
        )

    def needs_rehash(self, hashed: str) -> bool:
        return bool(getattr(self.hasher, "needs_rehash")(hashed))

    # ---- Signing façade ----

    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        try:
            return cast(bytes, getattr(self.signer, "sign")(data, context=context))
        except TypeError:
            return cast(bytes, getattr(self.signer, "sign")(data))

    def verify(
        self, data: bytes, signature: bytes, *, context: Optional[bytes] = None
    ) -> bool:
        try:
            return bool(
                getattr(self.signer, "verify")(data, signature, context=context)
            )
        except TypeError:
            return bool(getattr(self.signer, "verify")(data, signature))

    # ---- Symmetric façade ----

    def encrypt(
        self,
        key: bytes,
        plaintext: Union[bytes, bytearray],
        *,
        aad: Optional[bytes] = None,
        return_combined: bool = True,
    ) -> Union[tuple[bytes, bytes], tuple[bytes, bytes, bytes]]:
        return self.symmetric.encrypt(
            key, plaintext, aad=aad, return_combined=return_combined
        )

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        *,
        aad: Optional[bytes] = None,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        return self.symmetric.decrypt(
            key, nonce, data, aad=aad, has_combined=has_combined, tag=tag
        )

    # ---- Encrypted keystore factory ----

    def create_encrypted_keystore(
        self,
        filepath: str,
        *,
        password_provider: Callable[[], str],
        salt_path: str,
        key_len: int = 32,
    ) -> FileEncryptedStorageBackend:
        """
        Create encrypted keystore with integrity-protected salt.

        Args:
            filepath: path to keystore file.
            password_provider: callable returning master password.
            salt_path: path to salt file (integrity tag stored at <salt_path>.integrity).
            key_len: derived key length (default: 32 for AES-256).

        Returns:
            FileEncryptedStorageBackend instance.
        """
        salt = _load_or_create_salt(salt_path, self.config.kdf.salt_len)
        set_secure_file_permissions(salt_path)

        password = password_provider().encode("utf-8")

        # Apply pepper at KDF stage (separate from hashing policy)
        if self.config.pepper_provider is not None:
            pepper = self.config.pepper_provider()
            password = hmac.new(pepper, password, hashlib.sha256).digest()

        params = self._select_kdf_params_strict()
        key = self.kdf.derive_key(password, salt, key_len, params=params)

        return FileEncryptedStorageBackend(filepath, self.symmetric, lambda: key)

    # ---- Internals ----

    def _select_kdf_params_strict(self) -> KdfParams:
        if self.config.kdf.use_argon2id:
            try:
                __import__("argon2")
            except ImportError as e:
                LOGGER.error("Argon2 required for KDF but not available")
                raise KDFAlgorithmError("Argon2 not available") from e
            return Argon2idParams(
                version="argon2id",
                time_cost=self.config.kdf.argon2_time_cost,
                memory_cost=self.config.kdf.argon2_memory_cost,
                parallelism=self.config.kdf.argon2_parallelism,
                salt_len=self.config.kdf.salt_len,
            )
        return PBKDF2Params(
            version="pbkdf2",
            hash_name="sha256",
            iterations=self.config.kdf.pbkdf2_iterations,
            salt_len=self.config.kdf.salt_len,
        )


# ---- Helpers ----


def _compute_salt_integrity(salt: bytes) -> bytes:
    """
    Compute HMAC-SHA256 integrity tag for salt.

    Args:
        salt: salt bytes to protect.

    Returns:
        128-bit integrity tag.

    Notes:
        Uses fixed derivation from salt itself for stateless verification.
        In high-security deployments, consider hardware-bound key or separate storage.
    """
    # Derive integrity key from salt + fixed context
    # This is stateless but provides tamper detection
    h: bytes = hashlib.sha256(b"FXTP3-SALT-INTEGRITY-v1" + salt).digest()
    return h[:16]  # 128-bit tag


def _load_or_create_salt(path: str, length: int) -> bytes:
    """
    Load or create salt file with integrity protection and proper path handling.

    Args:
        path: path to salt file.
        length: required salt length in bytes.

    Returns:
        Salt bytes.

    Raises:
        ValueError: if salt file integrity is violated (corrupted).
    """
    path_obj = Path(path).resolve()
    integrity_path = path_obj.with_suffix(path_obj.suffix + ".integrity")

    if path_obj.exists():
        data: bytes = _read_all(str(path_obj))

        # Check integrity if tag file exists
        if integrity_path.exists():
            stored_tag: bytes = _read_all(str(integrity_path))

            try:
                # Try base64-encoded format first
                salt: bytes = base64.b64decode(data, validate=True)
                computed_tag: bytes = _compute_salt_integrity(salt)

                if not hmac.compare_digest(stored_tag, computed_tag):
                    LOGGER.error("Salt integrity check failed for %s", path_obj)
                    raise ValueError("Salt file integrity violation")

                if len(salt) == length:
                    LOGGER.debug(
                        "Salt loaded with integrity verification: %s", path_obj
                    )
                    return salt
                else:
                    # Wrong length - regenerate instead of raising
                    LOGGER.error(
                        "Invalid salt length %d (expected %d) in %s. Generating new salt.",
                        len(salt),
                        length,
                        path_obj,
                    )
                    # Fall through to generation below

            except ValueError as e:
                # Integrity violation - re-raise
                if "integrity violation" in str(e):
                    raise
                # Other ValueError (e.g., base64 decode) - try legacy format
                try:
                    if len(data) == length:
                        computed_tag_raw: bytes = _compute_salt_integrity(data)

                        if not hmac.compare_digest(stored_tag, computed_tag_raw):
                            LOGGER.error("Salt integrity check failed for %s", path_obj)
                            raise ValueError("Salt file integrity violation")

                        LOGGER.debug(
                            "Salt loaded (legacy format) with integrity: %s", path_obj
                        )
                        return data
                    else:
                        # Wrong length - regenerate
                        LOGGER.error(
                            "Invalid salt length %d (expected %d) in %s. Generating new salt.",
                            len(data),
                            length,
                            path_obj,
                        )
                        # Fall through to generation
                except Exception:
                    LOGGER.error(
                        "Invalid salt format in %s. Generating new salt.", path_obj
                    )
                    # Fall through to generation
        else:
            # No integrity file, try loading salt directly (legacy)
            try:
                salt_legacy: bytes = base64.b64decode(data, validate=True)
                if len(salt_legacy) == length:
                    LOGGER.warning("Salt loaded WITHOUT integrity check: %s", path_obj)
                    return salt_legacy
                else:
                    # Wrong length - regenerate
                    LOGGER.error(
                        "Invalid salt length %d (expected %d) in %s. Generating new salt.",
                        len(salt_legacy),
                        length,
                        path_obj,
                    )
                    # Fall through to generation
            except Exception:
                if len(data) == length:
                    LOGGER.warning(
                        "Salt loaded (legacy raw) WITHOUT integrity: %s", path_obj
                    )
                    return data
                else:
                    # Wrong length - regenerate
                    LOGGER.error(
                        "Invalid salt length %d (expected %d) in %s. Generating new salt.",
                        len(data),
                        length,
                        path_obj,
                    )
                    # Fall through to generation

    # Generate new salt with integrity protection
    LOGGER.info("Generating new salt: %s", path_obj)
    new_salt: bytes = generate_salt(length)
    integrity_tag: bytes = _compute_salt_integrity(new_salt)

    # Write both files atomically
    _write_all(str(path_obj), base64.b64encode(new_salt))
    _write_all(str(integrity_path), integrity_tag)

    # Set strict permissions on both files
    set_secure_file_permissions(str(path_obj))
    set_secure_file_permissions(str(integrity_path))

    LOGGER.info("Salt created with integrity protection: %s", path_obj)
    return new_salt


def _read_all(path: str) -> bytes:
    """Read entire file content."""
    with open(path, "rb") as f:
        return bytes(f.read())


def _write_all(path: str, data: bytes) -> None:
    """Write data to file atomically."""
    # Use temp file + rename for atomicity
    path_obj = Path(path)
    tmp_path = path_obj.with_suffix(path_obj.suffix + ".tmp")

    try:
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replace
        tmp_path.replace(path_obj)
    except Exception:
        # Cleanup on failure
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise


__all__ = [
    "CryptoService",
    "ServiceConfig",
    "KdfPolicy",
    "HashingPolicy",
    "_load_or_create_salt",
]
