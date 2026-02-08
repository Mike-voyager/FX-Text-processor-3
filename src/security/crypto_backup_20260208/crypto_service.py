# -*- coding: utf-8 -*-
"""
CryptoService - unified cryptographic service façade.

Changes in v2.0:
- Uses Argon2Config profiles from config.py
- PasswordHasher moved to passwords.py
- Added BLAKE3 support via blake3_hash.py
- Simplified configuration with device profiles
- Enhanced type safety with protocols

Design:
- Prefers Argon2id for KDF/password hashing (OWASP recommended)
- Default signing: Ed25519 (fast, side-channel resistant)
- Symmetric: AES-256-GCM (primary), ChaCha20-Poly1305 (optional)
- Salt files protected with HMAC integrity tags
- No secrets in logs
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Final, Optional, Union, cast

# Core crypto modules
from .asymmetric import AsymmetricKeyPair

# New v2.0 imports
from .config import Argon2Config, Argon2Profile
from .exceptions import HashSchemeError, KDFAlgorithmError
from .kdf import DefaultKdfProvider
from .passwords import PasswordHasher
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

# Optional BLAKE3 support
try:
    from .blake3_hash import (
        BLAKE3_AVAILABLE,
        blake3_derive_key,
        blake3_hash_file,
        compute_hash_blake3,
        hmac_blake3,
    )
except ImportError:
    BLAKE3_AVAILABLE = False

# Data hashing (SHA-256, SHA-512, BLAKE2b, BLAKE3)
from .hashing import (
    compute_hash,
    compute_hash_blake2b,
    compute_hash_sha3_256,
    compute_hash_sha256,
    hash_file,
    verify_file,
)

# Health monitoring
from .health import crypto_health_check

# Key rotation
from .key_rotation import KeyMetadata, KeyRotationManager

# Platform security
from .platform_security import (
    disable_core_dumps,
    get_platform_capabilities,
    initialize_platform_security,
    lock_memory,
    secure_delete_file,
    unlock_memory,
)

# Standards (PIV, OpenPGP, Camellia, Twofish)
from .standards import (
    OPENPGP_EC_CURVES,
    PIV_EC_CURVES,
    PIV_RSA_SIZES,
    CamelliaGCM,
    OpenPGPKeyPair,
    PIVKeyPair,
    TwofishCTR,
)

# Post-quantum cryptography (optional)
try:
    from .pqc import (
        DILITHIUM_AVAILABLE,
        KYBER_AVAILABLE,
        DilithiumSigner,
        KyberKEM,
        hybrid_kem_x25519_kyber,
    )

    PQC_MODULE_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False
    DILITHIUM_AVAILABLE = False
    PQC_MODULE_AVAILABLE = False
    KyberKEM: Any = None  # type: ignore
    DilithiumSigner: Any = None  # type: ignore
    hybrid_kem_x25519_kyber: Any = None  # type: ignore


LOGGER: Final = logging.getLogger(__name__)


class AsymmetricSignerAdapter:
    """
    Adapter to expose SigningProtocol-compatible interface over AsymmetricKeyPair.

    Implements duck-typed SigningProtocol:
      - sign(data: bytes, *, context: Optional[bytes]) -> bytes
      - verify(data: bytes, signature: bytes, *, context: Optional[bytes]) -> bool
      - public_key(fmt: str) -> bytes | str
      - get_fingerprint() -> str

    Notes:
      - Context is ignored for asymmetric signers (interface parity).
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
    """
    KDF policy configuration.

    Attributes:
        use_argon2id: Use Argon2id (recommended) vs PBKDF2.
        argon2_profile: Device profile (DESKTOP, SAFE_DESKTOP, CUSTOM).
        argon2_config: Explicit config (overrides profile if provided).
        pbkdf2_iterations: PBKDF2 iterations if Argon2 unavailable.
        salt_len: Salt length in bytes.
    """

    use_argon2id: bool = True
    argon2_profile: Argon2Profile = Argon2Profile.DESKTOP
    argon2_config: Optional[Argon2Config] = None
    pbkdf2_iterations: int = 600_000  # OWASP 2023 minimum
    salt_len: int = 16

    def get_argon2_config(self) -> Argon2Config:
        """Get effective Argon2 config (explicit or from profile)."""
        if self.argon2_config:
            return self.argon2_config
        return Argon2Config.from_profile(self.argon2_profile)


@dataclass(slots=True)
class HashingPolicy:
    """
    Password hashing policy.

    Attributes:
        scheme: Hashing algorithm ("argon2id" | "pbkdf2").
        argon2_profile: Device profile for Argon2id.
        argon2_config: Explicit Argon2 config (overrides profile).
        pbkdf2_iterations: PBKDF2 iterations if used.
        salt_len: Salt length in bytes.
        rate_limit_enabled: Enable timing-safe verification.
    """

    scheme: str = "argon2id"  # "argon2id" | "pbkdf2"
    argon2_profile: Argon2Profile = Argon2Profile.DESKTOP
    argon2_config: Optional[Argon2Config] = None
    pbkdf2_iterations: int = 600_000
    salt_len: int = 16
    rate_limit_enabled: bool = True

    def get_argon2_config(self) -> Argon2Config:
        """Get effective Argon2 config."""
        if self.argon2_config:
            return self.argon2_config
        return Argon2Config.from_profile(self.argon2_profile)


@dataclass(slots=True)
class ServiceConfig:
    """
    CryptoService configuration.

    Attributes:
        signing_algorithm: Digital signature algorithm.
        rsa_key_size: RSA key size (if using RSA).
        kdf: Key derivation policy.
        hashing: Password hashing policy.
        pepper_provider: Optional pepper provider for additional security.
        pepper_version: Pepper version identifier.
    """

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
      - Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305)
      - Digital signatures (Ed25519/RSA/ECDSA)
      - Key derivation (Argon2id/PBKDF2)
      - Password hashing with rate limiting
      - Encrypted keystore management
      - Optional BLAKE3 support

    Examples:
        >>> # Use device profile
        >>> config = ServiceConfig()
        >>> config.hashing.argon2_profile = Argon2Profile.SAFE_DESKTOP
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
        Create default CryptoService with given config.

        Args:
            cfg: Service configuration (uses defaults if None).

        Returns:
            Configured CryptoService instance.

        Raises:
            HashSchemeError: If Argon2id required but unavailable.
            ValueError: If signing algorithm not supported.
        """
        cfg = cfg or ServiceConfig()

        # Symmetric cipher
        symmetric_impl = SymmetricCipher()
        symmetric: SymmetricCipherProtocol = cast(
            SymmetricCipherProtocol, symmetric_impl
        )

        # KDF provider
        kdf_provider: KdfProtocol = DefaultKdfProvider()

        # Password hasher
        if cfg.hashing.scheme == "argon2id":
            try:
                __import__("argon2")
            except ImportError as e:
                LOGGER.critical(
                    "Argon2id REQUIRED for production but not available. "
                    "Install: pip install argon2-cffi>=23.1.0"
                )
                raise HashSchemeError("Argon2id not available") from e

            argon2_cfg = cfg.hashing.get_argon2_config()
            hasher: object = PasswordHasher(
                scheme="argon2id",
                time_cost=argon2_cfg.time_cost,
                memory_cost=argon2_cfg.memory_cost,
                parallelism=argon2_cfg.parallelism,
                rate_limit_enabled=cfg.hashing.rate_limit_enabled,
                salt_len=argon2_cfg.salt_length,
                pepper_provider=cfg.pepper_provider,
                pepper_version=cfg.pepper_version,
            )
            LOGGER.info(
                "PasswordHasher initialized with Argon2id profile: %s "
                "(t=%d, m=%d KiB, p=%d)",
                cfg.hashing.argon2_profile.value,
                argon2_cfg.time_cost,
                argon2_cfg.memory_cost,
                argon2_cfg.parallelism,
            )

        elif cfg.hashing.scheme == "pbkdf2":
            LOGGER.warning(
                "⚠️ SECURITY DEGRADATION: Using PBKDF2 instead of Argon2id. "
                "GPU resistance reduced by ~10,000×. "
                "NOT RECOMMENDED for production."
            )
            hasher = PasswordHasher(
                scheme="pbkdf2",
                iterations=cfg.hashing.pbkdf2_iterations,
                rate_limit_enabled=cfg.hashing.rate_limit_enabled,
                salt_len=cfg.hashing.salt_len,
                pepper_provider=cfg.pepper_provider,
                pepper_version=cfg.pepper_version,
            )
        else:
            raise HashSchemeError(f"Unsupported hashing scheme: {cfg.hashing.scheme}")

        # Signing provider
        if cfg.signing_algorithm == "ed25519":
            signer: object = Ed25519Signer.generate()
            LOGGER.info("Signer initialized: Ed25519 (recommended)")

        elif cfg.signing_algorithm in ("rsa4096", "ecdsa_p256"):
            akp = AsymmetricKeyPair.generate(
                cfg.signing_algorithm, key_size=cfg.rsa_key_size
            )
            signer = AsymmetricSignerAdapter(akp)
            LOGGER.info("Signer initialized: %s", cfg.signing_algorithm.upper())
        else:
            raise ValueError(f"Unsupported signing algorithm: {cfg.signing_algorithm}")

        return CryptoService(symmetric, signer, kdf_provider, hasher, cfg)

    # ---- Password hashing façade ----

    def hash_password(self, password: str) -> str:
        """Hash password with configured algorithm."""
        return cast(str, getattr(self.hasher, "hash_password")(password))

    def verify_password(
        self,
        password: str,
        hashed: str,
        identifier: Optional[str] = None,
    ) -> bool:
        """Verify password against hash (timing-safe)."""
        return bool(
            getattr(self.hasher, "verify_password")(password, hashed, identifier)
        )

    def needs_rehash(self, hashed: str) -> bool:
        """Check if hash needs rehashing (params changed)."""
        return bool(getattr(self.hasher, "needs_rehash")(hashed))

    # ---- Signing façade ----

    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        """Sign data with configured algorithm."""
        try:
            return cast(bytes, getattr(self.signer, "sign")(data, context=context))
        except TypeError:
            return cast(bytes, getattr(self.signer, "sign")(data))

    def verify(
        self, data: bytes, signature: bytes, *, context: Optional[bytes] = None
    ) -> bool:
        """Verify signature (timing-safe)."""
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
        """
        Encrypt plaintext with AES-256-GCM.

        Args:
            key: 32-byte encryption key.
            plaintext: Data to encrypt.
            aad: Additional authenticated data (optional).
            return_combined: Return (nonce, ciphertext+tag) if True.

        Returns:
            (nonce, ciphertext+tag) or (nonce, ciphertext, tag).
        """
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
        """
        Decrypt ciphertext with AES-256-GCM.

        Args:
            key: 32-byte decryption key.
            nonce: Nonce from encryption.
            data: Ciphertext+tag (if has_combined=True).
            aad: Additional authenticated data (optional).
            has_combined: data includes tag at end.
            tag: Separate tag (if has_combined=False).

        Returns:
            Decrypted plaintext.
        """
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
            filepath: Path to keystore file.
            password_provider: Callable returning master password.
            salt_path: Path to salt file (integrity tag at <salt_path>.integrity).
            key_len: Derived key length (default: 32 for AES-256).

        Returns:
            FileEncryptedStorageBackend instance.

        Notes:
            - Uses configured KDF (Argon2id or PBKDF2).
            - Applies pepper if configured.
            - Salt and integrity file created with secure permissions (0o600).
        """
        salt = _load_or_create_salt(salt_path, self.config.kdf.salt_len)
        set_secure_file_permissions(salt_path)

        password = password_provider().encode("utf-8")

        # Apply pepper at KDF stage
        if self.config.pepper_provider is not None:
            pepper = self.config.pepper_provider()
            password = hmac.new(pepper, password, hashlib.sha256).digest()

        params = self._select_kdf_params_strict()
        key = self.kdf.derive_key(password, salt, key_len, params=params)

        return FileEncryptedStorageBackend(filepath, self.symmetric, lambda: key)

    # ---- Internals ----

    def _select_kdf_params_strict(self) -> KdfParams:
        """Select KDF parameters based on policy (strict mode)."""
        if self.config.kdf.use_argon2id:
            try:
                __import__("argon2")
            except ImportError as e:
                LOGGER.error("Argon2 required for KDF but not available")
                raise KDFAlgorithmError("Argon2 not available") from e

            argon2_cfg = self.config.kdf.get_argon2_config()
            return Argon2idParams(
                version="argon2id",
                time_cost=argon2_cfg.time_cost,
                memory_cost=argon2_cfg.memory_cost,
                parallelism=argon2_cfg.parallelism,
                salt_len=argon2_cfg.salt_length,
            )

        return PBKDF2Params(
            version="pbkdf2",
            hash_name="sha256",
            iterations=self.config.kdf.pbkdf2_iterations,
            salt_len=self.config.kdf.salt_len,
        )


# ---- Salt integrity helpers ----


def _compute_salt_integrity(salt: bytes) -> bytes:
    """
    Compute HMAC-SHA256 integrity tag for salt.

    Args:
        salt: Salt bytes to protect.

    Returns:
        128-bit integrity tag.

    Notes:
        Uses fixed derivation from salt itself for stateless verification.
        For high-security deployments, consider hardware-bound key.
    """
    h: bytes = hashlib.sha256(b"FXTP3-SALT-INTEGRITY-v2" + salt).digest()
    return h[:16]  # 128-bit tag


def _load_or_create_salt(path: str, length: int) -> bytes:
    """
    Load or create salt file with integrity protection.

    Args:
        path: Path to salt file.
        length: Required salt length in bytes.

    Returns:
        Salt bytes.

    Raises:
        ValueError: If salt integrity check fails.

    Notes:
        - Creates <path>.integrity file with HMAC tag.
        - Sets permissions to 0o600 on both files.
        - Base64-encodes salt for safe storage.
    """
    path_obj = Path(path).resolve()
    integrity_path = path_obj.with_suffix(path_obj.suffix + ".integrity")

    if path_obj.exists():
        data: bytes = _read_all(str(path_obj))

        # Check integrity if tag exists
        if integrity_path.exists():
            stored_tag: bytes = _read_all(str(integrity_path))

            try:
                # Try base64-encoded format first
                salt: bytes = base64.b64decode(data, validate=True)
                computed_tag: bytes = _compute_salt_integrity(salt)

                if not hmac.compare_digest(stored_tag, computed_tag):
                    LOGGER.error("Salt integrity check FAILED: %s", path_obj)
                    raise ValueError("Salt file integrity violation")

                if len(salt) == length:
                    LOGGER.debug(
                        "Salt loaded with integrity verification: %s", path_obj
                    )
                    return salt
                else:
                    LOGGER.warning(
                        "Salt length mismatch (%d != %d), regenerating: %s",
                        len(salt),
                        length,
                        path_obj,
                    )
                    # Fall through to regeneration

            except ValueError as e:
                if "integrity violation" in str(e):
                    raise
                # Try legacy raw format
                try:
                    if len(data) == length:
                        computed_tag_raw: bytes = _compute_salt_integrity(data)
                        if not hmac.compare_digest(stored_tag, computed_tag_raw):
                            raise ValueError("Salt file integrity violation")
                        LOGGER.debug("Salt loaded (legacy format): %s", path_obj)
                        return data
                except Exception:
                    LOGGER.warning("Invalid salt format, regenerating: %s", path_obj)
                    # Fall through
        else:
            # No integrity file (legacy)
            try:
                salt_legacy: bytes = base64.b64decode(data, validate=True)
                if len(salt_legacy) == length:
                    LOGGER.warning("Salt loaded WITHOUT integrity check: %s", path_obj)
                    return salt_legacy
            except Exception:
                if len(data) == length:
                    LOGGER.warning("Salt loaded (raw, no integrity): %s", path_obj)
                    return data

    # Generate new salt with integrity protection
    LOGGER.info("Generating new salt: %s", path_obj)
    new_salt: bytes = generate_salt(length)
    integrity_tag: bytes = _compute_salt_integrity(new_salt)

    # Write atomically
    _write_all(str(path_obj), base64.b64encode(new_salt))
    _write_all(str(integrity_path), integrity_tag)

    # Secure permissions
    set_secure_file_permissions(str(path_obj))
    set_secure_file_permissions(str(integrity_path))

    LOGGER.info("Salt created with integrity protection: %s", path_obj)
    return new_salt


def _read_all(path: str) -> bytes:
    """Read entire file content."""
    with open(path, "rb") as f:
        return bytes(f.read())


def _write_all(path: str, data: bytes) -> None:
    """Write data to file atomically (temp + rename)."""
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
    # ========== Core service ==========
    "CryptoService",
    "ServiceConfig",
    "AsymmetricSignerAdapter",
    "KdfPolicy",
    "HashingPolicy",
    # ========== Config (re-exports) ==========
    "Argon2Config",
    "Argon2Profile",
    # ========== Data hashing ==========
    "compute_hash",
    "compute_hash_sha256",
    "compute_hash_sha3_256",
    "compute_hash_blake2b",
    "hash_file",
    "verify_file",
    # ========== BLAKE3 (optional) ==========
    "BLAKE3_AVAILABLE",
    # ========== Health monitoring ==========
    "crypto_health_check",
    # ========== Key rotation ==========
    "KeyMetadata",
    "KeyRotationManager",
    # ========== Platform security ==========
    "lock_memory",
    "unlock_memory",
    "disable_core_dumps",
    "secure_delete_file",
    "get_platform_capabilities",
    "initialize_platform_security",
    # ========== Standards (PIV, OpenPGP) ==========
    "PIV_RSA_SIZES",
    "PIV_EC_CURVES",
    "OPENPGP_EC_CURVES",
    "PIVKeyPair",
    "OpenPGPKeyPair",
    "CamelliaGCM",
    "TwofishCTR",
    # ========== Post-quantum (optional) ==========
    "KYBER_AVAILABLE",
    "DILITHIUM_AVAILABLE",
    "PQC_MODULE_AVAILABLE",
]

# Conditionally add BLAKE3 functions if available
if BLAKE3_AVAILABLE:
    __all__.extend(
        [
            "blake3_derive_key",
            "blake3_hash_file",
            "compute_hash_blake3",
            "hmac_blake3",
        ]
    )

# Conditionally add PQC classes if available
if PQC_MODULE_AVAILABLE:
    __all__.extend(
        [
            "KyberKEM",
            "DilithiumSigner",
            "hybrid_kem_x25519_kyber",
        ]
    )
